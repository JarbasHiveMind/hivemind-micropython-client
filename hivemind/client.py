"""HiveMind WebSocket client for MicroPython 1.20+ and CPython 3.10+.

Implements the full HiveMind handshake protocol (hello -> shake -> key
derivation -> encrypted session) over WebSocket transport.  On MicroPython
uses ``uwebsocket`` / ``uasyncio``; on CPython uses ``websockets`` /
``asyncio``.
"""

from __future__ import annotations

from typing import Callable, Dict, Optional, Tuple

try:
    import uwebsocket  # type: ignore[import]
    import uasyncio as asyncio  # type: ignore[import]
    from ubinascii import b2a_base64  # type: ignore[import]

    _MICROPYTHON = True
except ImportError:
    import asyncio
    from base64 import b64encode

    def b2a_base64(data: bytes) -> bytes:
        """Base64-encode *data* (CPython shim for MicroPython API)."""
        return b64encode(data)

    uwebsocket = None  # type: ignore[assignment]
    _MICROPYTHON = False

import json

from hivemind.crypto import (
    generate_hsub,
    extract_iv,
    derive_key,
    encrypt_json,
    decrypt_json,
    encrypt_json_hex,
    decrypt_json_hex,
    randbytes,
    CIPHER_AES_GCM,
    CIPHER_CHACHA20,
    _norm_cipher,
)
from hivemind.binary import encode as binary_encode, decode as binary_decode
from hivemind.noise import (
    PROTOCOL_V3,
    NoiseHandshake,
    NoiseHandshakeError,
    NoiseTransport,
    build_prologue,
    canonical_json,
    noise_protocol_name,
    select_noise_options,
)

# ---------------------------------------------------------------------------
# Connection states
# ---------------------------------------------------------------------------

STATE_DISCONNECTED: int = 0
STATE_CONNECTING: int = 1
STATE_HELLO_RECEIVED: int = 2
STATE_HANDSHAKE_SENT: int = 3
STATE_KEY_DERIVED: int = 4
STATE_READY: int = 5

# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

MSG_HANDSHAKE: int = 0
MSG_BUS: int = 1
MSG_SHARED_BUS: int = 2
MSG_BROADCAST: int = 3
MSG_PROPAGATE: int = 4
MSG_ESCALATE: int = 5
MSG_HELLO: int = 6
MSG_QUERY: int = 7
MSG_CASCADE: int = 8
MSG_PING: int = 9
MSG_RENDEZVOUS: int = 10
MSG_THIRDPARTY: int = 11
MSG_BINARY: int = 12
MSG_PONG: int = 13

_TYPE_NAMES: Dict[int, str] = {
    0: "shake", 1: "bus", 2: "shared_bus", 3: "broadcast",
    4: "propagate", 5: "escalate", 6: "hello", 7: "query",
    8: "cascade", 9: "ping", 10: "rendezvous", 11: "3rdparty",
    12: "bin", 13: "pong",
}
_NAME_TO_TYPE: Dict[str, int] = {v: k for k, v in _TYPE_NAMES.items()}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class HiveMindClient:
    """Async WebSocket client that performs HiveMind handshake and provides
    encrypted bus messaging.

    Works on both MicroPython (``uwebsocket`` + ``uasyncio``) and CPython
    (``websockets`` + ``asyncio``).
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        access_key: str,
        password: str,
        site_id: str = "micropython",
        preferred_cipher: str = CIPHER_AES_GCM,
        preferred_encoding: str = "JSON-HEX",
        reconnect_ms: int = 5000,
        psk: Optional[bytes] = None,
        noise_static_key: Optional[bytes] = None,
        server_noise_key: Optional[bytes] = None,
        max_protocol_version: int = PROTOCOL_V3,
    ) -> None:
        """
        Args:
            psk: The **provisioned** 32-byte Noise pre-shared key
                (HIVEMIND-CRYPTO-1 §3.4.4) — 32 raw bytes or a 64-char hex
                string. Constrained nodes never derive it on-device (argon2id
                is infeasible on a microcontroller): compute it once on a
                capable host (``hivemind-core derive-psk``, equal to
                ``argon2id(password, SHA-256(node_id))``). Enables the
                protocol v3 Noise handshake when the server offers it;
                without it the legacy v0-v2 handshake is used.
            noise_static_key: This node's static X25519 private key (32 raw
                bytes or hex). Generated per-connection when omitted;
                provision + persist it for a stable node identity and to use
                ``KKpsk0``.
            server_noise_key: The server's static X25519 public key (32 raw
                bytes or hex), pinned/provisioned out of band. Selects the
                ``KKpsk0`` pattern when the server offers it and makes any
                key mismatch a fatal authentication failure (TOFU pinning,
                §3.4.5). After an ``XXpsk2`` handshake the learned key is
                stored here for the caller to persist.
            max_protocol_version: Highest protocol version this client
                offers (default 3). Set to 2 to force the legacy handshake.
        """
        self.host: str = host
        self.port: int = port
        self.username: str = username
        self.access_key: str = access_key
        self.password: str = password
        self.site_id: str = site_id
        # Normalise to the canonical wire value so cipher negotiation strings
        # byte-match what the hub (hivemind-bus-client) expects.
        self.preferred_cipher: str = _norm_cipher(preferred_cipher)
        self.preferred_encoding: str = preferred_encoding
        self.reconnect_ms: int = reconnect_ms

        self.state: int = STATE_DISCONNECTED
        self._key: Optional[bytes] = None
        self._cipher: Optional[str] = None
        self._encoding: str = preferred_encoding
        self._client_iv: Optional[bytes] = None
        self._client_hsub: Optional[str] = None
        self._session_id: Optional[str] = None
        self._ws: object = None  # WebSocket connection (type varies by platform)

        # protocol v3 (Noise) state
        def _to_bytes(val):
            return bytes.fromhex(val) if isinstance(val, str) else val

        self.psk: Optional[bytes] = _to_bytes(psk)
        if self.psk is not None and len(self.psk) != 32:
            raise ValueError("psk must be exactly 32 bytes")
        self.noise_static_key: Optional[bytes] = _to_bytes(noise_static_key)
        self.server_noise_key: Optional[bytes] = _to_bytes(server_noise_key)
        self.max_protocol_version: int = max_protocol_version
        self._server_hello_payload: Optional[dict] = None
        self._noise_handshake: Optional[NoiseHandshake] = None
        self._noise_transport: Optional[NoiseTransport] = None

        # Callbacks
        self.on_bus_message: Optional[Callable[[str, dict, dict], None]] = None
        self.on_binary: Optional[Callable[[int, bytes], None]] = None
        self.on_state_change: Optional[Callable[[int], None]] = None
        self.on_connected: Optional[Callable[[], None]] = None

    # -- state management ---------------------------------------------------

    def _set_state(self, state: int) -> None:
        """Update connection state and notify callback."""
        self.state = state
        if self.on_state_change is not None:
            self.on_state_change(state)

    # -- session helpers ----------------------------------------------------

    @staticmethod
    def _generate_session_id() -> str:
        """Generate a 32-char random hex string formatted as a UUID-like ID."""
        raw = randbytes(16).hex()
        return (
            f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:32]}"
        )

    # -- envelope building --------------------------------------------------

    @staticmethod
    def _build_envelope(msg_type: str, payload: dict) -> str:
        """Build a JSON envelope string for *msg_type* with *payload*."""
        return json.dumps({
            "msg_type": msg_type,
            "payload": payload,
            "metadata": {},
            "route": [],
            "node": None,
            "target_site_id": None,
            "target_pubkey": None,
            "source_peer": None,
        })

    # -- transport ----------------------------------------------------------

    async def _send(self, data) -> None:
        """Send a text (``str``) or binary (``bytes``) frame over the
        websocket."""
        if self._ws is None:
            raise ConnectionError("WebSocket not connected")
        if _MICROPYTHON:
            self._ws.write(data)  # type: ignore[union-attr]
        else:
            await self._ws.send(data)  # type: ignore[union-attr]

    async def _send_encrypted(self, msg_type: str, payload: dict) -> None:
        """Encrypt an envelope and send it over the websocket.

        On a protocol v3 session every message is a Noise transport message
        (HIVEMIND-CRYPTO-1 §3.4.5); otherwise the legacy v0-v2 session
        cipher is used.
        """
        envelope = self._build_envelope(msg_type, payload)
        if self._noise_transport is not None:
            await self._send(self._noise_transport.encrypt_frame(envelope))
            return
        if self._key is None or self._cipher is None:
            raise RuntimeError("Session key not established")
        encrypted = encrypt_json(self._key, envelope.encode(), self._cipher, self._encoding)
        await self._send(encrypted)

    # -- connect / disconnect -----------------------------------------------

    async def connect(self) -> None:
        """Open a WebSocket connection and start the handshake.

        Generates a session ID, builds the authorization header, connects
        to the hub, and enters the receive loop.
        """
        self._session_id = self._generate_session_id()
        auth_raw = f"{self.username}:{self.access_key}".encode()
        auth = b2a_base64(auth_raw).decode().strip()
        url = f"ws://{self.host}:{self.port}/?authorization={auth}"

        self._set_state(STATE_CONNECTING)

        if _MICROPYTHON:
            self._ws = uwebsocket.connect(url)  # type: ignore[union-attr]
        else:
            import websockets  # type: ignore[import]
            self._ws = await websockets.connect(url)

        await self._receive_loop()

    async def disconnect(self) -> None:
        """Close the websocket and reset state."""
        try:
            if self._ws is not None:
                if _MICROPYTHON:
                    self._ws.close()  # type: ignore[union-attr]
                else:
                    await self._ws.close()  # type: ignore[union-attr]
        except Exception:
            pass
        finally:
            self._ws = None
            self._key = None
            self._cipher = None
            self._noise_handshake = None
            self._noise_transport = None
            self._server_hello_payload = None
            self._set_state(STATE_DISCONNECTED)

    async def _reconnect(self) -> None:
        """Wait and attempt to reconnect."""
        if _MICROPYTHON:
            await asyncio.sleep_ms(self.reconnect_ms)  # type: ignore[attr-defined]
        else:
            await asyncio.sleep(self.reconnect_ms / 1000)
        await self.connect()

    # -- receive loop -------------------------------------------------------

    async def _receive_loop(self) -> None:
        """Read messages from the websocket until disconnected."""
        try:
            while self.state != STATE_DISCONNECTED:
                if _MICROPYTHON:
                    raw = self._ws.readline()  # type: ignore[union-attr]
                    if raw is None:
                        break
                else:
                    raw = await self._ws.recv()  # type: ignore[union-attr]
                    if raw is None:
                        break

                if self.state < STATE_READY:
                    # handshake-phase envelopes are always JSON text
                    if isinstance(raw, bytes):
                        raw = raw.decode()
                    await self._handle_handshake(raw)
                else:
                    # protocol v3 transport frames arrive as binary; legacy
                    # sessions use text frames
                    if isinstance(raw, bytes) and self._noise_transport is None:
                        raw = raw.decode()
                    await self._dispatch_message(raw)
        except Exception:
            pass
        finally:
            if self.state != STATE_DISCONNECTED:
                self._set_state(STATE_DISCONNECTED)
                if self.reconnect_ms > 0:
                    asyncio.ensure_future(self._reconnect())

    # -- handshake ----------------------------------------------------------

    async def _handle_handshake(self, raw: str) -> None:
        """Process a handshake-phase message.

        Walks through the state machine: CONNECTING -> HELLO_RECEIVED ->
        HANDSHAKE_SENT -> KEY_DERIVED -> READY.
        """
        try:
            msg = json.loads(raw)
        except (ValueError, TypeError):
            return

        msg_type: str = msg.get("msg_type", "")
        payload: dict = msg.get("payload", {})

        if self.state == STATE_CONNECTING and msg_type == "hello":
            # Store server info
            self._server_pubkey: str = payload.get("pubkey", "")
            self._server_peer: str = payload.get("peer", "")
            self._server_node_id: str = payload.get("node_id", "")
            # exact payload retained for the Noise prologue (§3.4.3)
            self._server_hello_payload = dict(payload)
            self._set_state(STATE_HELLO_RECEIVED)

        elif self.state == STATE_HELLO_RECEIVED and msg_type == "shake":
            if not payload.get("handshake"):
                return
            if self._should_use_noise(payload):
                # protocol v3: Noise handshake (HIVEMIND-CRYPTO-1 §3.4)
                await self._start_noise_handshake(payload)
                return
            # legacy v0-v2 password handshake: generate client hsub
            iv, hsub_hex = generate_hsub(self.password)
            self._client_iv = iv
            self._client_hsub = hsub_hex
            # Build and send shake response
            response = self._build_envelope("shake", {
                "envelope": hsub_hex,
                "encodings": [self.preferred_encoding],
                "ciphers": [self.preferred_cipher],
                "binarize": False,
            })
            await self._send(response)
            self._set_state(STATE_HANDSHAKE_SENT)

        elif (self.state == STATE_HANDSHAKE_SENT and msg_type == "shake"
              and self._noise_handshake is not None):
            # protocol v3: server's Noise handshake message (§3.4.3 step 4)
            await self._receive_noise_handshake(payload)

        elif self.state == STATE_HANDSHAKE_SENT and msg_type == "shake":
            # Derive session key from server hsub
            server_hsub: str = payload.get("envelope", "")
            server_iv = extract_iv(server_hsub)
            if self._client_iv is None:
                return
            self._key = derive_key(self.password, self._client_iv, server_iv)
            self._cipher = payload.get("cipher", self.preferred_cipher)
            self._encoding = payload.get("encoding", self.preferred_encoding)
            self._set_state(STATE_KEY_DERIVED)

            # Send encrypted hello
            hello_payload = {
                "pubkey": "",
                "session": {"session_id": self._session_id},
                "site_id": self.site_id,
            }
            await self._send_encrypted("hello", hello_payload)
            self._set_state(STATE_READY)

            if self.on_connected is not None:
                self.on_connected()

    # -- protocol v3 (Noise) handshake ----------------------------------------

    def _should_use_noise(self, payload: dict) -> bool:
        """True when both peers are v3-capable and a PSK is provisioned.

        Per HIVEMIND-WIRE-1 §2 both peers operate at the highest protocol
        version both support: the server must advertise
        ``max_protocol_version`` >= 3 together with Noise
        ``patterns``/``suites`` this client can run (ChaChaPoly), and a
        32-byte PSK must be provisioned (§3.4.4 — never derived on-device).
        Any other combination falls back to the legacy v0-v2 handshake.
        """
        if self.psk is None or self.max_protocol_version < PROTOCOL_V3:
            return False
        if payload.get("max_protocol_version", 1) < PROTOCOL_V3:
            return False
        noise_params = payload.get("noise")
        if not isinstance(noise_params, dict):
            return False
        return select_noise_options(noise_params.get("patterns") or [],
                                    noise_params.get("suites") or [],
                                    self.server_noise_key) is not None

    async def _start_noise_handshake(self, payload: dict) -> None:
        """Send Noise message 1 (HIVEMIND-CRYPTO-1 §3.4.3 step 3).

        Selects one pattern and one suite from the server's advertised
        lists, binds the negotiation into the prologue, and carries the
        Noise message bytes inside the regular HANDSHAKE envelope.
        """
        noise_params = payload.get("noise") or {}
        pattern, suite = select_noise_options(
            noise_params.get("patterns") or [],
            noise_params.get("suites") or [],
            self.server_noise_key)
        name = noise_protocol_name(pattern, suite)
        prologue = build_prologue(self._server_hello_payload or {},
                                  payload, name)
        try:
            self._noise_handshake = NoiseHandshake(
                pattern=pattern,
                psk=self.psk,
                prologue=prologue,
                suite=suite,
                static_private=self.noise_static_key,
                remote_static=self.server_noise_key if pattern == "KKpsk0" else None,
            )
            # Noise payload of message 1: preference-ordered encodings +
            # binarize capability (§3.4.3 step 3)
            msg1 = self._noise_handshake.write_message(canonical_json({
                "binarize": False,
                "encodings": [self.preferred_encoding],
            }))
        except NoiseHandshakeError:
            await self._abort_noise()
            return
        response = self._build_envelope("shake", {
            "noise": {"pattern": pattern, "suite": suite,
                      "msg": msg1.hex()},
        })
        await self._send(response)
        self._set_state(STATE_HANDSHAKE_SENT)

    async def _receive_noise_handshake(self, payload: dict) -> None:
        """Consume the server's Noise message (§3.4.3 steps 4-7).

        Any authentication failure — wrong PSK (password), tampered
        negotiation (prologue mismatch), or a static key contradicting the
        pinned key — is fatal: the handshake aborts and the connection is
        rejected. On success the two transport CipherStates take over all
        session traffic and the encrypted HELLO is sent as the first Noise
        transport message.
        """
        try:
            msg = bytes.fromhex((payload.get("noise") or {}).get("msg", ""))
        except (TypeError, ValueError):
            await self._abort_noise()
            return
        try:
            noise_payload = self._noise_handshake.read_message(msg)
            if not self._noise_handshake.finished:
                # XXpsk2 message 3: our (encrypted) static key + final DH mix
                msg3 = self._noise_handshake.write_message(b"")
                await self._send(self._build_envelope(
                    "shake", {"noise": {"msg": msg3.hex()}}))
            transport = NoiseTransport(self._noise_handshake)
        except NoiseHandshakeError:
            await self._abort_noise()
            return

        # TOFU-then-pin the server's static key (§3.4.5): abort on mismatch,
        # expose the learned key so the caller can persist the pin
        if (self.server_noise_key
                and transport.remote_static_key != self.server_noise_key):
            await self._abort_noise()
            return
        self.server_noise_key = transport.remote_static_key

        try:
            selection = json.loads(noise_payload.decode()) if noise_payload else {}
        except (ValueError, TypeError):
            selection = {}
        self._encoding = selection.get("encoding", self.preferred_encoding)

        self._noise_transport = transport
        self._noise_handshake = None
        self._set_state(STATE_KEY_DERIVED)

        # first Noise transport message: the encrypted HELLO (§3.4.3 step 7)
        await self._send_encrypted("hello", {
            "pubkey": "",
            "session": {"session_id": self._session_id},
            "site_id": self.site_id,
        })
        self._set_state(STATE_READY)

        if self.on_connected is not None:
            self.on_connected()

    async def _abort_noise(self) -> None:
        """Fatal Noise handshake failure — reject the connection (§3.4.3)."""
        self._noise_handshake = None
        self._noise_transport = None
        await self.disconnect()

    # -- message dispatch ---------------------------------------------------

    async def _dispatch_message(self, raw) -> None:
        """Decrypt and dispatch a message received in READY state."""
        if self._noise_transport is not None:
            # protocol v3: every message is a Noise transport message; any
            # AEAD failure (tampering / replay / reordering) is fatal and is
            # never retried under another nonce (§3.4.5)
            try:
                if isinstance(raw, str):
                    raw = raw.encode()
                frame = self._noise_transport.decrypt_frame(bytes(raw))
            except (ValueError, TypeError):
                await self.disconnect()
                return
            if isinstance(frame, bytes):
                # HIVEMIND-WIRE-1 binary frame
                if self.on_binary is not None:
                    decoded = binary_decode(frame)
                    self.on_binary(decoded["bin_type"], decoded["payload"])
                return
            try:
                envelope = json.loads(frame)
            except (ValueError, TypeError):
                return
        else:
            if self._key is None or self._cipher is None:
                return
            try:
                plaintext = decrypt_json(self._key, raw, self._cipher, self._encoding)
                envelope = json.loads(plaintext)
            except (ValueError, TypeError, KeyError):
                return

        msg_type: str = envelope.get("msg_type", "")
        payload: dict = envelope.get("payload", {})

        if msg_type == "ping":
            await self._send_encrypted("pong", {})

        elif msg_type in ("bus", "shared_bus", "broadcast", "propagate",
                          "escalate", "query", "cascade"):
            inner_type: str = payload.get("type", "")
            inner_data: dict = payload.get("data", {})
            inner_context: dict = payload.get("context", {})
            if self.on_bus_message is not None:
                self.on_bus_message(inner_type, inner_data, inner_context)

        elif msg_type == "bin":
            if self.on_binary is not None:
                bin_type: int = payload.get("bin_type", 0)
                bin_data: bytes = bytes.fromhex(payload.get("data", ""))
                self.on_binary(bin_type, bin_data)

    # -- public send API ----------------------------------------------------

    async def send_utterance(self, text: str, lang: str = "en-us") -> None:
        """Send a user utterance to the hub as a ``recognizer_loop:utterance``
        bus message."""
        bus_payload = {
            "type": "recognizer_loop:utterance",
            "data": {"utterances": [text], "lang": lang},
            "context": {"session": {"session_id": self._session_id},
                        "site_id": self.site_id},
        }
        await self._send_encrypted("bus", bus_payload)

    async def send_bus_message(
        self,
        msg_type: str,
        data: Optional[dict] = None,
        context: Optional[dict] = None,
    ) -> None:
        """Send an arbitrary bus message to the hub.

        Args:
            msg_type: The OVOS message bus message type string.
            data: Message data payload.
            context: Message context (session, routing, etc.).
        """
        bus_payload = {
            "type": msg_type,
            "data": data or {},
            "context": context or {
                "session": {"session_id": self._session_id},
                "site_id": self.site_id,
            },
        }
        await self._send_encrypted("bus", bus_payload)

    async def send_binary(self, bin_type: int, data: bytes) -> None:
        """Send a binary frame to the hub.

        Args:
            bin_type: Application-defined binary payload type identifier.
            data: Raw binary payload.
        """
        encoded = binary_encode(MSG_BINARY, bin_type, b"{}", data)
        if self._noise_transport is not None:
            # protocol v3: binary-marker Noise transport frame (§3.4.5)
            await self._send(self._noise_transport.encrypt_frame(encoded))
        elif self._key is not None and self._cipher is not None:
            encrypted = encrypt_json(self._key, encoded, self._cipher, self._encoding)
            await self._send(encrypted)
        else:
            raise RuntimeError("Session key not established")
