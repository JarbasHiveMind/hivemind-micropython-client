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
)
from hivemind.binary import encode as binary_encode, decode as binary_decode

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
        preferred_cipher: str = "AES-GCM",
        preferred_encoding: str = "JSON-HEX",
        reconnect_ms: int = 5000,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.username: str = username
        self.access_key: str = access_key
        self.password: str = password
        self.site_id: str = site_id
        self.preferred_cipher: str = preferred_cipher
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

    async def _send(self, data: str) -> None:
        """Send a text frame over the websocket."""
        if self._ws is None:
            raise ConnectionError("WebSocket not connected")
        if _MICROPYTHON:
            self._ws.write(data)  # type: ignore[union-attr]
        else:
            await self._ws.send(data)  # type: ignore[union-attr]

    async def _send_encrypted(self, msg_type: str, payload: dict) -> None:
        """Encrypt an envelope and send it over the websocket."""
        if self._key is None or self._cipher is None:
            raise RuntimeError("Session key not established")
        envelope = self._build_envelope(msg_type, payload)
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
                    raw = raw.decode() if isinstance(raw, bytes) else raw
                else:
                    raw = await self._ws.recv()  # type: ignore[union-attr]
                    if raw is None:
                        break

                if self.state < STATE_READY:
                    await self._handle_handshake(raw)
                else:
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
            self._set_state(STATE_HELLO_RECEIVED)

        elif self.state == STATE_HELLO_RECEIVED and msg_type == "shake":
            if not payload.get("handshake"):
                return
            # Generate client hsub
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

    # -- message dispatch ---------------------------------------------------

    async def _dispatch_message(self, raw: str) -> None:
        """Decrypt and dispatch a message received in READY state."""
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
        if self._key is not None and self._cipher is not None:
            encrypted = encrypt_json(self._key, encoded, self._cipher, self._encoding)
            await self._send(encrypted)
        else:
            raise RuntimeError("Session key not established")
