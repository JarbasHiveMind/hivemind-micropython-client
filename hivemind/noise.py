"""HiveMind protocol v3 — Noise handshake (HIVEMIND-CRYPTO-1 §3.4).

Pure-Python implementation of the Noise Protocol Framework (revision 34)
subset HiveMind registers, runnable on MicroPython 1.20+ and CPython 3.10+
with no native crypto dependencies:

- ``Noise_XXpsk2_25519_ChaChaPoly_SHA256`` — general case (MUST-support):
  static keys are exchanged inside the handshake; TOFU-then-pin.
- ``Noise_KKpsk0_25519_ChaChaPoly_SHA256`` — pre-provisioned static keys.

Building blocks:

- **X25519** — RFC 7748 Montgomery ladder, pure Python big-int arithmetic.
  Slow on a microcontroller, but it only runs a handful of times per
  handshake (once per DH token plus key generation).
- **ChaCha20-Poly1305** — the pure-Python AEAD from :mod:`hivemind.crypto`,
  with the Noise ChaChaPoly nonce: 4 zero bytes followed by the 64-bit
  **little-endian** cipherstate counter.
- **SHA-256 / HMAC-SHA256 / HKDF** — HKDF chained from
  :func:`hivemind.crypto.hmac_sha256` per Noise spec §4.3.

The PSK is **provisioned** (HIVEMIND-CRYPTO-1 §3.4.4): a constrained node
never derives it on-device — argon2id is infeasible here. Compute it once
on a capable host (``hivemind-core derive-psk``, equal to
``argon2id(password, SHA-256(node_id))``) and store the 32 bytes in config.
"""

from __future__ import annotations

import struct
from typing import List, Optional, Tuple

try:
    import ujson as json  # type: ignore[import]
except ImportError:
    import json  # type: ignore[no-redef]

from hivemind.crypto import ChaCha20Poly1305, hmac_sha256, randbytes, sha256

# ---------------------------------------------------------------------------
# Registered patterns and suites (HIVEMIND-CRYPTO-1 §3.4.1-§3.4.2)
# ---------------------------------------------------------------------------

NOISE_PATTERN_XX = "XXpsk2"
NOISE_PATTERN_KK = "KKpsk0"

# suites this client can run (pure-Python ChaCha20-Poly1305 only)
NOISE_SUITES = ["25519_ChaChaPoly_SHA256"]

PROTOCOL_V3 = 3

# transport frame markers (first plaintext byte) — must match
# hivemind_bus_client.noise._FRAME_JSON / _FRAME_BINARY
FRAME_JSON = 0x00
FRAME_BINARY = 0x01

# Noise reserved nonce maximum (spec §5.1): rekey or reconnect before this
_MAX_NONCE = (1 << 64) - 1


def noise_protocol_name(pattern: str, suite: str) -> str:
    """Full Noise protocol name for a pattern + suite selection."""
    return "Noise_{}_{}".format(pattern, suite)


def select_noise_options(
    server_patterns: List[str],
    server_suites: List[str],
    pinned_remote_key: Optional[bytes] = None,
) -> Optional[Tuple[str, str]]:
    """Pick the handshake pattern and suite from the server's lists.

    ``KKpsk0`` is preferred when the server's static key is already
    pinned/provisioned (§3.4.2); otherwise ``XXpsk2``. Returns
    ``(pattern, suite)`` or ``None`` when there is no mutual option.
    """
    suite = None
    for s in NOISE_SUITES:
        if s in (server_suites or []):
            suite = s
            break
    if suite is None:
        return None
    if pinned_remote_key and NOISE_PATTERN_KK in (server_patterns or []):
        return (NOISE_PATTERN_KK, suite)
    if NOISE_PATTERN_XX in (server_patterns or []):
        return (NOISE_PATTERN_XX, suite)
    return None


def canonical_json(payload: dict) -> bytes:
    """Serialize *payload* byte-identically to Python's
    ``json.dumps(payload, sort_keys=True, separators=(",", ":"),
    ensure_ascii=False)`` — both peers must produce the same prologue bytes.
    """
    return _canon_value(payload).encode("utf-8")


def _canon_value(value) -> str:
    """Recursive canonical-JSON serializer (MicroPython ujson lacks
    ``sort_keys``, so sorting is done by hand)."""
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(
            _canon_string(k) + ":" + _canon_value(v) for k, v in items
        ) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canon_value(v) for v in value) + "]"
    if isinstance(value, str):
        return _canon_string(value)
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    # numbers: json.dumps int/float repr
    return json.dumps(value)


def _canon_string(s: str) -> str:
    """JSON string literal with ``ensure_ascii=False`` semantics."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append("\\u{:04x}".format(o))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def build_prologue(
    hello_payload: dict,
    handshake_payload: dict,
    protocol_name: str,
) -> bytes:
    """Prologue per HIVEMIND-CRYPTO-1 §3.4.3: the exact canonical-JSON bytes
    of the server's cleartext ``HELLO`` payload, its cleartext parameter
    ``HANDSHAKE`` payload, then the node's selected Noise protocol name."""
    return (
        canonical_json(hello_payload or {})
        + canonical_json(handshake_payload or {})
        + protocol_name.encode("utf-8")
    )


# ---------------------------------------------------------------------------
# X25519 (RFC 7748) — pure Python Montgomery ladder
# ---------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def _clamp_scalar(k: bytes) -> int:
    """RFC 7748 §5 scalar clamping (decodeScalar25519)."""
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(bytes(b), "little")


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """X25519 Diffie-Hellman: 32-byte private x 32-byte public -> 32 bytes."""
    if len(private_key) != 32 or len(public_key) != 32:
        raise ValueError("X25519 keys must be 32 bytes")
    k = _clamp_scalar(private_key)
    # decodeUCoordinate: mask the unused high bit
    u = int.from_bytes(public_key, "little") & ((1 << 255) - 1)

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = (da + cb) % _P
        x3 = (x3 * x3) % _P
        z3 = (da - cb) % _P
        z3 = (x1 * z3 * z3) % _P
        x2 = (aa * bb) % _P
        z2 = (e * (aa + _A24 * e)) % _P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2

    result = (x2 * pow(z2, _P - 2, _P)) % _P
    return result.to_bytes(32, "little")


def x25519_public_key(private_key: bytes) -> bytes:
    """Public key for a 32-byte X25519 private key (base point u=9)."""
    return x25519(private_key, (9).to_bytes(32, "little"))


def x25519_generate_private() -> bytes:
    """Generate a random 32-byte X25519 private key (clamped on use)."""
    return randbytes(32)


# ---------------------------------------------------------------------------
# Noise HKDF (spec §4.3) — chained HMAC-SHA256
# ---------------------------------------------------------------------------

def noise_hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int) -> Tuple[bytes, ...]:
    """HKDF(chaining_key, input_key_material) with 2 or 3 32-byte outputs."""
    temp_key = hmac_sha256(chaining_key, ikm)
    out1 = hmac_sha256(temp_key, b"\x01")
    out2 = hmac_sha256(temp_key, out1 + b"\x02")
    if num_outputs == 2:
        return (out1, out2)
    out3 = hmac_sha256(temp_key, out2 + b"\x03")
    return (out1, out2, out3)


# ---------------------------------------------------------------------------
# CipherState (spec §5.1) — ChaChaPoly with the LE counter nonce
# ---------------------------------------------------------------------------

class CipherState:
    """Noise CipherState: ChaCha20-Poly1305 keyed by ``k`` with the implicit
    monotonic 64-bit nonce counter ``n``.

    The ChaChaPoly nonce is 4 zero bytes followed by ``n`` encoded as a
    64-bit **little-endian** integer (Noise spec §12.2). The counter only
    advances on success, and a message that fails to decrypt at the current
    counter is rejected and never retried under another nonce (§3.4.5).
    """

    def __init__(self) -> None:
        self._k: Optional[bytes] = None
        self.n: int = 0

    def initialize_key(self, key: Optional[bytes]) -> None:
        """Set the cipher key and reset the nonce counter."""
        self._k = key
        self.n = 0

    @property
    def has_key(self) -> bool:
        """True once a key has been established."""
        return self._k is not None

    @staticmethod
    def _nonce(n: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack("<Q", n)

    def encrypt_with_ad(self, ad: bytes, plaintext: bytes) -> bytes:
        """AEAD-encrypt *plaintext*; returns ``ciphertext || tag``."""
        if self._k is None:
            return plaintext
        if self.n >= _MAX_NONCE:
            raise ValueError("Noise nonce exhausted — rekey or reconnect")
        ct, tag = ChaCha20Poly1305(self._k).encrypt(
            plaintext, self._nonce(self.n), aad=ad)
        self.n += 1
        return ct + tag

    def decrypt_with_ad(self, ad: bytes, data: bytes) -> bytes:
        """AEAD-decrypt ``ciphertext || tag``; raises ``ValueError`` on any
        authentication failure (tampering, replay, reordering). The counter
        is **not** advanced on failure (Noise spec §5.1)."""
        if self._k is None:
            return data
        if self.n >= _MAX_NONCE:
            raise ValueError("Noise nonce exhausted — rekey or reconnect")
        if len(data) < 16:
            raise ValueError("Noise ciphertext too short")
        ct, tag = data[:-16], data[-16:]
        plaintext = ChaCha20Poly1305(self._k).decrypt(
            ct, self._nonce(self.n), tag, aad=ad)
        self.n += 1
        return plaintext


# ---------------------------------------------------------------------------
# SymmetricState (spec §5.2)
# ---------------------------------------------------------------------------

class SymmetricState:
    """Noise SymmetricState: the chaining key ``ck`` and handshake hash ``h``."""

    def __init__(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= 32:
            self.h = protocol_name + b"\x00" * (32 - len(protocol_name))
        else:
            self.h = sha256(protocol_name)
        self.ck = self.h
        self.cipher = CipherState()

    def mix_hash(self, data: bytes) -> None:
        """h = SHA256(h || data)."""
        self.h = sha256(self.h + data)

    def mix_key(self, ikm: bytes) -> None:
        """(ck, temp_k) = HKDF(ck, ikm, 2); key the cipher with temp_k."""
        self.ck, temp_k = noise_hkdf(self.ck, ikm, 2)
        self.cipher.initialize_key(temp_k)

    def mix_key_and_hash(self, ikm: bytes) -> None:
        """(ck, temp_h, temp_k) = HKDF(ck, ikm, 3) — the psk token."""
        self.ck, temp_h, temp_k = noise_hkdf(self.ck, ikm, 3)
        self.mix_hash(temp_h)
        self.cipher.initialize_key(temp_k)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        """Encrypt with ``h`` as AD, then mix the ciphertext into ``h``."""
        ciphertext = self.cipher.encrypt_with_ad(self.h, plaintext)
        self.mix_hash(ciphertext)
        return ciphertext

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        """Decrypt with ``h`` as AD, then mix the ciphertext into ``h``."""
        plaintext = self.cipher.decrypt_with_ad(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return plaintext

    def split(self) -> Tuple[CipherState, CipherState]:
        """Derive the two transport CipherStates (spec §5.2)."""
        k1, k2 = noise_hkdf(self.ck, b"", 2)
        c1 = CipherState()
        c1.initialize_key(k1)
        c2 = CipherState()
        c2.initialize_key(k2)
        return (c1, c2)


# ---------------------------------------------------------------------------
# HandshakeState (spec §5.3) — initiator role only (the node is always the
# Noise initiator; the server is the responder — §3.4.3)
# ---------------------------------------------------------------------------

# psk-modified message token scripts (Noise spec §9)
_MESSAGE_PATTERNS = {
    # e / e,ee,s,es,psk / s,se
    NOISE_PATTERN_XX: [
        ["e"],
        ["e", "ee", "s", "es", "psk"],
        ["s", "se"],
    ],
    # psk,e,es,ss / e,ee,se
    NOISE_PATTERN_KK: [
        ["psk", "e", "es", "ss"],
        ["e", "ee", "se"],
    ],
}


class NoiseHandshakeError(ValueError):
    """Fatal Noise handshake failure — wrong PSK/password, tampered
    negotiation (prologue mismatch), bad static key, or protocol misuse."""


class NoiseHandshake:
    """Initiator-side Noise handshake for the registered HiveMind patterns.

    Step with :meth:`write_message` / :meth:`read_message`; after
    :attr:`finished`, wrap in :class:`NoiseTransport` (which calls
    :meth:`split`). The remote static key learned during an ``XXpsk2``
    handshake is exposed via :attr:`remote_static_key` for TOFU pinning.
    """

    def __init__(
        self,
        pattern: str,
        psk: bytes,
        prologue: bytes = b"",
        suite: str = "25519_ChaChaPoly_SHA256",
        static_private: Optional[bytes] = None,
        remote_static: Optional[bytes] = None,
        ephemeral_private: Optional[bytes] = None,
    ) -> None:
        """
        Args:
            pattern: ``"XXpsk2"`` or ``"KKpsk0"``.
            psk: The provisioned 32-byte pre-shared key (§3.4.4).
            prologue: Prologue bytes (see :func:`build_prologue`); both
                peers must supply identical bytes or the handshake aborts.
            suite: Cipher suite name; only ``25519_ChaChaPoly_SHA256``.
            static_private: This node's static X25519 private key
                (generated when omitted; persist it for a stable identity).
            remote_static: The server's static X25519 public key —
                required for ``KKpsk0``.
            ephemeral_private: Fixed ephemeral private key — deterministic
                interop tests ONLY, never production.
        """
        if suite not in NOISE_SUITES:
            raise NoiseHandshakeError("unsupported Noise suite: " + suite)
        if pattern not in _MESSAGE_PATTERNS:
            raise NoiseHandshakeError("unsupported Noise pattern: " + pattern)
        if len(psk) != 32:
            raise NoiseHandshakeError("Noise PSK must be exactly 32 bytes")
        if pattern == NOISE_PATTERN_KK and not remote_static:
            raise NoiseHandshakeError("KKpsk0 requires the remote static key")

        self.pattern = pattern
        self.protocol_name = noise_protocol_name(pattern, suite)
        self._psk = psk
        self._script = _MESSAGE_PATTERNS[pattern]
        self._msg_index = 0
        self.finished = False

        self._s_priv = static_private or x25519_generate_private()
        self.static_public = x25519_public_key(self._s_priv)
        self._e_priv = ephemeral_private  # generated lazily on first "e"
        self._e_pub: Optional[bytes] = None
        self._re: Optional[bytes] = None  # remote ephemeral
        self.remote_static_key: Optional[bytes] = remote_static

        self.symmetric = SymmetricState(self.protocol_name.encode("utf-8"))
        self.symmetric.mix_hash(prologue)

        # pre-messages: KK is "s / s" — initiator's static first (spec §7.2)
        if pattern == NOISE_PATTERN_KK:
            self.symmetric.mix_hash(self.static_public)
            self.symmetric.mix_hash(remote_static)

    # -- token processing ---------------------------------------------------

    def _dh(self, local_private: bytes, remote_public: bytes) -> None:
        shared = x25519(local_private, remote_public)
        self.symmetric.mix_key(shared)

    def _process_write_token(self, token: str, out: bytearray) -> None:
        if token == "e":
            if self._e_priv is None:
                self._e_priv = x25519_generate_private()
            self._e_pub = x25519_public_key(self._e_priv)
            out.extend(self._e_pub)
            self.symmetric.mix_hash(self._e_pub)
            # psk mode: MixKey(e.public_key) on every "e" (spec §9.1)
            self.symmetric.mix_key(self._e_pub)
        elif token == "s":
            out.extend(self.symmetric.encrypt_and_hash(self.static_public))
        elif token == "ee":
            self._dh(self._e_priv, self._re)
        elif token == "es":  # initiator: DH(e, rs)
            self._dh(self._e_priv, self.remote_static_key)
        elif token == "se":  # initiator: DH(s, re)
            self._dh(self._s_priv, self._re)
        elif token == "ss":
            self._dh(self._s_priv, self.remote_static_key)
        elif token == "psk":
            self.symmetric.mix_key_and_hash(self._psk)
        else:
            raise NoiseHandshakeError("unknown Noise token: " + token)

    def _process_read_token(self, token: str, data: bytes, offset: int) -> int:
        if token == "e":
            self._re = data[offset:offset + 32]
            if len(self._re) != 32:
                raise NoiseHandshakeError("truncated Noise handshake message")
            offset += 32
            self.symmetric.mix_hash(self._re)
            self.symmetric.mix_key(self._re)  # psk mode
        elif token == "s":
            length = 48 if self.symmetric.cipher.has_key else 32
            chunk = data[offset:offset + length]
            if len(chunk) != length:
                raise NoiseHandshakeError("truncated Noise handshake message")
            offset += length
            self.remote_static_key = self.symmetric.decrypt_and_hash(chunk)
        elif token == "ee":
            self._dh(self._e_priv, self._re)
        elif token == "es":  # initiator: DH(e, rs)
            self._dh(self._e_priv, self.remote_static_key)
        elif token == "se":  # initiator: DH(s, re)
            self._dh(self._s_priv, self._re)
        elif token == "ss":
            self._dh(self._s_priv, self.remote_static_key)
        elif token == "psk":
            self.symmetric.mix_key_and_hash(self._psk)
        else:
            raise NoiseHandshakeError("unknown Noise token: " + token)
        return offset

    # -- public stepping API --------------------------------------------------

    def write_message(self, payload: bytes = b"") -> bytes:
        """Produce the next handshake message (initiator writes even-indexed
        messages: 1, 3, ...)."""
        if self.finished or self._msg_index % 2 != 0:
            raise NoiseHandshakeError("Noise: not our turn to write")
        out = bytearray()
        for token in self._script[self._msg_index]:
            self._process_write_token(token, out)
        out.extend(self.symmetric.encrypt_and_hash(payload))
        self._msg_index += 1
        if self._msg_index == len(self._script):
            self.finished = True
        return bytes(out)

    def read_message(self, data: bytes) -> bytes:
        """Consume a handshake message from the responder. Raises
        :class:`NoiseHandshakeError` on any authentication failure — wrong
        PSK/password, mismatched prologue, or a tampered message."""
        if self.finished or self._msg_index % 2 != 1:
            raise NoiseHandshakeError("Noise: not our turn to read")
        offset = 0
        try:
            for token in self._script[self._msg_index]:
                offset = self._process_read_token(token, data, offset)
            payload = self.symmetric.decrypt_and_hash(data[offset:])
        except ValueError as e:
            raise NoiseHandshakeError(
                "Noise handshake authentication failure: {}".format(e))
        self._msg_index += 1
        if self._msg_index == len(self._script):
            self.finished = True
        return payload

    @property
    def handshake_hash(self) -> Optional[bytes]:
        """The final handshake hash ``h`` (32 bytes) for channel binding."""
        if not self.finished:
            return None
        return self.symmetric.h

    def split(self) -> Tuple[CipherState, CipherState]:
        """Return ``(send, recv)`` transport CipherStates (initiator order)."""
        if not self.finished:
            raise NoiseHandshakeError("Noise handshake not finished")
        return self.symmetric.split()


# ---------------------------------------------------------------------------
# NoiseTransport (§3.4.5) — post-Split() session encryption
# ---------------------------------------------------------------------------

class NoiseTransport:
    """Session encryption for an established protocol v3 connection.

    Every post-handshake message is a Noise transport message; the first
    plaintext byte is a frame marker (``0x00`` JSON / ``0x01`` binary) —
    must match ``hivemind_bus_client.noise.NoiseTransport``.
    """

    def __init__(self, handshake: NoiseHandshake) -> None:
        if not handshake.finished:
            raise NoiseHandshakeError("Noise handshake not finished")
        self.send_cipher, self.recv_cipher = handshake.split()
        self.remote_static_key = handshake.remote_static_key
        self.handshake_hash = handshake.handshake_hash

    def encrypt_frame(self, payload) -> bytes:
        """Encrypt a JSON string or binary bytes into a transport frame."""
        if isinstance(payload, str):
            plaintext = bytes([FRAME_JSON]) + payload.encode("utf-8")
        else:
            plaintext = bytes([FRAME_BINARY]) + bytes(payload)
        return self.send_cipher.encrypt_with_ad(b"", plaintext)

    def decrypt_frame(self, data: bytes):
        """Decrypt a transport frame; returns ``str`` (JSON frame) or
        ``bytes`` (binary frame). Raises ``ValueError`` on any AEAD failure
        (tampering / replay / reordering) — fatal, never retried (§3.4.5)."""
        plaintext = self.recv_cipher.decrypt_with_ad(b"", data)
        if not plaintext:
            raise ValueError("empty v3 transport frame")
        marker = plaintext[0]
        body = plaintext[1:]
        if marker == FRAME_JSON:
            return body.decode("utf-8")
        if marker == FRAME_BINARY:
            return body
        raise ValueError("unknown v3 frame marker: {}".format(marker))
