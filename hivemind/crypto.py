"""Pure Python cryptographic primitives for HiveMind MicroPython client.

Works on MicroPython 1.20+ and CPython 3.10+. Prefers C-accelerated or
``cryptography`` backends when available; falls back to pure Python.

Implements: HMAC-SHA256, PBKDF2, AES-256-GCM, ChaCha20-Poly1305,
hsub generation, key derivation, and JSON encrypt/decrypt helpers
with support for all 7 HiveMind encodings (HEX, B64, URLSAFE-B64,
B32, Z85B, Z85P, B91).
"""

from __future__ import annotations

import struct
from typing import Tuple

# ---------------------------------------------------------------------------
# Platform-adaptive imports
# ---------------------------------------------------------------------------

try:
    from _hivemind_crypto import (
        aes_gcm_encrypt,
        aes_gcm_decrypt,
        chacha20_encrypt as _c_chacha_encrypt,
        chacha20_decrypt as _c_chacha_decrypt,
        pbkdf2 as _c_pbkdf2,
    )
    _HAVE_C_MODULE = True
except ImportError:
    _HAVE_C_MODULE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM,
        ChaCha20Poly1305 as _CPyChaCha,
    )
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

try:
    from uhashlib import sha256 as _sha256_cls
    from ucryptolib import aes as _aes_ecb  # type: ignore[import]
    import uos as os  # type: ignore[import]

    def randbytes(n: int) -> bytes:
        """Return *n* random bytes (MicroPython)."""
        return os.urandom(n)
except ImportError:
    import hashlib
    import os

    _sha256_cls = None
    _aes_ecb = None

    def randbytes(n: int) -> bytes:  # type: ignore[misc]
        """Return *n* random bytes (CPython)."""
        return os.urandom(n)

try:
    import ujson as json  # type: ignore[import]
except ImportError:
    import json  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# SHA-256 wrapper
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Return SHA-256 digest of *data* (32 bytes)."""
    if _sha256_cls is not None:
        h = _sha256_cls(data)
        return h.digest()
    import hashlib as _hl
    return _hl.sha256(data).digest()


# ---------------------------------------------------------------------------
# HMAC-SHA256 (pure Python – MicroPython lacks ``hmac``)
# ---------------------------------------------------------------------------

_HMAC_BLOCK = 64


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Compute HMAC-SHA256(*key*, *msg*) and return 32-byte digest."""
    if len(key) > _HMAC_BLOCK:
        key = sha256(key)
    key = key + b"\x00" * (_HMAC_BLOCK - len(key))

    o_key_pad = bytes(b ^ 0x5C for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)

    inner = sha256(i_key_pad + msg)
    return sha256(o_key_pad + inner)


# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SHA256 (pure Python)
# ---------------------------------------------------------------------------

def pbkdf2_hmac_sha256(
    password: bytes,
    salt: bytes,
    iterations: int,
    dklen: int = 32,
) -> bytes:
    """Derive *dklen* bytes using PBKDF2 with HMAC-SHA256.

    Only a single block (dklen <= 32) is needed for HiveMind key derivation.
    Multiple blocks are supported for correctness.
    """
    if _HAVE_C_MODULE:
        return _c_pbkdf2(password, salt, iterations, dklen)

    dk = b""
    block_num = 1
    while len(dk) < dklen:
        u = hmac_sha256(password, salt + block_num.to_bytes(4, "big"))
        result = u
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            result = bytes(a ^ b for a, b in zip(result, u))
        dk += result
        block_num += 1
    return dk[:dklen]


# ---------------------------------------------------------------------------
# Hsub helpers
# ---------------------------------------------------------------------------

def generate_hsub(password: str) -> Tuple[bytes, str]:
    """Generate an hsub (hidden-subject) token.

    Returns ``(iv, hsub_hex)`` where *iv* is 8 random bytes and *hsub_hex*
    is the first 24 bytes (48 hex chars) of ``iv || SHA256(iv || password)``.
    """
    iv = randbytes(8)
    h = sha256(iv + password.encode())
    hsub_bytes = iv + h
    hsub_hex = hsub_bytes[:24].hex()
    return (iv, hsub_hex)


def extract_iv(hsub_hex: str) -> bytes:
    """Extract the 8-byte IV from an hsub hex string."""
    return bytes.fromhex(hsub_hex[:16])


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def derive_key(password: str, client_iv: bytes, server_iv: bytes) -> bytes:
    """Derive a 32-byte symmetric key from *password* and both IVs.

    The salt is the XOR of the two 8-byte IVs.  PBKDF2 with 100 000
    iterations is applied.
    """
    salt = bytes(a ^ b for a, b in zip(client_iv, server_iv))
    return pbkdf2_hmac_sha256(password.encode(), salt, 100_000, 32)


# ---------------------------------------------------------------------------
# AES-256-GCM (pure Python over AES-ECB)
# ---------------------------------------------------------------------------

class AesGcm:
    """AES-256-GCM using AES-ECB as the block cipher primitive.

    Provides authenticated encryption.  The pure-Python path is slow but
    correct; prefer ``_hivemind_crypto`` or ``cryptography`` when available.
    """

    NONCE_SIZE: int = 16
    TAG_SIZE: int = 16

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self._key = key

    # -- low-level helpers ------------------------------------------------

    def _aes_ecb_encrypt(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block with AES-ECB."""
        if _aes_ecb is not None:
            cipher = _aes_ecb(self._key, 1)  # 1 = ECB
            return cipher.encrypt(block)
        # CPython fallback via cryptography
        if _HAVE_CRYPTOGRAPHY:
            from cryptography.hazmat.primitives.ciphers import (
                Cipher,
                algorithms,
                modes,
            )
            enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
            return enc.update(block) + enc.finalize()
        raise RuntimeError("No AES-ECB backend available")

    @staticmethod
    def _inc32(counter: bytes) -> bytes:
        """Increment the last 4 bytes of *counter* as a big-endian integer."""
        prefix = counter[:12]
        ctr = int.from_bytes(counter[12:], "big")
        ctr = (ctr + 1) & 0xFFFFFFFF
        return prefix + ctr.to_bytes(4, "big")

    def _gctr(self, icb: bytes, data: bytes) -> bytes:
        """GCTR mode: XOR *data* with keystream blocks starting at *icb*."""
        if not data:
            return b""
        out = bytearray()
        cb = icb
        for i in range(0, len(data), 16):
            ks = self._aes_ecb_encrypt(cb)
            chunk = data[i : i + 16]
            out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
            cb = self._inc32(cb)
        return bytes(out)

    # -- GF(2^128) arithmetic --------------------------------------------

    @staticmethod
    def _gf_mult(x: int, y: int) -> int:
        """Multiply *x* and *y* in GF(2^128) with the GCM reduction polynomial."""
        # R = 0xE1000000000000000000000000000000
        R = 0xE1000000000000000000000000000000
        z = 0
        v = y
        for i in range(128):
            if (x >> (127 - i)) & 1:
                z ^= v
            carry = v & 1
            v >>= 1
            if carry:
                v ^= R
        return z

    def _ghash(self, h_int: int, aad: bytes, ciphertext: bytes) -> bytes:
        """Compute GHASH over *aad* and *ciphertext* with hash sub-key *h_int*."""

        def _pad16(d: bytes) -> bytes:
            r = len(d) % 16
            return d + b"\x00" * ((16 - r) % 16) if r else d

        data = _pad16(aad) + _pad16(ciphertext)
        data += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

        y = 0
        for i in range(0, len(data), 16):
            block = int.from_bytes(data[i : i + 16], "big")
            y = self._gf_mult(y ^ block, h_int)
        return y.to_bytes(16, "big")

    # -- public API -------------------------------------------------------

    def encrypt(self, plaintext: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt *plaintext* with *nonce*. Returns ``(ciphertext, tag)``."""
        h = self._aes_ecb_encrypt(b"\x00" * 16)
        h_int = int.from_bytes(h, "big")

        # J0: use first 12 bytes of nonce as IV
        j0 = nonce[:12] + b"\x00\x00\x00\x01"

        ciphertext = self._gctr(self._inc32(j0), plaintext)
        ghash_val = self._ghash(h_int, b"", ciphertext)
        tag = self._gctr(j0, ghash_val)
        return (ciphertext, tag)

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt *ciphertext*. Raises ``ValueError`` on auth failure."""
        h = self._aes_ecb_encrypt(b"\x00" * 16)
        h_int = int.from_bytes(h, "big")

        j0 = nonce[:12] + b"\x00\x00\x00\x01"

        ghash_val = self._ghash(h_int, b"", ciphertext)
        expected_tag = self._gctr(j0, ghash_val)
        if expected_tag != tag:
            raise ValueError("AES-GCM authentication failed")

        return self._gctr(self._inc32(j0), ciphertext)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 (pure Python)
# ---------------------------------------------------------------------------

class ChaCha20Poly1305:
    """ChaCha20-Poly1305 AEAD cipher (RFC 8439).

    Pure-Python implementation for MicroPython; falls back to
    ``cryptography`` on CPython when available.
    """

    NONCE_SIZE: int = 12
    TAG_SIZE: int = 16

    _CONSTANTS: Tuple[int, int, int, int] = (
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
    )

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("ChaCha20 requires a 32-byte key")
        self._key = key

    # -- ChaCha20 primitives ---------------------------------------------

    @staticmethod
    def _rotl32(v: int, n: int) -> int:
        """32-bit left rotate."""
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    @classmethod
    def _quarter_round(
        cls,
        s: list[int],
        a: int,
        b: int,
        c: int,
        d: int,
    ) -> None:
        """Perform a ChaCha20 quarter round in-place on state *s*."""
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = cls._rotl32(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = cls._rotl32(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = cls._rotl32(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = cls._rotl32(s[b], 7)

    @classmethod
    def _chacha20_block(cls, key: bytes, counter: int, nonce: bytes) -> bytes:
        """Generate one 64-byte ChaCha20 keystream block."""
        k = struct.unpack("<8I", key)
        n = struct.unpack("<3I", nonce)
        state = list(cls._CONSTANTS) + list(k) + [counter & 0xFFFFFFFF] + list(n)
        working = list(state)

        for _ in range(10):  # 20 rounds = 10 double-rounds
            # column rounds
            cls._quarter_round(working, 0, 4, 8, 12)
            cls._quarter_round(working, 1, 5, 9, 13)
            cls._quarter_round(working, 2, 6, 10, 14)
            cls._quarter_round(working, 3, 7, 11, 15)
            # diagonal rounds
            cls._quarter_round(working, 0, 5, 10, 15)
            cls._quarter_round(working, 1, 6, 11, 12)
            cls._quarter_round(working, 2, 7, 8, 13)
            cls._quarter_round(working, 3, 4, 9, 14)

        out = struct.pack(
            "<16I",
            *((working[i] + state[i]) & 0xFFFFFFFF for i in range(16)),
        )
        return out

    @classmethod
    def _chacha20_encrypt(
        cls,
        key: bytes,
        counter: int,
        nonce: bytes,
        data: bytes,
    ) -> bytes:
        """Encrypt (or decrypt) *data* with ChaCha20."""
        out = bytearray()
        for i in range(0, len(data), 64):
            ks = cls._chacha20_block(key, counter + i // 64, nonce)
            chunk = data[i : i + 64]
            out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        return bytes(out)

    # -- Poly1305 MAC ----------------------------------------------------

    @staticmethod
    def _poly1305_mac(key: bytes, data: bytes) -> bytes:
        """Compute Poly1305 MAC over *data* using 32-byte *key*."""
        r = int.from_bytes(key[:16], "little")
        # clamp r
        r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        s = int.from_bytes(key[16:32], "little")
        p = (1 << 130) - 5

        acc = 0
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            n = int.from_bytes(chunk, "little") | (1 << (len(chunk) * 8))
            acc = (acc + n) * r % p
        acc = (acc + s) & ((1 << 128) - 1)
        return acc.to_bytes(16, "little")

    @classmethod
    def _poly1305_aead(
        cls,
        poly_key: bytes,
        aad: bytes,
        ciphertext: bytes,
    ) -> bytes:
        """Poly1305 tag over AAD and ciphertext per RFC 8439 s2.8."""

        def _pad16(d: bytes) -> bytes:
            r = len(d) % 16
            return d + b"\x00" * ((16 - r) % 16) if r else d

        mac_data = (
            _pad16(aad)
            + _pad16(ciphertext)
            + struct.pack("<QQ", len(aad), len(ciphertext))
        )
        return cls._poly1305_mac(poly_key, mac_data)

    # -- public API -------------------------------------------------------

    def encrypt(self, plaintext: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
        """Encrypt *plaintext* with *nonce*. Returns ``(ciphertext, tag)``."""
        poly_key = self._chacha20_block(self._key, 0, nonce)[:32]
        ciphertext = self._chacha20_encrypt(self._key, 1, nonce, plaintext)
        tag = self._poly1305_aead(poly_key, b"", ciphertext)
        return (ciphertext, tag)

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
    ) -> bytes:
        """Decrypt *ciphertext*. Raises ``ValueError`` on auth failure."""
        poly_key = self._chacha20_block(self._key, 0, nonce)[:32]
        expected_tag = self._poly1305_aead(poly_key, b"", ciphertext)
        if expected_tag != tag:
            raise ValueError("ChaCha20-Poly1305 authentication failed")
        return self._chacha20_encrypt(self._key, 1, nonce, ciphertext)


# ---------------------------------------------------------------------------
# Encoding support (7 HiveMind encodings)
# ---------------------------------------------------------------------------

# Base64 imports: MicroPython uses ubinascii, CPython uses base64
try:
    from ubinascii import b2a_base64, a2b_base64  # type: ignore[import]
    _HAVE_UBINASCII = True
except ImportError:
    _HAVE_UBINASCII = False

try:
    import base64 as _base64
    _HAVE_BASE64 = True
except ImportError:
    _HAVE_BASE64 = False

# Z85B, Z85P, B91: optional dependency
try:
    from z85base91 import Z85B as _Z85B, Z85P as _Z85P, B91 as _B91
    _HAVE_Z85B91 = True
except ImportError:
    _HAVE_Z85B91 = False


def _b64_encode(data: bytes) -> bytes:
    """Encode bytes to base64."""
    if _HAVE_BASE64:
        return _base64.b64encode(data)
    if _HAVE_UBINASCII:
        return b2a_base64(data).rstrip(b"\n")
    raise RuntimeError("No base64 backend available")


def _b64_decode(data: bytes | str) -> bytes:
    """Decode base64 to bytes."""
    if isinstance(data, str):
        data = data.encode("ascii")
    if _HAVE_BASE64:
        return _base64.b64decode(data)
    if _HAVE_UBINASCII:
        return a2b_base64(data)
    raise RuntimeError("No base64 backend available")


def get_encoder(encoding: str):
    """Return an encoder callable ``(bytes) -> bytes`` for the given encoding.

    Supported encodings: ``JSON-HEX``, ``JSON-B64``, ``JSON-URLSAFE-B64``,
    ``JSON-B32``, ``JSON-Z85B``, ``JSON-Z85P``, ``JSON-B91``.
    """
    if encoding == "JSON-HEX":
        def _hex_enc(data: bytes) -> bytes:
            return data.hex().encode("ascii")
        return _hex_enc
    elif encoding == "JSON-B64":
        return _b64_encode
    elif encoding == "JSON-URLSAFE-B64":
        if not _HAVE_BASE64:
            raise RuntimeError("base64 module required for URLSAFE-B64")
        return _base64.urlsafe_b64encode
    elif encoding == "JSON-B32":
        if not _HAVE_BASE64:
            raise RuntimeError("base64 module required for B32")
        return _base64.b32encode
    elif encoding == "JSON-Z85B":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for Z85B encoding")
        return _Z85B.encode
    elif encoding == "JSON-Z85P":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for Z85P encoding")
        return _Z85P.encode
    elif encoding == "JSON-B91":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for B91 encoding")
        return _B91.encode
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


def get_decoder(encoding: str):
    """Return a decoder callable ``(bytes|str) -> bytes`` for the given encoding.

    Supported encodings: ``JSON-HEX``, ``JSON-B64``, ``JSON-URLSAFE-B64``,
    ``JSON-B32``, ``JSON-Z85B``, ``JSON-Z85P``, ``JSON-B91``.
    """
    if encoding == "JSON-HEX":
        def _hex_dec(data: bytes | str) -> bytes:
            if isinstance(data, bytes):
                data = data.decode("ascii")
            return bytes.fromhex(data)
        return _hex_dec
    elif encoding == "JSON-B64":
        return _b64_decode
    elif encoding == "JSON-URLSAFE-B64":
        if not _HAVE_BASE64:
            raise RuntimeError("base64 module required for URLSAFE-B64")
        return _base64.urlsafe_b64decode
    elif encoding == "JSON-B32":
        if not _HAVE_BASE64:
            raise RuntimeError("base64 module required for B32")
        return _base64.b32decode
    elif encoding == "JSON-Z85B":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for Z85B encoding")
        return _Z85B.decode
    elif encoding == "JSON-Z85P":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for Z85P encoding")
        return _Z85P.decode
    elif encoding == "JSON-B91":
        if not _HAVE_Z85B91:
            raise RuntimeError("z85base91 package required for B91 encoding")
        return _B91.decode
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")


# ---------------------------------------------------------------------------
# JSON encrypt / decrypt helpers
# ---------------------------------------------------------------------------

def encrypt_json(
    key: bytes,
    plaintext: bytes,
    cipher: str = "AES-GCM",
    encoding: str = "JSON-HEX",
) -> str:
    """Encrypt *plaintext* and return a JSON string with encoded fields.

    The JSON object contains ``ciphertext``, ``tag``, and ``nonce`` keys,
    text-encoded according to *encoding*.

    Supported *cipher* values: ``"AES-GCM"`` and ``"ChaCha20-Poly1305"``.
    Supported *encoding* values: ``"JSON-HEX"``, ``"JSON-B64"``,
    ``"JSON-URLSAFE-B64"``, ``"JSON-B32"``, ``"JSON-Z85B"``,
    ``"JSON-Z85P"``, ``"JSON-B91"``.
    """
    if cipher == "AES-GCM":
        if _HAVE_C_MODULE:
            ct, tag, nonce = aes_gcm_encrypt(key, plaintext)
        elif _HAVE_CRYPTOGRAPHY:
            nonce = randbytes(AesGcm.NONCE_SIZE)
            combined = AESGCM(key).encrypt(nonce, plaintext, None)
            ct, tag = combined[:-16], combined[-16:]
        else:
            nonce = randbytes(AesGcm.NONCE_SIZE)
            ct, tag = AesGcm(key).encrypt(plaintext, nonce)
    elif cipher == "ChaCha20-Poly1305":
        if _HAVE_C_MODULE:
            ct, tag, nonce = _c_chacha_encrypt(key, plaintext)
        elif _HAVE_CRYPTOGRAPHY:
            nonce = randbytes(ChaCha20Poly1305.NONCE_SIZE)
            combined = _CPyChaCha(key).encrypt(nonce, plaintext, None)
            ct, tag = combined[:-16], combined[-16:]
        else:
            nonce = randbytes(ChaCha20Poly1305.NONCE_SIZE)
            ct, tag = ChaCha20Poly1305(key).encrypt(plaintext, nonce)
    else:
        raise ValueError(f"Unsupported cipher: {cipher}")

    encode = get_encoder(encoding)

    def _to_str(val: bytes | str) -> str:
        """Ensure encoded value is a string for JSON serialization."""
        if isinstance(val, bytes):
            return val.decode("ascii")
        return val

    return json.dumps({
        "ciphertext": _to_str(encode(ct)),
        "tag": _to_str(encode(tag)),
        "nonce": _to_str(encode(nonce)),
    })


def decrypt_json(
    key: bytes,
    json_str: str,
    cipher: str = "AES-GCM",
    encoding: str = "JSON-HEX",
) -> bytes:
    """Decrypt a JSON payload produced by :func:`encrypt_json`.

    Raises ``ValueError`` on authentication failure or bad input.
    """
    obj = json.loads(json_str)
    decode = get_decoder(encoding)
    ct = decode(obj["ciphertext"])
    tag = decode(obj["tag"])
    nonce = decode(obj["nonce"])

    if cipher == "AES-GCM":
        if _HAVE_C_MODULE:
            return aes_gcm_decrypt(key, ct, tag, nonce)
        if _HAVE_CRYPTOGRAPHY:
            return AESGCM(key).decrypt(nonce, ct + tag, None)
        return AesGcm(key).decrypt(ct, nonce, tag)
    elif cipher == "ChaCha20-Poly1305":
        if _HAVE_C_MODULE:
            return _c_chacha_decrypt(key, ct, tag, nonce)
        if _HAVE_CRYPTOGRAPHY:
            return _CPyChaCha(key).decrypt(nonce, ct + tag, None)
        return ChaCha20Poly1305(key).decrypt(ct, nonce, tag)
    else:
        raise ValueError(f"Unsupported cipher: {cipher}")


# Backwards-compatible aliases
def encrypt_json_hex(
    key: bytes,
    plaintext: bytes,
    cipher: str = "AES-GCM",
) -> str:
    """Encrypt *plaintext* and return a JSON string with hex-encoded fields.

    DEPRECATED: Use :func:`encrypt_json` with ``encoding="JSON-HEX"`` instead.
    Kept for backwards compatibility.
    """
    return encrypt_json(key, plaintext, cipher=cipher, encoding="JSON-HEX")


def decrypt_json_hex(
    key: bytes,
    json_str: str,
    cipher: str = "AES-GCM",
) -> bytes:
    """Decrypt a JSON-hex payload produced by :func:`encrypt_json_hex`.

    DEPRECATED: Use :func:`decrypt_json` with ``encoding="JSON-HEX"`` instead.
    Kept for backwards compatibility.
    """
    return decrypt_json(key, json_str, cipher=cipher, encoding="JSON-HEX")
