"""Protocol-V1 conformance tests against the reference hivemind-bus-client.

These tests cross-check this client's crypto, key derivation, hsub format,
cipher/encoding negotiation strings, and binary framing against the canonical
CPython reference implementation (``hivemind_bus_client``).

The reference package is a hard requirement of the ``[test]`` extra, so these
tests always run in CI — there is no skip-on-missing-dependency path. They are
what guarantees byte-for-byte interop with a real ``hivemind-core`` hub without
needing a board or a network.

Two crypto code paths are validated:

* the ``cryptography``/C-accelerated path (used on CPython / desktop), and
* the *pure-Python* fallback (the path that actually runs on a microcontroller
  with no ``cryptography`` package). The pure-Python AES-GCM and
  ChaCha20-Poly1305 are exercised directly so an on-device regression cannot
  hide behind the faster CPython backend.
"""
import json
import unittest

# Reference implementation (the hub side of the wire).
from hivemind_bus_client.encryption import (
    encrypt_as_json,
    decrypt_from_json,
    SupportedCiphers,
    SupportedEncodings,
)
from hivemind_bus_client.serialization import get_bitstring, decode_bitstring
from hivemind_bus_client.message import (
    HiveMessageType,
    HiveMindBinaryPayloadType,
)
from hivemind_bus_client.util import cast2bytes
from poorman_handshake.symmetric import PasswordHandShake
from poorman_handshake.symmetric.utils import create_hsub, iv_from_hsub

import hivemind.crypto as mc
import hivemind.binary as mb

_KEY = mc.derive_key("conformance-pw", b"\x01" * 8, b"\x02" * 8)
_PLAINTEXT = b'{"msg_type": "bus", "payload": {"type": "speak"}}'


def _force_pure_python(cipher_cls):
    """Install an AES-ECB primitive so the pure-Python AES-GCM can run under
    CPython, simulating MicroPython's ``ucryptolib.aes`` (ECB mode)."""
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
    )

    class _ECB:
        def __init__(self, key, mode):
            self._key = key

        def encrypt(self, block):
            enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
            return enc.update(block) + enc.finalize()

    return _ECB


class _PurePythonCrypto:
    """Context manager that forces ``hivemind.crypto`` onto its pure-Python
    backends (no C module, no ``cryptography``) for the duration of a test."""

    def __enter__(self):
        self._saved = (mc._HAVE_C_MODULE, mc._HAVE_CRYPTOGRAPHY, mc._aes_ecb)
        mc._HAVE_C_MODULE = False
        mc._HAVE_CRYPTOGRAPHY = False
        if mc._aes_ecb is None:
            mc._aes_ecb = _force_pure_python(None)
        return self

    def __exit__(self, *exc):
        mc._HAVE_C_MODULE, mc._HAVE_CRYPTOGRAPHY, mc._aes_ecb = self._saved
        return False


class TestKeyDerivationConformance(unittest.TestCase):
    """Key derivation must match poorman_handshake's PasswordHandShake."""

    def test_derive_key_matches_reference(self):
        """salt = XOR(client_iv, server_iv); PBKDF2-HMAC-SHA256 100k -> 32B."""
        password = "correct horse battery staple 42!"
        # Reference: two peers each pick an IV, derive identical secret.
        client = PasswordHandShake(password)
        server = PasswordHandShake(password)
        client_env = client.generate_handshake()
        server_env = server.generate_handshake()
        client.receive_and_verify(server_env)
        ref_secret = client.secret

        client_iv = iv_from_hsub(client_env)
        server_iv = iv_from_hsub(server_env)
        mc_key = mc.derive_key(password, client_iv, server_iv)

        self.assertEqual(mc_key, ref_secret)
        self.assertEqual(len(mc_key), 32)

    def test_hsub_format_matches_reference(self):
        """hsub = (IV || SHA256(IV||password)) hex, first 48 chars."""
        password = "swordfish"
        iv, mc_hsub = mc.generate_hsub(password)
        ref_hsub = create_hsub(password, iv)  # default hsublen=48
        self.assertEqual(mc_hsub, ref_hsub)
        self.assertEqual(mc.extract_iv(mc_hsub), iv_from_hsub(ref_hsub))


class TestCipherNegotiationStrings(unittest.TestCase):
    """The wire cipher identifiers must byte-match SupportedCiphers."""

    def test_canonical_strings_match_reference_enum(self):
        self.assertEqual(mc.CIPHER_AES_GCM, SupportedCiphers.AES_GCM.value)
        self.assertEqual(
            mc.CIPHER_CHACHA20, SupportedCiphers.CHACHA20_POLY1305.value
        )

    def test_reference_accepts_our_cipher_strings(self):
        """The reference normaliser must accept what we put on the wire."""
        from hivemind_bus_client.encryption import _norm_cipher as ref_norm
        self.assertEqual(
            ref_norm(mc.CIPHER_AES_GCM), SupportedCiphers.AES_GCM
        )
        self.assertEqual(
            ref_norm(mc.CIPHER_CHACHA20), SupportedCiphers.CHACHA20_POLY1305
        )

    def test_legacy_spelling_normalised(self):
        """Old "ChaCha20-Poly1305" callers are coerced to the wire value."""
        self.assertEqual(mc._norm_cipher("ChaCha20-Poly1305"), mc.CIPHER_CHACHA20)


class TestCryptoInteropCryptographyBackend(unittest.TestCase):
    """Interop using the default (cryptography) backend on CPython."""

    _CIPHERS = [
        (mc.CIPHER_AES_GCM, SupportedCiphers.AES_GCM),
        (mc.CIPHER_CHACHA20, SupportedCiphers.CHACHA20_POLY1305),
    ]
    _ENCODINGS = [
        ("JSON-HEX", SupportedEncodings.JSON_HEX),
        ("JSON-B64", SupportedEncodings.JSON_B64),
        ("JSON-B32", SupportedEncodings.JSON_B32),
    ]

    def test_reference_decrypts_our_ciphertext(self):
        for mc_c, ref_c in self._CIPHERS:
            for mc_e, ref_e in self._ENCODINGS:
                with self.subTest(cipher=mc_c, encoding=mc_e):
                    blob = mc.encrypt_json(_KEY, _PLAINTEXT, mc_c, mc_e)
                    out = decrypt_from_json(_KEY, blob, ref_c, ref_e)
                    self.assertEqual(out.encode(), _PLAINTEXT)

    def test_we_decrypt_reference_ciphertext(self):
        for mc_c, ref_c in self._CIPHERS:
            for mc_e, ref_e in self._ENCODINGS:
                with self.subTest(cipher=mc_c, encoding=mc_e):
                    blob = encrypt_as_json(_KEY, _PLAINTEXT.decode(), ref_c, ref_e)
                    out = mc.decrypt_json(_KEY, blob, mc_c, mc_e)
                    self.assertEqual(out, _PLAINTEXT)


class TestPurePythonCryptoInterop(unittest.TestCase):
    """The pure-Python (on-device) crypto path must interop with the hub.

    This is the path that runs on a microcontroller. The hub uses 16-byte
    AES-GCM nonces, which require the GHASH-derived J0 (NIST SP 800-38D), not
    the 96-bit ``IV || 0x00000001`` shortcut. These tests guard that.
    """

    def test_pure_python_aes_gcm_interop_both_directions(self):
        with _PurePythonCrypto():
            blob = mc.encrypt_json(_KEY, _PLAINTEXT, mc.CIPHER_AES_GCM, "JSON-HEX")
            # our nonce is 16 bytes (matches the hub), so this also proves the
            # GHASH-derived J0 path.
            self.assertEqual(len(json.loads(blob)["nonce"]) // 2, 16)
            out = decrypt_from_json(
                _KEY, blob, SupportedCiphers.AES_GCM, SupportedEncodings.JSON_HEX
            )
            self.assertEqual(out.encode(), _PLAINTEXT)

            ref = encrypt_as_json(
                _KEY, _PLAINTEXT.decode(),
                SupportedCiphers.AES_GCM, SupportedEncodings.JSON_HEX,
            )
            self.assertEqual(
                mc.decrypt_json(_KEY, ref, mc.CIPHER_AES_GCM, "JSON-HEX"),
                _PLAINTEXT,
            )

    def test_pure_python_aes_gcm_12_byte_nonce(self):
        """The 96-bit nonce fast-path must still be correct (regression)."""
        with _PurePythonCrypto():
            g = mc.AesGcm(_KEY)
            ct, tag = g.encrypt(_PLAINTEXT, b"x" * 12)
            self.assertEqual(g.decrypt(ct, b"x" * 12, tag), _PLAINTEXT)

    def test_pure_python_chacha20_interop_both_directions(self):
        with _PurePythonCrypto():
            blob = mc.encrypt_json(_KEY, _PLAINTEXT, mc.CIPHER_CHACHA20, "JSON-HEX")
            out = decrypt_from_json(
                _KEY, blob,
                SupportedCiphers.CHACHA20_POLY1305, SupportedEncodings.JSON_HEX,
            )
            self.assertEqual(out.encode(), _PLAINTEXT)

            ref = encrypt_as_json(
                _KEY, _PLAINTEXT.decode(),
                SupportedCiphers.CHACHA20_POLY1305, SupportedEncodings.JSON_HEX,
            )
            self.assertEqual(
                mc.decrypt_json(_KEY, ref, mc.CIPHER_CHACHA20, "JSON-HEX"),
                _PLAINTEXT,
            )


class TestBinaryFramingConformance(unittest.TestCase):
    """The bitstring binary frame must be byte-identical to the reference."""

    def test_binary_frame_byte_identical(self):
        payload = bytes(range(64))
        meta = cast2bytes({}, False)  # b"{}"
        ref = get_bitstring(
            HiveMessageType.BINARY, payload, compressed=False,
            binary_type=HiveMindBinaryPayloadType.RAW_AUDIO,
            hivemeta={}, versioned=True,
        ).bytes
        ours = mb.encode(mb.MSG_BINARY, mb.BIN_RAW_AUDIO, meta, payload, versioned=True)
        self.assertEqual(ours, ref)

    def test_reference_decodes_our_bus_frame(self):
        payload = b'{"type": "speak", "data": {"utterance": "hi"}}'
        meta = cast2bytes({}, False)
        ours = mb.encode(1, 0, meta, payload, versioned=True)  # 1 == BUS
        decoded = decode_bitstring(ours)
        self.assertEqual(decoded.msg_type, HiveMessageType.BUS)

    def test_we_decode_reference_frame(self):
        payload = bytes(range(32))
        ref = get_bitstring(
            HiveMessageType.BINARY, payload, compressed=False,
            binary_type=HiveMindBinaryPayloadType.RAW_AUDIO,
            hivemeta={}, versioned=True,
        ).bytes
        decoded = mb.decode(ref)
        self.assertEqual(decoded["msg_type"], mb.MSG_BINARY)
        self.assertEqual(decoded["bin_type"], mb.BIN_RAW_AUDIO)
        self.assertEqual(decoded["payload"], payload)


if __name__ == "__main__":
    unittest.main()
