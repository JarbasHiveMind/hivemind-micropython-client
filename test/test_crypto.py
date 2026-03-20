"""Crypto unit tests — run with: python -m pytest test/ -v"""
import unittest
from hivemind.crypto import (
    sha256, hmac_sha256, pbkdf2_hmac_sha256,
    generate_hsub, extract_iv, derive_key,
    encrypt_json_hex, decrypt_json_hex,
)


class TestHmac(unittest.TestCase):
    """HMAC-SHA256 tests against RFC 4231 vectors."""

    def test_hmac_sha256_rfc4231_vector(self) -> None:
        """RFC 4231 Test Case 2."""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
        self.assertEqual(hmac_sha256(key, data), expected)


class TestPbkdf2(unittest.TestCase):
    """PBKDF2-HMAC-SHA256 tests against RFC 6070 vectors."""

    def test_rfc6070_vector(self) -> None:
        """RFC 6070 test vector (1 iteration)."""
        dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)
        expected = bytes.fromhex(
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        )
        self.assertEqual(dk, expected)


class TestHsub(unittest.TestCase):
    """Hsub generation and IV extraction tests."""

    def test_generate_hsub_length(self) -> None:
        """Hsub must be 48 hex chars with an 8-char IV prefix."""
        iv, hsub = generate_hsub("test_password")
        self.assertEqual(len(iv), 8)
        self.assertEqual(len(hsub), 48)
        # Verify all hex chars
        int(hsub, 16)

    def test_iv_extraction_roundtrip(self) -> None:
        """Extracted IV must match the one returned by generate_hsub."""
        iv, hsub = generate_hsub("test_password")
        extracted = extract_iv(hsub)
        self.assertEqual(iv, extracted)


class TestKeyDerivation(unittest.TestCase):
    """Key derivation determinism and uniqueness tests."""

    def test_derive_key_deterministic(self) -> None:
        """Same inputs must produce the same 32-byte key."""
        key1 = derive_key("password", b"\x01" * 8, b"\x02" * 8)
        key2 = derive_key("password", b"\x01" * 8, b"\x02" * 8)
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)

    def test_different_ivs_different_keys(self) -> None:
        """Different IVs must produce different keys."""
        key1 = derive_key("password", b"\x01" * 8, b"\x02" * 8)
        key2 = derive_key("password", b"\x01" * 8, b"\x03" * 8)
        self.assertNotEqual(key1, key2)


class TestEncryption(unittest.TestCase):
    """AES-GCM and ChaCha20-Poly1305 encrypt/decrypt roundtrip tests."""

    def test_aes_gcm_roundtrip(self) -> None:
        """AES-GCM encrypt then decrypt must return original plaintext."""
        key = derive_key("test", b"\xaa" * 8, b"\xbb" * 8)
        plaintext = b"hello hivemind"
        encrypted = encrypt_json_hex(key, plaintext, "AES-GCM")
        decrypted = decrypt_json_hex(key, encrypted, "AES-GCM")
        self.assertEqual(decrypted, plaintext)

    def test_chacha20_roundtrip(self) -> None:
        """ChaCha20-Poly1305 encrypt then decrypt must return original."""
        key = derive_key("test", b"\xaa" * 8, b"\xbb" * 8)
        plaintext = b"hello hivemind chacha"
        encrypted = encrypt_json_hex(key, plaintext, "ChaCha20-Poly1305")
        decrypted = decrypt_json_hex(key, encrypted, "ChaCha20-Poly1305")
        self.assertEqual(decrypted, plaintext)

    def test_wrong_key_fails(self) -> None:
        """Decrypting with a wrong key must raise an exception."""
        key1 = derive_key("test1", b"\xaa" * 8, b"\xbb" * 8)
        key2 = derive_key("test2", b"\xaa" * 8, b"\xbb" * 8)
        encrypted = encrypt_json_hex(key1, b"secret", "AES-GCM")
        with self.assertRaises((ValueError, Exception)):
            decrypt_json_hex(key2, encrypted, "AES-GCM")

    def test_empty_plaintext(self) -> None:
        """Empty plaintext must roundtrip correctly."""
        key = derive_key("test", b"\xaa" * 8, b"\xbb" * 8)
        encrypted = encrypt_json_hex(key, b"", "AES-GCM")
        decrypted = decrypt_json_hex(key, encrypted, "AES-GCM")
        self.assertEqual(decrypted, b"")

    def test_large_plaintext(self) -> None:
        """4KB plaintext must roundtrip correctly."""
        key = derive_key("test", b"\xaa" * 8, b"\xbb" * 8)
        plaintext = b"A" * 4096
        encrypted = encrypt_json_hex(key, plaintext, "AES-GCM")
        decrypted = decrypt_json_hex(key, encrypted, "AES-GCM")
        self.assertEqual(decrypted, plaintext)


if __name__ == "__main__":
    unittest.main()
