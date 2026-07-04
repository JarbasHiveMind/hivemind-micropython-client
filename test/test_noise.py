"""Protocol v3 Noise handshake tests — run with: python -m pytest test/ -v

Interop is the gate: ``test/noise_fixtures.json`` holds wire bytes produced
by the Python reference stack (``poorman_handshake.noise`` wrapping the
vetted ``noiseprotocol`` library) with fixed static and ephemeral keys.
The pure-Python initiator here must byte-match them. Regenerate with:

    python test/gen_noise_fixtures.py > test/noise_fixtures.json
"""
import json
import os
import unittest

from hivemind.noise import (
    NOISE_PATTERN_KK,
    NOISE_PATTERN_XX,
    CipherState,
    NoiseHandshake,
    NoiseHandshakeError,
    NoiseTransport,
    build_prologue,
    canonical_json,
    noise_protocol_name,
    select_noise_options,
    x25519,
    x25519_public_key,
)

_FIXTURES_PATH = os.path.join(os.path.dirname(__file__), "noise_fixtures.json")
with open(_FIXTURES_PATH) as _f:
    FX = json.load(_f)


def _hx(value: str) -> bytes:
    return bytes.fromhex(value)


def _make_handshake(pattern: str, **overrides) -> NoiseHandshake:
    """Build the fixture initiator (fixed static + ephemeral keys)."""
    fx = FX["kk" if pattern == NOISE_PATTERN_KK else "xx"]
    kwargs = dict(
        pattern=pattern,
        psk=_hx(FX["psk"]),
        prologue=_hx(fx["prologue"]),
        static_private=_hx(FX["s_initiator_priv"]),
        ephemeral_private=_hx(FX["e_initiator_priv"]),
        remote_static=(_hx(FX["s_responder_pub"])
                       if pattern == NOISE_PATTERN_KK else None),
    )
    kwargs.update(overrides)
    return NoiseHandshake(**kwargs)


class TestX25519(unittest.TestCase):
    """X25519 against RFC 7748 vectors and the fixture keys."""

    def test_rfc7748_vector_1(self) -> None:
        """RFC 7748 §5.2 test vector 1."""
        k = _hx("a546e36bf0527c9d3b16154b82465edd"
                "62144c0ac1fc5a18506a2244ba449ac4")
        u = _hx("e6db6867583030db3594c1a424b15f7c"
                "726624ec26b3353b10a903a6d0ab1c4c")
        expected = _hx("c3da55379de9c6908e94ea4df28d084f"
                       "32eccf03491c71f754b4075577a28552")
        self.assertEqual(x25519(k, u), expected)

    def test_rfc7748_key_exchange(self) -> None:
        """RFC 7748 §6.1 Diffie-Hellman vector."""
        a_priv = _hx("77076d0a7318a57d3c16c17251b26645"
                     "df4c2f87ebc0992ab177fba51db92c2a")
        b_priv = _hx("5dab087e624a8a4b79e17f8b83800ee6"
                     "6f3bb1292618b6fd1c2f8b27ff88e0eb")
        a_pub = x25519_public_key(a_priv)
        b_pub = x25519_public_key(b_priv)
        self.assertEqual(a_pub.hex(),
                         "8520f0098930a754748b7ddcb43ef75a"
                         "0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(b_pub.hex(),
                         "de9edb7d7b7dc1b4d35b61c2ece43537"
                         "3f8343c85b78674dadfc7e146f882b4f")
        shared = _hx("4a5d9d5ba4ce2de1728e3bf480350f25"
                     "e07e21c947d19e3376f09b3c1e161742")
        self.assertEqual(x25519(a_priv, b_pub), shared)
        self.assertEqual(x25519(b_priv, a_pub), shared)

    def test_fixture_public_keys(self) -> None:
        """Public keys derived from the fixture privates match the
        reference (pyca/cryptography) derivation."""
        self.assertEqual(x25519_public_key(_hx(FX["s_initiator_priv"])),
                         _hx(FX["s_initiator_pub"]))


class TestCanonicalJson(unittest.TestCase):
    """canonical_json must byte-match Python's
    json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)."""

    def test_hello_payload(self) -> None:
        self.assertEqual(canonical_json(FX["hello_payload"]),
                         _hx(FX["canonical_hello"]))

    def test_handshake_payload(self) -> None:
        """Nested dicts, lists, bools and ints all serialize canonically."""
        self.assertEqual(canonical_json(FX["handshake_payload"]),
                         _hx(FX["canonical_handshake"]))

    def test_non_ascii_passthrough(self) -> None:
        """ensure_ascii=False semantics: raw UTF-8, not \\u escapes."""
        self.assertEqual(canonical_json({"a": "olá"}),
                         json.dumps({"a": "olá"}, sort_keys=True,
                                    separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8"))

    def test_prologue(self) -> None:
        for tag, pattern in (("xx", NOISE_PATTERN_XX),
                             ("kk", NOISE_PATTERN_KK)):
            name = noise_protocol_name(pattern, "25519_ChaChaPoly_SHA256")
            self.assertEqual(
                build_prologue(FX["hello_payload"],
                               FX["handshake_payload"], name),
                _hx(FX[tag]["prologue"]))


class TestNegotiation(unittest.TestCase):
    """Pattern/suite selection from the server's advertised lists."""

    def test_prefers_kk_when_pinned(self) -> None:
        sel = select_noise_options(["KKpsk0", "XXpsk2"],
                                   ["25519_ChaChaPoly_SHA256"],
                                   pinned_remote_key=b"\x01" * 32)
        self.assertEqual(sel, ("KKpsk0", "25519_ChaChaPoly_SHA256"))

    def test_xx_without_pin(self) -> None:
        sel = select_noise_options(["KKpsk0", "XXpsk2"],
                                   ["25519_ChaChaPoly_SHA256"])
        self.assertEqual(sel, ("XXpsk2", "25519_ChaChaPoly_SHA256"))

    def test_no_mutual_suite(self) -> None:
        self.assertIsNone(select_noise_options(["XXpsk2"],
                                               ["25519_AESGCM_SHA256"]))

    def test_no_mutual_pattern(self) -> None:
        self.assertIsNone(select_noise_options(["NNpsk0"],
                                               ["25519_ChaChaPoly_SHA256"]))


class _HandshakeInteropMixin:
    """Shared byte-for-byte interop assertions against the reference stack."""

    pattern: str = ""
    tag: str = ""

    def _run(self) -> NoiseTransport:
        fx = FX[self.tag]
        hs = _make_handshake(self.pattern)
        msg1 = hs.write_message(_hx(FX["msg1_payload"]))
        self.assertEqual(msg1, _hx(fx["msg1"]),
                         "message 1 must byte-match the reference")
        payload2 = hs.read_message(_hx(fx["msg2"]))
        self.assertEqual(payload2, _hx(FX["msg2_payload"]),
                         "message 2 payload must decrypt to the reference")
        if not hs.finished:
            msg3 = hs.write_message(b"")
            self.assertEqual(msg3, _hx(fx["msg3"]),
                             "message 3 must byte-match the reference")
        self.assertTrue(hs.finished)
        self.assertEqual(hs.handshake_hash, _hx(fx["handshake_hash"]),
                         "handshake hash must match the reference")
        return NoiseTransport(hs)

    def test_handshake_interop(self) -> None:
        """Full handshake byte-matches the noiseprotocol reference."""
        self._run()

    def test_transport_interop(self) -> None:
        """Transport frames byte-match at counters 0 and 1, both ways."""
        fx = FX[self.tag]
        transport = self._run()
        # initiator -> responder ciphertext, counters 0 and 1
        c2s = _hx(FX["transport_c2s"])
        self.assertEqual(
            transport.send_cipher.encrypt_with_ad(b"", c2s),
            _hx(fx["ct_c2s"]))
        c2s_2 = _hx(FX["transport_c2s_2"])
        self.assertEqual(
            transport.send_cipher.encrypt_with_ad(b"", c2s_2),
            _hx(fx["ct_c2s_2"]))
        # responder -> initiator: decrypt reference JSON + binary frames
        self.assertEqual(transport.decrypt_frame(_hx(fx["ct_s2c"])),
                         _hx(FX["transport_s2c"])[1:].decode("utf-8"))
        self.assertEqual(transport.decrypt_frame(_hx(fx["ct_s2c_bin"])),
                         _hx(FX["transport_s2c_bin"])[1:])

    def test_encrypt_frame_markers(self) -> None:
        """encrypt_frame produces the reference ciphertext including the
        0x00 (JSON) frame marker."""
        fx = FX[self.tag]
        transport = self._run()
        json_body = _hx(FX["transport_c2s"])[1:].decode("utf-8")
        self.assertEqual(transport.encrypt_frame(json_body),
                         _hx(fx["ct_c2s"]))

    def test_wrong_psk_fails(self) -> None:
        """A wrong PSK fails cryptographically at handshake time."""
        hs = _make_handshake(self.pattern, psk=b"\xff" * 32)
        hs.write_message(_hx(FX["msg1_payload"]))
        with self.assertRaises(NoiseHandshakeError):
            hs.read_message(_hx(FX[self.tag]["msg2"]))

    def test_tampered_prologue_fails(self) -> None:
        """Any negotiation tampering changes the prologue and aborts."""
        tampered = _hx(FX[self.tag]["prologue"]) + b"X"
        hs = _make_handshake(self.pattern, prologue=tampered)
        hs.write_message(_hx(FX["msg1_payload"]))
        with self.assertRaises(NoiseHandshakeError):
            hs.read_message(_hx(FX[self.tag]["msg2"]))

    def test_tampered_message_fails(self) -> None:
        """A flipped ciphertext bit in message 2 aborts the handshake."""
        hs = _make_handshake(self.pattern)
        hs.write_message(_hx(FX["msg1_payload"]))
        msg2 = bytearray(_hx(FX[self.tag]["msg2"]))
        msg2[-1] ^= 0x01
        with self.assertRaises(NoiseHandshakeError):
            hs.read_message(bytes(msg2))

    def test_replay_rejected(self) -> None:
        """A replayed transport frame fails at the advanced counter and is
        never retried under another nonce (§3.4.5)."""
        fx = FX[self.tag]
        transport = self._run()
        ct = _hx(fx["ct_s2c"])
        transport.decrypt_frame(ct)  # decrypts at n=0
        with self.assertRaises(ValueError):
            transport.decrypt_frame(ct)  # replay at n=1 -> AEAD failure
        # counter did not advance on failure: still rejects
        self.assertEqual(transport.recv_cipher.n, 1)
        with self.assertRaises(ValueError):
            transport.decrypt_frame(ct)


class TestXXpsk2Interop(_HandshakeInteropMixin, unittest.TestCase):
    """Noise_XXpsk2_25519_ChaChaPoly_SHA256 against the reference vectors."""
    pattern = NOISE_PATTERN_XX
    tag = "xx"

    def test_learns_remote_static_key(self) -> None:
        """XX learns the responder's static key for TOFU pinning."""
        transport = self._run()
        self.assertEqual(transport.remote_static_key,
                         _hx(FX["s_responder_pub"]))


class TestKKpsk0Interop(_HandshakeInteropMixin, unittest.TestCase):
    """Noise_KKpsk0_25519_ChaChaPoly_SHA256 against the reference vectors."""
    pattern = NOISE_PATTERN_KK
    tag = "kk"

    def test_single_round_trip(self) -> None:
        """KKpsk0 completes after message 2 — no message 3."""
        hs = _make_handshake(self.pattern)
        hs.write_message(_hx(FX["msg1_payload"]))
        hs.read_message(_hx(FX["kk"]["msg2"]))
        self.assertTrue(hs.finished)

    def test_requires_remote_static(self) -> None:
        with self.assertRaises(NoiseHandshakeError):
            _make_handshake(self.pattern, remote_static=None)


class TestSelfTalk(unittest.TestCase):
    """Two pure-Python endpoints (initiator + hand-driven responder logic
    is out of scope; instead exercise state-machine guards and CipherState)."""

    def test_psk_must_be_32_bytes(self) -> None:
        with self.assertRaises(NoiseHandshakeError):
            NoiseHandshake(NOISE_PATTERN_XX, psk=b"short")

    def test_unsupported_suite(self) -> None:
        with self.assertRaises(NoiseHandshakeError):
            NoiseHandshake(NOISE_PATTERN_XX, psk=b"\x00" * 32,
                           suite="25519_AESGCM_SHA256")

    def test_out_of_turn(self) -> None:
        hs = _make_handshake(NOISE_PATTERN_XX)
        with self.assertRaises(NoiseHandshakeError):
            hs.read_message(b"\x00" * 48)  # must write message 1 first
        hs.write_message(b"")
        with self.assertRaises(NoiseHandshakeError):
            hs.write_message(b"")  # now it is the responder's turn

    def test_split_requires_finished(self) -> None:
        hs = _make_handshake(NOISE_PATTERN_XX)
        with self.assertRaises(NoiseHandshakeError):
            hs.split()
        with self.assertRaises(NoiseHandshakeError):
            NoiseTransport(hs)

    def test_cipherstate_nonce_is_le_counter(self) -> None:
        """Nonce = 4 zero bytes + 64-bit little-endian counter."""
        self.assertEqual(CipherState._nonce(1),
                         b"\x00" * 4 + b"\x01" + b"\x00" * 7)
        self.assertEqual(CipherState._nonce(0x0102030405060708),
                         b"\x00" * 4 + bytes.fromhex("0807060504030201"))

    def test_unknown_frame_marker(self) -> None:
        hs = _make_handshake(NOISE_PATTERN_KK)
        hs.write_message(_hx(FX["msg1_payload"]))
        hs.read_message(_hx(FX["kk"]["msg2"]))
        transport = NoiseTransport(hs)
        bad = transport.send_cipher.encrypt_with_ad(b"", b"\x07junk")
        # loop the frame back through a mirrored transport
        mirrored = NoiseTransport.__new__(NoiseTransport)
        mirrored.recv_cipher = CipherState()
        mirrored.recv_cipher.initialize_key(transport.send_cipher._k)
        with self.assertRaises(ValueError):
            mirrored.decrypt_frame(bad)


if __name__ == "__main__":
    unittest.main()
