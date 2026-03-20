"""Binary protocol unit tests."""
import unittest
from hivemind.binary import encode, decode, MSG_BINARY, BIN_RAW_AUDIO


class TestBinaryCodec(unittest.TestCase):
    """Roundtrip and edge-case tests for the binary protocol codec."""

    def test_bus_message_roundtrip(self) -> None:
        """A bus message (type 1) must survive encode/decode."""
        meta = b'{"source":"test"}'
        payload = b'{"type":"speak","data":{"utterance":"hello"}}'
        frame = encode(1, 0, meta, payload)
        result = decode(frame)
        self.assertEqual(result["msg_type"], 1)
        self.assertEqual(result["metadata"], meta)
        self.assertEqual(result["payload"], payload)
        self.assertTrue(result["versioned"])
        self.assertEqual(result["protocol_version"], 1)
        self.assertFalse(result["compressed"])

    def test_binary_with_bin_type(self) -> None:
        """MSG_BINARY frames must preserve the bin_type field."""
        payload = bytes(range(256))
        frame = encode(MSG_BINARY, BIN_RAW_AUDIO, b'{}', payload)
        result = decode(frame)
        self.assertEqual(result["msg_type"], MSG_BINARY)
        self.assertEqual(result["bin_type"], BIN_RAW_AUDIO)
        self.assertEqual(result["payload"], payload)

    def test_empty_metadata(self) -> None:
        """Empty metadata must roundtrip correctly."""
        frame = encode(1, 0, b'', b'test payload')
        result = decode(frame)
        self.assertEqual(result["metadata"], b'')
        self.assertEqual(result["payload"], b'test payload')

    def test_all_message_types(self) -> None:
        """All 14 message types (0-13) must roundtrip."""
        for mt in range(14):
            bt = BIN_RAW_AUDIO if mt == MSG_BINARY else 0
            frame = encode(mt, bt, b'{}', b'x')
            result = decode(frame)
            self.assertEqual(result["msg_type"], mt)

    def test_large_payload(self) -> None:
        """4KB payload must roundtrip correctly."""
        payload = bytes(range(256)) * 16
        frame = encode(1, 0, b'{}', payload)
        result = decode(frame)
        self.assertEqual(result["payload"], payload)


if __name__ == "__main__":
    unittest.main()
