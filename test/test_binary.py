"""Binary protocol unit tests."""
import os
import random
import unittest

from hivemind.binary import (
    encode,
    decode,
    MalformedBinaryFrame,
    MSG_BINARY,
    BIN_RAW_AUDIO,
    ASSIGNED_MSG_TYPES,
    FRAME_FORMAT_VERSION,
    BitWriter,
)


def _encode_with_version(msg_type, bin_type, metadata, payload, version):
    """Build a versioned frame like ``encode()``, but with an arbitrary
    frame-format version instead of FRAME_FORMAT_VERSION, so tests can
    exercise HIVEMIND-WIRE-1 §4.1 version rejection."""
    content_bits = 1 + 1 + 8 + 5 + 1 + 8 + len(metadata) * 8
    if msg_type == MSG_BINARY:
        content_bits += 4
    content_bits += len(payload) * 8
    leading_zeros = (8 - (content_bits % 8)) % 8

    w = BitWriter()
    w.write_bits(0, leading_zeros)
    w.write_bits(1, 1)  # pad marker
    w.write_bits(1, 1)  # versioned flag
    w.write_bits(version, 8)
    w.write_bits(msg_type, 5)
    w.write_bits(0, 1)  # compressed flag
    w.write_bits(len(metadata), 8)
    w.write_bytes(metadata)
    if msg_type == MSG_BINARY:
        w.write_bits(bin_type, 4)
    w.write_bytes(payload)
    return w.finish()


class TestBinaryCodec(unittest.TestCase):
    """Roundtrip and edge-case tests for the binary protocol codec."""

    def test_bus_message_roundtrip(self) -> None:
        """A bus message (type 1) must survive encode/decode."""
        meta = b'{"source":"test"}'
        payload = b'{"type":"speak","data":{"utterance":"hello"}}'
        frame = encode(1, 0, meta, payload)
        result = decode(frame)
        self.assertEqual(result["msg_type"], 1)
        self.assertEqual(result["metadata"], {"source": "test"})
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
        """HIVEMIND-WIRE-1 §4.1: a zero-length metadata block decodes as
        the empty object."""
        frame = encode(1, 0, b'', b'test payload')
        result = decode(frame)
        self.assertEqual(result["metadata"], {})
        self.assertEqual(result["payload"], b'test payload')

    def test_all_assigned_message_types_roundtrip(self) -> None:
        """Every HIVEMIND-WIRE-1 §4.2 assigned message type must roundtrip."""
        self.assertEqual(ASSIGNED_MSG_TYPES, frozenset(range(11)) | {12})
        for mt in sorted(ASSIGNED_MSG_TYPES):
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


class TestMalformedFrames(unittest.TestCase):
    """HIVEMIND-WIRE-1 §4.2: a receiver MUST reject a frame carrying an
    unassigned message-type code as malformed."""

    def test_unimplemented_frame_format_version_2_rejected(self) -> None:
        frame = _encode_with_version(1, 0, b'{}', b'x',
                                      FRAME_FORMAT_VERSION + 1)
        with self.assertRaisesRegex(MalformedBinaryFrame, "2"):
            decode(frame)

    def test_unimplemented_frame_format_version_0_rejected(self) -> None:
        frame = _encode_with_version(1, 0, b'{}', b'x', 0)
        with self.assertRaisesRegex(MalformedBinaryFrame, "0"):
            decode(frame)

    def test_unimplemented_frame_format_version_255_rejected(self) -> None:
        frame = _encode_with_version(1, 0, b'{}', b'x', 255)
        with self.assertRaisesRegex(MalformedBinaryFrame, "255"):
            decode(frame)

    def test_reserved_code_11_rejected(self) -> None:
        frame = encode(11, 0, b'{}', b'x')
        with self.assertRaises(MalformedBinaryFrame):
            decode(frame)

    def test_unassigned_code_13_rejected(self) -> None:
        frame = encode(13, 0, b'{}', b'x')
        with self.assertRaises(MalformedBinaryFrame):
            decode(frame)

    def test_unassigned_code_31_rejected(self) -> None:
        frame = encode(31, 0, b'{}', b'x')
        with self.assertRaises(MalformedBinaryFrame):
            decode(frame)

    def test_metadata_length_exceeds_remaining_bytes(self) -> None:
        # A well-formed frame with metadata_len=1 but zero metadata bytes
        # and no payload: claims one byte that does not exist.
        frame = encode(1, 0, b'', b'')
        # Corrupt the metadata-length field (last full byte before the
        # zero-length metadata/payload) to claim 255 bytes.
        corrupted = bytearray(frame)
        # metadata_len is the 8 bits right after msg_type(5)+compressed(1)
        # bits following the header; simplest reliable corruption is to
        # encode a frame with 1 byte of real metadata, then truncate the
        # trailing metadata byte off the wire representation.
        good = bytearray(encode(1, 0, b'x', b''))
        truncated = bytes(good[:-1])
        with self.assertRaises(MalformedBinaryFrame):
            decode(truncated)

    def test_truncated_frame(self) -> None:
        frame = encode(1, 0, b'{}', b'payload bytes here')
        with self.assertRaises(MalformedBinaryFrame):
            decode(frame[:1])

    def test_metadata_not_valid_json(self) -> None:
        frame = encode(1, 0, b'not json', b'x')
        with self.assertRaises(MalformedBinaryFrame):
            decode(frame)

    def test_fuzz_random_bytes_only_raise_malformed_or_decode_clean(self) -> None:
        """Feeding random bytes must never escape with anything other than
        MalformedBinaryFrame, or a clean decode."""
        rng = random.Random(1234)
        for _ in range(200):
            length = rng.randint(0, 64)
            data = bytes(rng.randrange(256) for _ in range(length))
            try:
                decode(data)
            except MalformedBinaryFrame:
                pass


if __name__ == "__main__":
    unittest.main()
