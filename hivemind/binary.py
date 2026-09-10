"""Bitstring binary protocol codec for HiveMind.

Works on MicroPython 1.20+ and CPython 3.10+. Uses bytearray-based bit
manipulation — no external dependencies.
"""

from __future__ import annotations

try:
    import ujson as json  # type: ignore[import]
except ImportError:
    import json  # type: ignore[no-redef]

# Message type constant (must match client.py)
MSG_BINARY = 12

# HIVEMIND-WIRE-1 §4.1: the frame-format version this client implements.
FRAME_FORMAT_VERSION = 1

# HIVEMIND-WIRE-1 §4.2: assigned message-type codes (0-10 and 12); 11 is
# reserved (removed THIRDPRTY), 13-31 are unassigned. A receiver MUST
# reject any other code as malformed rather than mapping it to a type.
ASSIGNED_MSG_TYPES = frozenset(range(11)) | {MSG_BINARY}


class MalformedBinaryFrame(ValueError):
    """A WIRE-1 §4 binary frame that cannot be decoded: truncated, a
    metadata length past the end of the frame, an unassigned message-type
    code, or a metadata block that is not valid JSON."""

# Binary payload sub-types
BIN_UNDEFINED = 0
BIN_RAW_AUDIO = 1
BIN_NUMPY_IMAGE = 2
BIN_FILE = 3
BIN_STT_TRANSCRIBE = 4
BIN_STT_HANDLE = 5
BIN_TTS_AUDIO = 6


class BitWriter:
    """Write arbitrary bit sequences into a bytearray buffer."""

    def __init__(self) -> None:
        self._buf: bytearray = bytearray()
        self._byte: int = 0
        self._bit_pos: int = 0  # bits written in current byte (0-7)

    def write_bits(self, value: int, n: int) -> None:
        """Write *n* bits from *value* (MSB first)."""
        for i in range(n - 1, -1, -1):
            bit = (value >> i) & 1
            self._byte = (self._byte << 1) | bit
            self._bit_pos += 1
            if self._bit_pos == 8:
                self._buf.append(self._byte)
                self._byte = 0
                self._bit_pos = 0

    def write_bytes(self, data: bytes) -> None:
        """Write each byte of *data* as 8 bits."""
        for b in data:
            self.write_bits(b, 8)

    def finish(self) -> bytes:
        """Pad remaining bits with zeros and return the completed bytes."""
        if self._bit_pos > 0:
            self._byte <<= (8 - self._bit_pos)
            self._buf.append(self._byte)
        return bytes(self._buf)


class BitReader:
    """Read arbitrary bit sequences from a bytes buffer."""

    def __init__(self, data: bytes) -> None:
        self._data: bytes = data
        self._byte_pos: int = 0
        self._bit_pos: int = 0  # next bit to read in current byte (0-7, MSB=0)

    def read_bits(self, n: int) -> int:
        """Read *n* bits and return as an integer."""
        value = 0
        for _ in range(n):
            byte = self._data[self._byte_pos]
            bit = (byte >> (7 - self._bit_pos)) & 1
            value = (value << 1) | bit
            self._bit_pos += 1
            if self._bit_pos == 8:
                self._byte_pos += 1
                self._bit_pos = 0
        return value

    def read_bytes(self, n: int) -> bytes:
        """Read *n* full bytes (8 bits each)."""
        result = bytearray()
        for _ in range(n):
            result.append(self.read_bits(8))
        return bytes(result)

    def remaining_bytes(self) -> int:
        """Approximate number of remaining full bytes."""
        total_bits = len(self._data) * 8
        consumed = self._byte_pos * 8 + self._bit_pos
        return (total_bits - consumed) // 8


def encode(msg_type: int, bin_type: int, metadata: bytes,
           payload: bytes, versioned: bool = True) -> bytes:
    """Encode a HiveMind binary frame.

    Args:
        msg_type: Message type (0-31, 5 bits).
        bin_type: Binary payload sub-type (0-15, 4 bits). Only used when
                  *msg_type* == ``MSG_BINARY``.
        metadata: Raw metadata bytes (max 255 bytes).
        payload: Raw payload bytes.
        versioned: Whether to include version header (always True).

    Returns:
        Encoded binary frame.
    """
    version = FRAME_FORMAT_VERSION
    compressed = False

    # Calculate total content bits
    content_bits = 1 + 1 + 8 + 5 + 1 + 8 + len(metadata) * 8
    if msg_type == MSG_BINARY:
        content_bits += 4
    content_bits += len(payload) * 8

    leading_zeros = (8 - (content_bits % 8)) % 8

    w = BitWriter()
    # Leading zeros then pad marker
    w.write_bits(0, leading_zeros)
    w.write_bits(1, 1)  # pad marker
    # Versioned flag
    w.write_bits(1 if versioned else 0, 1)
    # Protocol version
    w.write_bits(version, 8)
    # Message type (5 bits)
    w.write_bits(msg_type, 5)
    # Compressed flag
    w.write_bits(1 if compressed else 0, 1)
    # Metadata length + metadata
    w.write_bits(len(metadata), 8)
    w.write_bytes(metadata)
    # Binary sub-type (only for MSG_BINARY)
    if msg_type == MSG_BINARY:
        w.write_bits(bin_type, 4)
    # Payload
    w.write_bytes(payload)
    return w.finish()


def decode(data: bytes) -> dict:
    """Decode a HiveMind binary frame (HIVEMIND-WIRE-1 §4).

    Returns:
        Dict with keys: ``msg_type``, ``bin_type``, ``versioned``,
        ``protocol_version``, ``compressed``, ``metadata``, ``payload``.
        ``metadata`` is the decoded JSON object; a zero-length metadata
        block decodes as ``{}`` (§4.1).

    Raises:
        MalformedBinaryFrame: the frame-format version is not the one
            this client implements (§4.1), the message-type code is not
            one of the codes §4.2 assigns, the metadata length claims
            more bytes than remain in the frame, the metadata block is
            not valid UTF-8 JSON, or the frame is truncated.
    """
    try:
        r = BitReader(data)

        # Skip leading zeros until pad marker (1 bit)
        while r.read_bits(1) == 0:
            pass

        versioned = bool(r.read_bits(1))
        protocol_version = r.read_bits(8) if versioned else 0
        if versioned and protocol_version != FRAME_FORMAT_VERSION:
            raise MalformedBinaryFrame(
                "malformed binary frame: unimplemented frame-format "
                "version %d" % protocol_version)
        msg_type = r.read_bits(5)
        if msg_type not in ASSIGNED_MSG_TYPES:
            raise MalformedBinaryFrame(
                "malformed binary frame: unassigned WIRE-1 message-type "
                "code %d" % msg_type)
        compressed = bool(r.read_bits(1))
        meta_length = r.read_bits(8)
        if meta_length > r.remaining_bytes():
            raise MalformedBinaryFrame(
                "malformed binary frame: metadata_len claims %d bytes "
                "but only %d remain" % (meta_length, r.remaining_bytes()))
        raw_metadata = r.read_bytes(meta_length)
        if meta_length:
            metadata = json.loads(raw_metadata.decode("utf-8"))
        else:
            metadata = {}

        bin_type = r.read_bits(4) if msg_type == MSG_BINARY else 0

        payload = r.read_bytes(r.remaining_bytes())
    except MalformedBinaryFrame:
        raise
    except (IndexError, ValueError, UnicodeDecodeError) as e:
        raise MalformedBinaryFrame("malformed binary frame: %s" % e) from e

    return {
        "msg_type": msg_type,
        "bin_type": bin_type,
        "versioned": versioned,
        "protocol_version": protocol_version,
        "compressed": compressed,
        "metadata": metadata,
        "payload": payload,
    }
