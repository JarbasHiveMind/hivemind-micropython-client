"""Bitstring binary protocol codec for HiveMind.

Works on MicroPython 1.20+ and CPython 3.10+. Uses bytearray-based bit
manipulation — no external dependencies.
"""

from __future__ import annotations

# Message type constant (must match client.py)
MSG_BINARY = 12

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
    version = 1
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
    """Decode a HiveMind binary frame.

    Returns:
        Dict with keys: ``msg_type``, ``bin_type``, ``versioned``,
        ``protocol_version``, ``compressed``, ``metadata``, ``payload``.
    """
    r = BitReader(data)

    # Skip leading zeros until pad marker (1 bit)
    while r.read_bits(1) == 0:
        pass

    versioned = bool(r.read_bits(1))
    protocol_version = r.read_bits(8) if versioned else 0
    msg_type = r.read_bits(5)
    compressed = bool(r.read_bits(1))
    meta_length = r.read_bits(8)
    metadata = r.read_bytes(meta_length)

    bin_type = r.read_bits(4) if msg_type == MSG_BINARY else 0

    payload = r.read_bytes(r.remaining_bytes())

    return {
        "msg_type": msg_type,
        "bin_type": bin_type,
        "versioned": versioned,
        "protocol_version": protocol_version,
        "compressed": compressed,
        "metadata": metadata,
        "payload": payload,
    }
