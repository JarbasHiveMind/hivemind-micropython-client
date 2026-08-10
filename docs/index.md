# hivemind-micropython-client

Pure Python HiveMind WebSocket satellite client for MicroPython 1.20+ and CPython 3.10+.

## Architecture

```
HiveMindClient (async) -> crypto backend -> WebSocket transport
```

- `HiveMindClient` (`hivemind/client.py`): async connect/handshake/send/receive loop
- `crypto.py` (`hivemind/crypto.py`): three-tier crypto backends
- `binary.py` (`hivemind/binary.py`): bitstring binary protocol codec

## Crypto backend selection

| Priority | Backend | Flag | Use case |
|----------|---------|------|----------|
| 1 | `_hivemind_crypto` C module | `_HAVE_C_MODULE` | Frozen C extension wrapping mbedTLS. Production on ESP32. |
| 2 | `cryptography` (Python) | `_HAVE_CRYPTOGRAPHY` | CPython with pip-installed cryptography package. Testing. |
| 3 | Pure Python | neither flag set | Fallback. `AesGcm`, `ChaCha20Poly1305` classes. Slow on MicroPython. |

## Public API: `HiveMindClient` (`client.py`)

| Method | Description |
|--------|-------------|
| `__init__` | Configure host, port, credentials, cipher preference |
| `connect` | Open WebSocket, start handshake, enter receive loop |
| `disconnect` | Close WebSocket, reset state |
| `send_utterance` | Send `recognizer_loop:utterance` bus message |
| `send_bus_message` | Send arbitrary bus message |
| `send_binary` | Send binary frame (audio, etc.) |

### Callbacks

- `on_bus_message: Callable[[str, dict, dict], None]`: bus message received
- `on_binary: Callable[[int, bytes], None]`: binary data received
- `on_state_change: Callable[[int], None]`: FSM state transition
- `on_connected: Callable[[], None]`: handshake complete

## Crypto functions: `crypto.py`

| Function | Description |
|----------|-------------|
| `generate_hsub` | Generate hsub token (iv + SHA256) |
| `extract_iv` | Extract 8-byte IV from hsub hex |
| `derive_key` | PBKDF2-HMAC-SHA256, 100k iterations |
| `encrypt_json_hex` | Encrypt to JSON-hex envelope |
| `decrypt_json_hex` | Decrypt JSON-hex envelope |

## Binary codec: `binary.py`

| Function/Class | Description |
|----------------|-------------|
| `encode` | Encode V1 bitstring frame |
| `decode` | Decode V1 bitstring frame |
| `BitWriter` | Bit-level write buffer |
| `BitReader` | Bit-level read buffer |

## Transport: `client.py`

- MicroPython: `uwebsocket` + `uasyncio`
- CPython: `websockets` + `asyncio`

Detected at import time via the `_MICROPYTHON` flag in `client.py`.
