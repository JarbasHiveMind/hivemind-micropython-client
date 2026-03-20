# hivemind-micropython-client

Pure Python HiveMind WebSocket satellite client for MicroPython 1.20+ and CPython 3.10+.

## Architecture

```
HiveMindClient (async) -> crypto backend -> WebSocket transport
```

- `HiveMindClient` — `hivemind/client.py:85`: async connect/handshake/send/receive loop
- `crypto.py` — `hivemind/crypto.py:1`: three-tier crypto backends
- `binary.py` — `hivemind/binary.py:1`: bitstring binary protocol codec

## Crypto backend selection — `crypto.py:19-38`

| Priority | Backend | Import | Use case |
|----------|---------|--------|----------|
| 1 | `_hivemind_crypto` C module | `crypto.py:20` | Frozen C extension wrapping mbedTLS. Production on ESP32. |
| 2 | `cryptography` (Python) | `crypto.py:32` | CPython with pip-installed cryptography package. Testing. |
| 3 | Pure Python | `crypto.py:169-521` | Fallback. `AesGcm`, `ChaCha20Poly1305` classes. Slow on MicroPython. |

## Public API — `HiveMindClient` (`client.py:85`)

| Method | Line | Description |
|--------|------|-------------|
| `__init__` | 93 | Configure host, port, credentials, cipher preference |
| `connect` | 182 | Open WebSocket, start handshake, enter receive loop |
| `disconnect` | 203 | Close WebSocket, reset state |
| `send_utterance` | 352 | Send `recognizer_loop:utterance` bus message |
| `send_bus_message` | 363 | Send arbitrary bus message |
| `send_binary` | 386 | Send binary frame (audio, etc.) |

### Callbacks — `client.py:122-125`

- `on_bus_message: Callable[[str, dict, dict], None]` — bus message received
- `on_binary: Callable[[int, bytes], None]` — binary data received
- `on_state_change: Callable[[int], None]` — FSM state transition
- `on_connected: Callable[[], None]` — handshake complete

## Crypto functions — `crypto.py`

| Function | Line | Description |
|----------|------|-------------|
| `generate_hsub` | 133 | Generate hsub token (iv + SHA256) |
| `extract_iv` | 146 | Extract 8-byte IV from hsub hex |
| `derive_key` | 155 | PBKDF2-HMAC-SHA256, 100k iterations |
| `encrypt_json_hex` | 456 | Encrypt to JSON-hex envelope |
| `decrypt_json_hex` | 496 | Decrypt JSON-hex envelope |

## Binary codec — `binary.py`

| Function/Class | Line | Description |
|----------------|------|-------------|
| `encode` | 89 | Encode V1 bitstring frame |
| `decode` | 138 | Decode V1 bitstring frame |
| `BitWriter` | 22 | Bit-level write buffer |
| `BitReader` | 54 | Bit-level read buffer |

## Transport — `client.py:13-28`

- MicroPython: `uwebsocket` + `uasyncio`
- CPython: `websockets` + `asyncio`

Detected at import time via `_MICROPYTHON` flag (`client.py:18`).
