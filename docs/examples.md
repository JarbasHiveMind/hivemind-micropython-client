# Examples

Copy-paste patterns for common satellite tasks. Each runs on CPython as-is; on MicroPython, bring up Wi-Fi first (see `examples/text_satellite.py`).

## 1. Send an utterance, receive the spoken reply

```python
import asyncio
from hivemind.client import HiveMindClient

async def main():
    client = HiveMindClient(
        host="192.168.1.100", port=5678,
        username="esp32",
        access_key="your-access-key",
        password="your-password",
        site_id="my-esp32",
    )

    def on_bus_message(msg_type, data, context):
        if msg_type == "speak":
            print("hub:", data.get("utterance"))

    async def on_connected():
        await client.send_utterance("what time is it")

    client.on_bus_message = on_bus_message
    client.on_connected = on_connected
    await client.connect()

asyncio.run(main())
```

## 2. Send an arbitrary bus message

`send_bus_message` puts any OVOS message type onto the hub's bus:

```python
await client.send_bus_message(
    "my.custom.skill:event",
    data={"param": "value"},
    context={"user_id": "alice"},
)
```

When `context` is omitted, the client fills in the session id and `site_id` automatically.

## 3. Stream audio to the hub

Send raw PCM in chunks using the binary channel:

```python
from hivemind.binary import BIN_RAW_AUDIO

# audio_chunk: e.g. 2048 bytes of 16 kHz 16-bit mono PCM from an I2S mic
await client.send_binary(BIN_RAW_AUDIO, audio_chunk)
```

## 4. Receive TTS audio from the hub

Register a binary callback and play back what the hub sends:

```python
from hivemind.binary import BIN_TTS_AUDIO

def on_binary(bin_type, data):
    if bin_type == BIN_TTS_AUDIO:
        play_audio(data)   # raw PCM

client.on_binary = on_binary
```

Binary payload types are defined in `hivemind/binary.py`: `BIN_RAW_AUDIO`, `BIN_NUMPY_IMAGE`, `BIN_FILE`, `BIN_STT_TRANSCRIBE`, `BIN_STT_HANDLE`, `BIN_TTS_AUDIO`.

## 5. Track connection state

```python
from hivemind.client import (
    STATE_DISCONNECTED, STATE_CONNECTING, STATE_HELLO_RECEIVED,
    STATE_HANDSHAKE_SENT, STATE_KEY_DERIVED, STATE_READY,
)

client.on_state_change = lambda state: print("state:", state)
```

`STATE_READY` means the encrypted session is established.

## 6. Choose cipher and encoding

```python
client = HiveMindClient(
    host="192.168.1.100", port=5678,
    username="esp32", access_key="key", password="pass",
    preferred_cipher="CHACHA20-POLY1305",   # or "AES-GCM"
    preferred_encoding="JSON-B91",          # most compact; needs z85base91
)
```

The hub makes the final choice during the handshake. The seven encodings trade size against speed:

| Encoding | Relative size | Notes |
| --- | --- | --- |
| `JSON-HEX` | 200% | Default; simplest |
| `JSON-B64` | 133% | Standard base64 |
| `JSON-URLSAFE-B64` | 133% | URL-safe base64 |
| `JSON-B32` | 160% | Case-insensitive transports |
| `JSON-Z85B` | 125% | Needs `z85base91` |
| `JSON-Z85P` | 125% | Needs `z85base91` |
| `JSON-B91` | 122% | Most compact; needs `z85base91` |

See the runnable [`examples/`](../examples/) for the full text and mic satellites.
