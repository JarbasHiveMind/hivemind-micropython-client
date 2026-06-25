# hivemind-micropython-client

Lightweight [HiveMind](https://github.com/JarbasHiveMind/HiveMind-core) satellite client for MicroPython 1.20+ and CPython 3.10+, from one shared pure-Python codebase.

A **satellite** is an edge device that captures user input (text, audio, sensors) and forwards it to a central **hub** ([hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)), which runs the AI reasoning (intent parsing, skills, TTS) and sends responses back. This client runs the full HiveMind handshake and encrypted messaging on a microcontroller, so an ESP32 or Raspberry Pi Pico can be a satellite without running OVOS on-device.

```
ESP32 / Pico (this client)  ⇄  HiveMind hub (hivemind-core)  ⇄  OVOS skills
```

## Features

- **Tiny** — pure Python plus the MicroPython stdlib; no pip packages required on-device.
- **Encrypted** — AES-256-GCM or ChaCha20-Poly1305 AEAD; key derived from your password via PBKDF2-HMAC-SHA256.
- **Dual platform** — runs on MicroPython hardware and on CPython for development and testing, auto-detected at import.
- **Binary transport** — bitstring-encoded frames for streaming audio to/from the hub.
- **Async** — non-blocking I/O on `uasyncio` (MicroPython) or `asyncio` (CPython).

## Prerequisites

- A **microcontroller** with networking running **MicroPython 1.20+** (ESP32, Raspberry Pi Pico W, etc.), or **CPython 3.10+** for desktop testing.
- A running **HiveMind hub** ([hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)) reachable on the same network.
- A **client credential** (username, access key, password) issued by the hub with `hivemind-core add-client`.

## Install

### MicroPython (on-device)

```bash
mpremote mip install github:JarbasHiveMind/hivemind-micropython-client
```

Or from the REPL:

```python
import mip
mip.install("github:JarbasHiveMind/hivemind-micropython-client")
```

### CPython (development / testing)

Run from a checkout with the `hivemind/` package on `sys.path`. For the CPython transport and faster crypto, install the optional `websockets` and `cryptography` packages; the `JSON-Z85B` / `JSON-Z85P` / `JSON-B91` encodings additionally need `z85base91`. All are optional — the code falls back to pure Python when they are absent.

```bash
git clone https://github.com/JarbasHiveMind/hivemind-micropython-client
cd hivemind-micropython-client
pip install websockets cryptography z85base91   # optional accelerators
```

## Quickstart

**1. Register the satellite on the hub** (where `hivemind-core` is installed):

```bash
hivemind-core add-client --name esp32 \
  --access-key "your-access-key" --password "your-password"
```

Note the access key and password.

**2. Connect and send a message.** On CPython this runs as-is; on MicroPython, bring up Wi-Fi first (see `examples/text_satellite.py`).

```python
import asyncio
from hivemind.client import HiveMindClient

async def main():
    client = HiveMindClient(
        host="192.168.1.100",     # the hub's address
        port=5678,
        username="esp32",
        access_key="your-access-key",
        password="your-password",
        site_id="my-esp32",
    )

    def on_bus_message(msg_type, data, context):
        if msg_type == "speak":
            print("hub says:", data.get("utterance"))

    async def on_connected():
        print("connected to hub")
        await client.send_utterance("what time is it")

    client.on_bus_message = on_bus_message
    client.on_connected = on_connected

    await client.connect()   # handshake, then receive loop

asyncio.run(main())
```

`connect()` performs the encrypted handshake, fires `on_connected`, then runs the receive loop. `send_utterance` forwards text to the hub; the hub's `speak` reply arrives on `on_bus_message`.

## How the connection works

The handshake derives a session key from your password and negotiates a cipher, then all messages are encrypted:

```
Client                          Hub
  │ ── WebSocket connect ──────→ │
  │ ←─ HELLO (+ server pubkey) ─ │
  │ ── SHAKE (hsub) ───────────→ │
  │ ←─ SHAKE (cipher choice) ─── │
  │   PBKDF2-HMAC-SHA256 key derivation (100k iterations, both sides)
  │ ── HELLO (encrypted) ──────→ │
  │ ←─ READY ──────────────────  │
  └─ on_connected(); ready to send/receive
```

The session key is `PBKDF2(password)` mixed with the two 8-byte IVs exchanged in the handshake. Both ciphers and all encodings are byte-for-byte compatible with `hivemind-core` and the reference `hivemind-websocket-client`.

## Configuration

`HiveMindClient(...)` parameters:

| Parameter | Description | Default |
| --- | --- | --- |
| `host` | Hub address | — |
| `port` | Hub port | — |
| `username` | Client name registered on the hub | — |
| `access_key` | Access key from `hivemind-core add-client` | — |
| `password` | Password from `hivemind-core add-client` | — |
| `site_id` | Site identifier reported to the hub | `"micropython"` |
| `preferred_cipher` | `"AES-GCM"` or `"CHACHA20-POLY1305"` | `"AES-GCM"` |
| `preferred_encoding` | One of the 7 JSON encodings (see docs) | `"JSON-HEX"` |
| `reconnect_ms` | Reconnect delay after a drop | `5000` |

## Troubleshooting

- **First connection takes 10-30 s on ESP32** — pure-Python PBKDF2 at 100k iterations is slow. This is expected; for production, freeze the `_hivemind_crypto` C module into the firmware (handshake drops to ~2-3 s).
- **`MemoryError` on device** — send audio in small chunks and call `gc.collect()`; consider a more compact encoding.
- **Authentication / handshake failures** — verify `username`, `access_key`, and `password` match the credential registered on the hub.
- **Connection refused** — confirm the hub is listening and reachable at `host:port`.

See [`docs/troubleshooting.md`](docs/troubleshooting.md) for more.

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md) — prerequisites and first satellite.
- [`docs/index.md`](docs/index.md) — API and module reference.
- [`docs/examples.md`](docs/examples.md) — text, audio, and custom-message examples.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — common errors and fixes.
- [`docs/integration-testing.md`](docs/integration-testing.md) — testing against a live hub.

See [`examples/`](examples/) for the runnable text and mic satellites.
