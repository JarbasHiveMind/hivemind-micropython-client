# hivemind-micropython-client

Lightweight [HiveMind](https://github.com/JarbasHiveMind/HiveMind-core) satellite client for MicroPython 1.20+ and CPython 3.10+, from one shared pure-Python codebase.

A **satellite** is an edge device that captures user input (text, audio, sensors) and forwards it to a central **hub** ([hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)). The hub runs the AI reasoning (intent parsing, skills, TTS) and sends responses back. This client runs the full HiveMind handshake and encrypted messaging on a microcontroller. That lets an ESP32 or Raspberry Pi Pico act as a satellite without running OVOS on-device.

```
ESP32 / Pico (this client)  ⇄  HiveMind hub (hivemind-core)  ⇄  OVOS skills
```

## Features

- **Tiny**: pure Python plus the MicroPython stdlib. No pip packages are required on-device.
- **Encrypted**: AES-256-GCM or ChaCha20-Poly1305 AEAD. The key comes from your password through PBKDF2-HMAC-SHA256.
- **Dual platform**: runs on MicroPython hardware and on CPython for development and testing, auto-detected at import.
- **Binary transport**: bitstring-encoded frames for streaming audio to and from the hub.
- **Async**: non-blocking I/O on `uasyncio` (MicroPython) or `asyncio` (CPython).

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

Run from a checkout with the `hivemind/` package on `sys.path`. For the CPython transport and faster crypto, install the optional `websockets` and `cryptography` packages. The `JSON-Z85B` / `JSON-Z85P` / `JSON-B91` encodings also need `z85base91`. All of these are optional. The code falls back to pure Python when they are absent.

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

**2. Connect and send a message.** On CPython this runs as-is. On MicroPython, bring up Wi-Fi first (see `examples/text_satellite.py`).

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

`connect()` performs the encrypted handshake, fires `on_connected`, then runs the receive loop. `send_utterance` forwards text to the hub. The hub's `speak` reply arrives on `on_bus_message`.

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

### Protocol v3 (Noise handshake)

When the hub advertises protocol version 3 and a 32-byte PSK is provisioned, the client runs a **Noise handshake** (`Noise_XXpsk2_25519_ChaChaPoly_SHA256`, or `Noise_KKpsk0` when the server's static key is pinned) instead of the legacy exchange above. It adds mutual authentication, forward secrecy, replay resistance, and downgrade protection. All session traffic then flows as Noise transport frames with implicit counter nonces. Without a PSK, or against a v2 hub, the client uses the legacy v0-v2 handshake unchanged.

A microcontroller never derives the PSK on-device, because argon2id is infeasible there. Compute it once on a capable host with `argon2id(password, SHA-256(node_id))`, for example through `hivemind-core derive-psk`, and pass the 32 bytes as `psk`:

```python
client = HiveMindClient(
    host="192.168.1.10", port=5678,
    username="satellite", access_key="...", password="...",
    psk=bytes.fromhex("<64-hex-char provisioned PSK>"),
    # optional, enables KKpsk0 + TOFU pinning:
    # server_noise_key=bytes.fromhex("<server static X25519 pubkey>"),
    # noise_static_key=bytes.fromhex("<this node's static X25519 privkey>"),
)
```

After an `XXpsk2` handshake, the server's static key is available in `client.server_noise_key`. Persist it and pass it back as `server_noise_key` so later connections pin it. A mismatch then aborts the connection as a possible man-in-the-middle.

## Configuration

`HiveMindClient(...)` parameters:

| Parameter | Description | Default |
| --- | --- | --- |
| `host` | Hub address | none |
| `port` | Hub port | none |
| `username` | Client name registered on the hub | none |
| `access_key` | Access key from `hivemind-core add-client` | none |
| `password` | Password from `hivemind-core add-client` | none |
| `site_id` | Site identifier reported to the hub | `"micropython"` |
| `preferred_cipher` | `"AES-GCM"` or `"CHACHA20-POLY1305"` | `"AES-GCM"` |
| `preferred_encoding` | One of the 7 JSON encodings (see docs) | `"JSON-HEX"` |
| `reconnect_ms` | Reconnect delay after a drop | `5000` |
| `psk` | Provisioned 32-byte Noise PSK (bytes or hex), enables protocol v3 | `None` |
| `noise_static_key` | This node's static X25519 private key (bytes or hex) | generated |
| `server_noise_key` | Pinned server static X25519 public key (bytes or hex) | `None` |
| `max_protocol_version` | Highest protocol version to offer (`2` forces legacy) | `3` |

## Troubleshooting

- **First connection takes 10-30 s on ESP32**: pure-Python PBKDF2 at 100k iterations is slow. This is expected. For production, freeze the `_hivemind_crypto` C module into the firmware to drop the handshake to about 2-3 s.
- **Protocol v3 handshake is slow on-device**: pure-Python X25519 takes seconds per DH operation on an ESP32 (XXpsk2 does 3, plus key generation). It runs only once per connection. Transport encryption afterward is ChaCha20-Poly1305, the fastest pure-Python option.
- **`MemoryError` on device**: send audio in small chunks and call `gc.collect()`. Consider a more compact encoding.
- **Authentication or handshake failures**: verify that `username`, `access_key`, and `password` match the credential registered on the hub.
- **Connection refused**: confirm the hub is listening and reachable at `host:port`.

See [`docs/troubleshooting.md`](docs/troubleshooting.md) for more.

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md): prerequisites and first satellite.
- [`docs/index.md`](docs/index.md): API and module reference.
- [`docs/examples.md`](docs/examples.md): text, audio, and custom-message examples.
- [`docs/troubleshooting.md`](docs/troubleshooting.md): common errors and fixes.
- [`docs/integration-testing.md`](docs/integration-testing.md): testing against a live hub.

See [`examples/`](examples/) for the runnable text and mic satellites.
