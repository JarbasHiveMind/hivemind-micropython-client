# Integration & Conformance Testing

This client is tested at two levels. The first runs in CI on every PR with no
board and no network. The second is a manual procedure against a real hub and,
optionally, real hardware.

## 1. Automated tests (CI, no hub, no board)

`test/` runs entirely under CPython and is what the GitHub Actions workflow
executes on every push and PR to `dev`/`master`. It needs only the reference
HiveMind stack (`test-requirements.txt`):

```bash
uv pip install -r test-requirements.txt
PYTHONPATH="$PWD" pytest test/ -v
```

| File | What it proves |
|------|----------------|
| `test_crypto.py` | AES-GCM / ChaCha20-Poly1305 and all JSON encodings round-trip, plus HMAC/PBKDF2 against RFC vectors. |
| `test_binary.py` | The bitstring binary codec round-trips for every message type. |
| `test_conformance.py` | Byte-for-byte Protocol-V1 interop **against the reference `hivemind-bus-client`**. Covers key derivation, hsub format, cipher/encoding wire strings, AES-GCM/ChaCha20 ciphertext (both the CPython `cryptography` path and the pure-Python on-device path), and binary framing. |
| `test_integration.py` | A full **password handshake and encrypted message round-trip**. The hub side is the real reference protocol code, driven over an in-process mock WebSocket: handshake, encrypted `HELLO`, utterance/`speak`, and `PING`/`PONG`. |

Because the conformance and integration tests use the genuine reference
implementation as the other end of the wire, a green run guarantees the client
speaks Protocol V1 exactly as `hivemind-core` expects, without a running hub.

### Why the pure-Python crypto path is tested explicitly

On a desktop the client uses `cryptography` for AES-GCM/ChaCha20. On a
microcontroller there is no `cryptography`, so the **pure-Python** AEAD code
runs instead. `test_conformance.py` forces that path and cross-checks it against
the reference, so an on-device-only crypto regression (e.g. the AES-GCM J0
derivation for the hub's 16-byte nonce) cannot hide behind the faster backend.

## 2. Manual live-hub test

This exercises the real WebSocket transport against a running `hivemind-core`.
It is **not** in CI, because it needs a hub and the OVOS stack. Run it locally.

### Set up a hub

```bash
pip install hivemind-core
hivemind-core add-client --name "micropython-test"
# note the Access Key and Password it prints
hivemind-core listen           # serves ws://localhost:5678
```

### Connect with the client (CPython)

The client API is **async**. Run this from a checkout with `hivemind/` on the
path (`pip install websockets cryptography z85base91` for the fast path):

```python
import asyncio
from hivemind.client import HiveMindClient

async def main():
    got = asyncio.Event()
    client = HiveMindClient(
        host="localhost", port=5678,
        username="micropython-test",
        access_key="<access_key>", password="<password>",
        site_id="micropython-test",
        reconnect_ms=0,
    )

    def on_bus(msg_type, data, context):
        if msg_type == "speak":
            print("hub says:", data.get("utterance"))
            got.set()

    async def on_connected():
        await client.send_utterance("hello")

    client.on_bus_message = on_bus
    client.on_connected = on_connected

    task = asyncio.ensure_future(client.connect())
    await asyncio.wait_for(got.wait(), timeout=30)
    await client.disconnect()
    task.cancel()

asyncio.run(main())
```

A `speak` line means handshake, encryption, send and receive all worked against
a real hub.

### On-device (MicroPython) test

A true on-device end-to-end run is **not CI-feasible** (it needs flashed
hardware and a hub on the LAN), so it is a manual checklist:

1. Flash MicroPython 1.20+ to the board (ESP32 / Pico W).
2. `mpremote mip install github:JarbasHiveMind/hivemind-micropython-client`
   (and `mpremote mip install github:org/z85base91` only if you need the
   Z85/B91 encodings).
3. Bring up Wi-Fi, then run `examples/text_satellite.py` with your hub address
   and credentials.
4. Expect the first connect to take about 10-30 s: pure-Python PBKDF2 (100k
   iterations) is slow. Freeze a `_hivemind_crypto` C module into the firmware
   for production to cut this to a few seconds.

Watch the hub logs for the satellite's `HELLO` and the `recognizer_loop:utterance`
it forwards.

## Expected message flow

```
Client                          Hub (hivemind-core)
  │ ── ws connect (auth hdr) ──→ │
  │ ←─ HELLO (pubkey, node_id) ─ │
  │ ←─ SHAKE (request, ciphers) ─│
  │ ── SHAKE (hsub envelope) ──→ │   PBKDF2(password, salt=IV⊕IV, 100k) → key
  │ ←─ SHAKE (cipher/encoding) ──│
  │ ── HELLO (encrypted) ──────→ │   ready
  │ ── bus: utterance (enc) ───→ │
  │ ←─ bus: speak (enc) ───────  │
  │ ←─ ping (enc) ──────────────│
  │ ── pong (enc) ─────────────→ │
```

---
[← Troubleshooting](troubleshooting.md) · [Home](../README.md)
