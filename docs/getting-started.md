# Getting Started

This guide takes you from a bare microcontroller (or a desktop) to a HiveMind satellite that exchanges messages with a hub.

## What this client does

A HiveMind **satellite** captures input on an edge device and forwards it to a central **hub**. The hub runs the AI reasoning — intent parsing, skills, text-to-speech — and sends responses back. This client implements the satellite side: the encrypted HiveMind handshake and bus/binary messaging, small enough to run on MicroPython.

```
device (this client)  ⇄  hivemind-core hub  ⇄  OVOS skills
```

Running this client instead of full OVOS keeps the device footprint tiny: the hub does the heavy lifting over Wi-Fi.

## Prerequisites

### Device

- A microcontroller with networking running **MicroPython 1.20+** (ESP32, Raspberry Pi Pico W, etc.), or **CPython 3.10+** for desktop testing.
- Roughly 50 KB of storage for the client, crypto, and binary codec.

### Network

- Wi-Fi or wired access to the same LAN as the hub.

### Hub

- A running HiveMind hub ([hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core)) reachable at a known address and port (default `5678`).
- A client credential (username, access key, password) registered on the hub.

## Step 1 — Stand up a hub

On a desktop or home server:

```bash
pip install hivemind-core
hivemind-core listen
```

The hub listens on port `5678` by default.

## Step 2 — Register the satellite

```bash
hivemind-core add-client --name esp32 \
  --access-key "your-access-key" --password "your-password"
```

Keep the access key and password — the device authenticates with them. List clients with `hivemind-core list-clients`.

## Step 3 — Install the client

### MicroPython

```bash
mpremote mip install github:JarbasHiveMind/hivemind-micropython-client
```

Verify:

```python
import hivemind.client
print("client installed")
```

### CPython

```bash
git clone https://github.com/JarbasHiveMind/hivemind-micropython-client
cd hivemind-micropython-client
pip install websockets cryptography   # optional accelerators
```

Run scripts with the `hivemind/` package on `sys.path`.

## Step 4 — Connect and send a message

On CPython this script runs as-is. On MicroPython, bring up Wi-Fi first — see `examples/text_satellite.py`, which guards the `network` import so the same file runs on both platforms.

```python
import asyncio
from hivemind.client import HiveMindClient

async def main():
    client = HiveMindClient(
        host="192.168.1.100",
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
        print("connected")
        await client.send_utterance("what time is it")

    client.on_bus_message = on_bus_message
    client.on_connected = on_connected

    await client.connect()

asyncio.run(main())
```

Expected output:

```
connected
hub says: It is half past three.
```

## Next steps

- [API and module reference](index.md)
- [Examples](examples.md)
- [Troubleshooting](troubleshooting.md)
- [Integration testing against a live hub](integration-testing.md)
