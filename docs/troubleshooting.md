# Troubleshooting

## Connection refused

```
ConnectionError: [Errno 111] Connection refused
```

The hub is not running or is on a different address/port.

- Confirm the hub is listening: `hivemind-core listen`.
- Check the hub's IP and that `host`/`port` match (default port `5678`).
- Allow the port through any firewall.

## Handshake / authentication failure

The hub rejected the credentials.

- Verify `username`, `access_key`, and `password` exactly match the credential from `hivemind-core add-client`.
- List registered clients on the hub with `hivemind-core list-clients`.

## Decryption / MAC verification failure

```
ValueError: AES-GCM authentication failed
```

Client and hub disagree on cipher or encoding.

- Make sure both support the chosen cipher (`AES-GCM` vs `ChaCha20-Poly1305`).
- Try the defaults: `preferred_cipher="AES-GCM"`, `preferred_encoding="JSON-HEX"`.
- The `JSON-Z85B` / `JSON-Z85P` / `JSON-B91` encodings require the `z85base91` package; without it, choose a different encoding.

## First connection is very slow on ESP32

Pure-Python PBKDF2 at 100k iterations takes 10-30 s on an ESP32.

- This is expected on the first handshake.
- For production, freeze the `_hivemind_crypto` C module into the MicroPython firmware; the handshake then drops to roughly 2-3 s.

## MemoryError on device

```
MemoryError: allocation failed
```

- Stream audio in small chunks (for example 2-4 KB) via `send_binary`.
- Call `gc.collect()` between large operations.
- Use a more compact encoding (`JSON-B91`) to shrink message buffers.

## Wi-Fi drops mid-handshake

```
OSError: Connection reset
```

- Retry with a backoff; `reconnect_ms` controls the delay between reconnect attempts.
- Improve signal strength or move the device closer to the access point.

## `from __future__ import annotations` errors on MicroPython

Some MicroPython builds do not support this import. Use a build that does, or a frozen build of the modules.

## More questions

See [`FAQ.md`](../FAQ.md) for short answers about backends, ciphers, and the binary frame format.
