# FAQ — hivemind-micropython-client

**Q: Does it work on CPython?**
A: Yes. Uses `websockets` + `asyncio` on CPython, `uwebsocket` + `uasyncio` on MicroPython. Auto-detected at import — `client.py:13-28`.

**Q: Which crypto backend is used?**
A: In priority order: (1) `_hivemind_crypto` frozen C module, (2) `cryptography` pip package, (3) pure Python fallback. Selection at `crypto.py:19-38`.

**Q: How slow is PBKDF2 on ESP32 MicroPython?**
A: Pure Python PBKDF2 with 100k iterations takes minutes on ESP32. Use the frozen C module (`_hivemind_crypto`) for production. See `crypto.py:102-126`.

**Q: Which WebSocket library is used?**
A: `uwebsocket` on MicroPython, `websockets` on CPython — `client.py:14,198`.

**Q: How to install on MicroPython?**
A: `mpremote mip install github:JarbasHiveMind/hivemind-micropython-client`

**Q: What ciphers are supported?**
A: AES-256-GCM (`AesGcm`) and ChaCha20-Poly1305 (`ChaCha20Poly1305`). The wire identifiers are `"AES-GCM"` and `"CHACHA20-POLY1305"`, matching `hivemind-bus-client`'s `SupportedCiphers`; the cipher is negotiated during the handshake.

**Q: Does it interoperate with a real `hivemind-core` hub?**
A: Yes. `test/test_conformance.py` cross-checks key derivation, hsub, cipher/encoding strings, AEAD ciphertext, and binary framing byte-for-byte against the reference `hivemind-bus-client`, and `test/test_integration.py` completes a password handshake and an encrypted message round-trip driven by that reference code. The pure-Python crypto path (the one that runs on a board) is tested explicitly, including the AES-GCM J0 derivation for the hub's 16-byte nonce.

**Q: How does the client answer PING?**
A: When it receives an encrypted `ping`, it replies with an encrypted `pong`. See `HiveMindClient._dispatch_message`.

**Q: What is the binary frame format?**
A: V1 bitstring: leading-zero pad + pad marker(1) + versioned(1) + [version(8)] + type(5) + compressed(1) + metalen(8) + meta + [bintype(4) for BINARY] + payload. It is byte-identical to `hivemind-bus-client`'s `serialization.get_bitstring`. See `binary.encode`.
