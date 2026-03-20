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
A: `mpremote mip install github:OpenVoiceOS/hivemind-micropython-client`

**Q: What ciphers are supported?**
A: AES-256-GCM (`AesGcm` — `crypto.py:169`) and ChaCha20-Poly1305 (`ChaCha20Poly1305` — `crypto.py:296`). Negotiated during handshake.

**Q: What is the binary frame format?**
A: V1 bitstring: pad + versioned + version + type(5) + compressed + metalen(8) + meta + [bintype(4)] + payload. See `binary.py:89-135`.
