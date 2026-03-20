# Suggestions — hivemind-micropython-client

1. **Frozen C module for crypto** — Wrap mbedTLS as `_hivemind_crypto` MicroPython C extension. Eliminates MPY-001 and MPY-002 performance issues.
2. **Hardware-specific I2S examples** — Add examples for common mic boards (INMP441, SPH0645) with I2S audio capture and streaming.
3. **Wake word detection integration** — Lightweight on-device wake word (e.g., MicroWakeWord) before opening connection or streaming audio.
4. **Memory profiling on ESP32** — Profile heap usage during handshake and steady-state on ESP32 with 520KB SRAM. Document minimum free heap requirements.
5. **Structured error handling** — Replace bare `except Exception` in receive loop (`client.py:247`) with typed exceptions and logging.
