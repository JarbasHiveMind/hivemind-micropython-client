# Maintenance Report — hivemind-micropython-client

## 2026-06-25

- **AI Model**: Claude Opus 4.8
- **Actions Taken**: Protocol-V1 conformance pass against `hivemind-bus-client` 0.9.2a1.
  Fixed two interop bugs: the pure-Python AES-GCM J0 derivation (now SP 800-38D
  GHASH-derived for the hub's 16-byte nonce) and the ChaCha20 wire identifier
  (now canonical `CHACHA20-POLY1305`, with legacy-spelling normalisation).
  Added `test/test_conformance.py` (byte-for-byte cross-checks vs the reference,
  including the on-device pure-Python crypto path) and rewrote
  `test/test_integration.py` as a self-contained handshake + encrypted
  round-trip over a mock transport driven by the reference protocol code.
  Updated CI (`tests.yml`) to install the reference stack via
  `test-requirements.txt` and run the full suite on PRs to `dev`. Refreshed
  README/FAQ/AUDIT/docs.
- **Oversight**: Human-reviewed plan, AI-generated code.

## 2026-03-20

- **AI Model**: Claude Opus 4.6
- **Actions Taken**: Initial implementation of complete HiveMind MicroPython client — three-tier crypto backends (C module, cryptography, pure Python), async WebSocket client with handshake FSM, binary V1 bitstring codec, examples, and unit tests. Created `docs/index.md`, `FAQ.md`, `AUDIT.md`, `SUGGESTIONS.md`.
- **Oversight**: Human-reviewed plan, AI-generated code.
