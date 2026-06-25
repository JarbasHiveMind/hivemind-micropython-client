# Audit — hivemind-micropython-client

## Protocol-V1 conformance

The crypto, key derivation, hsub, cipher/encoding wire strings, and binary
framing are validated byte-for-byte against the reference `hivemind-bus-client`
by `test/test_conformance.py`, and a full password handshake plus encrypted
message round-trip is validated by `test/test_integration.py` (reference
protocol code over a mock transport). Both run in CI.

## Open items

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| MPY-001 | High | Pure-Python AES-GCM `_gf_mult` GF(2^128) multiply is O(128) per 16-byte block — slow on MicroPython. Correct (interop-tested) but freeze `_hivemind_crypto` for production. | `crypto.AesGcm._gf_mult` |
| MPY-002 | High | Pure-Python PBKDF2 100k iterations: tens of seconds on ESP32. Use the frozen C module (`_hivemind_crypto`) for production. | `crypto.pbkdf2_hmac_sha256` |
| MPY-003 | Medium | WebSocket reconnect (`_reconnect`) is exercised only via the mock transport, not on real hardware over a flaky link. | `client._reconnect` |
| MPY-004 | Low | `from __future__ import annotations` is used in all modules; tolerated by MicroPython 1.20+ but a build without it would need the import removed. | module headers |
| MPY-005 | Low | The receive loop catches all exceptions before reconnecting; failures are not surfaced to a callback. | `client._receive_loop` |
| MPY-006 | Low | Binary streaming over the wire (binarize) is negotiated off (`binarize: False` in the shake); the codec is correct and tested but the client does not currently send raw encrypted binary frames. Audio streaming to the hub needs the binarize path implemented. | `client.send_binary` |

## Resolved

- **AES-GCM 16-byte nonce interop** — the pure-Python AES-GCM now computes the
  pre-counter block J0 per NIST SP 800-38D (GHASH-derived for non-96-bit
  nonces), so it interoperates with the hub's 16-byte nonces. Previously it
  used the 96-bit `IV || 0x00000001` shortcut and silently failed to interop
  while still self-round-tripping. Guarded by `test_conformance.py`.
- **ChaCha20 cipher string** — the wire identifier is now the canonical
  `"CHACHA20-POLY1305"` (was `"ChaCha20-Poly1305"`, which the hub rejects).
  `_norm_cipher` still accepts the old spelling and coerces it.
