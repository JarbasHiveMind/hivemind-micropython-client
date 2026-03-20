# Audit — hivemind-micropython-client

## Known Issues

| ID | Severity | Description | Location |
|----|----------|-------------|----------|
| MPY-001 | High | Pure Python AES-GCM uses `_gf_mult` GF(2^128) multiply: O(128) iterations per 16-byte block. Very slow on MicroPython. | `crypto.py:226-239` |
| MPY-002 | High | Pure Python PBKDF2 100k iterations: minutes on ESP32 MicroPython. Must use frozen C module for production. | `crypto.py:102-126` |
| MPY-003 | Medium | WebSocket reconnect (`_reconnect` — `client.py:219`) not tested on real MicroPython hardware. | `client.py:219-225` |
| MPY-004 | Low | `from __future__ import annotations` used in all modules. May not work on all MicroPython builds. | `crypto.py:10`, `client.py:9`, `binary.py:7` |
| MPY-005 | Low | Exception handling in receive loop catches all exceptions silently. | `client.py:247-248` |
