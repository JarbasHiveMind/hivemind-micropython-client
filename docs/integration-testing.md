# Integration Testing Guide

This guide explains how to run integration tests that verify the MicroPython client works correctly against a real HiveMind hub.

## Prerequisites

1. **HiveMind Hub** — Install and run `hivemind-core`:
   ```bash
   pip install hivemind-core
   hivemind-core listen  # Starts hub on localhost:5678
   ```

2. **Hub Credentials** — Register a client:
   ```bash
   hivemind-core add-client --name "micropython-test"
   # Output:
   # Client registered: micropython-test
   # Access Key: <access_key>
   # Password: <password>
   # Note these for test environment variables
   ```

3. **Test Dependencies**:
   ```bash
   uv pip install pytest
   ```

## Running Integration Tests

Set environment variables and run pytest:

```bash
export HM_HOST=localhost
export HM_PORT=5678
export HM_USERNAME=micropython-test
export HM_ACCESS_KEY=<your_access_key>
export HM_PASSWORD=<your_password>
export HM_SITE_ID=micropython-test

uv run pytest test/test_integration.py -v -m integration
```

### Test Categories

| Test ID | Test Name | Validates |
|---------|-----------|-----------|
| INT-MP-01 | `test_connect_and_handshake_completes` | Handshake protocol, session establishment |
| INT-MP-02 | `test_connection_uses_negotiated_cipher` | Cipher negotiation, handshake completion |
| INT-MP-03 | `test_send_utterance_receives_response` | BUS message exchange, end-to-end routing |
| INT-MP-04 | `test_bus_message_roundtrip` | Custom message type support |
| INT-MP-05 | `test_send_binary_audio_frame` | Binary protocol, audio payload handling |
| INT-MP-06 | `test_reconnect_after_disconnect` | Graceful reconnect, session recovery |
| INT-MP-07 | `test_keep_alive_during_idle_period` | PING/PONG keep-alive, connection stability |

## Docker Setup (Optional)

For automated CI, run the hub in Docker:

```bash
docker run -p 5678:5678 -p 5679:5679 \
  -e HIVEMIND_DB=json \
  hivemind:latest

# In another terminal, add a test client:
docker exec <container> hivemind-core add-client --name "micropython-test"
```

## Troubleshooting

### Connection refused
- Ensure hub is running: `curl http://localhost:5679/ping`
- Check firewall if connecting remotely

### Handshake timeout
- Verify credentials (username, access_key, password)
- Check hub logs for authentication errors

### "No speak response received"
- May indicate hub cannot reach the NLP backend
- Verify hub has a skill/agent configured to handle `recognizer_loop:utterance`
- Check hub logs for skill execution errors

## Expected Message Flow

### Utterance → Response

```
Client sends:
  recognizer_loop:utterance {utterances: ["hello"]}

Hub processes:
  (NLU -> Intent matching -> Skill execution)

Hub responds:
  speak {utterance: "..."}
```

### Binary Audio Stream

```
Client sends:
  MSG_BINARY {bin_type: BIN_RAW_AUDIO, data: <audio_frame>}

Hub processes:
  (If STT configured, transcribes audio)

Hub responds:
  (Intent matching and skill execution as above)
```

## Next Steps

- **Performance testing** — Test with large payloads, multiple concurrent messages
- **Stress testing** — Rapid connect/disconnect cycles, long idle periods
- **Error recovery** — Network interruption simulation, server restart during connection
- **Encoding testing** — Verify all 7 encodings work with real hub (e.g., JSON-B64, JSON-Z85B)
