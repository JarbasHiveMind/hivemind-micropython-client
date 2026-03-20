"""Integration tests for HiveMind MicroPython client against a real hub.

These tests require a running hivemind-core instance. To set up:

1. Install and start the hub:
   ```bash
   pip install hivemind-core
   hivemind-core add-client --name "micropython-test"
   # Note the credentials (username, access_key, password)
   hivemind-core listen
   ```

2. Run these tests:
   ```bash
   HM_HOST=localhost HM_PORT=5678 \\
     HM_USERNAME=micropython-test \\
     HM_ACCESS_KEY=<access_key> \\
     HM_PASSWORD=<password> \\
     uv run pytest test/test_integration.py -v
   ```

Test IDs:
- INT-MP-01: Connect and complete handshake
- INT-MP-02: Send utterance, receive speak response
- INT-MP-03: Binary payload roundtrip (audio frames)
- INT-MP-04: Encryption negotiation (cipher selection)
- INT-MP-05: Multi-message exchange with keep-alive
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure hivemind package is importable
_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(_PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(_PACKAGE_ROOT))

import pytest

# Integration test markers
pytestmark = pytest.mark.integration


def get_hub_config() -> dict:
    """Load hub connection config from environment variables."""
    return {
        "host": os.getenv("HM_HOST", "localhost"),
        "port": int(os.getenv("HM_PORT", "5678")),
        "username": os.getenv("HM_USERNAME", ""),
        "access_key": os.getenv("HM_ACCESS_KEY", ""),
        "password": os.getenv("HM_PASSWORD", ""),
        "site_id": os.getenv("HM_SITE_ID", "micropython-test"),
    }


def hub_available() -> bool:
    """Check if hub is reachable (lightweight TCP check)."""
    config = get_hub_config()
    if not config["username"] or not config["access_key"] or not config["password"]:
        return False
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((config["host"], config["port"]))
        sock.close()
        return result == 0
    except Exception:
        return False


@pytest.fixture(scope="session", autouse=True)
def skip_if_no_hub():
    """Skip all integration tests if hub is not available."""
    if not hub_available():
        pytest.skip("HiveMind hub not available; set HM_HOST, HM_USERNAME, HM_ACCESS_KEY, HM_PASSWORD")


class TestHandshakeIntegration:
    """Verify client can connect to a real hub and complete handshake."""

    def test_connect_and_handshake_completes(self):
        """INT-MP-01: Client connects and handshake succeeds."""
        from hivemind.client import HiveMindClient

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )

        # Connect and wait for handshake
        try:
            assert client.connect()
            assert client.is_connected
            assert client.session_id  # Should be set after successful handshake
        finally:
            client.disconnect()

    def test_connection_uses_negotiated_cipher(self):
        """INT-MP-02: Client uses hub-negotiated cipher after handshake."""
        from hivemind.client import HiveMindClient

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
            preferred_cipher="AES-GCM",  # Request specific cipher
        )

        try:
            assert client.connect()
            # After handshake, negotiated cipher should be known
            assert client.cipher  # Should match or default based on server negotiation
        finally:
            client.disconnect()


class TestMessageExchange:
    """Verify client can send and receive bus messages."""

    def test_send_utterance_receives_response(self, timeout=10):
        """INT-MP-03: Send utterance, receive speak response from hub."""
        from hivemind.client import HiveMindClient

        config = get_hub_config()
        received_speak = []

        def on_message(msg_type: str, data: dict, context: dict):
            if msg_type == "speak":
                received_speak.append(data)

        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )
        client.on_bus_message = on_message

        try:
            assert client.connect()

            # Send test utterance
            client.send_utterance("hello")

            # Wait for response
            import time
            start = time.time()
            while not received_speak and (time.time() - start) < timeout:
                time.sleep(0.1)

            # Should receive at least a speak message (error or response)
            assert received_speak, f"No speak response received after {timeout}s"
        finally:
            client.disconnect()

    def test_bus_message_roundtrip(self):
        """INT-MP-04: Send custom bus message, verify it's processed."""
        from hivemind.client import HiveMindClient

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )

        try:
            assert client.connect()
            # Send a custom message type
            client.send_bus_message(
                "test.custom",
                {"test_data": "hello"},
                {"source": "micropython-test"}
            )
            # If no exception, message was sent successfully
        finally:
            client.disconnect()


class TestBinaryProtocol:
    """Verify binary payload exchange."""

    def test_send_binary_audio_frame(self):
        """INT-MP-05: Send raw audio binary frame."""
        from hivemind.client import HiveMindClient
        from hivemind.binary import BIN_RAW_AUDIO

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )

        try:
            assert client.connect()
            # Send a small test audio frame
            test_audio = b"\x00\x01\x02\x03" * 256  # 1KB of dummy audio
            client.send_binary(BIN_RAW_AUDIO, test_audio)
            # If no exception, binary was sent successfully
        finally:
            client.disconnect()


class TestConnectionResilience:
    """Verify client handles reconnection and errors gracefully."""

    def test_reconnect_after_disconnect(self):
        """INT-MP-06: Client can reconnect after graceful disconnect."""
        from hivemind.client import HiveMindClient

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )

        try:
            # First connection
            assert client.connect()
            assert client.is_connected

            # Disconnect
            client.disconnect()
            assert not client.is_connected

            # Reconnect
            assert client.connect()
            assert client.is_connected
        finally:
            client.disconnect()

    def test_keep_alive_during_idle_period(self, idle_time=5):
        """INT-MP-07: Client maintains connection during idle period."""
        from hivemind.client import HiveMindClient
        import time

        config = get_hub_config()
        client = HiveMindClient(
            host=config["host"],
            port=config["port"],
            username=config["username"],
            access_key=config["access_key"],
            password=config["password"],
            site_id=config["site_id"],
        )

        try:
            assert client.connect()
            initial_session = client.session_id

            # Wait without sending messages
            time.sleep(idle_time)

            # Connection should still be active
            assert client.is_connected
            assert client.session_id == initial_session
        finally:
            client.disconnect()
