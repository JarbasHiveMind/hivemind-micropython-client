"""Protocol v3 integration tests: full Noise handshake + message round-trip
against a mock hub whose crypto is the canonical Python reference
(``poorman_handshake.noise.NoiseHandShake``, wrapping ``noiseprotocol``).

The client side is the pure-Python initiator in ``hivemind/noise.py`` driven
through the real ``HiveMindClient`` state machine over an in-process mock
WebSocket. Because the server side IS the reference protocol code, a passing
run proves the client completes a protocol-v3 Noise handshake and exchanges
Noise transport frames exactly as a real hub expects.

No board, no network, and no running ``hivemind-core`` are required. For a
true on-device / live-hub test see ``docs/integration-testing.md``.
"""
import asyncio
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519 as _ref_x25519
from poorman_handshake.noise import NoiseHandShake

from hivemind.client import HiveMindClient, STATE_READY, STATE_DISCONNECTED
from hivemind.noise import build_prologue, noise_protocol_name

_PSK = bytes(range(32, 64))
_SERVER_STATIC = bytes([0x55] * 32)


def _server_static_pub() -> bytes:
    key = _ref_x25519.X25519PrivateKey.from_private_bytes(_SERVER_STATIC)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _envelope(msg_type, payload):
    return json.dumps({
        "msg_type": msg_type, "payload": payload,
        "metadata": {}, "route": [], "node": None,
        "target_site_id": None, "target_pubkey": None, "source_peer": None,
    })


class MockNoiseHub:
    """Minimal protocol-v3 hub: plays the Noise responder with the reference
    stack, advertises patterns/suites, and speaks transport frames."""

    def __init__(self, psk=_PSK, patterns=("KKpsk0", "XXpsk2"),
                 client_static_pub=None):
        self.psk = psk
        self.patterns = list(patterns)
        self.client_static_pub = client_static_pub  # for KKpsk0
        self.noise = None
        self.received = []      # decrypted client transport plaintexts
        self.hello_payload = {
            "pubkey": "", "peer": "mock@hub", "node_id": "mock-node",
        }
        self.handshake_payload = {
            "handshake": True,
            "binarize": False,
            "password": True,
            "min_protocol_version": 0,
            "max_protocol_version": 3,
            "encodings": ["JSON-HEX"],
            "ciphers": ["CHACHA20-POLY1305"],
            "noise": {"patterns": self.patterns,
                      "suites": ["25519_ChaChaPoly_SHA256"]},
        }

    def hello_frame(self):
        return _envelope("hello", self.hello_payload)

    def handshake_request_frame(self):
        return _envelope("shake", self.handshake_payload)

    def on_client_shake(self, frame):
        """Process a client HANDSHAKE envelope; returns the reply frame (the
        server's Noise message) or None (handshake already complete)."""
        msg = json.loads(frame)
        noise = msg["payload"]["noise"]
        if self.noise is None:
            # Noise message 1: fixes pattern + suite -> build the responder
            pattern = noise["pattern"]
            name = noise_protocol_name(pattern, noise["suite"])
            prologue = build_prologue(self.hello_payload,
                                      self.handshake_payload, name)
            import tempfile, os
            from binascii import hexlify
            with tempfile.TemporaryDirectory() as tmp:
                key_path = os.path.join(tmp, "hub.key")
                with open(key_path, "wb") as f:
                    f.write(hexlify(_SERVER_STATIC))
                self.noise = NoiseHandShake(
                    initiator=False, psk=self.psk, path=key_path,
                    remote_pubkey=(self.client_static_pub
                                   if pattern == "KKpsk0" else None),
                    prologue=prologue, pattern=name.encode())
            self.noise.read_message(bytes.fromhex(noise["msg"]))
            msg2 = self.noise.write_message(
                json.dumps({"encoding": "JSON-HEX"},
                           separators=(",", ":")).encode())
            return _envelope("shake", {"noise": {"msg": msg2.hex()}})
        # Noise message 3 (XXpsk2)
        self.noise.read_message(bytes.fromhex(noise["msg"]))
        return None

    def on_transport(self, data):
        """Decrypt an inbound Noise transport frame from the client."""
        self.received.append(self.noise.decrypt(bytes(data)))

    def encrypt_bus(self, msg_type, data, context=None):
        envelope = _envelope("bus", {"type": msg_type, "data": data,
                                     "context": context or {}})
        return self.noise.encrypt(b"\x00" + envelope.encode())


class MockWebSocket:
    """In-process async WebSocket routing frames between client and hub."""

    def __init__(self, hub):
        self._hub = hub
        self._inbox = asyncio.Queue()
        self.closed = False
        self._inbox.put_nowait(hub.hello_frame())
        self._inbox.put_nowait(hub.handshake_request_frame())

    async def recv(self):
        if self.closed:
            return None
        return await self._inbox.get()

    async def send(self, data):
        if isinstance(data, (bytes, bytearray)):
            # protocol v3 transport frame
            self._hub.on_transport(data)
            return
        msg = json.loads(data)
        if msg.get("msg_type") == "shake":
            reply = self._hub.on_client_shake(data)
            if reply is not None:
                self._inbox.put_nowait(reply)

    async def close(self):
        self.closed = True

    def queue_server(self, frame):
        self._inbox.put_nowait(frame)


def _drive(client, ws, until_state=STATE_READY):
    """Run the client's receive loop until the handshake settles."""

    async def runner():
        client._ws = ws
        client._session_id = client._generate_session_id()
        client._set_state(1)  # STATE_CONNECTING

        async def stop_after():
            for _ in range(100):
                await asyncio.sleep(0)
                if ws._inbox.empty() and client.state in (
                        until_state, STATE_DISCONNECTED):
                    break
            await asyncio.sleep(0)
            ws.closed = True
            client.state = STATE_DISCONNECTED
            ws._inbox.put_nowait("")  # unblock a pending recv

        await asyncio.gather(client._receive_loop(), stop_after())

    asyncio.run(runner())


def _make_client(**kwargs):
    defaults = dict(host="mock", port=0, username="u", access_key="k",
                    password="unused-at-v3", site_id="mock-sat",
                    reconnect_ms=0, psk=_PSK)
    defaults.update(kwargs)
    return HiveMindClient(**defaults)


class TestNoiseHandshakeXX(unittest.TestCase):
    """INT-MP-V3-01: XXpsk2 handshake against the reference responder."""

    def test_handshake_and_encrypted_hello(self):
        client = _make_client()
        hub = MockNoiseHub()
        ws = MockWebSocket(hub)
        connected = []
        client.on_connected = lambda: connected.append(True)

        _drive(client, ws)

        self.assertTrue(connected, "on_connected never fired")
        self.assertIsNotNone(client._noise_transport)
        # the hub decrypted the client's first transport message: the HELLO
        self.assertTrue(hub.received, "hub received no encrypted HELLO")
        marker, body = hub.received[0][:1], hub.received[0][1:]
        self.assertEqual(marker, b"\x00")
        hello = json.loads(body)
        self.assertEqual(hello["msg_type"], "hello")
        self.assertEqual(hello["payload"]["site_id"], "mock-sat")
        # XXpsk2 learned the server's static key for TOFU pinning
        self.assertEqual(client.server_noise_key, _server_static_pub())

    def test_bus_round_trip(self):
        client = _make_client()
        hub = MockNoiseHub()
        ws = MockWebSocket(hub)
        got = []
        client.on_bus_message = lambda t, d, c: got.append((t, d))
        client.on_connected = lambda: ws.queue_server(
            hub.encrypt_bus("speak", {"utterance": "hi"}))

        _drive(client, ws)

        self.assertIn(("speak", {"utterance": "hi"}), got)

    def test_wrong_psk_is_fatal(self):
        """A wrong provisioned PSK aborts at handshake time."""
        client = _make_client(psk=b"\xee" * 32)
        hub = MockNoiseHub()
        ws = MockWebSocket(hub)
        connected = []
        client.on_connected = lambda: connected.append(True)

        # the reference responder raises on the client's msg3 / or the
        # client aborts on msg2 — either way the client never reaches READY
        try:
            _drive(client, ws)
        except Exception:
            pass
        self.assertFalse(connected)
        self.assertIsNone(client._noise_transport)
        self.assertEqual(client.state, STATE_DISCONNECTED)

    def test_pinned_key_mismatch_is_fatal(self):
        """A pinned server key contradicting the handshake aborts (§3.4.5)."""
        client = _make_client(server_noise_key=b"\x99" * 32,
                              noise_static_key=b"\x66" * 32)
        # server only offers XX so the bogus pin is checked post-handshake
        hub = MockNoiseHub(patterns=("XXpsk2",))
        ws = MockWebSocket(hub)
        connected = []
        client.on_connected = lambda: connected.append(True)

        _drive(client, ws)

        self.assertFalse(connected)
        self.assertIsNone(client._noise_transport)


class TestNoiseHandshakeKK(unittest.TestCase):
    """INT-MP-V3-02: KKpsk0 with pre-provisioned static keys."""

    def test_kk_selected_and_completes(self):
        client_static = bytes([0x77] * 32)
        from hivemind.noise import x25519_public_key
        client = _make_client(noise_static_key=client_static,
                              server_noise_key=_server_static_pub())
        hub = MockNoiseHub(client_static_pub=x25519_public_key(client_static))
        ws = MockWebSocket(hub)
        connected = []
        client.on_connected = lambda: connected.append(True)

        _drive(client, ws)

        self.assertTrue(connected, "KKpsk0 handshake did not complete")
        self.assertTrue(hub.received)
        # KK completes in one round trip: hub got HELLO as first transport msg
        self.assertEqual(hub.received[0][:1], b"\x00")


class TestLegacyFallback(unittest.TestCase):
    """INT-MP-V3-03: v0-v2 keeps working when v3 cannot be negotiated."""

    def _assert_legacy_shake(self, client, hub):
        ws = MockWebSocket(hub)
        sent = []
        orig = ws.send

        async def spy(data):
            sent.append(data)
            if isinstance(data, str):
                msg = json.loads(data)
                if msg.get("msg_type") == "shake":
                    # legacy handshake carries an hsub envelope, never noise
                    self.assertIn("envelope", msg["payload"])
                    self.assertNotIn("noise", msg["payload"])
                    return  # don't run the noise hub logic
            await orig(data)

        ws.send = spy
        _drive(client, ws, until_state=3)
        shakes = [s for s in sent if isinstance(s, str)
                  and json.loads(s).get("msg_type") == "shake"]
        self.assertTrue(shakes, "client never sent a handshake")

    def test_no_psk_falls_back(self):
        """Server offers v3 but no PSK is provisioned -> legacy hsub path."""
        self._assert_legacy_shake(_make_client(psk=None), MockNoiseHub())

    def test_v2_server_falls_back(self):
        """Server maxes out at v2 -> legacy hsub path."""
        hub = MockNoiseHub()
        hub.handshake_payload["max_protocol_version"] = 2
        self._assert_legacy_shake(_make_client(), hub)

    def test_client_capped_at_v2_falls_back(self):
        self._assert_legacy_shake(_make_client(max_protocol_version=2),
                                  MockNoiseHub())

    def test_no_mutual_suite_falls_back(self):
        hub = MockNoiseHub()
        hub.handshake_payload["noise"]["suites"] = ["25519_AESGCM_SHA256"]
        self._assert_legacy_shake(_make_client(), hub)


if __name__ == "__main__":
    unittest.main()
