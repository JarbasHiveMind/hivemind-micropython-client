"""Integration tests: full handshake + message round-trip against a mock hub.

These tests exercise the real ``HiveMindClient`` handshake state machine and
encrypted-message dispatch end-to-end, with the *hub side* implemented by the
canonical reference (``poorman_handshake`` + ``hivemind_bus_client.encryption``)
speaking over an in-process mock WebSocket transport.

No board, no network, and no running ``hivemind-core`` are required, so the
whole thing runs in CI. Because the server side IS the reference protocol code,
a passing run proves the client completes a Protocol-V1 password handshake and
exchanges encrypted bus messages exactly as a real hub expects.

For a true on-device / live-hub test see ``docs/integration-testing.md``.
"""
import asyncio
import json
import unittest

from poorman_handshake.symmetric import PasswordHandShake
from poorman_handshake.symmetric.utils import iv_from_hsub
from hivemind_bus_client.encryption import (
    encrypt_as_json,
    decrypt_from_json,
    SupportedCiphers,
    SupportedEncodings,
)

from hivemind.client import HiveMindClient

_PASSWORD = "correct horse battery staple 42!"
_CIPHER = SupportedCiphers.AES_GCM
_ENCODING = SupportedEncodings.JSON_HEX
_CIPHER_WIRE = "AES-GCM"
_ENCODING_WIRE = "JSON-HEX"


class MockHub:
    """Minimal Protocol-V1 hub that drives the real reference handshake.

    Plays the server role: emits HELLO, then a HANDSHAKE request, then a
    HANDSHAKE response carrying its password envelope, then decrypts the
    client's encrypted HELLO and can exchange encrypted bus messages.
    """

    def __init__(self, password=_PASSWORD):
        self._shake = PasswordHandShake(password)
        self.key = None
        self.client_iv = None
        self.received = []  # decrypted client envelopes (after handshake)

    def hello_frame(self):
        return json.dumps({
            "msg_type": "hello",
            "payload": {"pubkey": "", "peer": "mock@hub", "node_id": "mock-node"},
            "metadata": {}, "route": [], "node": "mock-node",
            "target_site_id": None, "target_pubkey": None, "source_peer": None,
        })

    def handshake_request_frame(self):
        return json.dumps({
            "msg_type": "shake",
            "payload": {
                "handshake": True,
                "binarize": False,
                "password": True,
                "encodings": [_ENCODING_WIRE],
                "ciphers": [_CIPHER_WIRE],
            },
            "metadata": {}, "route": [], "node": None,
            "target_site_id": None, "target_pubkey": None, "source_peer": None,
        })

    def on_client_shake(self, frame):
        """Process the client's plaintext HANDSHAKE; return the server response
        frame and finalise the shared key."""
        msg = json.loads(frame)
        assert msg["msg_type"] == "shake", msg
        client_envelope = msg["payload"]["envelope"]
        self.client_iv = iv_from_hsub(client_envelope)
        server_envelope = self._shake.generate_handshake()
        # Hub derives the key from the client's envelope (verifies the password).
        self._shake.receive_and_verify(client_envelope)
        self.key = self._shake.secret
        return json.dumps({
            "msg_type": "shake",
            "payload": {
                "envelope": server_envelope,
                "cipher": _CIPHER_WIRE,
                "encoding": _ENCODING_WIRE,
            },
            "metadata": {}, "route": [], "node": None,
            "target_site_id": None, "target_pubkey": None, "source_peer": None,
        })

    def decrypt(self, blob):
        return decrypt_from_json(self.key, blob, _CIPHER, _ENCODING)

    def encrypt_bus(self, msg_type, data, context=None):
        envelope = json.dumps({
            "msg_type": "bus",
            "payload": {"type": msg_type, "data": data, "context": context or {}},
            "metadata": {}, "route": [], "node": None,
            "target_site_id": None, "target_pubkey": None, "source_peer": None,
        })
        return encrypt_as_json(self.key, envelope, _CIPHER, _ENCODING)


class MockWebSocket:
    """In-process async WebSocket. ``recv`` pops queued server frames; ``send``
    routes the client's frame to the hub and may queue a server reply."""

    def __init__(self, hub):
        self._hub = hub
        self._inbox = asyncio.Queue()
        self.closed = False
        # Server opens with HELLO then the handshake request.
        self._inbox.put_nowait(hub.hello_frame())
        self._inbox.put_nowait(hub.handshake_request_frame())

    async def recv(self):
        if self.closed:
            return None
        return await self._inbox.get()

    async def send(self, data):
        msg = json.loads(data)
        mtype = msg.get("msg_type")
        if mtype == "shake":
            # Client sent its handshake; reply with the server's envelope.
            self._inbox.put_nowait(self._hub.on_client_shake(data))
        else:
            # Encrypted message after the key is established.
            self._hub.received.append(self._hub.decrypt(data))

    async def close(self):
        self.closed = True

    def queue_server(self, frame):
        self._inbox.put_nowait(frame)


def _run_handshake(client, hub, ws, extra_frames=0):
    """Drive the client's receive loop through the handshake (and optional
    extra inbound frames), then stop. Returns when the loop exits."""

    async def runner():
        # Inject the mock transport and prime the state machine.
        client._ws = ws
        client._session_id = client._generate_session_id()
        client._set_state(1)  # STATE_CONNECTING

        async def stop_after():
            # Let the handshake and any queued frames drain, then disconnect
            # so the receive loop terminates deterministically.
            for _ in range(50):
                await asyncio.sleep(0)
                if ws._inbox.empty() and client.state >= 5:
                    break
            await asyncio.sleep(0)
            ws.closed = True
            client.state = 0  # STATE_DISCONNECTED -> loop exits
            ws._inbox.put_nowait("")  # unblock a pending recv

        await asyncio.gather(client._receive_loop(), stop_after())

    asyncio.run(runner())


class TestHandshakeRoundTrip(unittest.TestCase):
    """INT-MP-01: complete a password handshake with the reference hub."""

    def test_handshake_completes_and_keys_match(self):
        client = HiveMindClient(
            host="mock", port=0, username="u", access_key="k",
            password=_PASSWORD, site_id="mock-sat",
            reconnect_ms=0,  # no auto-reconnect in tests
        )
        hub = MockHub()
        ws = MockWebSocket(hub)

        connected = []
        client.on_connected = lambda: connected.append(True)

        _run_handshake(client, hub, ws)

        # Client reached READY (state 5) and on_connected fired.
        self.assertTrue(connected, "on_connected never fired")
        # Both sides derived the same session key.
        self.assertIsNotNone(client._key)
        self.assertEqual(client._key, hub.key)
        # Client negotiated the hub's cipher/encoding.
        self.assertEqual(client._cipher, _CIPHER_WIRE)
        self.assertEqual(client._encoding, _ENCODING_WIRE)
        # The hub received the client's encrypted HELLO and could decrypt it.
        self.assertTrue(hub.received, "hub received no encrypted HELLO")
        hello = json.loads(hub.received[0])
        self.assertEqual(hello["msg_type"], "hello")
        self.assertEqual(hello["payload"]["site_id"], "mock-sat")


class TestEncryptedMessageRoundTrip(unittest.TestCase):
    """INT-MP-02/03: send an utterance and receive a ``speak`` reply."""

    def test_utterance_then_speak_reply(self):
        client = HiveMindClient(
            host="mock", port=0, username="u", access_key="k",
            password=_PASSWORD, site_id="mock-sat", reconnect_ms=0,
        )
        hub = MockHub()
        ws = MockWebSocket(hub)

        spoken = []

        def on_bus(msg_type, data, context):
            if msg_type == "speak":
                spoken.append(data.get("utterance"))

        client.on_bus_message = on_bus

        async def runner():
            client._ws = ws
            client._session_id = client._generate_session_id()
            client._set_state(1)

            async def driver():
                # Wait for handshake to finish.
                for _ in range(50):
                    await asyncio.sleep(0)
                    if client.state >= 5:
                        break
                # Client sends an utterance -> hub decrypts it.
                await client.send_utterance("what time is it")
                await asyncio.sleep(0)
                # Hub replies with an encrypted speak bus message.
                ws.queue_server(
                    hub.encrypt_bus("speak", {"utterance": "it is noon"})
                )
                for _ in range(20):
                    await asyncio.sleep(0)
                    if spoken:
                        break
                ws.closed = True
                client.state = 0
                ws._inbox.put_nowait("")

            await asyncio.gather(client._receive_loop(), driver())

        asyncio.run(runner())

        # Hub decrypted the utterance the client sent.
        utt = [json.loads(m) for m in hub.received]
        sent_utts = [
            m["payload"]["data"]["utterances"]
            for m in utt
            if m["payload"].get("type") == "recognizer_loop:utterance"
        ]
        self.assertIn(["what time is it"], sent_utts)
        # Client decrypted and dispatched the hub's speak reply.
        self.assertEqual(spoken, ["it is noon"])


class TestPingPong(unittest.TestCase):
    """INT-MP-04: the client answers an encrypted PING with a responsive PING.

    There is no PONG message type (HIVEMIND-MSG-1 §4). The answer is this
    node's own PING carrying the originator's ``flood_id``, PROPAGATE-wrapped,
    which is what lets the originator match it to the flood it started. The
    client used to reply with a ``pong`` frame on wire code 13, which is
    unassigned, so a reference decoder rejected it outright.
    """

    def test_ping_is_answered_with_a_responsive_ping(self):
        client = HiveMindClient(
            host="mock", port=0, username="u", access_key="k",
            password=_PASSWORD, site_id="mock-sat", reconnect_ms=0,
        )
        hub = MockHub()
        ws = MockWebSocket(hub)

        async def runner():
            client._ws = ws
            client._session_id = client._generate_session_id()
            client._set_state(1)

            async def driver():
                for _ in range(50):
                    await asyncio.sleep(0)
                    if client.state >= 5:
                        break
                # Hub sends an encrypted ping envelope.
                ping = encrypt_as_json(
                    hub.key,
                    json.dumps({
                        "msg_type": "ping", "payload": {"flood_id": "flood-1"},
                        "metadata": {}, "route": [], "node": None,
                        "target_site_id": None, "target_pubkey": None,
                        "source_peer": None,
                    }),
                    _CIPHER, _ENCODING,
                )
                ws.queue_server(ping)
                for _ in range(20):
                    await asyncio.sleep(0)
                ws.closed = True
                client.state = 0
                ws._inbox.put_nowait("")

            await asyncio.gather(client._receive_loop(), driver())

        asyncio.run(runner())

        sent = [json.loads(m) for m in hub.received]

        # No frame may carry the retired pong type.
        self.assertEqual(
            [m for m in sent if m.get("msg_type") == "pong"], [],
            "client still emits a pong; wire code 13 is unassigned and a "
            "reference decoder rejects it",
        )

        # The answer is a PROPAGATE wrapping a PING with the same flood_id.
        answers = [
            m for m in sent
            if m.get("msg_type") == "propagate"
            and isinstance(m.get("payload"), dict)
            and m["payload"].get("msg_type") == "ping"
        ]
        self.assertTrue(answers, "client did not answer ping with a responsive ping")
        inner = answers[0]["payload"]["payload"]
        self.assertEqual(inner.get("flood_id"), "flood-1",
                         "the answer must carry the originator's flood_id")
        self.assertEqual(inner.get("site_id"), "mock-sat")
        self.assertIn("::", inner.get("peer", ""),
                      "peer should be username::session_id")

    def test_a_repeated_flood_is_answered_once(self):
        """A flood that arrives twice must not produce two answers, or the
        originator maps one node as two."""
        client = HiveMindClient(
            host="mock", port=0, username="u", access_key="k",
            password=_PASSWORD, site_id="mock-sat", reconnect_ms=0,
        )
        client._seen_flood_ids = []
        sent = []

        async def fake_send(msg_type, payload):
            sent.append((msg_type, payload))

        client._send_encrypted = fake_send
        client._session_id = "sess-1"

        asyncio.run(client._handle_ping({"flood_id": "same"}))
        asyncio.run(client._handle_ping({"flood_id": "same"}))
        self.assertEqual(len(sent), 1, "the same flood was answered twice")

        asyncio.run(client._handle_ping({"flood_id": "other"}))
        self.assertEqual(len(sent), 2, "a new flood must still be answered")


if __name__ == "__main__":
    unittest.main()
