"""hivemind-core 5.x sends its handshake parameters without a legacy ``handshake`` flag.

HIVEMIND-CRYPTO-1 §3.3 defines the server's step-2 parameter message by its
Noise parameters. hivemind-core 5.1.3a1 sends:

    {"max_protocol_version": 3, "binarize": false, "encodings": [...],
     "ciphers": [...], "noise": {"patterns": ["XXpsk2"],
     "suites": ["25519_ChaChaPoly_SHA256", "25519_AESGCM_SHA256"]}}

The client returned early unless ``payload["handshake"]`` was truthy, so it
ignored that message, never started the Noise handshake, and stayed in
STATE_HELLO_RECEIVED (2) until the caller timed out.
"""
import asyncio
import json

from hivemind.client import (
    STATE_CONNECTING,
    STATE_HANDSHAKE_SENT,
    STATE_HELLO_RECEIVED,
    HiveMindClient,
)

HELLO = {"msg_type": "hello", "payload": {
    "pubkey": "", "peer": "mpy-sat::1", "node_id": "hub-node-id"}}

CORE5_SHAKE = {"msg_type": "shake", "payload": {
    "max_protocol_version": 3,
    "binarize": False,
    "encodings": ["JSON-B64", "JSON-HEX"],
    "ciphers": ["CHACHA20-POLY1305", "AES-GCM"],
    "noise": {"patterns": ["XXpsk2"],
              "suites": ["25519_ChaChaPoly_SHA256", "25519_AESGCM_SHA256"]},
}}


def _client(**kwargs):
    client = HiveMindClient(host="127.0.0.1", port=5678, username="mpy-sat",
                            access_key="mpy-key", password="pw",
                            psk=bytes(range(32)), reconnect_ms=0, **kwargs)
    sent = []

    async def capture(frame):
        sent.append(frame)

    client._send = capture
    client._set_state(STATE_CONNECTING)
    return client, sent


def _run(client, *messages):
    async def feed():
        for msg in messages:
            await client._handle_handshake(json.dumps(msg))
    asyncio.run(feed())


def test_a_core5_shake_starts_the_noise_handshake():
    client, sent = _client()

    _run(client, HELLO, CORE5_SHAKE)

    assert client.state == STATE_HANDSHAKE_SENT, \
        f"client ignored the hub's shake (state {client.state})"
    frames = [json.loads(f) if isinstance(f, str) else f for f in sent]
    noise = [f for f in frames if isinstance(f, dict)
             and (f.get("payload") or {}).get("noise", {}).get("msg")]
    assert noise, f"no Noise message 1 was sent: {frames}"
    assert noise[0]["payload"]["noise"]["pattern"] == "XXpsk2"


def test_a_shake_without_noise_or_flag_is_still_ignored():
    client, sent = _client()

    _run(client, HELLO, {"msg_type": "shake", "payload": {"binarize": False}})

    assert client.state == STATE_HELLO_RECEIVED
    assert not sent
