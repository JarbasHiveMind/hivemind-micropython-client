#!/usr/bin/env python3
"""Generate Noise interop fixtures for the protocol-v3 implementation.

Runs a full ``Noise_XXpsk2_25519_ChaChaPoly_SHA256`` and
``Noise_KKpsk0_25519_ChaChaPoly_SHA256`` handshake with the Python reference
stack (``poorman_handshake.noise.NoiseHandShake``, which wraps the vetted
``noiseprotocol`` library) using **fixed static and ephemeral keys**, and
dumps every wire byte as JSON. The pure-Python Noise initiator in
``hivemind/noise.py`` must reproduce messages 1 and 3 byte-identically,
decrypt message 2 and the responder transport frames, and produce
byte-identical initiator transport frames at counters 0 and 1.

Usage:
    ~/.venvs/hivemind-v3/bin/python test/gen_noise_fixtures.py \
        > test/noise_fixtures.json
"""
import json
import os
import sys
import tempfile
from binascii import hexlify

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from noise.backends.default.diffie_hellmans import ED25519
from noise.backends.default.keypairs import KeyPair25519
from poorman_handshake.noise import NoiseHandShake

# ----------------------------------------------------------------- fixed keys
PSK = bytes(range(1, 33))                       # 0x01..0x20
S_INITIATOR = bytes([0x11] * 32)                # static privates (pre-clamp)
S_RESPONDER = bytes([0x22] * 32)
E_INITIATOR = bytes([0x33] * 32)                # ephemeral privates
E_RESPONDER = bytes([0x44] * 32)


def pub(priv: bytes) -> bytes:
    key = x25519.X25519PrivateKey.from_private_bytes(priv)
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# Deterministic ephemerals: noiseprotocol calls ED25519.generate_keypair()
# once per side, initiator first (its message 1 is written first).
_eph_queue = []


def _fixed_generate_keypair(self):
    priv = _eph_queue.pop(0)
    private_key = x25519.X25519PrivateKey.from_private_bytes(priv)
    public_key = private_key.public_key()
    return KeyPair25519(
        private_key, public_key,
        public_key.public_bytes(serialization.Encoding.Raw,
                                serialization.PublicFormat.Raw))


ED25519.generate_keypair = _fixed_generate_keypair


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------- prologue
# Representative negotiation payloads (HIVEMIND-CRYPTO-1 §3.4.3): the server's
# cleartext HELLO payload, its cleartext parameter HANDSHAKE payload, then the
# node's selected Noise protocol name.
HELLO_PAYLOAD = {
    "pubkey": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
    "peer": "tcp4:127.0.0.1:52250",
    "node_id": "hivemind-core@testhost",
    "session_id": "abcd1234",
}
HANDSHAKE_PAYLOAD = {
    "handshake": True,
    "binarize": True,
    "preshared_key": False,
    "password": True,
    "crypto_key": False,
    "min_protocol_version": 0,
    "max_protocol_version": 3,
    "encodings": ["JSON-HEX", "JSON-B64"],
    "ciphers": ["CHACHA20-POLY1305", "AES-GCM"],
    "noise": {
        "patterns": ["KKpsk0", "XXpsk2"],
        "suites": ["25519_ChaChaPoly_SHA256"],
    },
}

MSG1_PAYLOAD = canonical_json({"binarize": False, "encodings": ["JSON-HEX"]})
MSG2_PAYLOAD = canonical_json({"encoding": "JSON-HEX"})

TRANSPORT_C2S = b"\x00" + json.dumps(
    {"msg_type": "hello",
     "payload": {"pubkey": "", "session": {"session_id": "abcd1234"},
                 "site_id": "micropython-test"}},
    separators=(",", ":")).encode("utf-8")
TRANSPORT_C2S_2 = b"\x00" + b'{"msg_type":"bus","payload":{"type":"ping"}}'
TRANSPORT_S2C = b"\x00" + b'{"msg_type":"bus","payload":{"type":"pong"}}'
TRANSPORT_S2C_BIN = b"\x01" + bytes(range(48))


def run_handshake(pattern: str, protocol_name: str):
    prologue = (canonical_json(HELLO_PAYLOAD)
                + canonical_json(HANDSHAKE_PAYLOAD)
                + protocol_name.encode("utf-8"))

    _eph_queue.clear()
    _eph_queue.extend([E_INITIATOR, E_RESPONDER])

    kk = pattern == "KKpsk0"
    # fixed static keys go in via NoiseHandShake's key file (hex-encoded)
    with tempfile.TemporaryDirectory() as tmp:
        init_key = os.path.join(tmp, "initiator.key")
        resp_key = os.path.join(tmp, "responder.key")
        with open(init_key, "wb") as f:
            f.write(hexlify(S_INITIATOR))
        with open(resp_key, "wb") as f:
            f.write(hexlify(S_RESPONDER))
        init = NoiseHandShake(initiator=True, psk=PSK, path=init_key,
                              remote_pubkey=pub(S_RESPONDER) if kk else None,
                              prologue=prologue,
                              pattern=protocol_name.encode())
        resp = NoiseHandShake(initiator=False, psk=PSK, path=resp_key,
                              remote_pubkey=pub(S_INITIATOR) if kk else None,
                              prologue=prologue,
                              pattern=protocol_name.encode())

    msg1 = init.write_message(MSG1_PAYLOAD)
    p1 = resp.read_message(msg1)
    assert p1 == MSG1_PAYLOAD
    msg2 = resp.write_message(MSG2_PAYLOAD)
    p2 = init.read_message(msg2)
    assert p2 == MSG2_PAYLOAD
    msg3 = b""
    if not init.handshake_finished:
        msg3 = init.write_message(b"")
        resp.read_message(msg3)
    assert init.handshake_finished and resp.handshake_finished
    assert init.handshake_hash == resp.handshake_hash

    ct_c2s = init.encrypt(TRANSPORT_C2S)
    assert resp.decrypt(ct_c2s) == TRANSPORT_C2S
    ct_c2s_2 = init.encrypt(TRANSPORT_C2S_2)
    assert resp.decrypt(ct_c2s_2) == TRANSPORT_C2S_2
    ct_s2c = resp.encrypt(TRANSPORT_S2C)
    assert init.decrypt(ct_s2c) == TRANSPORT_S2C
    ct_s2c_bin = resp.encrypt(TRANSPORT_S2C_BIN)
    assert init.decrypt(ct_s2c_bin) == TRANSPORT_S2C_BIN

    return {
        "protocol_name": protocol_name,
        "prologue": prologue.hex(),
        "msg1": msg1.hex(), "msg2": msg2.hex(), "msg3": msg3.hex(),
        "handshake_hash": init.handshake_hash.hex(),
        "ct_c2s": ct_c2s.hex(), "ct_c2s_2": ct_c2s_2.hex(),
        "ct_s2c": ct_s2c.hex(), "ct_s2c_bin": ct_s2c_bin.hex(),
    }


def main():
    fixtures = {
        "psk": PSK.hex(),
        "s_initiator_priv": S_INITIATOR.hex(),
        "s_initiator_pub": pub(S_INITIATOR).hex(),
        "s_responder_pub": pub(S_RESPONDER).hex(),
        "e_initiator_priv": E_INITIATOR.hex(),
        "hello_payload": HELLO_PAYLOAD,
        "handshake_payload": HANDSHAKE_PAYLOAD,
        "msg1_payload": MSG1_PAYLOAD.hex(),
        "msg2_payload": MSG2_PAYLOAD.hex(),
        "transport_c2s": TRANSPORT_C2S.hex(),
        "transport_c2s_2": TRANSPORT_C2S_2.hex(),
        "transport_s2c": TRANSPORT_S2C.hex(),
        "transport_s2c_bin": TRANSPORT_S2C_BIN.hex(),
        "canonical_hello": canonical_json(HELLO_PAYLOAD).hex(),
        "canonical_handshake": canonical_json(HANDSHAKE_PAYLOAD).hex(),
        "xx": run_handshake("XXpsk2", "Noise_XXpsk2_25519_ChaChaPoly_SHA256"),
        "kk": run_handshake("KKpsk0", "Noise_KKpsk0_25519_ChaChaPoly_SHA256"),
    }
    json.dump(fixtures, sys.stdout, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    sys.exit(main())
