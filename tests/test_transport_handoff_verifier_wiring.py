from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from identity.keyring import KeyringStore
from identity.continuity_receipts import mint_receipt, fingerprint_public_key_pem
from identity.envelope import make_receipt_envelope
from stegtalk_transport.handoff import handoff_to_stegid
from stegtalk_transport.stegid_verifier_adapter import make_stegid_verify_fn


def test_handoff_calls_stegid_verifier_success():
    now = int(time.time())

    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    key_id = fingerprint_public_key_pem(pub_pem)

    kr = KeyringStore(redis_url=None)
    kr.upsert_key(key_id, {
        "key_id": key_id,
        "public_key_pem": pub_pem,
        "created_at": now - 10,
        "expires_at": now + 10_000,
        "revoked": False,
    })

    r = mint_receipt(
        account_id="acct_demo",
        sequence=0,
        issued_at=now,
        event_type="key_created",
        event_metadata={},
        payload={},
        prev_receipt=None,
        receipt_id="r1",
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
    )

    payload_bytes = json.dumps(r).encode("utf-8")
    env = make_receipt_envelope(payload_bytes)

    verify_fn = make_stegid_verify_fn(keyring=kr)

    out = handoff_to_stegid(
        envelope=env,
        payload_bytes=payload_bytes,
        steg_id_verify_fn=verify_fn,
    )

    assert out.ok is True
    assert out.receipt["account_id"] == "acct_demo"
