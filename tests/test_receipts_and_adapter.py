from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from identity.continuity_receipts import mint_receipt, verify_chain_and_sequence, fingerprint_public_key_pem
from identity.keyring import KeyringStore
from identity.stegtv_adapter import StegTVContinuityAdapter


def test_receipt_chain_verifies_and_adapter_accepts():
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

    r0 = mint_receipt(
        account_id="acct_demo",
        sequence=0,
        issued_at=now,
        event_type="key_created",
        event_metadata={},
        payload={},
        prev_receipt=None,
        receipt_id="r0",
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
    )

    ok, notes = verify_chain_and_sequence((r0,))
    assert ok is True

    adapter = StegTVContinuityAdapter(keyring=kr)
    out = adapter.verify_receipt_payload(json.dumps(r0).encode("utf-8"), now_epoch=now)
    assert out.ok is True
