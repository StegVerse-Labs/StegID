from __future__ import annotations

import json
import time
import pytest

from identity.verify_entrypoint import verify_receipt_payload_bytes, VerificationError
from identity.keyring import Keyring
from identity.continuity_receipts import mint_receipt, fingerprint_public_key_pem


def _mk_keyring_with_one_key(pub_pem: str, key_id: str, now: int) -> Keyring:
    kr = Keyring(redis_url=None)
    kr.upsert_key(key_id, {
        "key_id": key_id,
        "public_key_pem": pub_pem,
        "created_at": now - 10,
        "expires_at": now + 10_000,
        "revoked": False,
    })
    return kr


def test_verify_entrypoint_accepts_valid_receipt():
    now = int(time.time())

    # generate keypair via mint_receipt helper path
    # We use the same signing function used elsewhere; mint_receipt expects PEMs.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

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
    kr = _mk_keyring_with_one_key(pub_pem, key_id, now)

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

    out = verify_receipt_payload_bytes(json.dumps(r).encode("utf-8"), keyring=kr, now_epoch=now)
    assert out.ok is True
    assert out.receipt["account_id"] == "acct_demo"


def test_verify_entrypoint_rejects_missing_key():
    now = int(time.time())
    kr = Keyring(redis_url=None)  # empty

    fake = {"signing_key_id": "nope", "issued_at": now, "sequence": 0}
    with pytest.raises(VerificationError) as e:
        verify_receipt_payload_bytes(json.dumps(fake).encode("utf-8"), keyring=kr, now_epoch=now)
    assert e.value.code == "key_invalid"
