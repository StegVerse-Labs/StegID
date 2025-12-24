from __future__ import annotations

import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity import (
    KeyringStore,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_chain_and_sequence,
)
from identity.verify_entrypoint import verify_receipt_payload_bytes


def _mk_keyring(now: int):
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
    return kr, key_id, priv_pem


def test_contract_v1_accepts_single_receipt_object():
    now = int(time.time())
    kr, key_id, priv_pem = _mk_keyring(now)

    r = mint_receipt(
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

    out = verify_receipt_payload_bytes(json.dumps(r).encode("utf-8"), keyring=kr, now_epoch=now)
    assert out.ok is True
    assert out.receipt["receipt_id"] == "r0"


def test_contract_v1_accepts_receipts_array_shapes():
    now = int(time.time())
    kr, key_id, priv_pem = _mk_keyring(now)

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

    payload1 = {"receipts": [r0]}
    payload2 = {"receipt_chain": [r0]}

    out1 = verify_receipt_payload_bytes(json.dumps(payload1).encode("utf-8"), keyring=kr, now_epoch=now)
    out2 = verify_receipt_payload_bytes(json.dumps(payload2).encode("utf-8"), keyring=kr, now_epoch=now)
    assert out1.ok is True
    assert out2.ok is True


def test_contract_v1_chain_verification_returns_tuple_ok_notes():
    now = int(time.time())
    kr, key_id, priv_pem = _mk_keyring(now)

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

    ok, notes = verify_chain_and_sequence((r0,), keyring=kr)
    assert ok is True
    assert isinstance(notes, list)


@pytest.mark.parametrize("bad", [
    {},  # missing all
    {"sequence": 0},  # missing key id, etc
    {"signing_key_id": "nope", "issued_at": 0, "sequence": 0},  # missing required fields
])
def test_contract_v1_payload_invalid_is_stable(bad):
    now = int(time.time())
    kr = KeyringStore(redis_url=None)

    from identity.continuity_receipts import VerificationError

    with pytest.raises(VerificationError) as e:
        verify_receipt_payload_bytes(json.dumps(bad).encode("utf-8"), keyring=kr, now_epoch=now)
    assert e.value.code in ("payload_invalid", "key_invalid")
