# tests/test_receipts_and_adapter.py
from __future__ import annotations

import json
import time

import pytest

from identity import (
    KeyringStore,
    StegTVContinuityAdapter,
    VerificationError,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_chain_and_sequence,
)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def _gen_ed25519_pem_pair() -> tuple[str, str]:
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
    return priv_pem, pub_pem


def _keyring_add_public_pem(kr: KeyringStore, key_id: str, public_pem: str) -> None:
    """
    Best-effort helper so tests don't depend on one exact KeyringStore method name.
    Tries a few likely APIs.
    """
    # Common candidates
    candidates = [
        ("add_public_key_pem", (key_id, public_pem)),
        ("add_public_key", (key_id, public_pem)),
        ("put_public_key_pem", (key_id, public_pem)),
        ("put_public_key", (key_id, public_pem)),
        ("set_public_key_pem", (key_id, public_pem)),
        ("set_public_key", (key_id, public_pem)),
        ("store_public_key_pem", (key_id, public_pem)),
        ("store_public_key", (key_id, public_pem)),
    ]
    for name, args in candidates:
        fn = getattr(kr, name, None)
        if callable(fn):
            fn(*args)
            return

    # As a last resort: some implementations key by derived id
    fn = getattr(kr, "upsert_key", None)
    if callable(fn):
        fn(key_id=key_id, public_pem=public_pem, revoked=False)
        return

    raise RuntimeError(
        "KeyringStore has no recognizable method to add a public key. "
        "Please paste your src/identity/keyring.py and I’ll tailor this helper."
    )


def test_receipt_chain_verifies_and_adapter_accepts() -> None:
    now = int(time.time())

    priv_pem, pub_pem = _gen_ed25519_pem_pair()
    key_id = fingerprint_public_key_pem(pub_pem)

    kr = KeyringStore(redis_url=None)
    _keyring_add_public_pem(kr, key_id, pub_pem)

    r0 = mint_receipt(
        account_id="acct_demo",
        sequence=0,
        issued_at=now,
        event_type="key_created",
        event_metadata={},
        payload={"k": "v"},
        prev_receipt=None,
        receipt_id="r0",
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
    )

    ok, notes = verify_chain_and_sequence((r0,), keyring=kr)
    assert ok is True
    assert isinstance(notes, list)

    adapter = StegTVContinuityAdapter(keyring=kr)
    payload_bytes = json.dumps(r0).encode("utf-8")
    out = adapter.verify_receipt_payload(payload_bytes, now_epoch=now)
    assert out.ok is True
    assert isinstance(out.notes, list)
    assert isinstance(out.receipt, dict)


def test_adapter_rejects_missing_key() -> None:
    now = int(time.time())

    priv_pem, pub_pem = _gen_ed25519_pem_pair()
    key_id = fingerprint_public_key_pem(pub_pem)

    # Intentionally DO NOT load pub_pem into keyring
    kr = KeyringStore(redis_url=None)

    r0 = mint_receipt(
        account_id="acct_demo",
        sequence=0,
        issued_at=now,
        event_type="key_created",
        event_metadata={},
        payload={"k": "v"},
        prev_receipt=None,
        receipt_id="r0",
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
    )

    adapter = StegTVContinuityAdapter(keyring=kr)
    payload_bytes = json.dumps(r0).encode("utf-8")

    with pytest.raises(VerificationError) as e:
        adapter.verify_receipt_payload(payload_bytes, now_epoch=now)

    assert e.value.code in ("key_invalid", "payload_invalid")
