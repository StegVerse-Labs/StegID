import time
import uuid
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from src.identity.continuity_receipts import mint_receipt, verify_chain_and_sequence
from src.identity.keyring import VerifierKeyring, fingerprint_public_key_pem
from src.identity.stegtv_adapter import derive_signals_from_receipts_strict

def test_ed25519_strict_chain_sig_and_adapter():
    now = int(time.time())

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    keyring = VerifierKeyring()
    key_id = keyring.add_key(pub_pem, not_before_epoch=now-10_000)

    r1 = mint_receipt(
        account_id="acct1",
        sequence=0,
        issued_at=now-4000000,
        event_type="key_created",
        receipt_id=str(uuid.uuid4()),
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
        prev_receipt=None,
        payload={"device":"A"},
    )
    r2 = mint_receipt(
        account_id="acct1",
        sequence=1,
        issued_at=now-2000000,
        event_type="key_rotated",
        receipt_id=str(uuid.uuid4()),
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
        prev_receipt=r1,
        payload={"device":"A"},
    )
    r3 = mint_receipt(
        account_id="acct1",
        sequence=2,
        issued_at=now-1000,
        event_type="owner_presence",
        receipt_id=str(uuid.uuid4()),
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
        prev_receipt=r2,
        payload={"presence":"ok"},
    )

    ok, _ = verify_chain_and_sequence((r1, r2, r3))
    assert ok

    ds = derive_signals_from_receipts_strict([r1, r2, r3], keyring=keyring, now_epoch=now)
    assert 0.0 <= ds.crypto_continuity["score"] <= 1.0
    assert 0.0 <= ds.time_depth["score"] <= 1.0
    assert ds.crypto_continuity["evidence"]["rotations"] == 1
