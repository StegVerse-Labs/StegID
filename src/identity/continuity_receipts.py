from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keyring import KeyringStore


class VerificationError(Exception):
    def __init__(self, message: str, code: str = "verification_failed"):
        super().__init__(message)
        self.code = code


# -------------------------
# helpers
# -------------------------

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# -------------------------
# key helpers
# -------------------------

def fingerprint_public_key_pem(pem: str) -> str:
    pub = serialization.load_pem_public_key(pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("Expected Ed25519 public key")
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


# legacy aliases expected by tests
fingerprint_public_key = fingerprint_public_key_pem
fingerprint_key_id_from_pem = fingerprint_public_key_pem
key_id_from_public_key_pem = fingerprint_public_key_pem


# -------------------------
# mint
# -------------------------

def mint_receipt(
    *,
    account_id: str,
    sequence: int,
    issued_at: int,
    event_type: str,
    event_metadata: Dict[str, Any],
    payload: Dict[str, Any],
    prev_receipt: Optional[Dict[str, Any]],
    receipt_id: str,
    signing_key_id: str,
    ed25519_private_pem: str,
) -> Dict[str, Any]:

    priv = serialization.load_pem_private_key(
        ed25519_private_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key")

    body = {
        "account_id": account_id,
        "sequence": int(sequence),
        "issued_at": int(issued_at),
        "event_type": event_type,
        "event_metadata": dict(event_metadata),
        "payload": dict(payload),
        "prev_receipt": prev_receipt,
        "receipt_id": receipt_id,
        "signing_key_id": signing_key_id,
    }

    sig = priv.sign(_canonical_json(body))
    return {**body, "signature": _b64u(sig)}


# -------------------------
# verification
# -------------------------

def _verify_signature(
    receipt: Dict[str, Any],
    *,
    keyring: KeyringStore,
) -> None:
    key_id = receipt.get("signing_key_id")
    rec = keyring.get_key(key_id)

    if not rec or rec.revoked:
        raise VerificationError(
            "Unknown or revoked signing key.",
            code="key_invalid",
        )

    pub = serialization.load_pem_public_key(rec.public_key_pem.encode("utf-8"))
    sig = _b64u_decode(receipt["signature"])

    body = dict(receipt)
    body.pop("signature", None)

    try:
        pub.verify(sig, _canonical_json(body))
    except Exception:
        raise VerificationError("Invalid signature.", code="signature_invalid")


def verify_chain_and_sequence(
    receipts: Iterable[Dict[str, Any]],
    *,
    keyring: Optional[KeyringStore] = None,
) -> tuple[bool, list[str]]:

    if keyring is None:
        keyring = KeyringStore(redis_url=None)

    receipts = list(receipts)
    if not receipts:
        raise VerificationError("Empty receipt chain", code="empty_chain")

    last = None
    notes: list[str] = []

    for r in receipts:
        _verify_signature(r, keyring=keyring)

        if last is not None:
            if r["sequence"] != last["sequence"] + 1:
                raise VerificationError("Sequence break", code="sequence_invalid")
            if r["prev_receipt"] != last:
                raise VerificationError("Chain mismatch", code="chain_invalid")
        else:
            if r["prev_receipt"] is not None:
                raise VerificationError("First receipt must not have prev_receipt")

        last = r

    return True, notes
