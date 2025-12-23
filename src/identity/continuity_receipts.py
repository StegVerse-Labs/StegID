from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .keyring import KeyringStore


class VerificationError(Exception):
    pass


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def fingerprint_public_key_pem(pem_str: str) -> str:
    """
    Stable key_id from PEM public key:
    sha256(SPKI_DER) -> hex
    """
    pub = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        # tests are using Ed25519; keep message clear if something else arrives
        raise ValueError("Expected an Ed25519 public key PEM.")
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


# Backwards/compat aliases some modules/tests may expect
def fingerprint_public_key(public_key_pem: str) -> str:
    return fingerprint_public_key_pem(public_key_pem)


def fingerprint_key_id_from_pem(public_key_pem: str) -> str:
    return fingerprint_public_key_pem(public_key_pem)


def key_id_from_public_key_pem(public_key_pem: str) -> str:
    return fingerprint_public_key_pem(public_key_pem)


@dataclass(frozen=True)
class Receipt:
    account_id: str
    sequence: int
    issued_at: int
    event_type: str
    event_metadata: Dict[str, Any]
    payload: Dict[str, Any]
    prev_receipt: Optional[Dict[str, Any]]
    receipt_id: str
    signing_key_id: str
    signature: str  # b64url
    body: Dict[str, Any]


def mint_receipt(
    *,
    # Tests expect "account_id" specifically:
    account_id: Optional[str] = None,
    # allow historical alias without breaking
    acct_id: Optional[str] = None,
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
    acct = account_id if account_id is not None else acct_id
    if not acct:
        raise TypeError("mint_receipt() missing required argument: 'account_id'")

    priv = serialization.load_pem_private_key(ed25519_private_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key PEM.")

    body = {
        "account_id": acct,
        "sequence": int(sequence),
        "issued_at": int(issued_at),
        "event_type": str(event_type),
        "event_metadata": dict(event_metadata or {}),
        "payload": dict(payload or {}),
        "prev_receipt": prev_receipt,
        "receipt_id": str(receipt_id),
        "signing_key_id": str(signing_key_id),
    }

    sig = priv.sign(_canonical_json_bytes(body))
    receipt = {**body, "signature": _b64u(sig)}
    return receipt


def verify_chain_and_sequence(
    receipts: list[Dict[str, Any]],
    *,
    keyring: KeyringStore,
) -> bool:
    if not receipts:
        raise VerificationError("Empty receipt chain.")

    # Basic checks: monotonically increasing sequence, link prev_receipt, valid signatures
    last_seq = None
    last_receipt = None

    for r in receipts:
        for req in ("account_id", "sequence", "issued_at", "event_type", "event_metadata", "payload",
                    "prev_receipt", "receipt_id", "signing_key_id", "signature"):
            if req not in r:
                raise VerificationError(f"Missing field: {req}")

        seq = int(r["sequence"])
        if last_seq is not None and seq != last_seq + 1:
            raise VerificationError("Sequence is not contiguous.")

        if last_receipt is None:
            # first receipt should have prev_receipt None (or be absent, but we require it above)
            if r["prev_receipt"] is not None:
                raise VerificationError("First receipt must have prev_receipt=None.")
        else:
            if r["prev_receipt"] != last_receipt:
                raise VerificationError("Receipt chain linkage mismatch (prev_receipt).")

        key_id = r["signing_key_id"]
        rec = keyring.get_key(key_id)
        if not rec or rec.revoked:
            raise VerificationError("Unknown or revoked signing key.")

        pub = serialization.load_pem_public_key(rec.public_key_pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            raise VerificationError("Signing key is not Ed25519.")

        sig = _b64u_decode(r["signature"])

        body = dict(r)
        body.pop("signature", None)

        try:
            pub.verify(sig, _canonical_json_bytes(body))
        except Exception as e:
            raise VerificationError(f"Signature verification failed: {e}") from e

        last_seq = seq
        last_receipt = r

    return True
