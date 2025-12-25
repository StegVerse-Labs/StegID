from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto_agility import primary_signature
from .keyring import KeyringStore


@dataclass
class VerificationError(Exception):
    message: str
    code: str = "payload_invalid"

    def __str__(self) -> str:
        return self.message


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def fingerprint_public_key_pem(public_key_pem: str) -> str:
    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("Expected Ed25519 public key PEM.")
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def _canonical_receipt_bytes(receipt: Dict[str, Any]) -> bytes:
    """
    Canonicalize receipt excluding signature fields.

    Excludes BOTH:
      - legacy v1: signature, signing_key_id
      - v1.1+: signatures, signature_alg
    """
    obj = dict(receipt)
    for k in ("signature", "signing_key_id", "signatures", "signature_alg"):
        obj.pop(k, None)
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


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
    # v1.1 additive behavior:
    include_v1_1_signatures: bool = True,
    signature_alg: str = "ed25519",
) -> Dict[str, Any]:
    """
    Create a receipt and sign it with Ed25519.

    Backward-compatible (v1):
      - emits signing_key_id + signature

    Additive (v1.1+):
      - if include_v1_1_signatures=True, also emits:
          signature_alg
          signatures=[{"alg":"ed25519","key_id": signing_key_id, "sig": signature}]
    """
    base: Dict[str, Any] = {
        "account_id": account_id,
        "sequence": int(sequence),
        "issued_at": int(issued_at),
        "event_type": event_type,
        "event_metadata": event_metadata or {},
        "payload": payload or {},
        "prev_receipt": prev_receipt,
        "receipt_id": receipt_id,
    }

    priv = serialization.load_pem_private_key(ed25519_private_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key PEM.")

    sig_bytes = priv.sign(_canonical_receipt_bytes(base))
    sig = _b64url_encode(sig_bytes)

    # v1
    base["signing_key_id"] = signing_key_id
    base["signature"] = sig

    # v1.1 additive
    if include_v1_1_signatures:
        base["signature_alg"] = signature_alg
        base["signatures"] = [{"alg": signature_alg, "key_id": signing_key_id, "sig": sig}]

    return base


def _verify_signature(receipt: Dict[str, Any], *, keyring: KeyringStore) -> None:
    """
    Verify the receipt signature.

    Accepts:
      - v1 legacy fields
      - v1.1 signatures list

    Raises VerificationError with code:
      - payload_invalid
      - key_invalid
      - signature_invalid
    """
    sigrec = primary_signature(receipt, preferred_algs=["ed25519"])
    if sigrec is None:
        raise VerificationError("Missing signature fields.", code="payload_invalid")

    rec = keyring.get_key(sigrec.key_id)
    if not rec or getattr(rec, "revoked", False):
        raise VerificationError("Unknown or revoked signing key.", code="key_invalid")

    if sigrec.alg.lower() != "ed25519":
        raise VerificationError(f"Unsupported signature alg: {sigrec.alg}", code="signature_invalid")

    pub = serialization.load_pem_public_key(rec.public_key_pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise VerificationError("Keyring key is not Ed25519.", code="signature_invalid")

    try:
        pub.verify(_b64url_decode(sigrec.sig), _canonical_receipt_bytes(receipt))
    except InvalidSignature as e:
        raise VerificationError("Signature verification failed.", code="signature_invalid") from e


def verify_chain_and_sequence(
    receipts: Sequence[Dict[str, Any]],
    *,
    keyring: KeyringStore,
) -> Tuple[bool, List[str]]:
    """
    Verify:
      - contiguous sequence numbers
      - correct prev_receipt linkage (full object)
      - valid signature(s)
      - known / non-revoked signing keys

    Returns (ok, notes). Raises VerificationError for hard failures.
    """
    if not receipts:
        raise VerificationError("Empty receipt chain.", code="payload_invalid")

    notes: List[str] = []

    for i, r in enumerate(receipts):
        if "sequence" not in r or "issued_at" not in r or "receipt_id" not in r:
            raise VerificationError("Missing required fields.", code="payload_invalid")

        if i == 0:
            if r.get("sequence") != 0:
                raise VerificationError("First receipt must have sequence=0.", code="sequence_invalid")
            if r.get("prev_receipt") is not None:
                raise VerificationError("First receipt must have prev_receipt=null.", code="sequence_invalid")
        else:
            prev = receipts[i - 1]
            if int(r.get("sequence")) != int(prev.get("sequence")) + 1:
                raise VerificationError("Non-contiguous receipt chain.", code="sequence_invalid")
            if r.get("prev_receipt") != prev:
                raise VerificationError("prev_receipt linkage mismatch.", code="sequence_invalid")

        _verify_signature(r, keyring=keyring)

    notes.append("Chain verified.")
    return True, notes
