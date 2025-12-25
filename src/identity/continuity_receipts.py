# src/identity/continuity_receipts.py
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, TypedDict

from .keyring import KeyringStore

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError("cryptography is required for StegID v1") from e


# -----------------------------
# Public receipt “model” names (v1 frozen surface)
# -----------------------------
class ContinuityReceipt(TypedDict, total=False):
    contract_version: str
    signature_alg: str

    receipt_id: str
    account_id: str
    sequence: int
    issued_at: int

    event_type: str
    event_metadata: Dict[str, Any]
    payload: Dict[str, Any]

    prev_receipt_id: Optional[str]
    signing_key_id: str
    signature_b64: str


# alias preserved for v1 surface
ContinuityReceiptV1 = ContinuityReceipt


# -----------------------------
# Errors (v1 contract)
# -----------------------------
class VerificationError(Exception):
    """
    v1 contract error. Tests expect `.code`.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message}


# -----------------------------
# Helpers
# -----------------------------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _normalize_pem(pem: Union[str, bytes]) -> bytes:
    pem_b = pem.encode("utf-8") if isinstance(pem, str) else pem
    pem_b = pem_b.replace(b"\r\n", b"\n").strip() + b"\n"
    return pem_b


def fingerprint_public_key_pem(public_pem: Union[str, bytes]) -> str:
    """
    v1 deterministic key identifier: sha256 hex of normalized PUBLIC key PEM.
    """
    return hashlib.sha256(_normalize_pem(public_pem)).hexdigest()


def _load_private_key_from_pem(private_pem: Union[str, bytes]) -> Ed25519PrivateKey:
    priv = serialization.load_pem_private_key(_normalize_pem(private_pem), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise VerificationError("key_invalid", "private key is not Ed25519")
    return priv


def _load_public_key_from_pem(public_pem: Union[str, bytes]) -> Ed25519PublicKey:
    pub = serialization.load_pem_public_key(_normalize_pem(public_pem))
    if not isinstance(pub, Ed25519PublicKey):
        raise VerificationError("key_invalid", "public key is not Ed25519")
    return pub


def _canon_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _require(d: Dict[str, Any], key: str) -> Any:
    if key not in d:
        raise VerificationError("payload_invalid", f"missing field: {key}")
    return d[key]


def _receipt_core_for_signing(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """
    v1 signing core: stable fields only.
    """
    return {
        "account_id": receipt.get("account_id"),
        "sequence": receipt.get("sequence"),
        "issued_at": receipt.get("issued_at"),
        "event_type": receipt.get("event_type"),
        "event_metadata": receipt.get("event_metadata", {}),
        "payload": receipt.get("payload", {}),
        "prev_receipt_id": receipt.get("prev_receipt_id"),
        "signing_key_id": receipt.get("signing_key_id"),
        "signature_alg": receipt.get("signature_alg", "ed25519"),
        "contract_version": receipt.get("contract_version", "v1"),
    }


# -----------------------------
# Mint + verify (v1 contract)
# -----------------------------
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
) -> ContinuityReceipt:
    """
    v1 contract minting function (shape required by tests).
    Returns a JSON-serializable dict.
    """
    prev_receipt_id = None
    if prev_receipt is not None and isinstance(prev_receipt, dict):
        prev_receipt_id = prev_receipt.get("receipt_id")

    receipt: Dict[str, Any] = {
        "contract_version": "v1",
        "signature_alg": "ed25519",
        "receipt_id": receipt_id,
        "account_id": account_id,
        "sequence": int(sequence),
        "issued_at": int(issued_at),
        "event_type": event_type,
        "event_metadata": event_metadata or {},
        "payload": payload or {},
        "prev_receipt_id": prev_receipt_id,
        "signing_key_id": signing_key_id,
    }

    core = _receipt_core_for_signing(receipt)
    core_bytes = _canon_json_bytes(core)

    priv = _load_private_key_from_pem(ed25519_private_pem)
    sig = priv.sign(core_bytes)

    receipt["signature_b64"] = _b64e(sig)
    return receipt  # type: ignore[return-value]


def _verify_single_receipt(
    r: Dict[str, Any],
    *,
    keyring: KeyringStore,
) -> Dict[str, Any]:
    _require(r, "receipt_id")
    _require(r, "signing_key_id")
    _require(r, "issued_at")
    _require(r, "sequence")
    _require(r, "signature_b64")

    if r.get("signature_alg", "ed25519") != "ed25519":
        raise VerificationError("payload_invalid", "unsupported signature_alg")

    key_id = r["signing_key_id"]
    pub_pem = keyring.get_public_key_pem(key_id)
    if not pub_pem:
        raise VerificationError("key_invalid", "public key missing or revoked")

    core = _receipt_core_for_signing(r)
    core_bytes = _canon_json_bytes(core)

    try:
        pub = _load_public_key_from_pem(pub_pem)
        pub.verify(_b64d(r["signature_b64"]), core_bytes)
    except VerificationError:
        raise
    except Exception:
        raise VerificationError("signature_invalid", "signature verification failed")

    return {
        "receipt_id": r["receipt_id"],
        "signing_key_id": r["signing_key_id"],
        "sequence": int(r["sequence"]),
        "issued_at": int(r["issued_at"]),
    }


def verify_chain_and_sequence(
    receipts: Sequence[Dict[str, Any]],
    *,
    keyring: KeyringStore,
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    v1 contract:
      - returns (ok, notes_list) where notes_list is a list
      - strict sequence increments by 1 (when multiple receipts)
      - prev_receipt_id links (when provided)
      - per-receipt signature verified
    """
    if not receipts:
        raise VerificationError("chain_invalid", "empty receipts")

    notes: List[Dict[str, Any]] = []
    prev_id: Optional[str] = None
    prev_seq: Optional[int] = None

    for i, r in enumerate(receipts):
        if not isinstance(r, dict):
            raise VerificationError("payload_invalid", "receipt must be an object")

        n = _verify_single_receipt(r, keyring=keyring)

        if i > 0:
            seq = int(r.get("sequence"))
            if prev_seq is not None and seq != prev_seq + 1:
                raise VerificationError("chain_invalid", "sequence not monotonic +1")

            pri = r.get("prev_receipt_id")
            if pri is not None and prev_id is not None and pri != prev_id:
                raise VerificationError("chain_invalid", "prev_receipt_id mismatch")

        prev_id = r.get("receipt_id")
        prev_seq = int(r.get("sequence"))
        notes.append(n)

    return True, notes


def verify_receipt_chain(
    receipts: Sequence[Dict[str, Any]],
    *,
    keyring: KeyringStore,
) -> Tuple[bool, List[Dict[str, Any]]]:
    return verify_chain_and_sequence(receipts, keyring=keyring)
