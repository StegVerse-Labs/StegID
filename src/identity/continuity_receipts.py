"""
StegID – Continuity Receipts (v1 surface)

Goals:
- Minimal, deterministic, auditable receipt format
- Stable contract surface for tests/imports
- Crypto verification lives here (Ed25519 signatures)
- Policy/governance stays elsewhere

Notes:
- This module intentionally accepts receipts as dicts OR JSON strings.
- Canonicalization is deterministic (sorted keys, compact separators).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------
# Errors
# ---------------------------

class VerificationError(Exception):
    """Raised when receipt verification fails."""


# ---------------------------
# Helpers
# ---------------------------

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _canon_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def _to_dict(receipt: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(receipt, dict):
        return receipt
    if isinstance(receipt, str):
        return json.loads(receipt)
    raise TypeError("receipt must be dict or JSON string")

def fingerprint_public_key_pem(public_pem: str) -> str:
    """
    Stable key-id derivation (sha256 of PEM bytes).
    Tests typically use this as key_id.
    """
    if not isinstance(public_pem, str) or "BEGIN PUBLIC KEY" not in public_pem:
        raise ValueError("public_pem must be a PEM-encoded public key string")
    return _sha256_hex(public_pem.encode("utf-8"))


def _load_private_key_from_pem(private_pem: str) -> Ed25519PrivateKey:
    if not isinstance(private_pem, str) or "BEGIN" not in private_pem:
        raise ValueError("ed25519_private_pem must be a PEM-encoded string")
    key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not Ed25519")
    return key

def _load_public_key_from_pem(public_pem: str) -> Ed25519PublicKey:
    if not isinstance(public_pem, str) or "BEGIN" not in public_pem:
        raise ValueError("public_pem must be a PEM-encoded string")
    key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key is not Ed25519")
    return key


def _payload_to_bytes(payload: Any) -> bytes:
    """
    Accepts:
    - bytes / bytearray
    - dict/list/primitive (serialized canonically)
    - str (UTF-8)
    """
    if payload is None:
        return b""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return _canon_json_bytes(payload)


def _receipt_signing_material(receipt: Dict[str, Any]) -> bytes:
    """
    Deterministic signing material for Ed25519.
    IMPORTANT: excludes the 'sig' field itself.
    """
    r = dict(receipt)
    r.pop("sig", None)
    return _canon_json_bytes(r)


def _receipt_hash(receipt: Dict[str, Any]) -> str:
    """
    Deterministic receipt hash for chain-linking.
    Excludes no fields; hashes the canonical JSON of the full receipt dict.
    """
    return _sha256_hex(_canon_json_bytes(receipt))


# ---------------------------
# Receipt shape
# ---------------------------

@dataclass(frozen=True)
class ReceiptV1:
    """
    Convenience wrapper (not required by tests), but useful for clarity.
    """
    receipt: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return self.receipt


# ---------------------------
# Minting
# ---------------------------

def mint_receipt(
    *,
    receipt_id: str,
    signing_key_id: str,
    ed25519_private_pem: str,
    payload: Any = None,
    issued_at: Optional[int] = None,
    prev_receipt_hash: Optional[str] = None,
    meta: Optional[Dict[str, Any]] = None,
    algo: str = "Ed25519",
    receipt_version: str = "1.0",
) -> Dict[str, Any]:
    """
    Create a signed continuity receipt.

    Fields are intentionally minimal and deterministic:
    - receipt_version: "1.0"
    - receipt_id: caller-provided stable id
    - issued_at: epoch seconds
    - prev_receipt_hash: sha256 of previous receipt canonical JSON (optional)
    - signing_key_id: key identifier (often sha256(public_pem))
    - payload_b64: base64url of payload bytes
    - payload_hash: sha256 hex of payload bytes
    - algo: signature algorithm name
    - sig: base64url signature over canonical receipt (excluding sig)
    - meta: optional metadata (dict)

    Returns: dict receipt
    """
    if not receipt_id:
        raise ValueError("receipt_id required")
    if not signing_key_id:
        raise ValueError("signing_key_id required")

    if issued_at is None:
        issued_at = int(time.time())

    payload_bytes = _payload_to_bytes(payload)
    payload_b64 = _b64e(payload_bytes)
    payload_hash = _sha256_hex(payload_bytes)

    receipt: Dict[str, Any] = {
        "receipt_version": str(receipt_version),
        "receipt_id": str(receipt_id),
        "issued_at": int(issued_at),
        "prev_receipt_hash": prev_receipt_hash,
        "signing_key_id": str(signing_key_id),
        "payload_b64": payload_b64,
        "payload_hash": payload_hash,
        "algo": str(algo),
        "meta": meta or {},
    }

    sk = _load_private_key_from_pem(ed25519_private_pem)
    sig = sk.sign(_receipt_signing_material(receipt))
    receipt["sig"] = _b64e(sig)

    return receipt


# ---------------------------
# Verification
# ---------------------------

def verify_receipt_signature(
    receipt: Union[str, Dict[str, Any]],
    *,
    public_pem: str,
) -> None:
    """
    Raises VerificationError if signature/payload hash invalid.
    """
    r = _to_dict(receipt)

    # Basic required fields
    for f in ("receipt_version", "receipt_id", "issued_at", "signing_key_id", "payload_b64", "payload_hash", "algo", "sig"):
        if f not in r:
            raise VerificationError(f"missing_field:{f}")

    # Payload hash check
    payload_bytes = _b64d(str(r["payload_b64"]))
    expected_hash = str(r["payload_hash"])
    actual_hash = _sha256_hex(payload_bytes)
    if actual_hash != expected_hash:
        raise VerificationError("payload_invalid")

    # Signature check
    pk = _load_public_key_from_pem(public_pem)
    try:
        pk.verify(_b64d(str(r["sig"])), _receipt_signing_material(r))
    except Exception as e:
        raise VerificationError("sig_invalid") from e


def verify_chain_and_sequence(
    receipts: Sequence[Union[str, Dict[str, Any]]],
    *,
    keyring: Any,
    now_epoch: Optional[int] = None,
    max_clock_skew_sec: int = 24 * 60 * 60,
) -> Tuple[bool, List[str]]:
    """
    Verify a chain of receipts.

    Contract:
    - receipts must be in chronological order
    - each receipt.prev_receipt_hash must match sha256 of previous receipt
    - each receipt signature must validate using keyring

    keyring contract (duck-typed):
    - should provide get_public_pem(key_id) -> str | None
      OR get_public_key_pem(key_id) -> str | None
      OR get(key_id) -> str | None

    Returns: (ok, notes)
    """
    notes: List[str] = []
    if not receipts:
        return True, ["empty_chain"]

    if now_epoch is None:
        now_epoch = int(time.time())

    # Best-effort public pem getter
    def _get_public_pem(kr: Any, key_id: str) -> Optional[str]:
        for name in ("get_public_pem", "get_public_key_pem", "get"):
            fn = getattr(kr, name, None)
            if callable(fn):
                try:
                    return fn(key_id)
                except TypeError:
                    # some implementations may require kw args
                    try:
                        return fn(key_id=key_id)  # type: ignore
                    except Exception:
                        pass
        return None

    prev_hash: Optional[str] = None
    prev_receipt_obj: Optional[Dict[str, Any]] = None

    for idx, rec in enumerate(receipts):
        r = _to_dict(rec)

        # Clock sanity (non-fatal, but we flag)
        issued_at = int(r.get("issued_at", 0) or 0)
        if issued_at <= 0:
            return False, [f"invalid_issued_at@{idx}"]
        if issued_at > now_epoch + max_clock_skew_sec:
            notes.append(f"clock_future@{idx}")

        # Chain link
        if idx == 0:
            # first receipt may have null prev
            if r.get("prev_receipt_hash") not in (None, "", prev_hash):
                # allow None/"" only
                notes.append("non_null_prev_on_first")
        else:
            expected_prev = prev_hash
            got_prev = r.get("prev_receipt_hash")
            if not expected_prev or got_prev != expected_prev:
                return False, [f"chain_break@{idx}"]

        # Signature
        key_id = str(r.get("signing_key_id", ""))
        public_pem = _get_public_pem(keyring, key_id)
        if not public_pem:
            return False, [f"key_missing@{idx}:{key_id}"]

        try:
            verify_receipt_signature(r, public_pem=public_pem)
        except VerificationError as e:
            return False, [f"{e.args[0]}@{idx}"]

        # advance
        prev_receipt_obj = r
        prev_hash = _receipt_hash(r)

    notes.append("ok")
    if prev_receipt_obj is not None:
        notes.append(f"chain_len={len(receipts)}")
        notes.append(f"last_hash={prev_hash}")

    return True, notes
