from __future__ import annotations

import base64
import json
import hashlib
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))

def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_b64url(data: bytes) -> str:
    return b64url_encode(hashlib.sha256(data).digest())

def receipt_core(receipt: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "version": receipt["version"],
        "receipt_id": receipt["receipt_id"],
        "account_id": receipt["account_id"],
        "sequence": receipt["sequence"],
        "issued_at": receipt["issued_at"],
        "event": receipt["event"],
        "prev_hash": receipt["prev_hash"],
        "payload_hash": receipt["payload_hash"],
        "signing_key_id": receipt["signing_key_id"],
        "signature_alg": receipt["signature_alg"],
    }

def compute_prev_hash(prev_receipt: Optional[Dict[str, Any]]) -> str:
    if prev_receipt is None:
        return "GENESIS"
    core = receipt_core(prev_receipt)
    return sha256_b64url(canonical_json(core))

def compute_payload_hash(payload: Dict[str, Any]) -> str:
    return sha256_b64url(canonical_json(payload))

def sign_receipt_ed25519(private_key_pem: bytes, core_bytes: bytes) -> str:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    sig = priv.sign(core_bytes)
    return b64url_encode(sig)

def verify_receipt_ed25519(public_key_pem: bytes, core_bytes: bytes, signature_b64url: str) -> bool:
    pub = serialization.load_pem_public_key(public_key_pem)
    try:
        pub.verify(b64url_decode(signature_b64url), core_bytes)
        return True
    except Exception:
        return False

def mint_receipt(
    *,
    account_id: str,
    sequence: int,
    issued_at: int,
    event_type: str,
    event_metadata: Optional[Dict[str, Any]] = None,
    payload: Optional[Dict[str, Any]] = None,
    prev_receipt: Optional[Dict[str, Any]] = None,
    receipt_id: str,
    signing_key_id: str,
    ed25519_private_pem: bytes,
) -> Dict[str, Any]:
    """Create an Ed25519 continuity receipt with hash-chaining.

    - payload is stored only as payload_hash
    - prev_hash chains to previous receipt core
    """
    event = {"type": event_type, "metadata": event_metadata or {}}
    payload_obj = payload or {}

    r: Dict[str, Any] = {
        "version": "1.0",
        "receipt_id": receipt_id,
        "account_id": account_id,
        "sequence": int(sequence),
        "issued_at": int(issued_at),
        "event": event,
        "prev_hash": compute_prev_hash(prev_receipt),
        "payload_hash": compute_payload_hash(payload_obj),
        "signing_key_id": signing_key_id,
        "signature_alg": "ed25519",
        "signature": "",
    }

    core_bytes = canonical_json(receipt_core(r))
    r["signature"] = sign_receipt_ed25519(ed25519_private_pem, core_bytes)
    return r

def verify_chain_and_sequence(receipts: Tuple[Dict[str, Any], ...]) -> Tuple[bool, Tuple[str, ...]]:
    """Verify:
    - prev_hash chain integrity
    - strict monotonic sequence starting at receipts[0].sequence and incrementing by 1
    """
    notes = []
    prev = None
    expected_seq = None
    for idx, r in enumerate(receipts):
        # Strict sequence
        seq = int(r.get("sequence", -1))
        if expected_seq is None:
            expected_seq = seq
        if seq != expected_seq:
            notes.append(f"Sequence violation at index {idx}: got {seq}, expected {expected_seq}.")
            return False, tuple(notes)
        expected_seq += 1

        # Chain
        expected_prev = compute_prev_hash(prev)
        if r.get("prev_hash") != expected_prev:
            notes.append(f"Chain break at index {idx}: prev_hash mismatch.")
            return False, tuple(notes)

        # Enforce alg
        if r.get("signature_alg") != "ed25519":
            notes.append(f"Invalid signature_alg at index {idx}: {r.get('signature_alg')}")
            return False, tuple(notes)

        prev = r
    return True, tuple(notes)

  # -------------------------------------------------------------------
# Compatibility alias: stable name used by tests/adapters
# -------------------------------------------------------------------

def fingerprint_public_key_pem(public_key_pem: str) -> str:
    """
    Backwards/compat alias.
    Preferred stable API: fingerprint_public_key_pem(pem_str) -> key_id
    """
    # Try common internal function names without breaking refactors
    if "fingerprint_public_key" in globals():
        return globals()["fingerprint_public_key"](public_key_pem)  # type: ignore
    if "fingerprint_key_id_from_pem" in globals():
        return globals()["fingerprint_key_id_from_pem"](public_key_pem)  # type: ignore
    if "key_id_from_public_key_pem" in globals():
        return globals()["key_id_from_public_key_pem"](public_key_pem)  # type: ignore

    raise ImportError(
        "No underlying fingerprint function found. "
        "Expected one of: fingerprint_public_key, fingerprint_key_id_from_pem, key_id_from_public_key_pem."
    )
