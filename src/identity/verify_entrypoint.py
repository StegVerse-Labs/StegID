from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from .continuity_receipts import VerificationError, verify_chain_and_sequence
from .keyring import KeyringStore
from .policy import VerificationPolicy


@dataclass
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: List[str]


def _compute_chain_hash(receipts: List[Dict[str, Any]]) -> str:
    """
    Optional bundle commitment.
    Hashes canonical JSON bytes for each receipt in order, then sha256 of concatenation.
    """
    parts: List[bytes] = []
    for r in receipts:
        parts.append(json.dumps(r, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return hashlib.sha256(b"".join(parts)).hexdigest()


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: Optional[KeyringStore] = None,
    now_epoch: Optional[int] = None,
    policy: Optional[VerificationPolicy] = None,
) -> VerifiedReceipt:
    """
    Transport-safe entrypoint.

    Accepts JSON payloads shaped as:
    - single receipt object
    - list of receipts
    - {"receipts":[...]} or {"receipt_chain":[...]}
    - Optional {"chain_hash":"..."} alongside either of the above list shapes
    """
    if keyring is None:
        keyring = KeyringStore(redis_url=None)
    if policy is None:
        policy = VerificationPolicy()

    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise VerificationError("Invalid JSON payload.", code="payload_invalid") from e

    receipts: Union[List[Dict[str, Any]], None] = None
    declared_chain_hash: Optional[str] = None

    if isinstance(obj, list):
        receipts = obj
    elif isinstance(obj, dict):
        # allow optional chain_hash in wrapper payloads
        if "chain_hash" in obj and isinstance(obj["chain_hash"], str):
            declared_chain_hash = obj["chain_hash"]

        if "receipts" in obj:
            receipts = obj["receipts"]
        elif "receipt_chain" in obj:
            receipts = obj["receipt_chain"]
        else:
            # treat as single receipt object
            if "signing_key_id" in obj and "sequence" in obj:
                receipts = [obj]
            else:
                raise VerificationError("Expected receipt payload.", code="payload_invalid")
    else:
        raise VerificationError("Expected JSON object or array.", code="payload_invalid")

    if not isinstance(receipts, list) or not receipts:
        raise VerificationError("Empty or invalid receipt list.", code="payload_invalid")

    # If chain_hash declared, verify it (optional, non-breaking)
    if declared_chain_hash is not None:
        computed = _compute_chain_hash(receipts)
        if computed != declared_chain_hash:
            raise VerificationError("Chain hash mismatch.", code="payload_invalid")

    # Core chain verification (signatures + continuity)
    ok, notes = verify_chain_and_sequence(tuple(receipts), keyring=keyring)

    # Policy: key expiry (optional)
    if policy.enforce_key_expiry and now_epoch is not None:
        for r in receipts:
            key_id = r.get("signing_key_id")
            rec = keyring.get_key(key_id) if key_id else None
            if rec and getattr(rec, "expires_at", 0) and now_epoch > int(rec.expires_at):
                raise VerificationError("Signing key expired.", code="key_expired")

    # Policy: origin/domain scoping (optional; wrapper payload only)
    if isinstance(obj, dict):
        origin = obj.get("origin")
        domain = obj.get("domain")
        if policy.expected_origin is not None and origin is not None and origin != policy.expected_origin:
            raise VerificationError("Origin mismatch.", code="payload_invalid")
        if policy.expected_domain is not None and domain is not None and domain != policy.expected_domain:
            raise VerificationError("Domain mismatch.", code="payload_invalid")

    # Return last receipt as authoritative state
    last = receipts[-1]
    return VerifiedReceipt(ok=bool(ok), receipt=last, notes=list(notes))
