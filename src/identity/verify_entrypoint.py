from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from identity.continuity_receipts import verify_chain_and_sequence
from identity.keyring import KeyringStore
from identity.validation import validate_timestamps


@dataclass(frozen=True)
class VerificationError(Exception):
    code: str
    message: str


@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: Tuple[str, ...] = ()


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,
    max_future_skew_seconds: int = 120,
    require_monotonic_timestamps: bool = True,
) -> VerifiedReceipt:
    """
    Transport-agnostic verifier entrypoint.

    Input:
      - payload_bytes: opaque bytes (expected JSON receipt for Phase 1)
    Output:
      - VerifiedReceipt (ok=True) or raises VerificationError

    This function does NOT accept or require any transport metadata.
    """
    try:
        receipt = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise VerificationError("bad_payload", f"Could not decode JSON receipt payload: {e}")

    if not isinstance(receipt, dict):
        raise VerificationError("bad_payload", "Receipt payload must be a JSON object")

    key_id = receipt.get("signing_key_id")
    issued_at = receipt.get("issued_at")
    if not key_id or issued_at is None:
        raise VerificationError("bad_receipt", "Missing signing_key_id or issued_at")

    # Ensure the signing key is valid at issued_at
    pub = keyring.get_public_key_pem_if_valid(str(key_id), int(issued_at))
    if not pub:
        raise VerificationError(
            "key_invalid",
            f"Key not found/valid for signing_key_id={key_id} at issued_at={issued_at}",
        )

    # Verify continuity rules (signature/chain/sequence handled inside core receipt logic)
    ok, notes = verify_chain_and_sequence((receipt,))
    if not ok:
        raise VerificationError("chain_invalid", "Receipt failed chain/sequence verification")

    # Timestamp sanity (verifier-side)
    ts_ok = validate_timestamps(
        [receipt],
        now_epoch=now_epoch,
        max_future_skew_seconds=max_future_skew_seconds,
        require_monotonic=require_monotonic_timestamps,
    )
    if not ts_ok.ok:
        raise VerificationError("time_invalid", "; ".join(ts_ok.notes))

    return VerifiedReceipt(ok=True, receipt=receipt, notes=tuple(notes))
