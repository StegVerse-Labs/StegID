from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .continuity_receipts import (
    VerificationError,
    verify_chain_and_sequence,
)


@dataclass
class VerifiedReceipt:
    ok: bool
    notes: list
    receipt: Optional[Dict[str, Any]] = None


def verify_receipt_payload_bytes(
    payload: bytes,
    *,
    keyring,
    now_epoch: int,
) -> VerifiedReceipt:
    if not payload:
        raise VerificationError("payload_invalid", "Empty payload")

    if keyring is None:
        raise VerificationError("key_invalid", "Keyring is required")

    # Decode
    try:
        import json
        receipt = json.loads(payload.decode("utf-8"))
    except Exception:
        raise VerificationError("payload_invalid", "Payload is not valid JSON")

    ok, notes = verify_chain_and_sequence(
        (receipt,),
        keyring=keyring,
    )

    if not ok:
        raise VerificationError("payload_invalid", "Receipt verification failed")

    return VerifiedReceipt(ok=True, notes=notes, receipt=receipt)
