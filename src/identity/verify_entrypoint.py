from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .continuity_receipts import (
    VerificationError,
    verify_chain_and_sequence,
)
from .keyring import KeyringStore


@dataclass
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: Optional[KeyringStore] = None,
    now_epoch: Optional[int] = None,
) -> VerifiedReceipt:

    if keyring is None:
        keyring = KeyringStore(redis_url=None)

    obj = json.loads(payload_bytes.decode("utf-8"))

    # Accept single receipt
    if isinstance(obj, dict) and "signature" in obj:
        receipts = [obj]
    elif isinstance(obj, dict):
        receipts = obj.get("receipts") or obj.get("receipt_chain")
        if receipts is None:
            raise VerificationError(
                "Expected 'receipts' or 'receipt_chain' in payload.",
                code="payload_invalid",
            )
    elif isinstance(obj, list):
        receipts = obj
    else:
        raise VerificationError("Invalid payload", code="payload_invalid")

    ok, _ = verify_chain_and_sequence(receipts, keyring=keyring)

    return VerifiedReceipt(ok=ok, receipt=receipts[-1])
