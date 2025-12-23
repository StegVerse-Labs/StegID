from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .continuity_receipts import VerificationError, verify_chain_and_sequence
from .keyring import KeyringStore


@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    account_id: str
    last_sequence: int
    last_receipt_id: str


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: Optional[KeyringStore] = None,
) -> VerifiedReceipt:
    """
    Entry point used by tests:
    - payload_bytes is JSON bytes
    - expected shape: {"receipts":[...]} or {"receipt_chain":[...]} or a raw list
    """
    if keyring is None:
        keyring = KeyringStore(redis_url=None)

    obj = json.loads(payload_bytes.decode("utf-8"))

    if isinstance(obj, list):
        receipts = obj
    elif isinstance(obj, dict):
        receipts = obj.get("receipts") or obj.get("receipt_chain")
        if receipts is None:
            raise VerificationError("Expected 'receipts' or 'receipt_chain' in payload.")
    else:
        raise VerificationError("Invalid payload JSON.")

    ok = verify_chain_and_sequence(receipts, keyring=keyring)
    last = receipts[-1]
    return VerifiedReceipt(
        ok=ok,
        account_id=str(last["account_id"]),
        last_sequence=int(last["sequence"]),
        last_receipt_id=str(last["receipt_id"]),
    )
