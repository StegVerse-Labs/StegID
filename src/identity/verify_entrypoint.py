from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from .continuity_receipts import (
    VerificationError,
    verify_chain_and_sequence,
)
from .keyring import KeyringStore


@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    notes: Dict[str, Any]
    receipts: List[Dict[str, Any]]


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: Optional[KeyringStore] = None,
    now_epoch: Optional[int] = None,  # tests pass this; kept for compatibility
) -> VerifiedReceipt:
    """
    Entry point used by tests and adapters.

    Accepts payload_bytes containing JSON representing:
      - a single receipt dict
      - {"receipts":[...]} or {"receipt_chain":[...]}
      - a raw list/tuple of receipts

    Returns VerifiedReceipt; raises VerificationError on failure.
    """
    if keyring is None:
        keyring = KeyringStore(redis_url=None)

    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise VerificationError(f"Invalid JSON payload: {e}") from e

    receipts: List[Dict[str, Any]]

    # Accept single receipt dict
    if isinstance(obj, dict) and ("signature" in obj or "signing_key_id" in obj):
        receipts = [obj]
    elif isinstance(obj, list):
        receipts = obj
    elif isinstance(obj, dict):
        chain = obj.get("receipts") or obj.get("receipt_chain")
        if chain is None:
            raise VerificationError("Expected 'receipts' or 'receipt_chain' in payload.")
        receipts = list(chain)
    else:
        raise VerificationError("Unsupported payload type.")

    ok, notes = verify_chain_and_sequence(receipts, keyring=keyring)

    # now_epoch is currently not enforced by tests; retained for API compatibility.
    if now_epoch is not None:
        notes = dict(notes)
        notes["now_epoch"] = int(now_epoch)

    return VerifiedReceipt(ok=bool(ok), notes=notes, receipts=receipts)
