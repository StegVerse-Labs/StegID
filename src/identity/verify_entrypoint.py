from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List

from .continuity_receipts import VerificationError, verify_chain_and_sequence
from .keyring import KeyringStore


@dataclass
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: List[str]


def _parse_payload(payload_bytes: bytes) -> Dict[str, Any]:
    try:
        obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise VerificationError("Payload is not valid JSON.", code="payload_invalid") from e

    if not isinstance(obj, dict):
        raise VerificationError("Payload must be a JSON object.", code="payload_invalid")
    return obj


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: KeyringStore,
    now_epoch: int,
) -> VerifiedReceipt:
    """
    Transport-safe verification entrypoint.

    Accepts any of:
      - { "receipts": [ ... ] }
      - { "receipt_chain": [ ... ] }
      - { ...single receipt object... }
    """
    obj = _parse_payload(payload_bytes)

    receipts_obj: Any
    if "receipts" in obj:
        receipts_obj = obj.get("receipts")
    elif "receipt_chain" in obj:
        receipts_obj = obj.get("receipt_chain")
    else:
        receipts_obj = obj  # single receipt

    if isinstance(receipts_obj, dict):
        receipts = [receipts_obj]
    elif isinstance(receipts_obj, list):
        receipts = receipts_obj
    else:
        raise VerificationError("Unsupported payload shape.", code="payload_invalid")

    if not receipts or not all(isinstance(r, dict) for r in receipts):
        raise VerificationError("Receipt chain must be object(s).", code="payload_invalid")

    ok, notes = verify_chain_and_sequence(tuple(receipts), keyring=keyring)
    return VerifiedReceipt(ok=ok, receipt=receipts[-1], notes=notes)
