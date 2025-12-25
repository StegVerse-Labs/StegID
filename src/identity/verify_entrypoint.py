# src/identity/verify_entrypoint.py
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from .continuity_receipts import VerificationError, verify_chain_and_sequence
from .keyring import KeyringStore


@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: List[Dict[str, Any]]
    error: Optional[Dict[str, Any]] = None


def _parse_payload(payload_bytes: Union[bytes, bytearray]) -> Any:
    try:
        return json.loads(bytes(payload_bytes).decode("utf-8"))
    except Exception:
        raise VerificationError("payload_invalid", "payload is not valid JSON")


def _extract_chain(obj: Any) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Accepts contract shapes:
      - single receipt object  -> { ... }
      - {"receipts": [ ... ]}  -> receipts list
      - {"receipt_chain": [ ... ]} -> chain list
    Returns (chain_list, primary_receipt)
    """
    if isinstance(obj, dict) and ("receipts" in obj or "receipt_chain" in obj):
        chain = obj.get("receipts")
        if chain is None:
            chain = obj.get("receipt_chain")
        if not isinstance(chain, list):
            raise VerificationError("payload_invalid", "receipt chain must be an array")
        if not chain:
            raise VerificationError("payload_invalid", "empty receipt array")
        if not isinstance(chain[0], dict):
            raise VerificationError("payload_invalid", "receipt objects required")
        return chain, chain[0]

    if isinstance(obj, dict):
        # single receipt object
        return [obj], obj

    raise VerificationError("payload_invalid", "payload must be an object")


def verify_receipt_payload_bytes(
    payload_bytes: Union[bytes, bytearray],
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,  # accepted by contract; v1 doesn’t require time checks yet
) -> VerifiedReceipt:
    obj = _parse_payload(payload_bytes)
    chain, primary = _extract_chain(obj)

    try:
        ok, notes = verify_chain_and_sequence(tuple(chain), keyring=keyring)
        return VerifiedReceipt(ok=bool(ok), receipt=primary, notes=notes, error=None)
    except VerificationError as e:
        return VerifiedReceipt(ok=False, receipt=primary if isinstance(primary, dict) else {}, notes=[], error=e.to_dict())
