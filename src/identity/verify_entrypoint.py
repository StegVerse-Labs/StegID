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
    Accepted shapes (v1):
      - single receipt object             -> { ... }
      - {"receipts": [ ... ]}             -> list
      - {"receipt_chain": [ ... ]}        -> list
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
        if not all(isinstance(x, dict) for x in chain):
            raise VerificationError("payload_invalid", "receipt objects required")

        return chain, chain[0]

    if isinstance(obj, dict):
        return [obj], obj

    raise VerificationError("payload_invalid", "payload must be an object")


def verify_receipt_payload_bytes(
    payload_bytes: Union[bytes, bytearray],
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,  # accepted by contract; not enforced in v1 yet
) -> VerifiedReceipt:
    obj = _parse_payload(payload_bytes)
    chain, primary = _extract_chain(obj)

    try:
        ok, notes = verify_chain_and_sequence(tuple(chain), keyring=keyring)
        return VerifiedReceipt(ok=bool(ok), receipt=primary, notes=notes, error=None)
    except VerificationError as e:
        # primary is always a dict here (by _extract_chain contract)
        return VerifiedReceipt(ok=False, receipt=primary, notes=[], error=e.to_dict())
