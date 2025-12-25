from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple


class VerificationError(Exception):
    """Raised when receipt verification fails."""


@dataclass(frozen=True)
class ContinuityReceipt:
    receipt_id: str
    payload_hash: str
    signing_key_id: str
    issued_at: int


def _hash_payload(payload: Any) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    except Exception as e:
        raise VerificationError("payload_invalid") from e
    return hashlib.sha256(raw).hexdigest()


def mint_receipt(
    *,
    payload: Any,
    signing_key_id: str,
    now_epoch: int | None = None,
) -> ContinuityReceipt:
    """
    Minimal v1 receipt minting.
    No signing. No crypto beyond hashing.
    """
    if not signing_key_id:
        raise VerificationError("key_invalid")

    ts = now_epoch or int(time.time())
    payload_hash = _hash_payload(payload)

    receipt_id = f"r:{signing_key_id}:{payload_hash[:12]}:{ts}"

    return ContinuityReceipt(
        receipt_id=receipt_id,
        payload_hash=payload_hash,
        signing_key_id=signing_key_id,
        issued_at=ts,
    )


def verify_chain_and_sequence(
    receipts: Iterable[ContinuityReceipt],
    *,
    keyring: Any,
) -> Tuple[bool, List[str]]:
    """
    Minimal chain verification.
    Ensures receipts are well-formed and keys exist.
    """
    notes: List[str] = []

    for r in receipts:
        if not isinstance(r, ContinuityReceipt):
            raise VerificationError("receipt_invalid")

        if not keyring.has_key(r.signing_key_id):
            raise VerificationError("key_invalid")

    return True, notes
