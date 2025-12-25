from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


# =========================
# Errors
# =========================

class VerificationError(Exception):
    """
    Raised when a receipt or receipt chain fails verification.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# =========================
# Receipt model
# =========================

@dataclass(frozen=True)
class ContinuityReceipt:
    """
    Immutable continuity receipt.

    This is the atomic contract object for StegID v1.
    """
    receipt_id: str
    key_id: str
    payload_hash: str
    issued_at: int
    previous_receipt_id: Optional[str] = None


# =========================
# Helpers
# =========================

def fingerprint_public_key_pem(public_pem: str) -> str:
    """
    Stable fingerprint for a public key PEM.
    """
    h = hashlib.sha256()
    h.update(public_pem.encode("utf-8"))
    return h.hexdigest()


def _hash_payload(payload: bytes) -> str:
    h = hashlib.sha256()
    h.update(payload)
    return h.hexdigest()


# =========================
# Minting
# =========================

def mint_receipt(
    *,
    receipt_id: str,
    signing_key_id: str,
    payload: bytes,
    issued_at: Optional[int] = None,
    previous_receipt_id: Optional[str] = None,
) -> ContinuityReceipt:
    """
    Mint a new continuity receipt.

    NOTE:
    Cryptographic signing is intentionally out of scope for StegID v1.
    This function produces a deterministic, verifiable receipt object.
    """
    if not signing_key_id:
        raise VerificationError("key_invalid", "Missing signing key id")

    if not payload:
        raise VerificationError("payload_invalid", "Payload is empty")

    ts = issued_at if issued_at is not None else int(time.time())

    return ContinuityReceipt(
        receipt_id=receipt_id,
        key_id=signing_key_id,
        payload_hash=_hash_payload(payload),
        issued_at=ts,
        previous_receipt_id=previous_receipt_id,
    )


# =========================
# Verification
# =========================

def verify_chain_and_sequence(
    receipts: Iterable[ContinuityReceipt],
    *,
    keyring: Any,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, List[str]]:
    """
    Verify a receipt chain and its ordering.

    Returns:
        (ok, notes)
    """
    notes: List[str] = []
    receipts = list(receipts)

    if not receipts:
        raise VerificationError("payload_invalid", "No receipts provided")

    seen_ids = set()
    prev_id = None

    for r in receipts:
        if r.receipt_id in seen_ids:
            raise VerificationError("payload_invalid", "Duplicate receipt id")

        seen_ids.add(r.receipt_id)

        if prev_id is not None and r.previous_receipt_id != prev_id:
            raise VerificationError(
                "payload_invalid",
                "Receipt chain is broken",
            )

        # Key existence check (best-effort, interface-agnostic)
        if hasattr(keyring, "has_key"):
            if not keyring.has_key(r.key_id):
                raise VerificationError("key_invalid", "Unknown signing key")

        prev_id = r.receipt_id

    notes.append("chain_ok")
    return True, notes
