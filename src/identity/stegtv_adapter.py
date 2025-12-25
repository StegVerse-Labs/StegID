"""
StegTV ↔ StegID Continuity Adapter

Purpose:
- Glue layer between StegTV-style event minting
  and StegID continuity receipts
- No cryptography here beyond delegation
- Keeps adapter surface stable for tests

This file intentionally:
- Re-exports ContinuityReceipt
- Implements mint_receipt passthrough
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .continuity_receipts import (
    ReceiptV1 as ContinuityReceipt,
    VerificationError,
    mint_receipt,
    verify_chain_and_sequence,
)


# ---------------------------
# Adapter
# ---------------------------

@dataclass
class StegTVContinuityAdapter:
    """
    Minimal adapter used by tests and transport wiring.

    Contract:
    - keyring must be provided
    - mint() returns a ContinuityReceipt (dict)
    - verify_chain() delegates to StegID verification
    """

    keyring: Any

    # ---- minting ----

    def mint(
        self,
        *,
        receipt_id: str,
        signing_key_id: str,
        ed25519_private_pem: str,
        payload: Any = None,
        issued_at: Optional[int] = None,
        prev_receipt_hash: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mint a continuity receipt.

        NOTE:
        - We do not alter semantics here
        - This is a strict passthrough
        """
        return mint_receipt(
            receipt_id=receipt_id,
            signing_key_id=signing_key_id,
            ed25519_private_pem=ed25519_private_pem,
            payload=payload,
            issued_at=issued_at,
            prev_receipt_hash=prev_receipt_hash,
            meta=meta,
        )

    # ---- verification ----

    def verify_chain(
        self,
        receipts,
        *,
        now_epoch: Optional[int] = None,
    ):
        """
        Verify a chain of receipts using the adapter's keyring.
        """
        return verify_chain_and_sequence(
            receipts,
            keyring=self.keyring,
            now_epoch=now_epoch,
        )


# ---------------------------
# Public exports
# ---------------------------

__all__ = [
    "StegTVContinuityAdapter",
    "ContinuityReceipt",
    "VerificationError",
]
