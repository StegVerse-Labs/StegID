from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Union

from .continuity_receipts import (
    ContinuityReceipt,
    VerificationError,
    verify_receipt_chain,
    mint_receipt,
)
from .keyring import KeyringStore


ReceiptInput = Union[
    ContinuityReceipt,
    Dict[str, Any],
]


@dataclass
class StegTVContinuityAdapter:
    """
    Adapter layer expected by tests.

    Responsibilities:
    - Normalize receipt shapes
    - Enforce key presence
    - Mint continuity receipts
    - Delegate verification to continuity_receipts
    """

    keyring: KeyringStore
    now_epoch: Optional[int] = None

    # -------------------------
    # Public entrypoint
    # -------------------------

    def verify(
        self,
        receipts: Union[ReceiptInput, Iterable[ReceiptInput]],
        *,
        require_key: bool = True,
    ) -> List[ContinuityReceipt]:
        """
        Accepts:
        - single receipt object
        - dict receipt
        - iterable of either

        Returns:
        - list of verified ContinuityReceipt
        """

        now = self._now()

        normalized = self._normalize_receipts(receipts)

        if require_key:
            self._require_keys(normalized, now)

        verified = verify_receipt_chain(
            normalized,
            keyring=self.keyring,
            now_epoch=now,
        )

        return verified

    # -------------------------
    # Helpers
    # -------------------------

    def _now(self) -> int:
        return self.now_epoch if self.now_epoch is not None else int(time.time())

    def _normalize_receipts(
        self,
        receipts: Union[ReceiptInput, Iterable[ReceiptInput]],
    ) -> List[ContinuityReceipt]:

        if isinstance(receipts, (dict, ContinuityReceipt)):
            receipts = [receipts]

        out: List[ContinuityReceipt] = []

        for r in receipts:
            if isinstance(r, ContinuityReceipt):
                out.append(r)
            elif isinstance(r, dict):
                out.append(ContinuityReceipt(**r))
            else:
                raise VerificationError(
                    f"Unsupported receipt type: {type(r)}"
                )

        return out

    def _require_keys(
        self,
        receipts: List[ContinuityReceipt],
        now: int,
    ) -> None:
        """
        Enforces presence of keys required by receipts.
        """

        for r in receipts:
            key_id = r.signing_key_id
            if not key_id:
                raise VerificationError("Missing signing key")

            if not self.keyring.has_key(key_id, now_epoch=now):
                raise VerificationError(f"Unknown or expired key: {key_id}")

    # -------------------------
    # Mint passthrough
    # -------------------------

    def mint(
        self,
        *,
        payload: bytes,
        signing_key_id: str,
        signer_private_pem: str,
        expires_in: int = 3600,
    ) -> ContinuityReceipt:
        """
        Tests expect adapter.mint(...) to exist and work.
        """

        now = self._now()

        return mint_receipt(
            payload=payload,
            signing_key_id=signing_key_id,
            signer_private_pem=signer_private_pem,
            now_epoch=now,
            expires_at=now + expires_in,
        )
