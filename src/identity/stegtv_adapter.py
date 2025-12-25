from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .continuity_receipts import ContinuityReceipt, mint_receipt


@dataclass
class StegTVContinuityAdapter:
    """
    Thin adapter between StegTV and StegID continuity.
    """

    signing_key_id: str

    def mint(self, *, payload: Any, now_epoch: int) -> ContinuityReceipt:
        return mint_receipt(
            payload=payload,
            signing_key_id=self.signing_key_id,
            now_epoch=now_epoch,
        )
