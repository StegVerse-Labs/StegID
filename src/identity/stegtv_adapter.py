from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from identity.keyring import KeyringStore
from identity.verify_entrypoint import verify_receipt_payload_bytes, VerifiedReceipt


@dataclass(frozen=True)
class AdapterResult:
    ok: bool
    receipt: Optional[dict] = None
    notes: tuple[str, ...] = ()


class StegTVContinuityAdapter:
    """
    Thin adapter so StegTV / StegTVC components can verify StegID continuity receipts
    without importing from a 'src.' package path (which is not importable in CI).
    """

    def __init__(self, *, keyring: KeyringStore):
        self._keyring = keyring

    def verify_receipt_payload(self, payload_bytes: bytes, *, now_epoch: Optional[int] = None) -> AdapterResult:
        out: VerifiedReceipt = verify_receipt_payload_bytes(
            payload_bytes,
            keyring=self._keyring,
            now_epoch=now_epoch,
        )
        return AdapterResult(ok=out.ok, receipt=out.receipt, notes=out.notes)
