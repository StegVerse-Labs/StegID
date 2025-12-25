from __future__ import annotations

from dataclasses import dataclass

from .keyring import KeyringStore
from .verify_entrypoint import VerifiedReceipt, verify_receipt_payload_bytes


@dataclass
class StegTVContinuityAdapter:
    """
    Adapter wrapper for StegTV and similar downstream systems.

    Provides a stable method name and return type while using StegID's
    transport-safe verification entrypoint internally.
    """
    keyring: KeyringStore

    def verify_receipt_payload(self, payload_bytes: bytes, *, now_epoch: int) -> VerifiedReceipt:
        return verify_receipt_payload_bytes(payload_bytes, keyring=self.keyring, now_epoch=now_epoch)
