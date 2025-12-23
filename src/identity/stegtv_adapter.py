from __future__ import annotations

from typing import Optional

from .keyring import KeyringStore
from .verify_entrypoint import VerifiedReceipt, verify_receipt_payload_bytes


class StegTVContinuityAdapter:
    """
    Thin adapter used by tests to prove wiring between StegTV and StegID verification.
    """

    def __init__(self, keyring: Optional[KeyringStore] = None):
        self.keyring = keyring or KeyringStore(redis_url=None)

    def verify(self, payload_bytes: bytes) -> VerifiedReceipt:
        return verify_receipt_payload_bytes(payload_bytes, keyring=self.keyring)
