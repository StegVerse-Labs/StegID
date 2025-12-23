from __future__ import annotations

from typing import Optional

from .verify_entrypoint import verify_receipt_payload_bytes
from .keyring import KeyringStore


class StegTVContinuityAdapter:
    """
    Adapter used by StegTV / transport layer.

    Tests expect:
      adapter.verify_receipt_payload(payload_bytes, now_epoch=...)
    """

    def __init__(self, *, keyring: Optional[KeyringStore] = None):
        self.keyring = keyring or KeyringStore(redis_url=None)

    def verify_receipt_payload(
        self,
        payload_bytes: bytes,
        *,
        now_epoch: int,
    ):
        """
        Verify a receipt payload (JSON bytes).

        Returns VerifiedReceipt.
        Raises VerificationError on failure.
        """
        return verify_receipt_payload_bytes(
            payload_bytes,
            keyring=self.keyring,
            now_epoch=now_epoch,
        )
