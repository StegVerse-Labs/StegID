from __future__ import annotations

from .verify_entrypoint import verify_receipt_payload_bytes


class StegTVContinuityAdapter:
    def __init__(self, *, keyring):
        self.keyring = keyring

    def verify(self, payload_bytes: bytes):
        return verify_receipt_payload_bytes(
            payload_bytes,
            keyring=self.keyring,
        )
