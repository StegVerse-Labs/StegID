from __future__ import annotations

from identity.keyring import Keyring
from identity.verify_entrypoint import verify_receipt_payload_bytes, VerifiedReceipt


def make_stegid_verify_fn(*, keyring: Keyring):
    """
    Returns a function compatible with stegtalk_transport.handoff.handoff_to_stegid
    that verifies StegID receipt payload bytes using the provided Keyring.
    """
    def _verify(payload_bytes: bytes) -> VerifiedReceipt:
        return verify_receipt_payload_bytes(payload_bytes, keyring=keyring)
    return _verify
