from __future__ import annotations

from identity.keyring import KeyringStore
from identity.verify_entrypoint import verify_receipt_payload_bytes, VerifiedReceipt


def make_stegid_verify_fn(*, keyring: KeyringStore):
    """
    Returns a function compatible with stegtalk_transport.handoff.handoff_to_stegid
    that verifies StegID receipt payload bytes using the provided KeyringStore.
    """
    def _verify(payload_bytes: bytes) -> VerifiedReceipt:
        return verify_receipt_payload_bytes(payload_bytes, keyring=keyring)
    return _verify
