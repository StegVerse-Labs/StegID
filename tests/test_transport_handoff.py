from __future__ import annotations

import pytest

from identity.envelope import make_receipt_envelope
from stegtalk_transport.handoff import handoff_to_stegid, VerificationError, VerifiedReceipt


def test_handoff_rejects_bad_hash_and_size():
    payload = b"hello"
    env = make_receipt_envelope(payload)

    def fake_verify(_bytes: bytes) -> VerifiedReceipt:
        return VerifiedReceipt(ok=True, receipt={"demo": True})

    # bad size
    with pytest.raises(VerificationError) as e1:
        handoff_to_stegid(envelope=env, payload_bytes=b"helloo", steg_id_verify_fn=fake_verify)
    assert e1.value.code == "bad_size"

    # bad hash (same size, different bytes)
    with pytest.raises(VerificationError) as e2:
        handoff_to_stegid(envelope=env, payload_bytes=b"jello", steg_id_verify_fn=fake_verify)
    assert e2.value.code == "bad_hash"
