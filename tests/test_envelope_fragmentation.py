from __future__ import annotations

import base64
import hashlib
import math
from typing import Dict, List

from identity.envelope import make_receipt_envelope


def _split_bytes(payload: bytes, fragment_size: int) -> List[bytes]:
    return [payload[i : i + fragment_size] for i in range(0, len(payload), fragment_size)]


def _mk_fragment(envelope_hash: str, idx: int, total: int, frag: bytes) -> Dict[str, str | int]:
    return {
        "fragment_version": "1.0",
        "envelope_hash": envelope_hash,
        "fragment_index": idx,
        "fragment_count": total,
        "fragment_payload": base64.b64encode(frag).decode("ascii"),
        "fragment_hash": hashlib.sha256(frag).hexdigest(),
    }


def test_envelope_hash_and_reassembly_roundtrip():
    payload = b"stegid-receipt-payload-demo-" * 50  # enough bytes to fragment
    env = make_receipt_envelope(payload, encoding="binary")
    env_hash = env.envelope_hash()

    # fragment
    fragment_size = 64
    frags = _split_bytes(payload, fragment_size)
    total = len(frags)
    assert total == math.ceil(len(payload) / fragment_size)

    packets = [_mk_fragment(env_hash, i, total, frags[i]) for i in range(total)]

    # shuffle order to simulate mesh routing
    packets = list(reversed(packets))

    # verify fragments and reassemble
    out_parts: Dict[int, bytes] = {}
    for p in packets:
        assert p["envelope_hash"] == env_hash
        frag_bytes = base64.b64decode(p["fragment_payload"])  # type: ignore[arg-type]
        assert hashlib.sha256(frag_bytes).hexdigest() == p["fragment_hash"]
        out_parts[int(p["fragment_index"])] = frag_bytes  # type: ignore[arg-type]

    assert len(out_parts) == total
    rebuilt = b"".join(out_parts[i] for i in range(total))

    # verify payload hash matches envelope
    assert hashlib.sha256(rebuilt).hexdigest() == env.payload_hash
    assert rebuilt == payload
