from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from identity.envelope import StegIDEnvelope, sha256_hex


@dataclass(frozen=True)
class VerificationError(Exception):
    code: str
    message: str


@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: Tuple[str, ...] = ()


def handoff_to_stegid(
    *,
    envelope: StegIDEnvelope,
    payload_bytes: bytes,
    steg_id_verify_fn,
) -> VerifiedReceipt:
    """
    Transport-agnostic delivery to StegID verification.
    - Validates payload hash and size first (transport responsibility).
    - Calls provided StegID verifier function for cryptographic checks.
    """
    if len(payload_bytes) != envelope.payload_size:
        raise VerificationError("bad_size", f"payload size {len(payload_bytes)} != {envelope.payload_size}")

    if sha256_hex(payload_bytes) != envelope.payload_hash:
        raise VerificationError("bad_hash", "payload sha256 does not match envelope")

    # Decode is verifier responsibility (payload may be json/binary). We keep it opaque here.
    return steg_id_verify_fn(payload_bytes)
