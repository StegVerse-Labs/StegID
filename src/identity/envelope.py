from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Literal, Optional
import hashlib
import json


Encoding = Literal["binary", "base64", "qr"]


@dataclass(frozen=True)
class ReceiptHint:
    account_id: str
    sequence: int
    key_id: str


@dataclass(frozen=True)
class StegIDEnvelope:
    envelope_version: str
    payload_type: str
    payload_hash: str  # sha256 hex of raw payload bytes
    payload_size: int
    encoding: Encoding
    receipt_hint: Optional[ReceiptHint] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "envelope_version": self.envelope_version,
            "payload_type": self.payload_type,
            "payload_hash": self.payload_hash,
            "payload_size": self.payload_size,
            "encoding": self.encoding,
        }
        if self.receipt_hint is not None:
            d["receipt_hint"] = {
                "account_id": self.receipt_hint.account_id,
                "sequence": self.receipt_hint.sequence,
                "key_id": self.receipt_hint.key_id,
            }
        return d

    def to_canonical_bytes(self) -> bytes:
        """
        Deterministic serialization for envelope hashing/signaling.
        """
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    def envelope_hash(self) -> str:
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_receipt_envelope(
    payload: bytes,
    *,
    encoding: Encoding = "binary",
    receipt_hint: Optional[ReceiptHint] = None,
) -> StegIDEnvelope:
    return StegIDEnvelope(
        envelope_version="1.0",
        payload_type="stegid_receipt",
        payload_hash=sha256_hex(payload),
        payload_size=len(payload),
        encoding=encoding,
        receipt_hint=receipt_hint,
    )
