from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Optional


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def make_receipt_envelope(
    payload_bytes: bytes,
    *,
    origin: Optional[str] = None,
    domain: Optional[str] = None,
    include_payload_hash: bool = True,
) -> dict:
    """
    Minimal transport envelope for receipt payloads.
    - Does NOT include PII.
    - Designed for StegTalk or any carrier.
    """
    env = {}
    if origin is not None:
        env["origin"] = origin
    if domain is not None:
        env["domain"] = domain
    if include_payload_hash:
        env["payload_sha256"] = hashlib.sha256(payload_bytes).hexdigest()
        env["payload_b64u"] = _b64u(payload_bytes)
    return env
