from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple
import time
import hashlib
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def b64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def fingerprint_public_key_pem(public_pem: bytes) -> str:
    """Stable fingerprint for identifying the verifying key (NOT a user identifier)."""
    h = hashlib.sha256(public_pem).digest()
    return b64url_encode(h[:16])  # short fingerprint (128-bit)

@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    public_pem: bytes
    not_before_epoch: int
    not_after_epoch: Optional[int] = None
    revoked: bool = False

class VerifierKeyring:
    """A minimal verification keyring for Ed25519 receipt verification.

    In production, StegTV should store this in hardened storage and expose read-only verification material.
    """
    def __init__(self) -> None:
        self._keys: Dict[str, KeyRecord] = {}

    def add_key(self, public_pem: bytes, *, not_before_epoch: int, not_after_epoch: Optional[int] = None) -> str:
        key_id = fingerprint_public_key_pem(public_pem)
        self._keys[key_id] = KeyRecord(
            key_id=key_id,
            public_pem=public_pem,
            not_before_epoch=int(not_before_epoch),
            not_after_epoch=int(not_after_epoch) if not_after_epoch is not None else None,
            revoked=False,
        )
        return key_id

    def revoke_key(self, key_id: str) -> None:
        if key_id in self._keys:
            rec = self._keys[key_id]
            self._keys[key_id] = KeyRecord(
                key_id=rec.key_id,
                public_pem=rec.public_pem,
                not_before_epoch=rec.not_before_epoch,
                not_after_epoch=rec.not_after_epoch,
                revoked=True,
            )

    def get_public_pem(self, key_id: str, *, at_epoch: int) -> Tuple[Optional[bytes], Tuple[str, ...]]:
        notes = []
        rec = self._keys.get(key_id)
        if not rec:
            return None, ("Unknown signing_key_id.",)
        if rec.revoked:
            notes.append("Signing key is revoked.")
        if at_epoch < rec.not_before_epoch:
            notes.append("Receipt time is before key validity.")
        if rec.not_after_epoch is not None and at_epoch > rec.not_after_epoch:
            notes.append("Receipt time is after key expiry.")
        return rec.public_pem, tuple(notes)
