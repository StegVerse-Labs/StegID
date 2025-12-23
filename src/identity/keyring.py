from __future__ import annotations

from typing import Dict, Optional
import time


class _BaseKeyring:
    """
    Internal base keyring implementation.
    Stores public keys and validity windows.
    """

    def __init__(self, redis_url: Optional[str] = None):
        # Redis wiring may be added later; for now, in-memory
        self._keys: Dict[str, Dict] = {}

    def upsert_key(self, key_id: str, record: Dict) -> None:
        self._keys[key_id] = record

    def revoke_key(self, key_id: str) -> None:
        if key_id in self._keys:
            self._keys[key_id]["revoked"] = True

    def get_public_key_pem_if_valid(self, key_id: str, at_epoch: int) -> Optional[str]:
        rec = self._keys.get(key_id)
        if not rec:
            return None

        if rec.get("revoked"):
            return None

        created = rec.get("created_at", 0)
        expires = rec.get("expires_at")

        if at_epoch < created:
            return None
        if expires is not None and at_epoch > expires:
            return None

        return rec.get("public_key_pem")


# ✅ Canonical, public name used everywhere else
class KeyringStore(_BaseKeyring):
    """
    Public keyring interface used by StegID verifiers, adapters, and tests.

    This alias ensures stability even if the internal implementation changes.
    """
    pass
