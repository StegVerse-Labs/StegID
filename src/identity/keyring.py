from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class KeyRecord:
    key_id: str
    public_key_pem: str
    created_at: int
    expires_at: int
    revoked: bool = False


class KeyringStore:
    """
    Minimal keyring used by tests.
    Memory-backed by default (redis_url optional for future expansion).
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url
        self._mem: Dict[str, KeyRecord] = {}

    def upsert_key(self, key_id: str, record: Dict[str, Any]) -> None:
        self._mem[key_id] = KeyRecord(
            key_id=record.get("key_id", key_id),
            public_key_pem=record["public_key_pem"],
            created_at=int(record.get("created_at", 0)),
            expires_at=int(record.get("expires_at", 0)),
            revoked=bool(record.get("revoked", False)),
        )

    def get_key(self, key_id: str) -> Optional[KeyRecord]:
        return self._mem.get(key_id)
