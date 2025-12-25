# src/identity/keyring.py
from __future__ import annotations

from typing import Any, Dict, Optional


class KeyringStore:
    """
    Canonical keyring storage (v1).

    v1 reality: call sites/tests may use incompatible patterns.
    We keep a stable minimal surface AND accept legacy shapes.

    Supported:
      - add_public_key_pem(key_id, public_key_pem)
      - get_public_key_pem(key_id)
      - revoke_key(key_id)
      - upsert_key(key_id, record_dict)
      - upsert_key(key_id=..., public_key_pem=..., revoked=False, created_at=..., expires_at=...)
      - upsert_key(key_id=..., public_pem=..., revoked=False, ...)
    """

    def __init__(self, redis_url: Optional[str] = None):
        self._keys: Dict[str, Dict[str, Any]] = {}
        self.redis_url = redis_url  # accepted for compatibility

    def add_public_key_pem(self, key_id: str, public_key_pem: str) -> None:
        self._keys[key_id] = {
            "key_id": key_id,
            "public_key_pem": public_key_pem,
            "revoked": False,
        }

    def revoke_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Unknown key_id: {key_id}")
        self._keys[key_id]["revoked"] = True

    def get_public_key_pem(self, key_id: str) -> Optional[str]:
        entry = self._keys.get(key_id)
        if not entry or entry.get("revoked"):
            return None
        return entry.get("public_key_pem")

    def upsert_key(self, *args: Any, **kwargs: Any) -> None:
        """
        Compatibility shim.

        Accepts:
          - upsert_key(key_id, record_dict)
          - upsert_key(key_id=..., public_key_pem=..., revoked=False, ...)
          - upsert_key(key_id=..., public_pem=..., revoked=False, ...)
        """
        if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            key_id = args[0]
            record = dict(args[1])
            record.setdefault("key_id", key_id)
            record.setdefault("revoked", False)
            # normalize common field name
            if "public_pem" in record and "public_key_pem" not in record:
                record["public_key_pem"] = record["public_pem"]
            self._keys[key_id] = record
            return

        key_id = kwargs.get("key_id")
        public_key_pem = kwargs.get("public_key_pem") or kwargs.get("public_pem")
        revoked = bool(kwargs.get("revoked", False))

        if not isinstance(key_id, str) or not key_id:
            raise TypeError("upsert_key requires key_id")

        if not isinstance(public_key_pem, str) or not public_key_pem:
            raise TypeError("upsert_key requires public_key_pem (or public_pem)")

        rec = dict(kwargs)
        rec["key_id"] = key_id
        rec["public_key_pem"] = public_key_pem
        rec["revoked"] = revoked
        self._keys[key_id] = rec
