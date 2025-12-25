from __future__ import annotations

from typing import Any, Dict, Optional


class KeyringStore:
    """
    Canonical keyring storage (v1 frozen surface).

    Canonical methods:
      - add_public_key_pem(key_id, public_key_pem)
      - revoke_key(key_id)
      - get_public_key_pem(key_id) -> Optional[str]

    Compatibility:
      - upsert_key(...) accepts BOTH:
          (A) upsert_key(key_id, record_dict)
          (B) upsert_key(key_id=..., public_key_pem=..., revoked=False, created_at=..., expires_at=...)
          (C) upsert_key(key_id=..., public_pem=...)
    """

    def __init__(self, redis_url: Optional[str] = None):
        # redis_url accepted for API compatibility; in-memory for v1
        self._keys: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Canonical API (v1 frozen)
    # ------------------------------------------------------------------

    def add_public_key_pem(self, key_id: str, public_key_pem: str) -> None:
        self._keys[key_id] = {
            "public_key_pem": public_key_pem,
            "revoked": False,
        }

    def revoke_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Unknown key_id: {key_id}")
        self._keys[key_id]["revoked"] = True

    def get_public_key_pem(self, key_id: str) -> Optional[str]:
        entry = self._keys.get(key_id)
        if not entry or bool(entry.get("revoked", False)):
            return None
        return entry.get("public_key_pem")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _put_record(self, key_id: str, record: Dict[str, Any]) -> None:
        rec = dict(record)
        rec.setdefault("key_id", key_id)
        # normalize field names
        if "public_pem" in rec and "public_key_pem" not in rec:
            rec["public_key_pem"] = rec["public_pem"]
        if "revoked" not in rec:
            rec["revoked"] = False
        self._keys[key_id] = rec

    def get_key_record(self, key_id: str) -> Optional[Dict[str, Any]]:
        return self._keys.get(key_id)

    # ------------------------------------------------------------------
    # Compatibility surface (v1 frozen name, flexible args)
    # ------------------------------------------------------------------

    def upsert_key(self, *args: Any, **kwargs: Any) -> None:
        """
        Compatibility shim.

        Supported call patterns:
          upsert_key(key_id, record_dict)
          upsert_key(key_id=..., public_key_pem=..., revoked=False, created_at=..., expires_at=...)
          upsert_key(key_id=..., public_pem=..., revoked=False)
        """
        # Pattern: (key_id, record_dict)
        if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            self._put_record(args[0], args[1])
            return

        # Pattern: (key_id) as first positional + kwargs
        key_id = None
        if args and isinstance(args[0], str):
            key_id = args[0]
        if "key_id" in kwargs and isinstance(kwargs["key_id"], str):
            key_id = kwargs["key_id"]

        if not key_id:
            raise TypeError("upsert_key requires key_id")

        public_key_pem = (
            kwargs.get("public_key_pem")
            or kwargs.get("public_pem")
            or kwargs.get("public_pem_str")
            or kwargs.get("publicKeyPem")
        )

        record: Dict[str, Any] = {}
        if public_key_pem is not None:
            record["public_key_pem"] = public_key_pem

        # pass-through metadata if provided
        for k in ("created_at", "expires_at", "revoked"):
            if k in kwargs:
                record[k] = kwargs[k]

        # If caller gave nothing besides key_id: ensure record exists (noop else)
        if not record:
            if key_id not in self._keys:
                self._put_record(key_id, {"revoked": False})
            return

        self._put_record(key_id, record)
