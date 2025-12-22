from __future__ import annotations

import os
from typing import Optional

try:
    import redis  # type: ignore
except Exception:
    redis = None  # type: ignore

class SettingsStore:
    def __init__(self, redis_url: Optional[str] = None):
        self._mem = {}
        self._r = None
        if redis_url and redis is not None:
            try:
                self._r = redis.Redis.from_url(redis_url, decode_responses=True)
                self._r.ping()
            except Exception:
                self._r = None

    def get_active_signing_key_id(self) -> Optional[str]:
        if self._r is None:
            return self._mem.get("active_signing_key_id")
        try:
            return self._r.get("stegtv:active_signing_key_id")
        except Exception:
            return self._mem.get("active_signing_key_id")

    def set_active_signing_key_id(self, key_id: str) -> None:
        if self._r is None:
            self._mem["active_signing_key_id"] = key_id
            return
        try:
            self._r.set("stegtv:active_signing_key_id", key_id)
        except Exception:
            self._mem["active_signing_key_id"] = key_id
