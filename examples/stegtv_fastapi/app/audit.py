from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

try:
    import redis  # type: ignore
except Exception:
    redis = None  # type: ignore

class AuditStore:
    """Append-only audit log for admin actions (never crash)."""
    def __init__(self, redis_url: Optional[str] = None):
        self._mem: List[Dict[str, Any]] = []
        self._r = None
        if redis_url and redis is not None:
            try:
                self._r = redis.Redis.from_url(redis_url, decode_responses=True)
                self._r.ping()
            except Exception:
                self._r = None

    def append(self, event: Dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", int(time.time()))
        if self._r is None:
            self._mem.append(event)
            return
        try:
            self._r.rpush("stegtv:audit", json.dumps(event, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            self._mem.append(event)

    def list(self, limit: int = 200) -> List[Dict[str, Any]]:
        if self._r is None:
            return self._mem[-limit:]
        try:
            raw = self._r.lrange("stegtv:audit", max(0, -limit), -1)
            return [json.loads(x) for x in raw]
        except Exception:
            return self._mem[-limit:]
