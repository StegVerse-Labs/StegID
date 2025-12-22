from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

try:
    import redis  # type: ignore
except Exception:
    redis = None  # type: ignore


class ReceiptStore:
    """Receipt storage with Redis + memory fallback (never crash)."""

    def __init__(self, redis_url: Optional[str] = None):
        self._mem: Dict[str, List[Dict[str, Any]]] = {}
        self._r = None
        if redis_url and redis is not None:
            try:
                self._r = redis.Redis.from_url(redis_url, decode_responses=True)
                self._r.ping()
            except Exception:
                self._r = None

    def _key(self, account_id: str) -> str:
        return f"stegtv:receipts:{account_id}"

    def list_receipts(self, account_id: str) -> List[Dict[str, Any]]:
        if self._r is None:
            return list(self._mem.get(account_id, []))
        try:
            raw = self._r.lrange(self._key(account_id), 0, -1)
            return [json.loads(x) for x in raw]
        except Exception:
            return list(self._mem.get(account_id, []))

    def get_last_receipt(self, account_id: str) -> Optional[Dict[str, Any]]:
        rs = self.list_receipts(account_id)
        return rs[-1] if rs else None

    def append_receipt(self, account_id: str, receipt: Dict[str, Any]) -> None:
        if self._r is None:
            self._mem.setdefault(account_id, []).append(receipt)
            return
        try:
            self._r.rpush(self._key(account_id), json.dumps(receipt, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            self._mem.setdefault(account_id, []).append(receipt)


class KeyringStore:
    """Keyring storage with Redis + memory fallback (never crash)."""

    def __init__(self, redis_url: Optional[str] = None):
        self._mem: Dict[str, Dict[str, Any]] = {}
        self._r = None
        if redis_url and redis is not None:
            try:
                self._r = redis.Redis.from_url(redis_url, decode_responses=True)
                self._r.ping()
            except Exception:
                self._r = None

    def _key(self) -> str:
        return "stegtv:keyring"

    def list_keys(self) -> List[Dict[str, Any]]:
        if self._r is None:
            return list(self._mem.values())
        try:
            m = self._r.hgetall(self._key())
            return [json.loads(v) for v in m.values()]
        except Exception:
            return list(self._mem.values())

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        if self._r is None:
            return self._mem.get(key_id)
        try:
            v = self._r.hget(self._key(), key_id)
            return json.loads(v) if v else None
        except Exception:
            return self._mem.get(key_id)

    def upsert_key(self, key_id: str, data: Dict[str, Any]) -> None:
        data = dict(data)
        data["key_id"] = key_id
        if self._r is None:
            self._mem[key_id] = data
            return
        try:
            self._r.hset(self._key(), key_id, json.dumps(data, separators=(",", ":"), ensure_ascii=False))
        except Exception:
            self._mem[key_id] = data
