from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    """Block requests not from allowlisted IPs (best-effort; respects X-Forwarded-For).
    Use ONLY behind a trusted proxy (e.g., Cloudflare/Render) where XFF is set correctly.
    """

    def __init__(self, app, allowlist: Optional[Set[str]] = None, enabled: bool = False):
        super().__init__(app)
        self.allowlist = allowlist or set()
        self.enabled = enabled

    def _client_ip(self, request: Request) -> str:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # left-most is original client in typical proxy setups
            return xff.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        ip = self._client_ip(request)
        if ip not in self.allowlist:
            return JSONResponse({"error": "ip_not_allowed", "ip": ip}, status_code=403)
        return await call_next(request)


class SimpleRateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory sliding-window rate limiter by client IP.
    Not shared across instances; intended as a starter safety net.
    """

    def __init__(self, app, *, window_seconds: int = 60, max_requests: int = 120, enabled: bool = False):
        super().__init__(app)
        self.window = window_seconds
        self.max = max_requests
        self.enabled = enabled
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def _client_ip(self, request: Request) -> str:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        ip = self._client_ip(request)
        now = time.time()
        q = self._hits[ip]
        # drop old
        while q and (now - q[0]) > self.window:
            q.popleft()
        if len(q) >= self.max:
            return JSONResponse({"error": "rate_limited", "ip": ip, "retry_after_seconds": self.window}, status_code=429)
        q.append(now)
        return await call_next(request)


class AdminIPAllowlistMiddleware(BaseHTTPMiddleware):
    """Apply IP allowlist ONLY to admin routes (POST/PUT/PATCH/DELETE or matching path prefixes)."""
    def __init__(self, app, *, allowlist: Optional[Set[str]] = None, enabled: bool = False, admin_path_prefixes: Optional[Set[str]] = None):
        super().__init__(app)
        self.allowlist = allowlist or set()
        self.enabled = enabled
        self.admin_path_prefixes = admin_path_prefixes or {"/v1/identity/"}

    def _client_ip(self, request: Request) -> str:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        if request.client and request.client.host:
            return request.client.host
        return "unknown"

    def _is_admin_route(self, request: Request) -> bool:
        if request.method.upper() in ("POST","PUT","PATCH","DELETE"):
            return True
        path = request.url.path or ""
        return any(path.startswith(p) for p in self.admin_path_prefixes)

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)
        if not self._is_admin_route(request):
            return await call_next(request)
        ip = self._client_ip(request)
        if ip not in self.allowlist:
            return JSONResponse({"error": "admin_ip_not_allowed", "ip": ip}, status_code=403)
        return await call_next(request)
