from __future__ import annotations

import os
from fastapi import Header, HTTPException

def require_admin(x_admin_token: str | None = Header(default=None, alias="X-Admin-Token")) -> None:
    expected = os.getenv("STEGTV_ADMIN_TOKEN") or ""
    if not expected:
        raise HTTPException(status_code=500, detail="STEGTV_ADMIN_TOKEN not configured")
    if not x_admin_token or x_admin_token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
