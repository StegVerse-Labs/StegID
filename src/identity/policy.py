from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class VerificationPolicy:
    """
    Policy knobs for adapters and verifiers.

    IMPORTANT:
    - Core receipt signature verification remains offline/deterministic.
    - Policy only adds OPTIONAL checks (e.g., expiry, origin scoping).
    """
    # If True, reject receipts signed by keys whose expires_at < now_epoch.
    enforce_key_expiry: bool = False

    # If non-zero, allow small clock skew in time-based checks. (Advisory for now.)
    allowed_clock_skew_seconds: int = 0

    # Optional scoping: if provided, payload/envelope must match.
    expected_origin: Optional[str] = None
    expected_domain: Optional[str] = None
