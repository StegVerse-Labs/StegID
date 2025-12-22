from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import time


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    notes: Tuple[str, ...]


def validate_timestamps(
    receipts: List[Dict[str, Any]],
    *,
    now_epoch: Optional[int] = None,
    max_future_skew_seconds: int = 120,
    require_monotonic: bool = True,
) -> ValidationResult:
    """
    Prudent verifier-side checks (independent of cryptography):
    - Reject receipts too far in the future (default 120s skew)
    - Optionally require monotonic non-decreasing issued_at timestamps
    """
    if now_epoch is None:
        now_epoch = int(time.time())

    notes: List[str] = []
    last_ts: Optional[int] = None

    for i, r in enumerate(receipts):
        ts = int(r.get("issued_at", -1))
        if ts < 0:
            return ValidationResult(False, (f"Receipt[{i}] missing/invalid issued_at.",))

        if ts > now_epoch + max_future_skew_seconds:
            return ValidationResult(
                False,
                (f"Receipt[{i}] is future-dated beyond allowed skew: {ts} > {now_epoch}+{max_future_skew_seconds}.",),
            )

        if require_monotonic and last_ts is not None and ts < last_ts:
            return ValidationResult(False, (f"Receipt[{i}] issued_at not monotonic: {ts} < {last_ts}.",))

        last_ts = ts

    return ValidationResult(True, tuple(notes))


def summarize_gaps(
    receipts: List[Dict[str, Any]],
    *,
    gap_threshold_seconds: int = 7 * 24 * 3600,
) -> Dict[str, Any]:
    """
    Optional: summarize large time gaps.
    This does NOT invalidate continuity, but can inform tiering decisions.
    """
    if len(receipts) < 2:
        return {"gaps": [], "max_gap_seconds": 0}

    gaps = []
    max_gap = 0
    for i in range(1, len(receipts)):
        a = int(receipts[i - 1].get("issued_at", 0))
        b = int(receipts[i].get("issued_at", 0))
        gap = max(0, b - a)
        max_gap = max(max_gap, gap)
        if gap >= gap_threshold_seconds:
            gaps.append({"from_index": i - 1, "to_index": i, "gap_seconds": gap})

    return {"gaps": gaps, "max_gap_seconds": max_gap}
