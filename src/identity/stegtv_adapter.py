from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import time

from src.identity.continuity_receipts import (
    canonical_json,
    receipt_core,
    verify_receipt_ed25519,
    verify_chain_and_sequence,
)
from src.identity.keyring import VerifierKeyring

@dataclass(frozen=True)
class ReceiptDerivedSignals:
    crypto_continuity: Dict[str, Any]
    time_depth: Dict[str, Any]
    notes: Tuple[str, ...]

def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x

def derive_signals_from_receipts_strict(
    receipts: List[Dict[str, Any]],
    *,
    keyring: VerifierKeyring,
    now_epoch: Optional[int] = None,
) -> ReceiptDerivedSignals:
    """Strict derivation:
    - requires Ed25519
    - verifies signature of each receipt using keyring
    - verifies prev_hash chain + strict monotonic sequence
    """
    notes: List[str] = []
    if now_epoch is None:
        now_epoch = int(time.time())

    if not receipts:
        return ReceiptDerivedSignals(
            crypto_continuity={"score": 0.0, "evidence": {"reason": "no_receipts"}},
            time_depth={"score": 0.0, "evidence": {"reason": "no_receipts"}},
            notes=("No receipts provided.",),
        )

    ok, chain_notes = verify_chain_and_sequence(tuple(receipts))
    notes.extend(chain_notes)
    if not ok:
        notes.append("Receipts failed strict chain/sequence checks; continuity degraded.")
        return ReceiptDerivedSignals(
            crypto_continuity={"score": 0.05, "evidence": {"reason": "chain_or_sequence_invalid"}},
            time_depth={"score": 0.05, "evidence": {"reason": "chain_or_sequence_invalid"}},
            notes=tuple(notes),
        )

    # Verify signatures
    for idx, r in enumerate(receipts):
        key_id = r.get("signing_key_id", "")
        issued_at = int(r.get("issued_at", now_epoch))
        pub_pem, knotes = keyring.get_public_pem(key_id, at_epoch=issued_at)
        notes.extend(knotes)
        if pub_pem is None:
            notes.append(f"Missing public key for receipt index {idx}.")
            return ReceiptDerivedSignals(
                crypto_continuity={"score": 0.05, "evidence": {"reason": "unknown_key"}},
                time_depth={"score": 0.05, "evidence": {"reason": "unknown_key"}},
                notes=tuple(notes),
            )
        core_bytes = canonical_json(receipt_core(r))
        if not verify_receipt_ed25519(pub_pem, core_bytes, r.get("signature", "")):
            notes.append(f"Signature verification failed at index {idx}.")
            return ReceiptDerivedSignals(
                crypto_continuity={"score": 0.05, "evidence": {"reason": "bad_signature"}},
                time_depth={"score": 0.05, "evidence": {"reason": "bad_signature"}},
                notes=tuple(notes),
            )

    # Evidence extraction for scoring
    first = receipts[0]
    last = receipts[-1]
    first_seen = int(first.get("issued_at", now_epoch))
    last_seen = int(last.get("issued_at", now_epoch))
    span_days = max(0.0, (last_seen - first_seen) / 86400.0)

    key_created = any(r.get("event", {}).get("type") == "key_created" for r in receipts)
    rotations = sum(1 for r in receipts if r.get("event", {}).get("type") == "key_rotated")
    revokes = sum(1 for r in receipts if r.get("event", {}).get("type") == "key_revoked")

    base = 0.2
    if key_created:
        base = 0.7
    hygiene = min(0.20, rotations * 0.06)
    penalty = min(0.45, revokes * 0.25)
    crypto_score = _clamp01(base + hygiene - penalty)

    span_score = _clamp01(span_days / 365.0)
    recency_days = max(0.0, (now_epoch - last_seen) / 86400.0)
    recency_factor = 1.0 if recency_days <= 14 else _clamp01(14.0 / (recency_days + 1e-6))
    time_score = _clamp01(span_score * recency_factor)

    if revokes > 0:
        notes.append("Key revocation events present; require recovery drill and/or guardian quorum review.")

    return ReceiptDerivedSignals(
        crypto_continuity={
            "score": crypto_score,
            "evidence": {
                "key_created": key_created,
                "rotations": rotations,
                "revokes": revokes,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "strict": True,
            },
        },
        time_depth={
            "score": time_score,
            "evidence": {
                "span_days": span_days,
                "recency_days": recency_days,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "strict": True,
            },
        },
        notes=tuple(notes),
    )
