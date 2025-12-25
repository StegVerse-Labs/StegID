from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------------------
# Crypto agility helpers (backward compatible with v1 receipts)
#
# Supported receipt shapes:
#  - v1: { "signing_key_id": "...", "signature": "..." }
#  - v1.1: { "signatures": [ { "alg": "ed25519", "key_id": "...", "sig": "..." }, ... ] }
#  - hybrid-friendly: keep BOTH v1 and v1.1 fields during transition
#
# NOTE: v1.1 is additive. Existing verifiers MUST continue to accept v1 receipts.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SignatureRecord:
    alg: str
    key_id: str
    sig: str


def normalize_signatures(receipt: Dict[str, Any]) -> List[SignatureRecord]:
    """
    Returns a normalized list of signatures contained in `receipt`.

    Preference order:
      1) receipt["signatures"] list (v1.1+)
      2) legacy v1 fields: signing_key_id + signature

    This function never raises; it returns [] if no signatures exist.
    """
    sigs: List[SignatureRecord] = []

    raw = receipt.get("signatures")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            alg = str(item.get("alg", "")).strip()
            key_id = str(item.get("key_id", "")).strip()
            sig = str(item.get("sig", "")).strip()
            if alg and key_id and sig:
                sigs.append(SignatureRecord(alg=alg, key_id=key_id, sig=sig))

    # Legacy fallback
    if not sigs:
        key_id = receipt.get("signing_key_id")
        sig = receipt.get("signature")
        if isinstance(key_id, str) and key_id and isinstance(sig, str) and sig:
            sigs.append(
                SignatureRecord(
                    alg=str(receipt.get("signature_alg") or "ed25519"),
                    key_id=key_id,
                    sig=sig,
                )
            )

    return sigs


def primary_signature(
    receipt: Dict[str, Any],
    *,
    preferred_algs: Optional[List[str]] = None,
) -> Optional[SignatureRecord]:
    """
    Returns the "best" signature for verification based on `preferred_algs`.
    If no preference, returns first normalized signature.
    """
    sigs = normalize_signatures(receipt)
    if not sigs:
        return None

    if preferred_algs:
        pref = [a.lower() for a in preferred_algs]
        for a in pref:
            for s in sigs:
                if s.alg.lower() == a:
                    return s

    return sigs[0]
