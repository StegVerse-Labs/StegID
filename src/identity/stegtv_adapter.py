from __future__ import annotations

from typing import Any, Dict, List, Optional

from identity.continuity_receipts import VerificationError, verify_chain_and_sequence


class StegTVContinuityAdapter:
    """
    Minimal adapter: given a list of receipts, verify continuity and return status.
    (Wiring target: StegTV/StegTVC “continuity receipts”.)
    """

    def verify_receipts(self, receipts: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            verify_chain_and_sequence(receipts)
            return {"ok": True, "count": len(receipts)}
        except VerificationError as e:
            return {"ok": False, "error": str(e)}
