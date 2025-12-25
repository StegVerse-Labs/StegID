# src/identity/stegtv_adapter.py
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Union

from .continuity_receipts import VerificationError, verify_chain_and_sequence
from .keyring import KeyringStore
from .verify_entrypoint import VerifiedReceipt, verify_receipt_payload_bytes

ReceiptDict = Dict[str, Any]
ReceiptInput = Union[ReceiptDict, Iterable[ReceiptDict]]


@dataclass
class StegTVContinuityAdapter:
    """
    StegTV ↔ StegID adapter (v1).

    STRICT DEFAULT:
      - strict=True: raises VerificationError (so tests can use pytest.raises)
      - strict=False: returns VerifiedReceipt(ok=False, error=...)
    """

    keyring: KeyringStore
    now_epoch: Optional[int] = None

    def _now(self) -> int:
        return int(self.now_epoch if self.now_epoch is not None else time.time())

    def _normalize_receipts(self, receipts: ReceiptInput) -> List[ReceiptDict]:
        if isinstance(receipts, dict):
            return [receipts]

        out: List[ReceiptDict] = []
        for r in receipts:
            if not isinstance(r, dict):
                raise VerificationError("payload_invalid", f"receipt must be an object, got {type(r)}")
            out.append(r)
        if not out:
            raise VerificationError("payload_invalid", "empty receipt list")
        return out

    def verify_receipts(
        self,
        receipts: ReceiptInput,
        *,
        strict: bool = True,
    ) -> VerifiedReceipt:
        chain = self._normalize_receipts(receipts)
        primary = chain[0]

        if strict:
            # IMPORTANT: do not swallow contract errors in strict mode.
            ok, notes = verify_chain_and_sequence(tuple(chain), keyring=self.keyring)
            return VerifiedReceipt(ok=bool(ok), receipt=primary, notes=notes, error=None)

        # Non-strict: wrap failures into VerifiedReceipt
        try:
            ok, notes = verify_chain_and_sequence(tuple(chain), keyring=self.keyring)
            return VerifiedReceipt(ok=bool(ok), receipt=primary, notes=notes, error=None)
        except VerificationError as e:
            return VerifiedReceipt(ok=False, receipt=primary, notes=[], error=e.to_dict())

    # Legacy-friendly alias
    def verify(self, receipts: ReceiptInput, *, strict: bool = True) -> VerifiedReceipt:
        return self.verify_receipts(receipts, strict=strict)

    def verify_receipt_payload(
        self,
        payload_bytes: Union[bytes, bytearray],
        *,
        now_epoch: Optional[int] = None,
        strict: bool = True,
    ) -> VerifiedReceipt:
        """
        Verifies JSON payload shaped as:
          - single receipt object
          - {"receipts":[...]}
          - {"receipt_chain":[...]}
        """
        now = int(now_epoch if now_epoch is not None else self._now())
        return verify_receipt_payload_bytes(
            payload_bytes,
            keyring=self.keyring,
            now_epoch=now,
            strict=strict,
        )

    def export_verified_summary_json(self, receipts: ReceiptInput) -> str:
        # Prefer non-strict for summary export (never throws)
        out = self.verify_receipts(receipts, strict=False)
        return json.dumps(
            {
                "ok": out.ok,
                "error": out.error,
                "receipt_id": out.receipt.get("receipt_id"),
                "sequence": out.receipt.get("sequence"),
                "notes": out.notes,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
