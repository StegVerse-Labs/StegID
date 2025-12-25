# src/identity/continuity_receipts.py
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


# ----------------------------
# Errors
# ----------------------------

class VerificationError(Exception):
    """
    Structured verification error.

    Tests expect:
      - e.value.code == "key_invalid" when key missing/expired/revoked/unusable
      - e.value.code == "payload_invalid" when receipt/payload malformed or signature bad
    """
    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code
        self.message = message or code


# ----------------------------
# Helpers
# ----------------------------

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64d(s: str) -> bytes:
    # restore padding
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _now_epoch() -> int:
    return int(time.time())

def _canonical_receipt_signing_bytes(
    *,
    v: int,
    key_id: str,
    created_at: int,
    expires_at: int,
    payload_b64: str,
    prev_receipt_id: Optional[str],
) -> bytes:
    """
    Canonical bytes signed by Ed25519 private key.

    Important: keep stable across versions. This is our v1 canonicalization.
    """
    obj = {
        "v": v,
        "key_id": key_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "payload_b64": payload_b64,
        "prev_receipt_id": prev_receipt_id or "",
    }
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def _load_ed25519_private_pem(pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            pem.encode("utf-8"),
            password=None,
        )
    except Exception as e:
        raise VerificationError("payload_invalid", f"invalid private key pem: {e}") from e
    if not isinstance(key, Ed25519PrivateKey):
        raise VerificationError("payload_invalid", "private key is not Ed25519")
    return key

def _load_ed25519_public_pem(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except Exception as e:
        raise VerificationError("payload_invalid", f"invalid public key pem: {e}") from e
    if not isinstance(key, Ed25519PublicKey):
        raise VerificationError("payload_invalid", "public key is not Ed25519")
    return key


# ----------------------------
# Keyring access (best effort / duck-typing)
# ----------------------------

def _keyring_get_record(keyring: Any, key_id: str) -> Optional[Dict[str, Any]]:
    """
    Tries common keyring APIs. Expected record fields (any naming accepted):
      - public_key_pem / public_key / public_key_pem_str / public_key_pem_bytes
      - revoked (bool)
      - expires_at (int epoch)
    """
    if keyring is None:
        return None

    candidates = [
        ("get_key", (key_id,)),
        ("get", (key_id,)),
        ("lookup", (key_id,)),
        ("fetch", (key_id,)),
        ("read", (key_id,)),
    ]
    for name, args in candidates:
        fn = getattr(keyring, name, None)
        if callable(fn):
            try:
                out = fn(*args)
                if out is None:
                    return None
                if isinstance(out, dict):
                    return out
                # Sometimes returns dataclass/object
                if hasattr(out, "__dict__"):
                    return dict(out.__dict__)
            except TypeError:
                # signature mismatch, ignore
                continue
            except Exception:
                # treat as missing
                return None

    return None

def _extract_public_pem(rec: Dict[str, Any]) -> Optional[str]:
    for k in ("public_key_pem", "public_key_pem_str", "public_key", "pub_pem", "public_pem", "public_key_pem_text"):
        v = rec.get(k)
        if isinstance(v, str) and "BEGIN PUBLIC KEY" in v:
            return v
    # sometimes bytes
    for k in ("public_key_pem_bytes", "public_key_bytes", "pub_pem_bytes"):
        v = rec.get(k)
        if isinstance(v, (bytes, bytearray)):
            try:
                s = bytes(v).decode("utf-8")
                if "BEGIN PUBLIC KEY" in s:
                    return s
            except Exception:
                pass
    return None

def _record_is_revoked(rec: Dict[str, Any]) -> bool:
    v = rec.get("revoked")
    return bool(v) if v is not None else False

def _record_expires_at(rec: Dict[str, Any]) -> Optional[int]:
    v = rec.get("expires_at")
    if isinstance(v, (int, float)):
        return int(v)
    # alternate naming
    v = rec.get("expires")
    if isinstance(v, (int, float)):
        return int(v)
    return None

def _key_invalid(msg: str) -> VerificationError:
    return VerificationError("key_invalid", msg)

def _payload_invalid(msg: str) -> VerificationError:
    return VerificationError("payload_invalid", msg)


# ----------------------------
# Receipt model
# ----------------------------

@dataclass(frozen=True)
class ContinuityReceipt:
    """
    Continuity receipt (v1).
    """
    v: int
    receipt_id: str
    key_id: str
    created_at: int
    expires_at: int
    payload_b64: str
    sig_b64: str
    prev_receipt_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "v": self.v,
            "receipt_id": self.receipt_id,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "payload_b64": self.payload_b64,
            "sig_b64": self.sig_b64,
            "prev_receipt_id": self.prev_receipt_id,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ContinuityReceipt":
        try:
            return ContinuityReceipt(
                v=int(d["v"]),
                receipt_id=str(d["receipt_id"]),
                key_id=str(d["key_id"]),
                created_at=int(d["created_at"]),
                expires_at=int(d["expires_at"]),
                payload_b64=str(d["payload_b64"]),
                sig_b64=str(d["sig_b64"]),
                prev_receipt_id=(str(d["prev_receipt_id"]) if d.get("prev_receipt_id") not in (None, "") else None),
            )
        except Exception as e:
            raise _payload_invalid(f"invalid receipt dict: {e}") from e

    def payload_bytes(self) -> bytes:
        return _b64d(self.payload_b64)

    def signature_bytes(self) -> bytes:
        return _b64d(self.sig_b64)

    def signing_bytes(self) -> bytes:
        return _canonical_receipt_signing_bytes(
            v=self.v,
            key_id=self.key_id,
            created_at=self.created_at,
            expires_at=self.expires_at,
            payload_b64=self.payload_b64,
            prev_receipt_id=self.prev_receipt_id,
        )


# ----------------------------
# Public API
# ----------------------------

def mint_receipt(
    payload_bytes: bytes,
    *,
    signing_key_id: str,
    ed25519_private_pem: str,
    now_epoch: Optional[int] = None,
    expires_in_seconds: int = 10_000,
    prev_receipt_id: Optional[str] = None,
) -> ContinuityReceipt:
    """
    Create a v1 continuity receipt over payload_bytes, signed with Ed25519 private key.
    """
    if not isinstance(payload_bytes, (bytes, bytearray)) or len(payload_bytes) == 0:
        raise _payload_invalid("payload_bytes missing/empty")
    if not signing_key_id:
        raise _payload_invalid("signing_key_id missing")
    now = int(now_epoch if now_epoch is not None else _now_epoch())
    created_at = now
    expires_at = now + int(expires_in_seconds)

    payload_b64 = _b64e(bytes(payload_bytes))
    priv = _load_ed25519_private_pem(ed25519_private_pem)

    msg = _canonical_receipt_signing_bytes(
        v=1,
        key_id=signing_key_id,
        created_at=created_at,
        expires_at=expires_at,
        payload_b64=payload_b64,
        prev_receipt_id=prev_receipt_id,
    )
    sig = priv.sign(msg)
    sig_b64 = _b64e(sig)

    receipt_id = _sha256_hex(msg + sig)
    return ContinuityReceipt(
        v=1,
        receipt_id=receipt_id,
        key_id=signing_key_id,
        created_at=created_at,
        expires_at=expires_at,
        payload_b64=payload_b64,
        sig_b64=sig_b64,
        prev_receipt_id=prev_receipt_id,
    )


def verify_receipt_payload_bytes(
    payload_bytes: bytes,
    *,
    keyring: Any,
    now_epoch: int,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify a *single receipt* given as JSON bytes (or dict->bytes upstream).
    Returns (ok, notes).
    Raises VerificationError on failure.
    """
    receipt = _parse_receipt_payload_bytes(payload_bytes)
    _verify_single_receipt(receipt, keyring=keyring, now_epoch=now_epoch)
    return True, {"receipt_id": receipt.receipt_id, "key_id": receipt.key_id}


def verify_chain_and_sequence(
    receipts: Sequence[Union[ContinuityReceipt, Dict[str, Any], bytes, str]],
    *,
    keyring: Any,
    now_epoch: int,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify a receipt chain and its ordering. Accepts a sequence of:
      - ContinuityReceipt objects
      - dict receipts
      - JSON bytes
      - JSON strings
    """
    parsed = [_coerce_receipt(r) for r in receipts]
    if len(parsed) == 0:
        raise _payload_invalid("empty receipt chain")

    # Verify each receipt, then verify linkage (prev_receipt_id)
    for r in parsed:
        _verify_single_receipt(r, keyring=keyring, now_epoch=now_epoch)

    # enforce chain linkage when prev_receipt_id fields are present
    for i in range(1, len(parsed)):
        prev = parsed[i - 1]
        cur = parsed[i]
        if cur.prev_receipt_id is None:
            # if any link is missing, we don't fail hard; but we do note it
            continue
        if cur.prev_receipt_id != prev.receipt_id:
            raise _payload_invalid("receipt chain linkage mismatch")

    return True, {"count": len(parsed), "head": parsed[0].receipt_id, "tail": parsed[-1].receipt_id}


def verify_receipt_chain(
    receipts: Sequence[Union[ContinuityReceipt, Dict[str, Any], bytes, str]],
    *,
    keyring: Any,
    now_epoch: int,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Compatibility alias used by some tests/adapters.
    """
    return verify_chain_and_sequence(receipts, keyring=keyring, now_epoch=now_epoch)


# ----------------------------
# Internals
# ----------------------------

def _parse_receipt_payload_bytes(payload_bytes: bytes) -> ContinuityReceipt:
    if not isinstance(payload_bytes, (bytes, bytearray)) or len(payload_bytes) == 0:
        raise _payload_invalid("receipt payload bytes missing/empty")

    try:
        txt = bytes(payload_bytes).decode("utf-8")
        d = json.loads(txt)
        if not isinstance(d, dict):
            raise ValueError("receipt json is not an object")
        return ContinuityReceipt.from_dict(d)
    except VerificationError:
        raise
    except Exception as e:
        raise _payload_invalid(f"invalid receipt json: {e}") from e


def _coerce_receipt(x: Union[ContinuityReceipt, Dict[str, Any], bytes, str]) -> ContinuityReceipt:
    if isinstance(x, ContinuityReceipt):
        return x
    if isinstance(x, dict):
        return ContinuityReceipt.from_dict(x)
    if isinstance(x, (bytes, bytearray)):
        return _parse_receipt_payload_bytes(bytes(x))
    if isinstance(x, str):
        # accept json text
        try:
            d = json.loads(x)
            if isinstance(d, dict):
                return ContinuityReceipt.from_dict(d)
        except Exception as e:
            raise _payload_invalid(f"invalid receipt string: {e}") from e
    raise _payload_invalid("unsupported receipt type")


def _verify_single_receipt(r: ContinuityReceipt, *, keyring: Any, now_epoch: int) -> None:
    # version
    if r.v != 1:
        raise _payload_invalid("unsupported receipt version")

    # time validity
    if r.expires_at < int(now_epoch):
        raise _key_invalid("signing key/receipt expired (by receipt expires_at)")

    # key lookup
    rec = _keyring_get_record(keyring, r.key_id)
    if not rec:
        raise _key_invalid("signing key missing in keyring")

    if _record_is_revoked(rec):
        raise _key_invalid("signing key revoked")

    exp = _record_expires_at(rec)
    if exp is not None and exp < int(now_epoch):
        raise _key_invalid("signing key expired")

    pub_pem = _extract_public_pem(rec)
    if not pub_pem:
        raise _key_invalid("signing key record missing public pem")

    pub = _load_ed25519_public_pem(pub_pem)

    # signature verify
    msg = r.signing_bytes()
    sig = r.signature_bytes()
    try:
        pub.verify(sig, msg)
    except Exception as e:
        raise _payload_invalid(f"bad signature: {e}") from e

    # receipt_id sanity (must match canonical)
    expected_id = _sha256_hex(msg + sig)
    if r.receipt_id != expected_id:
        raise _payload_invalid("receipt_id mismatch")
