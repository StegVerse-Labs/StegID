# src/identity/continuity_receipts.py
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    # cryptography is already being used in your tests (Ed25519PrivateKey.generate etc.)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "cryptography is required for StegID continuity receipt verification"
    ) from e


# -----------------------------
# Errors
# -----------------------------
class VerificationError(Exception):
    """
    Raised when a receipt fails validation.
    Tests expect .code (string) and often compare exact values.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message}


# -----------------------------
# Helpers
# -----------------------------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _normalize_pem(pem: Union[str, bytes]) -> bytes:
    if isinstance(pem, str):
        pem_b = pem.encode("utf-8")
    else:
        pem_b = pem
    # normalize line endings + strip surrounding whitespace
    pem_b = pem_b.replace(b"\r\n", b"\n").strip() + b"\n"
    return pem_b


def fingerprint_public_key_pem(public_pem: Union[str, bytes]) -> str:
    """
    Deterministic key identifier from a PUBLIC key PEM.
    This is intentionally simple: sha256 hex of normalized PEM bytes.
    """
    h = hashlib.sha256(_normalize_pem(public_pem)).hexdigest()
    return h


def _load_public_key_from_pem(public_pem: Union[str, bytes]) -> Ed25519PublicKey:
    pem_b = _normalize_pem(public_pem)
    pub = serialization.load_pem_public_key(pem_b)
    if not isinstance(pub, Ed25519PublicKey):
        raise VerificationError("key_invalid", "public key is not Ed25519")
    return pub


def _load_private_key_from_pem(private_pem: Union[str, bytes]) -> Ed25519PrivateKey:
    pem_b = _normalize_pem(private_pem)
    priv = serialization.load_pem_private_key(pem_b, password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise VerificationError("key_invalid", "private key is not Ed25519")
    return priv


def _stable_payload_bytes(payload: Any) -> bytes:
    """
    Receipts sign canonical JSON bytes.
    If caller already has bytes, keep them.
    """
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# -----------------------------
# Models
# -----------------------------
@dataclass(frozen=True)
class ContinuityReceipt:
    """
    Canonical receipt object.
    Keep field names stable and JSON-friendly.
    """
    receipt_id: str
    key_id: str
    payload_b64: str
    signature_b64: str
    created_at: int
    expires_at: int
    prev_receipt_id: Optional[str] = None
    chain_hash: Optional[str] = None
    version: str = "v1"

    def payload_bytes(self) -> bytes:
        return _b64d(self.payload_b64)

    def signature_bytes(self) -> bytes:
        return _b64d(self.signature_b64)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "version": self.version,
            "receipt_id": self.receipt_id,
            "key_id": self.key_id,
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }
        if self.prev_receipt_id is not None:
            d["prev_receipt_id"] = self.prev_receipt_id
        if self.chain_hash is not None:
            d["chain_hash"] = self.chain_hash
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ContinuityReceipt":
        return ContinuityReceipt(
            version=str(d.get("version", "v1")),
            receipt_id=str(d["receipt_id"]),
            key_id=str(d["key_id"]),
            payload_b64=str(d["payload_b64"]),
            signature_b64=str(d["signature_b64"]),
            created_at=int(d["created_at"]),
            expires_at=int(d["expires_at"]),
            prev_receipt_id=d.get("prev_receipt_id"),
            chain_hash=d.get("chain_hash"),
        )


# -----------------------------
# Keyring (compat / storage)
# -----------------------------
class KeyringStore:
    """
    Minimal in-memory keyring with a *compatibility surface*.

    Your tests + adapters have bounced between:
      - add_public_key_pem(key_id, public_pem)
      - upsert_key(key_id=..., public_key_pem=..., revoked=False)
      - upsert_key(key_id, record_dict)
      - etc

    This implementation supports the common patterns WITHOUT breaking
    if callers pass different shapes.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        # redis_url accepted for signature compatibility; not used here
        self._keys: Dict[str, Dict[str, Any]] = {}

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        return self._keys.get(key_id)

    # Canonical writer
    def put_key_record(self, key_id: str, record: Dict[str, Any]) -> None:
        rec = dict(record)
        rec.setdefault("key_id", key_id)
        rec.setdefault("revoked", False)
        self._keys[key_id] = rec

    # Common APIs (aliases)
    def add_public_key_pem(self, key_id: str, public_pem: str) -> None:
        self.put_key_record(key_id, {"public_key_pem": public_pem, "revoked": False})

    def add_public_key(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    def set_public_key_pem(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    def store_public_key_pem(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    def store_public_key(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    def put_public_key_pem(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    def put_public_key(self, key_id: str, public_pem: str) -> None:
        self.add_public_key_pem(key_id, public_pem)

    # The messy one: upsert_key can be called in multiple incompatible ways.
    def upsert_key(self, *args: Any, **kwargs: Any) -> None:
        """
        Supported call patterns:
          upsert_key(key_id, record_dict)
          upsert_key(key_id=..., public_key_pem=..., revoked=False, created_at=..., expires_at=...)
          upsert_key(key_id=..., public_pem=..., revoked=False)
        """
        if args and len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], dict):
            key_id = args[0]
            record = args[1]
            self.put_key_record(key_id, record)
            return

        key_id = kwargs.get("key_id")
        if not key_id and args and isinstance(args[0], str):
            key_id = args[0]
        if not isinstance(key_id, str) or not key_id:
            raise TypeError("upsert_key requires key_id")

        public_pem = (
            kwargs.get("public_key_pem")
            or kwargs.get("public_pem")
            or kwargs.get("public_pem_str")
            or kwargs.get("publicKeyPem")
        )

        record: Dict[str, Any] = {}
        if public_pem is not None:
            record["public_key_pem"] = public_pem
        # allow extra metadata
        for k in ("created_at", "expires_at", "revoked"):
            if k in kwargs:
                record[k] = kwargs[k]

        # If nothing provided besides key_id, keep existing record (noop)
        if not record:
            if key_id not in self._keys:
                self.put_key_record(key_id, {"revoked": False})
            return

        self.put_key_record(key_id, record)

    def is_revoked(self, key_id: str) -> bool:
        rec = self.get_key(key_id)
        if not rec:
            return True
        return bool(rec.get("revoked", False))

    def get_public_key_pem(self, key_id: str) -> Optional[str]:
        rec = self.get_key(key_id)
        if not rec:
            return None
        return rec.get("public_key_pem") or rec.get("public_pem")  # tolerate old names


# -----------------------------
# Minting + verification
# -----------------------------
def mint_receipt(
    payload: Union[bytes, bytearray, Dict[str, Any], List[Any], str],
    *,
    signing_private_pem: Union[str, bytes],
    key_id: str,
    now_epoch: Optional[int] = None,
    expires_in_seconds: int = 10_000,
    prev_receipt_id: Optional[str] = None,
) -> ContinuityReceipt:
    """
    Create and sign a receipt for a payload.
    - Payload is canonicalized to bytes.
    - Receipt ID is deterministic from (key_id + payload_hash + created_at + prev_receipt_id).
    """
    now = int(now_epoch if now_epoch is not None else time.time())

    payload_bytes = _stable_payload_bytes(payload)
    payload_b64 = _b64e(payload_bytes)

    priv = _load_private_key_from_pem(signing_private_pem)

    # Sign payload hash + linking info to make tampering obvious
    payload_hash = _hash_bytes(payload_bytes).encode("utf-8")
    link = (prev_receipt_id or "").encode("utf-8")
    signing_material = b"|".join([key_id.encode("utf-8"), payload_hash, str(now).encode("utf-8"), link])
    sig = priv.sign(signing_material)
    sig_b64 = _b64e(sig)

    receipt_id = hashlib.sha256(signing_material + sig).hexdigest()
    chain_hash = hashlib.sha256((receipt_id + (prev_receipt_id or "")).encode("utf-8")).hexdigest()

    return ContinuityReceipt(
        receipt_id=receipt_id,
        key_id=key_id,
        payload_b64=payload_b64,
        signature_b64=sig_b64,
        created_at=now,
        expires_at=now + int(expires_in_seconds),
        prev_receipt_id=prev_receipt_id,
        chain_hash=chain_hash,
        version="v1",
    )


def verify_receipt_payload_bytes(
    payload_bytes: Union[bytes, bytearray],
    receipt: Union[ContinuityReceipt, Dict[str, Any]],
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify a receipt against payload bytes + keyring.
    Returns: (ok, notes_dict)
    Raises: VerificationError with specific .code on failure
    """
    now = int(now_epoch if now_epoch is not None else time.time())

    r = receipt if isinstance(receipt, ContinuityReceipt) else ContinuityReceipt.from_dict(receipt)

    if now > int(r.expires_at):
        raise VerificationError("expired", "receipt expired")

    if keyring.is_revoked(r.key_id):
        raise VerificationError("key_invalid", "key revoked or missing")

    public_pem = keyring.get_public_key_pem(r.key_id)
    if not public_pem:
        raise VerificationError("key_invalid", "public key not found")

    # Payload must match
    pb = bytes(payload_bytes)
    if _b64e(pb) != r.payload_b64:
        raise VerificationError("payload_invalid", "payload does not match receipt")

    pub = _load_public_key_from_pem(public_pem)

    payload_hash = _hash_bytes(pb).encode("utf-8")
    link = (r.prev_receipt_id or "").encode("utf-8")
    signing_material = b"|".join([r.key_id.encode("utf-8"), payload_hash, str(r.created_at).encode("utf-8"), link])

    try:
        pub.verify(r.signature_bytes(), signing_material)
    except Exception:
        raise VerificationError("signature_invalid", "signature verification failed")

    notes = {
        "receipt_id": r.receipt_id,
        "key_id": r.key_id,
        "created_at": r.created_at,
        "expires_at": r.expires_at,
        "chain_hash": r.chain_hash,
    }
    return True, notes


def verify_receipt_chain(
    receipts: Sequence[Union[ContinuityReceipt, Dict[str, Any]]],
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify an ordered chain of receipts:
      - each receipt verifies cryptographically
      - each receipt.prev_receipt_id matches previous receipt_id (when present)
    """
    now = int(now_epoch if now_epoch is not None else time.time())

    chain: List[ContinuityReceipt] = [
        r if isinstance(r, ContinuityReceipt) else ContinuityReceipt.from_dict(r) for r in receipts
    ]

    if not chain:
        raise VerificationError("chain_invalid", "empty chain")

    # verify each receipt signature+payload linkage
    for i, r in enumerate(chain):
        ok, _ = verify_receipt_payload_bytes(r.payload_bytes(), r, keyring=keyring, now_epoch=now)
        if not ok:
            raise VerificationError("chain_invalid", "receipt failed verification")
        if i > 0:
            prev = chain[i - 1]
            if r.prev_receipt_id is not None and r.prev_receipt_id != prev.receipt_id:
                raise VerificationError("chain_invalid", "prev_receipt_id mismatch")

    notes = {"count": len(chain), "head": chain[0].receipt_id, "tail": chain[-1].receipt_id}
    return True, notes


def verify_chain_and_sequence(
    receipts: Sequence[Union[ContinuityReceipt, Dict[str, Any]]],
    *,
    keyring: KeyringStore,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Alias used by some tests/adapters. Same as verify_receipt_chain.
    """
    return verify_receipt_chain(receipts, keyring=keyring, now_epoch=now_epoch)


# Convenience export for adapters/tests that want "v1" wording
ContinuityReceiptV1 = ContinuityReceipt
