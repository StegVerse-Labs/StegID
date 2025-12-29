from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

ActorClass = Literal["human", "ai", "system"]

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def sha256_json(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    h = hashlib.sha256(raw).hexdigest()
    return f"sha256:{h}"

def load_private_key_from_b64(b64: str) -> Ed25519PrivateKey:
    key_bytes = _b64url_decode(b64)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)

def load_public_key_from_b64(b64: str) -> Ed25519PublicKey:
    key_bytes = _b64url_decode(b64)
    return Ed25519PublicKey.from_public_bytes(key_bytes)

def public_key_to_b64(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return _b64url_encode(raw)

def private_key_to_b64(priv: Ed25519PrivateKey) -> str:
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return _b64url_encode(raw)

def generate_keypair() -> Tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return private_key_to_b64(priv), public_key_to_b64(pub)

def _sign(priv: Ed25519PrivateKey, payload_hash: str) -> str:
    sig = priv.sign(payload_hash.encode("utf-8"))
    return _b64url_encode(sig)

def _verify(pub: Ed25519PublicKey, payload_hash: str, sig_b64url: str) -> bool:
    try:
        pub.verify(_b64url_decode(sig_b64url), payload_hash.encode("utf-8"))
        return True
    except Exception:
        return False

@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    actor_class: ActorClass
    scopes: List[str]
    issued_at: str
    expires_at: str
    assurance_level: int
    signals: List[str]
    issuer: str
    kid: str
    payload_hash: str
    sig: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "actor_class": self.actor_class,
            "scopes": self.scopes,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "assurance_level": self.assurance_level,
            "signals": self.signals,
            "issuer": self.issuer,
            "kid": self.kid,
            "payload_hash": self.payload_hash,
            "sig": self.sig,
        }

def mint_receipt(
    *,
    priv_b64: str,
    actor_class: ActorClass,
    scopes: List[str],
    ttl_seconds: int = 900,
    assurance_level: int = 2,
    signals: Optional[List[str]] = None,
    issuer: str = "stegid",
    kid: str = "stegid-ed25519-001",
) -> Receipt:
    issued = _now()
    expires = issued + timedelta(seconds=int(ttl_seconds))

    unsigned = {
        "receipt_id": str(uuid.uuid4()),
        "actor_class": actor_class,
        "scopes": scopes,
        "issued_at": _iso(issued),
        "expires_at": _iso(expires),
        "assurance_level": int(assurance_level),
        "signals": list(signals or []),
        "issuer": issuer,
        "kid": kid,
    }

    payload_hash = sha256_json(unsigned)
    priv = load_private_key_from_b64(priv_b64)
    sig = _sign(priv, payload_hash)

    return Receipt(
        receipt_id=unsigned["receipt_id"],
        actor_class=unsigned["actor_class"],
        scopes=unsigned["scopes"],
        issued_at=unsigned["issued_at"],
        expires_at=unsigned["expires_at"],
        assurance_level=unsigned["assurance_level"],
        signals=unsigned["signals"],
        issuer=unsigned["issuer"],
        kid=unsigned["kid"],
        payload_hash=payload_hash,
        sig=sig,
    )

def verify_receipt(
    receipt: Dict[str, Any],
    *,
    pubkeys_by_kid: Dict[str, str],
    now_iso: Optional[str] = None,
) -> Tuple[bool, str]:
    for k in ["receipt_id","actor_class","scopes","issued_at","expires_at","assurance_level","signals","issuer","kid","payload_hash","sig"]:
        if k not in receipt:
            return False, f"missing:{k}"

    kid = str(receipt["kid"])
    pub_b64 = pubkeys_by_kid.get(kid)
    if not pub_b64:
        return False, "unknown_kid"

    unsigned = {
        "receipt_id": receipt["receipt_id"],
        "actor_class": receipt["actor_class"],
        "scopes": receipt["scopes"],
        "issued_at": receipt["issued_at"],
        "expires_at": receipt["expires_at"],
        "assurance_level": int(receipt["assurance_level"]),
        "signals": receipt["signals"],
        "issuer": receipt["issuer"],
        "kid": receipt["kid"],
    }
    expected_hash = sha256_json(unsigned)
    if expected_hash != receipt["payload_hash"]:
        return False, "payload_hash_mismatch"

    pub = load_public_key_from_b64(pub_b64)
    if not _verify(pub, expected_hash, str(receipt["sig"])):
        return False, "bad_signature"

    now = _parse_iso(now_iso) if now_iso else _now()
    exp = _parse_iso(str(receipt["expires_at"]))
    iss = _parse_iso(str(receipt["issued_at"]))
    if now < iss - timedelta(minutes=1):
        return False, "not_yet_valid"
    if now >= exp:
        return False, "expired"

    return True, "ok"
