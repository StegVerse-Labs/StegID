from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .middleware import IPAllowlistMiddleware, SimpleRateLimitMiddleware, AdminIPAllowlistMiddleware
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Import the canonical receipt minting + key fingerprint helper from the identity repo.
from src.identity.continuity_receipts import mint_receipt, verify_chain_and_sequence
from src.identity.keyring import fingerprint_public_key_pem

from .models import MintReceiptRequest, AddKeyRequest, KeyringKeyOut, RotateSigningKeyRequest
from .storage import ReceiptStore, KeyringStore
from .settings import SettingsStore
from .audit import AuditStore
from .security import require_admin

app = FastAPI(title="StegTV Identity API (Example)", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


IP_ALLOWLIST_ENABLED = (os.getenv("STEGTV_IP_ALLOWLIST_ENABLED") or "").lower() in ("1","true","yes","on")
RATE_LIMIT_ENABLED = (os.getenv("STEGTV_RATE_LIMIT_ENABLED") or "").lower() in ("1","true","yes","on")

# Comma-separated IPs
_allow = set([x.strip() for x in (os.getenv("STEGTV_IP_ALLOWLIST") or "").split(",") if x.strip()])
RATE_LIMIT_WINDOW = int(os.getenv("STEGTV_RATE_LIMIT_WINDOW_SECONDS") or "60")
RATE_LIMIT_MAX = int(os.getenv("STEGTV_RATE_LIMIT_MAX_REQUESTS") or "120")

app.add_middleware(AdminIPAllowlistMiddleware, allowlist=_allow, enabled=IP_ALLOWLIST_ENABLED, admin_path_prefixes={"/v1/identity/"})
app.add_middleware(SimpleRateLimitMiddleware, window_seconds=RATE_LIMIT_WINDOW, max_requests=RATE_LIMIT_MAX, enabled=RATE_LIMIT_ENABLED)
REDIS_URL = os.getenv("REDIS_URL")
receipts = ReceiptStore(redis_url=REDIS_URL)
keyring = KeyringStore(redis_url=REDIS_URL)
settings = SettingsStore(redis_url=REDIS_URL)
audit = AuditStore(redis_url=REDIS_URL)

def _load_signing_key() -> tuple[bytes, bytes]:
    pem = os.getenv("STEGTV_RECEIPT_SIGNING_KEY_PEM")
    if not pem:
        raise HTTPException(status_code=500, detail="STEGTV_RECEIPT_SIGNING_KEY_PEM not configured")
    priv = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise HTTPException(status_code=500, detail="Signing key must be Ed25519 private key PEM")
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.encode("utf-8"), pub_pem

def _active_signing_key_id(pub_pem: bytes) -> str:
    # Allow override, otherwise fingerprint public key
    return os.getenv("STEGTV_ACTIVE_SIGNING_KEY_ID") or fingerprint_public_key_pem(pub_pem)

@app.get("/v1/identity/keyring", response_model=list[KeyringKeyOut])
def get_keyring() -> list[KeyringKeyOut]:
    ks = keyring.list_keys()
    return [KeyringKeyOut(**k) for k in ks]



@app.get("/v1/identity/health")
def health() -> dict:
    # best-effort status: redis mode and keyring/receipt counts
    try:
        sample_keys = keyring.list_keys()
        keys_count = len(sample_keys)
    except Exception:
        keys_count = -1
    try:
        # No global receipt count in this minimal store; just report "ok"
        receipts_mode = "redis" if getattr(receipts, "_r", None) is not None else "memory"
        keyring_mode = "redis" if getattr(keyring, "_r", None) is not None else "memory"
        settings_mode = "redis" if getattr(settings, "_r", None) is not None else "memory"
    except Exception:
        receipts_mode = keyring_mode = settings_mode = "unknown"

    return {
        "ok": True,
        "modes": {
            "receipts": receipts_mode,
            "keyring": keyring_mode,
            "settings": settings_mode,
        },
        "keyring_keys_count": keys_count,
        "active_signing_key_id": settings.get_active_signing_key_id() or os.getenv("STEGTV_ACTIVE_SIGNING_KEY_ID") or None,
        "ip_allowlist_enabled": IP_ALLOWLIST_ENABLED,
        "rate_limit_enabled": RATE_LIMIT_ENABLED,
    }

@app.post("/v1/identity/keyring/keys", dependencies=[Depends(require_admin)], response_model=KeyringKeyOut)
def add_key(req: AddKeyRequest) -> KeyringKeyOut:
    pub_pem = req.public_pem.encode("utf-8")
    key_id = fingerprint_public_key_pem(pub_pem)
    data = {
        "key_id": key_id,
        "public_pem": req.public_pem,
        "not_before_epoch": int(req.not_before_epoch),
        "not_after_epoch": int(req.not_after_epoch) if req.not_after_epoch is not None else None,
        "revoked": False,
    }
    keyring.upsert_key(key_id, data)
    audit.append({"action":"add_key","key_id":key_id})
    return KeyringKeyOut(**data)



@app.get("/v1/identity/admin-receipts", dependencies=[Depends(require_admin)])
def list_admin_receipts() -> dict:
    rs = receipts.list_receipts(ADMIN_AUDIT_ACCOUNT_ID)
    return {"account_id": ADMIN_AUDIT_ACCOUNT_ID, "count": len(rs), "receipts": rs}

@app.get("/v1/identity/audit", dependencies=[Depends(require_admin)])
def get_audit(limit: int = 200) -> dict:
    events = audit.list(limit=limit)
    return {"count": len(events), "events": events}


@app.post("/v1/identity/keyring/revoke/{key_id}", dependencies=[Depends(require_admin)])
def revoke_key(key_id: str) -> dict:
    k = keyring.get_key(key_id)
    if not k:
        raise HTTPException(status_code=404, detail="Key not found")
    k["revoked"] = True
    keyring.upsert_key(key_id, k)
    audit.append({"action":"revoke_key","key_id":key_id})
    return {"ok": True, "key_id": key_id, "revoked": True}

@app.post("/v1/identity/keyring/rotate", dependencies=[Depends(require_admin)], response_model=KeyringKeyOut)
def rotate_signing_key(req: RotateSigningKeyRequest) -> KeyringKeyOut:
    """Registers a NEW verifying key in the keyring and sets it active.

    This endpoint does NOT change the server's signing private key by itself.
    You must also update `STEGTV_RECEIPT_SIGNING_KEY_PEM` to match the new keypair.
    Recommended procedure:
      1) Deploy with new STEGTV_RECEIPT_SIGNING_KEY_PEM (private) in place but keep old key active.
      2) Call this endpoint with new_public_pem and not_before_epoch ~ now.
      3) Optionally expire the previous active key (sets not_after_epoch).
    """
    now = int(time.time())
    new_pub_pem = req.new_public_pem.encode("utf-8")
    new_key_id = fingerprint_public_key_pem(new_pub_pem)

    # Upsert new key
    data = {
        "key_id": new_key_id,
        "public_pem": req.new_public_pem,
        "not_before_epoch": int(req.not_before_epoch),
        "not_after_epoch": None,
        "revoked": False,
    }
    keyring.upsert_key(new_key_id, data)

    # Expire previous active key if requested and exists
    prev_active = settings.get_active_signing_key_id() or os.getenv("STEGTV_ACTIVE_SIGNING_KEY_ID")
    if req.expire_previous and prev_active and prev_active != new_key_id:
        k = keyring.get_key(prev_active)
        if k and not k.get("revoked", False):
            # set not_after to now (or preserve earlier expiry)
            prev_not_after = k.get("not_after_epoch")
            k["not_after_epoch"] = min(int(prev_not_after), now) if prev_not_after is not None else now
            keyring.upsert_key(prev_active, k)

    # Persist new active
    settings.set_active_signing_key_id(new_key_id)
    audit.append({"action":"rotate_key","new_key_id":new_key_id,"prev_active": prev_active})

    return KeyringKeyOut(**data)


@app.get("/v1/identity/receipts/{account_id}")
def list_receipts(account_id: str) -> dict:
    rs = receipts.list_receipts(account_id)
    return {"account_id": account_id, "count": len(rs), "receipts": rs}

@app.post("/v1/identity/receipts/{account_id}", dependencies=[Depends(require_admin)])
def mint_and_append_receipt(account_id: str, req: MintReceiptRequest) -> dict:
    priv_pem, pub_pem = _load_signing_key()
    key_id = _active_signing_key_id(pub_pem)

    # Safety: ensure active key_id is consistent with the *actual* signing key unless an operator explicitly overrides via env/settings.
    derived = fingerprint_public_key_pem(pub_pem)
    if key_id != derived and not os.getenv("STEGTV_ACTIVE_SIGNING_KEY_ID"):
        # If operator persisted a different active key_id but did not override via env,
        # that's likely a misconfiguration (signing private key doesn't match active verifying key).
        raise HTTPException(status_code=500, detail={"error": "signing_key_mismatch", "active_key_id": key_id, "derived_from_private": derived})

    # Ensure key exists in keyring (best-effort auto-register)
    if not keyring.get_key(key_id):
        keyring.upsert_key(key_id, {
            "key_id": key_id,
            "public_pem": pub_pem.decode("utf-8"),
            "not_before_epoch": int(time.time()) - 60,
            "not_after_epoch": None,
            "revoked": False,
        })

    prev = receipts.get_last_receipt(account_id)
    next_seq = int(prev["sequence"]) + 1 if prev else 0
    issued_at = int(time.time())

    r = mint_receipt(
        account_id=account_id,
        sequence=next_seq,
        issued_at=issued_at,
        event_type=req.event_type,
        event_metadata=req.event_metadata,
        payload=req.payload,
        prev_receipt=prev,
        receipt_id=str(uuid.uuid4()),
        signing_key_id=key_id,
        ed25519_private_pem=priv_pem,
    )

    # Strict verify before storing (safety)
    chain_ok, chain_notes = verify_chain_and_sequence(tuple((receipts.list_receipts(account_id) + [r])))
    if not chain_ok:
        raise HTTPException(status_code=400, detail={"error": "chain_or_sequence_invalid", "notes": chain_notes})

    receipts.append_receipt(account_id, r)
    audit.append({"action":"mint_receipt","account_id":account_id,"event_type": req.event_type,"sequence": r.get("sequence")})
    return {"ok": True, "account_id": account_id, "receipt": r}


ADMIN_AUDIT_ACCOUNT_ID = os.getenv("STEGTV_ADMIN_AUDIT_ACCOUNT_ID") or "__stegtv_admin_audit__"

def _mint_admin_audit_receipt(action: str, metadata: dict) -> None:
    """Mint a continuity receipt representing an admin action.

    We reuse the existing receipt event types to avoid schema expansion in Phase 1.
    Admin actions are encoded as:
      event_type = "recovery_drill"
      event_metadata = {"action": <action>, ...metadata...}

    Stored under a dedicated account_id (ADMIN_AUDIT_ACCOUNT_ID) so sequencing is strict.
    """
    try:
        priv_pem, pub_pem = _load_signing_key()
        key_id = _active_signing_key_id(pub_pem)

        prev = receipts.get_last_receipt(ADMIN_AUDIT_ACCOUNT_ID)
        next_seq = int(prev["sequence"]) + 1 if prev else 0

        r = mint_receipt(
            account_id=ADMIN_AUDIT_ACCOUNT_ID,
            sequence=next_seq,
            issued_at=int(time.time()),
            event_type="recovery_drill",
            event_metadata={"action": action, **(metadata or {})},
            payload={},  # keep payload empty; everything goes in metadata
            prev_receipt=prev,
            receipt_id=str(uuid.uuid4()),
            signing_key_id=key_id,
            ed25519_private_pem=priv_pem,
        )

        # strict verify against full chain before append
        chain_ok, chain_notes = verify_chain_and_sequence(tuple((receipts.list_receipts(ADMIN_AUDIT_ACCOUNT_ID) + [r])))
        if not chain_ok:
            # don't crash service; just record an audit note
            audit.append({"action":"admin_audit_receipt_failed", "reason":"chain_or_sequence_invalid", "notes": list(chain_notes)})
            return

        receipts.append_receipt(ADMIN_AUDIT_ACCOUNT_ID, r)
        audit.append({"action":"admin_audit_receipt_minted", "sequence": r.get("sequence")})
    except Exception as e:
        # Never crash on audit receipt issues
        audit.append({"action":"admin_audit_receipt_error", "error": str(e)})
