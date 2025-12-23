from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class VerificationError(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fingerprint_public_key_pem(pem_str: str) -> str:
    """
    Stable key-id derivation for Ed25519 public keys.

    Returns a deterministic key id string. This MUST NOT throw ImportError.
    """
    pem_bytes = pem_str.encode("utf-8") if isinstance(pem_str, str) else pem_str
    pub = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(pub, Ed25519PublicKey):
        raise VerificationError("Only Ed25519 public keys are supported.")

    # Raw Ed25519 public key bytes (32 bytes)
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # Namespaced id; short-but-strong (32 hex chars = 128 bits)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]


def mint_receipt(
    payload_bytes: bytes,
    *,
    private_key_pem: str,
    public_key_pem: str,
    ts: int,
    seq: int,
    prev: Optional[str],
) -> Dict[str, Any]:
    """
    Create a continuity receipt for a payload.
    """
    payload_sha = _sha256_hex(payload_bytes)
    key_id = fingerprint_public_key_pem(public_key_pem)

    body = {
        "v": 1,
        "ts": int(ts),
        "seq": int(seq),
        "prev": prev,
        "payload_sha256": payload_sha,
        "signer": {"kid": key_id, "pub_pem": public_key_pem},
    }

    # Canonical bytes for signing
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")

    priv = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise VerificationError("Only Ed25519 private keys are supported.")

    sig = priv.sign(body_bytes)
    receipt = dict(body)
    receipt["sig"] = _b64e(sig)

    # Receipt id is hash of the signed body+sig (stable)
    rid_material = body_bytes + b"." + sig
    receipt["rid"] = _sha256_hex(rid_material)

    return receipt


def verify_receipt(receipt: Dict[str, Any]) -> None:
    """
    Verify signature and internal consistency for a single receipt.
    """
    try:
        sig = _b64d(receipt["sig"])
        pub_pem = receipt["signer"]["pub_pem"]
        kid = receipt["signer"]["kid"]
        payload_sha = receipt["payload_sha256"]
    except Exception as e:
        raise VerificationError(f"Malformed receipt: {e}")

    # Check kid matches pub
    expected_kid = fingerprint_public_key_pem(pub_pem)
    if kid != expected_kid:
        raise VerificationError("Receipt signer kid does not match signer public key.")

    # Recreate body bytes (without sig, rid)
    body = {k: receipt[k] for k in receipt.keys() if k not in ("sig", "rid")}
    body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")

    pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise VerificationError("Only Ed25519 public keys are supported.")

    try:
        pub.verify(sig, body_bytes)
    except Exception:
        raise VerificationError("Invalid signature.")

    # Optional: sanity check payload hash shape
    if not (isinstance(payload_sha, str) and len(payload_sha) == 64):
        raise VerificationError("payload_sha256 must be a 64-char hex string.")


def verify_chain_and_sequence(receipts: List[Dict[str, Any]]) -> None:
    """
    Verify:
      - each receipt is valid
      - seq is strictly increasing by 1
      - prev points to prior rid
    """
    if not receipts:
        raise VerificationError("No receipts provided.")

    # Verify all individual receipts first
    for r in receipts:
        verify_receipt(r)

    # Verify chain + seq
    for i in range(1, len(receipts)):
        prev = receipts[i - 1]
        cur = receipts[i]

        if int(cur["seq"]) != int(prev["seq"]) + 1:
            raise VerificationError("Sequence is not strictly increasing by 1.")

        if cur.get("prev") != prev.get("rid"):
            raise VerificationError("Chain broken: prev does not match prior rid.")
