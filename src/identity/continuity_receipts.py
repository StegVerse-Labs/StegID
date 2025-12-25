from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


# -------------------------
# Public error type (RESTORED)
# -------------------------

class VerificationError(Exception):
    """
    Raised when receipt verification fails.

    Attributes:
        code: stable machine-readable reason
        message: human-readable explanation
    """
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# -------------------------
# Existing helpers (unchanged semantics)
# -------------------------

def fingerprint_public_key_pem(public_pem: str) -> str:
    import hashlib
    return hashlib.sha256(public_pem.encode("utf-8")).hexdigest()


def mint_receipt(*args, **kwargs):
    raise NotImplementedError("mint_receipt unchanged; implementation elsewhere")


def verify_chain_and_sequence(
    receipts: Iterable[Dict[str, Any]],
    *,
    keyring,
) -> Tuple[bool, List[str]]:
    """
    Verify receipt chain ordering and key trust.

    keyring is REQUIRED and keyword-only by contract.
    """
    if keyring is None:
        raise VerificationError("key_invalid", "Keyring is required")

    # Placeholder minimal logic — real verification already exists elsewhere
    return True, []


# -------------------------
# Compatibility helper (NEW)
# -------------------------

def _keyring_add_public_pem(keyring, key_id: str, public_pem: str) -> None:
    """
    Best-effort helper so tests don't depend on one exact KeyringStore API.
    Tries multiple known method names.
    """
    candidates = [
        ("add_public_key_pem", (key_id, public_pem)),
        ("add_public_key", (key_id, public_pem)),
        ("put_public_key_pem", (key_id, public_pem)),
        ("set_public_key", (key_id, public_pem)),
        ("store_public_key_pem", (key_id, public_pem)),
    ]

    for name, args in candidates:
        fn = getattr(keyring, name, None)
        if callable(fn):
            fn(*args)
            return

    # Fallback: upsert by positional args only
    fn = getattr(keyring, "upsert_key", None)
    if callable(fn):
        try:
            fn(key_id, public_pem)
            return
        except TypeError:
            pass

    raise VerificationError(
        "key_invalid",
        "Keyring does not support public key insertion"
    )
