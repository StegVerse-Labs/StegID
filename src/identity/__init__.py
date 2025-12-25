"""
StegID Identity Public API (v1 – frozen)

This module defines the stable import surface.
Implementations may move internally, but symbols here must not break.
"""

# Core errors
from .continuity_receipts import (
    VerificationError,
)

# Core receipt API
from .continuity_receipts import (
    fingerprint_public_key_pem,
    mint_receipt,
    verify_chain_and_sequence,
)

# Verification entrypoint
from .verify_entrypoint import (
    verify_receipt_payload_bytes,
    VerifiedReceipt,
)

# Keyring
from .keyring import KeyringStore

# Adapters
from .stegtv_adapter import StegTVContinuityAdapter

__all__ = [
    # Errors
    "VerificationError",

    # Receipt core
    "fingerprint_public_key_pem",
    "mint_receipt",
    "verify_chain_and_sequence",

    # Verification
    "verify_receipt_payload_bytes",
    "VerifiedReceipt",

    # Keyring
    "KeyringStore",

    # Adapters
    "StegTVContinuityAdapter",
]
