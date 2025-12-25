"""
StegID Identity Public API (v1 – frozen)

This module defines the stable import surface.
Implementations may move internally, but symbols here must not break.
"""

# Core errors + receipt primitives
from .continuity_receipts import (
    VerificationError,
    ContinuityReceipt,
    ContinuityReceiptV1,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_receipt_chain,
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

    # Receipt models
    "ContinuityReceipt",
    "ContinuityReceiptV1",

    # Receipt core
    "fingerprint_public_key_pem",
    "mint_receipt",
    "verify_receipt_chain",
    "verify_chain_and_sequence",

    # Verification
    "verify_receipt_payload_bytes",
    "VerifiedReceipt",

    # Keyring
    "KeyringStore",

    # Adapters
    "StegTVContinuityAdapter",
]
