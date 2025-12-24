from __future__ import annotations

# Core receipt API
from .continuity_receipts import (
    VerificationError,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_chain_and_sequence,
)

# Verification entrypoint
from .verify_entrypoint import (
    VerifiedReceipt,
    verify_receipt_payload_bytes,
)

# AI Entity Identity (recommended public exports)
from .entity_identity import (
    entity_id_from_public_pem,
    entity_id_from_root_key_id,
    root_key_id_from_public_pem,
)

# Keyring (tests import this from identity)
from .keyring import KeyringStore

# Adapters
from .stegtv_adapter import StegTVContinuityAdapter

__all__ = [
    # Core receipt API
    "VerificationError",
    "fingerprint_public_key_pem",
    "mint_receipt",
    "verify_chain_and_sequence",
    # Verification entrypoint
    "verify_receipt_payload_bytes",
    "VerifiedReceipt",
    # Entity identity
    "root_key_id_from_public_pem",
    "entity_id_from_public_pem",
    "entity_id_from_root_key_id",
    # Keyring
    "KeyringStore",
    # Adapters
    "StegTVContinuityAdapter",
]
