from .continuity_receipts import (
    VerificationError,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_chain_and_sequence,
)

from .verify_entrypoint import (
    verify_receipt_payload_bytes,
    VerifiedReceipt,
)

from .entity_identity import (
    root_key_id_from_public_pem,
    entity_id_from_public_pem,
    entity_id_from_root_key_id,
)

from .keyring import KeyringStore

# IMPORTANT: export the StegTV adapter expected by tests
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
