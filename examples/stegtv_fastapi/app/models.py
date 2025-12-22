from __future__ import annotations

from typing import Any, Dict, Optional, Literal
from pydantic import BaseModel, Field

ReceiptEventType = Literal[
    "key_created",
    "key_rotated",
    "key_revoked",
    "owner_presence",
    "device_enrolled",
    "device_removed",
    "recovery_drill",
]

class MintReceiptRequest(BaseModel):
    event_type: ReceiptEventType
    event_metadata: Dict[str, Any] = Field(default_factory=dict)
    payload: Dict[str, Any] = Field(default_factory=dict)

class AddKeyRequest(BaseModel):
    public_pem: str = Field(..., description="Ed25519 public key in PEM format")
    not_before_epoch: int
    not_after_epoch: Optional[int] = None

class KeyringKeyOut(BaseModel):
    key_id: str
    public_pem: str
    not_before_epoch: int
    not_after_epoch: Optional[int] = None
    revoked: bool


class RotateSigningKeyRequest(BaseModel):
    """Register a NEW public key and set it active; optionally expire the previous active key."""
    new_public_pem: str = Field(..., description="New Ed25519 public key in PEM format")
    not_before_epoch: int = Field(..., description="When the new key becomes valid")
    expire_previous: bool = Field(True, description="If true, set not_after_epoch on previous active key to now")
