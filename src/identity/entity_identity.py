from __future__ import annotations

import hashlib
from typing import Literal

from cryptography.hazmat.primitives import serialization

EntityType = Literal["ai", "human", "svc"]

def root_key_id_from_public_pem(public_key_pem: str) -> str:
    """Return sha256(SPKI_DER(public_key)) -> hex."""
    pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()

def entity_id_from_root_key_id(root_key_id: str, entity_type: EntityType = "ai") -> str:
    """Return canonical entity_id: steg:<type>:<root_key_id>."""
    return f"steg:{entity_type}:{root_key_id}"

def entity_id_from_public_pem(public_key_pem: str, entity_type: EntityType = "ai") -> str:
    return entity_id_from_root_key_id(root_key_id_from_public_pem(public_key_pem), entity_type=entity_type)
