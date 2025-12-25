from typing import Optional, Dict


class KeyringStore:
    """
    Canonical keyring storage.

    This class intentionally exposes a minimal, strict API.
    Adapters MAY wrap it, but tests depend on deterministic behavior.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self._keys: Dict[str, Dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Canonical API (DO NOT CHANGE SIGNATURE WITHOUT VERSION BUMP)
    # ------------------------------------------------------------------

    def add_public_key_pem(self, key_id: str, public_key_pem: str) -> None:
        """
        Store a public key PEM by key_id.
        """
        self._keys[key_id] = {
            "public_key_pem": public_key_pem,
            "revoked": False,
        }

    def revoke_key(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(f"Unknown key_id: {key_id}")
        self._keys[key_id]["revoked"] = True

    def get_public_key_pem(self, key_id: str) -> Optional[str]:
        entry = self._keys.get(key_id)
        if not entry or entry.get("revoked"):
            return None
        return entry.get("public_key_pem")

    # ------------------------------------------------------------------
    # Backward-compat shim (STRICT)
    # ------------------------------------------------------------------

    def upsert_key(self, *, key_id: str, public_key_pem: str, revoked: bool = False) -> None:
        """
        Explicit compatibility shim.
        """
        self._keys[key_id] = {
            "public_key_pem": public_key_pem,
            "revoked": bool(revoked),
        }
