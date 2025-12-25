from .keyring import KeyringStore


def _keyring_add_public_pem(
    kr: KeyringStore,
    key_id: str,
    public_pem: str,
) -> None:
    """
    Deterministic helper.

    This function intentionally does NOT guess.
    It only calls supported APIs.
    """

    if hasattr(kr, "add_public_key_pem"):
        kr.add_public_key_pem(key_id, public_pem)
        return

    if hasattr(kr, "upsert_key"):
        kr.upsert_key(
            key_id=key_id,
            public_key_pem=public_pem,
            revoked=False,
        )
        return

    raise TypeError(
        "KeyringStore does not support required public key insertion API"
    )
