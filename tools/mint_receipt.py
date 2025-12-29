from __future__ import annotations

import argparse
import json
import os
from steg_id.receipts import mint_receipt

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--actor-class", default="ai", choices=["human","ai","system"])
    p.add_argument("--scopes", default="ai:run", help="Comma-separated scopes")
    p.add_argument("--ttl", type=int, default=900)
    p.add_argument("--assurance", type=int, default=2)
    p.add_argument("--signals", default="", help="Comma-separated signals")
    p.add_argument("--kid", default="stegid-ed25519-001")
    args = p.parse_args()

    priv = os.getenv("STEGID_ED25519_PRIVATE_B64", "").strip()
    if not priv:
        raise SystemExit("Missing env STEGID_ED25519_PRIVATE_B64")

    scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
    signals = [s.strip() for s in args.signals.split(",") if s.strip()]

    r = mint_receipt(
        priv_b64=priv,
        actor_class=args.actor_class,
        scopes=scopes,
        ttl_seconds=args.ttl,
        assurance_level=args.assurance,
        signals=signals,
        kid=args.kid,
    )
    print(json.dumps(r.to_dict(), indent=2, sort_keys=True))
