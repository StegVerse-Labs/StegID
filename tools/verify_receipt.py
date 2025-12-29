from __future__ import annotations

import argparse
import json
from pathlib import Path
from steg_id.receipts import verify_receipt

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--receipt", required=True, help="Path to receipt JSON")
    p.add_argument("--pubkeys", default="public_keys/keys.json", help="Path to kid->pub_b64 json")
    args = p.parse_args()

    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8"))
    pubkeys = json.loads(Path(args.pubkeys).read_text(encoding="utf-8"))

    ok, reason = verify_receipt(receipt, pubkeys_by_kid=pubkeys)
    print(json.dumps({"ok": ok, "reason": reason}, indent=2, sort_keys=True))
