from __future__ import annotations

import json
import sys

from .keyring import KeyringStore
from .verify_entrypoint import verify_receipt_payload_bytes


def main() -> int:
    payload = sys.stdin.buffer.read()
    if not payload:
        print("Expected JSON on stdin.", file=sys.stderr)
        return 2

    kr = KeyringStore(redis_url=None)
    # Note: for real usage, you’ll load keys into kr before verifying.
    try:
        out = verify_receipt_payload_bytes(payload, keyring=kr, now_epoch=0)
        print(json.dumps({"ok": out.ok, "notes": out.notes, "receipt": out.receipt}, indent=2))
        return 0
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
