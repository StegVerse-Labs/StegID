# StegID v0 — VerifiedReceipt mint + verify (docs-first minimal)

This bundle adds a minimal **receipt minting + verification** layer for StegVerse.

- **StegID mints receipts** (signed continuity evidence).
- **StegCore consumes receipts** (as VerifiedReceipt input) but does not mint/verify.
- **StegAgents / StegBrain** receive a receipt via env var `STEGID_VERIFIED_RECEIPT_JSON`.

## What you get
- `tools/keygen_ed25519.py` — generate an Ed25519 keypair (private for GitHub Secrets, public for repo)
- `src/stegid/receipts.py` — mint + verify receipts
- `tools/mint_receipt.py` — CLI mint (prints JSON)
- `tools/verify_receipt.py` — CLI verify
- `public_keys/keys.json` — kid->public key mapping (replace placeholder)

## Receipt JSON format (v0)
```json
{
  "receipt_id": "uuid",
  "actor_class": "ai",
  "scopes": ["ai:run","ops:gate"],
  "issued_at": "2025-12-28T00:00:00Z",
  "expires_at": "2025-12-28T00:15:00Z",
  "assurance_level": 2,
  "signals": [],
  "issuer": "stegid",
  "kid": "stegid-ed25519-001",
  "payload_hash": "sha256:...",
  "sig": "base64url..."
}
```

## GitHub Actions integration (v0)
1) Store private key in repo secrets as `STEGID_ED25519_PRIVATE_B64`
2) Add a step that runs `python tools/mint_receipt.py ...` and writes
   `STEGID_VERIFIED_RECEIPT_JSON` into `$GITHUB_ENV`

Then your existing StegCore guards in StegAgents/StegBrain work immediately.
