# StegTV Identity API (Example FastAPI Service)

This is a **drop-in example** of the StegTV/StegTVC Identity endpoints that mint and serve **Ed25519 continuity receipts**.

## Endpoints
- `GET /v1/identity/keyring` — public verification keys (read-only)
- `GET /v1/identity/receipts/{account_id}` — list receipts for an account
- `POST /v1/identity/receipts/{account_id}` — mint + append a receipt (admin only)
- `POST /v1/identity/keyring/keys` — add a public key to keyring (admin only)
- `POST /v1/identity/keyring/revoke/{key_id}` — revoke a key (admin only)

## Environment variables
- `STEGTV_ADMIN_TOKEN` (required for POST endpoints)
- `STEGTV_RECEIPT_SIGNING_KEY_PEM` (server Ed25519 private key PEM, required to mint receipts)
- `STEGTV_ACTIVE_SIGNING_KEY_ID` (optional; defaults to key_id derived from public key)
- `REDIS_URL` (optional; if unset uses memory fallback; never crashes)

## Run
```bash
cd examples/stegtv_fastapi
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

## Notes
- This service is intentionally **minimal** and uses a memory fallback if Redis is unavailable.
- Do not expose `POST` routes without additional protections (rate limiting, IP allowlists, etc.).


## Key rotation (recommended)
1) Generate a new Ed25519 keypair.
2) Deploy StegTV with `STEGTV_RECEIPT_SIGNING_KEY_PEM` set to the **new private key**.
3) Call `POST /v1/identity/keyring/rotate` with the **new public key**, `not_before_epoch=now`.
4) Keep old verifying key in keyring (optionally expired) so old receipts remain verifiable.


## Hardening knobs (starter)
### IP allowlist (recommended for admin routes)
- `STEGTV_IP_ALLOWLIST_ENABLED=true`
- `STEGTV_IP_ALLOWLIST=1.2.3.4,5.6.7.8`

> Note: IP allowlisting via `X-Forwarded-For` is only safe behind a trusted proxy that sets it correctly.

### Rate limiting (starter safety net)
- `STEGTV_RATE_LIMIT_ENABLED=true`
- `STEGTV_RATE_LIMIT_WINDOW_SECONDS=60`
- `STEGTV_RATE_LIMIT_MAX_REQUESTS=120`

### Health endpoint
- `GET /v1/identity/health` shows storage modes (redis vs memory), keyring count, and active key id.


## Admin audit log
- `GET /v1/identity/audit?limit=200` (admin only) returns recent admin actions:
  - add/revoke/rotate keys
  - mint receipts

## IP allowlist behavior
When enabled, the allowlist is applied to **admin routes** (write methods) so public read endpoints can remain reachable.


## Admin continuity receipts
StegTV can mint **continuity receipts for its own admin actions** (key changes, receipt minting).

- Stored under `STEGTV_ADMIN_AUDIT_ACCOUNT_ID` (default `__stegtv_admin_audit__`)
- `GET /v1/identity/admin-receipts` (admin only)

Encoding (Phase 1):
- `event_type = "recovery_drill"`
- `event_metadata.action = <admin action>`
