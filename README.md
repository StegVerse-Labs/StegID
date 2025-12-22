[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

## Continuity receipts (StegTV/StegTVC wiring)
- Schema: `specs/continuity-receipt.schema.json`
- Receipt helpers: `src/identity/continuity_receipts.py`
- Adapter: `src/identity/stegtv_adapter.py`

Flow:
1) StegTV/StegTVC mint append-only, signed receipts (hash-chained).
2) App fetches receipts from StegTV.
3) Adapter derives `crypto_continuity` and `time_depth` signals.
4) Feed those into the identity confidence engine.

Signature algorithm:
- Preferred: Ed25519 receipts (if `cryptography` is available)
- Fallback: HMAC-SHA256 for dev/testing only

### Strict mode (recommended)
Use `derive_signals_from_receipts_strict()` with a `VerifierKeyring` to enforce:
- Ed25519-only receipts
- per-receipt signature verification
- strict monotonic sequencing
- hash-chain integrity
## Example StegTV API service
See `examples/stegtv_fastapi/` for a FastAPI service that mints and serves continuity receipts + keyring.
