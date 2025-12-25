[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

> **Status:** Stable v1 contract (exports frozen). Forward evolution is additive-only.

## Contract Stability

StegID follows a strict contract-freeze policy.

All v1 public exports are permanently frozen and will not be renamed, removed, or semantically altered. Some identifiers reflect early naming decisions and are preserved indefinitely as legacy aliases.

Forward development uses canonical naming via compatibility adapters, ensuring long-term stability without breaking deployed systems.

📄 See: [CONTRACT_STABILITY.md](docs/CONTRACT_STABILITY.md)

## Continuity Receipts (StegTV / StegTVC wiring)

- Schema: `specs/continuity-receipt.schema.json`
- Receipt helpers: `src/identity/continuity_receipts.py`
- Adapter: `src/identity/stegtv_adapter.py`

### Flow

1. StegTV / StegTVC mint append-only, signed continuity receipts (hash-chained).
2. Client applications fetch receipts from StegTV.
3. Adapter derives `crypto_continuity` and `time_depth` signals.
4. Signals feed into the identity confidence engine.

### Signature Algorithms

- Preferred: **Ed25519** receipts (when `cryptography` is available)
- Fallback: **HMAC-SHA256 for local development/testing only**

### Strict Mode (recommended)

Use `derive_signals_from_receipts_strict()` with a `VerifierKeyring` to enforce:
- Ed25519-only receipts
- Per-receipt signature verification
- Strict monotonic sequencing
- Hash-chain integrity

## Example StegTV API Service

See `examples/stegtv_fastapi/` for a FastAPI service that mints and serves continuity receipts and key material.
