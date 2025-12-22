# Contributing to StegID

## Non-negotiable invariants (Phase 1)
- Ed25519-only signatures for receipts
- Strict `sequence` increments by 1
- Strict `prev_hash` chaining
- Backward verifiability for schema v1.0

## Review requirements
Changes touching these paths require careful review:
- `src/identity/`
- `specs/`
- `.github/workflows/`
- `SECURITY.md`, `THREAT_MODEL.md`, `GOVERNANCE.md`, `TIERS.md`, `PHASES.md`

## Testing
Run:
- `pytest`
CI must be green before merge.
