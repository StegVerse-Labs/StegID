# Contract Stability (StegID)

StegID is a contract-first repo. The v1 surface is intentionally small and frozen.

## Source of Truth for v1

Normative v1 documents:

- `docs/CONTINUITY_RECEIPTS.md` (receipt shape + verification semantics)
- `docs/VERSION_FREEZE_v1.md` (freeze declaration)
- `docs/WHY_STEGID_EXISTS.md` (scope + non-goals)

## Compatibility Rules

- v1 is additive-only: new optional fields MAY be introduced without breaking v1.
- Breaking changes require a major version bump (v2+) plus migration notes.

## Crypto Agility

Crypto agility planning lives in:

- `docs/CRYPTO_AGILITY.md`

Note: v1 verification currently enforces Ed25519 and the single-signature field `signature_b64`. Any multi-signature envelope is a planned additive extension and must not break v1 parsing.
