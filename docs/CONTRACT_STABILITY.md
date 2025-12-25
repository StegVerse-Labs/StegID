# Contract Stability (StegID)

StegID is a contract-first repo. The v1 surface is intentionally small and frozen.

Normative v1 docs:

- `docs/CONTINUITY_RECEIPTS.md`
- `docs/VERSION_FREEZE_v1.md`
- `docs/WHY_STEGID_EXISTS.md`

---

## Key ID Derivation (v1.x)

In StegID v1.x, `signing_key_id` / `key_id` is derived from the **normalized PUBLIC key PEM bytes**:

```text
sha256(normalized_public_key_pem_bytes) -> hex
```

This choice is intentionally conservative:
- it matches the v1 implementation
- it avoids breaking any already-minted receipts

A future major version may adopt SPKI DER hashing as a migration, but v1.x remains stable.

---

## Change Control

Breaking changes require:
- a major version bump (v2+)
- migration notes
- updated contract tests
