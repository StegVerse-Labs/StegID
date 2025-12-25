# StegID Launch Checklist (v1)

This repo is intended to be a minimal, standalone product:

- receipts (portable, verifiable history)
- verification entrypoint (transport-safe)
- adapters (downstream-friendly)
- optional entity identity helpers

---

## Freeze v1

- Tag release: `v1.0.0`
- Confirm CI green on Python 3.11 + 3.12
- Confirm docs present and consistent:
  - `docs/CONTINUITY_RECEIPTS.md`
  - `docs/CRYPTO_AGILITY.md`
  - `docs/WHY_STEGID_EXISTS.md`
  - `docs/VERSION_FREEZE_v1.md`

---

## README polish

- One 20-second summary
- Install + quickstart snippet
- Minimal verification example
- “What this is / is not”
- Minimal frozen API surface

---

## Soft-launch destinations

- GitHub (Release notes + pinned issue “Roadmap”)
- Hacker News (Show HN)
- Privacy / AI dev circles (Discord/Matrix/Reddit where relevant)

---

## Guardrails

- Never claim “identity truth” beyond what receipts encode
- Keep governance downstream; do not blend policy with cryptographic verification
