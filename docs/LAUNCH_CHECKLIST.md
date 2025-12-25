# StegID Launch Checklist (v1)

This repo is intended to be a minimal, standalone product:

- receipts (portable, verifiable history)
- verification entrypoint (transport-safe)
- adapters (downstream-friendly)
- optional entity identity helpers

## Freeze v1

- Tag release: `v1.0.0`
- Confirm CI green on Python 3.11 + 3.12
- Confirm docs present:
  - `docs/CONTINUITY_RECEIPTS.md`
  - `docs/CRYPTO_AGILITY.md`

## README polish

- One 20-second summary
- Install + quickstart snippet
- “What this is / is not”
- Minimal API surface

## “Why StegID exists”

Short post: one page.

- Problem: unverifiable identity events and non-portable audit trails
- Solution: receipts (truth) + governance (decisions) separation
- What’s next: crypto agility + policy gating + adapters

## Soft-launch destinations

- GitHub (Release notes + pinned issue “Roadmap”)
- Hacker News (Show HN)
- Privacy / AI dev circles (Discord/Matrix/Reddit where relevant)

## Guardrails

- Never claim “identity truth” beyond what receipts encode
- Keep governance downstream; do not blend policy with cryptographic verification
