# StegID Confidence Tiers (Phase 1)

StegID tiers represent **confidence in continuity**, not legal identity.

## Inputs (Phase 1)
- Verified receipt chain (strict sequence + prev_hash + Ed25519 signatures)
- Key hygiene events (created/rotated/revoked)
- Time depth (span between first and last receipt)
- Recency (how recently continuity was observed)
- Recovery drill evidence (explicit events)

## Tier 0 — Unverified / No continuity
- No receipts, or receipts fail strict verification
- Use for low-risk features only

## Tier 1 — Verified continuity (basic)
Requirements:
- Strict chain + strict sequencing verified
- Valid signing key present in keyring at issuance time
- At least 1 “key_created” or equivalent bootstrap event

Typical use:
- Normal account access for low/medium risk actions

## Tier 2 — Mature continuity (time + hygiene)
Requirements:
- Tier 1, plus:
- Time depth >= 90 days (or policy-defined)
- At least 1 key rotation OR multiple owner presence receipts
- No unresolved key revocation events

Typical use:
- Recovery flows, higher-value actions, governance participation (non-critical)

## Tier Ω — Catastrophic recovery confidence (Phase 1 doc only; implementation later)
Concept:
- Requires quorum/guardian verification + recovery drill chain
- Used for “root-of-root” actions: catastrophic restore, Tier 1 voting, global key resets

Note:
Tier Ω is intentionally not fully implemented in Phase 1 to avoid false certainty.
