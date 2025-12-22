# StegID Phases

## Phase 1 (Current): Continuity Identity Primitive
### Goal
Provide a privacy-preserving, offline-verifiable proof of **continuity of control** over an account identifier.

### In scope
- Ed25519-only continuity receipts
- Strict sequencing (`sequence` increments by 1)
- Hash chaining (`prev_hash` across receipt core)
- Keyring for verification (rotation + revocation + validity windows)
- Adapter that derives “confidence signals” from receipts
- Example StegTV API (optional) with safe defaults and “never crash” storage fallback
- Admin operations audited (log + continuity receipts)

### Non-goals / Not in scope
- Legal identity (name/SSN/DoB)
- KYC / AML databases
- Storage of PII
- Storage of biometric or genomic data
- “Real personhood” proofs (StegID is continuity, not citizenship)
- Mandatory online verification / central authority dependency
- Blockchain anchoring of user events (may be a later phase, opt-in only)

### Frozen invariants (Phase 1)
- `signature_alg = "ed25519"` ONLY
- Receipt schema `version = "1.0"` and must remain backward verifiable
- Verification must be possible offline with receipts + keyring

## Phase 1.5 (Now): Defensibility & Governance
Focus:
- Clear security posture + threat model
- Tier definitions (confidence levels)
- Change control rules to prevent weakening
- Optional validation helpers (timestamp monotonicity, skew checks)

## Phase 2 (Later): Marker Interfaces Only (No Data)
- Add interfaces for “markers” (biometric/genomic/etc.) without ingesting or storing sensitive payloads.
- Any marker ingestion must be opt-in and separated behind privacy & legal review.
