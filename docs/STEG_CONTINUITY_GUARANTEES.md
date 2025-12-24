# StegContinuity Guarantees (StegID / StegCore / StegTalk / StegTV / StegTVC)

**Status:** Stable Draft v1.0  
**Purpose:** Define system-wide guarantees and constraints for identity continuity, verification, and actor parity across StegVerse.

This document is the **Guarantees Layer**: it is normative (MUST/SHOULD/MAY) and applies to all modules that consume or emit Continuity Receipts.

---

## 1. Scope

This Guarantees Layer applies to:

- **StegID** (identity + continuity receipts + verification)
- **StegTalk** (transport + envelopes that carry receipts)
- **StegCore** (governance + orchestration that references continuity)
- **StegTV / StegTVC** (trust timelines + vault/authorization adapters)

Other repos may integrate, but are **not part of this core bundle** and MUST treat these guarantees as a stable contract.

---

## 2. Definitions

- **Receipt:** A signed JSON event object (see `docs/CONTINUITY_RECEIPTS.md`).
- **Chain:** A contiguous sequence of receipts linked by `prev_receipt`.
- **Verifier:** Any process that validates receipts/chains offline (no network required).
- **Actor:** Any entity that can hold keys and sign receipts (human, AI, system).
- **Identity Class:** A declared category of actor (Section 4).

---

## 3. Global Guarantees (Non-Negotiable)

### G1 â Offline Verifiability
Verification MUST succeed or fail **without network access**. Any online checks are optional and non-authoritative.

### G2 â Deterministic Results
Given the same inputs (`payload_bytes`, `keyring`, `now_epoch`, configuration), verifiers MUST produce the same decision.

### G3 â Explicit Machine-Readable Errors
Failures MUST raise `VerificationError` with a stable `.code` (see `CONTINUITY_RECEIPTS.md`).

### G4 â Cryptographic Minimalism
Receipt signatures MUST remain **Ed25519-only** for v1.x.

### G5 â Contract Compatibility
New versions MUST remain backward compatible for accepted payload shapes unless a major version bump is declared.

---

## 4. Identity Parity Guarantees (UX â AX)

### P0 â Cryptographic Parity
All identity classes are **cryptographically equal**: Ed25519 keys, receipts, and verification rules are the same across classes.

### P1 â Declared Identity Class
Each identity MUST declare an `identity_class` at genesis (or be inferable from genesis event metadata):

- `human`
- `ai`
- `system`
- `guardian`

This value MUST be stable for the lifetime of the identity unless a governance action explicitly migrates it.

### P2 â Capability Symmetry Rule
Any capability available to a `human` identity MUST either:
- be available to an `ai` identity, **or**
- be explicitly disallowed in this document with rationale.

**Allowed for AI (v1):**
- key ownership and signing
- key rotation (with continuity)
- offline verification participation
- delegated verification tasks

**Disallowed for AI (v1):**
- claiming biological markers (DNA, fingerprint, face) as primary authentication
- bypassing guardian/quorum controls when policy requires them

### P3 â Recovery Parity
Recovery MUST be possible for any identity class **without backdoors**.

- Humans MAY recover using devices + guardians.
- AI MUST recover using: prior receipts + guardian attestations + deterministic rules.

No âadmin overrideâ recovery path is permitted in core guarantees.

### P4 â Accountability Without Personhood
AI identities are accountable through **continuity and auditability**, not moral or legal personhood.

Systems MUST be able to:
- audit AI action lineage (via receipts)
- constrain/revoke AI keys
- require guardian/quorum authorization for sensitive operations

---

## 5. Key Lifecycle Guarantees

### K1 â Key Presence Requirement
A receipt MUST be rejected if its `signing_key_id` is unknown or revoked.

### K2 â Key Expiration Semantics (v1 policy)
If `now_epoch` is provided, verifiers SHOULD reject keys where `now_epoch > expires_at`.
If `now_epoch` is not reliable (offline), adapters MAY treat expiration as advisory.

**Recommended error code:** `key_expired` (reserved for v1.1 enforcement).

### K3 â Rotation Rules
Key rotation MUST be represented as receipts (e.g., `event_type="key_rotated"` or equivalent).

Rotation MUST NOT break continuity:
- sequence remains contiguous
- chain remains verifiable
- new signing keys MUST be in keyring before acceptance

### K4 â Multi-Key Overlap
Multiple active keys MAY exist, but verifiers SHOULD require that:
- each receiptâs `signing_key_id` is valid at the time of verification, and
- governance defines which event types are permitted for older keys.

---

## 6. Time Semantics & Clock Trust

### T1 â `issued_at` is Advisory
`issued_at` is informational unless an adapter explicitly enforces policy.

### T2 â Adapter Tolerance
Adapters SHOULD provide a configurable skew window (e.g., Â±Î seconds) for time-based checks.

### T3 â Replay Windows
Replay prevention SHOULD be implemented at adapter + transport layers (StegTalk/StegTV), not by changing core receipt verification.

---

## 7. Forking, Conflicts, and Linearity

### F1 â Linear Chains in v1
Receipt chains are linear. Forks are considered invalid **by default**.

### F2 â Fork Resolution is Out of Scope (v1)
If multi-device or concurrent signing creates forks, resolution MUST be handled by higher-level governance (StegCore), not core receipt verification.

This protects the primitive from becoming a consensus system prematurely.

---

## 8. Threat Model (Compact)

### In Scope
- tampering with receipt payloads
- forging signatures
- replaying old receipts
- presenting receipts signed by unknown/revoked keys
- chain splicing or sequence manipulation

### Out of Scope (Handled Elsewhere)
- endpoint OS compromise
- physical coercion
- key theft from a compromised device
- nation-state traffic analysis (transport layer mitigations apply, but not guaranteed)

Core guarantee: if keys remain private and verifiers have correct keyring state, receipts remain verifiable and auditable.

---

## 9. Change Control & Versioning

### V1 â Contract Stability
`docs/CONTINUITY_RECEIPTS.md` + this document define v1.

Breaking changes require:
- version bump (v2+)
- migration notes
- contract tests updated with explicit rationale

### V2 â Reserved Extensions (Non-Breaking if optional)
These fields MAY be introduced as optional:
- `chain_hash` (bundle commitment)
- `origin`, `domain` (replay/domain boundaries)
- checkpoint receipts (compression strategy)

---

## 10. Non-Goals

This Guarantees Layer does NOT define:
- consensus mechanisms
- distributed key distribution
- key escrow
- DNA/biometrics collection workflows
- identity âtruthâ outside continuity proofs
- centralized account systems

Those belong in higher-level repos and policies.

---

## Appendix A â Implementation Checklist (Core Bundle)

- [ ] Freeze v1 contract tests (recommended)
- [ ] Add `key_expired` enforcement behind adapter policy (v1.1)
- [ ] Add optional `chain_hash` support (v1.x non-breaking)
- [ ] Add `origin/domain` replay scoping in StegTalk transport (v1.x)
