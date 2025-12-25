# StegID v1.0 — Contract Freeze Notice

**Status:** Frozen (Foundational)

This document declares the StegID v1.0 contract layer **frozen**.

---

## What Is Frozen

The following are considered **normative and non-breaking** in StegID v1.0:

- Continuity Receipt contract
- Verification semantics
- Error codes and failure modes
- Governance separation (truth vs authority)
- Recovery guarantees (RCC ≥ RC-2)
- Crypto agility rules (additive evolution only)

These define **what must be true**, not how it is implemented.

---

## What May Still Change

The following may evolve without breaking v1.0 compatibility:

- Internal implementation details
- Performance optimizations
- Language bindings
- Adapters (StegTV, StegTalk, etc.)
- New cryptographic algorithms (via crypto agility rules)

---

## Compatibility Guarantee

Any future version claiming StegID compatibility MUST:

- Accept and verify v1.0 continuity receipts
- Preserve deterministic verification
- Preserve recovery guarantees defined by the charter
- Preserve truth/authority separation

Breaking changes require:
- explicit version bump
- migration documentation
- governance acknowledgment

---

## Why Freeze Now

StegID v1.0 is frozen because:

- its contracts are minimal and complete
- its guarantees are explicitly defined
- its recovery model is future-resilient
- its authority boundaries are non-negotiable

Further evolution is expected — **but not ambiguity**.

---

## Declaration

StegID v1.0 is declared **Foundational**.

The system may grow.
The truth must remain portable.
