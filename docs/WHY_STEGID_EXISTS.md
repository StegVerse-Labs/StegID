# Why StegID Exists

Most systems that claim “identity” quietly mix four separate concerns:

1) What happened?
2) Can it be proven?
3) Who is allowed to act on it?
4) Where is it stored and indexed?

This blending creates brittle systems, weak auditability, and portable-truth problems.

## StegID’s claim is intentionally small

StegID produces and verifies **Continuity Receipts**:
cryptographically verifiable event history for an account or entity.

- It does not store receipts.
- It does not distribute keys.
- It does not decide policy.

## The point

StegID answers:

> “What happened, and can it be proven offline?”

Governance answers:

> “Given verified facts, what should happen next?”

By separating “truth” from “authority”, StegVerse components can scale without becoming a monolith.

## Why it matters now

Humans and AI agents increasingly need:

- deterministic audit trails
- portable verification
- clear error semantics
- low-dependency primitives

StegID is meant to be that primitive.
