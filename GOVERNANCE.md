# StegID Governance (Phase 1.5)

## Why governance exists
Security failures often come from “helpful” changes that weaken invariants. Governance locks the invariants.

## Frozen invariants
- Ed25519-only signatures for receipts
- Strict sequencing + prev_hash chaining required for “verified continuity”
- Schema version 1.0 must remain verifiable forever

## Change control policy
### Changes that require review + quorum (recommended)
- Any change affecting verification rules
- Any change to receipt schema fields
- Any change that affects scoring/tier thresholds used for high-risk actions

### Changes allowed without quorum
- Documentation updates
- Example service improvements that do not alter receipt semantics
- New helper modules that do not weaken verification logic

## Backward compatibility
- A verifier that understands v1.0 receipts must be supported long-term.
- New versions must not invalidate existing receipts retroactively.

## Forking policy
If the repo forks:
- Forks must change package name and identifiers to avoid confusing verification ecosystems.
- Receipts minted under one trust ecosystem should not silently validate in another without explicit bridging.

## Disclosure and incident response
- All critical issues get a tracked issue + mitigation plan.
- Key compromise guidance: rotate, revoke/expire, recovery drill, elevate tier requirements temporarily.
