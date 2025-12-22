# Security Policy — StegID

## What StegID is
StegID is a continuity system: it helps prove that “the same controller” has maintained control of an account over time via cryptographically chained receipts.

## What StegID is NOT
- Not legal identity
- Not a KYC provider
- Not a personhood oracle
- Not a biometric/genomic vault (Phase 1 stores no PII, no biometrics, no DNA)

## Security goals (Phase 1)
- Offline verification (no central authority required to verify continuity)
- Tamper-evident history (hash chain + strict sequencing)
- Key hygiene support (rotation, revocation)
- Minimize sensitive data exposure (payload hashed; avoid storing raw sensitive material)

## Assumptions
- Private keys can be compromised in the real world.
- Infrastructure can be seized, logs can be altered, admins can behave maliciously.
- The verifier must assume the network is hostile.

## Key compromise philosophy
If a signing key is suspected compromised:
- Rotate to a new keypair
- Mark the old key as expired or revoked in the keyring
- Require a recovery drill / guardian review for high-tier actions

## Vulnerability reporting
If you find a security issue, open a GitHub Issue titled:
- `SECURITY: <short description>`
and include:
- impact, reproduction steps, and suggested mitigation
Do not publish exploit details until a fix is available.

## Safe defaults
- Ed25519-only signatures
- Strict sequence and chain verification
- Admin actions are audited and receipted (tamper-evident)
