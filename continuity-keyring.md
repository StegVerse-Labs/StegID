# Continuity Verification Keyring (Phase 1)

## Goal
Ensure continuity receipts are verifiable without calling a central authority, while still supporting key rotation and revocation.

## Keyring responsibilities
- Map `signing_key_id` -> Ed25519 public key PEM
- Enforce validity windows (`not_before`, optional `not_after`)
- Support revocation (mark key revoked)

## Receipt verification rules
- Only `signature_alg = ed25519` allowed
- Strict hash-chain verification (`prev_hash`)
- Strict monotonic sequencing (`sequence` increments by 1)
- Signature verification on every receipt using keyring

## Storage note
In production, StegTV stores the keyring in hardened storage and exposes public verification material read-only.
