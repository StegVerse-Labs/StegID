# Threat Model — StegID (Phase 1)

## Core assets
- Continuity receipts (account continuity evidence)
- Verification keyring (public keys + validity windows + revocations)
- Tier derivations (confidence signals used by downstream systems)

## Threats & mitigations

### T1: Network interception / replay
- Threat: adversary observes traffic, replays receipts
- Mitigation: receipts are public-proof objects; replay doesn’t grant control without private key
- Residual risk: privacy metadata leakage if payloads contain sensitive content (avoid payloads)

### T2: Receipt tampering
- Threat: attacker alters stored receipts
- Mitigation: strict sequencing + prev_hash chaining + signature verification
- Residual risk: if verifier fails to verify chain/signatures (verifier must enforce strict checks)

### T3: Key compromise (account takeover)
- Threat: attacker obtains Ed25519 private key and mints receipts
- Mitigation: key rotation + revocation; high-tier actions require additional evidence (time depth, recovery drills)
- Residual risk: immediate window between compromise and detection

### T4: Malicious admin / insider
- Threat: admin mints fake receipts, changes keyring, manipulates “active key”
- Mitigation: admin actions are audited AND also generate admin continuity receipts (tamper-evident)
- Residual risk: if admin controls both signing key and infrastructure, they can still mint — detection relies on governance/quorum

### T5: Infrastructure seizure / log deletion
- Threat: attacker deletes Redis data, audit logs, keyring
- Mitigation: “continuity receipts” are portable; verifiers can validate offsite backups; memory fallback prevents crash but not data loss
- Residual risk: availability loss without backups (use StegContinuity offsite replication later)

### T6: Time manipulation (future-dated receipts)
- Threat: attacker creates receipts with future timestamps to inflate confidence signals
- Mitigation: verifier-side checks: reject future-dated receipts beyond allowed skew; require monotonic timestamps
- Residual risk: if verifiers don’t apply checks (we provide helper validation)

## Phase 1 boundary
StegID does not store PII/biometrics/DNA. Any expansion must be opt-in and separately reviewed.
