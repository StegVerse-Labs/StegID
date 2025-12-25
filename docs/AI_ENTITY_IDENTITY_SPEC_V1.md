# AI Entity Identity Spec v1 (StegVerse / StegID)

This document defines a **portable, cryptographically-verifiable identity** for AI entities that must interoperate with **human** and **other AI** actors across StegVerse modules (StegID, StegTalk, StegTV, StegCore/SCW, etc.).

It is designed to be:

- **Deterministic** (stable IDs; reproducible fingerprints)
- **Transport-agnostic** (bytes-in/bytes-out)
- **Composable** (supports forks/merges/rotations)
- **Auditable** (append-only continuity receipts)
- **Multi-party attestable** (trust graph)

This spec is intentionally **implementation-light**: the source of truth is the **signed event chain**.

---

## 1. Core Concepts

### 1.1 Entity
An **Entity** is any actor that can sign and be verified:

- AI agent / AI service instance
- Human user (via StegID)
- Service principals (bots, CI, schedulers)

### 1.2 Root Identity (AI “DNA”)
Each AI Entity has a **Root Key**:

- `root_key_alg`: MUST be `Ed25519` for v1
- `root_key_id`: `sha256(normalized_public_key_pem_bytes) -> hex`
- Root keys are long-lived; rotations are explicit events.

**Note (v1 choice):** In StegID v1.x, key IDs are derived from **normalized PEM bytes** (line-ending normalized, trimmed, with a trailing newline). This matches the implementation and avoids breaking any existing minted receipts.

### 1.3 Continuity Ledger (AI “Memory”)
Identity over time is established via **Continuity Receipts** (see `docs/CONTINUITY_RECEIPTS.md`):

- monotonic `sequence`
- `prev_receipt_id` linkage (when present)
- signature verification
- key validity checks

AI identity is the **chain**, not a single record.

---

## 2. Canonical Entity ID

### 2.1 Entity ID Format
`entity_id` is a stable string derived from the root key:

```text
entity_id = "steg:ai:" + root_key_id
```

### 2.2 Display Name (Non-authoritative)
`display_name` is optional and **never authoritative** (may be spoofed). It is treated like metadata.

---

## 3. Entity Profile Object (Portable)

The **Entity Profile** is a compact JSON object that can be shipped with messages for interoperability.

### 3.1 JSON Shape
```json
{
  "entity_id": "steg:ai:<root_key_id>",
  "root_key_id": "<hex>",
  "root_public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
  "entity_type": "ai",
  "display_name": "StegTalk-Agent-01",
  "capabilities": ["receipt_verify", "transport_handoff"],
  "runtime_fingerprint": {
    "impl": "python",
    "impl_version": "3.12",
    "build_id": "optional-ci-build-hash",
    "model_hint": "optional"
  }
}
```

### 3.2 Notes
- `runtime_fingerprint` is advisory (biometrics-like). It may change without changing identity.
- `capabilities` are advisory. Proof of capability is by signed actions.

---

## 4. Identity Events (Receipt Event Types)

AI identity is maintained via a signed event stream. These events are encoded as **Continuity Receipts**.

### 4.1 Required v1 Events
- `entity_initialized`
- `key_created` (already used)
- `key_rotated`
- `entity_forked`
- `entity_merged`
- `capability_added`
- `capability_removed`
- `attestation_issued`
- `attestation_received`

---

## 5. Verification Requirements (Guarantees)

An implementation claiming compliance with v1 MUST:

1. Verify receipt signatures (Ed25519)
2. Enforce chain continuity:
   - contiguous `sequence` (+1 for multi-receipt v1 chains)
   - correct `prev_receipt_id` linkage (when present)
3. Enforce key validity:
   - signing key present in KeyringStore
   - not revoked
4. Produce deterministic outcomes:
   - same input -> same verified output
5. Expose stable, machine-readable error codes:
   - `payload_invalid`
   - `key_invalid`
   - `signature_invalid`
   - `chain_invalid`

---

## Appendix A: Derivation Functions

### A.1 Root Key ID (v1.x)
```text
root_key_id = sha256(normalized_public_key_pem_bytes) -> hex
```

### A.2 Entity ID
```text
entity_id = "steg:ai:" + root_key_id
```
