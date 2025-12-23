# Continuity Receipts (StegID)

Continuity Receipts provide a **cryptographically verifiable history** for an
identity or account. They are designed to be:

- **Deterministic**
- **Chain-verifiable**
- **Transport-agnostic**
- **Adapter-friendly** (StegTV, StegTalk, etc.)

This document defines the **public contract** for receipt generation and
verification within **StegID**.

---

## Receipt Structure

A receipt is a single JSON object with the following fields:

| Field             | Type            | Description |
|------------------|-----------------|-------------|
| `account_id`     | string          | Stable account or identity identifier |
| `sequence`       | int             | Monotonically increasing sequence number |
| `issued_at`      | int             | Unix epoch seconds |
| `event_type`     | string          | Event category (e.g. `key_created`) |
| `event_metadata` | object          | Non-authoritative metadata |
| `payload`        | object          | Authoritative event data |
| `prev_receipt`   | object \| null | Full previous receipt object |
| `receipt_id`     | string          | Unique receipt identifier |
| `signing_key_id` | string          | Fingerprint of signing public key |
| `signature`      | string          | Ed25519 signature (base64url) |

---

## Signing & Key Identity

- Receipts are signed using **Ed25519**
- `signing_key_id` is derived as:

```text
sha256(SPKI_DER(public_key)) â hex
```

- Public keys **must** exist in a `KeyringStore`
- Revoked keys automatically fail verification

---

## Receipt Creation

```python
from identity import mint_receipt

receipt = mint_receipt(
    account_id="acct_demo",
    sequence=0,
    issued_at=now,
    event_type="key_created",
    event_metadata={},
    payload={},
    prev_receipt=None,
    receipt_id="r0",
    signing_key_id=key_id,
    ed25519_private_pem=private_key_pem,
)
```

---

## Chain Verification

Receipt chains are verified for:

- Contiguous sequence numbers
- Correct `prev_receipt` linkage
- Valid Ed25519 signatures
- Known, non-revoked signing keys

```python
from identity import verify_chain_and_sequence

ok, notes = verify_chain_and_sequence(
    (receipt0, receipt1, ...),
    keyring=my_keyring,
)

assert ok is True
```

---

## Verification Entrypoint (Transport-Safe)

This is the **preferred verification API** for inbound payloads.

```python
from identity import verify_receipt_payload_bytes

out = verify_receipt_payload_bytes(
    payload_bytes,
    keyring=my_keyring,
    now_epoch=now,
)

assert out.ok is True
```

---

## Accepted Payload Shapes

The verifier accepts any of the following JSON shapes:

```json
{ "receipts": [ ... ] }
```

```json
{ "receipt_chain": [ ... ] }
```

```json
{ ...single receipt object... }
```

---

## VerifiedReceipt Result

`verify_receipt_payload_bytes()` returns a `VerifiedReceipt`:

```python
from dataclasses import dataclass

@dataclass
class VerifiedReceipt:
    ok: bool
    receipt: dict
    notes: list[str]
```

---

## Error Semantics

All verification failures raise `VerificationError`
with a stable machine-readable code.

| Code                | Meaning |
|---------------------|--------|
| `payload_invalid`   | Malformed or missing required fields |
| `key_invalid`       | Unknown or revoked signing key |
| `signature_invalid` | Signature verification failed |
| `sequence_invalid`  | Non-contiguous receipt chain |

### Example

```python
try:
    verify_receipt_payload_bytes(payload, keyring=kr)
except VerificationError as e:
    assert e.code == "key_invalid"
```

---

## StegTV Adapter

Adapters provide a stable interface for downstream systems.

```python
from identity import StegTVContinuityAdapter

adapter = StegTVContinuityAdapter(keyring=my_keyring)

out = adapter.verify_receipt_payload(
    payload_bytes,
    now_epoch=now,
)

assert out.ok is True
```

---

## Design Guarantees

- No network access required for verification
- Deterministic verification results
- Explicit error codes (machine-readable)
- Backward-compatible receipt parsing

---

## Non-Goals

- Key distribution
- Key revocation transport
- Receipt storage or indexing
- Consensus or quorum enforcement

These concerns are intentionally left to higher-level systems
(**StegOps**, **StegTV**, **StegTalk**).

---

## Status

**Stable â Public Contract (v1.0)**

Breaking changes require:

- Version bump
- Migration notes
- Test coverage
