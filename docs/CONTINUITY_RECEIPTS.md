# Continuity Receipts (StegID)

Continuity Receipts provide a **cryptographically verifiable history** for an identity or account. They are designed to be:

- **Deterministic**
- **Chain-verifiable**
- **Transport-agnostic**
- **Adapter-friendly** (StegTV, StegTalk, etc.)

This document defines the **public contract** for receipt generation and verification within **StegID**.

---

## Receipt Structure (v1 contract)

A receipt is a single JSON object with the following fields:

| Field              | Type           | Description |
|-------------------|----------------|-------------|
| `contract_version` | string        | Contract version (v1) |
| `signature_alg`    | string        | Signature algorithm (v1: `ed25519`) |
| `receipt_id`       | string        | Unique receipt identifier |
| `account_id`       | string        | Stable account or identity identifier |
| `sequence`         | int           | Monotonically increasing sequence number |
| `issued_at`        | int           | Unix epoch seconds |
| `event_type`       | string        | Event category (e.g. `key_created`) |
| `event_metadata`   | object        | Non-authoritative metadata |
| `payload`          | object        | Authoritative event data |
| `prev_receipt_id`  | string \| null | Previous receipt id (link field) |
| `signing_key_id`   | string        | Fingerprint of signing public key |
| `signature_b64`    | string        | Ed25519 signature (base64url) |

---

## Signing & Key Identity (v1.x)

- Receipts are signed using **Ed25519**
- `signing_key_id` is derived as:

```text
sha256(normalized_public_key_pem_bytes) --> hex
```

Where `normalized_public_key_pem_bytes` means:
- `\r\n` is normalized to `\n`
- surrounding whitespace is trimmed
- a trailing `\n` is ensured

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

- Contiguous sequence numbers (monotonic +1 in v1 for multi-receipt chains)
- Correct `prev_receipt_id` linkage (when provided)
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
from typing import Any, Dict, List, Optional

@dataclass(frozen=True)
class VerifiedReceipt:
    ok: bool
    receipt: Dict[str, Any]
    notes: List[Dict[str, Any]]
    error: Optional[Dict[str, Any]] = None
```

---

## Error Semantics

All verification failures raise `VerificationError` with a stable machine-readable `.code`.

| Code                | Meaning |
|---------------------|--------|
| `payload_invalid`   | Malformed payload or missing required fields |
| `key_invalid`       | Unknown or revoked signing key |
| `signature_invalid` | Signature verification failed |
| `chain_invalid`     | Non-contiguous chain / prev linkage mismatch / empty chain |

### Example

```python
try:
    verify_receipt_payload_bytes(payload, keyring=kr)
except VerificationError as e:
    assert e.code == "key_invalid"
```

---

## Status

**Stable - Public Contract (v1.0)**

Breaking changes require:
- Version bump
- Migration notes
- Test coverage
