# Crypto Agility (StegID)

StegID v1 uses **Ed25519** and v1 receipt fields.

Crypto agility is handled by **additive evolution**:
- introduce optional fields
- maintain backward compatibility
- reserve major breaks for v2+

---

## Key ID Derivation Note (v1.x)

StegID v1.x derives key IDs from **normalized PEM bytes**:

```text
sha256(normalized_public_key_pem_bytes) -> hex
```

If a future version adopts SPKI DER hashing, it must be introduced with migration notes and (ideally) dual-acceptance during transition.

---

## Planned v1.1 Additive Signature Envelope

An additive v1.1 signature envelope MAY be introduced later without breaking v1 parsing.

- `signature_alg`: string (e.g., `ed25519`)
- `signatures`: list of signature records

Signature record:

```json
{
  "alg": "ed25519",
  "key_id": "<fingerprint>",
  "sig": "<base64url signature>"
}
```
