# Crypto Agility (StegID)

StegID v1 uses **Ed25519** and the legacy fields:

- `signing_key_id`
- `signature`

To be future-proof (including post-quantum transitions), StegID supports an **additive v1.1 signature envelope**
that can be emitted alongside the legacy fields.

## v1.1 Additive Fields

A receipt MAY include:

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

### Backward Compatibility Rule

During transition, emit **both**:

- v1 fields (`signing_key_id`, `signature`)
- v1.1 fields (`signature_alg`, `signatures[]`)

Verifiers MUST accept either.

## Hybrid Signatures (Recommended Transition)

When adding a post-quantum algorithm later, use:

```json
"signatures": [
  { "alg": "ed25519", "key_id": "...", "sig": "..." },
  { "alg": "ml-dsa-65", "key_id": "...", "sig": "..." }
]
```

Policies (Governance) can progressively require hybrid validity without breaking existing deployments.

## Implementation Status

- Current implementation verifies **ed25519** signatures.
- The `signatures[]` envelope is supported now.
- Additional algorithms should be added via pluggable verifiers (keep receipt parsing stable).
