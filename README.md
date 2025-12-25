[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

> **Status:** Stable v1 contract (exports frozen). Forward evolution is additive-only.

# StegID

StegID provides **Ed25519-only continuity receipts** and a verifier/keyring system for
privacy-preserving identity confidence. It proves *continuity of control* over time
without requiring online authorities or storing PII.

---

## Contract Stability

StegID follows a strict contract-freeze policy.

All **v1 public exports are permanently frozen** and will not be renamed, removed,
or semantically altered. Some identifiers reflect early naming decisions and are
preserved indefinitely as legacy aliases.

Forward development uses canonical naming via compatibility adapters, ensuring
long-term stability without breaking deployed systems.

📄 See: [docs/CONTRACT_STABILITY.md](docs/CONTRACT_STABILITY.md)

---

## Continuity Receipts (StegTV / StegTVC wiring)

- Schema: `specs/continuity-receipt.schema.json`
- Receipt helpers: `src/identity/continuity_receipts.py`
- Adapter: `src/identity/stegtv_adapter.py`

### Flow

1. StegTV / StegTVC mint append-only, signed continuity receipts (hash-chained).
2. Client applications fetch receipts from StegTV.
3. Adapter derives continuity verification notes.
4. Downstream systems consume confidence signals.

### Signature Algorithms

- **Required:** Ed25519
- **Rejected:** All others (v1 invariant)

---

## Quickstart (60 seconds)

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .[dev]
pytest -q
```

If tests pass, the verifier is working.

---

## Minimal Verification Example

```python
from identity import KeyringStore, verify_receipt_payload_bytes

kr = KeyringStore(redis_url=None)

# Toy payload shape (normally produced by StegTV)
payload_bytes = b'{"receipts": []}'

out = verify_receipt_payload_bytes(payload_bytes, keyring=kr)
print(out.ok, out.notes, out.error)
```

Even though this example is minimal, it demonstrates:
- import surface stability
- verifier entrypoint
- deterministic output structure

---

## Example StegTV API Service

See `examples/stegtv_fastapi/` for a FastAPI service that mints and serves
continuity receipts and verification keys.

---

## Security

See:
- [SECURITY.md](SECURITY.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)

Security issues should be reported via **GitHub Security Advisories** (preferred)
or as issues titled `SECURITY: <summary>`.

---

## License

MIT License.
