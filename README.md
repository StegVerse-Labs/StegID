[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

> **Status:** Stable v1 contract (exports frozen). Forward evolution is additive-only.

# StegID

> **Status:** Stable v1 contract (exports frozen). Forward evolution is additive-only.

StegID is a **continuity identity primitive**: it proves that the *same controller* has maintained control of an account over time using cryptographically chained receipts.  
It is **not** legal identity, KYC, or personhood.

---

## Why StegID exists (30 seconds)

Most systems can prove *who* you are only by relying on centralized authorities.
StegID instead proves **continuity of control**:

> “This same key-holder has consistently controlled this identifier over time.”

That property is:
- offline-verifiable
- transport-agnostic
- resilient to infrastructure loss
- useful for recovery, governance, and trust bootstrapping

---

## Contract Stability

StegID follows a strict contract-freeze policy.

All **v1 public exports are permanently frozen** and will not be renamed, removed, or semantically altered.  
Some identifiers reflect early naming decisions and are preserved indefinitely as legacy aliases.

Forward development uses **canonical naming via adapters**, ensuring long-term stability without breaking deployed systems.

📄 See: `docs/CONTRACT_STABILITY.md`

---

## QuickStart (≈60 seconds)

```bash
# create venv (optional but recommended)
python -m venv .venv
source .venv/bin/activate

# install deps
python -m pip install -r requirements.txt
python -m pip install -e .

# run tests
pytest -q
```

If tests pass, the verifier is working correctly.

---

## Minimal Verification Example

This is intentionally small. It proves the verifier runs and enforces the contract.

```python
from identity import KeyringStore, verify_receipt_payload_bytes

# empty keyring (no trusted keys yet)
kr = KeyringStore(redis_url=None)

# minimal (invalid) payload — demonstrates enforcement, not success
payload_bytes = b'{"receipts": []}'

out = verify_receipt_payload_bytes(
    payload_bytes,
    keyring=kr,
)

print(out.ok)       # False
print(out.error)    # {'code': 'payload_invalid', ...}
```

Even this trivial example shows:
- JSON parsing
- contract-shape enforcement
- stable error codes

---

## Continuity Receipts (StegTV / StegTVC wiring)

- Schema: `specs/continuity-receipt.schema.json`
- Receipt primitives: `src/identity/continuity_receipts.py`
- Adapter: `src/identity/stegtv_adapter.py`

### Flow

1. StegTV mints signed continuity receipts (Ed25519).
2. Receipts are transported over any channel (QR, BLE, file, etc.).
3. Verifier checks:
   - signature validity
   - strict sequence (+1)
   - `prev_receipt_id` linkage
4. Downstream systems consume confidence signals.

---

## Security Disclosure

For **non-sensitive issues**, open a GitHub issue.

For **private security disclosure**, use **GitHub Security Advisories** for this repository.

See: `SECURITY.md`
