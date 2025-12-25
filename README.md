[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

# StegID

> **Status:** Stable v1 contract (exports frozen). Forward evolution is additive-only.

StegID is a **continuity identity primitive**: it proves that the *same controller*
has maintained control of an account over time using cryptographically chained
receipts.  
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

All **v1 public exports are permanently frozen** and will not be renamed, removed,
or semantically altered. Some identifiers reflect early naming decisions and are
preserved indefinitely as legacy aliases.

Forward development uses **canonical naming via adapters**, ensuring long-term
stability without breaking deployed systems.

📄 See: `docs/CONTRACT_STABILITY.md`

---

## QuickStart (≈60 seconds)

```bash
python -m venv .venv
source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e .

pytest -q
```

If tests pass, the verifier is working correctly.

---

## Minimal Verification Example

This is intentionally small. It proves the verifier runs and enforces the contract.

```python
import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from identity import (
    KeyringStore,
    fingerprint_public_key_pem,
    mint_receipt,
    verify_receipt_payload_bytes,
)

now = int(time.time())

# Generate keypair
priv = Ed25519PrivateKey.generate()
priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")
pub_pem = priv.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

# Add public key to keyring
key_id = fingerprint_public_key_pem(pub_pem)
kr = KeyringStore(redis_url=None)
kr.add_public_key_pem(key_id, pub_pem)

# Mint a v1 receipt
r0 = mint_receipt(
    account_id="acct_demo",
    sequence=0,
    issued_at=now,
    event_type="key_created",
    event_metadata={},
    payload={"example": True},
    prev_receipt=None,
    receipt_id="r0",
    signing_key_id=key_id,
    ed25519_private_pem=priv_pem,
)

# Verify inbound payload bytes
out = verify_receipt_payload_bytes(
    json.dumps(r0).encode("utf-8"),
    keyring=kr,
    now_epoch=now,
)

print(out.ok)    # True
print(out.notes) # verification notes
```

What this is / is not

StegID is:
	•	a receipt format + offline verifier
	•	a frozen v1 contract with enforced behavior
	•	adapter-friendly primitives (e.g. StegTV)

StegID is not:
	•	an identity provider
	•	a database
	•	a blockchain
	•	a governance system
	•	a network service

See:
	•	docs/WHY_STEGID_EXISTS.md
	•	docs/VERSION_FREEZE_v1.md
	•	docs/CONTINUITY_RECEIPTS.md

⸻

Security Disclosure

For non-sensitive issues, open a GitHub issue.

For private security disclosure, use GitHub Security Advisories.

See: SECURITY.md
