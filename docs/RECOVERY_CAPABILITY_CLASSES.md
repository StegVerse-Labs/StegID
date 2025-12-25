# Recovery Capability Classes (RCC)

Recovery Capability Classes (RCC) define the **minimum resilience guarantees**
a StegVerse component or evolution must preserve.

They allow recovery guarantees to be:
- explicit
- testable
- governance-enforceable
- independent of specific technologies

RCC levels describe *capability*, not implementation.

---

## RC-0 — Network-Dependent Recovery

**Description**
- Recovery requires live network access
- Depends on centralized services or authorities

**Examples**
- Cloud-only backups
- Remote key servers
- Online-only verification

**Status**
- Permitted for non-critical tooling
- **Not sufficient for core StegVerse continuity**

---

## RC-1 — Offline Digital Artifact Recovery

**Description**
- Recovery possible from offline digital artifacts
- Requires functioning digital storage and compute
- No live network required

**Examples**
- USB drive backups
- Offline disk images
- Encrypted local archives

**Status**
- Acceptable baseline
- Still vulnerable to platform loss

---

## RC-2 — Single Physical Artifact Recovery

**Description**
- Recovery possible from a **single physical artifact**
- Artifact may be scanned, photographed, or manually transcribed
- No assumptions about network or platform availability

**Examples**
- Printed QR mosaics
- Physical inscriptions containing hashes or seeds
- Optical or acoustic encodings

**Status**
- **Minimum required capability for StegVerse core systems**

---

## RC-3 — Covert or Deniable Recovery

**Description**
- Recovery possible under hostile or surveilled conditions
- Artifact does not appear to contain sensitive data
- Supports plausible deniability

**Examples**
- Steganographic images
- Benign-appearing audio or text
- Multi-modal disguised encodings

**Status**
- Strongly recommended for identity and governance roots

---

## RC-4 — Single-Artifact / Single-Device / No-Trust Recovery

**Description**
- Recovery possible from:
  - one artifact
  - one device
  - no pre-existing trust
- Does not require:
  - external authorities
  - prior identity
  - institutional validation

**Examples**
- Deterministic regeneration from symbolic contracts
- Self-describing computational recovery artifacts
- Seed-based identity rebinding

**Status**
- Aspirational upper bound
- Defines the long-term resilience target

---

## Governance Requirements

- All StegVerse core components MUST declare the **minimum RCC level**
  they preserve.
- Evolutions that reduce RCC below the declared minimum MUST be rejected
  or explicitly versioned with justification.
- Governance MAY enforce RCC thresholds as policy gates.

---

## Design Notes

- RCC levels are **orthogonal to cryptography choices**
- RCC does not mandate steganography or any specific medium
- Multiple recovery paths MAY satisfy a single RCC level
- Higher RCC levels MAY coexist with lower ones

---

## Summary Table

| RCC Level | Network Required | Physical Artifact | Covert | Single Device |
|---------:|------------------|------------------|--------|---------------|
| RC-0     | Yes              | No               | No     | No            |
| RC-1     | No               | No               | No     | No            |
| RC-2     | No               | Yes              | No     | No            |
| RC-3     | No               | Yes              | Yes    | No            |
| RC-4     | No               | Yes              | Optional | Yes        |

---

## Status

**Foundational – Stable**

Changes require:
- explicit versioning
- migration notes
- governance approval
