# Changelog

All notable changes to this project will be documented in this file.

This project follows:
- **Semantic Versioning**: https://semver.org/
- **Keep a Changelog** format: https://keepachangelog.com/en/1.1.0/

---

## v1.0.1 - 2025-12-25

### Added
- README: QuickStart section with install + test instructions.
- README: Minimal **successful** verification example demonstrating end-to-end mint → verify.
- Documentation links clarifying contract stability and frozen v1 guarantees.

### Changed
- Docs: clarified v1 key-ID derivation as  
  `sha256(normalized public key PEM bytes)` to match implementation.
- Docs: aligned receipt field names (`signature_b64`, `prev_receipt_id`) with the v1 contract.
- Docs: clarified crypto-agility as **planned additive evolution** (v1.1+), not a breaking change.

### Fixed
- Docs: `VerifiedReceipt` structure and error-code descriptions now match implementation and tests.

### Contract Stability
- **No contract changes.**
- v1 public exports remain frozen.
- Legacy identifiers preserved as aliases.

📄 See: `docs/CONTRACT_STABILITY.md`

---

## v1.0.0 - 2025-12-25

### Added
- Initial public release of StegID v1.
- Ed25519-only continuity receipt contract.
- Strict sequence and `prev_receipt_id` chain verification.
- Canonical verification entrypoint with stable error codes.
- Keyring storage with backward-compatible shims.
- StegTV adapter for receipt normalization and verification.
- Contract-freeze guarantees for all v1 public exports.

### Security
- Offline-verifiable receipt chains.
- Deterministic signing core.
- Explicit rejection of malformed payloads.
- Explicit key-missing and key-revoked handling.
