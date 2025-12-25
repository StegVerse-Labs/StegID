# Changelog

All notable changes to this project will be documented in this file.

This project follows:

- **Semantic Versioning**: https://semver.org/
- **Keep a Changelog** format: https://keepachangelog.com/en/1.1.0/

## [Unreleased]

### Added
- None

### Changed
- None

### Fixed
- None

## [1.0.1] - 2025-12-25

### Added
- README: QuickStart section and minimal verification examples (success + failure) for a 60-second run path.

### Changed
- Docs: Aligned receipt field names and verifier output documentation to the v1 contract (`signature_b64`, `prev_receipt_id`, `notes: List[Dict[str, Any]]`).
- Docs: Clarified v1 key-id derivation as `sha256(normalized PUBLIC key PEM bytes) -> hex` to match implementation and avoid breaking already-minted receipts.

### Fixed
- Documentation and markdown consistency fixes (headings, lists, code fences) to prevent rendering/copy-paste errors.

## [1.0.0] - 2025-12-25

### Added
- Initial public release of StegID v1.
- Ed25519-only continuity receipt contract.
- Strict sequence and `prev_receipt_id` chain verification.
- Canonical verification entrypoint with stable error codes.
- Keyring storage with backward-compatible shims.
- StegTV adapter for receipt normalization and verification.
- Contract stability guarantees (v1 exports frozen).

### Security
- Offline-verifiable receipt chains.
- Deterministic signing core.
- Explicit rejection of malformed payloads.
- Explicit key-missing and key-revoked handling.

### Contract stability
- v1 public exports are permanently frozen.
- Legacy identifiers preserved as aliases.
- Forward evolution is additive-only via adapters.

See: `docs/CONTRACT_STABILITY.md`
