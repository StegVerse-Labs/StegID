# Changelog

All notable changes to this project will be documented in this file.

This project follows:
- **Semantic Versioning**: https://semver.org/
- **Keep a Changelog** format: https://keepachangelog.com/en/1.1.0/

## Unreleased

### Added
- Contract stability policy link in README and changelog

### Changed
- None

### Fixed
- None


## v1.0.0 - 2025-12-25

### Added
- Initial public release of StegID v1
- Ed25519-only continuity receipt contract
- Strict sequence and `prev_receipt_id` chain verification
- Canonical verification entrypoint with stable error codes
- Keyring storage with backward-compatible shims
- StegTV adapter for receipt normalization and verification
- Contract stability guarantees (v1 exports frozen)

### Security
- Offline-verifiable receipt chains
- Deterministic signing core
- Explicit rejection of malformed payloads
- Explicit key-missing and key-revoked handling

### Contract Stability
- v1 public exports are permanently frozen
- Legacy identifiers preserved as aliases
- Forward evolution is additive-only via adapters
