# StegTalk → StegID Transport Handoff (v1.0)

## Purpose
Define the minimal interface by which StegTalk delivers reconstructed payloads to StegID
without StegID learning anything about transport, routing, hops, or carriers.

## Principle
- StegTalk delivers **opaque bytes** + StegIDEnvelope.
- StegID verifies **only** cryptographic continuity and strict rules.
- No transport metadata is required or accepted by StegID.

## Handoff function signature (conceptual)

Inputs:
- `envelope`: StegIDEnvelope (routing metadata + payload hash)
- `payload_bytes`: reconstructed bytes (must hash to `envelope.payload_hash`)

Output:
- Either:
  - `VerifiedReceipt` (success)
  - `VerificationError` (fail)

## Required verification steps before accept
StegTalk MUST validate:
- payload sha256 == envelope.payload_hash
- payload size == envelope.payload_size

StegID MUST validate:
- receipt signature (Ed25519)
- strict sequence and continuity chain
- key validity window and revocation status
- timestamp sanity checks (verifier-side)

## Non-goals
- No PII.
- No device identifiers.
- No “carrier evidence” inside StegID.
- No requirement for online connectivity.
