# StegID ↔ StegTalk Interface Contract (v1.0)

## Core rule
- **StegID** defines *meaning* (continuity receipts, verification, tier signals).
- **StegTalk** defines *movement* (transport, fragmentation, routing, retries).
- StegID MUST remain transport-agnostic.
- StegTalk MUST treat StegID payloads as opaque.

## StegIDEnvelope (routing metadata, safe to broadcast)
StegID produces an envelope describing a payload without exposing PII.

Fields:
- `envelope_version`: "1.0"
- `payload_type`: "stegid_receipt" (future types allowed)
- `payload_hash`: SHA-256 hex of raw payload bytes
- `payload_size`: bytes
- `encoding`: "binary" | "base64" | "qr"
- `receipt_hint` (optional):
  - `account_id` (string, not PII by itself)
  - `sequence` (int)
  - `key_id` (verification key fingerprint id)

StegTalk may use `receipt_hint` to route or prioritize delivery, but MUST NOT infer identity.

## Fragment format (StegTalk domain)
StegTalk MAY split payload bytes into fragments.

Minimal fragment fields:
- `fragment_version`: "1.0"
- `envelope_hash`: SHA-256 hex of the serialized StegIDEnvelope (or envelope canonical bytes)
- `fragment_index`: 0-based integer
- `fragment_count`: total fragments
- `fragment_payload`: base64 of fragment bytes
- `fragment_hash`: SHA-256 hex of fragment bytes

StegID never processes fragments; it only verifies fully reconstructed payloads.

## End-to-end offline flow
1) StegID mints a receipt payload and envelope.
2) StegTalk splits payload into fragments and propagates over any available channels (BLE/NFC/QR/audio/optical/etc.).
3) Endpoint reassembles fragments into payload bytes and checks:
   - fragment hashes
   - payload hash matches envelope
4) StegID verifies the receipt (signature + strict sequencing + chain + key validity).
5) Downstream systems consume StegID’s confidence signals.

## Non-goals
- StegID does not implement routing, mesh discovery, or protocol codecs.
- StegID does not learn which transports were used.
- StegID does not store PII, biometrics, or DNA in Phase 1.
