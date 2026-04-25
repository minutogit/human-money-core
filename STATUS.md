---
project: human-money-core
version: "0.2.10"
phase: "active-development"
health: "green"
last_updated: "2026-04-25"
blocks: []
blocked_by: []
priority_tasks:
  - id: "CORE-001"
    title: "Define WoT integration traits"
    status: "open"
    priority: "high"
    depends_on: ["WOT-001", "WOT-002"]
    description: "Define trait interfaces for WoT integration (TrustProvider trait, identity mapping). WoT implementation lives in humoco-web-of-trust, NOT in core."
  - id: "CORE-002"
    title: "Offline trust proof protocol"
    status: "open"
    priority: "high"
    depends_on: ["WOT-003"]
    description: "Implement BLE/NFC stranger discovery handshake in core"
  - id: "CORE-003"
    title: "Cuckoo filter implementation"
    status: "open"
    priority: "medium"
    depends_on: ["WOT-003"]
    description: "Key-Value Cuckoo filter for efficient trust storage"
---

# Human Money Core — Status

## Current Focus

The core library is stable and feature-rich. Current focus areas:
- **New**: WalletSeal Rollback Guard — cryptographic epoch management for state protection
- L2 gateway integration testing (playground & stress tests)
- Voucher validation hardening (edge-case tests for ISO 8601, date rounding)
- Security: Anti-Signature-Reuse-Firewall implemented
- **New**: 'Endorsed' voucher status for persistent guarantor signature tracking

## Architecture

- **14 service modules**: crypto, voucher management, validation, conflict management, L2 gateway, etc.
- **10 wallet modules**: lifecycle, transactions, queries, conflict handling, signatures
- **Extensive test suite**: 7 test categories (architecture, core logic, persistence, services, validation, wallet API, L2 integration)

## Known Issues

- WoT integration traits not yet defined — waiting for architecture finalization from `humoco-web-of-trust`
- **Note**: WoT implementation code lives in `humoco-web-of-trust`, NOT in this repo. Core only defines trait interfaces.
- L2 integration uses mock/playground setup (no real L2 node exists yet)

## Recent Milestones

- [x] Anti-Signature-Reuse-Firewall (security hardening)
- [x] CEL-based dynamic validation engine migration
- [x] L2 retention period and `deletable_at` refactoring
- [x] Comprehensive mutation testing tools
- [x] Edge-case tests (ISO 8601 parsing, date rounding, persistence)
- [x] 'Endorsed' voucher status & persistent signature logging workflow
- [x] User profile management (metadata retrieval and updates)
- [x] Decentralized conflict & reputation management (VIP gossip, proof persistence)
- [x] Multi-language mnemonic support (BIP-39 standard + custom German wordlist)
- [x] Refactored key derivation (strict BIP-39/SLIP-0010 compliance)
- [x] JWS & JWE standard compliance (RFC 7515/7516) and DIDComm-compatible URIs
- [x] Deep traceability testing & fix for voucher source sender identification
- [x] Anonymous Privacy Routing: Strict identity regulation based on PrivacyMode
- [x] Deep Privacy Balance Calculation: Hardened UTXO-based stealth key matching test suite
- [x] Hardened Privacy Mode Decryption: Mandatory privacy_guard validation for anonymous recipient IDs
- [x] **WalletSeal Rollback Guard**: Cryptographic epoch system with hash-chained seals, fork detection, hard lock, and recovery lifecycle integration

## Next Milestones

- [ ] WoT integration traits: `TrustProvider` trait, `TrustQuery` interface
- [ ] DID:key identity mapping helpers (Ed25519 ↔ did:key)
- [ ] Accept external WoT crate via dependency injection (trait objects)
- [ ] Stranger discovery protocol primitives (offline trust proof)
