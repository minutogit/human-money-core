---
project: human-money-core
version: "0.2.21"
phase: "active-development"
health: "green"
last_updated: "2026-08-13"
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
- **New**: Modularization and structure cleanup of validation and utility modules
- **New**: Fuzzy-Search for historical voucher logs (Voucher Linkage Recovery)
- **New**: WalletSeal Rollback Guard & Storage Integrity
- L2 gateway integration testing (playground & stress tests)
- Voucher validation hardening (edge-case tests for ISO 8601, date rounding)
- Security: Anti-Signature-Reuse-Firewall implemented
- **New**: 'Endorsed' voucher status for persistent guarantor signature tracking
- **New**: Storage Integrity for all wallet records
- **New**: Wallet Event Sourcing (Append-only Ledger for transaction history)

## Architecture

- **17 service modules**: crypto, voucher management, validation, conflict management, L2 gateway, etc.
- **10 wallet modules**: lifecycle, transactions, queries, conflict handling, signatures
- **Extensive test suite**: 7 test categories (architecture, core logic, persistence, services, validation, wallet API, app_service)

## Known Issues

- WoT integration traits not yet defined — waiting for architecture finalization from `humoco-web-of-trust`
- **Note**: WoT implementation code lives in `humoco-web-of-trust`, NOT in this repo. Core only defines trait interfaces.
- L2 integration uses mock/playground setup (no real L2 node exists yet)

## Recent Milestones

- [x] **Voucher Standard Builder & Root Cargo Workspace**: Established a root-level Cargo workspace (`members = [".", "bindings/wasm"]`), built a reusable WebAssembly bridge (`bindings/wasm/`) wrapping `human_money_core` and `cel-interpreter` for browser-side Ed25519 signing and CEL rule syntax checking, and created a focused Vite + React web tool under `tools/standard-builder/` for visual configuration, validation, and export of signed `.toml` standard definitions.
- [x] **WASM Target-Gating & Compilation Safety**: Placed OS-specific dependencies (`sysinfo`, `tokio`, `reqwest`) under target-gated dependency blocks (`target.'cfg(not(target_arch = "wasm32"))'`) in `Cargo.toml` and guarded OS system calls in `FileStorage`, enabling direct `wasm32-unknown-unknown` compilation for `human_money_core`.
- [x] **Voucher Standard Definition Hardening & Documentation**: Added comprehensive Rustdoc `///` comments to `VoucherStandardDefinition` and all sub-structs/enums, synchronized technical specification (`06_standard_definition.md`) with code (`allowed_t_types`, `stealth` privacy mode, `collateral_type` variants), and added detailed educational inline TOML comments across reference files (`minuto_v1`, `freetaler_v1`, `standard_template.toml`) while strictly preserving cryptographic signatures.
- [x] **VoucherCoreError Refactoring & Categorization**: Grouped and documented all `VoucherCoreError` variants with category comments and detailed docstrings, ensuring 100% Rustdoc coverage and clean error modularity.
- [x] **Examples Directory Documentation**: Added `//!` doc comments to all nine playground files in `examples/` and created `examples/README.md` to cleanly index and document all example scripts.
- [x] **Transaction Lifecycle Documentation**: Documented the 7-step transactional safety lifecycle (including rollback semantics, state isolation, generation checks, and process-wide locks) of `with_transactional_mut` and `TransactionOutcome` in `AppService`.
- [x] **UserIdError & GetPubkeyError thiserror Migration**: Migrated the manually implemented Display and Error traits for `UserIdError` and `GetPubkeyError` in `crypto_identity.rs` to use `thiserror` for project-wide consistency and architectural cleanliness.
- [x] **Cryptographic Utilities Modularity**: Decoupled the monolithic 1289-line `crypto_utils.rs` by splitting its functions into domain-specific sub-modules (`crypto_keys`, `crypto_symmetric`, `crypto_dh`, `crypto_identity`) and systematically refactored internal codebase imports to point directly to these modules, improving structural maintainability while preserving backward compatibility via the public facade.
- [x] **Crypto Constants Centralization**: Centralized cryptographic domain separation constants (`ed25519 seed`, `human-money-core/x25519-exchange`, and `human-money-profile-folder-v1`) into a dedicated `crypto_constants` service module, eliminating hardcoded strings across `crypto_utils.rs` and `app_service/mod.rs` to ensure cryptographic stability.
- [x] **Integration Test Consolidation**: Consolidated 17 separate floating integration test files into structured subdirectories (under `architecture`, `core_logic`, `persistence`, `services`, and `wallet_api`) and unified their 7 entry points into a single consolidated `tests/integration_tests.rs` runner, reducing compiled Cargo integration test binaries from 24 to 1 to optimize compilation times and developer velocity.
- [x] **Random Slope Attack Mitigation (Identity Trap)**: Hardened the Identity Trap mechanism against the Random Slope Attack by replacing the deterministic HKDF-based slope derivation with a Discrete Logarithm Equality (DLEQ/Chaum-Pedersen) proof. Added a DLEQ proof generator and verification engine, updated `RecipientPayload` to securely transport proof parameters using Base58-encoded fields, integrated validation in `Wallet` to reject non-deterministic slopes prior to importing/accepting transaction bundles, and verified the implementation against a comprehensive test suite.
- [x] **Security Audit (Identity Trap)**: Implemented 7 security audit tests in `tests/core_logic/security/identity_trap_audit.rs` verifying the mathematical correctness and robustness of the identity-trap mechanism against slope randomization, replay, Schnorr proof forgery, prefix independence, scalar malleability, and invalid/corrupted key extraction.
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
- [x] **WalletSeal Rollback Guard**: Cryptographic epoch system with hash-chained seals, fork-lock protection, Zonen-Modell replay protection with user-controlled recovery overrides.
- [x] **Storage Integrity**: SHA3-256 integrity record bound to WalletSeal, detecting missing, manipulated, or unknown items in the wallet storage with automated update-on-write.
- [x] **Security Hardening**: Argon2id-based key stretching for profile folders (Mobile/WASM tuned) and privacy-preserving arbitrary data naming (removed identity-leaking hashes from filenames).
- [x] **Maintenance Refactoring**: Consolidated storage cleanup into a single, efficient pass; migrated to `usize` for all collection counters and eliminated magic numbers for archival retention.
- [x] **Integrity Bugfix**: Resolved a critical issue where auto-cleanup on login could accidentally mask offline file tampering by rewriting the state before verification.
- [x] **Cloning Protection Hardening**: Implemented active runtime "traps" in AppService to detect improper `instance_id` storage (including parent directories), added aggressive security docstrings, and verified with architecture tests.
- [x] **Test Money Separation & Anti-Spoofing**: Strict cryptographic and structural separation of real and test money in balance aggregation; implemented automated rejection of deceptive "TEST" prefixes for real vouchers (UX security).
- [x] **Wallet Event Sourcing**: Append-only event ledger for all transaction types (VoucherCreated, TransferReceived, TransferSent, VoucherExpired), integrated into atomic `save` flow, with automatic expiration sweeps and in-memory reconciliation.
- [x] **Voucher Branding Migration**: Completed full technical transition from legacy "Silver" nomenclature to "FreeTaler" v1 standard system-wide; updated all test suites, constants, and examples to ensure naming consistency.
- [x] **Scalable Event Chunking**: Optimized event sourcing with time-based monthly chunks (YYYY_MM.json.enc), lazy "Move-then-Delete" migration for legacy logs, and O(N) idempotent appends with O(1) memory pagination.
- [x] **Prefix-less Identity Integration**: Implemented support for pure `did:key` Root-Accounts, decoupled HKDF derivation from legacy prefixes, and synchronized the 150+ test suite with the 2-decimal FreeTaler precision standard.
- [x] **Centralized Voucher Standard Parsing**: Exposed typsafe TOML parsing in `AppService`, enabling client apps to leverage core validation logic and signature verification with verified snake_case stability.
- [x] **Fuzzy-Search for historical voucher logs**: Resolved UI lookup errors by implementing a historical ID fallback mechanism in `Wallet::get_voucher_details`, allowing logs to correctly reference vouchers even after state-changing transactions.
- [x] **Transactional Command Helpers**: Hardened AppService architecture with `with_transactional_mut` and `TransactionOutcome`, centralizing locking, atomic cloning, saving, and sealing to reduce boilerplate and eliminate state orchestration errors.
- [x] **Core Refactoring & Modularity**: Modularized `voucher_manager`, `voucher_validation`, and `test_utils` into directory-based modules with facade patterns; removed legacy monolithic files (1400+ lines each) to reduce cognitive load and improve maintainability.
- [x] **English Documentation Migration**: Completed transition to English comments and Rustdoc for core library entry points (`lib.rs`, `error.rs`, `app_service`), as well as storage and archive modules (`src/storage/`, `src/archive/`), improving developer tool support, maintainability, and accessibility.
- [x] **README Architecture Overhaul**: Integrated comprehensive "Core Concepts" and updated technical architecture description to reflect the current identity-centric, offline-first design paradigm.
- [x] **Refactored Voucher Proof Matching**: Moved `get_proof_id_for_voucher` matching heuristics from Tauri backend to core `Wallet` for zero-copy/no-DTO lookup, exposing it in `AppService` and simplifying command handlers.
- [x] **WalletLockGuard Re-entrancy Bugfix**: Resolved a critical issue where `WalletLockGuard` drop destructor would delete the persistent lock file even when the lock was pre-existing (re-entrant lock), enabling stable sub-session data updates without losing parent session locks.
- [x] **Optimistic Locking**: Implemented generation-based optimistic concurrency locking and transparent 'reload-before-write' synchronization in `AppService` to protect against double-spend vulnerabilities from concurrent UI access.
- [x] **AppFacadeError Migration**: Migrated AppService facade from raw string errors to a structured, type-safe `AppFacadeError` enum, refactoring the entire test suite to support precise, frontend-i18n-ready error handling.


## Next Milestones

- [ ] WoT integration traits: `TrustProvider` trait, `TrustQuery` interface
- [ ] DID:key identity mapping helpers (Ed25519 ↔ did:key)
- [ ] Accept external WoT crate via dependency injection (trait objects)
- [ ] Stranger discovery protocol primitives (offline trust proof)
