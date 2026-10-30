# Security Audit: Wallet Storage, Key Security & Crash-Atomic Persistence

## AI Auditor Role & System Invariants

You are a senior systems security engineer, filesystem integrity auditor, and cryptographic key storage specialist.

### System Context & Threat Model
`human_money_core` manages user wallets, private signing keys, seed phrases (mnemonics), transaction ledgers, and local voucher archives on disk. Because the system is decentralized and offline-first, storage integrity and atomic crash recovery are fundamental to protecting user funds:

1. **At-Rest Confidentiality & Memory Hygiene:**
   - Private keys, seed phrases, and profile secrets must NEVER be persisted in plaintext. Encryption at rest (ChaCha20-Poly1305, Argon2id, PBKDF2) must be strictly enforced.
   - Sensitive key material in memory must be wrapped in `Zeroizing` and zeroed on drop. Error messages and logs must never leak plaintext keys or mnemonics.
2. **Crash-Atomic Wallet Transactions & Undo Journal:**
   - Multi-file storage mutations must be fully crash-atomic. Callers must hold `WalletLockGuard` throughout recovery and mutation.
   - An encrypted undo journal (`.wallet.undo.enc`) and commit marker (`.wallet.commit.enc`) protect multi-step wallet updates. If the process is terminated mid-write, the next startup safely rolls back incomplete mutations.
   - Size and quantity bounds (`MAX_JOURNAL_BYTES`, `MAX_FILE_BYTES`, `MAX_FILES`) prevent disk and memory exhaustion.
3. **Path Traversal & Cryptographic Storage Integrity:**
   - Wallet-relative item paths must strictly undergo component validation (`validate_item_name`) prior to any `Path::join`, rejecting absolute paths, backslashes, and `..` parent traversal components.
   - Manipulations, unauthorized edits, or bit-flips in archived vouchers or local storage files must be detected deterministically via `WalletSeal` and `StorageIntegrityRecord` before data is deserialized into memory.
4. **Differential Cloud Backups & Zero-Knowledge Transport:**
   - Backup operations (`AppService::create_differential_backup`, `inspect_backup`, `restore_backup`) are transport-independent; the core library performs zero network calls.
   - **Password-Slot Stripping:** Exported profiles in `BackupProtection::MnemonicOnly` retain the mnemonic recovery slot but replace the local password slot and salt with random bytes. `CustomBackupPassword` wraps the file key with an independent passphrase.
   - **HMAC Opaque Blob Naming:** Blob names are derived via truncated HMAC-SHA3-256 (`blob_<hex>.enc`), hiding item paths, voucher IDs, and storage structure from untrusted cloud object stores.
   - **Dual Signed Inventories:** The encrypted manifest contains separately signed inventories of both exported bytes and source bytes (including `seal.enc`), preventing forged diff reuse, file substitution, or stale blob replays.
5. **Staged Restore & Device Recovery Epoch Binding:**
   - Restore requires the exact full blob set and verifies paths, names, and cryptographic hashes before staging any files.
   - Files are staged in an isolated temporary directory (`.restore_tmp`); existing wallet profiles are preserved by assigning restored wallets fresh anonymous folder names.
   - Restore generates a device-bound recovery epoch and recalculates local storage integrity, preventing rollback replay attacks.
   - Restored wallets return original-anchor and active-voucher L2 status queries for application-level reconciliation without core performing network calls.

---

## Target Codebase Scope

Inspect the following files:
- `src/storage/wallet_transaction.rs`
- `src/storage/integrity.rs`
- `src/storage/seal_service.rs`
- `src/storage/lock.rs`
- `src/storage/file_storage.rs`
- `src/storage/key_manager.rs`
- `src/storage/encrypted_store.rs`
- `src/storage/event_store.rs`
- `src/storage/mod.rs`
- `src/app_service/backup_ops.rs`
- `src/wallet/reconciliation.rs`
- `src/archive/file_archive.rs`
- `src/models/backup.rs`
- `src/models/seal.rs`
- `src/models/storage_integrity.rs`
- `src/models/profile.rs`
- `src/services/mnemonic.rs`
- `docs/usage/wallet-backups.md`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Map out the transaction lifecycle in `storage/wallet_transaction.rs`, lock lifecycle in `storage/lock.rs`, and differential backup/restore pipelines in `app_service/backup_ops.rs`.
   - If complex sub-tasks or cross-file traces are needed, invoke specialized subagents (e.g. `research` subagents) to trace lock contention, journal replay, and restore staging.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Crash Consistency & Journal Corruption:** What happens if a process crashes while writing `.wallet.undo.enc` or `.wallet.commit.enc`? Can a corrupted or truncated journal brick the wallet permanently or roll back to an unauthorized state?
   - **Path Traversal & Staging Escape:** Can an attacker craft a backup manifest with malicious paths (e.g. `../../etc/passwd`, Windows backslashes, hidden files) that escape the staging directory during `restore_backup` or `validate_item_name`?
   - **Backup Metadata & Key Leakage:** Does `create_differential_backup` ever leak the local wallet password, unencrypted seed phrase, or plaintext file keys into the manifest or exported blobs?
   - **HMAC Blob Collision & Substitution:** Can an adversary tamper with remote blobs, swap blob contents, or feed mismatched blob sets without triggering inventory signature or hash verification failures?
   - **Recovery Epoch Rollback:** Can an attacker restore an outdated backup snapshot to reuse already spent vouchers without triggering L2 reconciliation queries or epoch advance?
   - **Lock Bypass & Multi-Process Corruption:** Can concurrent wallet instances bypass `WalletLockGuard`, overwrite active transactions, or corrupt profile integrity during simultaneous operations?
   - **Log/Error Disclosure:** Do any `Display` or `Debug` implementations on storage errors, backup payloads, or transaction models leak decrypted secrets or mnemonics?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. Explore any novel anomaly, filesystem race condition, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write an isolated Rust test in `tests/security_audit_module_05_storage.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(restore_backup(...).is_err())` or `assert!(validate_item_name(...).is_err())`).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Every reproduction test file must include the standardized metadata docblock:
     - `Finding-ID: AUDIT-05-STORAGE-[INDEX]`
     - `Severity: CRITICAL | HIGH | MEDIUM | LOW`
     - `CWE-Classification`
     - `Target Location`
     - `Threat Model & Exploitation`
     - `Impact Analysis`
     - `Root Cause`
     - `Remediation Strategy`
     - `Test Semantics (Fail-First)`
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]` (e.g. core performing zero network calls during restore, local encrypted event retention for offline dispute resolution, preserving existing profiles under randomized folder names), do not alter the logic; instead document the rationale in the code and protect it with an invariant test.
