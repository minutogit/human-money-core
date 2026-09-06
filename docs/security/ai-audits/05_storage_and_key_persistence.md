# Security Audit: Wallet Storage, Key Security & At-Rest Encryption

## AI Auditor Role & System Invariants

You are a senior systems security engineer and cryptographic key storage auditor.

### System Context & Threat Model
`human_money_core` manages user wallets, private signing keys, seed phrases (mnemonics), and local voucher archives on disk.
1. **At-Rest Confidentiality:** Private keys, seed phrases, and profile secrets must NEVER be persisted in plaintext. Encryption at rest (e.g. ChaCha20-Poly1305 / Argon2id / password-derived keys) must be strictly enforced.
2. **Crash Consistency & Atomic Writes:** Storage writes must be atomic (e.g. write-to-temp-then-rename). A power failure or process crash mid-write must never corrupt the wallet or lead to unrecoverable state loss.
3. **Storage Integrity:** Manipulations or bit-flips in archived vouchers or local storage files must be detected deterministically via integrity checksums before data is deserialized into memory.
4. **Memory Hygiene:** Sensitive key material and decrypted secrets should not linger unnecessarily in heap memory or leak into debug logs/error messages.

---

## Target Codebase Scope

Inspect the following files:
- `src/storage/` (all storage implementations, `file_storage.rs`, `mod.rs`)
- `src/archive/` (`file_archive.rs`, `mod.rs`)
- `src/services/mnemonic.rs`
- `src/models/profile.rs`
- `src/models/storage_integrity.rs`
- `src/services/integrity_manager.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Map out how `FileStorage` and `FileVoucherArchive` handle key derivation, serialization, file locking, and directory structures.
   - If necessary, delegate focused sub-inspections to subagents.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Key Leakage at Rest:** Are there code paths where private keys or seed phrases are written to disk unencrypted (e.g. during export, backup, or unauthenticated profile save)?
   - **Weak KDF / Salt Handling:** Are password-derived encryption keys using weak KDF parameters, static salts, or predictable nonces?
   - **Partial Write Corruption:** What happens if the process terminates during a multi-file write? Can a voucher be removed from active storage before being safely committed to the archive?
   - **Tampering & Storage Integrity Bypass:** Can a malicious local actor alter a voucher file in the archive to change its amount or validity without triggering `StorageError` or integrity checks?
   - **Log/Error Disclosure:** Do any `Display` or `Debug` implementations on error types or models format raw secret keys or mnemonics into logs?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. You are encouraged to explore any novel anomaly, filesystem race condition, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write an isolated Rust test in `tests/security_audit_module_05_storage.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)**.
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics).
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.

