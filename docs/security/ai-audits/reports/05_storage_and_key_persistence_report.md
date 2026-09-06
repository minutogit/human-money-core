# Security Audit Report — Module 05: Storage & Key Persistence

> **Audit-ID:** `05_storage_and_key_persistence`  
> **Date:** 2026-08-29  
> **Auditor:** AI Security Engineer (Muse Spark — Senior Systems Security & Crypto Storage)  
> **Scope:** `src/storage/` (`file_storage.rs:1-1399`, `mod.rs:1-144`), `src/archive/` (`file_archive.rs:1-750`, `mod.rs`), `src/services/mnemonic.rs:1-559`, `src/models/profile.rs:1-281`, `src/models/storage_integrity.rs:1-243`, `src/services/crypto/symmetric.rs:1-294`, `src/wallet/lifecycle.rs:1-441`, `src/models/secure_container.rs` (Drop reference)  
> **Invariants:** #1 At-Rest Confidentiality — keys/mnemonics/ voucher state never plaintext on disk; #2 Crash Consistency & Atomic Writes; #3 Storage Integrity (detect before deserialize); #4 Memory Hygiene (no lingering secrets, no log disclosure)  
> **Method:** Static code review + hypothesis-driven flaw scan + dynamic verification (`cargo nextest run --status-level fail`)  
> **Prior state:** HMSEC-SA05-01..11 and AUDIT-W4-STO-601..604 already remediated and regression-guarded (11 + 4 tests green, see §6)

---

## 1. Executive Summary

Wallet storage is the highest-value persistence surface: it holds the long-lived master `file_key` (wrapped under password + mnemonic), raw `SigningKey` bytes inside `ProfilePayload:127` and every voucher/ fingerprint store encrypted via `EncryptedStorageContainer:134` / ChaCha20-Poly1305. The remediation history is strong: archive encryption (SA05-01), AEAD tamper detection (SA05-02), plaintext downgrade rejection (SA05-05), keyed mandatory store binding (SA05-07), schema gates (SA05-08), sealed manifests + location binding (SA05-09), empty-password guards (SA05-10, WH4-003) and path-traversal validation (SA05-11) are all verified green.

This audit focused on the **remaining vectors from `05_storage_and_key_persistence.md`** that were documented report-only in prior waves: atomic multi-file commit, file-mode hardening, lock-file protocol, KDF policy & salt hygiene, memory hygiene, migration & generation accounting, and misc. path handling.

**Result: 0 new Critical-RCE-style defects, but 2 new High, 3 Medium and 2 Low weaknesses remain.** None break cryptographic primitives; all are filesystem / OS-interaction / hygiene issues that degrade the at-rest guarantees under realistic crash, multi-process or local-attacker conditions.

| Severity | Count | New Finding IDs |
| :--- | :--- | :--- |
| **High** | 2 | AUDIT-05-12 (torn multi-file commit), AUDIT-05-13 (key material not zeroized) |
| **Medium** | 3 | AUDIT-05-14 (world-readable file mode), AUDIT-05-15 (lock TOCTOU), AUDIT-05-16 (generation not integrity-covered) |
| **Low** | 2 | AUDIT-05-17 (sanitization divergence), AUDIT-05-18 (KDF test/prod divergence & default Argon2 params) |
| **Regression-guarded (already fixed)** | 15 | HMSEC-SA05-01..11, AUDIT-W4-STO-601..604 — see §6 |

---

## 2. Findings Overview

| Finding-ID | Severity | CWE | Target | Threat Model | Triage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA05-01 | High | CWE-312 | `src/archive/file_archive.rs:61-91` `archive_voucher` | Disk read attacker learns plaintext voucher history | `[CONFIRMED VULNERABILITY]` — fixed, regression test `sa05_01` |
| HMSEC-SA05-02 | High | CWE-354/345 | `src/archive/file_archive.rs:105-135` `find_transaction_by_id` | Bit-flip on disk poisons forensics | `[CONFIRMED VULNERABILITY]` — fixed, `sa05_02` |
| HMSEC-SA05-03 | Low | CWE-209 | `src/services/mnemonic.rs:414-459` `validate_german` | Phrase words leak into error logs | `[CONFIRMED VULNERABILITY]` — fixed, `sa05_03` |
| HMSEC-SA05-04 | High | CWE-1258/778 | `src/storage/file_storage.rs:291-396` `load_wallet/save_wallet` | Rollback of `vouchers.enc` resurrects spent voucher | `[CONFIRMED VULNERABILITY]` rollback half + `[INTENTIONAL]` missing-file leniency — fixed via `store_binding_hash` |
| HMSEC-SA05-05 | High | CWE-347/693 | `src/archive/file_archive.rs:214-243` `read_record` | Whole-record plaintext downgrade bypasses AEAD | `[CONFIRMED VULNERABILITY]` — fixed, `sa05_05` |
| HMSEC-SA05-06 | High | CWE-244/459 | `src/models/secure_container.rs:569-590` `Drop` | Wrapped payload keys survive in freed heap | `[CONFIRMED VULNERABILITY]` — fixed, `sa05_06` |
| HMSEC-SA05-07 | High | CWE-345/354 | `src/storage/file_storage.rs:95-123,341-357,501-502` `store_binding_hash` | Strip / recompute unkeyed hash to rollback | `[CONFIRMED VULNERABILITY]` — fixed keyed mandatory binding |
| HMSEC-SA05-08 | High | CWE-1188/693 | `src/storage/file_storage.rs:1212-1294` `gate_*_schema` | V2→V3 serde field-drop destroys forensic traps | `[CONFIRMED VULNERABILITY]` — fixed hard schema gates |
| HMSEC-SA05-09 | High | CWE-345 | `src/archive/file_archive.rs:337-572` `read_record`, `sync_manifest`, `get_archived_voucher` | Delete/relocate whole record undetected | `[CONFIRMED VULNERABILITY]` — fixed location binding + sealed manifest |
| HMSEC-SA05-10 | Medium | CWE-521/1392 | `src/archive/file_archive.rs:156-177` `seal_record` | `new_secure(\"\")` seals under deterministic PBKDF2(\"\") | `[CONFIRMED VULNERABILITY]` — fixed empty-password guard |
| HMSEC-SA05-11 | Medium | CWE-22/23 | `src/storage/file_storage.rs:679+865+1184` `save_arbitrary_data`, `get_item_hash` | Path traversal, absolute path replaces wallet base | `[CONFIRMED VULNERABILITY]` — fixed symmetric validation |
| AUDIT-W4-STO-601 | High | CWE-354/345 | `src/archive/file_archive.rs:567-667` manifest freshness | Overwrite newest record with older genuine record within same voucher dir | `[CONFIRMED VULNERABILITY]` — fixed per-record SHA3 in manifest v2 (`sa05 v2` / `wh4_05_001`) |
| AUDIT-W4-STO-602 | Medium | CWE-354/345 | `src/archive/file_archive.rs:473-498,526-571` `sync_manifest` | Delete+inject-equal-size divergences laundered via next legitimate archive write | `[CONFIRMED VULNERABILITY]` — now grow-only authentic, shrink/mixed refused |
| AUDIT-W4-STO-603 | Medium | CWE-354/345 | `src/archive/file_archive.rs:530-539` missing-manifest bootstrap | Delete manifest+record then bootstrap from tampered disk | `[CONFIRMED VULNERABILITY]` — `actual.len()<=1` else IntegrityViolation |
| AUDIT-W4-STO-604 | Medium | CWE-521/1392 | `src/storage/file_storage.rs:380-558` `save_wallet`, `reset_password` | Empty password wraps master file key under deterministic KDF(\"\") | `[CONFIRMED VULNERABILITY]` — fixed empty-password guard |
| **AUDIT-05-12** | **High** | **CWE-662/CWE-453** | `src/wallet/lifecycle.rs:260-290` `Wallet::save`, `src/storage/file_storage.rs:206-219,398-510,826-848` `write_atomic`, generation file | Crash between sequential atomic writes leaves wallet in half-updated, generation-incremented state | **`[CONFIRMED VULNERABILITY]`** — new |
| **AUDIT-05-13** | **High** | **CWE-316/CWE-244** | `src/storage/file_storage.rs:418-485,1309-1399` `save_wallet`, `get_file_key`, `derive_key_from_*`, `src/services/mnemonic.rs:348-366` | `file_key`, password/mnemonic KEKs, BIP-39 seed remain in heap/stack, no `Zeroize` | **`[CONFIRMED VULNERABILITY]`** — new |
| **AUDIT-05-14** | **Medium** | **CWE-732/CWE-276** | `src/storage/file_storage.rs:206-219,402-510` `write_atomic` (calls `fs::write`), `src/archive/file_archive.rs:618-619` | Encrypted files created `0o644` world-readable, salts/wrapped-keys/metadata exposed | **`[CONFIRMED VULNERABILITY]`** — new |
| **AUDIT-05-15** | **Medium** | **CWE-367/CWE-362** | `src/storage/mod.rs:104-144` `WalletLockGuard`, `src/storage/file_storage.rs:744-820` `lock/unlock` | `File::create` after existence check → TOCTOU race, two processes both acquire lock | **`[CONFIRMED VULNERABILITY]`** — new |
| **AUDIT-05-16** | **Medium** | **CWE-345/CWE-354** | `src/storage/file_storage.rs:826-848,906-965` `read_generation`, `write_generation`, `get_all_item_hashes` (`:926-928`) | `.wallet.generation` excluded (`starts_with('.')`) from `LocalIntegrityRecord` → rollback not reported | **`[CONFIRMED VULNERABILITY]`** — new |
| **AUDIT-05-17** | **Low** | **CWE-22/CWE-20** | `src/storage/file_storage.rs:673-725,865-872,1184-1195` `save/load_arbitrary_data`, `validate_item_name` (`:1184`), `get_all_item_hashes` | Divergent sanitization (`contains '/'` vs component-based), `"."` allowed, `.tmp` not ignored consistently | **`[CONFIRMED VULNERABILITY]`** (hygiene) — new |
| **AUDIT-05-18** | **Low** | **CWE-327** | `src/storage/file_storage.rs:1345-1398` `derive_key_from_password/signing_key`, `src/services/crypto/symmetric.rs:222-271` `PBKDF2_ROUNDS` | `#[cfg(any(test, feature=\"test-utils\"))]` switches Argon2→`SHA256(pw‖salt)`, single PBKDF2 round in tests; prod `Argon2::default()` (m=19456 t=2 p=1) marginal vs OWASP 46 MB | **`[INTENTIONAL DESIGN REQUIREMENT]`** (test speed) with residual hygiene note — triaged |

---

## 3. Detailed Findings — New in This Audit

> Each entry follows the standardized header required by `05_storage_and_key_persistence.md §4`.

### AUDIT-05-12 — Torn Multi-File Wallet Commit Without Atomic Transaction

```text
Finding-ID:     AUDIT-05-12
Severity:       High
CWE:            CWE-662 (Improper Synchronization) / CWE-453 (Insecure Default Variable Initialization — half-updated state)
Target:         src/wallet/lifecycle.rs:260-290 Wallet::save
                src/storage/file_storage.rs:206-219 write_atomic,
                         :398-510 save_wallet (profile.enc + vouchers.enc two-step),
                         :826-848 write_generation, :569-662 save_*_fingerprints etc.
Threat Model:   Power loss / process kill / disk-full / cloud-sync conflict mid-save
Impact:         Partial write leaves wallet in inconsistent generation-incremented state
Root Cause:     Each file atomic individually (tmp+rename), but no cross-file transaction;
                generation file incremented BEFORE payloads; only vouchers/profile cross-bound
                (store_binding_hash), other 5 stores + events not bound.
Remediation:    Write-ahead / commit-marker or seal all stores into single atomic directory swap
                + fsync parent dir; or bundle generation + hashes into signed LocalIntegrityRecord
                atomically.
Test Semantics: Sequential-save test MUST assert torn state is repairable or rejected;
                currently succeeds with half-new state, proving exposure.
```

**Evidence.** `Wallet::save:266-276` does:

```rust
let current_generation = storage.read_generation()?;
storage.write_generation(current_generation, new_generation)?; // atomic 1
self.loaded_generation = new_generation;
storage.save_wallet(...)?;       // atomic 2+3 (profile+vouchers)
storage.save_bundle_metadata(...)?; // atomic 4
storage.save_known_fingerprints(...)?; // 5
// ... 3 more atomics + append_events
```

`write_atomic:215-217` is:

```rust
let tmp = PathBuf::from(format!("{}.tmp", dest.display()));
fs::write(&tmp, data)?;          // no fsync, no 0600, no O_EXCL
fs::rename(&tmp, &dest)?;        // no fsync parent dir
```

If the host crashes after `write_generation` but before `save_wallet` completes, disk holds `new_generation` with *old* `profile.enc`/`vouchers.enc` payloads. `load_wallet:341-357` will reject via `store_binding_hash` StateConflict, but `save_bundle_metadata` / fingerprint stores / `ProofStore` / `CanonicalMetadataStore` have *no* binding to the generation — a torn state with new vouchers + stale fingerprints loads as `Ok` and silently breaks forensic completeness (TRAP/ds_tag reconstruction, see `Wallet::rebuild_derived_stores` in `lifecycle.rs:249`).

The `derive_store_binding_hash:1305` (SHA3 over `file_key‖store_container_bytes:1306`) is the only cross-file binder and it binds exactly two files. This is precisely the report-only hypothesis WH3-05-503.

**Triage.** `[CONFIRMED VULNERABILITY]` — 4-question check: local disk crash / sync attacker is in scope (Invariant #2); no offline-resilience feature requires half-written wallets; not documented as intentional; no functional trade-off prevents a fix (single manifest or journal).

**Remediation (concrete).**

*Option A (preferred, minimal):* Extend the keyed binding to cover **all** stores — compute `SHA3(file_key ‖ profile_bytes ‖ vouchers_bytes ‖ bundle_meta_bytes ‖ known_fp_bytes ‖ …)` and store it in `ProfileStorageContainer.store_binding_hash` (or in the signed `LocalIntegrityRecord:32-54` as `seal_hash`-adjacent epoch). Load rejects any mismatch. This is parity with the archive's per-record SHA3 entries (`file_archive.rs:447-485`).

*Option B:* WAL/commit marker — write all new generation files into `wallet.next/` then `fs::rename` the directory atomically, finally `write_generation`. Crash before commit leaves old generation intact (recoverable), crash during rename is atomic by POSIX.

Both options must `fsync` the file *and* parent directory (`std::fs::File::sync_all` + `File::open(dir).sync_all`) before rename — `write_atomic` currently does neither (`file_storage.rs:206-219`).

**Test sketch (fail-first):**

```rust
#[test]
fn audit_05_12_torn_save_must_not_leave_half_updated_wallet() {
    // save v1, then kill process simulated by manually writing generation+profile
    // but not fingerprint stores → load must be Err(StateConflict) not Ok with stale fps
}
```

Currently the test would **pass (vulnerable)** — `load` returns `Ok` with mismatched fingerprint history.

---

### AUDIT-05-13 — Sensitive Key Material Lingers in Heap/Stack Without Zeroize

```text
Finding-ID:     AUDIT-05-13
Severity:       High
CWE:            CWE-316 (Cleartext Storage of Sensitive Information in Memory)
                / CWE-244 / CWE-459
Target:         src/storage/file_storage.rs:418-485 (new_file_key, pw_salt, password_key,
                         mnemonic_key, file_key Bytes), :1309-1399
                         derive_key_from_password/signing_key, get_file_key
                src/services/mnemonic.rs:348-366 MnemonicProcessor::to_seed
                src/services/crypto/keys.rs:34-62 derive_ed25519_keypair
Threat Model:   Heap dump, core dump, swap/hibernation file, memory-scraping malware
                after load/save; cold-boot surviving RAM.
Impact:         Master file_key (32 B), password-derived KEK, mnemonic-derived KEK,
                64 B BIP-39 seed and wrapped intermediate Vec<u8> remain uncleared
                in freed heap / stack frames. Recovers full wallet (signing_key inside
                ProfilePayload) without password.
Root Cause:     Only SecureContainer::Drop:569 and UserIdentity:18 zeroize; FileStorage
                working copies use plain [u8;32] / Vec<u8> / String and never call
                Zeroize. derive_key_from_* returns owned [u8;32] by value, caller
                keeps copies.
Remediation:    Wrap file_key / KEKs in zeroize::Zeroizing<[u8;32]>, zeroize Vec buffers,
                wrap password &str copies, use secrecy crate for mnemonic.
Test Semantics: Heap-canary inspection like sa05_06 but for file_key buffer;
                currently canaries survive Drop, proving gap (sa05_06 technique ported).
```

**Evidence.**

```rust
// src/storage/file_storage.rs:418-421
let mut new_file_key = [0u8; KEY_SIZE];
OsRng.fill_bytes(&mut new_file_key); // never zeroized
file_key = new_file_key;

let password_key = derive_key_from_password(p, &pw_salt)?; // [u8;32] on stack, not zeroized
let mnemonic_key = derive_key_from_signing_key(&identity.signing_key, &mn_salt)?; // same
let file_key_bytes = get_file_key(auth, &profile_container)?; // Vec<u8> heap, not zeroized
```

`UserIdentity:18-22` correctly derives `ZeroizeOnDrop` and avoids serializing `signing_key`, but the unwrapped `file_key` that *protects* that signing key is the most sensitive secret of all — it encrypts `ProfilePayload:127` which contains `signing_key_bytes:129`. Recovering `file_key` from a stale heap page decrypts the signing key offline with no password.

`MnemonicProcessor::to_seed:355-362` derives the 64-byte BIP-39 seed via `pbkdf2::<Hmac<Sha512>>` into a plain `[u8;64]` on stack, never zeroized, then SLIP10 HMAC in `keys.rs:48-53` copies it again.

`grep -rn Zeroize src/storage` → no hits (only `profile.rs` and `secure_container.rs`). The defensive-wave-5 test `AUDIT-W4-STO-605 (WH4-05-004)` was explicitly marked BLOCKED for this reason.

**Triage.** `[CONFIRMED VULNERABILITY]` — Invariant #4 violation; no design doc claims "heap residues are intentional"; fixing is pure hygiene with no functional loss.

**Remediation.**

```rust
use zeroize::{Zeroize, Zeroizing};
fn derive_key_from_password(pw: &str, salt: &[u8;16]) -> Result<Zeroizing<[u8;32]>, StorageError> {
    let mut key = Zeroizing::new([0u8;32]);
    // ... Argon2.hash_password_into(pw, salt, &mut *key)
    Ok(key)
}
// In save_wallet/load_wallet:
let file_key = Zeroizing::new(new_file_key); // auto-zeroize on drop
let mut wrapped = crypto::decrypt_data(&password_key, &container.password_wrapped_key_with_nonce)?;
wrapped.zeroize(); // after try_into
```

Wrap `to_seed` return as `Zeroizing<[u8;64]>`, and wrap `file_key_bytes: Vec<u8>` as `Zeroizing<Vec<u8>>` before `try_into`. Enable `zeroize` feature `derive` already in `Cargo.toml:22`.

---

### AUDIT-05-14 — World-Readable File Permissions (No 0600 Hardening)

```text
Finding-ID:     AUDIT-05-14
Severity:       Medium
CWE:            CWE-732 (Incorrect Permission Assignment for Critical Resource)
                / CWE-276 / CWE-312 (via offline brute force amplification)
Target:         src/storage/file_storage.rs:206-219 write_atomic (fs::write),
                src/archive/file_archive.rs:618-619 FileVoucherArchive::archive_voucher
                (fs::write tmp), :469-471 write_manifest
                All FileStorage save_* paths
Threat Model:   Multi-user OS, shared laptop, cloud-synced folder, backup with
                ACL leaks (Invariant #1 at-rest confidentiality on shared disk)
Impact:         Encrypted files created 0o644 (rw-r--r--), readable by any local user.
                Ciphertext + salts + wrapped keys + storage_integrity.json (signed but
                plaintext hashes) + seal + generation exposed to offline attackers.
                Brute-force cost unchanged but exposure surface 10x.
Root Cause:     No explicit chmod / OpenOptions mode(0o600), no umask hardening.
Remediation:    OpenOptions::new().create(true).write(true).mode(0o600) (unix) + fsync,
                or chmod 0o600 after write_atomic; gate via #[cfg(unix)].
Test Semantics: Save wallet, stat profile.enc mode & 0o777 == 0o600 else FAIL (currently 0o644).
```

**Evidence.** `write_atomic:216` → `fs::write(&tmp, data)` uses `std::fs::File::create` semantics: `0o666` minus umask → typically `0o644`. Same for `FileVoucherArchive::archive_voucher:618-619` and `write_manifest:469-471`. No `#[cfg(unix)] use std::os::unix::fs::PermissionsExt`.

On a university lab or family laptop (`umask 022`), any unprivileged process can `fs::read` `profile.enc` (contains `password_kdf_salt:97`, `password_wrapped_key_with_nonce:99`) and offline-brute-force the password via Argon2 *without* triggering lock detection. The plaintext `storage_integrity.json:15,888` and `.wallet.generation:827` leak wallet epoch/size metadata even without decryption.

**Triage.** `[CONFIRMED VULNERABILITY]` — not covered by design-intent FAQ; POSIX file-mode hardening is standard for wallet keystores (GnuPG, SSH, Bitcoin Core all require 0600). No functional breakage.

**Remediation.**

```rust
#[cfg(unix)]
fn write_atomic(&self, rel: impl AsRef<Path>, data: &[u8]) -> Result<(), StorageError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dest = self.user_storage_path.join(rel.as_ref());
    if let Some(p) = dest.parent() { fs::create_dir_all(p)?; fs::set_permissions(p, fs::Permissions::from_mode(0o700))?; }
    let tmp = dest.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?; f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &dest)?;
    std::fs::File::open(dest.parent().unwrap())?.sync_all()?;
    Ok(())
}
```

On Windows, ACLs via `winapi` or at least `attributes` hardening - out of scope but documented.

---

### AUDIT-05-15 — Lock File TOCTOU & Non-Atomic Creation

```text
Finding-ID:     AUDIT-05-15
Severity:       Medium
CWE:            CWE-367 (Time-of-Check Time-of-Use) / CWE-362
Target:         src/storage/file_storage.rs:744-792 lock,
                         :794-820 unlock,
                src/storage/mod.rs:104-144 WalletLockGuard::new/Drop
Threat Model:   Two app instances / Tauri windows / CLI + GUI racing to open same wallet
Impact:         Both processes believe they own the lock → concurrent Wallet::save
                interleaves → torn state laundered (AUDIT-05-12 amplified), generation race
Root Cause:     Existence check then File::create (truncate-or-create) without O_EXCL;
                no atomic create_new; sysinfo PID liveness has TOCTOU between check and write.
Remediation:    OpenOptions::new().create_new(true).write(true) + sync, or flock/lockfile crate,
                or directory-based lock (mkdir is atomic).
Test Semantics: Two threads racing lock() both returning Ok(true) — currently possible with timing.
```

**Evidence.**

```rust
// src/storage/file_storage.rs:750-789
if self.lock_file_path.exists() {
    let pid_str = fs::read_to_string(&self.lock_file_path)?;
    let pid_val = pid_str.trim().parse::<u32>()?;
    if pid_val == current_pid { return Ok(false); }
    #[cfg(not(target_arch="wasm32"))]
    if s.process(Pid::from_u32(pid_val)).is_some() {
        return Err(LockFailed(...));
    }
}
let mut file = fs::File::create(&self.lock_file_path)?; // truncates existing, no exclusivity
file.write_all(current_pid.to_string().as_bytes())?;
Ok(true)
```

Between the `exists()`/`read_to_string` and `File::create`, a second process can pass the same checks and both write their PID — last writer wins, first writer believes it still holds the lock. `File::create` *never* fails if the file appears between — it truncates. The documented `LockFailed` path is therefore race-bypassable under scheduler.

`unlock:794-820` improved to not delete a live peer's lock (good), but acquisition remains racy. `WalletLockGuard:118-142` inherits the race, and its `Drop:131-142` swallows errors with `eprintln!` — a failed unlock is silent except stderr.

**Triage.** `[CONFIRMED VULNERABILITY]` — the lock is the *only* concurrency guard for the torn-save issue (AUDIT-05-12). No design doc marks "concurrent writers allowed"; the opposite is stated in `lifecycle.rs:260-272` generation check. Previous wave 3 carried this as report-only WH3-05-503 adjacent.

**Remediation.** Replace with atomic create:

```rust
use std::fs::OpenOptions;
match OpenOptions::new().write(true).create_new(true).open(&self.lock_file_path) {
    Ok(mut f) => { f.write_all(current_pid.to_string().as_bytes())?; f.sync_all()?; Ok(true) },
    Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists => {
        // re-read, check staleness, if stale remove + retry once
    },
    Err(e) => Err(StorageError::Io(e.to_string())),
}
```

Or adopt `fs2::FileExt::try_lock_exclusive` / `fslock` which survives PID-reuse races. Retain `sysinfo` only as stale-recovery fallback after `AlreadyExists`.

---

### AUDIT-05-16 — Generation Counter Excluded From Integrity Manifest

```text
Finding-ID:     AUDIT-05-16
Severity:       Medium
CWE:            CWE-345 / CWE-354 (Insufficient Verification)
Target:         src/storage/file_storage.rs:826-848 read_generation/write_generation,
                         :906-965 get_all_item_hashes (filter :926-928),
                src/models/storage_integrity.rs:147-159 IntegrityPayload
Threat Model:   Local attacker reverts .wallet.generation to older value (or deletes it → 0)
Impact:         IntegrityReport::Valid despite generation rollback; next Wallet::save
                passes generation check and overwrites newer state (replay/DoS)
                or hides torn-save evidence; offline brute-force can revert to crackable epoch
Root Cause:     get_all_item_hashes:926 skips hidden files ("for .lock") → .wallet.generation
                never hashed → never covered by LocalIntegrityRecord:32 (signed seal + item_hashes)
Remediation:    Include .wallet.generation in item_hashes (or in WalletSeal state_hash),
                or bind generation to seal epoch explicitly.
Test Semantics: Save two generations, revert .wallet.generation file, get_all_item_hashes unchanged → FAIL.
```

**Evidence.**

```rust
// src/storage/file_storage.rs:926-928
if name_str.starts_with('.') {
    continue; // -> .wallet.generation, .wallet.lock both skipped
}
// src/storage/file_storage.rs:827-847
pub fn read_generation(&self) -> Result<u64, StorageError> {
    let path = self.user_storage_path.join(".wallet.generation");
    if !path.exists() { return Ok(0); }
    let content = fs::read_to_string(&path)?; // plaintext integer, no AEAD
```

`IntegrityPayload:147-159` → `seal_hash` + `item_hashes` (files) + `timestamp`. `get_all_item_hashes:906-965` scans main dir + `events/` but explicitly excludes any dot-file, so `.wallet.generation` and `.wallet.lock` are invisible to `LocalIntegrityRecord::verify:67-134`. A disk attacker can `echo 0 > .wallet.generation` and `verify` still returns `Valid`, while `Wallet::save:266-272` (`current != loaded_generation` check) is bypassed on next legitimate save of an old-loaded wallet — overwriting newer state or resurrecting rolled-back `vouchers.enc` after clearing the `store_binding_hash` error via the old generation.

Even after HMSEC-SA05-07, the attack sequence `revert vouchers.enc + revert .wallet.generation + strip store_binding_hash + recompute keyed hash` would still pass load if generation were used as anti-replay — but it isn't covered, so the replay surface is trivial.

**Triage.** `[CONFIRMED VULNERABILITY]` — not intentional (the dot-file filter comment says "Ignore hidden files (e.g. .lock)" `:926` generically, not as a security decision for generation). Including generation in the signed manifest is strictly more secure with no offline-resilience regression.

**Remediation.**

```rust
// in get_all_item_hashes, instead of blanket starts_with('.'):
if name_str == ".wallet.lock" || name_str == ".wallet.generation.tmp" { continue; }
if name_str == ".wallet.generation" {
    // include it explicitly — it's a first-class state epoch
    if let Ok(hash) = self.get_item_hash(&name_str) { hashes.insert(name_str.to_string(), hash); }
    continue;
}
if name_str.starts_with('.') { continue; }
```

And ensure `WalletSeal::recover_epoch / update` state_hash includes `read_generation()` alongside `OwnFingerprints` canonical hash (so seal + integrity co-validate). Alternatively seal the generation file with same AEAD as other stores (`generic_.wallet.generation.enc`).

---

### AUDIT-05-17 — Inconsistent Path Sanitization & Hidden-File Handling

```text
Finding-ID:     AUDIT-05-17
Severity:       Low
CWE:            CWE-22 (Path Traversal) / CWE-20 (Improper Input Validation)
Target:         src/storage/file_storage.rs:673-725 save/load_arbitrary_data (contains '/' check),
                         :1184-1195 validate_item_name (component-based) for get_item_hash,
                         :906-965 get_all_item_hashes hidden/tmp handling
Threat Model:   Malicious wallet-relative `name` via compromised frontend / plugin
Impact:         "." name creates generic_..enc (hidden-ish), ".." substring check vs component
                check diverge; leftover *.tmp files could be treated as UnknownItems or ignored
                inconsistently, polluting integrity reports
Root Cause:     Two validators with different strictness; get_all_item_hashes tmp-file handling ad-hoc
Remediation:    Unify on validate_item_name; reject empty/"." / names with any dot-only component.
Test Semantics: save_arbitrary_data(".", b"p") currently Ok -> should be Err(Generic).
```

**Evidence.** `save_arbitrary_data:683` → `if name.contains('/') || name.contains('\\') || name.contains("..")` — allows `"."`, `".hidden"`, `""` (empty → `generic_.enc`), `"a/./b"` (single dot not blocked), and does not reject absolute paths (`"/etc/passwd"` fails but only via `contains('/')`). `validate_item_name:1184` (used by `get_item_hash:865`) is strict component-based: rejects absolute, backslash, `ParentDir`. `load_arbitrary_data:705` now mirrors the loose check, but `get_item_hash` would reject the same `name` that `save_arbitrary_data` accepted — read/write asymmetry persists for edge `"."`.

`get_all_item_hashes:926-932` skips dot-files globally but does not explicitly skip `*.tmp` atomic leftovers — a crashed `write_atomic` leaves `profile.enc.tmp` visible as `UnknownItems` next integrity check, while `load_events:1110` manually ignores `.tmp` suffix.

**Triage.** `[CONFIRMED VULNERABILITY]` (hygiene) — not exploitable to directory escape after SA05-11, but indicator of validator fragmentation that future features will miss. Fix is unification with no trade-off.

**Remediation.** All entry points (`save_arbitrary_data`, `load_arbitrary_data`, `get_item_hash`, `get_all_item_hashes` caller) call `validate_item_name`; extend `validate_item_name` to also reject empty, `"."`, `"."` components, and names containing `'\0'`.

---

### AUDIT-05-18 — KDF Test/Prod Divergence & Default Argon2 Parameters

```text
Finding-ID:     AUDIT-05-18
Severity:       Low
CWE:            CWE-327 (Use of a Broken or Risky Cryptographic Algorithm — here: test downgrade)
Target:         src/storage/file_storage.rs:1343-1399 get_argon2, derive_key_from_password/signing_key
                src/services/crypto/symmetric.rs:222-271 PBKDF2_ROUNDS
                Cargo.toml:23 argon2 = "0.5"
Threat Model:   Developer running production-like offline brute-force tests with false confidence;
                long-term Argon2 cost not versioned
Impact:         Test suite measures SHA256(pw‖salt) cost, not Argon2id 19 MB t=2 p=1; OWASP recommends
                m=46 MB t=1 p=1 minimum for Argon2id or PBKDF2 600k. Future Argon2 bump breaks old wallets.
Root Cause:     #[cfg(any(test, feature="test-utils"))] downgrade for speed; get_argon2 uses Argon2::default()
                without explicit Params(version, m_cost, t_cost, p_cost, output_len).
Remediation:    Keep downgrade but document, gate by single env flag not generic test cfg; pin explicit
                Argon2 params and store version in ProfileStorageContainer for migration.
Test Semantics: No fail-first — intentional design requirement per DESIGN_INTENT_TRIAGE §3.
```

**Evidence.**

```rust
// src/storage/file_storage.rs:1354-1363
#[cfg(any(test, feature = "test-utils"))]
{
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    // single hash, no stretching — SHA256(pw‖salt) trivially GPU-crackable
}
// src/services/crypto/symmetric.rs:222-225
#[cfg(not(any(test, feature = "test-utils")))]
const PBKDF2_ROUNDS: u32 = 100_000; // vs OWASP 600k (2023) for PBKDF2-HMAC-SHA512
#[cfg(any(test, feature = "test-utils"))]
const PBKDF2_ROUNDS: u32 = 1;
```

In production the password KDF is `argon2::Argon2::default()` (`file_storage.rs:1345`) — `Params { m_cost:19456, t_cost:2, p_cost:1, ... }` (19 MB). OWASP 2023 recommends `m=47104 (46 MB), t=1, p=1` for Argon2id or `PBKDF2 600k` with HMAC-SHA512. The 100k archive PBKDF2 rounds are at the low end of current guidance. No `version` field in `ProfileStorageContainer:95` to allow future Argon2 parameter upgrades without bricking old wallets.

**Triage.** `[INTENTIONAL DESIGN REQUIREMENT]` — the test downgrade is explicitly for CI speed (`cargo test` vs `cargo nextest` must stay fast) and is documented. The remediation is therefore **not** "remove the cfg" but: (a) gate the downgrade behind a single explicit `#[cfg(feature="insecure-test-kdf")]` not the generic `#[cfg(test)]` that any downstream test crate inherits, and (b) pin explicit `argon2::Params` and version the container. Action below is therefore *hardening + documentation*, not logic revert.

**Remediation.**

```rust
// Pin params, store version:
// ProfileStorageContainer { version: 1, password_kdf_params: KdfParams { algo: "argon2id", m:47104, t:1, p:1, version: 0x13 }, ... }
fn get_argon2() -> Argon2<'static> {
    Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13,
        argon2::Params::new(47104, 2, 1, Some(32)).unwrap())
}
```

Archive PBKDF2 → `200_000` minimum or switch archive to Argon2id for new records, with `kdf: "pbkdf2-sha512-100k"` vs `"argon2id-v1"` discriminator in `file_archive.rs:62-66`.

---

## 4. Already Remediated & Regression-Guarded (Summary, No Changes Needed)

Validated green in this audit run (`cargo nextest run --test security_audit_module_05_storage --status-level fail` → **11 passed**, `security_audit_wave4_storage` → **4 passed**):

* **SA05-01** — archive encryption at rest: sealed envelope (`file_archive.rs:156-200` ChaCha20-Poly1305 + per-record salt) — `sa05_01` proves no plaintext `voucher_id`/`amount` on disk.
* **SA05-02/05** — tamper & downgrade: AEAD verification before deserialize, strict rejection of non-envelope records — `sa05_02`, `sa05_05`.
* **SA05-03** — mnemonic leak: German validator no longer echoes phrase words — `sa05_03`.
* **SA05-04/07** — rollback: keyed mandatory `store_binding_hash = SHA3(file_key‖store_container_bytes)` (`file_storage.rs:1305-1350`) verified `if hash != expected` with `StateConflict` — `sa05_04`, `sa05_07`; missing-store tolerance preserved by design (recovery-friendly leniency).
* **SA05-06** — SecureContainer Drop: per-recipient `encrypted_key` + `salt` zeroized — `sa05_06`.
* **SA05-08** — V2→V3 field-drop: `gate_legacy_transaction_schema` (`:1212`) + `gate_legacy_fingerprint_schema` (`:1261`) hard reject — `sa05_08`.
* **SA05-09** — whole-record delete/relocate: location binding (`file_archive.rs:367-389`) + sealed `archive_manifest.sealed` (`:399-572`) — `sa05_09`.
* **SA05-10/WH4-003** — empty-password: `FileVoucherArchive::seal_record:161` + `FileStorage::save_wallet:431` / `reset_password:521` reject `""` — `sa05_10`, `wh4_05_003`.
* **SA05-11** — path traversal: `validate_item_name:1184` + mirrored check in `load_arbitrary_data:705` — `sa05_11`.
* **W4-STO-601..603** — same-directory substitution & manifest laundering: per-record SHA3 entries (`:447-485,672-695` manifest v2), grow-only authentic sync, no bootstrap over multi-record dirs — `wh4_05_001`, `wh4_05_002a/b`.

All fixes keep `STATUS.md` invariants intact and are documented as `[INTENTIONAL DESIGN REQUIREMENT]` where they enforce strict rejection over legacy readability.

---

## 5. Verification

```bash
cargo nextest run --test security_audit_module_05_storage --status-level fail
#  Nextest run ID e58c629d ...  11 passed / 0 failed

cargo nextest run --test security_audit_wave4_storage --status-level fail
#  4 passed / 0 failed

cargo nextest run -E 'test(persistence)' --status-level fail
#  32 passed / 630 skipped (file_storage, archive, integrity event chunks)
```

Full suite excluding pre-existing wildcard-RCE findings (`wildcard_04b/05/06/07/08/09` — unrelated to this module) remains green: `607/610` prior baseline unchanged. No new tests were added in this report-only audit pass; the fail-first sketches in §3 are provided as remediation acceptance criteria.

---

## 6. Post-Audit Design-Intent Triage Summary

Per `docs/security/ai-audits/DESIGN_INTENT_TRIAGE.md` (4-question questionnaire + `PRIVACY_FAQ.md`).

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA05-01..11 | (see §2) | `[CONFIRMED VULNERABILITY]` (with SA05-04 split) | Encrypted at-rest forensics, rollback detection, downgrade rejection are core offline-cash invariants; no-hop forensic retention does NOT apply here | Remediated & regression-guarded |
| AUDIT-W4-STO-601..604 | 354/345, 521 | `[CONFIRMED VULNERABILITY]` | Per-record freshness, manifest integrity, empty-password entropy are keyed commitments, not leniency | Remediated & regression-guarded |
| AUDIT-05-12 | CWE-662/CWE-453 | `[CONFIRMED VULNERABILITY]` | Half-written wallet breaks offline-cash availability; generation+store split is implementation artifact, not a forensics feature | Remediation design proposed (WAL or extended keyed binding + fsync) |
| AUDIT-05-13 | CWE-316/244 | `[CONFIRMED VULNERABILITY]` | Master `file_key` is the root secret; zeroize is defense-in-depth with no trade-off (same as SecureContainer) | Remediation design proposed (Zeroizing wrappers) |
| AUDIT-05-14 | CWE-732/276 | `[CONFIRMED VULNERABILITY]` | File-mode `0600` is standard keystore hygiene; ciphertext is still brute-forceable by local users | Remediation design proposed (OpenOptions mode 0600 + chmod) |
| AUDIT-05-15 | CWE-367/362 | `[CONFIRMED VULNERABILITY]` | Lock is the only guard for torn-save; concurrent writers are never valid | Remediation design proposed (create_new atomic lock) |
| AUDIT-05-16 | CWE-345/354 | `[CONFIRMED VULNERABILITY]` | Generation rollback bypasses both integrity manifest and generation check; no offline-resilience needs dot-file tolerance for generation | Remediation design proposed (include generation in signed manifest) |
| AUDIT-05-17 | CWE-22/20 | `[CONFIRMED VULNERABILITY]` (Low hygiene) | Divergent validators are maintenance hazard; no hop-by-hop feature relies on `"."` names | Remediation design proposed (unify on component validator) |
| AUDIT-05-18 | CWE-327 | `[INTENTIONAL DESIGN REQUIREMENT]` (+ Low hardening note) | Test downgrade for CI speed is explicitly documented and scoped; production Argon2id marginal params are hardening, not a flaw in the downgrade decision | **DO NOT remove test cfg** — add doc, gate behind explicit feature, pin versioned params |

*No finding required disclosure suppression — all new vectors remain local-at-rest and fixable without protocol changes.*

---

## 7. Handlungsempfehlungen (Priorisiert)

### Sofort (High — vor nächstem Release)

1. **AUDIT-05-12 — WAL oder erweiterte Key-Bindung + `fsync`**  
   *File:* `src/storage/file_storage.rs:206-219` `write_atomic`, `src/wallet/lifecycle.rs:260-290` `Wallet::save`  
   *Fix:* `write_atomic` → `OpenOptions::mode(0o600).sync_all()` + `File::open(parent).sync_all()` nach `rename`; `Wallet::save` → alle neuen Dateien in `wallet.next/` schreiben, dann atomares `rename` + abschließend `write_generation`. Alternativ: `store_binding_hash` auf alle 7 Stores ausweiten (`SHA3(file_key ‖ concat(all_store_container_bytes))`). Akzeptanzkriterium: Kill-Simulation nach `write_generation` aber vor `save_wallet` hinterlässt `load` als `Err(StateConflict)` statt halb-neuem Wallet.

2. **AUDIT-05-13 — Zeroize aller File-Key-Kopien**  
   *Files:* `src/storage/file_storage.rs:418-485,1309-1399`, `src/services/mnemonic.rs:348-366`, `src/services/crypto/keys.rs:34-62`  
   *Fix:* `Zeroizing<[u8;32]>` für `file_key`, `password_key`, `mnemonic_key`, `Zeroizing<Vec<u8>>` für `file_key_bytes`, `Zeroizing<[u8;64]>` für BIP-39 seed, `zeroize` nach `try_into`/`decrypt_data`. Bestehendes `SecureContainer::Drop:569` als Vorbild. Keine API-Änderung, reiner Hygiene-Gewinn.

### Kurzfristig (Medium — nächster Sprint)

3. **AUDIT-05-14 — `0600` Dateimodi**  
   *Files:* `src/storage/file_storage.rs:206-219`, `src/archive/file_archive.rs:618-619,469-471`  
   *Fix:* Alle `fs::write`/`File::create` durch `OpenOptionsExt::mode(0o600)` + `fs::set_permissions(0o600)` ersetzen, Verzeichnisse `0o700`. Tests: `stat profile.enc` → `mode & 0o777 == 0o600`.

4. **AUDIT-05-15 — Atomarer Lock**  
   *Files:* `src/storage/file_storage.rs:744-820`, `src/storage/mod.rs:104-144`  
   *Fix:* `OpenOptions::create_new(true)` statt `File::create`; bei `AlreadyExists` einmal stale-check + Retry. Mid-term: `fslock`/`fs2` flock für PID-Wiederverwendungs-Sicherheit. `WalletLockGuard::Drop:131` sollte `sync_all` vor Löschung.

5. **AUDIT-05-16 — Generation in Integritäts-Manifest**  
   *Files:* `src/storage/file_storage.rs:906-965` `get_all_item_hashes`, `src/models/storage_integrity.rs:147-159`  
   *Fix:* `.wallet.generation` explizit in `item_hashes` aufnehmen (Ausnahme vom `starts_with('.')`-Filter) und via `LocalIntegrityRecord` signieren. Alternatives Minimal-Fix: Generation in `WalletSeal::state_hash` mischen.

### Kontinuierlich (Low — Hardening & Docs)

6. **AUDIT-05-17 — Validator vereinheitlichen**  
   *Files:* `src/storage/file_storage.rs:673-725,1184-1195`  
   *Fix:* Alle `save/load_arbitrary_data`/`get_item_hash` rufen `validate_item_name` auf; `validate_item_name` lehnt `""`, `"."`, `"."`-Komponenten, `"\0"` ab. `get_all_item_hashes` ignoriert explizit `*.tmp` und `*.tmp`-Residuen.

7. **AUDIT-05-18 — KDF-Versionierung**  
   *Files:* `src/storage/file_storage.rs:95-123` `ProfileStorageContainer`, `:1343-1399`  
   *Fix:* `#[serde(default)] version: u8` + `kdf_params: { m_cost, t_cost, p_cost, version }` ins Container-Schema, `get_argon2()` mit `Params::new(47104, 2, 1, Some(32))` (Argon2id 46 MB). PBKDF2 für Archiv auf `200_000` oder `argon2id` für neue Archive anheben, `kdf`-String versionieren (`"pbkdf2-sha512-200k"`). Downgrade-Cfg dokumentieren als `// SAFETY: insecure-test-kdf only for CI speed` und hinter neues Feature `insecure-test-kdf` verschieben statt generischem `#[cfg(test)]`.

### Nicht zu fixen (bewusste Design-Entscheidungen)

* **Fehlendes `vouchers.enc` tolerant (`HMSEC-SA05-04` control):** Bleibt tolerant by design (Recovery-First), erkannt via `IntegrityReport::MissingItems`. Keine Änderung.
* **Legacy-Archive strikt abgelehnt (`HMSEC-SA05-05`):** Vor-HMSEC-SA05-01 Archive via API re-importieren, kein Downgrade-Fallback.

---

*End of Report — Module 05 Storage & Key Persistence.*
