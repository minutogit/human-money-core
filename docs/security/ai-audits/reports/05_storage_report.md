# Module 05 Audit Report — Storage & Key Persistence (Agent A-05)

> Wave 2, Phase B (sequential). Scope: `src/storage/` (`file_storage.rs`, `mod.rs`),
> `src/archive/` (`file_archive.rs`), `models/secure_container.rs`,
> `services/integrity_manager.rs` cross-references.
> Test file: `tests/security_audit_module_05_storage.rs`.
> Pre-existing findings HMSEC-SA05-01..03 were already remediated in an earlier wave
> and are regression-guarded by the existing tests in the module test file.

## Summary Table

| Finding-ID | Hypothesis | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA05-04 | H-05-01 Silent empty-state & undetected rollback of `vouchers.enc` | High | CONFIRMED + FIXED (rollback half); missing-file half INTENTIONAL (control assertion) | `sa05_04_rolled_back_voucher_store_must_not_load_silently` | `src/storage/file_storage.rs` (`store_binding_hash` in `ProfileStorageContainer`, verified in `load_wallet`, written in `save_wallet`) |
| HMSEC-SA05-05 | H-05-02 Legacy downgrade bypass: plaintext JSON circumvents AEAD integrity check | High | CONFIRMED + FIXED | `sa05_05_plaintext_archive_record_must_be_rejected_as_integrity_violation` | `src/archive/file_archive.rs::read_record` (strict rejection of unsealed records) |
| HMSEC-SA05-06 | H-05-04 SecureContainer Drop/Zeroize untested + field coverage gaps | High | CONFIRMED + FIXED (coverage gap); previously covered fields now mutant-guarded | `sa05_06_secure_container_drop_must_zeroize_all_sensitive_fields` | `src/models/secure_container.rs` (`impl Drop for SecureContainer`) |

Not processed in this wave (documented, lower priority, remain open hypotheses):
H-05-03 (lock TOCTOU / log reflection — MEDIUM; acquisition race overlaps
module-00-wildcard unlock ownership question) and H-05-05/H-05-06 (KDF policy,
dev-cli plaintext keys — MEDIUM/LOW). These require coordination decisions and did
not fit the three-hypothesis scope of this wave.

## Finding Details

### HMSEC-SA05-04 — Undetected Rollback of vouchers.enc (H-05-01)

- **CWE:** CWE-1258 / CWE-778 (silent state rollback without any signal)
- **Verified failure:** After two consecutive `save_wallet` calls (store with one
  active voucher → empty store), reverting `vouchers.enc` to the exact bytes of the
  first generation made `load_wallet` return `Ok` with the *spent voucher silently
  resurrected*. Because the persistent file key never changes across saves, the old
  record decrypts cleanly under AEAD — no error path existed.
- **Triage:** `[CONFIRMED VULNERABILITY]` for rollback. 4-question check: local
  threat boundary (in scope); no offline-resilience feature relies on rollback;
  nowhere documented as intended; no functional trade-off. The *missing-file*
  half is `[INTENTIONAL DESIGN REQUIREMENT]`: tolerant load is explicitly
  documented (`tests/persistence/file_storage.rs::test_load_with_missing_voucher_store`,
  `tests/README.md`) and deletion is detected by the signed Storage Integrity layer
  as `IntegrityReport::MissingItems`. Pinned by a control assertion inside the test.
- **Fix:** `ProfileStorageContainer` gained `store_binding_hash: Option<String>`
  (`#[serde(default)]` — legacy containers deserialize unchanged, old readers ignore
  the new key). `save_wallet` binds SHA3-256 over the exact serialized
  `VoucherStorageContainer` bytes into the profile generation it writes together with;
  `load_wallet` rejects any mismatch with `StorageError::StateConflict` before
  decryption. Serialization formats of domain models untouched.
- **Regression verification:** 62 storage-affine tests (persistence, architecture
  fork/cloning guards, double-spend suite) pass.

### HMSEC-SA05-05 — Plaintext Downgrade Bypasses Archive Integrity (H-05-02)

- **CWE:** CWE-347 / CWE-693 (downgrade around a verification mechanism)
- **Verified failure:** Replacing a sealed archive record on disk with canonical
  plaintext voucher JSON (inflated amount) yielded `Ok(Some(forged voucher))` from
  `find_transaction_by_id`: `looks_like_envelope` did not match, so the "legacy
  read-only compatibility" fallback deserialized unauthenticated content directly —
  defeating the entire HMSEC-SA05-02 remediation (bit-flips were detected, whole-record
  replacement was not).
- **Triage:** `[CONFIRMED VULNERABILITY]`. Since the HMSEC-SA05-01 remediation every
  writer seals records; the fallback had no legitimate producer left. Strict rejection
  of legacy-insecure records is a documented compatibility decision per audit rules:
  archives from pre-encryption versions must be re-imported via the public API instead
  of accepting unauthenticated forensic data. Module documentation updated accordingly.
- **Fix:** `read_record` returns `ArchiveError::IntegrityViolation` for any record
  without sealed-envelope markers, before deserialization.
- **Regression verification:** 38 archive-affine tests (persistence/archive, sa04,
  double-spend) pass.

### HMSEC-SA05-06 — SecureContainer Drop Zeroize Coverage Gap (H-05-04)

- **CWE:** CWE-244 / CWE-459 (heap memory not cleared before release)
- **Verified failure:** Unsafe heap inspection with canary buffers proved that after
  `drop_in_place::<SecureContainer>`, `JweRecipient.encrypted_key` (wrapped payload
  key material) and `salt` survived uncleared in freed heap memory, while the
  previously covered fields (ciphertext etc.) were zeroed. `temp/uncovered_code.md`
  had flagged the untested `Drop` impl as CRITICAL coverage gap — a zeroize-removal
  mutant would have survived the suite.
- **Triage:** `[CONFIRMED VULNERABILITY]` (coverage gap). Wrapped payload keys are
  the most sensitive remnants; recovering them from stale heap memory (crash dumps,
  swap, memory scrapers) defeats the forward-secrecy design. No documented exception.
- **Fix:** `Drop` now also zeroizes every recipient's `encrypted_key` and the
  symmetric salt. JSON headers (`unprotected`, `recipient.header`) cannot be reliably
  byte-zeroized (`serde_json::Value` nested Strings); they are released to `None` as
  defense-in-depth, with the limitation honestly documented in the Rust doc-comment.
  Test technique note: buffer suffix from byte 32 is inspected to stay clear of
  allocator free-list metadata written into the first ~16 bytes of freed chunks;
  String zeroize cannot cover reallocated copies (defense-in-depth level, not an
  allocator strategy).
- **Regression verification:** 48 container/bundle/crypto-affine tests pass.

## Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA05-04 | CWE-1258/778 | `[CONFIRMED VULNERABILITY]` (rollback) + `[INTENTIONAL DESIGN REQUIREMENT]` (missing store = documented recovery leniency, integrity-layer detection) | Cross-file generation binding restores invariant #3 without touching documented leniency | Fail-first test + minimal fix (`store_binding_hash`) + control assertion |
| HMSEC-SA05-05 | CWE-347/693 | `[CONFIRMED VULNERABILITY]` | Legacy fallback served only attackers post-SA05-01; strict rejection documented | Fail-first test + strict rejection fix |
| HMSEC-SA05-06 | CWE-244/459 | `[CONFIRMED VULNERABILITY]` (coverage gap) | Memory hygiene invariant #4 must be test-regression-guarded | Fail-first unsafe-inspection test + Drop extension |

## Verification

Module filter result after all changes:
`cargo nextest run -E 'test(sa05)' --status-level fail` → **6 passed / 0 failed**
(3 pre-existing SA05-01..03 regressions guards + 3 new findings).
Targeted filtered regression sweeps over storage-, archive-, container-, bundle-,
crypto- and double-spend-affine suites: all green. No git operations performed.

---

# Wave 3 Addendum (WH3-05-501..506, Phase B remediation)

Scope: `tests/security_audit_module_05_storage.rs` tests `sa05_07`..`sa05_11`.
All five fail-first proofs confirmed the vulnerabilities on unpatched code
(coordinator run: 5 FAIL). Fix locations stayed strictly inside A-05's
exclusive files (`src/storage/file_storage.rs`, `src/archive/file_archive.rs`);
Module 03/04 src changes were not touched.

## HMSEC-SA05-07 — Unauthenticated, Strippable Store Binding (WH3-05-501)

- **CWE:** CWE-345 / CWE-354
- **Verified failure:** With `store_binding_hash` as an optional plaintext
  JSON field verified via unkeyed SHA3 under `if let Some`, a local attacker
  could (a) strip the field to skip the SA05-04 generation check entirely and
  (b) recompute the plain hash over stale bytes — both restored a rolled-back
  `vouchers.enc` silently.
- **Triage:** `[CONFIRMED VULNERABILITY]`. The profile container is an
  unencrypted JSON envelope; any protection readable/writable without the
  wallet secret is attacker-forgeable. No documented leniency applies to
  containers that ship a `vouchers.enc`.
- **Fix:** The binding is now a KEYED commitment:
  `derive_store_binding_hash(file_key, store_bytes)` = SHA3 over file key ‖
  serialized container (fixed-length key prefix; SHA3 is length-extension
  safe). Verification in `load_wallet` is MANDATORY whenever `vouchers.enc`
  exists: absent field ⇒ `StorageError::StateConflict` (field stripping =
  tampering); mismatched value ⇒ `StateConflict`. The documented
  missing-store tolerance (SA05-04 control) is unchanged.
- **Compatibility decision (documented strictness):** profiles written by
  pre-hardening versions carry no (or an unkeyed) binding and now fail loudly
  at load instead of serving possibly rolled-back state. Re-save migrates.
- **Test:** `sa05_07_store_binding_hash_must_be_authenticated_and_mandatory`

## HMSEC-SA05-08 — V2→V3 Serde Field-Drop Without Schema Gate (WH3-05-502)

- **CWE:** CWE-1188 / CWE-693
- **Verified failure:** A byte-exact V2-era `own_fingerprints` payload loaded
  cleanly as degraded hybrids (`layer2_signature` present, trap shards
  default-empty) and was rewritten lossily, destroying V2 identity material
  in the "complete and immutable" history.
- **Triage:** `[CONFIRMED VULNERABILITY]`. Silent accept-and-degrade violates
  invariant #3 for forensic evidence; neither hard error nor preservation
  existed.
- **Fix shape — DECISION: HARD REJECT (documented for Wildcard agent):**
  - Fingerprint stores (`load_own_fingerprints`, `load_known_fingerprints`):
    `gate_legacy_fingerprint_schema` inspects the decrypted payload BEFORE
    typed deserialization; any entry carrying legacy keys `u`/`blinded_id`
    yields `StorageError::InvalidFormat("legacy V2 fingerprint schema …")`.
    Data stays byte-identical on disk until explicit migration. Empty-shard
    V3 genesis placeholders (`"none"`) are unaffected.
  - Voucher store (`load_wallet`): `gate_legacy_transaction_schema` rejects
    any persisted transaction whose `trap_data` object carries legacy keys
    `u`/`blinded_id`/`proof` with `InvalidFormat("legacy V2 trap_data
    schema …")` (recursive scan scoped to `trap_data` objects only).
  - **For Wildcard_06:** both gates are load-time hard errors with matchable
    markers; `Wallet::load` propagates them (`?`), so legacy wallets fail
    login with a recognizable protocol gate instead of displaying anything
    Active/spendable. Note: wildcard_06's fixture coerces its legacy blob to
    an EMPTY typed `TrapData` before persisting (`unwrap_or_default`), so no
    legacy keys reach disk and the storage gate cannot fire for that exact
    residue; that stranding/display case remains the wallet-side chain-
    validation gate (lifecycle.rs) per AUDIT-00-WILDCARD-06's own scope note.
- **Test:** `sa05_08_legacy_v2_fingerprint_data_must_not_be_silently_degraded`

## HMSEC-SA05-09 — Undetectable Whole-Record Delete/Relocate in Archive (WH3-05-504)

- **CWE:** CWE-345
- **Verified failure:** AEAD binds content, not context: deleting the newest
  record silently served the older state; relocating a genuine envelope into
  another voucher's directory re-attributed its history.
- **Triage:** `[CONFIRMED VULNERABILITY]`. Forensic rollback/misattribution;
  the signed integrity layer does not cover archive subdirectories.
- **Fix (two layers):**
  1. *Location binding:* `read_record` verifies the decrypted voucher's
     `voucher_id` against its parent directory name; mismatches yield
     `ArchiveError::IntegrityViolation` (covers global scans too).
  2. *Sealed per-voucher manifest:* every voucher directory gains
     `archive_manifest.sealed` (same key source, atomic tmp+rename) pinning
     the exact record-ID set. `get_archived_voucher` requires the on-disk
     `*.json` set to equal the manifest set; missing manifest or divergence =
     `IntegrityViolation` (whole-record deletion/injection detected).
     `archive_voucher` keeps the manifest in sync; a shrinking record set
     while the manifest is intact refuses rewrite (no deletion laundering via
     interleaved writes). Missing manifests bootstrap from disk contents
     (crash recovery); pre-manifest archives must be re-archived.
- **Residual (documented):** deleting a non-newest record of a FOREIGN
  voucher during a pure `find_transaction_by_id` scan degrades to NotFound
  semantics; full-set verification runs on `get_archived_voucher`.
- **Test:** `sa05_09_archive_record_deletion_and_relocation_must_be_detectable`

## HMSEC-SA05-10 — Empty-Password Archive Keys (WH3-05-505)

- **CWE:** CWE-521 / CWE-1392
- **Verified failure:** `FileVoucherArchive::new_secure(dir, "")` sealed
  records under PBKDF2("", salt) — deterministic, offline-reconstructable.
- **Triage:** `[CONFIRMED VULNERABILITY]` (zero-entropy credential path; no
  second factor downstream unlike FileStorage).
- **Fix:** Seal-time guard in `seal_record`: empty password and all-zero raw
  key are rejected with `ArchiveError::Generic` BEFORE any bytes touch disk
  (constructors keep their signatures by design, as anticipated by the test).
  Read paths fail closed anyway (AEAD).
- **Test:** `sa05_10_archive_construction_with_empty_password_must_be_rejected`

## HMSEC-SA05-11 — Path Traversal on Read/Hash Paths (WH3-05-506)

- **CWE:** CWE-22 / CWE-23
- **Verified failure:** `get_item_hash` joined raw names (absolute paths
  replaced the wallet base → hash oracle; traversals escaped it);
  `load_arbitrary_data` skipped the write-side validation entirely.
- **Triage:** `[CONFIRMED VULNERABILITY]` (sanitize-on-write-only asymmetry).
- **Fix:** `load_arbitrary_data` now mirrors `save_arbitrary_data` exactly
  (`'/' | '\\' | ".."` ⇒ `Err(Generic)`). `get_item_hash` uses component-based
  validation (`validate_item_name`): absolute paths, backslashes and `..`
  components rejected, because it legitimately serves wallet-relative sub-paths
  ("events/YYYY_MM.json.enc") consumed by `get_all_item_hashes`.
- **Test:** `sa05_11_arbitrary_data_read_paths_must_enforce_name_sanitization`

## Wave 3 Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA05-07 | CWE-345/354 | `[CONFIRMED VULNERABILITY]` | Keyless binding = forgeable; absence-tolerance = strip bypass | Keyed mandatory binding, fail-closed load |
| HMSEC-SA05-08 | CWE-1188/693 | `[CONFIRMED VULNERABILITY]` | serde field-drop destroys forensic evidence silently | Hard schema gates (fingerprint + voucher stores), markers documented for Wildcard |
| HMSEC-SA05-09 | CWE-345 | `[CONFIRMED VULNERABILITY]` | AEAD authenticates content, never location/set | Location binding + sealed manifests |
| HMSEC-SA05-10 | CWE-521/1392 | `[CONFIRMED VULNERABILITY]` | Zero-entropy key path without downstream factor | Seal-time empty-credential guard |
| HMSEC-SA05-11 | CWE-22/23 | `[CONFIRMED VULNERABILITY]` | Write-only sanitization asymmetry | Symmetric read/hash validation |

Report-only items carried forward (unchanged): WH3-05-503 (torn-write brick
without recovery API — needs fault injection / recovery spec) and WH3-05-507
(raw IDs as archive file names — defense-in-depth behind Base58 chain
validation).

## Wave 3 Verification

- Module filter: `cargo nextest run --test security_audit_module_05_storage
  --status-level fail` → **11 passed / 0 failed** (all findings green,
  SA05-01..06 regression-guarded).
- Mandated regressions: `persistence::` 29/29, `wallet_api::` 134/134,
  `security_audit_module_04_integrity` 9/9 (+1 ignored) — all green.
- Full suite: 607/610 passed. Remaining failures are the pre-existing,
  unfixed Module-00 wildcard findings (`wildcard_04b/05/06/07/08/09`,
  flaky subset per run — proven identical with A-05's changes reverted)
  plus one RNG-flaky fuzz test that passes on rerun. None touch A-05 files.
