//! # tests/security_audit_wave4_storage.rs
//!
//! Security Audit Wave 4 — Module 05: Storage, Archive & Key Persistence.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. These tests turn green only after the
//! corresponding remediation has been implemented.
//!
//! Scope: src/archive/file_archive.rs, src/storage/file_storage.rs.
//!
//! ## Finding Summary
//!
//! | Finding-ID     | Wave-ID    | Severity | CWE         | Target                                        |
//! |----------------|------------|----------|-------------|-----------------------------------------------|
//! | AUDIT-W4-STO-601 | WH4-05-001 | High   | 354/345     | archive/file_archive.rs:567-590/:349-389       |
//! | AUDIT-W4-STO-602 | WH4-05-002a| Medium | 354/345     | archive/file_archive.rs:473-498                |
//! | AUDIT-W4-STO-603 | WH4-05-002b| Medium | 354/345     | archive/file_archive.rs:473-498/:514-555       |
//! | AUDIT-W4-STO-604 | WH4-05-003 | Medium | 521/1392    | storage/file_storage.rs:380-417/:473-509       |
//!
//! AUDIT-W4-STO-605 (WH4-05-004, LOW, zeroize coverage of FileStorage working
//! copies) has NO test here: a faithful heap-canary probe through
//! `save_wallet`/`load_wallet` requires capturing interior pointers of buffers
//! that only exist inside library-private scopes (see
//! temp/wave4-results/module-05.md, BLOCKED with rationale).

use human_money_core::archive::file_archive::FileVoucherArchive;
use human_money_core::archive::VoucherArchive;
use human_money_core::models::voucher::{Transaction, Voucher};
use human_money_core::test_utils::setup_voucher_with_one_tx;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

/// Raw-key mode avoids the per-record PBKDF2 cost; a non-zero key satisfies
/// the degenerate-key seal guard (HMSEC-SA05-10 remediation).
const AUDIT_KEY: [u8; 32] = [0x5Au8; 32];

/// Derives the successor state of a voucher chain: clones `voucher`, appends
/// one transaction with the given fresh `t_id` and returns the new state.
/// Chain length grows strictly monotonically, mirroring genuine archival of
/// evolving voucher states (the archive layer itself does not re-validate
/// chain signatures — whole-record operations are the target).
fn successor_state(voucher: &Voucher, new_t_id: &str, recipient_id: &str) -> Voucher {
    let mut next = voucher.clone();
    let prev_hash = next
        .transactions
        .last()
        .map(|t| t.t_id.clone())
        .unwrap_or_default();
    next.transactions.push(Transaction {
        t_id: new_t_id.to_string(),
        t_time: "2032-01-01T00:00:00Z".to_string(),
        prev_hash,
        recipient_id: recipient_id.to_string(),
        amount: voucher.nominal_value.amount.clone(),
        ..Default::default()
    });
    next
}

/// Builds the on-disk record path `<archive>/<voucher_id>/<t_id>.json`.
fn record_path(archive_root: &Path, voucher_id: &str, last_t_id: &str) -> std::path::PathBuf {
    archive_root
        .join(voucher_id)
        .join(format!("{}.json", last_t_id))
}

// =============================================================================
// FINDING AUDIT-W4-STO-601 (Wave 4 — WH4-05-001)
// -----------------------------------------------------------------------------
// Finding-ID:    AUDIT-W4-STO-601
// Severity:      High
// CWE-Classification: CWE-354 (Improper Validation of Integrity Check Value)
//                     / CWE-345 (Insufficient Verification of Data Authenticity)
// Target Location: src/archive/file_archive.rs:567-590 (`get_archived_voucher`
//                  sealed-manifest SET equality check), :349-389 (`read_record`
//                  AEAD + location binding), :392-420 (`read_manifest`).
//
// ## Threat Model & Exploitation
// A local attacker with disk write access (the exact attacker of HMSEC-SA05-
// 04/05/09) overwrites the bytes of the NEWEST record `<t3>.json` with the
// bytes of an OLDER genuine record of the SAME voucher directory
// (`fs::copy <t2>.json -> <t3>.json`). Every existing check passes:
// (1) the sealed manifest pins only the SET of record IDs — unchanged by the
// copy; (2) AEAD verification succeeds because the copied bytes are a genuine,
// untampered envelope; (3) the location binding compares only `voucher_id`
// against the parent directory — identical. The forensic history is silently
// rolled back from state t3 to state t2.
//
// ## Impact Analysis
// The newest spend evidence is replaced by an older state with zero detection
// — precisely the rollback outcome HMSEC-SA05-09 was meant to make impossible
// ("deleting the newest record silently served the older state"). Deleting the
// newest evidence this way can launder a double-spend dispute. Violates
// System Invariant #3: manipulations of archived vouchers must be detected
// deterministically BEFORE deserialization — extended to whole-record
// SUBSTITUTION within a directory, not just bit-flips or deletions.
//
// ## Root Cause
// The manifest authenticates WHICH record IDs exist, never WHICH CONTENT each
// record ID carries. AEAD authenticates content but not freshness/generation;
// no per-record generation binding (e.g. keyed hash in the manifest) exists.
//
// ## Remediation Strategy
// Bind each record's content to its record ID in the sealed manifest (keyed
// per-record hash analogous to `derive_store_binding_hash`) and verify it in
// `get_archived_voucher`/`find_transaction_by_id` BEFORE deserialization;
// mismatch => `ArchiveError::IntegrityViolation`.
//
// ## Test Semantics (Fail-First)
// Three genuinely archived states t1->t2->t3 (strictly growing chain).
// Attack: overwrite `<t3>.json` with the exact bytes of `<t2>.json`.
// SOLL: `get_archived_voucher` returns `Err(ArchiveError::IntegrityViolation)`
// (freshness/content binding violated). IST on unpatched code: every check
// passes and the older state t2 is served as `Ok` — assertion FAILS, proving
// the undetectable rollback. Control: an UNMODIFIED archive of the same three
// states must keep loading `Ok` with the full t3 chain (no false positive of
// the future binding).
// =============================================================================
#[test]
fn wh4_05_001_record_substitution_within_directory_must_be_detected() {
    use human_money_core::archive::ArchiveError;

    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let vid = voucher.voucher_id.clone();

    // Build the three evolving states t1 -> t2 -> t3 (growing chains).
    let state1 = voucher.clone();
    let state2 = successor_state(&state1, "wh4-05-001-state-two-t-id", &alice.user_id);
    let t2_id = state2.transactions.last().expect("t2 present").t_id.clone();
    let state3 = successor_state(&state2, "wh4-05-001-state-three-t-id", &alice.user_id);
    let t3_id = state3.transactions.last().expect("t3 present").t_id.clone();

    // --- ATTACK ARCHIVE -----------------------------------------------------
    let dir_attack = tempdir().expect("tempdir creation failed");
    let archive =
        FileVoucherArchive::with_key(dir_attack.path(), AUDIT_KEY);
    archive
        .archive_voucher(&state1, &alice.user_id, standard)
        .expect("archiving t1 must succeed");
    archive
        .archive_voucher(&state2, &alice.user_id, standard)
        .expect("archiving t2 must succeed");
    archive
        .archive_voucher(&state3, &alice.user_id, standard)
        .expect("archiving t3 must succeed");

    let newest_record = record_path(dir_attack.path(), &vid, &t3_id);
    let older_record = record_path(dir_attack.path(), &vid, &t2_id);
    assert!(newest_record.exists(), "test setup: t3 record missing");
    assert!(older_record.exists(), "test setup: t2 record missing");

    // Baseline control INSIDE the attacked archive: while intact, the full t3
    // chain is served.
    let before = archive
        .get_archived_voucher(&vid)
        .expect("baseline lookup must succeed while records are intact");
    assert_eq!(
        before.transactions.len(),
        state3.transactions.len(),
        "test setup: intact archive must serve the newest (longest-chain) state"
    );

    // 2. ATTACK: substitute the CONTENT of the newest record with the exact
    //    bytes of the older genuine record (same-directory whole-record
    //    substitution). Manifest ID-set, AEAD authenticity and location
    //    binding all remain satisfied by construction.
    fs::copy(&older_record, &newest_record).expect("attacker copy must succeed");

    // 3. SECURE INVARIANT (Soll-Verhalten): the freshness/content substitution
    //    MUST be detected deterministically before any state is served.
    let after = archive.get_archived_voucher(&vid);
    assert!(
        matches!(after, Err(ArchiveError::IntegrityViolation(_))),
        "AUDIT-W4-STO-601 VIOLATION: copying the older genuine record <{}>.json \
         over the newest record <{}>.json went UNDETECTED — \
         get_archived_voucher served a ROLLED-BACK history ({} transactions \
         instead of {}) because the sealed manifest pins only the record ID \
         SET, never the per-record content/generation. Whole-record \
         substitution within one directory must yield IntegrityViolation \
         (CWE-354/CWE-345).",
        t2_id,
        t3_id,
        after.as_ref().ok().map(|v| v.transactions.len()).unwrap_or(0),
        state3.transactions.len()
    );

    // --- CONTROL ARCHIVE (no false positive of the future binding) ----------
    let dir_control = tempdir().expect("tempdir creation failed");
    let control = FileVoucherArchive::with_key(dir_control.path(), AUDIT_KEY);
    control
        .archive_voucher(&state1, &alice.user_id, standard)
        .expect("control archiving t1 must succeed");
    control
        .archive_voucher(&state2, &alice.user_id, standard)
        .expect("control archiving t2 must succeed");
    control
        .archive_voucher(&state3, &alice.user_id, standard)
        .expect("control archiving t3 must succeed");

    let untouched = control
        .get_archived_voucher(&vid)
        .expect("unmodified archive must keep loading cleanly");
    assert_eq!(
        untouched.transactions.len(),
        state3.transactions.len(),
        "CONTROL FAILED: an unmanipulated archive must continue to serve the \
         genuine newest state — a content/freshness binding must not produce \
         false positives."
    );
}

// =============================================================================
// FINDING AUDIT-W4-STO-602 (Wave 4 — WH4-05-002, variant a)
// -----------------------------------------------------------------------------
// Finding-ID:    AUDIT-W4-STO-602
// Severity:      Medium
// CWE-Classification: CWE-354 (Improper Validation of Integrity Check Value)
//                     / CWE-345 (Insufficient Verification of Data Authenticity)
// Target Location: src/archive/file_archive.rs:473-498 (`sync_manifest`:
//                  shrinkage-only refusal at :480-489, bootstrap-from-disk at
//                  :497), interplay with :514-555 (`archive_voucher`).
//
// ## Threat Model & Exploitation
// The HMSEC-SA05-09 bookkeeping refuses a manifest rewrite ONLY when the
// on-disk record set SHRANK and is a strict subset of the manifest. Variant
// (a): an attacker deletes the newest record AND injects any extra `.json`
// file (junk). The set no longer shrank (delete + inject = equal size), so the
// guard passes and the NEXT LEGITIMATE `archive_voucher` rewrites the sealed
// manifest over the tampered state — the deletion is LAUNDERED forever, and
// the victim additionally suffers a PERMANENT IntegrityViolation brick on
// every future read (the junk record can never decrypt, and removing it would
// re-diverge the rewritten manifest).
//
// ## Impact Analysis
// Deletion laundering via interleaved legitimate writes defeats the entire
// whole-record detection design; the amplified brick converts a transient
// tamper into persistent self-healing-never data loss for the forensics path.
//
// ## Root Cause
// The divergence guard is a narrow shrinkage heuristic instead of full
// set-divergence refusal: any non-shrinkage divergence (grow/substitute/
// mixed) silently triggers `write_manifest(actual)`.
//
// ## Remediation Strategy
// Refuse the rewrite with `ArchiveError::IntegrityViolation` whenever the
// intact manifest diverges from disk in ANY direction (not only shrinkage);
// alternatively make readers deterministically REPORT the divergence by name.
// A post-laundering opaque content error is NOT acceptable: once the manifest
// was rewritten, the information needed for detection is destroyed forever.
//
// ## Test Semantics (Fail-First)
// Two genuine states archived (intact manifest {t1,t2}); baseline read Ok.
// Attack: remove `<t2>.json`, inject `wh4-junk.json` containing `{}`.
// Legitimate write `archive_voucher(t3)`: SOLL = `Err(IntegrityViolation)`
// (sync refuses arbitrary divergence). IST on unpatched code: sync rewrites
// the manifest to {junk,t1,t3} WITHOUT error (= the laundering proof) — the
// fallback branch then additionally proves there is NO deterministic
// divergence report afterwards (only the opaque junk-decrypt failure), so the
// test FAILS on unpatched code either way.
// =============================================================================
#[test]
fn wh4_05_002a_manifest_sync_must_refuse_diverged_disk_state() {
    use human_money_core::archive::ArchiveError;

    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let vid = voucher.voucher_id.clone();

    let state1 = voucher.clone();
    let state2 = successor_state(&state1, "wh4-05-002-state-two-t-id", &alice.user_id);
    let t2_id = state2.transactions.last().expect("t2 present").t_id.clone();
    let state3 = successor_state(&state2, "wh4-05-002-state-three-t-id", &alice.user_id);

    // 1. SETUP: two genuine states, manifest intact.
    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::with_key(dir.path(), AUDIT_KEY);
    archive
        .archive_voucher(&state1, &alice.user_id, standard)
        .expect("archiving t1 must succeed");
    archive
        .archive_voucher(&state2, &alice.user_id, standard)
        .expect("archiving t2 must succeed");

    let voucher_dir = dir.path().join(&vid);
    let baseline = archive
        .get_archived_voucher(&vid)
        .expect("baseline read must succeed while intact");
    assert_eq!(
        baseline.transactions.len(),
        state2.transactions.len(),
        "test setup: intact archive must serve the newest state"
    );

    // 2. ATTACK: delete the newest record AND inject a junk `.json` file.
    //    On-disk set {t1, junk} vs manifest {t1, t2}: equal size, not a subset
    //    — the shrinkage-only guard does not fire.
    fs::remove_file(record_path(dir.path(), &vid, &t2_id))
        .expect("attacker deletion must succeed");
    fs::write(voucher_dir.join("wh4-junk.json"), b"{}")
        .expect("attacker injection must succeed");

    // 3. LEGITIMATE WRITE: the victim archives the next genuine state.
    let write_result = archive.archive_voucher(&state3, &alice.user_id, standard);

    match write_result {
        // Secure behavior: the sync refuses to enshrine the diverged state.
        Err(ArchiveError::IntegrityViolation(_)) => { /* secure */ }
        Err(other) => panic!(
            "AUDIT-W4-STO-602 VIOLATION (wrong error class): the manifest sync \
             detected the delete+inject divergence but surfaced {:?} instead of \
             ArchiveError::IntegrityViolation — detection must be typed and \
             deterministic (CWE-354/CWE-345).",
            other
        ),
        Ok(()) => {
            // Laundering occurred: the manifest was rewritten over the
            // tampered state without any error (THE vulnerability proof).
            // Alternative secure design would tolerate the write but MUST let
            // readers deterministically report the DIVERGENCE (manifest vs.
            // disk bookkeeping). Prove that no such report exists today:
            let read_after = archive.get_archived_voucher(&vid);
            match read_after {
                Ok(served) => panic!(
                    "AUDIT-W4-STO-602 VIOLATION: after deleting <{}>.json and \
                     injecting junk, the next legitimate archive_voucher \
                     rewrote the sealed manifest WITHOUT error and \
                     get_archived_voucher served a history of {} transactions \
                     — delete+inject tampering was laundered permanently \
                     (CWE-354/CWE-345).",
                    t2_id,
                    served.transactions.len()
                ),
                Err(read_error) => {
                    let msg = read_error.to_string();
                    assert!(
                        msg.contains("manifest") || msg.contains("record set"),
                        "AUDIT-W4-STO-602 VIOLATION: the manifest sync accepted \
                         (laundered) the delete+inject divergence by rewriting \
                         the manifest without error, and the subsequent read \
                         only fails with an OPAQUE content error ('{}') instead \
                         of a deterministic divergence report naming the \
                         manifest/disk mismatch. Once rewritten, the deletion \
                         evidence is destroyed forever and the junk record \
                         bricks every future read (permanent \
                         IntegrityViolation, self-healing-never) \
                         (CWE-354/CWE-345).",
                        msg
                    );
                }
            }
        }
    }
}

// =============================================================================
// FINDING AUDIT-W4-STO-603 (Wave 4 — WH4-05-002, variant b)
// -----------------------------------------------------------------------------
// Finding-ID:    AUDIT-W4-STO-603
// Severity:      Medium
// CWE-Classification: CWE-354 / CWE-345 (as above)
// Target Location: src/archive/file_archive.rs:473-498 (`sync_manifest`
//                  missing-manifest bootstrap at :497) with :514-555
//                  (`archive_voucher` bookkeeping call).
//
// ## Threat Model & Exploitation
// An attacker deletes BOTH the sealed manifest and a genuine record. Because
// `sync_manifest` bootstraps a fresh manifest from raw disk contents whenever
// the manifest file is missing, the attacker simply waits for (or triggers)
// the next legitimate `archive_voucher`: the missing bookkeeping is silently
// regenerated over the reduced record set — deletion detection is RESET
// without any error, and every future read happily serves the rolled-back
// history ({t1, t3}) as fully consistent.
//
// ## Impact Analysis
// Whole-record deletion becomes forensically invisible via one interleaved
// legitimate write: the reader-side missing-manifest guard can never fire
// again because the attacker-induced absence was "healed" from tampered disk
// contents.
//
// ## Root Cause
// Bootstrap-from-disk cannot distinguish "crash between record and manifest
// write on an EMPTY directory" (legitimate fresh archive) from "bookkeeping
// deleted while genuine records exist" (attack/corruption): the latter must
// refuse instead of regenerating.
//
// ## Remediation Strategy
// When the manifest is missing but the voucher directory already contains
// state records, refuse the write with `ArchiveError::IntegrityViolation`
// (deletion cannot be ruled out) instead of bootstrapping from disk.
//
// ## Test Semantics (Fail-First)
// Two genuine states archived; attacker removes the manifest AND `<t2>.json`;
// one legitimate `archive_voucher(t3)` follows. SOLL:
// `Err(ArchiveError::IntegrityViolation)` — silent records exist, deletion
// cannot be ruled out. IST on unpatched code: the manifest is bootstrapped
// from {t1, t3} and the write returns `Ok` — assertion FAILS, proving the
// detection reset.
// =============================================================================
#[test]
fn wh4_05_002b_missing_manifest_must_not_bootstrap_over_deleted_records() {
    use human_money_core::archive::ArchiveError;

    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let vid = voucher.voucher_id.clone();

    let state1 = voucher.clone();
    let state2 = successor_state(&state1, "wh4-05-002b-state-two-t-id", &alice.user_id);
    let t2_id = state2.transactions.last().expect("t2 present").t_id.clone();
    let state3 = successor_state(&state2, "wh4-05-002b-state-three-t-id", &alice.user_id);

    // 1. SETUP: two genuine states, manifest intact.
    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::with_key(dir.path(), AUDIT_KEY);
    archive
        .archive_voucher(&state1, &alice.user_id, standard)
        .expect("archiving t1 must succeed");
    archive
        .archive_voucher(&state2, &alice.user_id, standard)
        .expect("archiving t2 must succeed");

    let voucher_dir = dir.path().join(&vid);

    // 2. ATTACK: destroy the bookkeeping together with a genuine record.
    fs::remove_file(voucher_dir.join("archive_manifest.sealed"))
        .expect("attacker manifest deletion must succeed");
    fs::remove_file(record_path(dir.path(), &vid, &t2_id))
        .expect("attacker record deletion must succeed");

    // 3. LEGITIMATE WRITE: must NOT silently bootstrap the bookkeeping over
    //    the attacker-reduced record set.
    let write_result = archive.archive_voucher(&state3, &alice.user_id, standard);
    assert!(
        matches!(write_result, Err(ArchiveError::IntegrityViolation(_))),
        "AUDIT-W4-STO-603 VIOLATION: after deleting the sealed manifest and the \
         genuine record <{}>.json, the next legitimate archive_voucher \
         BOOTSTRAPPED a fresh manifest from the tampered disk contents and \
         returned {:?} — deletion detection was silently reset and every \
         future read serves the rolled-back {{t1, t3}} history as consistent. \
         A missing manifest above EXISTING records must refuse the rewrite \
         with IntegrityViolation (CWE-354/CWE-345).",
        t2_id,
        write_result.map(|_| "Ok(())".to_string())
    );
}

// =============================================================================
// FINDING AUDIT-W4-STO-604 (Wave 4 — WH4-05-003)
// -----------------------------------------------------------------------------
// Finding-ID:    AUDIT-W4-STO-604
// Severity:      Medium
// CWE-Classification: CWE-521 (Weak Password Requirements)
//                     / CWE-1392 (Use of Default Credentials)
// Target Location: src/storage/file_storage.rs:380-417 (`save_wallet` initial
//                  save — derives/wraps under ANY password without an entropy
//                  floor), :473-509 (`reset_password` — accepts an empty
//                  `new_password` and rewrites the container), :1610-1633
//                  (`derive_key_from_password`; KDF cfg-split: SHA256 fast
//                  path under test/test-utils, Argon2id otherwise — this test
//                  asserts acceptance behavior only, never KDF determinism).
//
// ## Threat Model & Exploitation
// `FileStorage` wraps the master file key under BOTH a password-derived and a
// mnemonic-derived key — but the PASSWORD wrap alone recovers the file key
// (`get_file_key`, Password branch). Neither `save_wallet` (initial creation)
// nor `reset_password` reject an empty credential: a wallet created/reset
// with "" is protected by KDF("", salt) — fully deterministic and offline-
// reconstructable by anyone who obtains `profile.enc` (cloud-synced folder,
// stolen backup). The full wallet including the private signing key decrypts.
//
// ## Impact Analysis
// At-rest confidentiality invariant #1 depends purely on caller discipline.
// The archive received a seal-time empty-password guard (HMSEC-SA05-10); the
// storage layer did not — an asymmetry that leaves the MORE sensitive
// container (raw signing key payload) weaker than archive records.
//
// ## Root Cause
// No credential validation anywhere on the storage key path before key
// material is wrapped/persisted.
//
// ## Remediation Strategy
// Reject empty (zero-entropy) passwords in `save_wallet` (initial save AND
// update path) and in `reset_password` with `StorageError::Generic` BEFORE
// any key derivation/persistence — parity with the HMSEC-SA05-10 archive
// guard.
//
// ## Test Semantics (Fail-First)
// (a) `save_wallet(.., &AuthMethod::Password(""))` MUST return
//     `Err(StorageError::Generic(_))` and leave NO `profile.enc` on disk.
//     IST: returns Ok and persists a container whose password wrap decrypts
//     under KDF("") — FAILS, proving the gap.
// (b) With a wallet created under a VALID password, `reset_password(.., "")`
//     MUST return `Err(StorageError::Generic(_))` and leave `profile.enc`
//     byte-identical (no rewrite). IST: returns Ok and rewrites the container
//     under KDF("") — FAILS, proving the gap.
// =============================================================================
#[test]
fn wh4_05_003_file_storage_must_reject_empty_passwords_at_save_and_reset() {
    use human_money_core::models::profile::{UserProfile, VoucherStore};
    use human_money_core::storage::AuthMethod;
    use human_money_core::{FileStorage, Storage, StorageError};

    let (_standard, _standard_hash, alice, _bob, _voucher, _secrets) =
        setup_voucher_with_one_tx();
    let profile = UserProfile {
        user_id: alice.user_id.clone(),
        ..Default::default()
    };
    let empty_store = VoucherStore::default();

    // --- Aspect (a): initial save under an EMPTY password -------------------
    let dir_a = tempdir().expect("tempdir creation failed");
    let mut storage_a = FileStorage::new(dir_a.path().join("wallet"));

    let save_result =
        storage_a.save_wallet(&profile, &empty_store, &alice, &AuthMethod::Password(""));
    assert!(
        matches!(save_result, Err(StorageError::Generic(_))),
        "AUDIT-W4-STO-604 VIOLATION (a): FileStorage::save_wallet accepted an \
         EMPTY password for the initial wallet save and wrapped the master \
         file key under KDF(\"\", salt) — a deterministic credential anyone \
         with profile.enc (cloud sync, stolen backup) can reconstruct \
         offline, decrypting the full wallet incl. the raw signing key. Zero-\
         entropy credentials must be rejected with StorageError::Generic \
         before persistence (CWE-521/CWE-1392); got {:?}.",
        save_result.map(|_| "Ok(())".to_string())
    );
    assert!(
        !dir_a.path().join("wallet").join("profile.enc").exists(),
        "AUDIT-W4-STO-604 VIOLATION (a): despite the required empty-password \
         rejection, profile.enc was persisted to disk (CWE-521/CWE-1392)."
    );

    // --- Aspect (b): password RESET to an EMPTY password --------------------
    let dir_b = tempdir().expect("tempdir creation failed");
    let mut storage_b = FileStorage::new(dir_b.path().join("wallet"));
    let auth_valid = AuthMethod::Password("wh4-05-03-valid-password");
    storage_b
        .save_wallet(&profile, &empty_store, &alice, &auth_valid)
        .expect("setup save with a valid password must succeed");

    let profile_path = dir_b.path().join("wallet").join("profile.enc");
    let bytes_before = fs::read(&profile_path).expect("profile.enc readable after setup");

    let reset_result = storage_b.reset_password(&alice, "");
    assert!(
        matches!(reset_result, Err(StorageError::Generic(_))),
        "AUDIT-W4-STO-604 VIOLATION (b): FileStorage::reset_password accepted \
         an EMPTY new password and rewrapped the master file key under \
         KDF(\"\", new_salt), downgrading an existing protected wallet to a \
         deterministic offline-reconstructable credential. Zero-entropy \
         credentials must be rejected with StorageError::Generic without any \
         rewrite (CWE-521/CWE-1392); got {:?}.",
        reset_result.map(|_| "Ok(())".to_string())
    );
    let bytes_after = fs::read(&profile_path).expect("profile.enc still readable");
    assert_eq!(
        bytes_before, bytes_after,
        "AUDIT-W4-STO-604 VIOLATION (b): the rejected reset must not rewrite \
         profile.enc — the container was modified despite the empty-password \
         rejection requirement (CWE-521/CWE-1392)."
    );
}
