//! # tests/security_audit_module_05_storage.rs
//!
//! Security Audit — Module 05: Wallet Storage, Key Security & At-Rest Encryption.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. These tests are expected to turn green
//! only after the corresponding remediation has been implemented.
//!
//! Audit scope: src/archive/file_archive.rs, src/storage/file_storage.rs,
//! src/services/mnemonic.rs, src/models/storage_integrity.rs,
//! src/services/integrity_manager.rs.
//!
//! ## Finding Summary
//!
//! | Finding-ID     | Severity | CWE    | Target                                        |
//! |----------------|----------|--------|-----------------------------------------------|
//! | HMSEC-SA05-01  | High     | 312    | archive/file_archive.rs::archive_voucher      |
//! | HMSEC-SA05-02  | High     | 354/345| archive/file_archive.rs::find_transaction_by_id|
//! | HMSEC-SA05-03  | Low      | 209    | services/mnemonic.rs::validate_german         |
//! | HMSEC-SA05-04  | High     | 1258/778| storage/file_storage.rs::load_wallet          |
//! | HMSEC-SA05-05  | High     | 347    | archive/file_archive.rs::read_record           |
//! | HMSEC-SA05-06  | High     | 244/459| models/secure_container.rs::impl Drop          |
//! | HMSEC-SA05-07  | High     | 345/354| storage/file_storage.rs::store_binding_hash    |
//! | HMSEC-SA05-08  | High     | 1188/693| models/conflict.rs::TransactionFingerprint (V2->V3 serde-drop) |
//! | HMSEC-SA05-09  | High     | 345    | archive/file_archive.rs (whole-record delete/relocate) |
//! | HMSEC-SA05-10  | Medium   | 521    | archive/file_archive.rs::new_secure            |
//! | HMSEC-SA05-11  | Medium   | 22/23  | storage/file_storage.rs::get_item_hash/load_arbitrary_data |
//!
//! Report-only findings (documented in the audit report, no deterministic
//! fail-first test feasible without fault injection): torn multi-file save
//! in `FileStorage::save_wallet` (no fsync / non-atomic across two files),
//! direct non-atomic `fs::write` in `save_arbitrary_data`, and TOCTOU race in
//! the PID lock file protocol. Wave 3 additions: path traversal via the `name`
//! parameter of `get_item_hash`/`load_arbitrary_data` now HAS a dedicated
//! fail-first test (HMSEC-SA05-11); remaining report-only items are
//! WH3-05-503 (SA05-04-fix torn-write window bricks the wallet without any
//! recovery path) and WH3-05-507 (raw voucher_id/t_id as archive file names,
//! defense-in-depth rest behind Base58 chain validation).

use human_money_core::archive::file_archive::FileVoucherArchive;
use human_money_core::services::mnemonic::{GERMAN_WORDLIST, MnemonicLanguage, MnemonicProcessor};
use human_money_core::test_utils::setup_voucher_with_one_tx;
use human_money_core::{Transaction, Voucher};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

/// Recursively collects all regular files below `dir`.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

// =============================================================================
// FINDING HMSEC-SA05-01
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-01
// Severity:      High
// CWE:           CWE-312 (Cleartext Storage of Sensitive Information)
// Target:        src/archive/file_archive.rs:61-91 (`FileVoucherArchive::archive_voucher`,
//                admitted by in-code TODO at line 67: "The archive files should be encrypted.")
// Threat Model:  A local attacker with read access to the user's disk (stolen
//                laptop, malware, cloud-synced/backup folder). The wallet core
//                store is encrypted (vouchers.enc, profile.enc), but every
//                archived voucher state is written as canonical JSON PLAINTEXT.
// Impact:        Full disclosure of the forensic voucher history: amounts,
//                transaction chains, did:key identities, signatures and profile
//                data of every state ever seen — bypassing the entire at-rest
//                encryption architecture of System Invariant #1.
// Root Cause:    `archive_voucher` serializes the voucher with
//                `to_canonical_json` and writes it unencrypted to disk; no key
//                derivation, no AEAD container.
// Remediation:   Encrypt each archive record with a password/mnemonic-derived
//                key (ChaCha20-Poly1305 via crypto_symmetric, mirroring
//                FileStorage's ProfileStorageContainer pattern) and derive
//                privacy-preserving file/directory names from hashes instead of
//                raw voucher_id/t_id.
// Test Semantics: After archiving, NO file below the archive root may contain
//                 plaintext voucher material (voucher_id, t_id, did:key,
//                 nominal amount, signature) nor deserialize as a `Voucher`.
//                 FAILS on unpatched code (archive is plaintext JSON).
// =============================================================================
#[test]
fn sa05_01_archived_voucher_states_must_be_encrypted_at_rest() {
    // 1. SETUP: a fully valid voucher with one transfer (FreeTaler standard).
    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();

    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::new_secure(dir.path(), "audit-test-pw");
    archive
        .archive_voucher(&voucher, &alice.user_id, standard)
        .expect("archiving must succeed");

    // 2. Collect everything that was persisted to disk.
    let mut files = Vec::new();
    collect_files(dir.path(), &mut files);
    assert!(
        !files.is_empty(),
        "test setup: archive must have produced state files"
    );

    // Plaintext canaries: identifiers and value data that must never appear
    // unencrypted on disk.
    let last_tx = voucher.transactions.last().expect("voucher has transactions");
    let quoted_amount = format!("\"{}\"", voucher.nominal_value.amount);
    let mut markers: Vec<(&str, String)> = vec![
        ("voucher_id", voucher.voucher_id.clone()),
        ("transaction id", last_tx.t_id.clone()),
        ("creator identity (did:key)", alice.user_id.clone()),
        ("nominal amount", quoted_amount),
    ];
    if let Some(sig) = voucher.signatures.first() {
        markers.push(("signature material", sig.signature.clone()));
    }

    // 3. SECURE INVARIANT (Soll-Verhalten): at-rest confidentiality.
    for file in &files {
        let bytes = fs::read(file).expect("archive file must be readable");
        let text = String::from_utf8_lossy(&bytes);

        // Ciphertext property: an encrypted record cannot deserialize as Voucher.
        assert!(
            serde_json::from_slice::<Voucher>(&bytes).is_err(),
            "HMSEC-SA05-01 VIOLATION: {} stores a deserializable plaintext Voucher. \
             Archive records must be encrypted at rest (CWE-312).",
            file.display()
        );

        for (label, marker) in &markers {
            assert!(
                !text.contains(marker.as_str()),
                "HMSEC-SA05-01 VIOLATION: plaintext {} ('{}...') found in archived \
                 file {}. Archive files must be encrypted at rest (CWE-312).",
                label,
                &marker.chars().take(16).collect::<String>(),
                file.display()
            );
        }
    }
}

// =============================================================================
// FINDING HMSEC-SA05-02
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-02
// Severity:      High
// CWE:           CWE-354 (Improper Validation of Integrity Check Value)
//                / CWE-345 (Insufficient Verification of Data Authenticity)
// Target:        src/archive/file_archive.rs:105-135 (`find_transaction_by_id`
//                silently skips unreadable files via `if let Ok(voucher)`;
//                `get_archived_voucher` deserializes without any check).
//                The archive directory is NOT covered by Storage Integrity
//                (`FileStorage::get_all_item_hashes` only scans the profile
//                directory), so no checksum/signature protects these files.
// Threat Model:  A malicious local actor edits an archived voucher state on
//                disk (e.g. inflates `nominal_value.amount`, shifts
//                transaction timestamps) to poison forensic evidence.
// Impact:        Tampered states are served back into memory and feed the
//                double-spend analysis pipeline
//                (`Wallet::find_transaction_in_stores` -> archive), which can
//                flip "Earliest Wins" conflict resolutions and corrupt
//                ProofOfDoubleSpend evidence. Violates System Invariant #3:
//                manipulations must be detected deterministically BEFORE
//                deserialization.
// Root Cause:    No integrity checksum is written or verified for archive
//                records; deserialization failures are silently swallowed,
//                making tampering undetectable (silent skip == Ok(None)).
// Remediation:   Store a keyed or identity-signed SHA3-256 checksum per
//                archive record (e.g. inside an archive manifest bound to the
//                WalletSeal epoch like LocalIntegrityRecord) and verify it
//                BEFORE `serde_json::from_slice`; surface violations as a
//                dedicated `ArchiveError::IntegrityViolation` variant instead
//                of skipping.
// Test Semantics: A bit-level manipulated archive record MUST cause
//                 `find_transaction_by_id` / `find_voucher_by_tx_id` to return
//                 an error; tampered voucher data must never be returned as
//                 Ok(Some(_)). FAILS on unpatched code (returns the tampered
//                 voucher).
// =============================================================================
#[test]
fn sa05_02_tampered_archive_record_must_be_detected_before_deserialization() {
    // 1. SETUP: archive a valid voucher state.
    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let last_tx = voucher.transactions.last().expect("voucher has transactions");

    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::new_secure(dir.path(), "audit-test-pw");
    archive
        .archive_voucher(&voucher, &alice.user_id, standard)
        .expect("archiving must succeed");

    let record_path = dir
        .path()
        .join(&voucher.voucher_id)
        .join(format!("{}.json", last_tx.t_id));
    assert!(record_path.exists(), "test setup: archive record missing");

    // 2. ATTACK: local actor flips one bit mid-file directly on disk.
    //    The manipulation is format-agnostic (no assumption about the stored
    //    representation): integrity MUST hold for ANY stored byte layout and be
    //    verified BEFORE the record is deserialized into domain types.
    let mut bytes = fs::read(&record_path).expect("record readable");
    let flip_index = bytes.len() / 2;
    bytes[flip_index] ^= 0xFF;
    fs::write(&record_path, &bytes).expect("attacker write must succeed");

    // 3. SECURE INVARIANT (Soll-Verhalten): integrity violation surfaces as a
    //    typed error; manipulated data is never handed back to callers.
    let by_tx = archive.find_transaction_by_id(&last_tx.t_id);
    assert!(
        by_tx.is_err(),
        "HMSEC-SA05-02 VIOLATION: find_transaction_by_id served tampered archive \
         data (byte flipped on disk) without any integrity error. Got Ok with \
         voucher_id={:?}. Manipulations must be detected deterministically via \
         checksums BEFORE deserialization (CWE-354/CWE-345).",
        by_tx
            .as_ref()
            .ok()
            .and_then(|o| o.as_ref())
            .map(|(v, _)| v.voucher_id.clone())
    );

    let by_voucher = archive.find_voucher_by_tx_id(&last_tx.t_id);
    assert!(
        by_voucher.is_err(),
        "HMSEC-SA05-02 VIOLATION: find_voucher_by_tx_id served tampered archive \
         data without any integrity error (CWE-354/CWE-345)."
    );
}

// =============================================================================
// FINDING HMSEC-SA05-03
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-03
// Severity:      Low
// CWE:           CWE-209 (Generation of Error Message Containing Sensitive
//                Information)
// Target:        src/services/mnemonic.rs:414-459 (`MnemonicProcessor::validate_german`,
//                line ~426: `format!("Word '{}' not in German wordlist", word)`).
// Threat Model:  A user's secret BIP-39 phrase is validated against the wrong
//                wordlist (e.g. English phrase, German default) or contains a
//                corrupted segment. Error strings propagate into UI logs /
//                telemetry via AppService::validate_mnemonic.
// Impact:        Verbatim words of the SECRET recovery phrase are disclosed in
//                error output (logs, crash reports, support tickets). Each
//                leaked word reduces mnemonic entropy and aids offline
//                brute-forcing of the remaining words. Violates System
//                Invariant #4 (memory/log hygiene for mnemonics).
// Root Cause:    The custom German validator embeds the offending phrase token
//                itself into the error message instead of its index.
// Remediation:   Echo only positional metadata ("Ungültiges Wort Nummer {n}",
//                deliberately German — every English phrasing collides as a
//                substring with BIP-39 English wordlist words), mirroring the
//                bip39 crate's index-based `UnknownWord(usize)` error design.
// Test Semantics: Validating a real English mnemonic against the German
//                 wordlist MUST produce an error that does not contain ANY of
//                 the secret phrase's words. FAILS on unpatched code (the
//                 first non-German word is echoed verbatim).
// =============================================================================
#[test]
fn sa05_03_mnemonic_validation_errors_must_not_disclose_phrase_words() {
    // Fixed text that the remediated error output may legitimately contain
    // (VoucherCoreError::Crypto display prefix + positional German wording).
    // Phrase words colliding with this sentinel would be false positives of
    // the substring check, so such phrases are regenerated (e.g. "error" is
    // itself a BIP-39 English word).
    const ERROR_SENTINEL: &str = "Cryptography error: Ungültiges Wort Nummer 24";

    // Victim's secret recovery phrase (English wordlist).
    let secret_phrase = loop {
        let phrase = MnemonicProcessor::generate(12, MnemonicLanguage::English)
            .expect("mnemonic generation failed");
        let has_foreign_word = phrase.split_whitespace().any(|w| !GERMAN_WORDLIST.contains(&w));
        let collides_with_sentinel = phrase
            .split_whitespace()
            .any(|w| ERROR_SENTINEL.contains(w));
        if has_foreign_word && !collides_with_sentinel {
            break phrase;
        }
        // Astronomically unlikely; retry to keep the PoC deterministic.
    };

    // Recovery flow misconfigured to the German wordlist.
    let err = MnemonicProcessor::validate(&secret_phrase, MnemonicLanguage::German)
        .expect_err("cross-language validation must fail");

    let msg = err.to_string();
    for word in secret_phrase.split_whitespace() {
        assert!(
            !msg.contains(word),
            "HMSEC-SA05-03 VIOLATION: mnemonic validation error discloses a word of \
             the secret recovery phrase ('{}') in its message ('{}'). Error output \
             must never contain phrase material (CWE-209).",
            word,
            msg
        );
    }
}

// =============================================================================
// FINDING HMSEC-SA05-04
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-04
// Severity:      High
// CWE:           CWE-1258 (Hidden Functionality / Obfuscated Logic in
//                Persistence) / CWE-778 (Insufficient Logging of Explicit
//                State Transition — silent rollback without any signal)
// Target:        src/storage/file_storage.rs::load_wallet (silent
//                `VoucherStore::default()` fallback) and ::save_wallet (two
//                independent tmp+rename pairs with no cross-file binding;
//                the persistent `file_key` never changes across saves).
// Threat Model:  A local attacker (or a crash between the two renames, or a
//                sync/backup restore) replaces or reverts `vouchers.enc`.
//                Because the file key is stable across saves, an OLDER record
//                still decrypts cleanly under the current profile — the AEAD
//                layer cannot detect the generation mismatch. A deleted store
//                silently degrades to `VoucherStore::default()`.
// Impact:        Silent state rollback: spent/archived vouchers are resurrected
//                into the active wallet, corrupting double-spend forensics and
//                "Earliest Wins" conflict resolution; silent data loss presents
//                as a valid empty wallet. Violates System Invariants #2/#3:
//                loss/corruption/rollback of a store must never pass as a valid
//                state without any error signal.
// Root Cause:    No cross-file generation binding between profile.enc and
//                vouchers.enc; load_wallet treats "profile present but store
//                stale" identically to a fresh first-time creation.
// Remediation:   Bind the exact serialized VoucherStorageContainer bytes via
//                SHA3-256 into ProfileStorageContainer on every save_wallet
//                (`store_binding_hash`, #[serde(default)] for legacy wallets)
//                and verify it BEFORE decryption on load. Mismatch =>
//                StorageError::StateConflict.
//
//                Design note (documented intentional leniency): a MISSING
//                vouchers.enc alongside an existing profile remains tolerated
//                by design ("test_load_with_missing_voucher_store" in
//                tests/persistence/file_storage.rs, documented in
//                tests/README.md) and is separately flagged by the signed
//                Storage Integrity layer (IntegrityReport::MissingItems). The
//                rollback scenario below has no such detection at load time
//                and MUST hard-fail.
// Test Semantics: After reverting vouchers.enc to the previous generation's
//                 exact bytes, load_wallet MUST return Err(StorageError::
//                 StateConflict); it must never return Ok carrying the
//                 resurrected voucher. FAILS on unpatched code (returns Ok
//                 with the rolled-back store silently restored).
// =============================================================================
#[test]
fn sa05_04_rolled_back_voucher_store_must_not_load_silently() {
    use human_money_core::FileStorage;
    use human_money_core::StorageError;
    use human_money_core::models::profile::{UserProfile, VoucherStore};
    use human_money_core::storage::AuthMethod;
    use human_money_core::wallet::Wallet;

    // 1. SETUP: identity + one fully valid voucher (FreeTaler standard).
    let (_standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let auth = AuthMethod::Password("sa05-04-pw");

    let dir = tempdir().expect("tempdir creation failed");
    let mut storage = FileStorage::new(dir.path().join("wallet"));

    let profile = UserProfile {
        user_id: alice.user_id.clone(),
        ..Default::default()
    };

    // Generation N: exactly one active voucher instance in the store.
    let mut store_with_voucher = VoucherStore::default();
    let local_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("local instance id derivation failed");
    store_with_voucher.vouchers.insert(
        local_id.clone(),
        human_money_core::VoucherInstance {
            voucher: voucher.clone(),
            status: human_money_core::VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        },
    );

    storage
        .save_wallet(&profile, &store_with_voucher, alice, &auth)
        .expect("initial save must succeed");
    assert!(
        storage.profile_exists(),
        "test setup: profile.enc must exist after save"
    );

    // Snapshot the exact store generation bound to this profile generation.
    let store_path = storage.user_storage_path.join("vouchers.enc");
    let committed_bytes = fs::read(&store_path).expect("vouchers.enc readable");

    // 2. Advance the wallet state: the voucher leaves the active store
    //    (simulating spend/transfer), producing a NEWER consistent pair.
    let empty_store = VoucherStore::default();
    storage
        .save_wallet(&profile, &empty_store, alice, &auth)
        .expect("second save must succeed");

    // 3. ATTACK / SIMULATED CRASH: revert vouchers.enc to the previous
    //    generation. Torn multi-file write, backup restore or a local actor
    //    performing a rollback all produce exactly this byte state. The old
    //    record decrypts fine under the unchanged file key.
    fs::write(&store_path, &committed_bytes).expect("attacker write must succeed");

    // 4. SECURE INVARIANT (Soll-Verhalten): the stale generation must be
    //    rejected with an explicit conflict error. Resurrecting the spent
    //    voucher silently would poison forensic evidence.
    match storage.load_wallet(&auth) {
        Err(StorageError::StateConflict(_)) => { /* secure behavior */ }
        other => panic!(
            "HMSEC-SA05-04 VIOLATION: load_wallet accepted a ROLLED-BACK \
             vouchers.enc without any conflict error (got {:?}). An older \
             store generation that still decrypts under the persistent file \
             key must be detected via a cross-file generation binding, never \
             served as valid wallet state (CWE-1258/CWE-778).",
            other.map(|(p, s, _)| {
                (p.user_id.clone(), format!("{} voucher instances", s.vouchers.len()))
            })
        ),
    }

    // 5. DOCUMENTED INTENTIONAL DESIGN (control assertion, no logic change):
    //    a *missing* vouchers.enc stays tolerated by load_wallet by explicit
    //    design decision (recovery-friendly first-load semantics; see
    //    tests/persistence/file_storage.rs::test_load_with_missing_voucher_store
    //    and tests/README.md). Detection for that scenario is delegated to the
    //    signed Storage Integrity layer (IntegrityReport::MissingItems, see
    //    tests/persistence/integrity.rs). This control pins that contract so
    //    future hardening cannot accidentally break the documented behavior.
    fs::remove_file(&store_path).expect("removing vouchers.enc must succeed");
    let (loaded_profile, loaded_store, _identity) =
        storage.load_wallet(&auth).expect("missing-store tolerance is documented design");
    assert_eq!(loaded_profile.user_id, alice.user_id);
    assert!(
        loaded_store.vouchers.is_empty(),
        "missing vouchers.enc must degrade to the documented empty-store default"
    );
}

// =============================================================================
// FINDING HMSEC-SA05-05
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-05
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature)
//                / CWE-693 (Protection Mechanism Failure — downgrade bypass)
// Target:        src/archive/file_archive.rs::read_record (legacy plaintext
//                fallback) + looks_like_envelope (purely structural heuristic
//                without any authenticity check).
// Threat Model:  A malicious local actor does NOT flip bits inside the sealed
//                envelope (that fails AEAD verification as intended by the
//                HMSEC-SA05-02 remediation). Instead they REPLACE the whole
//                record on disk with canonical PLAINTEXT Voucher JSON carrying
//                manipulated financial data. The structural envelope heuristic
//                does not match, so the legacy fallback deserializes the
//                forged plaintext directly — completely bypassing every
//                integrity/authenticity check.
// Impact:        Tampered amounts and transaction chains flow into
//                find_transaction_by_id / get_archived_voucher and poison the
//                double-spend forensics pipeline exactly like the bit-flip
//                attack that HMSEC-SA05-02 was supposed to prevent. At-rest
//                encryption effectively becomes an OPT-IN integrity mechanism:
//                stripping the format escapes all verification.
// Root Cause:    `read_record` accepts any non-envelope JSON as a "legacy
//                plaintext record" without any authentication; since the
//                HMSEC-SA05-01 remediation every writer seals records, so the
//                fallback serves no legitimate write path anymore — only an
//                attacker.
// Remediation:   Strict rejection of unsealed records: any archive record that
//                does not carry the sealed-envelope format markers yields
//                ArchiveError::IntegrityViolation BEFORE deserialization.
//                Backward-compatibility note: this deliberately breaks reading
//                of pre-encryption ("legacy") archives. Users of such ancient
//                archives can re-import states via the public API; accepting
//                unauthenticated forensic data is not a secure alternative.
// Test Semantics: Replacing a sealed record with canonical plaintext Voucher
//                 JSON (manipulated amount) MUST cause find_transaction_by_id
//                 and get_archived_voucher to return
//                 Err(ArchiveError::IntegrityViolation(_)). FAILS on unpatched
//                 code (returns Ok(Some(forged voucher))).
// =============================================================================
#[test]
fn sa05_05_plaintext_archive_record_must_be_rejected_as_integrity_violation() {
    use human_money_core::StorageError;

    // 1. SETUP: archive one valid voucher state via the sealed writer.
    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let last_tx = voucher.transactions.last().expect("voucher has transactions");

    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::new_secure(dir.path(), "audit-test-pw");
    archive
        .archive_voucher(&voucher, &alice.user_id, standard)
        .expect("archiving must succeed");

    let record_path = dir
        .path()
        .join(&voucher.voucher_id)
        .join(format!("{}.json", last_tx.t_id));
    assert!(record_path.exists(), "test setup: archive record missing");

    // 2. ATTACK: replace the sealed envelope entirely with canonical
    //    PLAINTEXT voucher JSON carrying an inflated amount. This is the
    //    legacy-downgrade variant of the HMSEC-SA05-02 bit-flip attack: no
    //    envelope marker remains, so the structural heuristic misclassifies
    //    the forged record as a trusted "legacy plaintext" record.
    let mut forged = voucher.clone();
    forged.nominal_value.amount = format!("{}0", voucher.nominal_value.amount);
    let forged_plaintext =
        serde_json::to_vec(&forged).expect("forged voucher serialization failed");
    fs::write(&record_path, &forged_plaintext).expect("attacker write must succeed");

    // 3. SECURE INVARIANT (Soll-Verhalten): unsealed records are rejected as
    //    integrity violations BEFORE deserialization; the forged voucher is
    //    never served back into the forensics pipeline.
    let by_tx = archive.find_transaction_by_id(&last_tx.t_id);
    assert!(
        matches!(by_tx, Err(StorageError::IntegrityViolation(_))),
        "HMSEC-SA05-05 VIOLATION: find_transaction_by_id accepted a plaintext \
         forged record instead of failing with IntegrityViolation (got {:?}). \
         Unencrypted records bypass the AEAD integrity check — the legacy \
         downgrade path must be rejected (CWE-347/CWE-693).",
        by_tx
            .as_ref()
            .ok()
            .and_then(|o| o.as_ref())
            .map(|(v, _)| v.nominal_value.amount.clone())
    );

    let by_voucher = archive.get_archived_voucher(&voucher.voucher_id);
    assert!(
        matches!(by_voucher, Err(StorageError::IntegrityViolation(_))),
        "HMSEC-SA05-05 VIOLATION: get_archived_voucher accepted a plaintext \
         forged record instead of failing with IntegrityViolation \
         (CWE-347/CWE-693)."
    );
}

// =============================================================================
// FINDING HMSEC-SA05-06
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-06
// Severity:      High
// CWE:           CWE-244 (Improper Clearing of Heap Memory Before Release)
//                / CWE-459 (Incomplete Cleanup)
// Target:        src/models/secure_container.rs :: impl Drop for SecureContainer
//                (~line 182, flagged CRITICAL-uncovered in temp/uncovered_code.md
//                line ~124). The Drop impl only zeroized protected/iv/ciphertext/
//                tag/signature; recipients[].encrypted_key (Base64 of the
//                per-recipient wrapped payload keys — the most sensitive remnant
//                of all) and salt (PBKDF2 salt for Symmetric containers) were
//                never cleared.
// Threat Model:  Memory scrapers, crash-dump exfiltration, core-dump collection
//                or swap/hibernation-file analysis after a SecureContainer was
//                processed and dropped. Wrapped payload keys recovered from
//                stale heap memory directly decrypt captured containers,
//                defeating the forward-secrecy design of the ephemeral key
//                wrapping.
// Impact:        Sensitive key-material remnants persist in freed heap memory;
//                the memory-hygiene guarantee (System Invariant #4) was purely
//                declarative — a mutant removing ANY zeroize call would survive
//                the whole suite because Drop behavior had no regression guard.
// Root Cause:    Incomplete field coverage in the Drop implementation plus a
//                missing invariant test (the in-crate unit test only checks
//                that drop does not panic).
// Remediation:   Zeroize every JweRecipient::encrypted_key and the symmetric
//                salt alongside the existing fields. JSON header values
//                (unprotected / recipient header) cannot be reliably zeroized
//                (nested Strings inside serde_json::Value); they are released
//                (set to None) as defense-in-depth, documented limitation.
// Test Semantics: Unsafe heap-buffer inspection: known canary buffers are
//                 leaked into a SecureContainer, dropped in place, and their
//                 heap bytes inspected afterwards (suffix from byte 32 to stay
//                 clear of allocator free-list metadata written into the first
//                 ~16 bytes of a freed chunk). (a) ciphertext buffer fully
//                 zeroed = regression guard against mutants; (b) encrypted_key
//                 and salt buffers fully zeroed = THIS assert fails on
//                 unpatched code (fields untouched by Drop), proving the
//                 coverage gap. Note honestly: String zeroize cannot cover
//                 reallocated copies — this pins the achievable in-place level,
//                 it does not replace an allocator strategy.
// =============================================================================
#[test]
fn sa05_06_secure_container_drop_must_zeroize_all_sensitive_fields() {
    use human_money_core::models::secure_container::{JweRecipient, SecureContainer};
    use std::ptr;

    const INSPECT_OFFSET: usize = 32;

    // Local helper: reads `buf.len() - INSPECT_OFFSET` bytes starting at
    // `INSPECT_OFFSET` from a possibly-freed heap buffer. Formal UB, but the
    // established technique for verifying in-place zeroization; performed
    // immediately after the drop without any intermediate allocations that
    // could reuse the chunks.
    let tail_is_zeroed = |ptr: *const u8, len: usize| -> bool {
        if len <= INSPECT_OFFSET {
            return true;
        }
        unsafe { std::slice::from_raw_parts(ptr.add(INSPECT_OFFSET), len - INSPECT_OFFSET) }
            .iter()
            .all(|&b| b == 0)
    };

    // 1. SETUP: container with distinctive canary heap buffers.
    //    (Full literal: functional update syntax `..Default::default()` is
    //    forbidden for Drop types.)
    let mut container = SecureContainer {
        protected: "P".repeat(96),
        unprotected: None,
        recipients: Vec::new(),
        iv: "I".repeat(24),
        ciphertext: "C".repeat(96),
        tag: "T".repeat(16),
        signature: "S".repeat(96),
        et: human_money_core::models::secure_container::EncryptionType::Symmetric,
        salt: Some("Z".repeat(64)),
        i: "i".repeat(8),
        c: human_money_core::models::secure_container::PayloadType::Generic(
            "audit".to_string(),
        ),
    };
    container.recipients.push(JweRecipient {
        header: None,
        encrypted_key: "K".repeat(96),
    });

    // Capture the heap locations BEFORE the move into the Box (moving a String
    // relocates only its (ptr,len,cap) triple, never the heap buffer).
    let ct_ptr = container.ciphertext.as_ptr();
    let ct_len = container.ciphertext.len();
    let ek_ptr = container.recipients[0].encrypted_key.as_ptr();
    let ek_len = container.recipients[0].encrypted_key.len();
    let salt_ptr = container.salt.as_ref().expect("salt set").as_ptr();
    let salt_len = container.salt.as_ref().expect("salt set").len();

    // Sanity: canaries really live in distinct non-empty heap buffers.
    assert!(ct_len > INSPECT_OFFSET && ek_len > INSPECT_OFFSET && salt_len > INSPECT_OFFSET);
    assert_ne!(ct_ptr, ek_ptr);

    // 2. ACTION: leak the box, run ONLY the Drop implementation in place.
    let raw = Box::into_raw(Box::new(container));
    unsafe { ptr::drop_in_place(raw) };
    // `raw`'s box header intentionally leaks (test-scoped); the field Strings
    // were deallocated by their own Drop AFTER SecureContainer::drop ran.

    // 3. SECURE INVARIANT (Soll-Verhalten): every sensitive heap buffer must be
    //    zeroed before release.
    let ct_zeroed = tail_is_zeroed(ct_ptr, ct_len);
    assert!(
        ct_zeroed,
        "HMSEC-SA05-06 VIOLATION: SecureContainer.ciphertext was not zeroized \
         on Drop — regression against CWE-244 (this guards previously covered \
         fields against mutant removal)."
    );

    let ek_zeroed = tail_is_zeroed(ek_ptr, ek_len);
    assert!(
        ek_zeroed,
        "HMSEC-SA05-06 VIOLATION: JweRecipient.encrypted_key (wrapped payload \
         key material) survives Drop in plaintext heap memory (CWE-244/\
         CWE-459). Every recipient's wrapped key MUST be zeroized."
    );

    let salt_zeroed = tail_is_zeroed(salt_ptr, salt_len);
    assert!(
        salt_zeroed,
        "HMSEC-SA05-06 VIOLATION: SecureContainer.salt survives Drop uncleared \
         (CWE-244/CWE-459)."
    );
}

// =============================================================================
// FINDING HMSEC-SA05-07 (Wave 3 — WH3-05-501)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-07
// Severity:      High
// CWE:           CWE-345 (Insufficient Verification of Data Authenticity)
//                / CWE-354 (Improper Validation of Integrity Check Value)
// Target:        src/storage/file_storage.rs :: ProfileStorageContainer.
//                store_binding_hash (~110-121, plaintext JSON field guarded
//                by `#[serde(default)]`), load_wallet (~293-302, the check is
//                skipped entirely when the field is absent: `if let Some`),
//                save_wallet (~425-427, binding written as an UNKEYED
//                SHA3-256 over the vouchers.enc bytes).
// Threat Model:  profile.enc is an UNENCRYPTED JSON container (only its inner
//                payloads are AEAD-sealed), so a local attacker with write
//                access can disable the HMSEC-SA05-04 rollback detection in
//                two key-free ways:
//                (a) FIELD STRIPPING: remove `store_binding_hash` from the
//                    JSON; serde(default) deserializes it as `None` and
//                    load_wallet skips the generation check completely;
//                (b) HASH RECOMPUTATION: restore a Gen-N-1 vouchers.enc and
//                    overwrite the field with SHA3-256 over those stale bytes;
//                    since get_hash is unkeyed, the check passes.
// Impact:        The SA05-04 remediation detects only ACCIDENTAL torn writes,
//                not the addressed attacker: spent/archived vouchers are
//                silently resurrected (state rollback), poisoning double-spend
//                forensics exactly like the original finding.
// Root Cause:    The binding hash carries no authenticity (no keyed MAC, not
//                covered by the signed LocalIntegrityRecord) and its absence
//                stays tolerated without limit even for containers rewritten
//                by post-fix code.
// Remediation:   Authenticate the binding (keyed MAC under the file key or
//                inclusion in the signed integrity record) and close the
//                post-migration strip-tolerance: containers written by fixed
//                code MUST carry the field; absence = tamper => StateConflict.
// Test Semantics: After reverting vouchers.enc to the previous generation's
//                 exact bytes, BOTH variants (field stripped; field recomputed
//                 over the stale store) MUST make load_wallet return
//                 Err(StorageError::StateConflict). FAILS on unpatched code
//                 (both variants return Ok with the resurrected voucher).
// =============================================================================
#[test]
fn sa05_07_store_binding_hash_must_be_authenticated_and_mandatory() {
    use human_money_core::models::profile::{UserProfile, VoucherStore};
    use human_money_core::services::crypto::get_hash;
    use human_money_core::storage::AuthMethod;
    use human_money_core::wallet::Wallet;
    use human_money_core::{FileStorage, StorageError, VoucherInstance, VoucherStatus};

    // Rewrites profile.enc (plaintext JSON container) through `f`.
    fn modify_profile_json(
        path: &Path,
        f: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) {
        let mut value: serde_json::Value = serde_json::from_slice(
            &fs::read(path).expect("profile.enc must be readable"),
        )
        .expect("profile.enc must be valid JSON");
        f(value.as_object_mut().expect("profile.enc must be a JSON object"));
        fs::write(path, serde_json::to_vec(&value).expect("re-serialization failed"))
            .expect("attacker write must succeed");
    }

    // 1. SETUP: identity + one fully valid voucher; two generations saved.
    let (_standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();
    let auth = AuthMethod::Password("sa05-07-pw");

    let dir = tempdir().expect("tempdir creation failed");
    let mut storage = FileStorage::new(dir.path().join("wallet"));
    let profile = UserProfile {
        user_id: alice.user_id.clone(),
        ..Default::default()
    };

    let mut store_with_voucher = VoucherStore::default();
    let local_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("local instance id derivation failed");
    store_with_voucher.vouchers.insert(
        local_id.clone(),
        VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        },
    );

    storage
        .save_wallet(&profile, &store_with_voucher, alice, &auth)
        .expect("initial save must succeed");

    let store_path = storage.user_storage_path.join("vouchers.enc");
    let profile_path = storage.user_storage_path.join("profile.enc");
    let gen1_store_bytes = fs::read(&store_path).expect("Gen1 vouchers.enc readable");

    let empty_store = VoucherStore::default();
    storage
        .save_wallet(&profile, &empty_store, alice, &auth)
        .expect("second save must succeed");

    // Baseline control: the consistent Gen2 pair loads cleanly.
    assert!(
        storage.load_wallet(&auth).is_ok(),
        "test setup: consistent Gen2 pair must load without conflict"
    );

    // 2. ATTACK (a): strip the binding field entirely, restore the stale store.
    fs::write(&store_path, &gen1_store_bytes).expect("attacker write must succeed");
    modify_profile_json(&profile_path, |obj| {
        obj.remove("store_binding_hash");
    });

    match storage.load_wallet(&auth) {
        Err(StorageError::StateConflict(_)) => { /* secure behavior */ }
        other => panic!(
            "HMSEC-SA05-07 VIOLATION (a): load_wallet accepted vouchers.enc \
             rolled back to Gen1 after an attacker simply REMOVED the plaintext \
             store_binding_hash field from profile.enc — serde(default) turned \
             it into None and the generation check was skipped. The binding \
             must be authenticated AND mandatory post-migration; got {:?} \
             (CWE-345/CWE-354).",
            other.map(|(p, s, _)| (p.user_id.clone(), s.vouchers.len()))
        ),
    }

    // 3. ATTACK (b): keep the stale store but RECOMPUTE the unkeyed hash over
    //    its bytes — no secret knowledge required at all.
    modify_profile_json(&profile_path, |obj| {
        obj.insert(
            "store_binding_hash".to_string(),
            serde_json::Value::String(get_hash(&gen1_store_bytes)),
        );
    });

    match storage.load_wallet(&auth) {
        Err(StorageError::StateConflict(_)) => { /* secure behavior */ }
        other => panic!(
            "HMSEC-SA05-07 VIOLATION (b): load_wallet accepted a Gen1 rollback \
             whose binding hash was recomputed by the attacker as plain \
             SHA3-256 over the stale vouchers.enc bytes — the binding is \
             unauthenticated and therefore forgeable. A keyed/signed binding \
             must reject this with StateConflict; got {:?} (CWE-345/CWE-354).",
            other.map(|(p, s, _)| (p.user_id.clone(), s.vouchers.len()))
        ),
    }
}

// =============================================================================
// FINDING HMSEC-SA05-08 (Wave 3 — WH3-05-502)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-08
// Severity:      High
// CWE:           CWE-1188 (Insecure Default Initialization of Data)
//                / CWE-693 (Protection Mechanism Failure)
// Target:        src/models/conflict.rs :: TransactionFingerprint (~17-63,
//                sender_ephemeral_pub/trap_r/trap_s carry #[serde(default)]);
//                src/models/voucher.rs :: TrapData (~88-99, same pattern);
//                src/storage/file_storage.rs :: load_own_fingerprints /
//                load_known_fingerprints (plain serde deserialization without
//                any schema-version gate).
// Threat Model:  The V2->V3 protocol change REPLACED fingerprint fields
//                ({u, blinded_id} -> {sender_ephemeral_pub, trap_r, trap_s})
//                without any persistence-layer schema gate. A wallet upgraded
//                from V2 loads its encrypted stores successfully: unknown V2
//                fields are silently DROPPED by serde, defaulted V3 fields
//                materialize as EMPTY strings. The documented "complete and
//                immutable" OwnFingerprints.history is then written back in
//                the lossy V3 shape on the next save — V2 identity
//                reconstruction material for old conflicts is destroyed
//                irreversibly. (Scope note: the Wallet state/stranding side is
//                covered elsewhere; THIS test pins the storage/serialization
//                contract.)
// Impact:        Silent destruction of forensic evidence: degraded spend
//                fingerprints (empty trap shards) lose their trap meaning and
//                the lossy rewrite makes the damage permanent.
// Root Cause:    No schema version field / migration gate in the fingerprint
//                containers; #[serde(default)] converts a format change into
//                silent data destruction instead of a loud failure or a real
//                data-preserving migration.
// Remediation:   Either reject legacy-shaped stores with a hard error
//                (InvalidFormat/UnsupportedSchemaVersion) or preserve the
//                legacy fields verbatim until an explicit migration upgrades
//                them; never accept-and-degrade, and never rewrite history
//                with empty-shard placeholders.
// Test Semantics: A byte-exact V2-era own_fingerprints payload (u/blinded_id,
//                 layer2_signature present, NO trap fields) inside a valid
//                 encrypted container MUST either fail to load (schema gate)
//                 or survive load + save round trip verbatim/upgraded. It must
//                 NEVER load as a hybrid (layer2_signature set while trap_r/
//                 trap_s empty) nor be rewritten lossily. FAILS on unpatched
//                 code (silent Ok with degraded hybrids + lossy write-back).
// =============================================================================
#[test]
fn sa05_08_legacy_v2_fingerprint_data_must_not_be_silently_degraded() {
    use base64::{engine::general_purpose, Engine as _};
    use human_money_core::models::conflict::{OwnFingerprints, TransactionFingerprint};
    use human_money_core::models::profile::{UserProfile, VoucherStore};
    use human_money_core::services::crypto::{decrypt_data, encrypt_data};
    use human_money_core::storage::AuthMethod;
    use human_money_core::FileStorage;

    const PW: &str = "sa05-08-pw";

    let (_standard, _standard_hash, alice, _bob, _voucher, _secrets) = setup_voucher_with_one_tx();
    let auth = AuthMethod::Password(PW);

    let dir = tempdir().expect("tempdir creation failed");
    let mut storage = FileStorage::new(dir.path().join("wallet"));

    let profile = UserProfile {
        user_id: alice.user_id.clone(),
        ..Default::default()
    };
    storage
        .save_wallet(&profile, &VoucherStore::default(), alice, &auth)
        .expect("initial save must succeed");

    // CONTROL: prove the plumbing itself works — current-shape stores round
    // trip through save/load losslessly.
    let mut control = OwnFingerprints::default();
    control.history.insert(
        "control-key".to_string(),
        vec![TransactionFingerprint {
            ds_tag: "control-ds-tag".to_string(),
            t_id: "control-t-id".to_string(),
            encrypted_timestamp: 42,
            layer2_signature: "control-l2-sig".to_string(),
            sender_ephemeral_pub: "control-ephemeral-pub".to_string(),
            deletable_at: "2030-01-01T00:00:00Z".to_string(),
            trap_r: "control-trap-r".to_string(),
            trap_s: "control-trap-s".to_string(),
            // New V3 fields (serde default shape); this control fingerprint
            // only pins the storage round trip and is never signature-checked.
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
        }],
    );
    storage
        .save_own_fingerprints(&auth, &control)
        .expect("control save must succeed");
    let reloaded = storage
        .load_own_fingerprints(&auth)
        .expect("control load must succeed");
    assert_eq!(
        reloaded.history.get("control-key"),
        control.history.get("control-key"),
        "test harness sanity: current-shape round trip must be lossless"
    );

    // Recover the master file key exactly like the host app can (session key
    // unwraps the wrapped file key stored in the plaintext profile container),
    // so a byte-exact V2-era payload can be planted inside a VALID container.
    let session_key = storage
        .derive_key_for_session(PW)
        .expect("session key derivation failed");
    let profile_container: serde_json::Value = serde_json::from_slice(
        &fs::read(storage.user_storage_path.join("profile.enc"))
            .expect("profile.enc readable"),
    )
    .expect("profile.enc is a JSON container");
    let wrapped = general_purpose::STANDARD
        .decode(
            profile_container["password_wrapped_key_with_nonce"]
                .as_str()
                .expect("wrapped file key present"),
        )
        .expect("base64 decode of wrapped file key failed");
    let file_key: [u8; 32] = decrypt_data(&session_key, &wrapped)
        .expect("file key unwrap failed")
        .try_into()
        .expect("file key has 32 bytes");

    // ATTACK: plant the exact JSON shape a pre-V3 installation persists —
    // identity material u/blinded_id present, V3 shard fields absent.
    let legacy_payload = serde_json::json!({
        "active_fingerprints": {},
        "history": {
            "legacy-v2-spend-t-id": [{
                "u": "v2-identity-point-u-canary",
                "blinded_id": "v2-blinded-id-canary",
                "ds_tag": "legacy-v2-ds-tag",
                "t_id": "legacy-v2-spend-t-id",
                "encrypted_timestamp": 1700000000000u64,
                "layer2_signature": "v2-layer2-signature-canary",
                "deletable_at": "2030-01-01T00:00:00Z"
            }]
        }
    });
    let encrypted = encrypt_data(&file_key, legacy_payload.to_string().as_bytes())
        .expect("payload encryption failed");
    let container = serde_json::json!({
        "encrypted_store_payload": general_purpose::STANDARD.encode(encrypted)
    });
    fs::write(
        storage.user_storage_path.join("own_fingerprints.enc"),
        serde_json::to_vec(&container).expect("container serialization failed"),
    )
    .expect("legacy-container write must succeed");

    // SECURE INVARIANT (Soll-Verhalten): schema gate OR preservation — never
    // silent degradation, never lossy write-back.
    match storage.load_own_fingerprints(&auth) {
        Err(_) => {
            // Schema-gate variant: hard failure instead of silent loss is an
            // accepted secure outcome; nothing else to pin here.
        }
        Ok(own) => {
            // (1) No degraded hybrid may be accepted: a spend fingerprint with
            //     an L2 signature but empty trap shards lost its forensic meaning.
            for fingerprint in own.history.values().flatten() {
                let shards_missing =
                    fingerprint.trap_r.is_empty() || fingerprint.trap_s.is_empty();
                assert!(
                    !(!fingerprint.layer2_signature.is_empty() && shards_missing),
                    "HMSEC-SA05-08 VIOLATION: legacy V2 spend fingerprint loaded as \
                     degraded hybrid (layer2_signature present while trap_r/trap_s \
                     default to empty strings) — serde field-drop destroyed the \
                     trap data without any schema gate (CWE-1188/CWE-693)."
                );
            }

            // (2) Write-back must not destroy the documented "complete and
            //     immutable" history: the V2 identity material must still be on
            //     disk, or the entry must have been genuinely upgraded to V3.
            storage
                .save_own_fingerprints(&auth, &own)
                .expect("write-back save must succeed");
            let written: serde_json::Value = serde_json::from_slice(
                &fs::read(storage.user_storage_path.join("own_fingerprints.enc"))
                    .expect("own_fingerprints.enc readable"),
            )
            .expect("container is JSON");
            let payload = decrypt_data(
                &file_key,
                &general_purpose::STANDARD
                    .decode(written["encrypted_store_payload"].as_str().expect("payload present"))
                    .expect("base64 decode failed"),
            )
            .expect("round-trip decryption failed");
            let round_trip: serde_json::Value =
                serde_json::from_slice(&payload).expect("payload is JSON");
            let entry = &round_trip["history"]["legacy-v2-spend-t-id"][0];
            let preserved_verbatim =
                entry.get("u").is_some() && entry.get("blinded_id").is_some();
            let upgraded_to_v3 = entry["trap_r"].as_str().is_some_and(|s| !s.is_empty())
                && entry["trap_s"].as_str().is_some_and(|s| !s.is_empty());
            assert!(
                preserved_verbatim || upgraded_to_v3,
                "HMSEC-SA05-08 VIOLATION: the 'complete and immutable' own-\
                 fingerprint history was rewritten LOSSILY — V2 identity material \
                 (u/blinded_id) is gone and no V3 shards exist. Silent destruction \
                 of forensic evidence via serde field-drop (CWE-1188/CWE-693)."
            );
        }
    }
}

// =============================================================================
// FINDING HMSEC-SA05-09 (Wave 3 — WH3-05-504)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-09
// Severity:      High
// CWE:           CWE-345 (Insufficient Verification of Data Authenticity)
// Target:        src/archive/file_archive.rs :: read_record (AEAD binds ONLY
//                the plaintext, never the storage location),
//                get_archived_voucher (~362-393, silently serves the remaining
//                older state after deletion of newer records),
//                find_transaction_by_id (~396-419, global directory scan with
//                pure location-based attribution).
// Threat Model:  Whole-record operations stay undetectable because the sealed
//                envelope authenticates content, not context:
//                (a) DELETE/ROLLBACK: removing the newest `<t_id>.json` makes
//                    get_archived_voucher silently serve the older state —
//                    forensic history rolls back without any error;
//                (b) SWAP/MISATTRIBUTION: relocating a genuine encrypted
//                    envelope into another voucher's directory makes the global
//                    scan attribute that transaction history to the wrong
//                    voucher ("Earliest Wins" corruption).
//                The signed Storage Integrity layer does NOT cover archive
//                subdirectories (get_all_item_hashes scans only events/).
// Impact:        Undetectable forensic rollback and cross-voucher history
//                misattribution poison double-spend analysis — extending the
//                SA05-02 gap from bit-level tampering to whole-record level.
// Root Cause:    No manifest / location binding: nothing ties a valid envelope
//                to its voucher directory or counts expected records.
// Remediation:   Bind each record to its location/context (e.g. include
//                voucher_id as AEAD associated data, plus a per-voucher
//                manifest counting states) and verify BEFORE serving results.
// Test Semantics: (a) After deleting the newest of two archived states,
//                 get_archived_voucher MUST fail (detected loss) instead of
//                 silently returning the older state. (b) After copying a
//                 genuine envelope of voucher A into voucher B's directory,
//                 get_archived_voucher(B) MUST NOT return a voucher carrying
//                 A's voucher_id. FAILS on unpatched code (both attacks pass
//                 silently).
// =============================================================================
#[test]
fn sa05_09_archive_record_deletion_and_relocation_must_be_detectable() {
    
    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();

    // Fabricate a strictly newer state (longer chain). The archive layer is
    // agnostic to chain signatures — whole-record operations are the target.
    let original_last_t_id = voucher
        .transactions
        .last()
        .expect("voucher has transactions")
        .t_id
        .clone();
    let mut newer_state = voucher.clone();
    newer_state.transactions.push(Transaction {
        t_id: "sa05-09-newest-state-t-id".to_string(),
        t_time: "2031-01-01T00:00:00Z".to_string(),
        prev_hash: format!("prev-of-{}", original_last_t_id),
        recipient_id: alice.user_id.clone(),
        amount: voucher.nominal_value.amount.clone(),
        ..Default::default()
    });

    // --- Aspect (a): deleting the newest record silently rolls back history ---
    let dir_a = tempdir().expect("tempdir creation failed");
    let archive_a = FileVoucherArchive::new_secure(dir_a.path(), "audit-test-pw");
    archive_a
        .archive_voucher(&voucher, &alice.user_id, standard)
        .expect("archiving state N must succeed");
    archive_a
        .archive_voucher(&newer_state, &alice.user_id, standard)
        .expect("archiving state N+1 must succeed");

    let newest_record = dir_a
        .path()
        .join(&voucher.voucher_id)
        .join("sa05-09-newest-state-t-id.json");
    assert!(newest_record.exists(), "test setup: newest record missing");

    // Control: while intact, the newest state wins (longest chain).
    let before = archive_a
        .get_archived_voucher(&voucher.voucher_id)
        .expect("control lookup must succeed");
    assert_eq!(
        before.transactions.len(),
        newer_state.transactions.len(),
        "test setup: newest state must be selected while both records exist"
    );

    // ATTACK: remove ONLY the newest state file (silent forensic rollback).
    fs::remove_file(&newest_record).expect("attacker deletion must succeed");

    let after_delete = archive_a.get_archived_voucher(&voucher.voucher_id);
    assert!(
        after_delete.is_err(),
        "HMSEC-SA05-09 VIOLATION (a): deleting the newest archive record went \
         UNDETECTED — get_archived_voucher silently served the older state \
         ({} transactions) instead of reporting the loss. Whole-record deletion \
         must be detected via a manifest/location binding (CWE-345).",
        after_delete.as_ref().ok().map(|v| v.transactions.len()).unwrap_or(0)
    );

    // --- Aspect (b): relocating a genuine envelope re-attributes history ---
    let dir_b = tempdir().expect("tempdir creation failed");
    let archive_b = FileVoucherArchive::new_secure(dir_b.path(), "audit-test-pw");

    let mut victim_b = voucher.clone();
    victim_b.voucher_id = "Sa05_09_SwapVictimB000000000000000000".to_string();
    archive_b
        .archive_voucher(&victim_b, &alice.user_id, standard)
        .expect("archiving victim B must succeed");

    archive_b
        .archive_voucher(&newer_state, &alice.user_id, standard)
        .expect("archiving genuine A newest state must succeed");

    let genuine_newest = dir_b
        .path()
        .join(&voucher.voucher_id)
        .join("sa05-09-newest-state-t-id.json");
    assert!(genuine_newest.exists(), "test setup: genuine A record missing");

    let smuggled_target = dir_b
        .path()
        .join(&victim_b.voucher_id)
        .join("smuggled_state.json");
    fs::copy(&genuine_newest, &smuggled_target).expect("attacker relocation must succeed");

    match archive_b.get_archived_voucher(&victim_b.voucher_id) {
        Err(_) => { /* secure: location/context binding rejects foreign envelopes */ }
        Ok(relocated) => assert_eq!(
            relocated.voucher_id,
            victim_b.voucher_id,
            "HMSEC-SA05-09 VIOLATION (b): moving a genuine encrypted envelope from \
             voucher A's directory into B's directory re-attributed A's history — \
             get_archived_voucher(B) returned a voucher carrying id '{}'. The AEAD \
             seal authenticates only the plaintext, never the storage location \
             (CWE-345).",
            relocated.voucher_id
        ),
    }
}

// =============================================================================
// FINDING HMSEC-SA05-10 (Wave 3 — WH3-05-505)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-10
// Severity:      Medium
// CWE:           CWE-521 (Weak Password Requirements)
//                / CWE-1392 (Use of Default Credentials)
// Target:        src/archive/file_archive.rs :: new_secure (~122-127, stores
//                the password string unchecked); src/services/crypto_symmetric.rs ::
//                encrypt_symmetric_password (~206) / decrypt_symmetric_password
//                (~247, no is_empty guard — PBKDF2("", salt) yields a fully
//                deterministic, offline-reconstructable key).
// Threat Model:  A host app passing an obvious empty default password obtains
//                an archive whose record keys derive deterministically from ""
//                and a salt stored NEXT TO the ciphertext. Any scanner knowing
//                the public envelope format (hmc-archive-v1 + pbkdf2-sha512)
//                decrypts every record within seconds — collapsing at-rest
//                confidentiality AND integrity (with the known key, valid-looking
//                forged records pass AEAD verification).
// Impact:        Confidentiality (Invariant #1) and integrity (Invariant #3)
//                become purely obfuscation for every host that forwards "".
// Root Cause:    No entropy floor anywhere on the archive key path; unlike
//                FileStorage there is no second factor that would catch an
//                empty password downstream.
// Remediation:   Guard: construction (future Result-returning constructor) or,
//                compiling today, the first seal operation must reject empty
//                passwords with a typed error before any bytes touch disk.
// Test Semantics: FileVoucherArchive::new_secure(dir, "") followed by
//                 archive_voucher MUST yield Err, and no record file may have
//                 been persisted. FAILS on unpatched code (seals happily under
//                 the empty-password key).
// =============================================================================
#[test]
fn sa05_10_archive_construction_with_empty_password_must_be_rejected() {
    let (standard, _standard_hash, alice, _bob, voucher, _secrets) = setup_voucher_with_one_tx();

    let dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::new_secure(dir.path(), "");

    // SECURE INVARIANT (Soll-Verhalten): an empty password carries zero
    // entropy — the first seal operation must reject it before any record is
    // persisted (a construction-time guard would change the signature and is
    // equally acceptable; this assertion covers the seal-time enforcement).
    let seal_result = archive.archive_voucher(&voucher, &alice.user_id, standard);
    assert!(
        seal_result.is_err(),
        "HMSEC-SA05-10 VIOLATION: FileVoucherArchive accepted an EMPTY password \
         and sealed records under PBKDF2(\"\", salt) — a key every offline \
         scanner can derive in seconds given the public envelope format. An \
         empty password must never produce working record keys (CWE-521)."
    );

    // Guard completeness: despite the rejected seal, no readable record file
    // may exist below the archive root.
    let mut files = Vec::new();
    collect_files(dir.path(), &mut files);
    assert!(
        files.is_empty(),
        "HMSEC-SA05-10 VIOLATION: an empty-password archive wrote {} record(s) \
         despite the required guard (CWE-521).",
        files.len()
    );
}

// =============================================================================
// FINDING HMSEC-SA05-11 (Wave 3 — WH3-05-506)
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA05-11
// Severity:      Medium
// CWE:           CWE-22 (Improper Limitation of a Pathname to a Restricted
//                Directory) / CWE-23 (Relative Path Traversal)
// Target:        src/storage/file_storage.rs :: get_item_hash (~1076-1083,
//                raw `user_storage_path.join(name)` — absolute names REPLACE
//                the wallet base, relative traversals escape it);
//                load_arbitrary_data (~866-888, NO name validation) vs.
//                save_arbitrary_data (~838-842, rejects '/'|'\\'|"..").
// Threat Model:  Storage is public trait API and Tauri hosts forward UI input:
//                get_item_hash("/abs/path") returns a SHA3 hash oracle over
//                ANY process-readable file; relative traversals read outside
//                the wallet directory. load_arbitrary_data applies none of the
//                write-side checks (sanitize-on-write-only asymmetry) and its
//                NotFound-vs-AuthenticationFailed distinction leaks existence
//                semantics for reachable paths.
// Impact:        Violates storage boundary discipline: operations escape the
//                wallet directory (defense-in-depth against host-layer input
//                injection), leaking hashes/existence of foreign files.
// Root Cause:    The established save-side validation convention was never
//                applied to the read/hash paths.
// Remediation:   Apply the identical name validation ('/'|'\\'|".." rejection,
//                Err(Generic)) to get_item_hash and load_arbitrary_data before
//                any path construction.
// Test Semantics: get_item_hash with an absolute path OUTSIDE the wallet base
//                 and with "../../outside_secret.txt" MUST return
//                 Err(Generic) (like save); load_arbitrary_data("../outside")
//                 MUST return the SAME rejection class instead of NotFound
//                 (consistency). FAILS on unpatched code (hash oracle returns
//                 Ok; load returns NotFound).
// =============================================================================
#[test]
fn sa05_11_arbitrary_data_read_paths_must_enforce_name_sanitization() {
    use human_money_core::models::profile::{UserProfile, VoucherStore};
    use human_money_core::storage::AuthMethod;
    use human_money_core::{FileStorage, StorageError};

    let (_standard, _standard_hash, alice, _bob, _voucher, _secrets) = setup_voucher_with_one_tx();
    let auth = AuthMethod::Password("sa05-11-pw");

    let dir = tempdir().expect("tempdir creation failed");
    let outside_file = dir.path().join("outside_secret.txt");
    fs::write(&outside_file, b"top-secret-outside-content").expect("outside fixture write");

    let mut storage = FileStorage::new(dir.path().join("wallet"));
    let profile = UserProfile {
        user_id: alice.user_id.clone(),
        ..Default::default()
    };
    storage
        .save_wallet(&profile, &VoucherStore::default(), alice, &auth)
        .expect("initial save must succeed");

    // DOCUMENTED CONVENTION (control, passes today): the WRITE side validates
    // names before any path construction.
    let save_reject = storage.save_arbitrary_data(&auth, "../outside", b"x");
    assert!(
        matches!(save_reject, Err(StorageError::Generic(_))),
        "test setup: save_arbitrary_data must reject traversal names (existing convention)"
    );

    // SECURE INVARIANT (Soll-Verhalten): the hash path must obey the SAME
    // boundary — absolute replacement and relative traversal both rejected.
    let absolute_outside = outside_file.to_string_lossy().into_owned();
    for hostile_name in [absolute_outside, "../../outside_secret.txt".to_string()] {
        match storage.get_item_hash(&hostile_name) {
            Err(StorageError::Generic(_)) => {}
            other => panic!(
                "HMSEC-SA05-11 VIOLATION: get_item_hash accepted hostile item name \
                 {:?} — raw join() lets absolute paths REPLACE the wallet base and \
                 relative traversals ESCAPE it, turning the method into a hash \
                 oracle over arbitrary process-readable files. Expected the save-\
                 side rejection (Err(Generic)), got {:?} (CWE-22/CWE-23).",
                hostile_name,
                other
                    .map(|h| format!("Ok(<sha3:{}...>)", h.chars().take(8).collect::<String>()))
            ),
        }
    }

    // CONSISTENCY (Soll): the READ side must apply the SAME validation class
    // as the write side — NotFound would leak path-resolution semantics rather
    // than rejecting the hostile name itself.
    match storage.load_arbitrary_data(&auth, "../outside") {
        Err(StorageError::Generic(_)) => {}
        other => panic!(
            "HMSEC-SA05-11 VIOLATION: load_arbitrary_data does not enforce the name \
             validation that save_arbitrary_data applies (sanitize-on-write-only \
             asymmetry). Expected Err(Generic) for '../outside', got {:?} \
             (CWE-22/CWE-23).",
            other.map(|bytes| format!("Ok(<{} bytes>)", bytes.len()))
        ),
    }
}
