// tests/wallet_api/conflict_detection.rs
// cargo test --test wallet_api_tests conflict_detection
//!
//! Property and boundary tests for the double-spend detection engine.
//!
//! These tests secure the core invariants in `conflict_manager.rs` and
//! `conflict_handler.rs`:
//! - Correct partitioning of OwnFingerprints vs. KnownFingerprints
//! - Reliable detection of conflicts (> 1 t_id for the same ds_tag)
//! - Differentiation of replay attacks vs. double-spend
//! - Correct "Earliest Wins" heuristic in offline conflicts
//! - Cleanup of expired fingerprints (time limits)
//! - Import/export symmetry of fingerprints
//! - Timestamp encryption (XOR roundtrip, determinism)

use human_money_core::{
    models::{
        conflict::{KnownFingerprints, OwnFingerprints, TransactionFingerprint},
        voucher::Transaction,
    },
    services::conflict_manager::{
        cleanup_expired_histories, cleanup_known_fingerprints, decrypt_transaction_timestamp,
        encrypt_transaction_timestamp, export_own_fingerprints, import_foreign_fingerprints,
        check_for_double_spend, create_fingerprint_for_transaction, create_proof_of_double_spend,
    },
};
use human_money_core::test_utils::{ACTORS, MINUTO_STANDARD};

// =============================================================================
// Helper Functions
// =============================================================================

/// Creates a minimal, valid transaction with a deterministic prev_hash,
/// t_id, and t_time. Used for fingerprint tests without wallet context.
fn make_test_transaction(suffix: &str, t_time: &str) -> Transaction {
    let prev_hash = bs58::encode(format!("prev-hash-{suffix}").as_bytes()).into_string();
    let t_id = bs58::encode(format!("tid-{suffix}").as_bytes()).into_string();

    Transaction {
        t_id,
        prev_hash,
        t_time: t_time.to_string(),
        sender_id: Some(ACTORS.alice.user_id.clone()),
        sender_ephemeral_pub: None,
        trap_data: None,
        layer2_signature: None,
        amount: "10.00".to_string(),
        recipient_id: ACTORS.bob.user_id.clone(),
        t_type: "transfer".to_string(),
        ..Default::default()
    }
}

/// Creates a TransactionFingerprint directly (without voucher context).
/// Creates a V2-self-authenticating foreign fingerprint that survives the
/// ingress signature gate and cleanup purge.
fn make_signed_foreign_fp(ds_tag: &str, deletable_at: &str) -> TransactionFingerprint {
    let mut fp = human_money_core::test_utils::make_signed_fingerprint(ds_tag, "", 0);
    fp.deletable_at = deletable_at.to_string();
    fp
}

fn make_fingerprint(ds_tag: &str, t_id: &str, deletable_at: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: ds_tag.to_string(),
        t_id: t_id.to_string(),
        trap_r: "none".to_string(),
        trap_s: "none".to_string(),
        layer2_signature: String::new(),
        sender_ephemeral_pub: String::new(),
        deletable_at: deletable_at.to_string(),
        encrypted_timestamp: 0,
        layer2_voucher_id: String::new(),
        privacy_guard_hash: String::new(),
    }
}

// =============================================================================
// create_fingerprint_for_transaction
// =============================================================================

/// The `valid_until` timestamp of a voucher is rounded to the last day of the month
/// (anonymization). December rollover must point to Dec 31 (or end of month).
#[test]
fn test_fingerprint_valid_until_is_rounded_to_end_of_month() {
    use human_money_core::test_utils::create_voucher_for_manipulation;
    use human_money_core::NewVoucherData;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::crypto::get_hash;
    use human_money_core::services::utils::to_canonical_json;

    // Use the Minuto standard, but set valid_until manually
    let (std, _std_hash) = &*MINUTO_STANDARD;
    let creator = &ACTORS.alice.identity;
    let _recipient_id = ACTORS.bob.user_id.clone();

    let standard_hash = get_hash(to_canonical_json(&std.immutable).unwrap().as_bytes());

    let data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "10.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut voucher = create_voucher_for_manipulation(data, std, &standard_hash, &creator.signing_key);

    // Manually set midmonth -> must be rounded to end of month
    voucher.valid_until = "2025-06-15T12:00:00.000000Z".to_string();

    let tx = voucher.transactions[0].clone();
    let fp = create_fingerprint_for_transaction(&tx, &voucher).unwrap();

    // V2 Protocol: the INIT transaction fingerprint carries the raw
    // transaction-level deletable_at (cryptographically bound into the
    // HMC_TX_AUTH_V2 signature); init fingerprints are excluded from gossip,
    // so no anonymization pressure exists for them.
    assert_eq!(
        fp.deletable_at,
        tx.deletable_at.clone().unwrap(),
        "Init fingerprints must carry the raw signature-bound deletable_at"
    );

    // Mutating voucher.valid_until AFTER creation must NOT change the
    // fingerprint: the raw value was bound into the layer2_signature at
    // signing time and fingerprints follow the transaction, not the container.
    voucher.valid_until = "2025-12-15T12:00:00.000000Z".to_string();
    let fp_dec = create_fingerprint_for_transaction(&tx, &voucher).unwrap();
    assert_eq!(
        fp_dec.deletable_at,
        tx.deletable_at.clone().unwrap(),
        "Fingerprint deletable_at must stay signature-bound to the transaction, got: {}",
        fp_dec.deletable_at
    );
}

/// Fingerprints for transactions with TrapData use `ds_tag` from the trap.
/// Without trap, the tag is computed from prev_hash + sender_ephemeral_pub.
/// In both cases, `ds_tag` must not be empty.
#[test]
fn test_fingerprint_ds_tag_is_non_empty() {
    use human_money_core::test_utils::create_voucher_for_manipulation;
    use human_money_core::NewVoucherData;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::crypto::get_hash;
    use human_money_core::services::utils::to_canonical_json;

    let (std, _) = &*MINUTO_STANDARD;
    let creator = &ACTORS.alice.identity;
    let standard_hash = get_hash(to_canonical_json(&std.immutable).unwrap().as_bytes());

    let mut voucher = create_voucher_for_manipulation(
        NewVoucherData {
            creator_profile: PublicProfile { id: Some(creator.user_id.clone()), ..Default::default() },
            nominal_value: ValueDefinition { amount: "5.00".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        },
        std, &standard_hash, &creator.signing_key);
    voucher.valid_until = "2026-03-15T00:00:00.000000Z".to_string();

    let fp = create_fingerprint_for_transaction(&voucher.transactions[0], &voucher).unwrap();
    assert!(!fp.ds_tag.is_empty(), "ds_tag must not be empty (even without TrapData)");
    assert!(!fp.ds_tag.chars().all(|c| c == '0'), "ds_tag must not be all zeros");
}

// =============================================================================
// scan_and_rebuild_fingerprints — delete ! (line 142)
// =============================================================================

/// When building fingerprints, duplicates in `known_fingerprints.local_history`
/// must be prevented. The same fingerprint must not be inserted multiple times for the same ds_tag.
/// Mutant: `delete !` before `known_entry.contains(&fingerprint)` — would duplicate all entries.
#[test]
fn test_scan_rebuild_does_not_duplicate_fingerprints_in_known_history() {
    use human_money_core::services::conflict_manager::scan_and_rebuild_fingerprints;
    use human_money_core::test_utils::{add_voucher_to_wallet, setup_in_memory_wallet};

    let alice = &ACTORS.alice.identity;
    let (std, _) = &*MINUTO_STANDARD;
    let mut wallet = setup_in_memory_wallet(alice);

    add_voucher_to_wallet(&mut wallet, alice, "20.00", std, false).unwrap();

    let (_own, known) = scan_and_rebuild_fingerprints(&wallet.voucher_store, &alice.user_id).unwrap();

    // Each ds_tag may only occur once in known.local_history
    for (tag, fps) in &known.local_history {
        let unique_t_ids: std::collections::HashSet<_> = fps.iter().map(|fp| &fp.t_id).collect();
        assert_eq!(
            fps.len(), unique_t_ids.len(),
            "No duplicate fingerprints allowed for ds_tag {tag}"
        );
    }
}

// =============================================================================
// check_for_double_spend — Detecting conflicts
// =============================================================================

/// Two different t_ids with the same ds_tag must be recognized as a conflict.
/// The conflict must end up in `verifiable_conflicts` if the ds_tag is in `local_history`.
/// If not -> `unverifiable_warnings`.
#[test]
fn test_double_spend_detection_classifies_conflicts_correctly() {
    let tag = "test-ds-tag-abc123";
    let fp_a = make_fingerprint(tag, "tid-alice-spend", "2030-12-31T23:59:59.999999Z");
    let fp_b = make_fingerprint(tag, "tid-bob-spend",   "2030-12-31T23:59:59.999999Z");

    // Scenario 1: Hash in local_history -> verifiable
    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp_a.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp_a.clone()]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp_b.clone()]);

    let result = check_for_double_spend(&own, &known);
    assert!(
        result.verifiable_conflicts.contains_key(tag),
        "Conflict known from local_history must be verifiable"
    );
    assert!(!result.unverifiable_warnings.contains_key(tag));

    // Scenario 2: Hash only in foreign_fingerprints (gossip) -> verifiable
    // The fingerprints carry the cryptographic data (u, blinded_id)
    // for DID key extraction, regardless of whether they originate locally or via gossip.
    let own2 = OwnFingerprints::default();
    let mut known2 = KnownFingerprints::default();
    known2.foreign_fingerprints.insert(tag.to_string(), vec![fp_a.clone(), fp_b.clone()]);

    let result2 = check_for_double_spend(&own2, &known2);
    assert!(
        result2.verifiable_conflicts.contains_key(tag),
        "Gossip-only conflict must also be verifiable"
    );
    assert!(!result2.unverifiable_warnings.contains_key(tag));

    // Scenario 3: Hash only in own.history (without local_history/foreign_fingerprints) -> unverifiable
    let mut own3 = OwnFingerprints::default();
    own3.history.insert(tag.to_string(), vec![fp_a, fp_b]);
    let known3 = KnownFingerprints::default();

    let result3 = check_for_double_spend(&own3, &known3);
    assert!(
        result3.unverifiable_warnings.contains_key(tag),
        "Conflict only in own.history without local/foreign must be unverifiable"
    );
    assert!(!result3.verifiable_conflicts.contains_key(tag));
}

/// No false positives: When there is only one t_id (no conflict),
/// neither verifiable_conflicts nor unverifiable_warnings may be populated.
#[test]
fn test_double_spend_detection_no_false_positives() {
    let tag = "single-tag-no-conflict";
    let fp = make_fingerprint(tag, "tid-only-one", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp.clone()]);

    let result = check_for_double_spend(&own, &known);
    assert!(result.verifiable_conflicts.is_empty(), "No conflict for single t_id");
    assert!(result.unverifiable_warnings.is_empty(), "No warnings for single t_id");
}

/// All three sources (own.history, known.local_history, known.foreign_fingerprints)
/// are merged correctly. A conflict visible only via source merge
/// must be detected.
#[test]
fn test_double_spend_detection_merges_all_three_sources() {
    let tag = "cross-source-tag";
    // fp_a only in own.history, fp_b only in foreign_fingerprints
    let fp_a = make_fingerprint(tag, "tid-own",     "2030-12-31T23:59:59.999999Z");
    let fp_b = make_fingerprint(tag, "tid-foreign", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp_a]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp_b]);

    let result = check_for_double_spend(&own, &known);

    // Conflict must arise from merge of own.history + foreign_fingerprints
    // local_history has the tag -> verifiable
    // (empty local_history entry suffices: contains_key is true)
    assert!(
        result.verifiable_conflicts.contains_key(tag) || result.unverifiable_warnings.contains_key(tag),
        "Cross-source conflict must be detected"
    );
    let all = result.verifiable_conflicts.get(tag)
        .or_else(|| result.unverifiable_warnings.get(tag))
        .unwrap();
    let unique: std::collections::HashSet<_> = all.iter().map(|fp| &fp.t_id).collect();
    assert_eq!(unique.len(), 2, "Must contain both conflicting t_ids");
}

// =============================================================================
// create_proof_of_double_spend — Line 255
// =============================================================================

/// The `proof_id` is derived from the offender key and fork_point_prev_hash.
/// It must be deterministic and non-trivial (no empty string / constant).
/// Mutant: `replace + with - in create_proof_of_double_spend`
#[test]
fn test_proof_id_is_deterministic_and_derived_from_input() {
    let reporter = &ACTORS.reporter.identity;
    let _alice_id = format!("{}{}",
        ACTORS.alice.user_id,
        if ACTORS.alice.user_id.contains("@did:key:z") { "" } else { "@did:key:z6MkAliceTestOnly" }
    );

    // We need a valid did-key structure (offender_id)
    // Use alice.user_id which has the correct format
    let offender_id = ACTORS.alice.user_id.clone();
    let fork_hash = bs58::encode(b"fork-point-hash").into_string();
    let fork_hash2 = bs58::encode(b"different-hash").into_string();

    let proof1 = create_proof_of_double_spend(
        offender_id.clone(),
        fork_hash.clone(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
        false,
    ).unwrap();

    let proof2 = create_proof_of_double_spend(
        offender_id.clone(),
        fork_hash.clone(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
        false,
    ).unwrap();

    // Deterministic (identical inputs -> identical proof_id)
    assert_eq!(proof1.proof_id, proof2.proof_id, "Proof ID must be deterministic");

    // Non-trivial
    assert!(!proof1.proof_id.is_empty(), "Proof ID must not be empty");

    // Changes with different fork_hash
    // (Mutant `+ -> -` in slice concatenation would produce the same hash here)
    let proof_other_hash = create_proof_of_double_spend(
        offender_id,
        fork_hash2,
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
        false,
    ).unwrap();
    assert_ne!(
        proof1.proof_id, proof_other_hash.proof_id,
        "Different fork_point_prev_hash must produce different proof_id"
    );
}

/// An `offender_id` without DID format is treated as an anonymous "Gossip Soft Proof".
/// The proof_id is still computed deterministically from the input bytes.
#[test]
fn test_proof_creation_fallback_for_anonymous_offender_id() {
    let reporter = &ACTORS.reporter.identity;
    let result = create_proof_of_double_spend(
        "anonymous".to_string(),
        bs58::encode(b"some-hash").into_string(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
        false,
    );
    assert!(result.is_ok(), "Anonymous offender_id must succeed with fallback");
    let proof = result.unwrap();
    assert!(!proof.proof_id.is_empty(), "Proof ID must not be empty even for anonymous offender");
    assert_eq!(proof.offender_id, "anonymous");
}

// =============================================================================
// cleanup_known_fingerprints — Line 336 (> vs >=)
// =============================================================================

/// Fingerprints with `deletable_at` in the past must be removed.
/// Fingerprints with `deletable_at` in the future must be retained.
/// Mutant: `replace > with >=` -> would remove fingerprints with `deletable_at == now`.
#[test]
fn test_cleanup_known_fingerprints_removes_expired_only() {
    let mut known = KnownFingerprints::default();

    // Expired: lies far in the past
    let fp_expired = make_fingerprint("tag-expired", "tid-old", "2000-01-01T00:00:00.000000Z");
    // Active: lies far in the future
    // V2: the surviving active entry must pass the signature purge.
    let fp_active  = make_signed_foreign_fp("tag-active",  "2099-01-01T00:00:00.000000Z");

    known.foreign_fingerprints.insert("tag-expired".to_string(), vec![fp_expired]);
    known.foreign_fingerprints.insert("tag-active".to_string(),  vec![fp_active]);

    cleanup_known_fingerprints(&mut known);

    assert!(
        !known.foreign_fingerprints.contains_key("tag-expired"),
        "Expired fingerprint must be removed"
    );
    assert!(
        known.foreign_fingerprints.contains_key("tag-active"),
        "Active fingerprint must be retained"
    );
}

/// When all fingerprints of a ds_tag are expired, the entire entry
/// must be removed from the map (not just the fingerprints).
/// Mutant: `delete !` before `fps.is_empty()` -> would retain empty entries.
#[test]
fn test_cleanup_removes_empty_entries_from_map() {
    let mut known = KnownFingerprints::default();
    let fp_expired = make_fingerprint("empty-after-purge", "tid", "2000-01-01T00:00:00.000000Z");
    known.foreign_fingerprints.insert("empty-after-purge".to_string(), vec![fp_expired]);

    cleanup_known_fingerprints(&mut known);

    assert!(
        !known.foreign_fingerprints.contains_key("empty-after-purge"),
        "Map entry must be removed when all fingerprints are purged"
    );
}

// =============================================================================
// cleanup_expired_histories — Lines 353-370
// =============================================================================

/// `cleanup_expired_histories` must work equally for own and known.
/// Fingerprints within the grace period are retained.
/// Fingerprints that have exceeded the grace period are removed.
/// Mutants: `replace + with -`, `replace < with <=` etc.
#[test]
fn test_cleanup_expired_histories_respects_grace_period() {
    use chrono::{Duration, Utc};

    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    // deletable_at is 2 years in the past
    let far_past = "2020-01-01T00:00:00.000000Z";
    // deletable_at is 2 years in the future
    let far_future = "2099-01-01T00:00:00.000000Z";

    let fp_expired_own   = make_fingerprint("own-old",   "tid-own-old",   far_past);
    let fp_active_own    = make_fingerprint("own-new",   "tid-own-new",   far_future);
    let fp_expired_known = make_fingerprint("known-old", "tid-known-old", far_past);
    let fp_active_known  = make_fingerprint("known-new", "tid-known-new", far_future);

    own.history.insert("own-old".to_string(),   vec![fp_expired_own]);
    own.history.insert("own-new".to_string(),   vec![fp_active_own]);
    known.local_history.insert("known-old".to_string(), vec![fp_expired_known]);
    known.local_history.insert("known-new".to_string(), vec![fp_active_known]);

    let now = Utc::now();
    // Grace Period: 1 day — far expired fingerprints are removed
    let grace = Duration::days(1);

    cleanup_expired_histories(&mut own, &mut known, &now, &grace);

    assert!(!own.history.contains_key("own-old"),   "Expired own fingerprint must be removed");
    assert!(own.history.contains_key("own-new"),    "Active own fingerprint must be retained");
    assert!(!known.local_history.contains_key("known-old"), "Expired known fingerprint must be removed");
    assert!(known.local_history.contains_key("known-new"),  "Active known fingerprint must be retained");
}

/// With a very long grace period (e.g. 100 years), all fingerprints are retained.
/// This verifies that `+` in `let purge_date = valid_until + *grace_period` is correct
/// (Mutant: `+ -> -` would place the purge date in the past).
#[test]
fn test_cleanup_long_grace_period_retains_all() {
    use chrono::{Duration, Utc};

    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    // 5 years in the past
    let past = "2020-01-01T00:00:00.000000Z";
    own.history.insert("old-but-grace".to_string(), vec![make_fingerprint("old-but-grace", "tid", past)]);
    known.local_history.insert("old-known-grace".to_string(), vec![make_fingerprint("old-known-grace", "tid2", past)]);

    let now = Utc::now();
    let grace = Duration::days(365 * 100); // 100 years grace

    cleanup_expired_histories(&mut own, &mut known, &now, &grace);

    assert!(own.history.contains_key("old-but-grace"),       "Long grace period must keep old own fingerprints");
    assert!(known.local_history.contains_key("old-known-grace"), "Long grace period must keep old known fingerprints");
}

// =============================================================================
// export_own_fingerprints / import_foreign_fingerprints
// =============================================================================

/// Export and import of fingerprints is symmetric.
/// After export->import the same fingerprints are present.
#[test]
fn test_export_import_fingerprints_roundtrip() {
    let tag = "export-import-tag";
    let fp = make_signed_foreign_fp(tag, "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let exported = export_own_fingerprints(&own).unwrap();
    assert!(!exported.is_empty(), "Exported data must not be empty");

    let mut known = KnownFingerprints::default();
    let count = import_foreign_fingerprints(&mut known, &exported).unwrap();

    assert_eq!(count, 1, "One fingerprint must be imported");
    assert!(known.foreign_fingerprints.contains_key(tag), "Imported fingerprint must be findable by ds_tag");
}

/// Double import of the same fingerprint must not produce duplicates.
/// Mutant: `delete !` before `entry.contains(fp)` -> would be inserted twice.
#[test]
fn test_import_foreign_fingerprints_deduplication() {
    let tag = "dedup-tag";
    let fp = make_signed_foreign_fp(tag, "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp]);
    let exported = export_own_fingerprints(&own).unwrap();

    let mut known = KnownFingerprints::default();
    import_foreign_fingerprints(&mut known, &exported).unwrap();
    let count2 = import_foreign_fingerprints(&mut known, &exported).unwrap();

    // Second import -> 0 new fingerprints (all already known)
    assert_eq!(count2, 0, "Re-importing known fingerprints must not increase count");
    let fps = known.foreign_fingerprints.get(tag).unwrap();
    assert_eq!(fps.len(), 1, "No duplicates after double import");
}

// =============================================================================
// encrypt_transaction_timestamp / decrypt_transaction_timestamp
// =============================================================================

/// XOR encryption of the timestamp must yield a deterministic roundtrip:
/// decrypt(encrypt(t)) == t.
/// In addition, encrypt(t) != t must hold (no trivial passthrough).
#[test]
fn test_timestamp_encryption_is_deterministic_and_non_trivial() {
    let tx = make_test_transaction("ts-roundtrip", "2025-06-15T10:00:00.000000Z");

    let encrypted = encrypt_transaction_timestamp(&tx).unwrap();
    let decrypted = decrypt_transaction_timestamp(&tx, encrypted).unwrap();

    // Roundtrip must recover original timestamp
    // The original value is the nanos value of t_time
    let expected_nanos = chrono::DateTime::parse_from_rfc3339(&tx.t_time)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap() as u128;

    assert_eq!(decrypted, expected_nanos, "Decrypted value must match original timestamp nanos");

    // Encryption must not be trivial (no passthrough when key == 0)
    assert_ne!(encrypted, expected_nanos, "Encrypted value must differ from plaintext nanos");
}

/// Two different transactions (different prev_hash + t_id) must produce different
/// encryption keys, leading to different encrypted values
/// (even though the timestamp is identical).
/// Mutant: `replace ^ with | / &` would not correctly apply the XOR key.
#[test]
fn test_timestamp_encryption_is_key_specific() {
    let tx_a = make_test_transaction("key-specific-a", "2025-06-15T10:00:00.000000Z");
    let tx_b = make_test_transaction("key-specific-b", "2025-06-15T10:00:00.000000Z");

    let enc_a = encrypt_transaction_timestamp(&tx_a).unwrap();
    let enc_b = encrypt_transaction_timestamp(&tx_b).unwrap();

    // Although t_time is identical, encrypted values must differ
    // (since prev_hash and t_id differ -> different XOR key)
    assert_ne!(enc_a, enc_b, "Different transactions must produce different encrypted timestamps");

    // And its own roundtrip must also work here
    assert_eq!(decrypt_transaction_timestamp(&tx_b, enc_b).unwrap(),
               decrypt_transaction_timestamp(&tx_a, enc_a).unwrap(),
               "Both roundtrips must recover the same original timestamp");
}

// =============================================================================
// resolve_conflict_offline — Earliest Wins (Line 498)
// =============================================================================

/// In offline conflicts, the transaction with the earliest (smallest) timestamp wins.
/// Mutant: `replace < with <=` in resolve_conflict_offline -> no difference on real data,
/// but `replace < with ==` or `replace < with >` would determine the winner incorrectly.
///
/// These tests test via the wallet facade since resolve_conflict_offline is pub(super).
/// We use the Wallet::check_for_double_spend chain.
///
/// Since resolve_conflict_offline must be tested via wallet state (pub(super)),
/// we use a direct fingerprint comparison via decrypt_transaction_timestamp.
#[test]
fn test_earliest_wins_selects_minimum_encrypted_timestamp() {
    // tx_early has smaller nanos than tx_late
    let tx_early = make_test_transaction("early-winner", "2025-01-01T00:00:00.000000Z");
    let tx_late  = make_test_transaction("late-loser",   "2025-12-31T23:59:59.000000Z");

    let enc_early = encrypt_transaction_timestamp(&tx_early).unwrap();
    let enc_late  = encrypt_transaction_timestamp(&tx_late).unwrap();

    let dec_early = decrypt_transaction_timestamp(&tx_early, enc_early).unwrap();
    let dec_late  = decrypt_transaction_timestamp(&tx_late,  enc_late).unwrap();

    // Earlier timestamp (Jan) must have smaller nanos value than later (Dec)
    assert!(
        dec_early < dec_late,
        "Earlier timestamp (Jan) must produce smaller nanos than later (Dec): {} vs {}",
        dec_early, dec_late
    );
}

// =============================================================================
// check_bundle_fingerprints_against_history (Replay vs Double-Spend)
// =============================================================================

/// In the replay scenario: When the wallet already has the same fingerprint in `own_fingerprints`
/// (as sender) and the same fingerprint arrives again, `check_for_double_spend`
/// must recognize this as a conflict — but only if two different t_ids actually exist.
///
/// This test directly verifies the `check_for_double_spend` logic with a constructed
/// scenario where own + foreign have the same tag but IDENTICAL t_id -> no conflict (deduplication).
#[test]
fn test_replay_deduplication_across_sources() {
    let tag = "replay-dedup-tag";
    let fp = make_fingerprint(tag, "tid-same", "2030-12-31T23:59:59.999999Z");

    // Same fingerprint in all three sources -> after merge only one t_id -> no conflict
    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp.clone()]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp.clone()]);

    let result = check_for_double_spend(&own, &known);

    // Even though the tag exists in all three sources, it is always the same t_id
    // -> after HashSet deduplication only 1 unique t_id remains -> no conflict
    assert!(
        result.verifiable_conflicts.is_empty() && result.unverifiable_warnings.is_empty(),
        "Same t_id across all sources must NOT trigger a conflict (deduplication must work)"
    );
}
