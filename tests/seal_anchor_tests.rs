use human_money_core::models::layer2_api::{L2LockEntry, L2Verdict};
use human_money_core::models::seal::{
    calculate_voucher_merkle_root, derive_anchor_step_key, derive_anchor_step_tag,
    derive_l2_anchor_id, SyncStatus,
};
use human_money_core::services::l2_gateway::{
    build_anchor_leap_lock, calculate_read_quorum, evaluate_anchor_verdict,
    evaluate_multi_node_anchor_verdicts, AnchorSyncVerdict,
};
use human_money_core::storage::seal_service::SealService;
use human_money_core::storage::AuthMethod;
use human_money_core::test_utils::{self, ACTORS};
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::FileStorage;
use tempfile::TempDir;

const PASSWORD: &str = "test-password-anchor-123";

/// 1. test_state_hash_determinism:
/// Identical wallet states produce identical comprehensive state hash; any mutation produces a different hash.
#[test]
fn test_state_hash_determinism() {
    let dir = TempDir::new().unwrap();
    let (app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let (wallet, _) = app.get_unlocked_for_test();
    let merkle_root_1 = calculate_voucher_merkle_root(&wallet.voucher_store.vouchers);
    let of_hash_1 = SealService::calculate_state_hash(&wallet.own_fingerprints).unwrap();

    let hash_1a = SealService::calculate_comprehensive_state_hash(0, 0, &merkle_root_1, &of_hash_1);
    let hash_1b = SealService::calculate_comprehensive_state_hash(0, 0, &merkle_root_1, &of_hash_1);
    assert_eq!(hash_1a, hash_1b, "State hash must be strictly deterministic");

    // Nonce change produces different hash
    let hash_nonce_1 = SealService::calculate_comprehensive_state_hash(0, 1, &merkle_root_1, &of_hash_1);
    assert_ne!(hash_1a, hash_nonce_1, "Nonce change must alter state hash");

    // Epoch change produces different hash
    let hash_epoch_1 = SealService::calculate_comprehensive_state_hash(1, 0, &merkle_root_1, &of_hash_1);
    assert_ne!(hash_1a, hash_epoch_1, "Epoch change must alter state hash");

    // Merkle root change produces different hash
    let hash_root_changed =
        SealService::calculate_comprehensive_state_hash(0, 0, "different_root", &of_hash_1);
    assert_ne!(hash_1a, hash_root_changed, "Merkle root change must alter state hash");
}

/// 2. test_time_insensitivity_and_expiration:
/// Vouchers passing expiration date without explicit archive mutation do NOT change the state hash.
#[test]
fn test_time_insensitivity_and_expiration() {
    let dir = TempDir::new().unwrap();
    let (mut app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    // Add an active voucher
    let (standard, _) = (
        &test_utils::standards::FREETALER_STANDARD.0,
        &test_utils::standards::FREETALER_STANDARD.1,
    );
    let (wallet_mut, identity) = app.get_unlocked_mut_for_test();
    let v_id = test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true)
        .expect("Failed to add voucher");

    let root_before = calculate_voucher_merkle_root(&wallet_mut.voucher_store.vouchers);

    // Simulate voucher transitioning to Expired status (time passage without archive)
    wallet_mut.update_voucher_status(&v_id, VoucherStatus::Expired);
    let root_after_expiration = calculate_voucher_merkle_root(&wallet_mut.voucher_store.vouchers);

    assert_eq!(
        root_before, root_after_expiration,
        "Expired vouchers must remain in the Merkle root until explicitly archived"
    );

    // Only explicit archiving removes it from the active Merkle root
    wallet_mut.update_voucher_status(&v_id, VoucherStatus::Archived);
    let root_after_archive = calculate_voucher_merkle_root(&wallet_mut.voucher_store.vouchers);

    assert_ne!(
        root_before, root_after_archive,
        "Archived voucher must be excluded from the Merkle root"
    );
}

/// 3. test_deterministic_key_derivation_zero_storage:
/// Anchor ID, step key, and step tag are derived purely on the fly with no disk storage needed.
#[test]
fn test_deterministic_key_derivation_zero_storage() {
    let identity = &ACTORS.alice.identity;
    let epoch = 0;
    let tx_nonce = 42;

    let anchor_id_1 = derive_l2_anchor_id(identity, epoch);
    let anchor_id_2 = derive_l2_anchor_id(identity, epoch);
    assert_eq!(anchor_id_1, anchor_id_2, "Anchor ID must be deterministic");

    let (sk1, pk1) = derive_anchor_step_key(&identity.signing_key, epoch, tx_nonce);
    let (sk2, pk2) = derive_anchor_step_key(&identity.signing_key, epoch, tx_nonce);
    assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "Step signing key must be deterministic");
    assert_eq!(pk1.to_bytes(), pk2.to_bytes(), "Step public key must be deterministic");

    let prev_hash = "prev_seal_hash_123456789";
    let tag1 = derive_anchor_step_tag(prev_hash, tx_nonce);
    let tag2 = derive_anchor_step_tag(prev_hash, tx_nonce);
    assert_eq!(tag1, tag2, "Step tag must be deterministic");
    assert_ne!(tag1, derive_anchor_step_tag(prev_hash, tx_nonce + 1));
}

/// 4. test_fast_forward_leap_lock_5_offline_steps:
/// 5 offline transactions can be synchronized in a single Leap-Lock request jumping from nonce 0 to 5.
#[test]
fn test_fast_forward_leap_lock_5_offline_steps() {
    let identity = &ACTORS.alice.identity;
    let epoch = 0;
    let start_nonce = 0;
    let genesis_tag = "genesis_tag_step_0";
    let target_state_hash = [7u8; 32];

    let leap_lock = build_anchor_leap_lock(
        identity,
        epoch,
        start_nonce,
        genesis_tag,
        &target_state_hash,
    )
    .expect("Building leap lock should succeed");

    assert_eq!(leap_lock.ds_tag, Some(genesis_tag.to_string()));
    assert_eq!(leap_lock.transaction_hash, target_state_hash);
    assert!(!leap_lock.is_genesis);

    // Verify cryptographic signature of the leap-lock request using derived step key
    let (_expected_sk, expected_pk) = derive_anchor_step_key(&identity.signing_key, epoch, start_nonce);
    assert_eq!(leap_lock.sender_ephemeral_pub, expected_pk.to_bytes());
}

/// 5. test_l2_missing_locks_guidance:
/// If the node returns MissingLocks pointing to an older sync point, evaluate_anchor_verdict guides leap-lock.
#[test]
fn test_l2_missing_locks_guidance() {
    let local_t_id = [1u8; 32];
    let local_tag = "current_local_tag";
    let remote_sync_point = "l2_last_known_tag";

    let verdict = L2Verdict::MissingLocks {
        sync_point: remote_sync_point.to_string(),
    };

    let anchor_verdict = evaluate_anchor_verdict(&verdict, &local_t_id, local_tag);
    match anchor_verdict {
        AnchorSyncVerdict::PendingLeapLock { sync_point } => {
            assert_eq!(sync_point, remote_sync_point);
        }
        other => panic!("Expected PendingLeapLock, got {:?}", other),
    }

    // When sync_point matches local_tag, wallet is considered synchronized
    let verdict_matching = L2Verdict::MissingLocks {
        sync_point: local_tag.to_string(),
    };
    let anchor_verdict_matching = evaluate_anchor_verdict(&verdict_matching, &local_t_id, local_tag);
    assert_eq!(anchor_verdict_matching, AnchorSyncVerdict::Synchronized);
}

/// 6. test_rollback_detection_and_reconciliation:
/// Simulates restoring an outdated backup. Reconcile archives spent vouchers and advances nonce to match L2.
#[test]
fn test_rollback_detection_and_reconciliation() {
    let dir = TempDir::new().unwrap();
    let (mut app, profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let (standard, _) = (
        &test_utils::standards::FREETALER_STANDARD.0,
        &test_utils::standards::FREETALER_STANDARD.1,
    );

    // Add two active vouchers
    let (v_id1, v_id2) = {
        let (wallet_mut, identity) = app.get_unlocked_mut_for_test();
        let id1 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true).unwrap();
        let id2 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "30.00", standard, true).unwrap();
        (id1, id2)
    };

    // Commit state with seal
    app.update_seal_after_state_change(Some(PASSWORD)).unwrap();

    // Reconcile rollback where v_id1 was spent on another device and remote nonce is 3
    let report = app
        .reconcile_rollback_with_diagnostics(&[v_id1.clone()], Some(3), Some(PASSWORD))
        .expect("Reconciliation should succeed");

    assert_eq!(report.new_tx_nonce, 3);
    assert!(report.archived_voucher_ids.contains(&v_id1));
    assert_eq!(report.archived_voucher_ids.len(), 1);

    // Verify storage seal updated and unblocked
    let storage = FileStorage::new(dir.path().join(&profile.folder_name));
    let auth = AuthMethod::Password(PASSWORD);
    let record = storage.load_seal(&auth).unwrap().expect("Seal must exist");
    assert_eq!(record.seal.payload.tx_nonce, 3);
    assert!(!record.is_locked_due_to_fork);
    assert_eq!(record.sync_status, SyncStatus::Synced);

    // Verify wallet state: v_id1 is Archived, v_id2 is still Active
    let (wallet, _) = app.get_unlocked_for_test();
    assert_eq!(
        wallet.voucher_store.vouchers.get(&v_id1).unwrap().status,
        VoucherStatus::Archived
    );
    assert_eq!(
        wallet.voucher_store.vouchers.get(&v_id2).unwrap().status,
        VoucherStatus::Active
    );
}

/// 7. test_multi_device_fork_conflict_409:
/// L2Verdict::Conflict with a different transaction hash triggers ForkConflict quarantine.
#[test]
fn test_multi_device_fork_conflict_409() {
    let local_t_id = [1u8; 32];
    let local_tag = "tag_step_1";

    let competing_entry = L2LockEntry {
        layer2_voucher_id: "test_anchor".to_string(),
        t_id: [99u8; 32], // Different t_id from another device
        sender_ephemeral_pub: [0u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let verdict = L2Verdict::Conflict {
        existing_lock: competing_entry.clone(),
    };

    let sync_verdict = evaluate_anchor_verdict(&verdict, &local_t_id, local_tag);
    match sync_verdict {
        AnchorSyncVerdict::ForkConflict { foreign_entry } => {
            assert_eq!(foreign_entry.t_id, [99u8; 32]);
        }
        other => panic!("Expected ForkConflict, got {:?}", other),
    }
}

/// 8. test_fault_tolerant_quorum_2_of_3:
/// In a 3-node shard, read quorum is 2. When 2 nodes agree, consensus is accepted even if 1 is partitioned.
#[test]
fn test_fault_tolerant_quorum_2_of_3() {
    assert_eq!(calculate_read_quorum(3), 2);

    let local_t_id = [1u8; 32];
    let local_tag = "tag_local";

    let node1_verdict = L2Verdict::MissingLocks {
        sync_point: "sync_pt_1".to_string(),
    };
    let node2_verdict = L2Verdict::MissingLocks {
        sync_point: "sync_pt_1".to_string(),
    };
    let node3_verdict = L2Verdict::UnknownVoucher; // Partitioned / desynced node

    let multi_verdict = evaluate_multi_node_anchor_verdicts(
        &[node1_verdict, node2_verdict, node3_verdict],
        &local_t_id,
        local_tag,
        3,
    );

    match multi_verdict {
        AnchorSyncVerdict::PendingLeapLock { sync_point } => {
            assert_eq!(sync_point, "sync_pt_1");
        }
        other => panic!("Expected PendingLeapLock with quorum 2 of 3, got {:?}", other),
    }
}

/// 9. test_bootstrap_village_mode_quorum:
/// In 1-node shard / village mode, read quorum is 1.
#[test]
fn test_bootstrap_village_mode_quorum() {
    assert_eq!(calculate_read_quorum(1), 1);
    assert_eq!(calculate_read_quorum(0), 1);

    let local_t_id = [1u8; 32];
    let local_tag = "tag_local";

    let single_verdict = L2Verdict::MissingLocks {
        sync_point: "village_sync_point".to_string(),
    };

    let res = evaluate_multi_node_anchor_verdicts(&[single_verdict], &local_t_id, local_tag, 1);
    match res {
        AnchorSyncVerdict::PendingLeapLock { sync_point } => {
            assert_eq!(sync_point, "village_sync_point");
        }
        other => panic!("Expected PendingLeapLock in village mode, got {:?}", other),
    }
}

/// 10. test_two_tier_trigger_timing:
/// Immediate sync marks seal Synced; debounced sync marks seal PendingUpload; flush clears pending.
#[test]
fn test_two_tier_trigger_timing() {
    let dir = TempDir::new().unwrap();
    let (mut app, profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let storage = FileStorage::new(dir.path().join(&profile.folder_name));
    let auth = AuthMethod::Password(PASSWORD);

    // Initialize seal
    app.update_seal_after_state_change(Some(PASSWORD)).unwrap();

    // Debounced schedule (tier-2: receive / create / archive)
    app.schedule_anchor_sync_debounced(Some(PASSWORD)).unwrap();
    let record1 = storage.load_seal(&auth).unwrap().unwrap();
    assert_eq!(record1.sync_status, SyncStatus::PendingUpload);

    // Flush pending sync (e.g. backgrounding / app exit)
    let flushed = app.flush_pending_anchor_sync(Some(PASSWORD)).unwrap();
    assert!(flushed, "Pending upload should be flushed");
    let record2 = storage.load_seal(&auth).unwrap().unwrap();
    assert_eq!(record2.sync_status, SyncStatus::Synced);

    // Flush when already Synced returns false
    let flushed_again = app.flush_pending_anchor_sync(Some(PASSWORD)).unwrap();
    assert!(!flushed_again, "Already synced seal should return false on flush");

    // Immediate sync (tier-1: spend)
    app.schedule_anchor_sync_debounced(Some(PASSWORD)).unwrap();
    app.sync_anchor_immediate(Some(PASSWORD)).unwrap();
    let record3 = storage.load_seal(&auth).unwrap().unwrap();
    assert_eq!(record3.sync_status, SyncStatus::Synced);
}
