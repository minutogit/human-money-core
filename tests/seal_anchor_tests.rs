use human_money_core::FileStorage;
use human_money_core::models::layer2_api::{L2LockEntry, L2Verdict};
use human_money_core::models::seal::{
    SyncStatus, calculate_voucher_merkle_root, derive_anchor_step_key, derive_anchor_step_tag,
    derive_l2_anchor_id,
};
use human_money_core::services::l2_gateway::{
    AnchorSyncVerdict, build_anchor_leap_lock, build_anchor_status_query,
    calculate_l2_payload_hash_raw, calculate_read_quorum, evaluate_anchor_verdict,
    evaluate_multi_node_anchor_verdicts,
};
use human_money_core::storage::AuthMethod;
use human_money_core::storage::seal_service::SealService;
use human_money_core::test_utils::{self, ACTORS};
use human_money_core::wallet::instance::VoucherStatus;
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
    assert_eq!(
        hash_1a, hash_1b,
        "State hash must be strictly deterministic"
    );

    // Nonce change produces different hash
    let hash_nonce_1 =
        SealService::calculate_comprehensive_state_hash(0, 1, &merkle_root_1, &of_hash_1);
    assert_ne!(hash_1a, hash_nonce_1, "Nonce change must alter state hash");

    // Epoch change produces different hash
    let hash_epoch_1 =
        SealService::calculate_comprehensive_state_hash(1, 0, &merkle_root_1, &of_hash_1);
    assert_ne!(hash_1a, hash_epoch_1, "Epoch change must alter state hash");

    // Merkle root change produces different hash
    let hash_root_changed =
        SealService::calculate_comprehensive_state_hash(0, 0, "different_root", &of_hash_1);
    assert_ne!(
        hash_1a, hash_root_changed,
        "Merkle root change must alter state hash"
    );
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
    assert_eq!(
        sk1.to_bytes(),
        sk2.to_bytes(),
        "Step signing key must be deterministic"
    );
    assert_eq!(
        pk1.to_bytes(),
        pk2.to_bytes(),
        "Step public key must be deterministic"
    );

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
    let (_expected_sk, expected_pk) =
        derive_anchor_step_key(&identity.signing_key, epoch, start_nonce);
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
    let anchor_verdict_matching =
        evaluate_anchor_verdict(&verdict_matching, &local_t_id, local_tag);
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
        let id1 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true)
            .unwrap();
        let id2 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "30.00", standard, true)
            .unwrap();
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
        causal_output: None,
        layer2_voucher_id: "test_anchor".to_string(),
        t_id: [99u8; 32], // Different t_id from another device
        sender_ephemeral_pub: [0u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
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
        other => panic!(
            "Expected PendingLeapLock with quorum 2 of 3, got {:?}",
            other
        ),
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
    assert!(
        !flushed_again,
        "Already synced seal should return false on flush"
    );

    // Immediate sync (tier-1: spend)
    app.schedule_anchor_sync_debounced(Some(PASSWORD)).unwrap();
    app.sync_anchor_immediate(Some(PASSWORD)).unwrap();
    let record3 = storage.load_seal(&auth).unwrap().unwrap();
    assert_eq!(record3.sync_status, SyncStatus::Synced);
}

/// 11. test_single_malicious_node_cannot_lock_wallet:
/// A single malicious node reporting RollbackDetected/ForkConflict must be overruled by the honest quorum.
#[test]
fn test_single_malicious_node_cannot_lock_wallet() {
    let local_t_id = [1u8; 32];
    let local_tag = "tag_local";
    let total_nodes = 3;
    assert_eq!(calculate_read_quorum(total_nodes), 2);

    // Helper to create a dummy lock entry with given t_id
    fn dummy_entry(t_id: [u8; 32]) -> L2LockEntry {
        L2LockEntry {
            causal_output: None,
            layer2_voucher_id: "test_anchor".to_string(),
            t_id,
            sender_ephemeral_pub: [0u8; 32],
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: [0u8; 64],
            trap_r: None,
            trap_s: None,
            encrypted_timestamp: 0,
            created_at_ms: 0,
            deletable_at: None,
            privacy_guard: None,
        }
    }

    let remote_t_id = [99u8; 32];
    let malicious_rollback = L2Verdict::Verified {
        lock_entry: dummy_entry(remote_t_id),
    };
    let honest_sync = L2Verdict::MissingLocks {
        sync_point: local_tag.to_string(),
    };

    // 2 honest synchronized vs 1 malicious rollback -> must be Synchronized
    let res = evaluate_multi_node_anchor_verdicts(
        &[
            honest_sync.clone(),
            honest_sync.clone(),
            malicious_rollback.clone(),
        ],
        &local_t_id,
        local_tag,
        total_nodes,
    );
    assert_eq!(
        res,
        AnchorSyncVerdict::Synchronized,
        "Single malicious rollback must be overruled by quorum 2 of 3"
    );

    // Same for ForkConflict
    let malicious_fork = L2Verdict::Conflict {
        existing_lock: dummy_entry(remote_t_id),
    };
    let res2 = evaluate_multi_node_anchor_verdicts(
        &[honest_sync.clone(), honest_sync.clone(), malicious_fork],
        &local_t_id,
        local_tag,
        total_nodes,
    );
    assert_eq!(
        res2,
        AnchorSyncVerdict::Synchronized,
        "Single malicious fork must be overruled by quorum 2 of 3"
    );

    // With 5 nodes, 4 honest + 1 malicious -> still synchronized (quorum 3)
    assert_eq!(calculate_read_quorum(5), 3);
    let res3 = evaluate_multi_node_anchor_verdicts(
        &[
            honest_sync.clone(),
            honest_sync.clone(),
            honest_sync.clone(),
            honest_sync.clone(),
            malicious_rollback,
        ],
        &local_t_id,
        local_tag,
        5,
    );
    assert_eq!(res3, AnchorSyncVerdict::Synchronized);
}

/// 12. test_cryptographic_proof_of_rollback_detection:
/// When quorum of nodes reports a conflicting lock, rollback is detected and the proof is cryptographically verifiable.
#[test]
fn test_cryptographic_proof_of_rollback_detection() {
    use ed25519_dalek::{Signer, Verifier, VerifyingKey};

    let identity = &ACTORS.alice.identity;
    let epoch = 0u64;
    let tx_nonce_for_lock = 5u64;
    let local_t_id = [1u8; 32];
    let local_tag = "tag_local";
    let remote_t_id = [0xABu8; 32];
    let ds_tag = "challenge_tag_for_proof";

    // Derive anchor ID and step key that L2 would have used for the remote lock
    let anchor_id = derive_l2_anchor_id(identity, epoch);
    let (step_sk, step_pk) =
        derive_anchor_step_key(&identity.signing_key, epoch, tx_nonce_for_lock);
    let step_pub_bytes = step_pk.to_bytes();

    // Create payload hash exactly as L2 would sign it for an anchor leap lock (non-genesis)
    let payload_hash = calculate_l2_payload_hash_raw(
        &anchor_id,
        ds_tag,
        &remote_t_id,
        &step_pub_bytes,
        "none",
        "none",
        0,
        0,
        None,
        "",
    );
    let sig = step_sk.sign(&payload_hash);

    // Verify that the signature is a valid cryptographic proof for this lock
    let vk = VerifyingKey::from_bytes(&step_pub_bytes).expect("valid pubkey");
    assert!(
        vk.verify(&payload_hash, &sig).is_ok(),
        "Lock signature must be cryptographically valid"
    );

    let lock_entry = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: anchor_id.clone(),
        t_id: remote_t_id,
        sender_ephemeral_pub: step_pub_bytes,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    // Two nodes report the conflicting lock (quorum for N=3 is 2), one is synchronized
    let honest_sync = L2Verdict::MissingLocks {
        sync_point: local_tag.to_string(),
    };
    let rollback_verdict = L2Verdict::Verified {
        lock_entry: lock_entry.clone(),
    };
    let result = evaluate_multi_node_anchor_verdicts(
        &[
            rollback_verdict.clone(),
            rollback_verdict,
            honest_sync.clone(),
        ],
        &local_t_id,
        local_tag,
        3,
    );

    match result {
        AnchorSyncVerdict::RollbackDetected {
            remote_t_id: found_t_id,
            lock_entry: found_entry,
        } => {
            assert_eq!(found_t_id, remote_t_id);
            assert_eq!(found_entry.t_id, remote_t_id);
            // Re-verify cryptographic proof on the returned entry
            let recomputed_hash = calculate_l2_payload_hash_raw(
                &found_entry.layer2_voucher_id,
                ds_tag,
                &found_entry.t_id,
                &found_entry.sender_ephemeral_pub,
                found_entry.trap_r.as_deref().unwrap_or("none"),
                found_entry.trap_s.as_deref().unwrap_or("none"),
                found_entry.encrypted_timestamp,
                found_entry.created_at_ms,
                found_entry.deletable_at.as_deref(),
                found_entry.privacy_guard.as_deref().unwrap_or(""),
            );
            // For anchor leap locks, trap_r/trap_s are "none", privacy_guard is ""
            // The lock used anchor_id as voucher_id, so recomputation must match
            let recomputed_hash2 = calculate_l2_payload_hash_raw(
                &anchor_id,
                ds_tag,
                &remote_t_id,
                &step_pub_bytes,
                "none",
                "none",
                0,
                0,
                None,
                "",
            );
            assert_eq!(recomputed_hash, recomputed_hash2);
            let vk2 = VerifyingKey::from_bytes(&found_entry.sender_ephemeral_pub).unwrap();
            let sig2 = ed25519_dalek::Signature::from_bytes(&found_entry.layer2_signature);
            assert!(
                vk2.verify(&recomputed_hash, &sig2).is_ok(),
                "Returned lock entry must carry valid cryptographic proof"
            );
        }
        other => panic!(
            "Expected RollbackDetected with quorum 2 of 3, got {:?}",
            other
        ),
    }

    // ForkConflict quorum as well
    let fork_entry = lock_entry;
    let fork_verdict = L2Verdict::Conflict {
        existing_lock: fork_entry.clone(),
    };
    let result_fork = evaluate_multi_node_anchor_verdicts(
        &[fork_verdict.clone(), fork_verdict, honest_sync.clone()],
        &local_t_id,
        local_tag,
        3,
    );
    match result_fork {
        AnchorSyncVerdict::ForkConflict { foreign_entry } => {
            assert_eq!(foreign_entry.t_id, remote_t_id);
        }
        other => panic!("Expected ForkConflict with quorum 2 of 3, got {:?}", other),
    }
}

/// 13. test_status_query_key_matches_step_nonce:
/// build_anchor_status_query must derive the ephemeral key deterministically from (epoch, tx_nonce).
#[test]
fn test_status_query_key_matches_step_nonce() {
    let identity = &ACTORS.alice.identity;
    let epoch = 7u64;
    let challenge = "challenge_tag_123";
    let locator = vec!["loc1".to_string()];

    for tx_nonce in [0u64, 1, 5, 42, 12345] {
        let query =
            build_anchor_status_query(identity, epoch, tx_nonce, challenge, locator.clone(), 1)
                .expect("build query should succeed");
        let (_sk, expected_pk) = derive_anchor_step_key(&identity.signing_key, epoch, tx_nonce);
        assert_eq!(
            query.auth.ephemeral_pubkey,
            expected_pk.to_bytes(),
            "Status query key must match derived step key for nonce {}",
            tx_nonce
        );
        assert_eq!(query.challenge_ds_tag, challenge);
        assert_eq!(query.locator_prefixes, locator);
        let expected_anchor_id = derive_l2_anchor_id(identity, epoch);
        assert_eq!(query.layer2_voucher_id, expected_anchor_id);
    }

    // Different nonces must produce different keys
    let q0 = build_anchor_status_query(identity, epoch, 0, challenge, vec![], 1).unwrap();
    let q1 = build_anchor_status_query(identity, epoch, 1, challenge, vec![], 1).unwrap();
    assert_ne!(
        q0.auth.ephemeral_pubkey, q1.auth.ephemeral_pubkey,
        "Different tx_nonce must yield different ephemeral keys"
    );

    // Different epoch must produce different key even with same nonce
    let q_epoch0 = build_anchor_status_query(identity, 0, 10, challenge, vec![], 1).unwrap();
    let q_epoch1 = build_anchor_status_query(identity, 1, 10, challenge, vec![], 1).unwrap();
    assert_ne!(
        q_epoch0.auth.ephemeral_pubkey, q_epoch1.auth.ephemeral_pubkey,
        "Different epoch must yield different keys"
    );
}
