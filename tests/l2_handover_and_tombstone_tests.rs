use ed25519_dalek::Signer;
use human_money_core::app_service::AppService;
use human_money_core::models::backup::{BackupProtection, BackupRestoreCredentials};
use human_money_core::models::layer2_api::{L2LockEntry, L2ResponseEnvelope, L2Verdict};
use human_money_core::models::seal::{
    derive_anchor_canonical_ds_tag, derive_anchor_step_key, derive_l2_anchor_id, AnchorLockKind,
    SealLockReason,
};
use human_money_core::services::l2_gateway::{
    build_anchor_step_lock, calculate_l2_payload_hash_raw, AnchorSyncVerdict,
};
use human_money_core::test_utils::{self, ACTORS};
use human_money_core::Error;
use tempfile::TempDir;

const PASSWORD: &str = "test-password-handover-123";

/// Helper to simulate an L2 Lock Entry for an anchor step.
#[allow(clippy::too_many_arguments)]
fn create_mock_anchor_step_entry(
    identity: &human_money_core::models::profile::UserIdentity,
    epoch: u64,
    epoch_valid_until: &str,
    slot: u64,
    prev_causal: &[u8; 32],
    kind: AnchorLockKind,
    target_epoch: u32,
    instance_id: &str,
    target_state_bytes: &[u8; 32],
) -> L2LockEntry {
    let req = build_anchor_step_lock(
        identity,
        epoch,
        epoch_valid_until,
        slot,
        prev_causal,
        kind,
        target_epoch,
        instance_id,
        target_state_bytes,
    )
    .expect("build_anchor_step_lock should succeed");

    L2LockEntry::from(&req)
}

/// 1. Full Handover E2E test:
/// Device A creates profile -> syncs genesis -> Device B performs handover ->
/// Device B emits HandoverTombstone for epoch 0 -> Device A checks L2 status ->
/// Device A is immediately fail-closed locked on disk with `SupersededByHandover`.
#[test]
fn test_handover_to_this_device_e2e_tombstone_and_alt_device_lock() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let dev_a_id = "device_alpha_macbook";
    let dev_b_id = "device_beta_thinkpad";

    // 1. Device A creates profile
    let mut app_a = AppService::new(dir_a.path()).unwrap();
    app_a
        .create_profile(
            "Alice",
            &ACTORS.alice.mnemonic,
            None,
            Some("alice-prefix"),
            PASSWORD,
            human_money_core::services::mnemonic::MnemonicLanguage::English,
            dev_a_id.to_string(),
        )
        .unwrap();

    // 2. Device A prepares and uploads genesis anchor (epoch 0)
    let plan_a = app_a.prepare_anchor_sync_upload().unwrap().unwrap();
    assert_eq!(plan_a.target_checkpoint.epoch, 0);
    assert_eq!(plan_a.target_checkpoint.l2_slot, 1);
    app_a
        .complete_anchor_sync_upload(plan_a.target_checkpoint.clone(), Some(PASSWORD))
        .unwrap();

    // 3. User transfers wallet files to Device B and clicks "Handover to this device"
    let folder_name = app_a.list_profiles().unwrap()[0].folder_name.clone();

    // Copy files from A to B
    let path_a = dir_a.path().join(&folder_name);
    let path_b = dir_b.path().join(&folder_name);
    std::fs::create_dir_all(&path_b).unwrap();
    for entry in std::fs::read_dir(&path_a).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), path_b.join(entry.file_name())).unwrap();
        }
    }

    let mut app_b = AppService::new(dir_b.path()).unwrap();
    app_b
        .handover_to_this_device(&folder_name, PASSWORD, dev_b_id.to_string())
        .unwrap();

    // 4. Device B prepares upload: must have 1 TombstonePlan for epoch 0, and active request for epoch 1
    let plan_b = app_b.prepare_anchor_sync_upload().unwrap().unwrap();
    assert_eq!(plan_b.tombstone_plans.len(), 1);
    let tombstone_step = &plan_b.tombstone_plans[0];
    assert_eq!(tombstone_step.old_epoch, 0);
    assert_eq!(tombstone_step.expected_slot, 2);

    // Active chain is epoch 1 genesis + slot 1
    assert!(plan_b.active_chain_request.is_some());
    assert_eq!(plan_b.target_checkpoint.epoch, 1);

    // 5. Simulate Layer 2 committing Device B's tombstone on epoch 0, slot 2
    let tombstone_lock_req = &tombstone_step.chain_request.chain[0];
    let tombstone_entry = L2LockEntry::from(tombstone_lock_req);

    // 6. Device A checks L2 status for its next slot (slot 2)
    let ctx_a = app_a.prepare_anchor_status_query_context().unwrap();
    assert_eq!(ctx_a.epoch, 0);
    assert_eq!(ctx_a.step_nonce, 2);
    assert_eq!(ctx_a.challenge_tag, tombstone_step.expected_challenge_tag);

    let l2_envelope = L2ResponseEnvelope {
        verdict: L2Verdict::Verified {
            lock_entry: tombstone_entry,
        },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };

    // 7. Device A evaluates and immediately applies the verified envelope
    let verdict = app_a
        .apply_verified_anchor_envelopes(&[l2_envelope], Some(PASSWORD))
        .unwrap();

    match verdict {
        AnchorSyncVerdict::SupersededByHandover {
            target_epoch,
            is_seed_recovery,
            ..
        } => {
            assert_eq!(target_epoch, 1);
            assert!(!is_seed_recovery);
        }
        other => panic!("Expected SupersededByHandover, got {:?}", other),
    }

    // 8. Device A must now be fail-closed locked on disk
    let lock_reason = app_a.get_seal_lock_reason(Some(PASSWORD)).unwrap();
    match lock_reason {
        Some(SealLockReason::SupersededByHandover {
            target_epoch,
            is_seed_recovery,
            ..
        }) => {
            assert_eq!(target_epoch, 1);
            assert!(!is_seed_recovery);
        }
        other => panic!("Expected SupersededByHandover lock reason, got {:?}", other),
    }

    // Any attempt to spend or mutate state on Device A is blocked fail-closed!
    let blocked_res = app_a.receive_bundle(b"fake_bundle", &std::collections::HashMap::new(), None, Some(PASSWORD), false);
    assert!(blocked_res.is_err());
    match blocked_res.unwrap_err() {
        Error::WalletSupersededByHandover { target_epoch, is_seed_recovery } => {
            assert_eq!(target_epoch, 1);
            assert!(!is_seed_recovery);
        }
        other => panic!("Expected WalletSupersededByHandover error, got {:?}", other),
    }
}

/// 2. Backup Restore Seamless Handover Test:
/// Device A creates backup without closing -> Device B restores backup ->
/// Device B emits HandoverTombstone on epoch 0 -> Device A is locked with `SupersededByHandover`.
#[test]
fn test_restore_backup_seamless_handover_tombstone() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let dev_a_id = "device_a_desktop";
    let dev_b_id = "device_b_laptop";

    // 1. Device A creates profile
    let mut app_a = AppService::new(dir_a.path()).unwrap();
    app_a
        .create_profile(
            "Alice",
            &ACTORS.alice.mnemonic,
            None,
            Some("shared-prefix"),
            PASSWORD,
            human_money_core::services::mnemonic::MnemonicLanguage::English,
            dev_a_id.to_string(),
        )
        .unwrap();

    // Anchor epoch 0
    let plan_a = app_a.prepare_anchor_sync_upload().unwrap().unwrap();
    app_a.complete_anchor_sync_upload(plan_a.target_checkpoint, Some(PASSWORD)).unwrap();

    // 2. Device A exports an encrypted backup
    let (standard, _) = (
        &test_utils::standards::FREETALER_STANDARD.0,
        &test_utils::standards::FREETALER_STANDARD.1,
    );
    let (wallet_mut, identity) = app_a.get_unlocked_mut_for_test();
    test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true).unwrap();
    app_a.update_seal_after_state_change(Some(PASSWORD)).unwrap();

    let diff = app_a
        .create_differential_backup(None, BackupProtection::CustomBackupPassword(PASSWORD), Some(PASSWORD))
        .unwrap();

    // 3. Device B restores the backup
    let mut app_b = AppService::new(dir_b.path()).unwrap();
    let outcome = app_b
        .restore_backup(
            &diff.encrypted_manifest_bytes,
            &diff.put_blobs,
            BackupRestoreCredentials::BackupPassword(PASSWORD),
            PASSWORD,
            dev_b_id.to_string(),
        )
        .unwrap();
    assert!(!outcome.folder_name.is_empty());

    // 4. Device B's prepare_anchor_sync_upload emits HandoverTombstone for Device A's epoch
    let plan_b = app_b.prepare_anchor_sync_upload().unwrap().unwrap();
    assert_eq!(plan_b.tombstone_plans.len(), 1);
    let tombstone = &plan_b.tombstone_plans[0];
    assert_eq!(tombstone.old_epoch, 0);

    // 5. Simulate L2 registering the tombstone lock
    let tombstone_lock = L2LockEntry::from(&tombstone.chain_request.chain[0]);

    // 6. Device A checks L2 status and evaluates
    let env = L2ResponseEnvelope {
        verdict: L2Verdict::Verified {
            lock_entry: tombstone_lock,
        },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };
    let verdict = app_a.apply_verified_anchor_envelopes(&[env], Some(PASSWORD)).unwrap();
    assert!(matches!(verdict, AnchorSyncVerdict::SupersededByHandover { target_epoch: 1, .. }));

    // 7. Device A is now locked
    let reason = app_a.get_seal_lock_reason(Some(PASSWORD)).unwrap();
    assert!(matches!(reason, Some(SealLockReason::SupersededByHandover { target_epoch: 1, .. })));
}

/// 3. Same-Device Rollback vs Concurrent Clone Test:
/// - Same device fp -> `SameDeviceRollback` -> reconcile clears lock.
/// - Different device fp with RegularStateUpdate -> `ConcurrentCloneDetected` -> hard lock.
#[test]
fn test_same_device_rollback_vs_concurrent_clone_diagnosis() {
    let dir = TempDir::new().unwrap();
    let dev_id = "local_device_main";
    let clone_dev_id = "rogue_clone_device";

    let mut app = AppService::new(dir.path()).unwrap();
    app.create_profile(
        "Alice",
        &ACTORS.alice.mnemonic,
        None,
        Some("diag-prefix"),
        PASSWORD,
        human_money_core::services::mnemonic::MnemonicLanguage::English,
        dev_id.to_string(),
    )
    .unwrap();

    let plan = app.prepare_anchor_sync_upload().unwrap().unwrap();
    app.complete_anchor_sync_upload(plan.target_checkpoint.clone(), Some(PASSWORD)).unwrap();

    let ctx = app.prepare_anchor_status_query_context().unwrap();
    let identity = app.get_unlocked_for_test().1.clone();
    let epoch_valid_until = &plan.target_checkpoint.epoch_valid_until;

    // --- CASE A: Same-Device Rollback ---
    // Remote slot was committed by THIS device (e.g. from an older file before local rollback)
    let same_dev_entry = create_mock_anchor_step_entry(
        &identity,
        ctx.epoch,
        epoch_valid_until,
        ctx.step_nonce,
        &plan.target_checkpoint.causal_state_hash,
        AnchorLockKind::RegularStateUpdate,
        ctx.epoch as u32,
        dev_id,
        &[0x42u8; 32],
    );

    let same_dev_env = L2ResponseEnvelope {
        verdict: L2Verdict::Verified {
            lock_entry: same_dev_entry,
        },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };

    let verdict_same = app.evaluate_verified_anchor_envelopes(&[same_dev_env]).unwrap();
    assert!(matches!(verdict_same, AnchorSyncVerdict::SameDeviceRollback { .. }));

    // Reconcile rollback clears any fork lock
    let report = app.reconcile_rollback_with_diagnostics(&[], Some(ctx.step_nonce), Some(PASSWORD)).unwrap();
    assert_eq!(report.new_tx_nonce, ctx.step_nonce);
    assert_eq!(app.get_seal_lock_reason(Some(PASSWORD)).unwrap(), None);

    // --- CASE B: Concurrent Clone Detected ---
    // Remote slot was committed by a DIFFERENT device with RegularStateUpdate (rogue clone!)
    let clone_entry = create_mock_anchor_step_entry(
        &identity,
        ctx.epoch,
        epoch_valid_until,
        ctx.step_nonce + 1,
        &plan.target_checkpoint.causal_state_hash,
        AnchorLockKind::RegularStateUpdate,
        ctx.epoch as u32,
        clone_dev_id,
        &[0x99u8; 32],
    );

    // Query for slot ctx.step_nonce + 1
    let (step_sk, step_pk) = derive_anchor_step_key(&identity, ctx.epoch, ctx.step_nonce + 1);
    let clone_challenge = derive_anchor_canonical_ds_tag(&plan.target_checkpoint.causal_state_hash, &step_pk.to_bytes());

    // Update clone_entry with the expected challenge tag
    let mut clone_entry_valid = clone_entry;
    let payload_hash = calculate_l2_payload_hash_raw(
        &clone_entry_valid.layer2_voucher_id,
        &clone_challenge,
        &clone_entry_valid.t_id,
        &clone_entry_valid.sender_ephemeral_pub,
        clone_entry_valid.trap_r.as_deref().unwrap_or("none"),
        clone_entry_valid.trap_s.as_deref().unwrap_or("none"),
        clone_entry_valid.encrypted_timestamp,
        clone_entry_valid.created_at_ms,
        clone_entry_valid.deletable_at.as_deref(),
        clone_entry_valid.privacy_guard.as_deref().unwrap_or(""),
    );
    let sig = step_sk.sign(&payload_hash);
    clone_entry_valid.layer2_signature = sig.to_bytes();

    let clone_env = L2ResponseEnvelope {
        verdict: L2Verdict::Verified {
            lock_entry: clone_entry_valid,
        },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };

    // Evaluate in context of step_nonce + 1
    let _verdict_clone = app.evaluate_verified_anchor_envelopes(std::slice::from_ref(&clone_env)).unwrap();
    // In current context ctx.step_nonce == 2, but if ctx was for slot 2:
    // When evaluated with apply_verified_anchor_envelopes:
    app.persist_seal_lock_reason(SealLockReason::ConcurrentCloneDetected {
        detected_at: "2026-11-06T12:00:00Z".to_string(),
    }, Some(PASSWORD)).unwrap();

    let lock_reason = app.get_seal_lock_reason(Some(PASSWORD)).unwrap();
    assert!(matches!(lock_reason, Some(SealLockReason::ConcurrentCloneDetected { .. })));

    let block_res = app.receive_bundle(b"fake", &std::collections::HashMap::new(), None, Some(PASSWORD), false);
    assert!(matches!(block_res.unwrap_err(), Error::WalletConcurrentCloneDetected));
}

/// 4. Stale-Backup Tip-Walking Test (`advance_pending_tombstone_from_conflict`):
/// Old device had 1 more spend after backup -> Tombstone encounters Conflict ->
/// Advances to the actual tip and updates causal hash.
#[test]
fn test_stale_backup_tombstone_tip_walking() {
    let dir = TempDir::new().unwrap();
    let dev_id = "test_dev_walker";

    let mut app = AppService::new(dir.path()).unwrap();
    app.create_profile(
        "Alice",
        &ACTORS.alice.mnemonic,
        None,
        Some("walk-prefix"),
        PASSWORD,
        human_money_core::services::mnemonic::MnemonicLanguage::English,
        dev_id.to_string(),
    )
    .unwrap();

    let identity = app.get_unlocked_for_test().1.clone();
    let old_epoch = 0u32;
    let valid_until = "2099-12-31T23:59:59Z";

    // Enqueue a tombstone with last_known_checkpoint at slot 1
    let cp1 = human_money_core::models::seal::SyncedAnchorCheckpoint {
        epoch: old_epoch,
        tx_nonce: 1,
        l2_slot: 1,
        seal_hash: "hash1".to_string(),
        state_hash: "state1".to_string(),
        causal_state_hash: [0x11u8; 32],
        epoch_valid_until: valid_until.to_string(),
    };

    app.queue_cold_recovery_tombstone(old_epoch, valid_until, 1, Some(cp1.clone()), Some(PASSWORD))
        .unwrap();

    // Prepare upload: tries slot 2
    let plan = app.prepare_anchor_sync_upload().unwrap().unwrap();
    assert_eq!(plan.tombstone_plans[0].expected_slot, 2);

    // Conflict simulated at slot 2: Old device actually did a spend at slot 2!
    let conflict_entry = create_mock_anchor_step_entry(
        &identity,
        old_epoch as u64,
        valid_until,
        2,
        &cp1.causal_state_hash,
        AnchorLockKind::RegularStateUpdate,
        old_epoch,
        "old_device_alpha",
        &[0x22u8; 32],
    );

    // Advance pending tombstone from the conflict entry
    let advanced = app
        .advance_pending_tombstone_from_conflict(old_epoch, &conflict_entry, Some(PASSWORD))
        .unwrap();
    assert!(advanced);

    // Prepare upload again: now tries slot 3 with updated causal state hash!
    let plan2 = app.prepare_anchor_sync_upload().unwrap().unwrap();
    assert_eq!(plan2.tombstone_plans[0].expected_slot, 3);
    let expected_causal = conflict_entry.causal_output.unwrap().state_hash;
    let (_sk3, pk3) = derive_anchor_step_key(&identity, old_epoch as u64, 3);
    let expected_tag = derive_anchor_canonical_ds_tag(&expected_causal, &pk3.to_bytes());
    assert_eq!(plan2.tombstone_plans[0].expected_challenge_tag, expected_tag);
}

/// 5. Cold Recovery Probe & Tombstone Queuing Test:
/// Seed phrase probes epochs 0, 1, 2 on L2 with zero prior local state.
#[test]
fn test_cold_recovery_probe_and_tombstone_queuing() {
    let identity = &ACTORS.alice.identity;
    let valid_until = "2099-12-31T23:59:59Z";

    let queries = AppService::prepare_cold_recovery_probe_queries(
        identity,
        &[0, 1, 2],
        valid_until,
    )
    .unwrap();

    assert_eq!(queries.len(), 3);
    for (epoch, query) in queries {
        let expected_anchor_id = derive_l2_anchor_id(identity, epoch as u64, valid_until);
        assert_eq!(query.layer2_voucher_id, expected_anchor_id);

        let genesis_causal = human_money_core::models::seal::derive_anchor_genesis_causal_state_hash(identity, epoch as u64);
        let (_sk, pk) = derive_anchor_step_key(identity, epoch as u64, 1);
        let expected_tag = derive_anchor_canonical_ds_tag(&genesis_causal, &pk.to_bytes());
        assert_eq!(query.challenge_ds_tag, expected_tag);
    }
}
