//! # tests/l2_wallet_safety_tests.rs
//!
//! Integration and safety tests verifying:
//! 1. Gateway Retry Invariant & HTTP Success Status Handling (Rule 3 idempotency, 200 vs 201)
//! 2. Backup Restore & Two-Tier Ingress Safety Reconciliation (State Anchor macro-check + Voucher micro-check)
//! 3. Accidental Double-Spend Prevention on Spent/Archived Voucher Outputs

use ed25519_dalek::Signer;
use human_money_core::VoucherCoreError;
use human_money_core::models::layer2_api::{
    L2LockEntry, L2ResponseEnvelope, L2Verdict, VoucherReconciliationResult,
};
use human_money_core::models::seal::calculate_voucher_merkle_root;
use human_money_core::services::l2_gateway::{
    VerdictAction, derive_challenge_tag, extract_layer2_voucher_id, generate_lock_request,
    is_l2_success_http_status, process_l2_verdict,
};
use human_money_core::test_utils::{self, ACTORS};
use human_money_core::wallet::instance::VoucherStatus;
use sha2::{Digest, Sha256};

/// 1. test_gateway_retry_preserves_identical_payload_and_handles_200_and_201:
/// - Generate L2LockRequest.
/// - Verify byte-level serialization determinism (multiple retries produce identical payload).
/// - Verify is_l2_success_http_status(200) and is_l2_success_http_status(201) are true, while 400/409/500 are false.
/// - Verify process_l2_verdict handles both initial confirmation (201) and idempotent replay (200 with server_t_id == local_t_id).
#[test]
fn test_gateway_retry_preserves_identical_payload_and_handles_200_and_201() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let (_standard, _hash, _creator, _recipient, voucher1, _secrets1) =
        test_utils::setup_voucher_with_one_tx();
    let layer2_id = extract_layer2_voucher_id(&voucher1).expect("extract layer2 id");
    let spend_tx = &voucher1.transactions[1];

    let sender_str = spend_tx
        .sender_ephemeral_pub
        .as_deref()
        .expect("sender ephemeral pub");
    let sender_bytes =
        human_money_core::services::crypto::decode_bs58_fixed::<32>(sender_str, "sender_pub")
            .unwrap();

    let req =
        generate_lock_request(&layer2_id, spend_tx, &sender_bytes).expect("generate lock request");

    // A. Verify byte-level serialization determinism (multiple retries produce identical payload)
    let payload_attempt_1 = serde_json::to_vec(&req).expect("serialize lock request 1");
    let payload_attempt_2 = serde_json::to_vec(&req).expect("serialize lock request 2");
    assert_eq!(
        payload_attempt_1, payload_attempt_2,
        "Retrying lock submission MUST produce bit-identical byte payload (Rule 3 invariant)"
    );

    // B. Verify HTTP status helper covers both 201 Created and 200 OK as success
    assert!(
        is_l2_success_http_status(200),
        "200 OK must be accepted as successful confirmation (idempotent replay)"
    );
    assert!(
        is_l2_success_http_status(201),
        "201 Created must be accepted as successful confirmation (first-time lock)"
    );
    assert!(
        !is_l2_success_http_status(400),
        "400 Bad Request is not success"
    );
    assert!(
        !is_l2_success_http_status(404),
        "404 Not Found is not success"
    );
    assert!(
        !is_l2_success_http_status(409),
        "409 Conflict is not success"
    );
    assert!(
        !is_l2_success_http_status(500),
        "500 Internal Error is not success"
    );

    // C. Verify process_l2_verdict handles both initial confirmation (201) and idempotent replay (200)
    let mut rng = rand::thread_rng();
    let server_sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let server_pk = server_sk.verifying_key();
    let lock_entry = L2LockEntry::from(req);
    let local_t_id_str = bs58::encode(lock_entry.t_id).into_string();
    let challenge_ds_tag = derive_challenge_tag(spend_tx).expect("derive challenge ds tag");

    let sign_verdict = |verdict: L2Verdict| -> Vec<u8> {
        let v_bytes = serde_json::to_vec(&verdict).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&v_bytes);
        let sig = server_sk.sign(&hasher.finalize());
        let env = L2ResponseEnvelope::new(verdict, sig.to_bytes());
        serde_json::to_vec(&env).unwrap()
    };

    // 1. Initial confirmation (L2Verdict::Verified) -> ConfirmLocal
    let initial_env_bytes = sign_verdict(L2Verdict::Verified {
        lock_entry: lock_entry.clone(),
    });
    let action_initial = process_l2_verdict(
        &initial_env_bytes,
        server_pk.as_bytes(),
        &local_t_id_str,
        &challenge_ds_tag,
        Some(sender_str),
        &layer2_id,
    )
    .expect("Process verified verdict");
    assert_eq!(action_initial, VerdictAction::ConfirmLocal);

    // 2. Idempotent replay (L2Verdict::Conflict with identical local_t_id) -> ConfirmLocal
    let idempotent_env_bytes = sign_verdict(L2Verdict::Conflict {
        existing_lock: lock_entry.clone(),
    });
    let action_idempotent = process_l2_verdict(
        &idempotent_env_bytes,
        server_pk.as_bytes(),
        &local_t_id_str,
        &challenge_ds_tag,
        Some(sender_str),
        &layer2_id,
    )
    .expect("Process idempotent conflict verdict");
    assert_eq!(
        action_idempotent,
        VerdictAction::ConfirmLocal,
        "Idempotent retry with matching t_id must evaluate to ConfirmLocal, not double-spend quarantine"
    );

    // 3. Foreign conflict (competing transaction on same ds_tag) -> TriggerQuarantine
    let mut competing_lock = lock_entry.clone();
    competing_lock.t_id = [0x99u8; 32];
    let foreign_sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let foreign_pk = foreign_sk.verifying_key();
    competing_lock.sender_ephemeral_pub = *foreign_pk.as_bytes();
    let entry_is_genesis = competing_lock.trap_r.as_deref() == Some("none")
        && competing_lock.trap_s.as_deref() == Some("none");
    let effective_voucher_id = if entry_is_genesis {
        "none"
    } else {
        competing_lock.layer2_voucher_id.as_str()
    };
    let guard_comm = human_money_core::services::l2_gateway::privacy_guard_commitment(
        competing_lock.privacy_guard.as_deref(),
    );
    let foreign_payload_hash =
        human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
            effective_voucher_id,
            &challenge_ds_tag,
            &competing_lock.t_id,
            &competing_lock.sender_ephemeral_pub,
            competing_lock.trap_r.as_deref().unwrap_or("none"),
            competing_lock.trap_s.as_deref().unwrap_or("none"),
            competing_lock.encrypted_timestamp,
            competing_lock.created_at_ms,
            competing_lock.deletable_at.as_deref(),
            guard_comm.as_str(),
        );
    competing_lock.layer2_signature = foreign_sk.sign(&foreign_payload_hash).to_bytes();

    let foreign_env_bytes = sign_verdict(L2Verdict::Conflict {
        existing_lock: competing_lock,
    });
    let action_conflict = process_l2_verdict(
        &foreign_env_bytes,
        server_pk.as_bytes(),
        &local_t_id_str,
        &challenge_ds_tag,
        Some(sender_str),
        &layer2_id,
    )
    .expect("Process competing conflict verdict");
    assert_eq!(
        action_conflict,
        VerdictAction::TriggerQuarantine(bs58::encode([0x99u8; 32]).into_string())
    );
}

/// 2. test_wallet_backup_restore_reconciles_already_spent_voucher_via_status_query:
/// - Setup a wallet with an active voucher. Note initial balance.
/// - Simulate a backup restore where remote L2 has a child lock on this voucher output.
/// - Call wallet.build_voucher_status_query to verify query formation.
/// - Call wallet.reconcile_voucher_state(..., Some(&child_lock)) -> returns AlreadySpent.
/// - Verify status changed to Archived.
/// - Verify wallet balance drops to 0 (wallet.get_aggregated_balances).
/// - Demonstrate the Two-Tier tie-in: calculate_voucher_merkle_root excludes the archived voucher and reconcile_rollback_with_diagnostics consolidates the state.
#[test]
fn test_wallet_backup_restore_reconciles_already_spent_voucher_via_status_query() {
    let (mut wallet, identity) =
        test_utils::create_test_wallet("backup-seed", "device-restored".to_string()).unwrap();
    let standard = &test_utils::standards::FREETALER_STANDARD.0;

    // Setup wallet with an active voucher
    let local_id =
        test_utils::add_voucher_to_wallet(&mut wallet, &identity, "100.00", standard, true)
            .expect("Add voucher");

    let initial_balances = wallet.get_aggregated_balances();
    assert_eq!(initial_balances.len(), 1);
    assert_eq!(initial_balances[0].total_amount, "100.00");

    let initial_root = calculate_voucher_merkle_root(&wallet.voucher_store.vouchers);
    assert!(
        !initial_root.is_empty(),
        "Merkle root must reflect active voucher"
    );

    // Simulate backup restore scenario:
    // 1. Build voucher status query
    let status_query = wallet
        .build_voucher_status_query(&local_id, 1)
        .expect("Build status query");
    assert_eq!(status_query.read_quorum, 1);
    assert!(!status_query.layer2_voucher_id.is_empty());
    assert!(!status_query.challenge_ds_tag.is_empty());

    // 2. Query returns HTTP 200 with child lock (remote spend occurred before backup was restored)
    let child_t_id = [0x77u8; 32];
    let child_lock = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: status_query.layer2_voucher_id.clone(),
        t_id: child_t_id,
        sender_ephemeral_pub: [0x11u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x22u8; 64],
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 12345,
        created_at_ms: 1000,
        deletable_at: None,
        privacy_guard: None,
    };

    // Reconcile voucher state with remote child lock
    let reconciliation_res = wallet
        .reconcile_voucher_state(&local_id, Some(&child_lock))
        .expect("Reconcile voucher state");

    let expected_successor_id = bs58::encode(child_t_id).into_string();
    assert_eq!(
        reconciliation_res,
        VoucherReconciliationResult::AlreadySpent {
            successor_t_id: expected_successor_id.clone(),
        }
    );

    // Verify voucher status transitioned to Archived
    let instance = wallet
        .get_voucher_instance(&local_id)
        .expect("Instance must exist");
    assert_eq!(instance.status, VoucherStatus::Archived);

    // Verify wallet balance drops to 0
    let balances_after = wallet.get_aggregated_balances();
    assert!(
        balances_after.is_empty(),
        "Aggregated balance must be empty after archiving the spent voucher"
    );

    // Demonstrate the Two-Tier tie-in:
    // Tier 1 (calculate_voucher_merkle_root) excludes the archived voucher
    let empty_map = std::collections::HashMap::new();
    let empty_root = calculate_voucher_merkle_root(&empty_map);
    let root_after = calculate_voucher_merkle_root(&wallet.voucher_store.vouchers);
    assert_eq!(
        root_after, empty_root,
        "calculate_voucher_merkle_root must exclude archived vouchers (matches empty set)"
    );
    assert_ne!(initial_root, root_after);

    // Now demonstrate state consolidation via AppService
    let dir = tempfile::TempDir::new().unwrap();
    let password = "test-pw-backup-safety";
    let (mut app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", password);

    // Add voucher in app and commit state with seal
    let app_voucher_id = {
        let (wallet_mut, identity) = app.get_unlocked_mut_for_test();
        test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true).unwrap()
    };
    app.update_seal_after_state_change(Some(password)).unwrap();

    // Test AppService::reconcile_voucher_state (Tier 2 micro-check through facade)
    let app_reconcile_res = app
        .reconcile_voucher_state(&app_voucher_id, Some(&child_lock), Some(password))
        .expect("AppService reconcile voucher state");
    assert_eq!(
        app_reconcile_res,
        VoucherReconciliationResult::AlreadySpent {
            successor_t_id: expected_successor_id,
        }
    );

    // Reconcile rollback with diagnostics: confirms Tier 1 / Tier 2 consolidation
    let report = app
        .reconcile_rollback_with_diagnostics(&[app_voucher_id.clone()], Some(42), Some(password))
        .expect("reconcile rollback with diagnostics");
    assert!(report.archived_voucher_ids.contains(&app_voucher_id));
    assert_eq!(report.new_tx_nonce, 42);

    let (wallet_consolidated, _) = app.get_unlocked_for_test();
    assert_eq!(
        wallet_consolidated
            .get_voucher_instance(&app_voucher_id)
            .unwrap()
            .status,
        VoucherStatus::Archived
    );
    assert!(wallet_consolidated.get_aggregated_balances().is_empty());
}

/// 3. test_wallet_prevents_accidental_double_spend_after_status_detects_successor:
/// - Setup wallet with active voucher.
/// - Reconcile with successor lock -> voucher becomes Archived.
/// - Attempt to spend via _execute_single_transfer: fails with VoucherCoreError::VoucherNotActive(VoucherStatus::Archived).
/// - Verify user is protected against accidental double-spend!
#[test]
fn test_wallet_prevents_accidental_double_spend_after_status_detects_successor() {
    let (mut wallet, identity) =
        test_utils::create_test_wallet("safety-seed", "device-local".to_string()).unwrap();
    let standard = &test_utils::standards::FREETALER_STANDARD.0;

    let local_id =
        test_utils::add_voucher_to_wallet(&mut wallet, &identity, "100.00", standard, true)
            .expect("Add voucher");

    // Remote child lock detected via L2 status query
    let child_lock = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "test_voucher_id".to_string(),
        t_id: [0x55u8; 32],
        sender_ephemeral_pub: [0x33u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0x44u8; 64],
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 100,
        created_at_ms: 200,
        deletable_at: None,
        privacy_guard: None,
    };

    // Reconcile -> marks voucher Archived
    let res = wallet
        .reconcile_voucher_state(&local_id, Some(&child_lock))
        .expect("Reconciliation succeeds");
    assert!(matches!(
        res,
        VoucherReconciliationResult::AlreadySpent { .. }
    ));
    assert_eq!(
        wallet.get_voucher_instance(&local_id).unwrap().status,
        VoucherStatus::Archived
    );

    // Attempt to spend via _execute_single_transfer
    let transfer_res = wallet._execute_single_transfer(
        &identity,
        standard,
        &local_id,
        &ACTORS.bob.identity.user_id,
        "50.00",
        None,
        None,
        None,
    );

    // Must fail with VoucherNotActive(VoucherStatus::Archived)
    match transfer_res {
        Err(VoucherCoreError::VoucherNotActive(status)) => {
            assert_eq!(
                status,
                VoucherStatus::Archived,
                "Transfer must be blocked because the voucher was archived after remote spend detection"
            );
        }
        other => panic!("Expected VoucherNotActive(Archived), got {:?}", other),
    }
}
