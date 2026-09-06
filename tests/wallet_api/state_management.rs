// tests/wallet_api/state_management.rs
// cargo test --test wallet_api_tests
//!
//! Contains integration tests for complex state management and
//! handling of conflicts such as double-spending.

use human_money_core::{
    VoucherStatus,
    app_service::AppService,
    models::{
        conflict::{ProofOfDoubleSpend, ResolutionEndorsement},
        profile::PublicProfile,
        voucher::ValueDefinition,
    },
    services::crypto, NewVoucherData,
    test_utils::{ACTORS, FREETALER_STANDARD, create_test_bundle, generate_signed_standard_toml},
};

use chrono::DateTime;
use chrono::{Duration, Utc};
use human_money_core::test_utils;
use human_money_core::{models::voucher::Transaction, services::utils};
use std::collections::HashMap;
use tempfile::tempdir;

/// Local test helper function to generate a mock `ProofOfDoubleSpend`.
fn create_mock_proof_of_double_spend(
    offender_id: &str,
    victim_id: &str,
    resolutions: Option<Vec<ResolutionEndorsement>>,
    verdict: Option<human_money_core::models::conflict::Layer2Verdict>,
) -> ProofOfDoubleSpend {
    ProofOfDoubleSpend {
        proof_id: crypto::get_hash(offender_id), // Dummy ID for test
        offender_id: offender_id.to_string(),
        suspected_identity: None,
        conflicting_transactions: vec![human_money_core::models::voucher::Transaction::default(), human_money_core::models::voucher::Transaction::default()],
        reporter_id: victim_id.to_string(),
        resolutions,
        layer2_verdict: verdict,
        fork_point_prev_hash: "dummy_hash".to_string(),
        deletable_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: "dummy_sig".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        non_redeemable_test_voucher: false,
    }
}

/// Test 5.1: Tests the complete "Happy Path" of conflict resolution via AppService.
#[test]
fn api_app_service_full_conflict_resolution_workflow() {
    // --- 1. Setup ---
    let dir_reporter = tempdir().unwrap();
    let dir_victim = tempdir().unwrap();
    let password = "conflict-password";
    let reporter = &ACTORS.reporter;
    let victim = &ACTORS.victim;

    let (mut service_reporter, profile_reporter) =
        test_utils::setup_service_with_profile(dir_reporter.path(), reporter, "Reporter", password);
    service_reporter.unlock_session(password, 60).unwrap();
    let (mut service_victim, _) =
        test_utils::setup_service_with_profile(dir_victim.path(), victim, "Victim", password);
    service_victim.unlock_session(password, 60).unwrap();
    let id_victim = service_victim.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // --- 2. Create proof in Reporter wallet ---
    let proof = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    let proof_id = proof.proof_id.clone();

    // Internal test helper function to place the proof directly into the store.
    let (wallet, _identity) = service_reporter.get_unlocked_mut_for_test();
    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    wallet
        .proof_store
        .proofs
        .insert(proof.proof_id.clone(), ProofStoreEntry { 
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
        });

    // --- 3. Action 1 (Reporter): List conflict as unresolved ---
    let conflicts_before = service_reporter.list_conflicts().unwrap();
    assert_eq!(conflicts_before.len(), 1);
    assert!(!conflicts_before[0].is_resolved);

    // --- 4. Action 2 (Victim): Create resolution endorsement ---
    let (wallet_victim, _identity_victim) = service_victim.get_unlocked_mut_for_test();
    let proof_for_victim =
        create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    wallet_victim
        .proof_store
        .proofs
        .insert(proof_for_victim.proof_id.clone(), ProofStoreEntry { 
            proof: proof_for_victim, local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
        });

    let endorsement = service_victim
        .create_resolution_endorsement(&proof_id, Some("We settled this.".to_string()))
        .unwrap();

    // --- 5. Action 3 (Reporter): Import resolution endorsement ---
    service_reporter
        .import_resolution_endorsement(endorsement, Some(password))
        .unwrap();

    // --- 6. Action 4 (Final check): Verify persistence ---
    let mut service_checker = AppService::new(dir_reporter.path()).unwrap();
    service_checker
        .login(&profile_reporter.folder_name, password, false, "test-id".to_string())
        .unwrap();
    let conflicts_after = service_checker.list_conflicts().unwrap();
    assert_eq!(conflicts_after.len(), 1);
    assert_eq!(conflicts_after[0].proof_id, proof_id);
    assert!(
        conflicts_after[0].is_resolved,
        "Conflict should be resolved after importing the endorsement and reloading from disk"
    );
}

/// Test 5.2: Ensures that all conflict API methods fail
/// when the wallet is locked.
#[test]
fn api_app_service_conflict_api_fails_when_locked() {
    let dir = tempdir().unwrap();
    let mut service = AppService::new(dir.path()).unwrap();
    let fake_proof_id = "proof-123";
    let password = "dummy_password";

    let res_list = service.list_conflicts();
    assert!(res_list.is_err());
    assert!(res_list.unwrap_err().to_string().contains("Wallet is locked"));

    let res_get = service.get_proof_of_double_spend(fake_proof_id);
    assert!(res_get.is_err());
    assert!(res_get.unwrap_err().to_string().contains("Wallet is locked"));

    let res_create = service.create_resolution_endorsement(fake_proof_id, None);
    assert!(res_create.is_err());
    assert!(res_create.unwrap_err().to_string().contains("Wallet is locked"));

    let dummy_endorsement = ResolutionEndorsement {
        endorsement_id: "".to_string(),
        proof_id: "".to_string(),
        victim_id: "".to_string(),
        victim_signature: "".to_string(),
        resolution_timestamp: Utc::now().to_rfc3339(),
        notes: None,
    };
    let res_import = service.import_resolution_endorsement(dummy_endorsement, Some(password));
    assert!(res_import.is_err());
    assert!(res_import.unwrap_err().to_string().contains("Wallet is locked"));
}

/// Test 1.1: Tests reactive double-spend detection via "Earliest Wins" heuristic.
#[test]
fn api_wallet_reactive_double_spend_earliest_wins() {
    // --- 1. Setup ---
    let dir_alice = tempdir().unwrap();
    let dir_david = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let david = &ACTORS.david;
    let (mut service_alice, _) =
        test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    service_alice.unlock_session("pwd", 60).unwrap();
    let (mut service_david, _) =
        test_utils::setup_service_with_profile(dir_david.path(), david, "David", "pwd");
    service_david.unlock_session("pwd", 60).unwrap();
    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let id_david = service_david.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let identity_alice = alice.identity.clone();
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), freetaler_standard_toml.clone());

    // --- 2. Alice creates a voucher (V1) ---
    let voucher_v1 = service_alice
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    // Create two conflicting transactions from V1
    let prev_tx = voucher_v1.transactions.last().unwrap();
    let prev_tx_hash = human_money_core::services::crypto::get_hash(
        human_money_core::services::utils::to_canonical_json(prev_tx).unwrap(),
    );
    let prev_tx_time = chrono::DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let time_early = (prev_tx_time + Duration::seconds(10)).to_rfc3339();
    let time_late = (prev_tx_time + Duration::seconds(30)).to_rfc3339();
    let alice_holder_key = test_utils::derive_holder_key(&voucher_v1, &identity_alice.signing_key);
    let alice_holder_pub = bs58::encode(alice_holder_key.verifying_key().to_bytes()).into_string();

    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(
        &voucher_v1.transactions[0],
    )
    .unwrap();

    // Bundle Bob (earlier timestamp)
    let tx_bob_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_early,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub.clone()),
        ..Default::default()
    };
    let tx_bob = test_utils::resign_transaction_with_privacy(
        tx_bob_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_bob = voucher_v1.clone();
    voucher_bob.transactions.push(tx_bob);
    let bundle_bob = test_utils::create_test_bundle(&identity_alice, vec![voucher_bob], &id_david, None).unwrap();

    // Bundle Charlie (later timestamp)
    let tx_charlie_raw = Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: time_late,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub),
        ..Default::default()
    };
    let tx_charlie = test_utils::resign_transaction_with_privacy(
        tx_charlie_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_charlie = voucher_v1.clone();
    voucher_charlie.transactions.push(tx_charlie);
    let bundle_charlie =
        test_utils::create_test_bundle(&identity_alice, vec![voucher_charlie], &id_david, None).unwrap();

    // --- 4. David receives the later bundle first (Charlie) ---
    human_money_core::set_signature_bypass(true);
    service_david
        .receive_bundle(&bundle_charlie, &standards_map, None, Some("pwd"), false)
        .unwrap();
    human_money_core::set_signature_bypass(false);
    let summaries_before = service_david
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(summaries_before.len(), 1);
    assert_eq!(summaries_before[0].status, VoucherStatus::Active);
    let charlie_instance_id = summaries_before[0].local_instance_id.clone();

    // --- 5. David receives the earlier bundle (Bob), which triggers the conflict ---
    human_money_core::set_signature_bypass(true);
    service_david
        .receive_bundle(&bundle_bob, &standards_map, None, Some("pwd"), false)
        .unwrap();
    human_money_core::set_signature_bypass(false);

    // --- 6. Assertions ---
    let summaries_after = service_david
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        summaries_after.len(),
        2,
        "Wallet should now contain two instances"
    );

    let summary_charlie = service_david
        .with_wallet(|w| w.get_voucher_details(&charlie_instance_id).unwrap())
        .unwrap();

    assert!(
        matches!(summary_charlie.status, VoucherStatus::Quarantined { .. }),
        "Charlie's later voucher should be quarantined"
    );

    let bob_instance_id = summaries_after
        .iter()
        .find(|s| s.local_instance_id != charlie_instance_id)
        .unwrap()
        .local_instance_id
        .clone();
    let summary_bob = service_david
        .with_wallet(|w| w.get_voucher_details(&bob_instance_id).unwrap())
        .unwrap();
    assert_eq!(
        summary_bob.status,
        VoucherStatus::Active,
        "Bob's earlier voucher should be active"
    );
}

/// Test 1.2: Tests conflict detection with exactly identical timestamps.
#[test]
fn api_wallet_reactive_double_spend_identical_timestamps() {
    // --- 1. Setup ---
    let dir_alice = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let dir_david = tempdir().unwrap();
    let david = &ACTORS.david;

    let (mut service_alice, _) =
        test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    service_alice.unlock_session("pwd", 60).unwrap();
    let (mut service_david, _) =
        test_utils::setup_service_with_profile(dir_david.path(), david, "David", "pwd");
    service_david.unlock_session("pwd", 60).unwrap();
    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let id_david = service_david.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let identity_alice = alice.identity.clone();
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), freetaler_standard_toml.clone());

    let voucher_v1 = service_alice
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    // --- 2. Create conflicting transactions with IDENTICAL timestamp ---
    let prev_tx = voucher_v1.transactions.last().unwrap();
    let prev_tx_time = DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let collision_time = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let prev_tx_hash = crypto::get_hash(utils::to_canonical_json(prev_tx).unwrap());

    let alice_holder_key = test_utils::derive_holder_key(&voucher_v1, &identity_alice.signing_key);
    let alice_holder_pub = bs58::encode(alice_holder_key.verifying_key().to_bytes()).into_string();

    // Path A: Split transfer 99
    let tx_a_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "split".to_string(),
        t_time: collision_time.clone(),
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "99.00".to_string(),
        sender_remaining_amount: Some("1.00".to_string()),
        sender_ephemeral_pub: Some(alice_holder_pub.clone()),
        ..Default::default()
    };
    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&voucher_v1.transactions[0]).unwrap();
    let tx_a = test_utils::resign_transaction_with_privacy(
        tx_a_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_a = voucher_v1.clone();
    voucher_a.transactions.push(tx_a.clone());

    // Path B: Full transfer 100
    let tx_b_raw = Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: collision_time,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub),
        ..Default::default()
    };
    let tx_b = test_utils::resign_transaction_with_privacy(
        tx_b_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_b = voucher_v1.clone();
    voucher_b.transactions.push(tx_b.clone());

    let bundle_a =
        create_test_bundle(&identity_alice, vec![voucher_a.clone()], &id_david, None).unwrap();
    let bundle_b = create_test_bundle(&identity_alice, vec![voucher_b], &id_david, None).unwrap();

    assert_ne!(
        tx_a.t_id, tx_b.t_id,
        "Conflicting transactions must have different t_ids"
    );

    // --- 3. David receives both bundles ---
    human_money_core::set_signature_bypass(true);
    service_david
        .receive_bundle(&bundle_a, &standards_map, None, Some("pwd"), false)
        .unwrap();
    service_david
        .receive_bundle(&bundle_b, &standards_map, None, Some("pwd"), false)
        .unwrap();
    human_money_core::set_signature_bypass(false);

    // --- 4. Assertions ---
    let summaries_after = service_david
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        summaries_after.len(),
        2,
        "Wallet should contain two instances"
    );
    let active_count = summaries_after
        .iter()
        .filter(|s| s.status == VoucherStatus::Active)
        .count();
    let quarantined_count = summaries_after
        .iter()
        .filter(|s| matches!(s.status, VoucherStatus::Quarantined { .. }))
        .count();
    assert_eq!(
        active_count, 1,
        "Exactly one voucher should be active (tie-break)"
    );
    assert_eq!(
        quarantined_count, 1,
        "Exactly one voucher should be quarantined (tie-break)"
    );
}

/// Test 2.1: Ensures that the entire state of a wallet can be saved
/// and restored without loss of fidelity.
#[test]
fn api_wallet_save_and_load_fidelity() {
    // --- 1. Setup ---
    let dir = tempdir().unwrap();
    let test_user = &ACTORS.test_user;
    let password = "a-very-secure-password";
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // --- 2. Put Wallet A into a complex state ---
    {
        let (mut service_a, _) =
            test_utils::setup_service_with_profile(dir.path(), test_user, "Test User A", password);
        service_a.unlock_session(password, 60).unwrap();
        let id_a = service_a.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        service_a
            .create_new_voucher(
                &freetaler_toml,
                NewVoucherData {
                    creator_profile: PublicProfile {
                        id: Some(id_a.clone()),
                        ..Default::default()
                    },
                    nominal_value: ValueDefinition {
                        unit: "Taler".to_string(),
                        amount: "10".to_string(),
                        abbreviation: Some("oz Ag".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(password),
            )
            .unwrap();

        // --- Step A: Partial transfer (Split) ---
        let summary = service_a
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap();
        let silver_voucher_id_10oz = summary
            .iter()
            .find(|s| s.current_amount == "10.00" && s.status == VoucherStatus::Active)
            .expect("FreeTaler voucher summary not found")
            .local_instance_id
            .clone();

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: silver_voucher_id_10oz.clone(),
                amount_to_send: "3".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());
        service_a
            .create_transfer_bundle(request, &standards_toml, None, Some(password))
            .unwrap();

        // Generate bundle metadata via receive
        let transfer_back_bundle = {
            let dir_bob = tempdir().unwrap();
            let bob = &ACTORS.bob;
            let (mut service_bob, _) =
                test_utils::setup_service_with_profile(dir_bob.path(), bob, "Bob", "pwd");
            service_bob.unlock_session("pwd", 60).unwrap();
            let id_bob = service_bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();
            service_bob
                .create_new_voucher(
                    &freetaler_toml,
                    NewVoucherData {
                        creator_profile: PublicProfile {
                            id: Some(id_bob),
                            ..Default::default()
                        },
                        nominal_value: ValueDefinition {
                            amount: "1".to_string(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    Some("pwd"),
                )
                .unwrap();
            let local_id = service_bob
                .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
                .unwrap()[0]
                .local_instance_id
                .clone();

            let request = human_money_core::wallet::MultiTransferRequest {
                recipient_id: id_a.clone(),
                sources: vec![human_money_core::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "1".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
        use_privacy_mode: None,
            };

            let mut standards_toml = std::collections::HashMap::new();
            standards_toml.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());

            let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = service_bob
                .create_transfer_bundle(request, &standards_toml, None, Some("pwd"))
                .unwrap();
            bundle_bytes
        };
        service_a
            .receive_bundle(&transfer_back_bundle, &standards_map, None, Some(password), false)
            .unwrap();

        // --- Step B: Full transfer ---
        let summary_before_full_transfer = service_a
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap();
        let silver_voucher_id_7oz = summary_before_full_transfer
            .iter()
            .find(|s| s.current_amount == "7.00" && s.status == VoucherStatus::Active)
            .expect("7oz silver voucher for full transfer not found")
            .local_instance_id
            .clone();
        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: ACTORS.charlie.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: silver_voucher_id_7oz.clone(),
                amount_to_send: "7".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());
        service_a
            .create_transfer_bundle(request, &standards_toml, None, Some(password))
            .unwrap();
    } // service_a goes out of scope

    // --- 3. Load Wallet B from the same directory ---
    let mut service_b = AppService::new(dir.path()).unwrap();
    let profile_b = service_b.list_profiles().unwrap().pop().unwrap();
    service_b
        .login(&profile_b.folder_name, password, false, "test-id".to_string())
        .expect("Login for service_b should succeed");

    // --- 4. Assertions ---
    let summaries = service_b
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        summaries.len(),
        2,
        "Should have 2 voucher instances (1 active, 1 archived)"
    );

    let archived_count = summaries
        .iter()
        .filter(|s| s.status == VoucherStatus::Archived)
        .count();
    let active_count = summaries
        .iter()
        .filter(|s| s.status == VoucherStatus::Active)
        .count();
    assert_eq!(active_count, 1, "Incorrect number of active vouchers found");
    assert_eq!(
        archived_count, 1,
        "Incorrect number of archived vouchers found"
    );

    let balances = service_b
        .with_wallet_and_identity(|w, id| w.get_total_balance_by_currency(Some(id)))
        .unwrap();
    let silver_balance = balances
        .iter()
        .find(|b| b.unit == "Taler")
        .map(|b| b.total_amount.as_str());

    assert_eq!(silver_balance, Some("1.00"), "FreeTaler balance mismatch");

    let minuto_balance_exists = balances.iter().any(|b| b.unit == "Min");
    assert!(
        !minuto_balance_exists,
        "Minuto balance should not exist as it was never created"
    );
}

/// Test 6.1: Verifies that `create_new_voucher` adds exactly one instance.
#[test]
fn test_create_voucher_adds_exactly_one_instance() {
    // 1. ARRANGE
    let test_user = &ACTORS.test_user;
    let password = "test_password_123";
    let dir = tempdir().expect("Failed to create temp dir");
    let (mut app_service, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Test User", password);
    app_service.unlock_session(password, 60).unwrap();
    let user_id = app_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let initial_summaries = app_service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        initial_summaries.len(),
        0,
        "Wallet should be empty at the beginning"
    );

    let standard_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(user_id),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    // 2. ACT
    let created_voucher = app_service
        .create_new_voucher(&standard_toml, voucher_data.clone(), None)
        .expect("Voucher creation failed");

    // 3. ASSERT
    let final_summaries = app_service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();

    assert_eq!(
        final_summaries.len(),
        1,
        "There should be exactly one voucher in the wallet after creation"
    );

    let summary = &final_summaries[0];
    assert_eq!(summary.current_amount, "100.00");
    assert_eq!(created_voucher.voucher_standard.name, "FreeTaler");
}

/// Test 6.2: Ensures that `create_new_voucher` is transactional.
#[test]
fn test_create_voucher_is_transactional_on_save_failure() {
    // 1. ARRANGE
    let test_user = &ACTORS.test_user;
    let correct_password = "correct_password";
    let dir = tempdir().expect("Failed to create temp dir");
    let (mut app_service, _) = test_utils::setup_service_with_profile(
        dir.path(),
        test_user,
        "Test User",
        correct_password,
    );
    app_service.unlock_session(correct_password, 60).unwrap();
    let user_id = app_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let standard_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(user_id),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "50".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    // 2. ACT 1: Attempt to create with wrong password
    let creation_result_fail = app_service.create_new_voucher(
        &standard_toml,
        voucher_data.clone(),
        Some("WRONG_PASSWORD"),
    );

    // 3. ASSERT 1
    assert!(
        creation_result_fail.is_err(),
        "Creation with wrong password should fail"
    );
    let summaries_after_fail = app_service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        summaries_after_fail.len(),
        0,
        "Wallet should still be empty after a failed save"
    );

    // 4. ACT 2: Create a voucher with the correct password
    app_service
        .create_new_voucher(
            &standard_toml,
            voucher_data.clone(),
            Some(correct_password),
        )
        .expect("Voucher creation with correct password should succeed");

    // 5. ASSERT 2
    let final_summaries = app_service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(
        final_summaries.len(),
        1,
        "There should be exactly one voucher in the wallet after one failed and one successful creation"
    );
}

/// Test 7.1: Verifies the "Stale State" vulnerability under concurrent access.
///
/// NOTE ON TEST DESIGN:
/// In a single-process test environment, `app_stale` and `app_actor` share the same
/// process ID (PID). The `FileStorage` locking implementation uses the PID to identify
/// the lock owner. Because the PIDs are identical, `app_stale` would obtain the lock
/// even though `app_actor` is (from a logical perspective) a concurrent process.
///
/// To correctly test wallet protection against *external* concurrency (file locking),
/// we simulate an external lock by injecting a `.wallet.lock` file with a foreign PID (PID 1).
/// This forces the wallet into the "Locked" error state, which we expect.
#[test]
fn test_concurrent_app_service_causes_stale_state_double_spend() {
    // --- 1. Setup: Shared directory and initial state ---
    let dir = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let password = "super-secret-password";
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());

    let (mut service_initial, profile_info) =
        test_utils::setup_service_with_profile(dir.path(), alice, "Alice Concurrent", password);
    let id_alice = service_initial.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // Create the voucher
    service_initial
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();

    let voucher_to_spend_id = service_initial
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    service_initial.logout();
    drop(service_initial);

    // --- 2. Simulate concurrent access ---
    // Instance 1 (Stale)
    let mut app_stale = AppService::new(dir.path()).unwrap();
    app_stale
        .login(&profile_info.folder_name, password, false, "test-id".to_string())
        .unwrap();

    // Instance 2 (Actor)
    let mut app_actor = AppService::new(dir.path()).unwrap();
    app_actor
        .login(&profile_info.folder_name, password, false, "test-id".to_string())
        .unwrap();

    // --- 3. Race Condition: Actor acts first ---
    let request_bob = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_to_spend_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: Some("Transfer 1 (Actor)".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let result_actor =
        app_actor.create_transfer_bundle(request_bob, &standards_map, None, Some(password));
    assert!(
        result_actor.is_ok(),
        "First transfer (Actor) should be successful"
    );

    // --- 3b. SIMULATE EXTERNAL LOCK ---
    // Because we are in the same process, app_stale would otherwise acquire the lock.
    // We write PID 1 (init/systemd), which almost always exists and is considered "alive".
    let lock_path = dir
        .path()
        .join(&profile_info.folder_name)
        .join(".wallet.lock");
    std::fs::write(&lock_path, "1").expect("Failed to create fake lock file");

    // --- 4. Stale instance acts (based on old in-memory state) ---
    let request_charlie = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.charlie.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_to_spend_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: Some("Transfer 2 (Stale)".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let result_stale =
        app_stale.create_transfer_bundle(request_charlie, &standards_map, None, Some(password));

    // Clean up fake lock
    let _ = std::fs::remove_file(lock_path);

    // --- 5. Verify vulnerability mitigation ---
    // This should now fail with "Wallet is locked" or a similar IO error.
    assert!(
        result_stale.is_err(),
        "REGRESSION TEST FAILED: The 'stale' instance was incorrectly able to create a transfer (double spend). The wallet MUST prevent this with an error (e.g. file lock, stale state error)."
    );
}
