// tests/wallet_api/transactionality.rs
// cargo test --test wallet_api_tests
//!
//! Contains integration tests ensuring that all state-modifying
//! operations of `AppService` are atomic. An operation must either
//! succeed completely (including storage) or leave the in-memory state
//! as if it had never been executed.

use std::collections::HashMap;
use tempfile::tempdir;

use chrono::{Duration, Utc};

use human_money_core::test_utils;
use human_money_core::{
    VoucherStatus,
    models::{
        conflict::{ProofOfDoubleSpend, ResolutionEndorsement},
        profile::PublicProfile,
        secure_container::{ContainerConfig, PrivacyMode, SecureContainer},
        voucher::ValueDefinition,
    },
    services::{crypto_utils, voucher_manager::NewVoucherData},
    test_utils::{ACTORS, FREETALER_STANDARD, create_custom_standard, generate_signed_standard_toml},
};

/// Local test helper function to generate a mock `ProofOfDoubleSpend`.
/// NOTE: Copied from `state_management.rs` to avoid import issues.
fn create_mock_proof_of_double_spend(
    offender_id: &str,
    victim_id: &str,
    resolutions: Option<Vec<ResolutionEndorsement>>,
    verdict: Option<human_money_core::models::conflict::Layer2Verdict>,
) -> ProofOfDoubleSpend {
    ProofOfDoubleSpend {
        proof_id: crypto_utils::get_hash(offender_id),
        offender_id: offender_id.to_string(),
        suspected_identity: None,
        conflicting_transactions: vec![],
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

/// Test 7.1: Ensures that `create_transfer_bundle` does not modify
/// the in-memory state of the wallet on a storage failure.
#[test]
fn test_transfer_bundle_is_transactional_on_save_failure() {
    // 1. ARRANGE: Prepare wallet with an active voucher of 100 units.
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;
    let (mut service, _) = test_utils::setup_service_with_profile(
        dir.path(),
        test_user,
        "Test User",
        correct_password,
    );

    // Create a Flexible FreeTaler Standard to allow non-DID recipients
    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Flexible;
    });
    let flexible_toml =
        toml::to_string(&flexible_standard).expect("Failed to serialize flexible standard");

    let user_id = service.get_user_id().unwrap();

    service
        .create_new_voucher(
            &flexible_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(user_id.clone()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(correct_password),
        )
        .unwrap();

    let voucher_id = service.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let recipient = &ACTORS.recipient1;
    let (service_recipient, _) =
        test_utils::setup_service_with_profile(dir.path(), recipient, "Recipient", "pwd");
    let id_recipient = service_recipient.get_user_id().unwrap();

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "40".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    // --- FIX: The test was faulty. ---
    // The test should check transactionality upon a *save failure*.
    // A save failure is best simulated by passing a WRONG password
    // to the *persisting* function (here `create_transfer_bundle`).

    let result_fail = service.create_transfer_bundle(
        request,
        &standards_toml,
        None,
        Some("WRONG_PASSWORD_TO_FORCE_SAVE_FAILURE"),
    );

    // 3. ASSERT: Operation failed and state is unchanged.
    assert!(
        result_fail.is_err(),
        "Operation should fail due to wrong password"
    );

    // NOTE: The error can be "Authentication failed" or "Wallet is locked",
    // depending on how the implementation handles the wrong password in Mode A.
    // What matters is THAT an error occurs and the state afterwards is correct.
    let error_msg = result_fail.unwrap_err().to_string();
    assert!(
        error_msg.contains("Authentication failed")
            || error_msg.contains("Wallet is locked")
            || error_msg.contains("User ID or Key Error"),
        "Unexpected error message: {}",
        error_msg
    );

    // NOTE: This test continues to fail because it reveals a real bug.
    // The `create_transfer_bundle` operation is not atomic. The state in memory
    // is modified (the 100 voucher is replaced by a 60 voucher), but not rolled back
    // after the save failure. The following assertion would thus fail.
    let summaries_after = service.get_voucher_summaries(None, None, None).unwrap();
    assert_eq!(
        summaries_after.len(),
        1,
        "Wallet should contain exactly one voucher instance after failed transfer"
    );

    assert_eq!(
        summaries_after[0].current_amount, "100.00",
        "Voucher amount should be rolled back to 100"
    );
}

/// Test 7.2: Ensures that `receive_bundle` does not retain the new
/// voucher in the in-memory state of the wallet on a storage failure.
#[test]
fn test_receive_bundle_is_transactional_on_save_failure() {
    // 1. ARRANGE: Prepare an empty recipient wallet and a valid bundle.
    let dir_sender = tempdir().unwrap();
    let sender = &ACTORS.sender;
    let dir_recipient = tempdir().unwrap();
    let recipient = &ACTORS.recipient1;
    let correct_password = "correct_password";
    let (mut service_sender, _) =
        test_utils::setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    let (mut service_recipient, _) = test_utils::setup_service_with_profile(
        dir_recipient.path(),
        recipient,
        "Recipient",
        correct_password,
    );

    // Create a Flexible FreeTaler Standard
    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Flexible;
    });
    let flexible_toml =
        toml::to_string(&flexible_standard).expect("Failed to serialize flexible standard");

    let id_sender = service_sender.get_user_id().unwrap();
    let id_recipient = service_recipient.get_user_id().unwrap();

    // FIX: Use explicit voucher data instead of Default::default() to avoid panic.
    service_sender
        .create_new_voucher(
            &flexible_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(id_sender),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();
    let voucher_id = service_sender.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: bundle,
        ..
    } = service_sender
        .create_transfer_bundle(request, &standards_toml, None, Some("pwd"))
        .unwrap();

    let mut standards_map = HashMap::new();
    standards_map.insert(flexible_standard.immutable.identity.uuid.clone(), flexible_toml);

    // 2. ACT: Attempt to receive the bundle with the wrong password.
    let result = service_recipient.receive_bundle(
        &bundle,
        &standards_map,
        None,
        Some("WRONG_PASSWORD_TO_FORCE_SAVE_FAILURE"), // Wrong password
        false,
    );

    // 3. ASSERT: Operation failed and wallet is still empty.
    assert!(result.is_err(), "Receive operation should fail");

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Authentication failed") || error_msg.contains("Wallet is locked"),
        "Unexpected error message: {}",
        error_msg
    );

    let summaries_after = service_recipient.get_voucher_summaries(None, None, None).unwrap();
    assert!(
        summaries_after.is_empty(),
        "Recipient's wallet should remain empty after a failed receive"
    );
}

/// Test 7.3: Ensures that `process_and_attach_signature` does not modify
/// voucher state (status, signature count) in-memory on a storage failure.
#[test]
fn test_attach_signature_is_transactional_on_save_failure() {
    // 1. ARRANGE: Prepare wallet with a voucher (FreeTaler standard, requires no guarantors).
    let dir_creator = tempdir().unwrap();
    let correct_password = "correct_password";
    let creator = &ACTORS.alice;
    let (mut service_creator, _) = test_utils::setup_service_with_profile(
        dir_creator.path(),
        creator,
        "Creator",
        correct_password,
    );
    let id_creator = service_creator.get_user_id().unwrap();

    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(freetaler_standard.immutable.identity.uuid.clone(), freetaler_toml.clone());

    let signer = &ACTORS.guarantor1;
    let dir_signer = tempdir().unwrap();
    let (mut service_signer, _) =
        test_utils::setup_service_with_profile(dir_signer.path(), signer, "Signer", "pwd");
    let id_signer = service_signer.get_user_id().unwrap();

    // Create voucher -> Status: Active (since no guarantors are required)
    // FIX: Use explicit voucher data instead of Default::default() to avoid panic.
    service_creator
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(id_creator.clone()),
                    first_name: Some("Test".to_string()),
                    last_name: Some("Creator".to_string()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    unit: freetaler_standard.immutable.blueprint.unit.clone(),
                    ..Default::default()
                },
                validity_duration: Some("P1Y".to_string()),
                ..Default::default()
            },
            Some(correct_password),
        )
        .unwrap();

    let local_id = service_creator.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let details_before = service_creator.get_voucher_details(&local_id).unwrap();
    // FIX: After refactoring, the voucher already contains
    // the creator's signature (role: "creator") upon creation.
    //
    assert_eq!(details_before.voucher.signatures.len(), 1);
    assert!(matches!(
        details_before.status, // The voucher should be Active
        VoucherStatus::Active
    ));

    // 1. Prepare signature from external signer (Additional Signature)
    let bundle_req = service_creator
        .create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(id_signer.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    let (_, signer_identity_ref) = service_signer.get_unlocked_mut_for_test();
    let signer_identity = signer_identity_ref.clone();
    let request_container: SecureContainer = serde_json::from_slice(&bundle_req).unwrap();
    let payload = human_money_core::services::secure_container_manager::open_secure_container(
        &request_container,
        &signer_identity,
        None,
    )
    .unwrap();
    let voucher_from_request: human_money_core::models::voucher::Voucher =
        serde_json::from_slice(&payload).unwrap();

    // FIX: Pass arguments in correct order (voucher_id, description).
    // 1. Create signature from external signer.
    let _sig_data1 = human_money_core::test_utils::create_additional_signature_data(
        &signer_identity,
        &voucher_from_request.voucher_id,
    );

    // 3. Guarantor creates response bundle.
    // Signer creates response bundle.
    // FIX: The 4th argument is the response recipient ID, and 2nd & 3rd are role and include_details
    let detached_sig1 = service_signer
        .create_detached_signature_response_bundle(
            &voucher_from_request,
            "guarantor",
            true,
            ContainerConfig::TargetDid(id_creator.clone(), PrivacyMode::TrialDecryption),
            Some("pwd"),
        )
        .unwrap();

    // FIX: The 2nd argument is the standard TOML, not the local_id.
    service_creator
        .process_and_attach_signature(&detached_sig1, &freetaler_toml, None, Some(correct_password))
        .expect("First signature attachment failed. The utility logic should now be correct.");

    let details_mid = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_mid.voucher.signatures.len(),
        2, // creator + sig 1
        "Should have 2 signatures (creator + signer 1) after first attachment"
    );
    assert!(matches!(details_mid.status, VoucherStatus::Active));

    // 2. Prepare second signature from external signer
    let bundle_req2 = service_creator
        .create_signing_request_bundle(
            &local_id,
            ContainerConfig::TargetDid(id_signer.clone(), PrivacyMode::TrialDecryption), // Same ID again, which might cause an error in practice, but only tests rollback here
        )
        .unwrap();

    let (_, signer_identity_ref2) = service_signer.get_unlocked_mut_for_test();
    let signer_identity2 = signer_identity_ref2.clone();
    let request_container2: SecureContainer = serde_json::from_slice(&bundle_req2).unwrap();
    let payload2 = human_money_core::services::secure_container_manager::open_secure_container(
        &request_container2,
        &signer_identity2,
        None,
    )
    .unwrap();
    let voucher_from_request2: human_money_core::models::voucher::Voucher =
        serde_json::from_slice(&payload2).unwrap();

    // 2. Create second signature.
    let _sig_data2 = human_money_core::test_utils::create_additional_signature_data(
        &signer_identity2,
        &voucher_from_request2.voucher_id,
    );

    let detached_sig2 = service_signer
        .create_detached_signature_response_bundle(
            &voucher_from_request2,
            "guarantor",
            true,
            ContainerConfig::TargetDid(id_creator.clone(), PrivacyMode::TrialDecryption),
            Some("pwd"),
        )
        .unwrap();

    // 2. ACT: Attempt to add second signature with wrong password.
    let result = service_creator.process_and_attach_signature(
        &detached_sig2,
        &freetaler_toml,
        None,
        Some("WRONG_PASSWORD"),
    );

    // 3. ASSERT: Operation fails, state remains unchanged.
    assert!(result.is_err(), "Signature attachment should fail");

    let details_after = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_after.voucher.signatures.len(),
        2, // creator + sig 1
        "Signature count should remain 2 (creator + signer 1) after failed attachment"
    );
    assert!(
        matches!(details_after.status, VoucherStatus::Active), // Must remain Active
        "Status should remain Active after failed attachment"
    );
}

/// Test 7.4: Ensures that `import_resolution_endorsement` does not modify
/// the in-memory conflict proof on a storage failure.
#[test]
fn test_import_endorsement_is_transactional_on_save_failure() {
    // 1. ARRANGE: Prepare wallet with an unresolved conflict proof.
    let dir_reporter = tempdir().unwrap();
    let correct_password = "correct_password";
    let reporter = &ACTORS.reporter;
    let dir_victim = tempdir().unwrap();
    let victim = &ACTORS.victim;
    let (mut service_reporter, _) = test_utils::setup_service_with_profile(
        dir_reporter.path(),
        reporter,
        "Reporter",
        correct_password,
    );
    let (mut service_victim, _) =
        test_utils::setup_service_with_profile(dir_victim.path(), victim, "Victim", "pwd");
    let id_victim = service_victim.get_user_id().unwrap();

    // Manually add proof and save via another operation
    let proof = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    let proof_id = proof.proof_id.clone();
    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    {
        let (wallet, _identity) = service_reporter.get_unlocked_mut_for_test();
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), ProofStoreEntry { 
                proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
            });
    }
    // FIX: `wallet.save` is not directly usable. Perform another `AppService` action
    // to save the state (including the manually added proof). (Mode A)
    service_reporter
        .save_encrypted_data("dummy", b"data", Some(correct_password))
        .unwrap();

    let conflicts_before = service_reporter.list_conflicts().unwrap();
    assert!(
        !conflicts_before[0].is_resolved,
        "Conflict should initially be unresolved"
    );

    // Have victim create a valid settlement
    let (wallet_victim, _) = service_victim.get_unlocked_mut_for_test();
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

    // 2. ACT: Attempt to import settlement with wrong password.
    let result =
        service_reporter.import_resolution_endorsement(endorsement, Some("WRONG_PASSWORD"));

    // 3. ASSERT: Operation fails, conflict remains unresolved.
    assert!(result.is_err(), "Endorsement import should fail");

    let conflicts_after = service_reporter.list_conflicts().unwrap();
    assert_eq!(conflicts_after.len(), 1);
    assert!(
        !conflicts_after[0].is_resolved,
        "Conflict should remain unresolved after failed import"
    );

    let proof_details = service_reporter
        .get_proof_of_double_spend(&proof_id)
        .unwrap();
    assert!(
        proof_details.resolutions.is_none()
            || proof_details.resolutions.as_ref().unwrap().is_empty(),
        "Proof should have no endorsements after failed import"
    );
}

/// Test 7.5: Ensures that `receive_bundle` completely resets state on a conflict
/// followed by a storage failure.
#[test]
fn test_receive_bundle_is_transactional_on_conflict_and_save_failure() {
    human_money_core::set_signature_bypass(true);
    // 1. ARRANGE: David receives a voucher (Path A). A second,
    // conflicting voucher (Path B) is prepared.
    let dir_alice = tempdir().unwrap();
    let dir_david = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let correct_password = "correct_password";
    let david = &ACTORS.david;
    let (mut service_alice, _) =
        test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_david, _) =
        test_utils::setup_service_with_profile(dir_david.path(), david, "David", correct_password);
    let id_david = service_david.get_user_id().unwrap();

    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // FIX: Use explicit voucher data instead of Default::default() to avoid panic.
    let id_alice = service_alice.get_user_id().unwrap();
    let identity_alice = alice.identity.clone();
    let voucher_v1 = service_alice
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    // Create two conflicting transactions from V1
    let prev_tx = voucher_v1.transactions.last().unwrap();
    let prev_tx_hash = human_money_core::services::crypto_utils::get_hash(
        human_money_core::services::utils::to_canonical_json(prev_tx).unwrap(),
    );
    // FIX: Timestamps must be guaranteed to be after voucher creation.
    let prev_tx_time = chrono::DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let time_a = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let time_b = (prev_tx_time + Duration::seconds(2)).to_rfc3339();
    let alice_holder_key = test_utils::derive_holder_key(&voucher_v1, &identity_alice.signing_key);
    let alice_holder_pub = bs58::encode(alice_holder_key.verifying_key().to_bytes()).into_string();

    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(
        &voucher_v1.transactions[0],
    )
    .unwrap();

    // Path A (is received successfully first)
    let mut tx_a = human_money_core::models::voucher::Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_a,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub.clone()),
        ..Default::default()
    };
    // FIX: Use resign_transaction_with_privacy to ensure privacy guard is added
    tx_a = human_money_core::test_utils::resign_transaction_with_privacy(
        tx_a,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_path_a = voucher_v1.clone();
    voucher_path_a.transactions.push(tx_a);
    let bundle_a = human_money_core::test_utils::create_test_bundle(
        &identity_alice,
        vec![voucher_path_a],
        &id_david,
        None,
    )
    .unwrap();
    
    // Path B (triggers the conflict)
    let mut tx_b = human_money_core::models::voucher::Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: time_b,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub),
        ..Default::default()
    };
    // FIX: Use resign_transaction_with_privacy to ensure privacy guard is added
    tx_b = human_money_core::test_utils::resign_transaction_with_privacy(
        tx_b,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &id_david,
    );
    let mut voucher_path_b = voucher_v1.clone();
    voucher_path_b.transactions.push(tx_b);
    let bundle_b = human_money_core::test_utils::create_test_bundle(
        &identity_alice,
        vec![voucher_path_b],
        &id_david,
        None,
    )
    .unwrap();

    // David receives Path A successfully
    service_david
        .receive_bundle(&bundle_a, &standards_map, None, Some(correct_password), false)
        .unwrap();
    assert_eq!(
        service_david
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .len(),
        1
    );
    assert!(service_david.list_conflicts().unwrap().is_empty());

    // 2. ACT: David attempts to receive the conflicting bundle B with wrong password.
    let result =
        service_david.receive_bundle(&bundle_b, &standards_map, None, Some("WRONG_PASSWORD"), false);

    // 3. ASSERT: Operation fails, state is completely rolled back.
    assert!(
        result.is_err(),
        "Receive should fail on conflict + save error"
    );

    let summaries_after = service_david.get_voucher_summaries(None, None, None).unwrap();
    assert_eq!(
        summaries_after.len(),
        1,
        "Should only contain the original voucher from path A"
    );
    assert_eq!(
        summaries_after[0].status,
        VoucherStatus::Active,
        "Original voucher should remain active"
    );

    let conflicts_after = service_david.list_conflicts().unwrap();
    assert!(
        conflicts_after.is_empty(),
        "No conflict proof should be left in memory after failed operation"
    );
}

/// Test 7.6: Verifies that the `balances_are_summable` flag in the standard correctly
/// affects aggregation in `TransferSummary`.
#[test]
fn test_balances_are_summable_behavior() {
    let dir_recipient = tempdir().unwrap();
    let dir_sender = tempdir().unwrap();
    
    let test_user = &ACTORS.test_user;
    let sender_user = &ACTORS.sender;

    let (mut service, _) = test_utils::setup_service_with_profile(
        dir_recipient.path(),
        test_user,
        "Recipient",
        "pwd",
    );
    let (mut service_sender, _) = test_utils::setup_service_with_profile(
        dir_sender.path(),
        sender_user,
        "Sender",
        "pwd",
    );

    let user_id = service.get_user_id().unwrap();
    let sender_id = service_sender.get_user_id().unwrap();

    // 1. Create summable standard (balances_are_summable = true)
    let (summable_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.identity.uuid = "SUMMABLE-V1".to_string();
        s.immutable.identity.name = "Summable Standard".to_string();
        s.immutable.identity.abbreviation = "EUR".to_string();
        s.immutable.blueprint.unit = "EUR".to_string();
        s.immutable.features.balances_are_summable = true;
    });
    let summable_toml = toml::to_string(&summable_standard).unwrap();

    // 2. Create non-summable standard (balances_are_summable = false)
    let (non_summable_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.identity.uuid = "NON-SUMMABLE-V1".to_string();
        s.immutable.identity.name = "Non-Summable Standard".to_string();
        s.immutable.identity.abbreviation = "ITEM".to_string();
        s.immutable.blueprint.unit = "ITEM".to_string();
        s.immutable.features.balances_are_summable = false;
    });
    let non_summable_toml = toml::to_string(&non_summable_standard).unwrap();

    let mut standards_map = HashMap::new();
    standards_map.insert("SUMMABLE-V1".to_string(), summable_toml.clone());
    standards_map.insert("NON-SUMMABLE-V1".to_string(), non_summable_toml.clone());

    // 3. Create vouchers for both standards in SENDER wallet
    // Summable: 2x 10.0
    for _ in 0..2 {
        service_sender.create_new_voucher(
            &summable_toml,
            NewVoucherData {
                creator_profile: PublicProfile { id: Some(sender_id.clone()), ..Default::default() },
                nominal_value: ValueDefinition {
                    amount: "10.0".to_string(),
                    unit: "EUR".to_string(),
                    abbreviation: None,
                    description: None,
                },
                ..Default::default()
            },
            Some("pwd"),
        ).unwrap();
    }

    // Non-Summable: 2x 1.0
    for _ in 0..2 {
        service_sender.create_new_voucher(
            &non_summable_toml,
            NewVoucherData {
                creator_profile: PublicProfile { id: Some(sender_id.clone()), ..Default::default() },
                nominal_value: ValueDefinition {
                    amount: "1.0".to_string(),
                    unit: "ITEM".to_string(),
                    abbreviation: None,
                    description: None,
                },
                ..Default::default()
            },
            Some("pwd"),
        ).unwrap();
    }

    // 4. Sender transfers all vouchers to Recipient
    let source_vouchers = service_sender.get_voucher_summaries(None, None, None).unwrap();
    let sources = source_vouchers.into_iter().map(|s| human_money_core::wallet::SourceTransfer {
        local_instance_id: s.local_instance_id,
        amount_to_send: s.current_amount,
    }).collect::<Vec<_>>();

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: user_id.clone(),
        sources,
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_res = service_sender.create_transfer_bundle(request, &standards_map, None, Some("pwd")).unwrap();

    // 5. Process bundle in Recipient wallet
    let result = service.receive_bundle(&bundle_res.bundle_bytes, &standards_map, None, Some("pwd"), false).unwrap();

    // 6. ASSERT TransferSummary
    // Summable (EUR): 10.0 + 10.0 = 20.0 (in summable_amounts)
    // Note: current_amount in summaries is formatted with 4 decimal places, hence "20.00"
    assert_eq!(result.transfer_summary.summable_amounts.get("EUR").unwrap(), "20.00");
    assert!(!result.transfer_summary.countable_items.contains_key("EUR"));

    // Non-Summable (ITEM): 2 items (in countable_items)
    assert_eq!(*result.transfer_summary.countable_items.get("ITEM").unwrap(), 2);
    assert!(!result.transfer_summary.summable_amounts.contains_key("ITEM"));
}
