// tests/wallet_api/role_integration.rs
// cargo test --test wallet_api_tests role_integration
//!
//! Integration tests for automatic role recognition (Victim vs. Witness)
//! during conflict processing.

use human_money_core::{
    VoucherStatus,
    models::{
        profile::PublicProfile,
        voucher::{ValueDefinition, Transaction},
        conflict::{ConflictRole, ProofOfDoubleSpend},
    },
    services::{crypto_utils, voucher_manager::NewVoucherData},
    test_utils::{self, ACTORS, FREETALER_STANDARD, generate_signed_standard_toml},
};

use chrono::{Duration, Utc};
use std::collections::HashMap;
use tempfile::tempdir;

/// Tests whether a user is correctly identified as a VICTIM.
/// Scenario: Alice has a voucher that is quarantined by an external proof (gossip)
/// because someone else received it earlier.
#[test]
fn test_integration_detects_victim_role() {
    human_money_core::set_signature_bypass(true);
    
    // --- 1. Setup ---
    let dir_alice = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    service_alice.unlock_session("pwd", 60).unwrap();
    let id_alice = service_alice.get_user_id().unwrap();
    
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // --- 2. Alice receives a voucher (V1) ---
    service_alice.create_new_voucher(
        &freetaler_toml,
        NewVoucherData {
            nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
            creator_profile: PublicProfile { id: Some(id_alice.clone()), ..Default::default() },
            ..Default::default()
        },
        Some("pwd"),
    ).unwrap();
    
    let alice_v_id = service_alice.get_voucher_summaries(None, None, None).unwrap()[0].local_instance_id.clone();
    
    // Retrieve data for the proof
    let (wallet_alice, identity_alice) = service_alice.get_unlocked_mut_for_test();
    let voucher_base = wallet_alice.voucher_store.vouchers.get(&alice_v_id).unwrap().voucher.clone();
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto_utils::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let alice_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_alice.signing_key);
    let alice_holder_pub = bs58::encode(alice_holder_key.verifying_key().to_bytes()).into_string();

    // --- 3. Simulate proof of an EARLIER transfer to Charlie ---
    let time_early = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let tx_early_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_early,
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub.clone()),
        ..Default::default()
    };
    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&voucher_base.transactions[0]).unwrap();
    let tx_early = test_utils::resign_transaction_with_privacy(
        tx_early_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &ACTORS.charlie.user_id.clone(), // Use a real actor for valid DID format
    );

    let proof = ProofOfDoubleSpend {
        proof_id: "test-proof-victim".to_string(),
        offender_id: id_alice.clone(),
        conflicting_transactions: vec![tx_early, voucher_base.transactions.last().unwrap().clone()],
        reporter_id: "reporter-xyz".to_string(),
        resolutions: None,
        layer2_verdict: None,
        fork_point_prev_hash: prev_tx_hash,
        deletable_at: (Utc::now() + Duration::days(1)).to_rfc3339(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: "sig".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        non_redeemable_test_voucher: false,
    };

    // --- 4. Alice must first have the voucher in quarantine so import_proof identifies Victim ---
    // (Or we use maintenance logic, but import_proof is more direct for testing)
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        wallet.voucher_store.vouchers.get_mut(&alice_v_id).unwrap().status = VoucherStatus::Quarantined { reason: "test".to_string() };
    }

    // --- 5. Import proof ---
    service_alice.import_proof(proof, Some("pwd")).unwrap();

    // --- 6. ASSERT ---
    let conflicts = service_alice.list_conflicts().unwrap();
    let victim_conflict = conflicts.iter().find(|c| c.proof_id == "test-proof-victim");
    assert!(victim_conflict.is_some());
    assert_eq!(victim_conflict.unwrap().conflict_role, ConflictRole::Victim, "Alice must be identified as Victim");

    human_money_core::set_signature_bypass(false);
}

/// Tests whether a user is correctly identified as a WITNESS.
/// Scenario: Alice receives two payments for the same amount, one of which is a double spend.
/// She retains an active voucher and is therefore only a witness to the fraud attempt.
#[test]
fn test_integration_detects_witness_role_on_split_win() {
    human_money_core::set_signature_bypass(true);
    
    // --- 1. Setup ---
    let (dir_alice, dir_bob) = (tempdir().unwrap(), tempdir().unwrap());
    let (alice, bob) = (&ACTORS.alice, &ACTORS.bob);
    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_bob, _) = test_utils::setup_service_with_profile(dir_bob.path(), bob, "Bob", "pwd");
    service_alice.unlock_session("pwd", 60).unwrap();
    service_bob.unlock_session("pwd", 60).unwrap();
    let id_alice = service_alice.get_user_id().unwrap();
    let id_bob = service_bob.get_user_id().unwrap();
    
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // --- 2. Bob creates a voucher ---
    service_bob.create_new_voucher(
        &freetaler_toml,
        NewVoucherData {
            nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
            creator_profile: PublicProfile { id: Some(id_bob.clone()), ..Default::default() },
            ..Default::default()
        },
        Some("pwd"),
    ).unwrap();
    
    let bob_v_id = service_bob.get_voucher_summaries(None, None, None).unwrap()[0].local_instance_id.clone();
    let (wallet_bob, identity_bob) = service_bob.get_unlocked_mut_for_test();
    let voucher_base = wallet_bob.voucher_store.vouchers.get(&bob_v_id).unwrap().voucher.clone();

    // --- 3. Bob creates two competing paths to Alice ---
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto_utils::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let bob_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_bob.signing_key);
    let bob_holder_pub = bs58::encode(bob_holder_key.verifying_key().to_bytes()).into_string();

    let time_early = (Utc::now() + Duration::seconds(10)).to_rfc3339();
    let time_late = (Utc::now() + Duration::seconds(30)).to_rfc3339();

    // Path A (Early)
    let tx_early_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_early,
        sender_id: Some(id_bob.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(bob_holder_pub.clone()),
        ..Default::default()
    };
    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&voucher_base.transactions[0]).unwrap();
    let tx_early = test_utils::resign_transaction_with_privacy(
        tx_early_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &id_alice,
    );
    let mut v_early = voucher_base.clone();
    v_early.transactions.push(tx_early);
    let bundle_early = test_utils::create_test_bundle(&identity_bob, vec![v_early], &id_alice, None).unwrap();

    // Path B (Late)
    let tx_late_raw = Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: time_late,
        sender_id: Some(id_bob.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(bob_holder_pub),
        ..Default::default()
    };
    let tx_late = test_utils::resign_transaction_with_privacy(
        tx_late_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &id_alice,
    );
    let mut v_late = voucher_base.clone();
    v_late.transactions.push(tx_late);
    let bundle_late = test_utils::create_test_bundle(&identity_bob, vec![v_late], &id_alice, None).unwrap();

    // --- 4. Alice receives both ---
    service_alice.receive_bundle(&bundle_early, &standards_map, None, Some("pwd"), false).unwrap();
    service_alice.receive_bundle(&bundle_late, &standards_map, None, Some("pwd"), false).unwrap();

    // --- 5. ASSERT ---
    let conflicts = service_alice.list_conflicts().unwrap();
    let witness_conflict = conflicts.iter().find(|c| c.conflict_role == ConflictRole::Witness);
    assert!(witness_conflict.is_some(), "Alice must be identified as Witness, since she retains an active path");

    human_money_core::set_signature_bypass(false);
}

/// Tests whether a user is correctly identified as a VICTIM when they ONLY possess the losing voucher
/// and an external proof (gossip) is imported.
#[test]
fn test_integration_detects_victim_role_on_loser_only() {
    human_money_core::set_signature_bypass(true);
    
    // --- 1. Setup ---
    let (dir_alice, dir_bob) = (tempdir().unwrap(), tempdir().unwrap());
    let (alice, bob) = (&ACTORS.alice, &ACTORS.bob);
    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_bob, _) = test_utils::setup_service_with_profile(dir_bob.path(), bob, "Bob", "pwd");
    service_alice.unlock_session("pwd", 60).unwrap();
    service_bob.unlock_session("pwd", 60).unwrap();
    let id_alice = service_alice.get_user_id().unwrap();
    let id_bob = service_bob.get_user_id().unwrap();
    
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // --- 2. Bob (Actor A) creates a voucher ---
    service_bob.create_new_voucher(
        &freetaler_toml,
        NewVoucherData {
            nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
            creator_profile: PublicProfile { id: Some(id_bob.clone()), ..Default::default() },
            ..Default::default()
        },
        Some("pwd"),
    ).unwrap();
    
    let bob_v_id = service_bob.get_voucher_summaries(None, None, None).unwrap()[0].local_instance_id.clone();
    let (wallet_bob, identity_bob) = service_bob.get_unlocked_mut_for_test();
    let voucher_base = wallet_bob.voucher_store.vouchers.get(&bob_v_id).unwrap().voucher.clone();

    // Retrieve cryptographic data
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto_utils::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let bob_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_bob.signing_key);
    let bob_holder_pub = bs58::encode(bob_holder_key.verifying_key().to_bytes()).into_string();
    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&voucher_base.transactions[0]).unwrap();

    // --- 3. Bob double-spends: early to Charlie (Winner) and late to Alice (Loser) ---
    let time_early = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let time_late = Utc::now().to_rfc3339();

    // Winner transaction to Charlie (Actor B)
    let tx_early_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_early,
        sender_id: Some(id_bob.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(bob_holder_pub.clone()),
        ..Default::default()
    };
    let tx_early = test_utils::resign_transaction_with_privacy(
        tx_early_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &ACTORS.charlie.user_id.clone(),
    );

    // Loser transaction to Alice (Actor C, us)
    let tx_late_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_late,
        sender_id: Some(id_bob.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(bob_holder_pub),
        ..Default::default()
    };
    let tx_late = test_utils::resign_transaction_with_privacy(
        tx_late_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &id_alice,
    );

    // Build voucher with loser transaction for Alice
    let mut v_late = voucher_base.clone();
    v_late.transactions.push(tx_late.clone());
    let bundle_late = test_utils::create_test_bundle(&identity_bob, vec![v_late], &id_alice, None).unwrap();

    // --- 4. Alice receives bundle with loser transaction ---
    service_alice.receive_bundle(&bundle_late, &standards_map, None, Some("pwd"), false).unwrap();
    let alice_v_id = service_alice.get_voucher_summaries(None, None, None).unwrap()[0].local_instance_id.clone();

    // Check if Alice's voucher is initially active
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        let instance = wallet.voucher_store.vouchers.get(&alice_v_id).unwrap();
        assert!(matches!(instance.status, VoucherStatus::Active));
    }

    // --- 5. Build proof ---
    let proof = ProofOfDoubleSpend {
        proof_id: "test-proof-victim-loser-only".to_string(),
        offender_id: id_bob.clone(),
        conflicting_transactions: vec![tx_early, tx_late],
        reporter_id: "reporter-xyz".to_string(),
        resolutions: None,
        layer2_verdict: None,
        fork_point_prev_hash: prev_tx_hash,
        deletable_at: (Utc::now() + Duration::days(1)).to_rfc3339(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: "sig".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        non_redeemable_test_voucher: false,
    };

    // --- 6. Import proof into Alice ---
    service_alice.import_proof(proof, Some("pwd")).unwrap();

    // --- 7. ASSERT ---
    // A: Alice's local voucher must be quarantined
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        let instance = wallet.voucher_store.vouchers.get(&alice_v_id).unwrap();
        assert!(
            matches!(instance.status, VoucherStatus::Quarantined { .. }),
            "Alice's local voucher must be marked as Quarantined"
        );
    }

    // B: Alice must be identified as Victim
    let conflicts = service_alice.list_conflicts().unwrap();
    let victim_conflict = conflicts.iter().find(|c| c.proof_id == "test-proof-victim-loser-only");
    assert!(victim_conflict.is_some());
    assert_eq!(
        victim_conflict.unwrap().conflict_role,
        ConflictRole::Victim,
        "Alice must be identified as Victim, since she possesses the losing voucher"
    );

    human_money_core::set_signature_bypass(false);
}
