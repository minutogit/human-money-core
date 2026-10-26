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
        conflict::ConflictRole,
    },
    services::crypto, NewVoucherData,
    test_utils::{self, ACTORS, FREETALER_STANDARD, generate_signed_standard_toml},
};

use chrono::{Duration, Utc};
use std::collections::HashMap;
use tempfile::tempdir;

/// Creates fully signed forks with production key ownership and private receipts.
fn resign_role_transaction(
    mut tx: Transaction,
    owner: &ed25519_dalek::SigningKey,
    voucher_id: &str,
    input: Option<&crypto::EphemeralKey>,
    recipient_id: &str,
) -> Transaction {
    let input = input.unwrap();
    let seed = [31u8; 32];
    let recipient = crypto::get_pubkey_from_user_id(recipient_id).unwrap();
    tx.receiver_ephemeral_pub_hash = Some(crypto::get_hash(
        crypto::derive_stealth_ephemeral_point(&recipient, &seed)
            .unwrap()
            .compress()
            .as_bytes(),
    ));
    tx.trap_data = None;
    tx.privacy_guard = None;
    tx.t_id.clear();
    tx.layer2_signature = None;
    tx.sender_identity_signature = None;
    tx.t_id = crypto::get_hash(human_money_core::services::utils::to_canonical_json(&tx).unwrap());
    let eph = input.verifying_key().to_bytes();
    let tag =
        crypto::get_ds_tag(&tx.prev_hash, tx.sender_ephemeral_pub.as_deref().unwrap()).unwrap();
    let (_, witness) = human_money_core::services::trap_manager::generate_sst_trap(
        owner,
        &tag,
        &eph,
        &tx.t_id,
        "",
        &input.input_seed().unwrap(),
    )
    .unwrap();
    let payload = human_money_core::models::voucher::RecipientPayload {
        sender_permanent_did: tx
            .sender_id
            .clone()
            .unwrap_or_else(|| crypto::create_user_id(&owner.verifying_key(), None).unwrap()),
        next_key_seed: bs58::encode(seed).into_string(),
        trap_k_point: Some(witness.k_trap.clone()),
        dleq_c: Some(witness.dleq_c.clone()),
        dleq_s: Some(witness.dleq_s.clone()),
        trap_r_sig: Some(witness.r_sig.clone()),
        trap_s_sig: Some(witness.s_sig.clone()),
        trap_m_r: Some(witness.m_r.clone()),
        trap_m_s: Some(witness.m_s.clone()),
        input_key_seed: Some(witness.input_seed.clone()),
        ..Default::default()
    };
    tx.privacy_guard = Some(
        crypto::encrypt_recipient_payload(
            &serde_json::to_vec(&payload).unwrap(),
            &recipient,
            recipient_id,
        )
        .unwrap(),
    );
    let guard = human_money_core::services::l2_gateway::privacy_guard_commitment(
        tx.privacy_guard.as_deref(),
    );
    tx.trap_data = Some(
        human_money_core::services::trap_manager::shard_from_witness(
            &witness,
            &crypto::ed25519_pk_to_curve_point(&owner.verifying_key()).unwrap(),
            &tag,
            &eph,
            &tx.t_id,
            &guard,
        )
        .unwrap(),
    );
    test_utils::resign_transaction_ext(tx, owner, voucher_id, Some(input))
}

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
    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    
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
    
    let alice_v_id = service_alice
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();
    
    // Retrieve data for the proof
    let (wallet_alice, identity_alice) = service_alice.get_unlocked_mut_for_test();
    let voucher_base = wallet_alice.voucher_store.vouchers.get(&alice_v_id).unwrap().voucher.clone();
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
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
    // Fixture hardening (AUDIT-01-F05): attach valid SST shards bound to the
    // claimed offender (Alice) BEFORE signing, so the proof passes both the
    // layer2 digest check and the attribution verification.
    let tx_early = resign_role_transaction(
        tx_early_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &ACTORS.charlie.user_id.clone(), // Use a real actor for valid DID format
    );

    // Build the LOSING fork transaction (late spend by Alice).
    let tx_late_raw = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: Utc::now().to_rfc3339(),
        sender_id: Some(id_alice.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_ephemeral_pub: Some(alice_holder_pub.clone()),
        ..Default::default()
    };
    let tx_late = resign_role_transaction(
        tx_late_raw,
        &identity_alice.signing_key,
        &v_id,
        Some(&alice_holder_key),
        &ACTORS.charlie.user_id.clone(),
    );

    // SECURITY: proofs must be properly signed and internally consistent
    // (import_proof enforces structure, reporter signature and proof-id).
    let genuine_proof = human_money_core::services::conflict_manager::create_proof_of_double_spend(
        id_alice.clone(),
        prev_tx_hash.clone(),
        vec![tx_early.clone(), tx_late.clone()],
        (Utc::now() + Duration::days(1)).to_rfc3339(),
        &ACTORS.charlie.identity,
        false,
    )
    .unwrap();
    let test_proof_id = genuine_proof.proof_id.clone();

    // --- 4. Alice must first have the losing transaction locally (quarantined), so import_proof identifies Victim ---
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        let instance = wallet.voucher_store.vouchers.get_mut(&alice_v_id).unwrap();
        instance.voucher.transactions.push(tx_late);
        instance.status = VoucherStatus::Quarantined { reason: "test".to_string() };
    }

    // --- 5. Import proof ---
    service_alice.import_proof(genuine_proof, Some("pwd")).unwrap();

    // --- 6. ASSERT ---
    let conflicts = service_alice.list_conflicts().unwrap();
    let victim_conflict = conflicts.iter().find(|c| c.proof_id == test_proof_id);
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
    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let id_bob = service_bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    
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
    
    let bob_v_id = service_bob
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();
    let (wallet_bob, identity_bob) = service_bob.get_unlocked_mut_for_test();
    let voucher_base = wallet_bob.voucher_store.vouchers.get(&bob_v_id).unwrap().voucher.clone();

    // --- 3. Bob creates two competing paths to Alice ---
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
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
    let tx_early = resign_role_transaction(
        tx_early_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &id_alice,
    );
    let mut v_early = voucher_base.clone();
    v_early.transactions.push(tx_early);
    let bundle_early = test_utils::create_test_bundle(identity_bob, vec![v_early], &id_alice, None).unwrap();

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
    let tx_late = resign_role_transaction(
        tx_late_raw,
        &identity_bob.signing_key,
        &v_id,
        Some(&bob_holder_key),
        &id_alice,
    );
    let mut v_late = voucher_base.clone();
    v_late.transactions.push(tx_late);
    let bundle_late = test_utils::create_test_bundle(identity_bob, vec![v_late], &id_alice, None).unwrap();

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
    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let id_bob = service_bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    
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
    
    let bob_v_id = service_bob
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();
    let (wallet_bob, identity_bob) = service_bob.get_unlocked_mut_for_test();
    let voucher_base = wallet_bob.voucher_store.vouchers.get(&bob_v_id).unwrap().voucher.clone();

    // Retrieve cryptographic data
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let bob_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_bob.signing_key);
    let bob_holder_pub = bs58::encode(bob_holder_key.verifying_key().to_bytes()).into_string();
    let v_id = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&voucher_base.transactions[0]).unwrap();

    // --- 3. Bob double-spends: early to Charlie (Winner) and late to Alice (Loser) ---
    let time_early = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let time_late = Utc::now().to_rfc3339();

    // Winner transaction to Charlie (Actor B) — SST trap + witness guard
    // attached before signing so the HMC_TX_AUTH_V3 digest and the fail-closed
    // ingest check both pass.
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
    let tx_early = resign_role_transaction(tx_early_raw, &identity_bob.signing_key, &v_id, Some(&bob_holder_key), &ACTORS.charlie.user_id);

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
    let tx_late = resign_role_transaction(tx_late_raw, &identity_bob.signing_key, &v_id, Some(&bob_holder_key), &id_alice);

    // Build voucher with loser transaction for Alice
    let mut v_late = voucher_base.clone();
    v_late.transactions.push(tx_late.clone());
    let bundle_late = test_utils::create_test_bundle(identity_bob, vec![v_late], &id_alice, None).unwrap();

    // --- 4. Alice receives bundle with loser transaction ---
    service_alice.receive_bundle(&bundle_late, &standards_map, None, Some("pwd"), false).unwrap();
    let alice_v_id = service_alice
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    // Check if Alice's voucher is initially active
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        let instance = wallet.voucher_store.vouchers.get(&alice_v_id).unwrap();
        assert!(matches!(instance.status, VoucherStatus::Active));
    }

    // --- 5. Build proof (properly signed by an honest third party) ---
    let genuine_proof = human_money_core::services::conflict_manager::create_proof_of_double_spend(
        id_bob.clone(),
        prev_tx_hash.clone(),
        vec![tx_early, tx_late],
        (Utc::now() + Duration::days(1)).to_rfc3339(),
        &ACTORS.charlie.identity,
        false,
    )
    .unwrap();
    let test_proof_id = genuine_proof.proof_id.clone();

    // --- 6. Import proof into Alice ---
    service_alice.import_proof(genuine_proof, Some("pwd")).unwrap();

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
    let victim_conflict = conflicts.iter().find(|c| c.proof_id == test_proof_id);
    assert!(victim_conflict.is_some());
    assert_eq!(
        victim_conflict.unwrap().conflict_role,
        ConflictRole::Victim,
        "Alice must be identified as Victim, since she possesses the losing voucher"
    );

    human_money_core::set_signature_bypass(false);
}
