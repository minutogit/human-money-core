// tests/wallet_api/role_integration.rs
// cargo test --test wallet_api_tests role_integration
//!
//! Integrationstests für die automatische Rollenerkennung (Victim vs. Witness)
//! während der Konfliktverarbeitung.

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

/// Testet, ob ein Nutzer korrekt als OPFER (Victim) erkannt wird.
/// Szenario: Alice hat einen Gutschein, der durch einen externen Beweis (Gossip)
/// in Quarantäne geschickt wird, da jemand anderes ihn früher erhalten hat.
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

    // --- 2. Alice erhält einen Gutschein (V1) ---
    service_alice.create_new_voucher(
        &freetaler_toml, "en",
        NewVoucherData {
            nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
            creator_profile: PublicProfile { id: Some(id_alice.clone()), ..Default::default() },
            ..Default::default()
        },
        Some("pwd"),
    ).unwrap();
    
    let alice_v_id = service_alice.get_voucher_summaries(None, None, None).unwrap()[0].local_instance_id.clone();
    
    // Wir holen uns die Daten für den Beweis
    let (wallet_alice, identity_alice) = service_alice.get_unlocked_mut_for_test();
    let voucher_base = wallet_alice.voucher_store.vouchers.get(&alice_v_id).unwrap().voucher.clone();
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto_utils::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let alice_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_alice.signing_key);
    let alice_holder_pub = bs58::encode(alice_holder_key.verifying_key().to_bytes()).into_string();

    // --- 3. Wir simulieren einen Beweis für einen FRÜHEREN Transfer an Charlie ---
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

    // --- 4. Alice muss den Gutschein erst in Quarantäne haben, damit import_proof Victim erkennt ---
    // (Oder wir nutzen die maintenance Logik, aber import_proof ist direkter für den Test)
    {
        let (wallet, _) = service_alice.get_unlocked_mut_for_test();
        wallet.voucher_store.vouchers.get_mut(&alice_v_id).unwrap().status = VoucherStatus::Quarantined { reason: "test".to_string() };
    }

    // --- 5. Proof importieren ---
    service_alice.import_proof(proof, Some("pwd")).unwrap();

    // --- 6. ASSERT ---
    let conflicts = service_alice.list_conflicts().unwrap();
    let victim_conflict = conflicts.iter().find(|c| c.proof_id == "test-proof-victim");
    assert!(victim_conflict.is_some());
    assert_eq!(victim_conflict.unwrap().conflict_role, ConflictRole::Victim, "Alice muss als Victim erkannt werden");

    human_money_core::set_signature_bypass(false);
}

/// Testet, ob ein Nutzer korrekt als ZEUGE (Witness) erkannt wird.
/// Szenario: Alice bekommt zwei Zahlungen für denselben Betrag, eine davon ist ein Double-Spend.
/// Sie behält einen aktiven Gutschein und ist daher nur Zeuge des Betrugsversuchs.
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

    // --- 2. Bob erstellt einen Gutschein ---
    service_bob.create_new_voucher(
        &freetaler_toml, "en",
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

    // --- 3. Bob erstellt zwei konkurrierende Pfade an Alice ---
    let prev_tx = voucher_base.transactions.last().unwrap();
    let prev_tx_hash = crypto_utils::get_hash(human_money_core::services::utils::to_canonical_json(prev_tx).unwrap());
    let bob_holder_key = test_utils::derive_holder_key(&voucher_base, &identity_bob.signing_key);
    let bob_holder_pub = bs58::encode(bob_holder_key.verifying_key().to_bytes()).into_string();

    let time_early = (Utc::now() + Duration::seconds(10)).to_rfc3339();
    let time_late = (Utc::now() + Duration::seconds(30)).to_rfc3339();

    // Pfad A (Early)
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

    // Pfad B (Late)
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

    // --- 4. Alice empfängt beide ---
    service_alice.receive_bundle(&bundle_early, &standards_map, None, Some("pwd"), false).unwrap();
    service_alice.receive_bundle(&bundle_late, &standards_map, None, Some("pwd"), false).unwrap();

    // --- 5. ASSERT ---
    let conflicts = service_alice.list_conflicts().unwrap();
    let witness_conflict = conflicts.iter().find(|c| c.conflict_role == ConflictRole::Witness);
    assert!(witness_conflict.is_some(), "Alice muss als Witness erkannt werden, da sie einen aktiven Pfad behält");

    human_money_core::set_signature_bypass(false);
}
