// tests/wallet_api/privacy_balance_checks.rs

use human_money_core::models::voucher_standard_definition::{VoucherStandardDefinition, PrivacyMode};
use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{self, ACTORS, SILVER_STANDARD};
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer, CreateBundleResult};
use human_money_core::wallet::Wallet;
use human_money_core::VoucherStatus;
use std::collections::HashMap;

/// Helper function to configure a standard with a specific Privacy Mode
fn setup_standard(mode: PrivacyMode) -> (VoucherStandardDefinition, String, HashMap<String, VoucherStandardDefinition>) {
    let mut standard_def = SILVER_STANDARD.0.clone();
    standard_def.immutable.features.privacy_mode = mode;
    let standard_hash = get_hash(to_canonical_json(&standard_def.immutable).unwrap());
    
    let mut standards_map = HashMap::new();
    standards_map.insert(standard_def.immutable.identity.uuid.clone(), standard_def.clone());
    
    (standard_def, standard_hash, standards_map)
}

/// Helper to get active summaries
fn list_active(wallet: &Wallet, identity: &human_money_core::models::profile::UserIdentity) -> Vec<human_money_core::wallet::VoucherSummary> {
    wallet.list_vouchers(Some(identity), None, Some(&[VoucherStatus::Active]))
}

/// Helper to get the total spendable balance for an identity
fn get_balance(wallet: &Wallet, identity: &human_money_core::models::profile::UserIdentity) -> f64 {
    let active = list_active(wallet, identity);
    active.iter().map(|v| v.current_amount.parse::<f64>().unwrap_or(0.0)).sum()
}

#[test]
fn test_deep_privacy_balance_calculation() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, _standard_hash, standards_map) = setup_standard(PrivacyMode::Private);

    let mut alice = test_utils::setup_in_memory_wallet(&ACTORS.alice.identity);
    let mut bob = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);
    let mut charlie = test_utils::setup_in_memory_wallet(&ACTORS.charlie.identity);
    let mut dave = test_utils::setup_in_memory_wallet(&ACTORS.david.identity);

    // =========================================================================
    // Schritt 0: Setup & Init
    // Alice erstellt einen Gutschein über 1000.
    // =========================================================================
    let _start_id = test_utils::add_voucher_to_wallet(
        &mut alice, 
        &ACTORS.alice.identity, 
        "1000", 
        &standard_def, 
        true
    ).expect("Voucher creation failed");

    assert_eq!(get_balance(&alice, &ACTORS.alice.identity), 1000.0, "Alices Guthaben nach Init ist inkorrekt");
    assert_eq!(get_balance(&bob, &ACTORS.bob.identity), 0.0, "Bobs Guthaben nach Init ist inkorrekt");
    assert_eq!(get_balance(&charlie, &ACTORS.charlie.identity), 0.0, "Charlies Guthaben nach Init ist inkorrekt");
    assert_eq!(get_balance(&dave, &ACTORS.david.identity), 0.0, "Daves Guthaben nach Init ist inkorrekt");

    // =========================================================================
    // Schritt 1: Der erste große Split
    // Alice sendet 300 an Bob (Privacy Mode).
    // =========================================================================
    let alice_vouchers_before = list_active(&alice, &ACTORS.alice.identity);
    let alice_source_id_1 = alice_vouchers_before[0].local_instance_id.clone();
    
    let CreateBundleResult { bundle_bytes: b1, .. } = alice.execute_multi_transfer_and_bundle(
        &ACTORS.alice.identity, &standards_map, 
        MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: alice_source_id_1, amount_to_send: "300".to_string() }],
            notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
        }, None).expect("Transfer Alice -> Bob fehlgeschlagen");

    bob.process_encrypted_transaction_bundle(&ACTORS.bob.identity, &b1, None, &standards_map).unwrap();

    assert_eq!(get_balance(&alice, &ACTORS.alice.identity), 700.0, "Alices Guthaben nach Schritt 1 ist inkorrekt (Change wurde ggf. nicht erkannt)");
    assert_eq!(get_balance(&bob, &ACTORS.bob.identity), 300.0, "Bobs Guthaben nach Schritt 1 ist inkorrekt");
    assert_eq!(get_balance(&charlie, &ACTORS.charlie.identity), 0.0, "Charlies Guthaben nach Schritt 1 ist inkorrekt");
    assert_eq!(get_balance(&dave, &ACTORS.david.identity), 0.0, "Daves Guthaben nach Schritt 1 ist inkorrekt");

    // =========================================================================
    // Schritt 2: Verketteter Split (Empfänger splittet weiter)
    // Bob sendet 100 von seinen 300 an Charlie.
    // =========================================================================
    let bob_vouchers_before = list_active(&bob, &ACTORS.bob.identity);
    let bob_source_id = bob_vouchers_before[0].local_instance_id.clone();
    
    let CreateBundleResult { bundle_bytes: b2, .. } = bob.execute_multi_transfer_and_bundle(
        &ACTORS.bob.identity, &standards_map, 
        MultiTransferRequest {
            recipient_id: ACTORS.charlie.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: bob_source_id, amount_to_send: "100".to_string() }],
            notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
        }, None).expect("Transfer Bob -> Charlie fehlgeschlagen");

    charlie.process_encrypted_transaction_bundle(&ACTORS.charlie.identity, &b2, None, &standards_map).unwrap();

    assert_eq!(get_balance(&alice, &ACTORS.alice.identity), 700.0, "Alices Guthaben nach Schritt 2 ist inkorrekt (sollte unberührt bleiben)");
    assert_eq!(get_balance(&bob, &ACTORS.bob.identity), 200.0, "Bobs Guthaben nach Schritt 2 ist inkorrekt (sollte 200 Wechselgeld sein)");
    assert_eq!(get_balance(&charlie, &ACTORS.charlie.identity), 100.0, "Charlies Guthaben nach Schritt 2 ist inkorrekt");
    assert_eq!(get_balance(&dave, &ACTORS.david.identity), 0.0, "Daves Guthaben nach Schritt 2 ist inkorrekt");

    // =========================================================================
    // Schritt 3: Paralleler Split (Ursprungs-Sender splittet erneut)
    // Alice sendet 250 von ihren verbliebenen 700 an Dave.
    // =========================================================================
    let alice_vouchers_step3 = list_active(&alice, &ACTORS.alice.identity);
    let alice_source_id_3 = alice_vouchers_step3.iter().find(|v| v.current_amount == "700.0000").expect("Alice must have her 700 voucher").local_instance_id.clone();

    let CreateBundleResult { bundle_bytes: b3, .. } = alice.execute_multi_transfer_and_bundle(
        &ACTORS.alice.identity, &standards_map, 
        MultiTransferRequest {
            recipient_id: ACTORS.david.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: alice_source_id_3, amount_to_send: "250".to_string() }],
            notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
        }, None).expect("Transfer Alice -> Dave fehlgeschlagen");

    dave.process_encrypted_transaction_bundle(&ACTORS.david.identity, &b3, None, &standards_map).unwrap();

    assert_eq!(get_balance(&alice, &ACTORS.alice.identity), 450.0, "Alices Guthaben nach Schritt 3 ist inkorrekt (700 - 250)");
    assert_eq!(get_balance(&bob, &ACTORS.bob.identity), 200.0, "Bobs Guthaben nach Schritt 3 ist inkorrekt (sollte unberührt bleiben)");
    assert_eq!(get_balance(&charlie, &ACTORS.charlie.identity), 100.0, "Charlies Guthaben nach Schritt 3 ist inkorrekt (sollte unberührt bleiben)");
    assert_eq!(get_balance(&dave, &ACTORS.david.identity), 250.0, "Daves Guthaben nach Schritt 3 ist inkorrekt");

    // =========================================================================
    // Schritt 4: Der Zusammenfluss (Aggregation-Check)
    // Charlie sendet seine gesamten 100 an Dave (Full Transfer, kein Split).
    // =========================================================================
    let charlie_vouchers = list_active(&charlie, &ACTORS.charlie.identity);
    let charlie_source_id = charlie_vouchers[0].local_instance_id.clone();

    let CreateBundleResult { bundle_bytes: b4, .. } = charlie.execute_multi_transfer_and_bundle(
        &ACTORS.charlie.identity, &standards_map, 
        MultiTransferRequest {
            recipient_id: ACTORS.david.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: charlie_source_id, amount_to_send: "100".to_string() }],
            notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
        }, None).expect("Transfer Charlie -> Dave fehlgeschlagen");

    dave.process_encrypted_transaction_bundle(&ACTORS.david.identity, &b4, None, &standards_map).unwrap();

    assert_eq!(get_balance(&alice, &ACTORS.alice.identity), 450.0, "Alices Guthaben nach Schritt 4 ist inkorrekt");
    assert_eq!(get_balance(&bob, &ACTORS.bob.identity), 200.0, "Bobs Guthaben nach Schritt 4 ist inkorrekt");
    assert_eq!(get_balance(&charlie, &ACTORS.charlie.identity), 0.0, "Charlies Guthaben nach Schritt 4 ist inkorrekt (sollte 0 sein)");
    assert_eq!(get_balance(&dave, &ACTORS.david.identity), 350.0, "Daves Guthaben nach Schritt 4 ist inkorrekt (Summe aus 250 + 100)");
}
