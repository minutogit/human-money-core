// tests/wallet_api/chained_workflows.rs

use human_money_core::models::voucher_standard_definition::{VoucherStandardDefinition, PrivacyMode};
use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer, CreateBundleResult};
use human_money_core::wallet::Wallet;
use human_money_core::VoucherStatus;
use std::collections::HashMap;

/// Helper function to configure a standard with a specific Privacy Mode
fn setup_standard(mode: PrivacyMode) -> (VoucherStandardDefinition, String, HashMap<String, VoucherStandardDefinition>) {
    let mut standard_def = FREETALER_STANDARD.0.clone();
    standard_def.immutable.features.privacy_mode = mode;
    let standard_hash = get_hash(to_canonical_json(&standard_def.immutable).unwrap());
    
    let mut standards_map = HashMap::new();
    standards_map.insert(standard_def.immutable.identity.uuid.clone(), standard_def.clone());
    
    (standard_def, standard_hash, standards_map)
}

/// Helper to get the first local ID from a wallet
fn get_first_local_id(wallet: &Wallet) -> String {
    wallet.voucher_store.vouchers.keys().next().expect("Wallet must have at least one voucher").clone()
}

/// Helper to get active summaries
fn list_active(wallet: &Wallet, identity: &human_money_core::models::profile::UserIdentity) -> Vec<human_money_core::wallet::VoucherSummary> {
    wallet.list_vouchers(Some(identity), None, Some(&[VoucherStatus::Active]), None)
}

// ============================================================================
// AUFGABE 1: Strict Public Chain
// ============================================================================
#[test]
fn test_chained_workflow_strict_public() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, _standard_hash, standards_map) = setup_standard(PrivacyMode::Public);

    let mut alice = test_utils::setup_in_memory_wallet(&ACTORS.alice.identity);
    let mut bob = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);
    let mut charlie = test_utils::setup_in_memory_wallet(&ACTORS.charlie.identity);

    // --- INIT: Alice creates voucher of 100 ---
    let local_id = test_utils::add_voucher_to_wallet(
        &mut alice, 
        &ACTORS.alice.identity, 
        "100", 
        &standard_def, 
        true
    ).expect("Voucher creation failed");

    // --- PHASE 1: Alice sends 40 to Bob (Split) ---
    assert!(alice.execute_multi_transfer_and_bundle(
        &ACTORS.alice.identity, &standards_map,
        MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: local_id.clone(), amount_to_send: "40".to_string() }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: Some(true), 
        },
        None
    ).is_err(), "Public standard should reject use_privacy_mode=true");

    let CreateBundleResult { bundle_bytes, .. } = alice.execute_multi_transfer_and_bundle(
        &ACTORS.alice.identity, &standards_map,
        MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: local_id, amount_to_send: "40".to_string() }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: Some(false),
        },
        None
    ).expect("Alice transfer to Bob failed");

    bob.process_encrypted_transaction_bundle(&ACTORS.bob.identity, &bundle_bytes, None, &standards_map).unwrap();

    let list_alice = list_active(&alice, &ACTORS.alice.identity);
    assert_eq!(list_alice[0].current_amount, "60.0000");
    
    let v_bob = bob.get_voucher_details(&get_first_local_id(&bob)).unwrap().voucher;
    let tx_bob_0 = &v_bob.transactions.last().unwrap();
    assert_eq!(tx_bob_0.sender_id, Some(ACTORS.alice.user_id.clone()), "Sender ID must be visible");
    assert_eq!(tx_bob_0.recipient_id, ACTORS.bob.user_id.clone(), "Recipient ID must be visible");

    // --- PHASE 2: Bob sends 40 to Charlie (Full) ---
    let CreateBundleResult { bundle_bytes, .. } = bob.execute_multi_transfer_and_bundle(
        &ACTORS.bob.identity, &standards_map,
        MultiTransferRequest {
            recipient_id: ACTORS.charlie.user_id.clone(),
            sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&bob), amount_to_send: "40".to_string() }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        },
        None
    ).expect("Bob transfer to Charlie failed");

    charlie.process_encrypted_transaction_bundle(&ACTORS.charlie.identity, &bundle_bytes, None, &standards_map).unwrap();

    let list_charlie = list_active(&charlie, &ACTORS.charlie.identity);
    assert_eq!(list_charlie[0].current_amount, "40.0000");
    
    let v_charlie = charlie.get_voucher_details(&get_first_local_id(&charlie)).unwrap().voucher;
    let tx_charlie_0 = &v_charlie.transactions.last().unwrap();
    assert_eq!(tx_charlie_0.sender_id, Some(ACTORS.bob.user_id.clone()), "Sender ID must be visible");
    assert_eq!(tx_charlie_0.recipient_id, ACTORS.charlie.user_id.clone(), "Recipient ID must be visible");
}

// ============================================================================
// AUFGABE 2: Strict Private Chain
// ============================================================================
#[test]
fn test_chained_workflow_strict_private() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, _standard_hash, standards_map) = setup_standard(PrivacyMode::Stealth);

    let mut alice = test_utils::setup_in_memory_wallet(&ACTORS.alice.identity);
    let mut bob = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);
    let mut charlie = test_utils::setup_in_memory_wallet(&ACTORS.charlie.identity);
    let mut dave = test_utils::setup_in_memory_wallet(&ACTORS.david.identity);

    // --- INIT: Alice creates voucher of 100 ---
    let local_id = test_utils::add_voucher_to_wallet(
        &mut alice, 
        &ACTORS.alice.identity, 
        "100", 
        &standard_def, 
        true
    ).unwrap();

    // --- PHASE 1: Alice sends 60 to Bob (Split) ---
    let CreateBundleResult { bundle_bytes, .. } = alice.execute_multi_transfer_and_bundle(&ACTORS.alice.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.bob.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: local_id, amount_to_send: "60".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: None,
    }, None).unwrap();
    bob.process_encrypted_transaction_bundle(&ACTORS.bob.identity, &bundle_bytes, None, &standards_map).expect("Bob processing failed");

    let v_bob = bob.get_voucher_details(&get_first_local_id(&bob)).unwrap().voucher;
    let tx_bob = &v_bob.transactions.last().unwrap();
    assert_eq!(tx_bob.sender_id, None, "Strict Private: Sender ID must be None");
    assert_eq!(tx_bob.recipient_id, "anonymous", "Strict Private: Recipient ID must be 'anonymous'");

    // --- PHASE 2: Bob sends 20 to Charlie (Split vom Wechselgeld) ---
    let CreateBundleResult { bundle_bytes, .. } = bob.execute_multi_transfer_and_bundle(&ACTORS.bob.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.charlie.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&bob), amount_to_send: "20".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: None,
    }, None).unwrap();
    charlie.process_encrypted_transaction_bundle(&ACTORS.charlie.identity, &bundle_bytes, None, &standards_map).unwrap();

    let v_charlie = charlie.get_voucher_details(&get_first_local_id(&charlie)).unwrap().voucher;
    let tx_charlie = &v_charlie.transactions.last().unwrap();
    assert_eq!(tx_charlie.sender_id, None);
    assert_eq!(tx_charlie.recipient_id, "anonymous");

    // --- PHASE 3: Charlie sends 20 to Dave (Full Transfer) ---
    let CreateBundleResult { bundle_bytes, .. } = charlie.execute_multi_transfer_and_bundle(&ACTORS.charlie.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.david.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&charlie), amount_to_send: "20".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: None,
    }, None).unwrap();
    dave.process_encrypted_transaction_bundle(&ACTORS.david.identity, &bundle_bytes, None, &standards_map).unwrap();

    assert_eq!(list_active(&alice, &ACTORS.alice.identity)[0].current_amount, "40.0000");
    assert_eq!(list_active(&bob, &ACTORS.bob.identity)[0].current_amount, "40.0000");
    assert_eq!(list_active(&dave, &ACTORS.david.identity)[0].current_amount, "20.0000");
}

// ============================================================================
// AUFGABE 3: Ultimate Flexible Chain
// ============================================================================
#[test]
fn test_chained_workflow_ultimate_flexible() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, _standard_hash, standards_map) = setup_standard(PrivacyMode::Flexible);

    let mut alice = test_utils::setup_in_memory_wallet(&ACTORS.alice.identity);
    let mut bob = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);
    let mut charlie = test_utils::setup_in_memory_wallet(&ACTORS.charlie.identity);
    let mut dave = test_utils::setup_in_memory_wallet(&ACTORS.david.identity);

    // --- INIT ---
    let local_id = test_utils::add_voucher_to_wallet(
        &mut alice, 
        &ACTORS.alice.identity, 
        "100", 
        &standard_def, 
        true
    ).unwrap();

    // --- PHASE 1: Public Split: Alice -> Bob 50 ---
    let CreateBundleResult { bundle_bytes, .. } = alice.execute_multi_transfer_and_bundle(&ACTORS.alice.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.bob.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: local_id, amount_to_send: "50".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: Some(false),
    }, None).unwrap();
    bob.process_encrypted_transaction_bundle(&ACTORS.bob.identity, &bundle_bytes, None, &standards_map).unwrap();

    let v_bob = bob.get_voucher_details(&get_first_local_id(&bob)).unwrap().voucher;
    let tx_bob = &v_bob.transactions.last().unwrap();
    assert_eq!(tx_bob.sender_id, Some(ACTORS.alice.user_id.clone()), "Flexible Public: Sender should be visible");
    assert_eq!(tx_bob.recipient_id, "anonymous", "Flexible mode: Recipient is always anonymous");

    // --- PHASE 2: Private Split: Bob -> Charlie 30 ---
    let CreateBundleResult { bundle_bytes, .. } = bob.execute_multi_transfer_and_bundle(&ACTORS.bob.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.charlie.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&bob), amount_to_send: "30".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
    }, None).expect("Bob private split failed");
    charlie.process_encrypted_transaction_bundle(&ACTORS.charlie.identity, &bundle_bytes, None, &standards_map).unwrap();
    
    let v_charlie = charlie.get_voucher_details(&get_first_local_id(&charlie)).unwrap().voucher;
    let tx_charlie = &v_charlie.transactions.last().unwrap();
    assert_eq!(tx_charlie.sender_id, None, "Private mode requested: Sender must be None");
    assert_eq!(tx_charlie.recipient_id, "anonymous");

    // --- PHASE 3: Public Full: Charlie -> Dave 30 ---
    let CreateBundleResult { bundle_bytes, .. } = charlie.execute_multi_transfer_and_bundle(&ACTORS.charlie.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.david.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&charlie), amount_to_send: "30".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: Some(false),
    }, None).unwrap();
    dave.process_encrypted_transaction_bundle(&ACTORS.david.identity, &bundle_bytes, None, &standards_map).unwrap();

    // --- PHASE 4: Private Full: Alice -> Dave 50 (Restliches Wechselgeld) ---
    let CreateBundleResult { bundle_bytes, .. } = alice.execute_multi_transfer_and_bundle(&ACTORS.alice.identity, &standards_map, MultiTransferRequest {
        recipient_id: ACTORS.david.user_id.clone(),
        sources: vec![SourceTransfer { local_instance_id: get_first_local_id(&alice), amount_to_send: "50".to_string() }],
        notes: None, sender_profile_name: None, use_privacy_mode: Some(true),
    }, None).unwrap();
    dave.process_encrypted_transaction_bundle(&ACTORS.david.identity, &bundle_bytes, None, &standards_map).unwrap();

    // Final Asserts
    assert_eq!(list_active(&alice, &ACTORS.alice.identity).len(), 0);
    assert_eq!(list_active(&bob, &ACTORS.bob.identity)[0].current_amount, "20.0000");
    assert_eq!(list_active(&charlie, &ACTORS.charlie.identity).len(), 0);
    
    let daves_vouchers = list_active(&dave, &ACTORS.david.identity);
    assert_eq!(daves_vouchers.len(), 2, "Dave should have 2 distinct vouchers");
    let sum: f64 = daves_vouchers.iter().map(|v| v.current_amount.parse::<f64>().unwrap()).sum();
    assert_eq!(sum, 80.0, "Dave's total balance should be 80");
}
