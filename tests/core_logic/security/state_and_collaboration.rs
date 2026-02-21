// tests/core_logic/security/state_and_collaboration.rs
// cargo test --test core_logic_tests

// HINWEIS: Importiert das Modul, das im `mod.rs` bereitgestellt wird.
use self::test_utils::{ACTORS, SILVER_STANDARD, setup_in_memory_wallet};
use super::test_utils;
use ed25519_dalek::SigningKey;
use human_money_core::crypto_utils;
use human_money_core::models::voucher::{Collateral, ValueDefinition, Voucher, VoucherSignature};
use human_money_core::services::crypto_utils::{create_user_id, get_hash_from_slices, sign_ed25519};
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::services::voucher_manager::get_spendable_balance;
use human_money_core::wallet::Wallet;
use human_money_core::{UserIdentity, VoucherStatus};
use human_money_core::{create_transaction, create_voucher, to_canonical_json};
use rust_decimal_macros::dec;

// ===================================================================================
// HILFSFUNKTIONEN & SETUP (Kopiert aus vulnerabilities.rs)
// ===================================================================================

// HINWEIS: Alle Helferfunktionen (mutate_*, etc.)
// wurden in vulnerabilities.rs belassen, um die Duplizierung
// zu minimieren und die Abhängigkeiten klar zu halten.
// Wir kopieren nur die benötigten Helfer.

/// Erstellt ein frisches, leeres In-Memory-Wallet für einen Akteur.
fn setup_test_wallet(identity: &UserIdentity) -> Wallet {
    setup_in_memory_wallet(identity)
}

/// **NEUER STUB:** Erstellt einen Test-Creator für die neuen Tests.
fn setup_creator() -> (SigningKey, human_money_core::models::profile::PublicProfile) {
    let (public_key, signing_key) =
        crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub"));
    let user_id = create_user_id(&public_key, Some("cs")).unwrap();
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(user_id),
        first_name: Some("Stub".to_string()),
        last_name: Some("Creator".to_string()),
        ..Default::default()
    };
    (signing_key, creator)
}

/// **NEUER STUB:** Erstellt Test-Voucher-Daten für die neuen Tests.
fn create_test_voucher_data_with_amount(
    creator_profile: human_money_core::models::profile::PublicProfile,
    amount: &str,
) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: amount.to_string(),
            ..Default::default()
        },
        collateral: Some(Collateral::default()),
        creator_profile,
    }
}

// ===================================================================================
// WALLET-ZUSTANDSVERWALTUNG & KOLLABORATION TESTS (Klasse 5/6)
// ===================================================================================

#[test]
fn test_wallet_state_management_on_split() {
    // 1. Setup
    let a_identity = &ACTORS.alice;
    let b_identity = &ACTORS.bob;
    let mut wallet_a = setup_test_wallet(a_identity);
    let mut wallet_b = setup_test_wallet(b_identity);

    // 2. Erstelle einen Gutschein explizit und füge ihn zu Wallet A hinzu, um das Setup zu verdeutlichen.
    let creator_data = human_money_core::models::profile::PublicProfile {
        id: Some(a_identity.user_id.clone()),
        first_name: Some("Alice".to_string()),
        last_name: Some("Test".to_string()),
        ..Default::default()
    };
    let voucher_data = create_test_voucher_data_with_amount(creator_data, "100.0000");

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &a_identity.signing_key,
        "en",
    )
    .unwrap();

    let local_id =
        Wallet::calculate_local_instance_id(&initial_voucher, &a_identity.user_id).unwrap();
    // KORREKTUR: Manuelle Insertion inkl. Seed
    let instance_a = human_money_core::wallet::instance::VoucherInstance {
        voucher: initial_voucher.clone(),
        status: human_money_core::wallet::instance::VoucherStatus::Active,
        local_instance_id: local_id.clone(),
    };
    wallet_a.voucher_store.vouchers.insert(local_id.clone(), instance_a);
    let original_local_id = wallet_a
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    // 3. Aktion: Wallet A sendet 40 an Wallet B
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: b_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: original_local_id.clone(),
            amount_to_send: "40".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: bundle_to_b,
        ..
    } = wallet_a
        .execute_multi_transfer_and_bundle(&a_identity, &standards, request, None)
        .unwrap();

    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );
    wallet_b
        .process_encrypted_transaction_bundle(&b_identity, &bundle_to_b, None, &standards_for_bob)
        .unwrap();

    // 4. Verifizierung (Wallet A)
    // NACH ÄNDERUNG: Wallet A sollte jetzt nur noch EINE Instanz haben - den aktiven Restbetrag.
    // Die ursprüngliche Instanz wird gelöscht, nicht archiviert.
    assert_eq!(
        wallet_a.voucher_store.vouchers.len(),
        1,
        "Wallet A should have exactly one instance (the active remainder)."
    );
    assert!(
        wallet_a
            .voucher_store
            .vouchers
            .get(&original_local_id)
            .is_none(),
        "The original voucher instance must be removed."
    );

    let remainder_instance = wallet_a
        .voucher_store
        .vouchers
        .values()
        .next()
        .expect("Wallet A must have one voucher instance left.");
    assert_eq!(remainder_instance.status, VoucherStatus::Active);

    let remainder_balance =
        get_spendable_balance(&remainder_instance.voucher, &a_identity.user_id, standard).unwrap();
    assert_eq!(remainder_balance, dec!(60));

    // 5. Verifizierung (Wallet B)
    assert_eq!(
        wallet_b.voucher_store.vouchers.len(),
        1,
        "Wallet B should have one voucher instance."
    );
    let received_instance = wallet_b.voucher_store.vouchers.values().next().unwrap();
    assert_eq!(received_instance.status, VoucherStatus::Active);

    let received_balance =
        get_spendable_balance(&received_instance.voucher, &b_identity.user_id, standard).unwrap();
    assert_eq!(received_balance, dec!(40));
}

#[test]
fn test_collaborative_fraud_detection_with_fingerprints() {
    // 1. Setup
    let a_identity = &ACTORS.alice;
    let mut alice_wallet = setup_test_wallet(a_identity);
    let b_identity = &ACTORS.bob;
    let mut bob_wallet = setup_test_wallet(b_identity);
    // Wir verwenden den "Hacker" als böswilligen Akteur Eve
    let eve_identity = &ACTORS.hacker;
    let mut eve_wallet = setup_test_wallet(eve_identity);

    // 2. Akt 1 (Double Spend)
    let mut eve_creator = setup_creator().1;
    eve_creator.id = Some(eve_identity.user_id.clone());
    let voucher_data = create_test_voucher_data_with_amount(eve_creator, "100");

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &eve_identity.signing_key,
        "en",
    )
    .unwrap();

    let holder_key = self::test_utils::derive_holder_key(&initial_voucher, &eve_identity.signing_key);
    let (voucher_for_alice, _) = create_transaction(
        &initial_voucher,
        standard,
        &eve_identity.user_id,
        &eve_identity.signing_key,
        &holder_key,
        &a_identity.user_id,
        "100",
    )
    .unwrap();
    let (voucher_for_bob, _) = create_transaction(
        &initial_voucher,
        standard,
        &eve_identity.user_id,
        &eve_identity.signing_key,
        &holder_key,
        &b_identity.user_id,
        "100",
    )
    .unwrap();

    // Eve verpackt und sendet die Gutscheine
    let (bundle_to_alice, _header) = eve_wallet
        .create_and_encrypt_transaction_bundle(
            &eve_identity,
            vec![voucher_for_alice],
            &a_identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None,
        )
        .unwrap();
    let (bundle_to_bob, _header) = eve_wallet
        .create_and_encrypt_transaction_bundle(
            &eve_identity,
            vec![voucher_for_bob],
            &b_identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None,
        )
        .unwrap();

    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_map = std::collections::HashMap::new();
    standards_map.insert(
        SILVER_STANDARD.0.metadata.uuid.clone(),
        SILVER_STANDARD.0.clone(),
    );

    alice_wallet
        .process_encrypted_transaction_bundle(&a_identity, &bundle_to_alice, None, &standards_map)
        .unwrap();
    bob_wallet
        .process_encrypted_transaction_bundle(&b_identity, &bundle_to_bob, None, &standards_map)
        .unwrap();

    // 3. Akt 2 (Austausch)
    println!("\n[DEBUG TEST] --- Phase 2: Austausch ---");
    alice_wallet.scan_and_rebuild_fingerprints().unwrap();
    // KORREKTUR: Für die kollaborative Betrugserkennung muss Alice ihre gesamte lokale
    // Historie teilen, nicht nur die Fingerprints von Transaktionen, die sie gesendet hat.
    println!(
        "[DEBUG TEST] Alice's local_history nach Scan: {:#?}",
        alice_wallet.known_fingerprints.local_history
    );

    // KORREKTUR: Für die kollaborative Betrugserkennung muss Alice ihre gesamte lokale
    // Historie teilen, nicht nur die Fingerprints von Transaktionen, die sie gesendet hat.
    let alice_fingerprints =
        serde_json::to_vec(&alice_wallet.known_fingerprints.local_history).unwrap();
    println!(
        "[DEBUG TEST] Alice's exportierte Fingerprints (JSON): {}",
        String::from_utf8_lossy(&alice_fingerprints)
    );

    let import_count = bob_wallet
        .import_foreign_fingerprints(&alice_fingerprints)
        .unwrap();
    println!(
        "[DEBUG TEST] Bob hat {} neue Fingerprints importiert.",
        import_count
    );
    println!(
        "[DEBUG TEST] Bob's foreign_fingerprints nach Import: {:#?}",
        bob_wallet.known_fingerprints.foreign_fingerprints
    );

    // 4. Akt 3 (Aufdeckung)
    println!("\n[DEBUG TEST] --- Phase 3: Aufdeckung ---");
    bob_wallet.scan_and_rebuild_fingerprints().unwrap();
    println!(
        "[DEBUG TEST] Bob's local_history nach Scan: {:#?}",
        bob_wallet.known_fingerprints.local_history
    );
    let check_result = bob_wallet.check_for_double_spend();
    println!(
        "[DEBUG TEST] Ergebnis von Bob's check_for_double_spend: {:#?}",
        check_result
    );

    // 5. Verifizierung
    assert!(
        check_result.unverifiable_warnings.is_empty(),
        "There should be no unverifiable warnings."
    );
    assert_eq!(
        check_result.verifiable_conflicts.len(),
        1,
        "A verifiable conflict must be detected."
    );

    let conflict = check_result.verifiable_conflicts.values().next().unwrap();
    assert_eq!(
        conflict.len(),
        2,
        "The conflict should involve two transactions."
    );
    println!("SUCCESS: Collaborative fraud detection upgraded a warning to a verifiable conflict.");
}

#[test]
fn test_serialization_roundtrip_with_special_chars() {
    // 1. Setup
    let (signing_key, mut creator) = setup_creator();
    creator.first_name = Some("Jörg-ẞtråße".to_string()); // Sonderzeichen

    let voucher_data = create_test_voucher_data_with_amount(creator, "123");

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut original_voucher =
        create_voucher(voucher_data, standard, standard_hash, &signing_key, "en").unwrap();

    // Mache den Gutschein komplexer
    let g1_identity = &ACTORS.guarantor1;

    // **KORRIGIERTER AUFRUF:** Metadaten werden jetzt bei der Erstellung übergeben.
    let guarantor_sig = VoucherSignature {
        signer_id: g1_identity.user_id.clone(),
        role: "guarantor".to_string(),
        signature_time: get_current_timestamp(),
        details: Some(human_money_core::models::profile::PublicProfile {
            first_name: Some("Garant".to_string()),
            last_name: Some("Test".to_string()),
            organization: Some("Bürge & Co.".to_string()),
            gender: Some("1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    // HINWEIS: create_guarantor_signature wurde entfernt, muss neu erstellt werden
    let mut sig_obj = guarantor_sig.clone();
    let mut sig_obj_for_id = sig_obj.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    let init_t_id = &original_voucher.transactions[0].t_id;
    sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&sig_obj_for_id).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);
    let signature = sign_ed25519(&g1_identity.signing_key, sig_obj.signature_id.as_bytes());
    sig_obj.signature = bs58::encode(signature.to_bytes()).into_string();
    original_voucher.signatures.push(sig_obj);

    // FÜGE ZWEITEN BÜRGEN HINZU, UM DIE VALIDIERUNG ZU ERFÜLLEN
    // ÄNDERUNG: Gender auf "2" gesetzt, um die Regel des Minuto-Standards zu erfüllen.
    let second_guarantor_identity = &ACTORS.guarantor2;
    let second_guarantor_sig = VoucherSignature {
        signer_id: second_guarantor_identity.user_id.clone(),
        role: "guarantor".to_string(),
        signature_time: get_current_timestamp(),
        details: Some(human_money_core::models::profile::PublicProfile {
            first_name: Some("Garantin".to_string()),
            last_name: Some("Test".to_string()),
            gender: Some("2".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut sig_obj = second_guarantor_sig.clone();
    let mut sig_obj_for_id = sig_obj.clone();
    sig_obj_for_id.signature_id = "".to_string();
    sig_obj_for_id.signature = "".to_string();
    let init_t_id = &original_voucher.transactions[0].t_id;
    sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&sig_obj_for_id).unwrap().as_bytes(),
        init_t_id.as_bytes(),
    ]);
    let signature = sign_ed25519(
        &second_guarantor_identity.signing_key,
        sig_obj.signature_id.as_bytes(),
    );
    sig_obj.signature = bs58::encode(signature.to_bytes()).into_string();
    original_voucher.signatures.push(sig_obj);

    let holder_key = self::test_utils::derive_holder_key(&original_voucher, &signing_key);
    let (ov, _) = create_transaction(
        &original_voucher,
        standard,
        &original_voucher.creator_profile.id.as_ref().unwrap(),
        &signing_key,
        &holder_key,
        &human_money_core::test_utils::ACTORS.bob.user_id, // Valid DID
        "23",
    )
    .unwrap();
    original_voucher = ov;

    // 2. Aktion
    // Wir verwenden serde_json::to_string direkt, um den Prozess ohne unsere Wrapper zu testen.
    let json_string = serde_json::to_string(&original_voucher).unwrap();
    let deserialized_voucher: Voucher = serde_json::from_str(&json_string).unwrap();

    // 3. Verifizierung
    assert_eq!(
        original_voucher, deserialized_voucher,
        "The deserialized voucher must be identical to the original."
    );
}
