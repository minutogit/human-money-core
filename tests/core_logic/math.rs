// tests/core_logic/math.rs
// cargo test --test core_logic_tests

//! # Integrationstest für die numerische Robustheit von Transaktionen
//!
//! Diese Test-Suite verifiziert die korrekte arithmetische Verarbeitung
//! von `Decimal`-Werten in der `create_transaction`-Funktion.
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Ganzzahl-Transaktionen:** Korrekte Subtraktion und Skalierung.
//! - **Dezimal-Transaktionen:** Verarbeitung mit maximaler und geringerer Präzision.
//! - **Gemischte Transaktionen:** Korrekte Arithmetik bei Interaktionen zwischen
//!   ganzzahligen und dezimalen Guthaben.
//! - **Regelkonformität:** Sicherstellung, dass die `amount_decimal_places`-Regel
//!   des Standards korrekt angewendet wird (Skalierung und Validierung).
//! - **Fehlerfall:** Ablehnung von Transaktionen, deren Betrag die vom Standard
//!   erlaubte Präzision überschreitet.
//! - **Vollständiger Transfer:** Korrekte Erstellung einer Transaktion ohne Restbetrag,
//!   wenn das gesamte Guthaben überwiesen wird.

use human_money_core::test_utils::{ACTORS, SILVER_STANDARD};
use human_money_core::{
    // Structs/Enums from the crate root (or re-exported there)
    NewVoucherData,
    VoucherCoreError,
    // Structs from specific modules
    models::voucher::ValueDefinition,
    services::voucher_manager::{
        VoucherManagerError, create_transaction, create_voucher, get_spendable_balance,
    },
    services::voucher_validation::validate_voucher_against_standard,
};
use rust_decimal_macros::dec;

// --- TESTFÄLLE ---

#[test]
fn test_chained_transaction_math_and_scaling() {
    // --- 1. SETUP ---
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    assert_eq!(
        standard
            .immutable.features.amount_decimal_places,
        4,
        "This test requires the silver standard with 4 decimal places."
    );

    // Erstelle Alice (Sender) und Bob (Empfänger)
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    // Erstelle einen initialen Gutschein für Alice mit dem Wert 100
    let alice_creator_info = human_money_core::models::profile::PublicProfile {
        id: Some(alice.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = NewVoucherData {
        creator_profile: alice_creator_info,
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let mut current_voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &alice.signing_key,
        "en",
    )
    .unwrap();
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(100)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(0)
    );

    // --- 2. FALL: GANZZAHL-SPLIT VON GANZZAHL-GUTHABEN ---
    // Alice (100) sendet "40" an Bob.
    let holder_key =
        human_money_core::test_utils::derive_holder_key(&current_voucher, &alice.signing_key);
    let (v, secrets_1) = create_transaction(
        &current_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &holder_key, // Init->Tx1
        &bob.user_id,
        "40",
        None,
    )
    .unwrap();
    current_voucher = v;

    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, &standard).unwrap(),
        dec!(60)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, &standard).unwrap(),
        dec!(40)
    );
    let tx1 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx1.amount, "40.0000"); // Korrekt skaliert
    assert_eq!(tx1.sender_remaining_amount, Some("60.0000".to_string()));

    // --- 3. FALL: DEZIMAL-SPLIT (MAX. PRÄZISION) VON GANZZAHL-GUTHABEN ---
    // Alice (60) sendet "10.1234" an Bob.
    // Use change seed from Tx1 for Tx2
    let change_seed_1 = secrets_1.change_seed.expect("Tx1 should have change");
    let change_key_1 = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&change_seed_1)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, secrets_2) = create_transaction(
        &current_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &change_key_1,
        &bob.user_id,
        "10.1234",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(49.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(10.1234) // Guthaben ist nur der Betrag der letzten Transaktion
    );

    // --- 4. FALL: GANZZAHL-SPLIT VON DEZIMAL-GUTHABEN ---
    // Alice (49.8766) sendet "9" an Bob.
    // Use change seed from Tx2 for Tx3
    let change_seed_2 = secrets_2.change_seed.expect("Tx2 should have change");
    let change_key_2 = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&change_seed_2)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, secrets_3) = create_transaction(
        &current_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &change_key_2,
        &bob.user_id,
        "9",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(40.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(9.0000) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx3 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx3.amount, "9.0000"); // Korrekt skaliert

    // --- 5. FALL: SPLIT MIT WENIGER NACHKOMMASTELLEN ALS ERLAUBT ---
    // Alice (40.8766) sendet "0.87" (2 statt 4 Stellen) an Bob.
    let change_seed_3 = secrets_3.change_seed.expect("Tx3 should have change");
    let change_key_3 = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&change_seed_3)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, secrets_4) = create_transaction(
        &current_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &change_key_3,
        &bob.user_id,
        "0.87",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(40.0066)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(0.8700) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx4 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx4.amount, "0.8700"); // Korrekt skaliert

    // --- 6. FALL: VOLLER TRANSFER DES RESTGUTHABENS ---
    // Alice (40.0066) sendet ihr komplettes Restguthaben "40.0066" an Bob.
    let change_seed_4 = secrets_4.change_seed.expect("Tx4 should have change");
    let change_key_4 = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&change_seed_4)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, secrets_5) = create_transaction(
        &current_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &change_key_4,
        &bob.user_id,
        "40.0066",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(0)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(40.0066) // Guthaben ist nur der Betrag der letzten Transaktion
    );
    let tx5 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx5.t_type, "transfer"); // Korrigiert: Ein voller Transfer hat jetzt den Typ "transfer".
    assert!(tx5.sender_remaining_amount.is_none());
    assert_eq!(tx5.amount, "40.0066");

    // --- 7. FALL: RÜCKTRANSAKTIONEN VON BOB AN ALICE ---
    // Bob (Guthaben: 40.0066) sendet "10" (Ganzzahl) zurück an Alice.
    // Bob spends the "received" amount from Tx6. He needs recipient_seed from secrets_5.
    let bob_seed = secrets_5.recipient_seed;
    let bob_key = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&bob_seed)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, secrets_6) = create_transaction(
        &current_voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_key, // Bob spends received
        &alice.user_id,
        "10",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();

    // Prüfe die Guthaben nach der ersten Rücktransaktion
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(30.0066) // Bobs Restguthaben
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard).unwrap(),
        dec!(10.0000) // Alice' neues Guthaben
    );

    // Bob (Guthaben: 30.0066) sendet "0.0066" (Dezimal) zurück an Alice.
    let bob_change_seed = secrets_6.change_seed.expect("Tx7 should have change");
    let bob_change_key = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&bob_change_seed)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let (v, _) = create_transaction(
        &current_voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_change_key, // Init->Tx2 (Continuing chain)
        &alice.user_id,
        "0.0066",
        None,
    )
    .unwrap();
    current_voucher = v;
    validate_voucher_against_standard(&current_voucher, standard).unwrap();

    // Prüfe die Guthaben nach der zweiten Rücktransaktion
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard).unwrap(),
        dec!(30.0000) // Bobs Restguthaben
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, &standard).unwrap(),
        dec!(0.0066) // Alice' neues Guthaben
    );
}

#[test]
fn test_transaction_fails_on_excess_precision() {
    // --- SETUP ---
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    let alice_creator_info = human_money_core::models::profile::PublicProfile {
        id: Some(alice.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = NewVoucherData {
        creator_profile: alice_creator_info,
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &alice.signing_key,
        "en",
    )
    .unwrap();

    // --- AKTION & PRÜFUNG ---
    // Alice versucht, "0.12345" (5 Nachkommastellen) zu senden, erlaubt sind aber nur 4.
    let result = create_transaction(
        &voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &alice.signing_key,
        &bob.user_id,
        "0.12345",
        None,
    );

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::AmountPrecisionExceeded {
            allowed: 4,
            found: 5
        })
    ));
}
