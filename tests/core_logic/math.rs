// tests/core_logic/math.rs
// cargo test --test core_logic_tests

//! # Integration test for numerical robustness of transactions
//!
//! This test suite verifies the correct arithmetic processing
//! of `Decimal` values in the `create_transaction` function.
//!
//! ## Covered scenarios:
//!
//! - **Integer transactions:** Correct subtraction and scaling.
//! - **Decimal transactions:** Processing with maximum and lower precision.
//! - **Mixed transactions:** Correct arithmetic during interactions between
//!   integer and decimal balances.
//! - **Rule compliance:** Ensuring that the `amount_decimal_places` rule
//!   of the standard is applied correctly (scaling and validation).
//! - **Error case:** Rejection of transactions whose amount exceeds precision
//!   allowed by the standard.
//! - **Full transfer:** Correct creation of a transaction without remaining amount
//!   when the entire balance is transferred.

use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD};
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

// --- TEST CASES ---

#[test]
fn test_chained_transaction_math_and_scaling() {
    // --- 1. SETUP ---
    let mut standard_obj = FREETALER_STANDARD.0.clone();
    standard_obj.immutable.features.amount_decimal_places = 4;
    standard_obj.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    
    let mut standard_to_hash = standard_obj.clone();
    standard_to_hash.signature = None;
    let standard_hash = human_money_core::services::crypto_utils::get_hash(
        human_money_core::services::utils::to_canonical_json(&standard_to_hash.immutable).unwrap()
    );
    let standard = &standard_obj;
    let standard_hash = &standard_hash;


    // Create Alice (sender) and Bob (recipient)
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    // Create an initial voucher for Alice with value 100
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
        &alice.signing_key)
    .unwrap();
    validate_voucher_against_standard(&current_voucher, standard).unwrap();
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(100)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(0)
    );

    // --- 2. CASE: INTEGER SPLIT FROM INTEGER BALANCE ---
    // Alice (100) sends "40" to Bob.
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
        get_spendable_balance(&current_voucher, &alice.user_id, &standard, None).unwrap(),
        dec!(60)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, &standard, None).unwrap(),
        dec!(40)
    );
    let tx1 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx1.amount, "40.0000"); // Correctly scaled
    assert_eq!(tx1.sender_remaining_amount, Some("60.0000".to_string()));

    // --- 3. CASE: DECIMAL SPLIT (MAX PRECISION) FROM INTEGER BALANCE ---
    // Alice (60) sends "10.1234" to Bob.
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
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(49.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(10.1234) // Balance is only the amount of the last transaction
    );

    // --- 4. CASE: INTEGER SPLIT FROM DECIMAL BALANCE ---
    // Alice (49.8766) sends "9" to Bob.
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
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(40.8766)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(9.0000) // Balance is only the amount of the last transaction
    );
    let tx3 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx3.amount, "9.0000"); // Correctly scaled

    // --- 5. CASE: SPLIT WITH FEWER DECIMAL PLACES THAN ALLOWED ---
    // Alice (40.8766) sends "0.87" (2 instead of 4 decimal places) to Bob.
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
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(40.0066)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(0.8700) // Balance is only the amount of the last transaction
    );
    let tx4 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx4.amount, "0.8700"); // Correctly scaled

    // --- 6. CASE: FULL TRANSFER OF REMAINING BALANCE ---
    // Alice (40.0066) sends her complete remaining balance "40.0066" to Bob.
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
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(0)
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(40.0066) // Balance is only the amount of the last transaction
    );
    let tx5 = current_voucher.transactions.last().unwrap();
    assert_eq!(tx5.t_type, "transfer"); // Corrected: A full transfer now has type "transfer".
    assert!(tx5.sender_remaining_amount.is_none());
    assert_eq!(tx5.amount, "40.0066");

    // --- 7. CASE: RETURN TRANSACTIONS FROM BOB TO ALICE ---
    // Bob (balance: 40.0066) sends "10" (integer) back to Alice.
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

    // Check balances after the first return transaction
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(30.0066) // Bob's remaining balance
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, standard, None).unwrap(),
        dec!(10.0000) // Alice's new balance
    );

    // Bob (balance: 30.0066) sends "0.0066" (decimal) back to Alice.
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

    // Check balances after the second return transaction
    assert_eq!(
        get_spendable_balance(&current_voucher, &bob.user_id, standard, None).unwrap(),
        dec!(30.0000) // Bob's remaining balance
    );
    assert_eq!(
        get_spendable_balance(&current_voucher, &alice.user_id, &standard, None).unwrap(),
        dec!(0.0066) // Alice's new balance
    );
}

#[test]
fn test_transaction_fails_on_excess_precision() {
    // --- SETUP ---
    let mut standard_obj = FREETALER_STANDARD.0.clone();
    standard_obj.immutable.features.amount_decimal_places = 4;
    standard_obj.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    let mut standard_to_hash = standard_obj.clone();
    standard_to_hash.signature = None;
    let standard_hash = human_money_core::services::crypto_utils::get_hash(
        human_money_core::services::utils::to_canonical_json(&standard_to_hash.immutable).unwrap()
    );
    let standard = &standard_obj;
    let standard_hash = &standard_hash;
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
        &alice.signing_key)
    .unwrap();

    // --- ACTION & VERIFICATION ---
    // Alice attempts to send "0.12345" (5 decimal places), but only 4 are allowed.
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
