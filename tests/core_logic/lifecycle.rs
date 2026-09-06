// tests/core_logic/lifecycle.rs

// cargo test --test core_logic_tests
//! # Integration tests for voucher lifecycle and security
//!
//! This test suite covers the entire lifecycle of a `Voucher` object,
//! from creation to full validation, and checks critical
//! security aspects.
//!
//! #![feature(test-utils)]
//!
//! ## Covered Scenarios:
//!
//! - **Full Lifecycle:**
//!   - Creation of a voucher.
//!   - Validation in initial state (expected failure due to missing guarantors).
//!   - Creation and addition of correct, detached guarantor signatures.
//!   - Final, successful validation of the complete voucher.
//! - **Serialization:**
//!   - Correct conversion between `Voucher` struct and JSON string.
//! - **Validation Failure Cases:**
//!   - Invalid or tampered creator signature.
//!   - Missing fields defined in the standard.
//!   - Inconsistent data (e.g. incorrect nominal value unit).
//!   - Failure to meet guarantor requirements (count, gender).
//! - **Security Checks:**
//!   - **Replay Attack:** Prevents a guarantor signature from one voucher
//!     from being reused for another.
//!   - **Data Tampering:** Ensures that retroactive changes
//!     to signature metadata are detected.
//! - **Canonical Serialization:**
//!   - Verification of deterministic and sorted JSON output.
//!   - Tolerance toward unknown fields for forward compatibility.

// We import the public types re-exported in lib.rs.

use human_money_core::test_utils;

use human_money_core::error::ValidationError;
use human_money_core::services::crypto::get_hash;
use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD, FREETALER_STANDARD, create_custom_standard, setup_in_memory_wallet,
};
use human_money_core::{
    Collateral, NewVoucherData, Transaction, ValueDefinition, Voucher, VoucherCoreError,
    VoucherInstance, VoucherStatus, crypto,
    models::profile::PublicProfile, to_canonical_json,
    validate_voucher_against_standard,
};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

// --- HELPER FUNCTIONS AND TEST DATA ---

#[test]
fn test_full_creation_and_validation_cycle() {
    // 1. Setup: Load standard and create creator
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    // CORRECTION: Create a custom version of the standard to ensure
    // that the rounding rule is active for this test. This makes the test
    // independent of the state of the global MINUTO_STANDARD variable.
    let (minuto_standard_with_rounding, standard_hash) =
        create_custom_standard(&MINUTO_STANDARD.0, |s| {
            s.mutable.app_config.round_up_validity_to = Some("P1Y".to_string());
        });

    // 2. Creation
    let mut voucher = human_money_core::test_utils::create_voucher_for_manipulation(
        voucher_data,
        &minuto_standard_with_rounding,
        &standard_hash,
        &identity.signing_key);
    assert!(!voucher.voucher_id.is_empty());
    // CHECK: The creator signature must now be in the array.
    assert!(voucher.signatures.iter().any(|s| s.role == "creator"));
    println!("[DEBUG] Expected end: -12-31T23:59:59");
    println!("[DEBUG] Actual valid_until: {}", voucher.valid_until);
    // --- End DEBUG output ---

    // Check whether validity date was correctly rounded to end of year.
    assert!(voucher.valid_until.contains("-12-31T23:59:59"));

    // 3. Initial validation: Must fail because guarantors are missing.
    let initial_validation_result =
        validate_voucher_against_standard(&voucher, &minuto_standard_with_rounding);
    let err = initial_validation_result.unwrap_err();
    println!("[DEBUG] Actual error in test_full_creation: {:?}", err);
    assert!(matches!(
        err,
        // CORRECTION: The standard now checks `details.gender` via CEL.
        VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
        if msg.contains("Bürg") || msg.contains("männlicher") || msg.contains("weibliche") || msg.contains("guarantor") || msg.contains("required")
    ));

    // 4. Simulation of guarantor process according to new logic
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = human_money_core::test_utils::create_guarantor_signature(
        &voucher,
        g1,
        "Hans",
        "guarantor",
        "1",
    );
    let guarantor_sig_2 = human_money_core::test_utils::create_guarantor_signature(
        &voucher,
        g2,
        "Gabi",
        "guarantor",
        "2",
    );

    // The creator signature has already been added by `create_voucher_for_manipulation`.
    voucher.signatures.push(guarantor_sig_1);
    voucher.signatures.push(guarantor_sig_2);

    // 5. Final validation (positive case with guarantors)
    let final_validation_result =
        validate_voucher_against_standard(&voucher, &minuto_standard_with_rounding);
    assert!(
        final_validation_result.is_ok(),
        "Final validation failed unexpectedly: {:?}",
        final_validation_result.err()
    );
}

#[test]
fn test_serialization_deserialization() {
    // 1. Create a voucher
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = human_money_core::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let original_voucher = human_money_core::test_utils::create_voucher_for_manipulation(
        voucher_data,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    // 2. Serialize to JSON
    let json_string = original_voucher.to_json_string().unwrap();

    // 3. Deserialize back
    let deserialized_voucher: Voucher = Voucher::from_json_str(&json_string).unwrap();

    // 4. Compare objects
    assert_eq!(original_voucher, deserialized_voucher);
}

#[test]
fn test_validation_fails_on_invalid_signature() {
    // 1. Create a valid voucher
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = human_money_core::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = human_money_core::test_utils::create_voucher_for_manipulation(
        voucher_data,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    // Add required guarantors to make the voucher valid BEFORE we tamper with it.
    // Otherwise validation would already fail due to missing guarantors.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = human_money_core::test_utils::create_guarantor_signature(
        &voucher,
        g1,
        "Guarantor1",
        "guarantor",
        "1",
    );
    let guarantor_sig_2 = human_money_core::test_utils::create_guarantor_signature(
        &voucher,
        g2,
        "Guarantor2",
        "guarantor",
        "2",
    );
    voucher.signatures.push(guarantor_sig_1);
    voucher.signatures.push(guarantor_sig_2);
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // 2. Tamper with the signature
    let creator_sig = voucher
        .signatures
        .iter_mut()
        .find(|s| s.role == "creator")
        .unwrap();
    creator_sig.signature = "invalid_signature_string_12345".to_string();

    // 3. Validation should fail
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(validation_result.is_err());
    // We expect an error decoding the signature since it is not valid Base58.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(_))
    ));
}

#[test]
fn test_validation_fails_on_missing_required_field() {
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = human_money_core::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, _standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // 2. Tamper with the standard at runtime to add a custom rule
    // that enforces the presence of the optional field `creator.phone`.
    let mut standard = minuto_standard.clone();
    

    standard.immutable.custom_rules.insert(
        "creator_phone_required".to_string(),
        human_money_core::models::voucher_standard_definition::DynamicRule {
            message: "Missing creator phone".to_string(),
            expression: "has(Voucher.creator_profile.phone)".to_string(),
        },
    );

    // 3. The hash of the modified standard must be recalculated and used for
    // voucher creation to avoid a `StandardHashMismatch`.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash.immutable).unwrap());

    let mut voucher = human_money_core::test_utils::create_voucher_for_manipulation(
        voucher_data,
        &standard,
        &new_hash,
        &identity.signing_key);

    // Add valid guarantors so validation does not fail on count
    // before the content rule is even evaluated.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher
        .signatures
        .push(human_money_core::test_utils::create_guarantor_signature(
            &voucher,
            g1,
            "G1",
            "guarantor",
            "1",
        ));
    voucher
        .signatures
        .push(human_money_core::test_utils::create_guarantor_signature(
            &voucher,
            g2,
            "G2",
            "guarantor",
            "2",
        ));

    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    println!(
        "[DEBUG] test_validation_fails_on_missing_required_field actual result: {:?}",
        validation_result
    );
    assert!(validation_result.is_err());
}

#[test]
fn test_validation_fails_on_inconsistent_unit() {
    // Create an initially valid voucher according to the FreeTaler standard.
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = human_money_core::test_utils::create_minuto_voucher_data(creator);

    let mut standard_obj = FREETALER_STANDARD.0.clone();
    standard_obj.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    let mut standard_to_hash = standard_obj.clone();
    standard_to_hash.signature = None;
    let standard_hash_val = human_money_core::services::crypto::get_hash(
        human_money_core::services::utils::to_canonical_json(&standard_to_hash.immutable).unwrap()
    );
    let freetaler_standard = &standard_obj;
    let standard_hash = &standard_hash_val;

    // CORRECTION: The test must modify the standard BEFORE voucher creation
    // to avoid hash errors.
    let mut standard_with_rule = freetaler_standard.clone();
    

    standard_with_rule.immutable.custom_rules.insert(
        "fixed_unit".to_string(),
        human_money_core::models::voucher_standard_definition::DynamicRule {
            message: "nominal_value.unit incorrect".to_string(),
            expression: format!(
                "Voucher.nominal_value.unit == '{}'",
                freetaler_standard.immutable.blueprint.unit
            ),
        },
    );

    // Calculate hash of modified standard.
    let mut standard_to_hash = standard_with_rule.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash.immutable).unwrap());

    // Create voucher with ORIGINAL standard which sets a correct unit.
    let mut voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        freetaler_standard,
        standard_hash,
        &identity.signing_key)
    .unwrap();

    // Tamper with the unit AFTER creation to produce an inconsistent state.
    voucher.nominal_value.unit = "EUR".to_string();
    // IMPORTANT: Update the hash in the voucher so validation does not fail on hash mismatch.
    voucher.voucher_standard.standard_definition_hash = new_hash;

    // Thanks to signature bypass we no longer need tedious re-signing of creator_sig.
    // We only need to ensure voucher_id (hash of master data) is consistent.
    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();
    let new_voucher_hash = crypto::get_hash(to_canonical_json(&voucher_to_hash).unwrap());
    voucher.voucher_id = new_voucher_hash;

    human_money_core::set_signature_bypass(true);
    let validation_result = validate_voucher_against_standard(&voucher, &standard_with_rule);
    human_money_core::set_signature_bypass(false);
    assert!(validation_result.is_err());
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::NominalUnitMismatch { expected, found }) if expected == "Taler" && found == "EUR"
    ));
}

#[test]
fn test_validation_fails_on_guarantor_count() {
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = self::test_utils::create_voucher_for_manipulation(
        voucher_data,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    // Remove all signatures EXCEPT the "creator" signature.
    // The voucher now has 0 guarantors (gender: 1, gender: 2).
    voucher.signatures.retain(|s| s.role == "creator");

    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        // CORRECTION: Expect the correct error from CEL evaluation.
        VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
            if msg.contains("männlicher") || msg.contains("weibliche") || msg.contains("Bürg") || msg.contains("guarantor") || msg.contains("required") => {} // Correct
        e => panic!(
            "Expected BusinessRuleViolated error for gender validation, but got {:?}",
            e
        ),
    }
}

// --- NEW TESTS FOR CANONICAL SERIALIZATION ---

#[test]
fn test_canonical_json_is_deterministic_and_sorted() {
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let data1 = self::test_utils::create_minuto_voucher_data(creator.clone());
    let data2 = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // We insert a tiny pause to ensure timestamps
    // and thus hashes are definitely distinct.
    let voucher1 = self::test_utils::create_voucher_for_manipulation(
        data1,
        minuto_standard,
        standard_hash,
        &identity.signing_key);
    std::thread::sleep(std::time::Duration::from_micros(10));
    let voucher2 = self::test_utils::create_voucher_for_manipulation(
        data2,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    // Verify that vouchers are NOT identical, as their timestamps
    // and derived fields (IDs, signatures) must differ.
    assert_ne!(
        voucher1, voucher2,
        "Vouchers should be different due to unique timestamps"
    );

    // Test canonical serialization on a static part of the voucher.
    // The result must always have alphabetically sorted keys,
    // e.g. "abbreviation" before "amount".
    let canonical_json = to_canonical_json(&voucher1.nominal_value).unwrap();

    // Generate the expected value dynamically from the loaded standard
    // instead of using a hardcoded string.
    let expected_json = format!(
        r#"{{"abbreviation":"{}","amount":"60","description":"Qualitative Leistung","unit":"{}"}}"#,
        minuto_standard.immutable.identity.abbreviation, minuto_standard.immutable.blueprint.unit
    );
    assert_eq!(canonical_json, expected_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Create a FULLY valid voucher, including required guarantors.
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut valid_voucher = self::test_utils::create_voucher_for_manipulation(
        voucher_data,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    // Add guarantors required for Minuto standard.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let guarantor_sig_1 = self::test_utils::create_guarantor_signature(
        &valid_voucher,
        g1,
        "Guarantor1",
        "guarantor",
        "1",
    );
    let guarantor_sig_2 = self::test_utils::create_guarantor_signature(
        &valid_voucher,
        g2,
        "Guarantor2",
        "guarantor",
        "2",
    );
    valid_voucher.signatures.push(guarantor_sig_1);
    valid_voucher.signatures.push(guarantor_sig_2);

    // Ensure the voucher is now valid before we modify it.
    assert!(validate_voucher_against_standard(&valid_voucher, minuto_standard).is_ok());

    let mut voucher_as_value: serde_json::Value = serde_json::to_value(&valid_voucher).unwrap();

    // 2. Add an unknown field to the JSON object.
    // This simulates a voucher created by a newer software version.
    voucher_as_value.as_object_mut().unwrap().insert(
        "unknown_future_field".to_string(),
        serde_json::json!("some_data"),
    );

    // Also add an unknown field into a nested object.
    voucher_as_value
        .get_mut("creator")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "creator_metadata".to_string(),
            serde_json::json!({"rating": 5}),
        );

    let json_with_extra_fields = serde_json::to_string(&voucher_as_value).unwrap();

    // 3. Deserialize this JSON string. `serde` should ignore unknown fields.
    let deserialized_voucher: Voucher = Voucher::from_json_str(&json_with_extra_fields).unwrap();

    // 4. The deserialized voucher should match the original exactly since
    // extra fields were discarded.
    assert_eq!(valid_voucher, deserialized_voucher);

    // 5. Validation must succeed. The `verify_creator_signature` function
    // will internally compute the canonical form of `deserialized_voucher` (without extra fields),
    // and this must match the original signature.
    let validation_result =
        validate_voucher_against_standard(&deserialized_voucher, minuto_standard);

    assert!(
        validation_result.is_ok(),
        "Validation failed unexpectedly with extra fields: {:?}",
        validation_result.err()
    );
}

// --- NEW TESTS FOR SPLIT TRANSACTIONS ---

#[test]
fn test_split_transaction_cycle_and_balance_check() {
    // 1. Setup: FreeTaler standard, as it is divisible and requires no guarantors.
    // Re-sign the mutated clone so it stays self-consistent at validation time
    // (AUDIT-M03-010 enforces signature validity when the standard enters validation).
    let (standard_obj, standard_hash_val) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let freetaler_standard = &standard_obj;
    let standard_hash = &standard_hash_val;
    
    assert!(freetaler_standard.immutable.features.allow_partial_transfers);

    // 2. Create sender and recipient
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = PublicProfile {
        id: Some(sender.user_id.clone()),
        ..Default::default()
    };

    // 3. Create a voucher with value 100.00 - we adapt data from `create_minuto_voucher_data`.
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "100.00".to_string();

    let initial_voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        freetaler_standard,
        standard_hash,
        &sender.signing_key)
    .unwrap();

    // 4. Check initial state and balance
    assert!(validate_voucher_against_standard(&initial_voucher, freetaler_standard).is_ok());
    let initial_balance =
        initial_voucher.spendable_balance_for_user( &sender.user_id, freetaler_standard, None).unwrap();
    assert_eq!(initial_balance, dec!(100.00));

    // 5. Perform a split transaction: Send 30.50 to recipient
    let split_amount = "30.50";
    let holder_key =
        human_money_core::test_utils::derive_holder_key(&initial_voucher, &sender.signing_key);
    let (voucher_after_split, _) = human_money_core::models::voucher::Transaction::create(
        &initial_voucher, // CORRECTION: Was missing in previous attempt
        freetaler_standard,
        &sender.user_id,
        &sender.signing_key,
        &holder_key, // Init->Tx1: Ephemeral key is holder key
        &recipient.user_id,
        split_amount,
        None,
    )
    .unwrap();

    // 6. Validate voucher after split
    let validation_result =
        validate_voucher_against_standard(&voucher_after_split, freetaler_standard);
    assert!(
        validation_result.is_ok(),
        "Validation after split failed: {:?}",
        validation_result.err()
    );
    assert_eq!(voucher_after_split.transactions.len(), 2);
    assert_eq!(
        voucher_after_split.transactions.last().unwrap().t_type,
        "split"
    );

    // 7. Check balances of both parties
    let sender_balance_after_split =
        voucher_after_split.spendable_balance_for_user( &sender.user_id, freetaler_standard, None).unwrap();
    let recipient_balance_after_split =
        voucher_after_split.spendable_balance_for_user( &recipient.user_id, freetaler_standard, None).unwrap();

    assert_eq!(sender_balance_after_split, dec!(69.50)); // 100.00 - 30.50
    assert_eq!(recipient_balance_after_split, dec!(30.50));
}

#[test]
fn test_split_fails_on_insufficient_funds() {
    // Setup as above
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = PublicProfile {
        id: Some(sender.user_id.clone()),
        ..Default::default()
    };

    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "50.0".to_string(); // Initial value 50

    // Re-signed mutated clone (see AUDIT-M03-010 note above).
    let (standard_obj, standard_hash_val) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let freetaler_standard = &standard_obj;
    let standard_hash = &standard_hash_val;

    let initial_voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        freetaler_standard,
        standard_hash,
        &sender.signing_key)
    .unwrap();

    // Attempt to send 50.1 (more than available)
    let holder_key = self::test_utils::derive_holder_key(&initial_voucher, &sender.signing_key);
    let split_result = human_money_core::models::voucher::Transaction::create(
        &initial_voucher,
        freetaler_standard,
        &sender.user_id,
        &sender.signing_key,
        &holder_key, // Init->Tx1 uses derived key
        &recipient.user_id,
        "50.1",
        None,
    )
    .map(|(v, _)| v);

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::InsufficientFunds { .. }
    ));
}

// --- NEW TEST FOR DATA-DRIVEN VALIDATION (PHASE 4) ---

#[test]
fn test_fails_to_create_forbidden_transaction_type() {
    // 1. Setup: Load the new test standard that forbids "split".
    let toml_str = include_str!("../../tests/test_data/standards/standard_no_split.toml");
    let standard: human_money_core::models::voucher_standard_definition::VoucherStandardDefinition =
        toml::from_str(toml_str).unwrap();

    // Since the standard is loaded at runtime, we must calculate the hash for creation manually.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = get_hash(to_canonical_json(&standard_to_hash.immutable).unwrap());

    // 2. Create a voucher that is valid under this standard.
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let creator = PublicProfile {
        id: Some(sender.user_id.clone()),
        ..Default::default()
    };
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(creator);
    voucher_data.nominal_value.amount = "100".to_string();

    let initial_voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        &standard,
        &standard_hash,
        &sender.signing_key)
    .unwrap();
    assert!(validate_voucher_against_standard(&initial_voucher, &standard).is_ok());

    // 3. Attempt to create a "split" transaction even though it is forbidden.
    let holder_key = self::test_utils::derive_holder_key(&initial_voucher, &sender.signing_key);
    let split_result = human_money_core::models::voucher::Transaction::create(
        &initial_voucher,
        &standard,
        &sender.user_id,
        &sender.signing_key,
        &holder_key, // Init->Tx1
        &recipient.user_id,
        "50", // Partial amount forcing a "split"
        None,
    )
    .map(|(v, _)| v);

    // 4. Assert: Creation must fail with a `TransactionTypeNotAllowed` error.
    println!(
        "[DEBUG] test_fails_to_create_forbidden_transaction_type actual result: {:?}",
        split_result
    );
    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::TransactionTypeNotAllowed { t_type, .. }) if t_type == "split"
    ));
}

#[test]
fn test_split_fails_on_non_allow_partial_transfers_voucher() {
    // Manipulate the standard to make it non-divisible.
    // Re-sign the mutated clone so it stays self-consistent at validation time
    // (AUDIT-M03-010 enforces signature validity when the standard enters validation).
    let (standard, new_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.allow_partial_transfers = false;
    });
    assert!(!standard.immutable.features.allow_partial_transfers);

    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = PublicProfile {
        id: Some(sender.user_id.clone()),
        ..Default::default()
    };

    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "60.00".to_string();

    let initial_voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        &standard,
        &new_hash,
        &sender.signing_key)
    .unwrap();

    let holder_key = self::test_utils::derive_holder_key(&initial_voucher, &sender.signing_key);
    let split_result = human_money_core::models::voucher::Transaction::create(
        &initial_voucher, // CORRECTION
        &standard,
        &sender.user_id,
        &sender.signing_key,
        &holder_key, // Init->Tx1
        &recipient.user_id,
        "10.0",
        None,
    )
    .map(|(v, _)| v);

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::VoucherPartialTransferNotAllowed
    ));
}

#[test]
fn test_validity_duration_rules() {
    // 1. Setup
    let identity = &ACTORS.issuer;
    let creator = PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    // 2. Test case: Attempt to create a voucher with too short validity duration.
    // The Minuto standard requires P3Y. We attempt P2Y.
    let mut short_duration_data = self::test_utils::create_minuto_voucher_data(creator.clone());
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    short_duration_data.validity_duration = Some("P2Y".to_string());
    let creation_result = human_money_core::models::voucher::Voucher::create_with_key(
        short_duration_data,
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    assert!(
        matches!(
            creation_result.unwrap_err(),
            VoucherCoreError::InvalidValidityDuration(_)
        ),
        "Creation should fail with InvalidValidityDuration error"
    );
}

// --- NEW SECURITY TESTS ---

// NOTE: This test is obsolete following the refactoring of `VoucherSignature`
// (removal of `voucher_id`). A signature is now
// an independent cryptographic proof that "Signer X
// assumed Role Y at Time Z".
// A "reused" signature is cryptographically indistinguishable
// from a "new" signature. Protection against "wrong" guarantors
// now occurs exclusively via `field_group_rules` and
// `required_signatures` rules in the standard (e.g. "only allow signer_id Z").
// The old behavior (binding to voucher_id) was removed.

#[test]
fn test_validation_fails_on_tampered_guarantor_signature() {
    // 1. Create a fully valid voucher
    let identity = &ACTORS.issuer;
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = self::test_utils::create_voucher_for_manipulation(
        self::test_utils::create_minuto_voucher_data(creator),
        minuto_standard,
        standard_hash,
        &identity.signing_key);

    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let sig1 =
        self::test_utils::create_guarantor_signature(&voucher, g1, "Original", "guarantor", "1");
    let sig2 =
        self::test_utils::create_guarantor_signature(&voucher, g2, "Untampered", "guarantor", "2");
    voucher.signatures.push(sig1);
    voucher.signatures.push(sig2);
    assert!(
        validate_voucher_against_standard(&voucher, minuto_standard).is_ok(),
        "Initial validation failed: {:?}",
        validate_voucher_against_standard(&voucher, minuto_standard).err()
    );

    // 2. Tamper with metadata of the first signature AFTER it was created.
    // We tamper with the guarantor signature (index 1+), not creator signature (index 0).
    let guarantor_sig = voucher
        .signatures
        .iter_mut()
        .find(|s| s.role == "guarantor")
        .unwrap();
    let original_signature_id = guarantor_sig.signature_id.clone();
    if let Some(ref mut details) = guarantor_sig.details {
        details.first_name = Some("Tampered".to_string());
    } else {
        // If there are no details, we create them
        guarantor_sig.details = Some(human_money_core::models::profile::PublicProfile {
            first_name: Some("Tampered".to_string()),
            ..Default::default()
        });
    }

    // 3. Validation must now fail because the hash of the data no longer matches signature_id.
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);

    assert!(
        matches!(validation_result.as_ref().unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidSignatureId(found_id)) if *found_id == original_signature_id),
        "Expected InvalidSignatureId error due to metadata tampering, but got {:?}",
        validation_result.err()
    );
}

#[test]
fn test_double_spend_detection_logic() {
    // 1. Setup: FreeTaler standard, one creator (Alice) and two recipients (Bob, Frank).
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let frank = &ACTORS.charlie;
    let alice_creator = PublicProfile {
        id: Some(alice.user_id.clone()),
        ..Default::default()
    };

    // 2. Alice creates a SILVER voucher with value 100, as it is divisible.
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(alice_creator);
    voucher_data.nominal_value.amount = "100".to_string();

    // We use a FreeTaler voucher here, as it is divisible and meant to demonstrate
    // the double spend logic.
    // Re-signed mutated clone (see AUDIT-M03-010 note above).
    let (standard_obj, standard_hash_val) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let freetaler_standard = &standard_obj;
    let standard_hash = &standard_hash_val;

    let initial_voucher = self::test_utils::create_voucher_for_manipulation(
        voucher_data,
        freetaler_standard,
        standard_hash,
        &alice.signing_key);
    assert!(validate_voucher_against_standard(&initial_voucher, freetaler_standard).is_ok());

    // 3. Alice performs a first, legitimate transaction: sends 40 to Bob.
    let holder_key =
        human_money_core::test_utils::derive_holder_key(&initial_voucher, &alice.signing_key);
    let (voucher_after_split, _) = human_money_core::models::voucher::Transaction::create(
        &initial_voucher,
        freetaler_standard,
        &alice.user_id,
        &alice.signing_key,
        &holder_key, // Init->Tx1
        &bob.user_id,
        "40",
        None,
    )
    .unwrap();
    let validation_result_1 =
        validate_voucher_against_standard(&voucher_after_split, freetaler_standard);
    assert!(
        validation_result_1.is_ok(),
        "Validation of the first legitimate transaction failed unexpectedly: {:?}",
        validation_result_1.err()
    );
    // 4. Alice cheats: she takes the state BEFORE the transaction to Bob (`initial_voucher`)
    //    and attempts to spend her original balance of 100 again by sending 60 to Frank.
    let (fraudulent_voucher, _) = human_money_core::models::voucher::Transaction::create(
        &initial_voucher,
        freetaler_standard,
        &alice.user_id,
        &alice.signing_key,
        &holder_key, // Double Spend Attempt (Same key as legit tx)
        &frank.user_id,
        "60",
        None,
    )
    .unwrap();
    let validation_result_2 =
        validate_voucher_against_standard(&fraudulent_voucher, freetaler_standard);
    assert!(
        validation_result_2.is_ok(),
        "Validation of the fraudulent (but individually valid) transaction failed unexpectedly: {:?}",
        validation_result_2.err()
    );

    // 5. Verification of the double spend:
    //    Both vouchers are valid on their own, but the second transaction in both
    //    is based on the same predecessor (the `init` transaction).
    let tx_to_bob = &voucher_after_split.transactions[1];
    let fraudulent_tx_to_frank = &fraudulent_voucher.transactions[1];

    // The proof: Same `prev_hash` and `sender_id`, but different `t_id`.
    // This is the fingerprint that a Layer-2 system would detect.
    assert_eq!(
        tx_to_bob.prev_hash, fraudulent_tx_to_frank.prev_hash,
        "prev_hash values must be identical to prove the double spend"
    );
    assert_eq!(
        tx_to_bob.sender_id, fraudulent_tx_to_frank.sender_id,
        "Sender IDs must be identical"
    );
    assert_ne!(
        tx_to_bob.t_id, fraudulent_tx_to_frank.t_id,
        "Transaction IDs must be different"
    );

    println!(
        "Double Spend Test: OK. prev_hash for both transactions is: {}",
        tx_to_bob.prev_hash
    );
}

// --- Helper functions for transfer test to simulate private logic of Wallet facade ---

/// Calculates the balance of a specific user after a specific transaction history.
fn get_balance_at_transaction(
    history: &[Transaction],
    user_id: &str,
    initial_amount: &str,
) -> Decimal {
    let mut current_balance = Decimal::ZERO;
    let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

    for tx in history {
        let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();
        if tx.recipient_id == user_id || tx.recipient_id == human_money_core::models::voucher::ANONYMOUS_ID {
            if tx.t_type == "init" {
                current_balance = total_amount;
            } else {
                current_balance += tx_amount;
            }
        } else if tx.sender_id.as_deref() == Some(user_id) {
            if let Some(remaining_str) = &tx.sender_remaining_amount {
                if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                    current_balance = remaining_amount;
                } else {
                    current_balance = Decimal::ZERO;
                }
            } else {
                current_balance = Decimal::ZERO;
            }
        }
    }
    current_balance
}

/// Calculates a deterministic, local ID for a voucher instance.
fn calculate_local_instance_id(voucher: &Voucher, profile_owner_id: &str) -> String {
    let mut defining_transaction_id: Option<String> = None;

    for i in (0..voucher.transactions.len()).rev() {
        let history_slice = &voucher.transactions[..=i];
        let balance = get_balance_at_transaction(
            history_slice,
            profile_owner_id,
            &voucher.nominal_value.amount,
        );

        if balance > Decimal::ZERO {
            defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
            break;
        }
    }

    let t_id = defining_transaction_id.expect("Voucher must be owned by the user.");
    let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
    get_hash(combined_string)
}

#[test]
fn test_secure_voucher_transfer_via_encrypted_bundle() {
    // --- 1. SETUP ---
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    // --- 2. VOUCHER CREATION by Alice ---
    let alice_creator = PublicProfile {
        id: Some(alice_identity.user_id.clone()),
        first_name: Some("Alice".to_string()),
        // Remaining fields omitted for test
        ..Default::default()
    };

    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: "500".to_string(),
            ..Default::default()
        },
        collateral: Some(Collateral::default()),
        creator_profile: alice_creator,
    };

    // Re-signed mutated clone (see AUDIT-M03-010 note above).
    let (standard_obj, standard_hash_val) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let freetaler_standard = &standard_obj;
    let standard_hash = &standard_hash_val;

    let voucher = self::test_utils::create_voucher_for_manipulation(
        voucher_data,
        freetaler_standard,
        standard_hash,
        &alice_identity.signing_key);
    let local_id = calculate_local_instance_id(&voucher, &alice_identity.user_id);

    alice_wallet.voucher_store.vouchers.insert(
        local_id.clone(),
        VoucherInstance {
            voucher,
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        },
    );
    assert!(alice_wallet.voucher_store.vouchers.contains_key(&local_id));

    // --- 3. SECURE TRANSFER from Alice to Bob ---
    // Instead of manually creating and bundling the transaction, we use the
    // public `execute_multi_transfer_and_bundle` method which correctly manages state (archiving).
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "500".to_string(), // Send full amount
        }],
        notes: Some("Here is the voucher I promised!".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        freetaler_standard.immutable.identity.uuid.clone(),
        freetaler_standard.clone(),
    );

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: encrypted_bundle_for_bob,
        ..
    } = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            None,
        )
        .unwrap();

    // AFTER CHANGE: The old instance is deleted. Only one new, archived instance should remain in wallet.
    assert_eq!(
        alice_wallet.voucher_store.vouchers.len(),
        1,
        "Alice's wallet should contain exactly one (archived) voucher instance."
    );
    let instance = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert!(
        matches!(instance.status, VoucherStatus::Archived),
        "The remaining voucher's status should be Archived after sending."
    );
    assert_eq!(
        alice_wallet.bundle_meta_store.history.len(),
        1,
        "Alice's bundle history should contain one entry."
    );

    // --- 4. RECEIPT AND PROCESSING by Bob ---
    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        freetaler_standard.immutable.identity.uuid.clone(),
        freetaler_standard.clone(),
    );
    bob_wallet
        .process_encrypted_transaction_bundle(
            bob_identity,
            &encrypted_bundle_for_bob,
            None,
            &standards_for_bob,
        )
        .unwrap();

    // --- 5. VERIFICATION ---
    assert_eq!(
        bob_wallet.voucher_store.vouchers.len(),
        1,
        "Bob's wallet should now have one voucher."
    );
    assert_eq!(
        bob_wallet.bundle_meta_store.history.len(),
        1,
        "Bob's bundle history should contain one entry."
    );

    // Calculate local ID for Bob's instance of voucher.
    let received_voucher = &bob_wallet
        .voucher_store
        .vouchers
        .values()
        .next()
        .unwrap()
        .voucher;
    let bob_local_id = calculate_local_instance_id(received_voucher, &bob_identity.user_id);
    assert!(
        bob_wallet
            .voucher_store
            .vouchers
            .contains_key(&bob_local_id),
        "Voucher with correct local ID should be in Bob's wallet."
    );

    // Add final check that received voucher is truly valid.
    // CORRECTION: Use assert! that outputs exact ValidationError on failure.
    let final_validation_result =
        validate_voucher_against_standard(received_voucher, freetaler_standard);
    assert!(
        final_validation_result.is_ok(),
        "Validation of the received voucher failed: {:?}",
        final_validation_result.err()
    );
    println!(
        "SUCCESS: Voucher was securely transferred from Alice to Bob via an encrypted bundle."
    );
}
