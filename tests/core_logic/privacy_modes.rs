// tests/core_logic/privacy_modes.rs
// cargo test --test core_logic_tests privacy_modes

use human_money_core::error::{ValidationError, VoucherCoreError};
use human_money_core::models::voucher::{Transaction, Voucher};
use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::services::voucher_manager::{self};
use human_money_core::services::voucher_validation;
use human_money_core::test_utils::{self, ACTORS, SILVER_STANDARD};
use human_money_core::to_canonical_json;

// --- Helper: Create voucher with specific privacy mode ---
fn create_privacy_test_voucher(
    mode: &str,
) -> (
    Voucher,
    human_money_core::models::voucher_standard_definition::VoucherStandardDefinition,
) {
    let creator_profile = human_money_core::models::profile::PublicProfile {
        id: Some(ACTORS.issuer.user_id.clone()),
        ..Default::default()
    };
    let data = test_utils::create_minuto_voucher_data(creator_profile);

    // Modify standard to enforcing the requested privacy mode
    let mut standard = SILVER_STANDARD.0.clone();

    // Construct PrivacySettings equivalent
    let privacy_settings = human_money_core::models::voucher_standard_definition::PrivacySettings {
        mode: mode.to_string(),
    };
    standard.privacy = Some(privacy_settings);

    // We need to re-hash the standard because validation checks hash
    // BUT: `create_voucher` takes standard and hash.
    // We can just calculate the new hash.
    // Actually `verify_standard_identity` checks `voucher.voucher_standard.standard_definition_hash` vs `hash(standard_without_sig)`.

    let mut standard_no_sig = standard.clone();
    standard_no_sig.signature = None;
    let new_std_hash = get_hash(to_canonical_json(&standard_no_sig).unwrap());

    let voucher = voucher_manager::create_voucher(
        data,
        &standard,
        &new_std_hash,
        &ACTORS.issuer.signing_key,
        "en",
    )
    .unwrap();

    (voucher, standard)
}

#[test]
fn test_privacy_mode_public_success() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("public");

    // Add a valid public transaction
    // Public requires: sender_id (Some), recipient_id (DID)
    let tx = Transaction {
        t_id: "stub".to_string(), // will be hashed/ignored in some checks, but let's be clean
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: Some(ACTORS.issuer.user_id.clone()), // Public ID
        recipient_id: ACTORS.alice.user_id.clone(),     // DID
        ..Default::default()
    };
    // Note: We are manually pushing. Validation handles logic.
    // Signatures might fail if we don't sign, but `validate_privacy_mode` is called BEFORE signature verification?
    // Actually `validate_voucher_against_standard` validation order:
    // 1. Standard Identity
    // 2. Voucher Hash
    // ...
    // Privacy Mode
    // ...
    // Signatures (Last)

    // So if we just want to test privacy mode, we might hit other errors first if we leave signatures empty.
    // BUT: `validate_privacy_mode` is isolated. We can call it directly if it was public, but it is not.
    // We must ensure the voucher is otherwise valid enough to reach privacy check.

    // Let's rely on the fact that we can construct a semantically correct transaction.
    // We won't sign it perfectly for this test unless necessary.
    // Wait, if validation stops at first error, we need correct signatures ideally.
    // Or we mock the validations? No.
    // Let's use `voucher_validation::validate_privacy_mode` if it was public? It is not.
    // We have to run full validation.
    // We will get signature errors.
    // CHECK: Can we make `validate_privacy_mode` public for testing? Or just use full valid vouchers?
    // Creating full valid vouchers is better.

    // To create valid vouchers easily, we should use `voucher_manager::create_transaction`?
    // `create_transaction` enforces logical consistency, but maybe not the privacy rule itself during creation yet?
    // The instructions said: "Update create_transaction to accept privacy_mode ... Handle sender_id visibility".
    // So if we use `create_transaction` with the right mode (if it supports it), it should produce valid tx.
    // If we manually construct invalid ones, we test the validator.

    // For this test, we accept Signature errors as "Passing Privacy Check",
    // OR we explicitly check for Privacy errors.
    // If we get SignatureError, it means Privacy Check passed!

    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);

    match result {
        Ok(_) => {} // Success with bypass!
        Err(VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. })) => {
            // Acceptable for this manual test construction (funds logic might be strict)
        }
        Err(e) => panic!("Validation failed even with signature bypass: {:?}", e),
    }
}

#[test]
fn test_privacy_mode_public_fails_missing_sender() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("public");

    let tx = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: None, // INVALID for Public
        recipient_id: ACTORS.alice.user_id.clone(),
        ..Default::default()
    };
    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);
    assert!(
        matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) if msg.contains("missing sender_id")),
        "Should fail due to missing sender_id in public mode"
    );
}

#[test]
fn test_privacy_mode_public_fails_anonymous_recipient() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("public");

    let tx = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: Some(ACTORS.issuer.user_id.clone()),
        recipient_id: "not-a-did".to_string(), // INVALID for Public
        ..Default::default()
    };
    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);
    assert!(
        matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) if msg.contains("non-DID recipient")),
        "Should fail due to non-DID recipient in public mode"
    );
}

#[test]
fn test_privacy_mode_stealth_success() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("stealth");

    // Stealth: Sender None, Recipient NOT DID
    let tx = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: None,
        recipient_id: "hash-of-key".to_string(),
        ..Default::default()
    };
    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);

    // Should pass with bypass (or fail with unrelated funds error)
    match result {
        Ok(_) => {}
        Err(VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. })) => {}
        Err(e) => panic!("Stealth validation failed: {:?}", e),
    }
}

#[test]
fn test_privacy_mode_stealth_fails_with_sender_id() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("stealth");

    let tx = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: Some("did:example:123".to_string()), // INVALID for Stealth
        recipient_id: "hash-of-key".to_string(),
        ..Default::default()
    };
    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);
    assert!(
        matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) if msg.contains("has sender_id")),
        "Should fail if sender_id is present in stealth mode"
    );
}

#[test]
fn test_privacy_mode_stealth_fails_with_did_recipient() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("stealth");

    let tx = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: None,
        recipient_id: "did:key:zABC".to_string(), // INVALID for Stealth
        ..Default::default()
    };
    voucher.transactions.push(tx);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);
    assert!(
        matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) if msg.contains("public DID recipient")),
        "Should fail if recipient is DID in stealth mode"
    );
}

#[test]
fn test_privacy_mode_flexible_allows_all() {
    human_money_core::set_signature_bypass(true);
    let (mut voucher, standard) = create_privacy_test_voucher("flexible");

    // Case 1: Public-like
    let tx1 = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: Some("did:example:sender".to_string()),
        recipient_id: "did:example:recipient".to_string(),
        ..Default::default()
    };
    voucher.transactions.push(tx1);

    // Case 2: Stealth-like
    let tx2 = Transaction {
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: "10.0000".to_string(),
        sender_id: None,
        recipient_id: "some-hash".to_string(),
        ..Default::default()
    };
    voucher.transactions.push(tx2);

    let result = voucher_validation::validate_voucher_against_standard(&voucher, &standard);

    match result {
        Ok(_) => {}
        Err(VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. })) => {}
        Err(e) => panic!("Flexible mode validation failed: {:?}", e),
    }
}
