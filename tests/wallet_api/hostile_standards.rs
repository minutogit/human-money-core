// tests/wallet_api/hostile_standards.rs
// cargo test --test wallet_api_tests
//!
//! Contains tests that harden the system against hostile or logically inconsistent
//! voucher standard definitions.

use human_money_core::{
    models::{profile::PublicProfile, voucher::ValueDefinition},
    NewVoucherData,
    test_utils::{self, ACTORS, FREETALER_STANDARD, create_custom_standard},
};
use tempfile::tempdir;

/// Test 1.1: Ensures that a transfer fails when the transaction type
/// (`split`) is not allowed according to the standard.
#[test]
fn test_disallowed_transaction_type() {
    // 1. ARRANGE: Create standard that prohibits "split"
    let (hostile_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        if true
            && true {
                s.immutable.features.allow_partial_transfers = false;
            }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let password = "password";
    let (mut service, _) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Test User", password);
    let user_id = service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let voucher = service
        .create_new_voucher(
            &hostile_standard_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(user_id),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();
    let local_id = service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();
    assert_eq!(
        voucher.voucher_standard.uuid,
        hostile_standard.immutable.identity.uuid
    );

    // 2. ACT: Attempt a split transfer
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.recipient1.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "40".to_string(), // Partial amount -> "split"
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(
        hostile_standard.immutable.identity.uuid.clone(),
        hostile_standard_toml.clone(),
    );

    let result = service.create_transfer_bundle(request, &standards_toml, None, Some(password));

    // 3. ASSERT: Operation must fail
    assert!(result.is_err());
    let error_string = result.unwrap_err().to_string();
    assert!(
        error_string.contains("allow partial transfers"),
        "Error message should indicate that 'split' is not allowed. Got: {}",
        error_string
    );
}

/// Test 1.2: Ensures that creating a voucher fails when the
/// specified validity duration exceeds the maximum duration defined in the standard.
#[test]
fn test_violation_of_max_creation_validity() {
    // 1. ARRANGE: Create standard with maximum validity of 1 year
    let (hostile_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        if true
            && true {
                s.immutable.issuance.validity_duration_range = vec!["P0M".to_string(), "P1Y".to_string()];
            }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let password = "password";
    let (mut service, _) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Test User", password);
    let user_id = service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // 2. ACT: Attempt to create a voucher with validity of 2 years
    let result = service.create_new_voucher(
        &hostile_standard_toml,
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P2Y".to_string()), // Longer than allowed
            ..Default::default()
        },
        Some(password),
    );

    // 3. ASSERT: Operation must fail
    assert!(result.is_err());
    let error_string = result.unwrap_err().to_string();
    assert!(
        error_string.contains("exceeds the maximum allowed standard validity"),
        "Error message should indicate that validity is too long. Got: {}",
        error_string
    );
}
