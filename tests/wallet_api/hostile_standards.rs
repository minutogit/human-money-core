// tests/wallet_api/hostile_standards.rs
// cargo test --test wallet_api_tests
//!
//! Enthält Tests, die das System gegen feindselige oder logisch inkonsistente
//! Gutschein-Standard-Definitionen härten.

use human_money_core::{
    models::{profile::PublicProfile, voucher::ValueDefinition},
    services::voucher_manager::NewVoucherData,
    test_utils::{self, ACTORS, SILVER_STANDARD, create_custom_standard},
};
use tempfile::tempdir;

/// Test 1.1: Stellt sicher, dass ein Transfer fehlschlägt, wenn der Transaktionstyp
/// (`split`) laut Standard nicht erlaubt ist.
#[test]
fn test_disallowed_transaction_type() {
    // 1. ARRANGE: Standard erstellen, der "split" verbietet
    let (hostile_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        if true {
            if true {
                s.immutable.features.allow_partial_transfers = false;
            }
        }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let password = "password";
    let (mut service, _) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Test User", password);
    let user_id = service.get_user_id().unwrap();

    let voucher = service
        .create_new_voucher(
            &hostile_standard_toml,
            "en",
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
    let local_id = service.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();
    assert_eq!(
        voucher.voucher_standard.uuid,
        hostile_standard.immutable.identity.uuid
    );

    // 2. ACT: Versuche einen Split-Transfer
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.recipient1.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "40".to_string(), // Teilbetrag -> "split"
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(
        hostile_standard.immutable.identity.uuid.clone(),
        hostile_standard_toml.clone(),
    );

    let result = service.create_transfer_bundle(request, &standards_toml, None, Some(password));

    // 3. ASSERT: Operation muss fehlschlagen
    assert!(result.is_err());
    let error_string = result.unwrap_err();
    assert!(
        error_string.contains("allow partial transfers"),
        "Error message should indicate that 'split' is not allowed. Got: {}",
        error_string
    );
}

/// Test 1.2: Stellt sicher, dass die Erstellung eines Gutscheins fehlschlägt, wenn die
/// angegebene Gültigkeitsdauer die im Standard definierte maximale Dauer überschreitet.
#[test]
fn test_violation_of_max_creation_validity() {
    // 1. ARRANGE: Standard mit maximaler Gültigkeit von 1 Jahr erstellen
    let (hostile_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        if true {
            if true {
                s.immutable.issuance.validity_duration_range = vec!["P0M".to_string(), "P1Y".to_string()];
            }
        }
    });
    let hostile_standard_toml = toml::to_string(&hostile_standard).unwrap();

    let dir = tempdir().unwrap();
    let password = "password";
    let (mut service, _) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Test User", password);
    let user_id = service.get_user_id().unwrap();

    // 2. ACT: Versuche, einen Gutschein mit einer Gültigkeit von 2 Jahren zu erstellen
    let result = service.create_new_voucher(
        &hostile_standard_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P2Y".to_string()), // Länger als erlaubt
            ..Default::default()
        },
        Some(password),
    );

    // 3. ASSERT: Operation muss fehlschlagen
    assert!(result.is_err());
    let error_string = result.unwrap_err();
    assert!(
        error_string.contains("exceeds the maximum allowed standard validity"),
        "Error message should indicate that validity is too long. Got: {}",
        error_string
    );
}
