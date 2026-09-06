// tests/validation/validity_rounding.rs
// cargo test --test integration_tests validation::validity_rounding

use human_money_core::error::{ValidationError, VoucherCoreError};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::NewVoucherData;
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::{
    create_custom_standard, create_female_guarantor_signature, create_male_guarantor_signature,
    ACTORS, MINUTO_STANDARD,
};

#[test]
fn test_validation_accepts_valid_voucher_with_rounded_max_duration_yearly() {
    let (custom_standard, standard_hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
        // Standard defines max 5 years validity duration
        s.immutable.issuance.validity_duration_range = vec!["P1Y".to_string(), "P5Y".to_string()];
        // Default validity duration is 5 years
        s.mutable.app_config.default_validity_duration = Some("P5Y".to_string());
        // Rounding rule: round up to end of calendar year (P1Y)
        s.mutable.app_config.round_up_validity_to = Some("P1Y".to_string());
    });

    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator_identity.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "10".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P5Y".to_string()),
        ..Default::default()
    };

    // 1. Create the voucher with 5-year base duration
    let mut voucher = human_money_core::Voucher::create_with_key(
        voucher_data,
        &custom_standard,
        &standard_hash,
        &creator_identity.signing_key,
    )
    .expect("Voucher creation should succeed");

    // Add the required guarantor signatures so that all other rules are satisfied
    voucher
        .signatures
        .push(create_male_guarantor_signature(&voucher));
    voucher
        .signatures
        .push(create_female_guarantor_signature(&voucher));

    // 2. Validate the voucher against the standard.
    // Despite rounding up to the end of the year (e.g. 5.4 years), the voucher must be valid,
    // because it does not exceed the maximum base duration (5 years) plus standard rounding.
    let validation_result = validate_voucher_against_standard(&voucher, &custom_standard);
    assert!(
        validation_result.is_ok(),
        "Validation should pass with rounded max duration tolerance, got: {:?}",
        validation_result
    );
}

#[test]
fn test_validation_accepts_quarterly_and_half_year_rounding() {
    let creator_identity = &ACTORS.alice;

    for rounding_rule in ["P3M", "P6M", "P1D", "P1M"] {
        let (custom_standard, standard_hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
            s.immutable.issuance.validity_duration_range =
                vec!["P1Y".to_string(), "P3Y".to_string()];
            s.mutable.app_config.default_validity_duration = Some("P3Y".to_string());
            s.mutable.app_config.round_up_validity_to = Some(rounding_rule.to_string());
        });

        let voucher_data = NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(creator_identity.user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "10".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P3Y".to_string()),
            ..Default::default()
        };

        let mut voucher = human_money_core::Voucher::create_with_key(
            voucher_data,
            &custom_standard,
            &standard_hash,
            &creator_identity.signing_key,
        )
        .expect("Voucher creation should succeed");

        voucher
            .signatures
            .push(create_male_guarantor_signature(&voucher));
        voucher
            .signatures
            .push(create_female_guarantor_signature(&voucher));

        let validation_result = validate_voucher_against_standard(&voucher, &custom_standard);
        assert!(
            validation_result.is_ok(),
            "Validation should pass for rounding rule {}, got: {:?}",
            rounding_rule,
            validation_result
        );
    }
}

#[test]
fn test_validation_rejects_voucher_exceeding_rounded_max_duration() {
    let (custom_standard, standard_hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
        s.immutable.issuance.validity_duration_range = vec!["P1Y".to_string(), "P5Y".to_string()];
        s.mutable.app_config.round_up_validity_to = Some("P1Y".to_string());
    });

    let creator_identity = &ACTORS.alice;
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator_identity.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "10".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P5Y".to_string()),
        ..Default::default()
    };

    let mut voucher = human_money_core::Voucher::create_with_key(
        voucher_data,
        &custom_standard,
        &standard_hash,
        &creator_identity.signing_key,
    )
    .expect("Voucher creation should succeed");

    voucher
        .signatures
        .push(create_male_guarantor_signature(&voucher));
    voucher
        .signatures
        .push(create_female_guarantor_signature(&voucher));

    // Manipulate valid_until to 1 year beyond the allowed rounded maximum
    let original_valid_until_dt =
        chrono::DateTime::parse_from_rfc3339(&voucher.valid_until).unwrap();
    let exceeded_valid_until_dt =
        human_money_core::services::utils::add_iso8601_duration(original_valid_until_dt.into(), "P1Y")
            .unwrap();
    voucher.valid_until = exceeded_valid_until_dt.to_rfc3339();

    // Check validity duration validation directly
    let validation_result = human_money_core::services::voucher_validation::verify_validity_duration(&voucher, &custom_standard);
    assert!(
        validation_result.is_err(),
        "Validation should fail when valid_until exceeds rounded max duration"
    );

    match validation_result {
        Err(VoucherCoreError::Validation(ValidationError::ValidityDurationTooLong { max_allowed })) => {
            assert_eq!(max_allowed, "P5Y");
        }
        other => panic!("Expected ValidityDurationTooLong, got: {:?}", other),
    }
}

