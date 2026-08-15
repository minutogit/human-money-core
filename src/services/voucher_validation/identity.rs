use crate::error::{StandardDefinitionError, ValidationError, VoucherCoreError};
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::get_hash;
use crate::services::utils::to_canonical_json;

pub fn verify_standard_identity(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.voucher_standard.uuid != standard.immutable.identity.uuid {
        return Err(ValidationError::StandardUuidMismatch {
            expected: standard.immutable.identity.uuid.clone(),
            found: voucher.voucher_standard.uuid.clone(),
        }
        .into());
    }

    let expected_hash = get_hash(to_canonical_json(&standard.immutable)?);

    if voucher.voucher_standard.standard_definition_hash != expected_hash {
        return Err(VoucherCoreError::Standard(
            StandardDefinitionError::StandardHashMismatch,
        ));
    }
    Ok(())
}

pub fn verify_voucher_hash(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();

    let calculated_hash = get_hash(to_canonical_json(&voucher_to_hash)?);

    if calculated_hash != voucher.voucher_id {
        Err(ValidationError::InvalidVoucherHash.into())
    } else {
        Ok(())
    }
}

pub fn verify_anti_spoofing(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    if !voucher.non_redeemable_test_voucher {
        let currency_upper = voucher.nominal_value.unit.to_uppercase();
        let standard_upper = voucher.voucher_standard.name.to_uppercase();

        if currency_upper.starts_with("TEST") {
            return Err(ValidationError::DeceptiveNaming {
                reason: format!("Currency unit '{}' starts with 'TEST' but voucher is NOT marked as test voucher.", voucher.nominal_value.unit)
            }.into());
        }

        if standard_upper.starts_with("TEST") {
            return Err(ValidationError::DeceptiveNaming {
                reason: format!("Standard name '{}' starts with 'TEST' but voucher is NOT marked as test voucher.", voucher.voucher_standard.name)
            }.into());
        }
    }
    Ok(())
}

pub fn verify_nominal_value(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.nominal_value.unit != standard.immutable.blueprint.unit {
        return Err(ValidationError::NominalUnitMismatch {
            expected: standard.immutable.blueprint.unit.clone(),
            found: voucher.nominal_value.unit.clone(),
        }
        .into());
    }
    Ok(())
}

pub fn verify_validity_duration(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    let standard_min_duration = standard.immutable.issuance.issuance_minimum_validity_duration.clone();

    if !standard_min_duration.is_empty() {
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        let min_valid_until_dt = crate::services::voucher_manager::add_iso8601_duration(
            creation_dt,
            &standard_min_duration,
        )?;

        let actual_valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        if actual_valid_until_dt < min_valid_until_dt {
            return Err(ValidationError::ValidityDurationTooShort.into());
        }
    }

    let standard_min_range = standard
        .immutable
        .issuance
        .validity_duration_range
        .get(0)
        .cloned()
        .unwrap_or_default();

    if !standard_min_range.is_empty() {
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        let min_range_valid_until_dt = crate::services::voucher_manager::add_iso8601_duration(
            creation_dt,
            &standard_min_range,
        )?;

        let actual_valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        if actual_valid_until_dt < min_range_valid_until_dt {
            return Err(ValidationError::ValidityDurationTooShort.into());
        }
    }

    let standard_max_duration = standard.immutable.issuance.validity_duration_range.get(1).cloned().unwrap_or_default();

    if !standard_max_duration.is_empty() {
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        let mut max_valid_until_dt = crate::services::voucher_manager::add_iso8601_duration(
            creation_dt,
            &standard_max_duration,
        )?;

        if let Some(rounding_str) = &standard.mutable.app_config.round_up_validity_to {
            max_valid_until_dt = crate::services::voucher_manager::round_up_date(max_valid_until_dt, rounding_str)?;
        }

        let actual_valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        if actual_valid_until_dt > max_valid_until_dt {
            return Err(ValidationError::ValidityDurationTooLong {
                max_allowed: standard_max_duration,
            }
            .into());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_nominal_value_success() {
        let mut voucher = Voucher::default();
        voucher.nominal_value.unit = "Minuten".to_string();

        let mut standard = VoucherStandardDefinition::default();
        standard.immutable.blueprint.unit = "Minuten".to_string();

        assert!(verify_nominal_value(&voucher, &standard).is_ok());
    }

    #[test]
    fn test_verify_nominal_value_mismatch() {
        let mut voucher = Voucher::default();
        voucher.nominal_value.unit = "Gramm Gold".to_string();

        let mut standard = VoucherStandardDefinition::default();
        standard.immutable.blueprint.unit = "Minuten".to_string();

        let result = verify_nominal_value(&voucher, &standard);
        assert!(result.is_err());
        match result {
            Err(VoucherCoreError::Validation(ValidationError::NominalUnitMismatch { expected, found })) => {
                assert_eq!(expected, "Minuten");
                assert_eq!(found, "Gramm Gold");
            }
            other => panic!("Expected NominalUnitMismatch, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_validity_duration_min_range_violation() {
        let mut voucher = Voucher::default();
        voucher.creation_date = "2026-01-01T00:00:00Z".to_string();
        // 2 years validity
        voucher.valid_until = "2028-01-01T00:00:00Z".to_string();

        let mut standard = VoucherStandardDefinition::default();
        standard.immutable.issuance.issuance_minimum_validity_duration = "P1Y".to_string();
        // Standard requires between 3 and 5 years
        standard.immutable.issuance.validity_duration_range = vec!["P3Y".to_string(), "P5Y".to_string()];

        let result = verify_validity_duration(&voucher, &standard);
        assert!(result.is_err());
        match result {
            Err(VoucherCoreError::Validation(ValidationError::ValidityDurationTooShort)) => {}
            other => panic!("Expected ValidityDurationTooShort, got {:?}", other),
        }
    }
}
