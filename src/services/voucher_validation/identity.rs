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

pub fn verify_validity_duration(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    let standard_min_duration = standard.immutable.issuance.issuance_minimum_validity_duration.clone();

    if voucher
        .voucher_standard
        .template
        .issuance_minimum_validity_duration
        != standard_min_duration
    {
        return Err(ValidationError::MismatchedMinimumValidity {
            expected: standard_min_duration,
            found: voucher
                .voucher_standard
                .template
                .issuance_minimum_validity_duration
                .clone(),
        }
        .into());
    }

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

    let standard_max_duration = standard.immutable.issuance.validity_duration_range.get(1).cloned().unwrap_or_default();

    if !standard_max_duration.is_empty() {
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
            .map_err(|_| ValidationError::InvalidDateLogic {
                creation: voucher.creation_date.clone(),
                valid_until: voucher.valid_until.clone(),
            })?
            .with_timezone(&chrono::Utc);

        let max_valid_until_dt = crate::services::voucher_manager::add_iso8601_duration(
            creation_dt,
            &standard_max_duration,
        )?;

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
