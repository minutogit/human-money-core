mod identity;
mod rules;
mod chain;
mod signatures;

use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;

pub use identity::*;
pub use rules::*;
pub use chain::*;
pub use signatures::*;

/// Main function for validating a voucher against its standard.
/// This is the central orchestrator that invokes all subordinate validation steps.
pub fn validate_voucher_against_standard(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    identity::verify_standard_identity(voucher, standard)?;
    identity::verify_nominal_value(voucher, standard)?;
    identity::verify_voucher_hash(voucher)?;
    identity::verify_anti_spoofing(voucher)?;

    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
        .map_err(|_| ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        })?
        .with_timezone(&chrono::Utc);
    let valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|_| ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        })?
        .with_timezone(&chrono::Utc);

    if valid_until_dt < creation_dt {
        return Err(ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        }
        .into());
    }

    identity::verify_validity_duration(voucher, standard)?;
    rules::validate_transaction_types(voucher, standard)?;

    let failing_rules = rules::get_failing_custom_rules(voucher, standard)?;
    if !failing_rules.is_empty() {
        return Err(ValidationError::BusinessRuleViolated(failing_rules[0].clone()).into());
    }

    let privacy_mode = &standard.immutable.features.privacy_mode;
    chain::validate_privacy_mode(voucher, privacy_mode)?;

    chain::verify_transactions(voucher, standard)?;
    signatures::verify_signatures(voucher, standard)?;
    Ok(())
}

#[cfg(test)]
mod anti_spoofing_tests {
    use super::*;
    use crate::models::voucher::Voucher;

    #[test]
    fn test_validation_rejects_live_voucher_with_test_prefix_currency() {
        let mut voucher = Voucher::default();
        voucher.non_redeemable_test_voucher = false;
        voucher.nominal_value.unit = "TEST-Euro".to_string();
        
        let result = identity::verify_anti_spoofing(&voucher);
        assert!(result.is_err());
        match result {
            Err(VoucherCoreError::Validation(ValidationError::DeceptiveNaming { reason })) => {
                assert!(reason.contains("Currency unit 'TEST-Euro'"));
            }
            _ => panic!("Expected DeceptiveNaming error, got {:?}", result),
        }
    }

    #[test]
    fn test_validation_rejects_live_voucher_with_test_prefix_standard() {
        let mut voucher = Voucher::default();
        voucher.non_redeemable_test_voucher = false;
        voucher.voucher_standard.name = "test_minuto".to_string();
        
        let result = identity::verify_anti_spoofing(&voucher);
        assert!(result.is_err());
        match result {
            Err(VoucherCoreError::Validation(ValidationError::DeceptiveNaming { reason })) => {
                assert!(reason.contains("Standard name 'test_minuto'"));
            }
            _ => panic!("Expected DeceptiveNaming error, got {:?}", result),
        }
    }
}
