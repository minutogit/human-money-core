//! # src/services/decimal_utils.rs
//!
//! Contains central helper functions for consistent validation and formatting
//! of `Decimal` values. The functions defined here ensure that
//! all amounts in the system are treated uniformly to avoid rounding and
//! comparison errors.

use crate::error::VoucherCoreError;
use crate::services::voucher_manager::VoucherManagerError;
use rust_decimal::Decimal;

/// **Principle: Strict validation on input.**
///
/// Ensures that a `Decimal` value does not exceed the number of decimal
/// places allowed by the standard. Fails if the input precision is too high.
///
/// # Arguments
/// * `amount` - The `Decimal` value to check.
/// * `allowed_places` - The maximum allowed number of decimal places.
///
/// # Returns
/// A `Result` that is empty on success or contains a `VoucherCoreError`.
pub fn validate_precision(amount: &Decimal, allowed_places: u32) -> Result<(), VoucherCoreError> {
    if amount.scale() > allowed_places {
        Err(VoucherManagerError::AmountPrecisionExceeded {
            allowed: allowed_places,
            found: amount.scale(),
        }
        .into())
    } else {
        Ok(())
    }
}

/// **Principle: Canonical storage format.**
///
/// Formats a `Decimal` value into the canonical string stored in the
/// transaction chain (e.g. 60 -> "60.0000").
///
/// # Arguments
/// * `amount` - The `Decimal` value to format.
/// * `places` - The number of decimal places in the output string.
///
/// # Returns
/// A `String` with the canonical representation of the amount.
pub fn format_for_storage(amount: &Decimal, places: u32) -> String {
    format!("{:.1$}", amount, places as usize)
}
