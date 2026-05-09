//! # Voucher Manager Service
//!
//! This service orchestrates the lifecycle of vouchers, including creation,
//! transaction processing, balance calculation, and validation rules.

pub mod creation;
pub mod transaction;
pub mod balance;
pub mod date_utils;

use rust_decimal::Decimal;
use thiserror::Error;

// Re-exports for API stability
pub use creation::{create_voucher, from_json, to_json, NewVoucherData};
pub use transaction::{create_transaction, TransactionSecrets};
pub use balance::{get_spendable_balance, validate_issuance_firewall};
pub use date_utils::{add_iso8601_duration, round_up_date};

/// Defines the errors that can occur within the `voucher_manager` module.
#[derive(Error, Debug)]
pub enum VoucherManagerError {
    /// The voucher does not allow partial transfers according to its standard.
    #[error("Voucher does not allow partial transfers according to its standard.")]
    VoucherPartialTransferNotAllowed,
    /// Insufficient funds for the transaction.
    #[error("Insufficient funds: Available: {available}, Needed: {needed}")]
    InsufficientFunds { available: Decimal, needed: Decimal },
    /// Amount precision exceeds the limit allowed by the standard.
    #[error("Amount precision exceeds standard limit. Allowed: {allowed}, Found: {found}")]
    AmountPrecisionExceeded { allowed: u32, found: u32 },
    /// A template value from the standard is invalid.
    #[error("Invalid template value from standard: {0}")]
    InvalidTemplateValue(String),
    /// The specified validity duration does not meet the standard's requirements.
    #[error("Invalid validity duration: {0}")]
    InvalidValidityDuration(String),
    /// A general error with a description.
    #[error("Voucher Manager Error: {0}")]
    Generic(String),
    /// A validation error from the validation module.
    #[error("Validation Error: {0}")]
    ValidationError(String),
}

impl From<rust_decimal::Error> for VoucherManagerError {
    fn from(err: rust_decimal::Error) -> Self {
        VoucherManagerError::Generic(err.to_string())
    }
}

impl From<serde_json::Error> for VoucherManagerError {
    fn from(err: serde_json::Error) -> Self {
        VoucherManagerError::Generic(err.to_string())
    }
}
