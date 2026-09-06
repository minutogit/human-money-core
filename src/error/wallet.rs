//! # src/error/wallet.rs
//!
//! Wallet-domain typed errors.
//! Replaces the former `Error::Generic` and `Error::VoucherManagerGeneric`
//! ad-hoc strings with discriminable variants (`AmountOverflow`,
//! `InvalidTimestamp`, `StateConflict`, `InvariantViolation`, …).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed wallet errors that previously surfaced as `Error::Generic(String)`
/// or `Error::VoucherManagerGeneric(String)`.
#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum WalletError {
    /// Aggregated voucher amounts overflowed `Decimal::MAX`.
    #[error("Amount overflow while aggregating received voucher amounts: {details}")]
    AmountOverflow { details: String },

    /// A timestamp string could not be parsed.
    #[error("Invalid timestamp: {reason}")]
    InvalidTimestamp { reason: String },

    /// Standard definition not found for a voucher's UUID.
    #[error("Standard definition not found for UUID: {uuid}")]
    StandardNotFound { uuid: String },

    /// Voucher carries no transactions where at least one was expected.
    #[error("Voucher has no transactions")]
    MissingTransactions,

    /// An amount string is not a valid decimal.
    #[error("Invalid amount: {reason}")]
    InvalidAmount { reason: String },

    /// A nonce could not be decoded.
    #[error("Invalid nonce: {reason}")]
    InvalidNonce { reason: String },

    /// Creator profile has no ID.
    #[error("Creator profile has no ID")]
    MissingCreatorId,

    /// Signature not found.
    #[error("Signature with ID '{signature_id}' not found")]
    SignatureNotFound { signature_id: String },

    /// Proof not found.
    #[error("Proof with ID '{proof_id}' not found")]
    ProofNotFound { proof_id: String },

    /// Endorsement or proof import error.
    #[error("Endorsement error: {reason}")]
    EndorsementError { reason: String },

    /// JWS profile import/export error.
    #[error("JWS error: {reason}")]
    JwsError { reason: String },

    /// Missing `sender_ephemeral_pub` for L2 lock request.
    #[error("Missing sender_ephemeral_pub for L2 lock request")]
    MissingSenderEphemeralPub,

    /// Missing `layer2_signature` for L2 lock request.
    #[error("Missing layer2_signature for L2 lock request")]
    MissingLayer2Signature,

    /// Only `init` transactions can define a voucher id.
    #[error("Only init transactions can define a voucher id")]
    OnlyInitTransactionsAllowed,

    /// Seed re-derivation failed (no valid ownership strategy).
    #[error("Seed derivation failed: {reason}")]
    SeedDerivationFailed { reason: String },

    /// Invalid creation date.
    #[error("Failed to parse creation date: {reason}")]
    InvalidCreationDate { reason: String },

    /// Invalid voucher date field.
    #[error("Failed to parse voucher date '{field}': {reason}")]
    InvalidVoucherDate { field: String, reason: String },

    /// Template value from standard is invalid.
    #[error("Invalid template value from standard: {reason}")]
    InvalidTemplateValue { reason: String },

    /// Validity duration is invalid.
    #[error("Invalid validity duration: {reason}")]
    InvalidDuration { reason: String },

    /// Generic invariant violation (logic error, replaces ad-hoc Generic).
    #[error("Invariant violation: {message}")]
    InvariantViolation { message: String },

    /// State conflict (generation mismatch, concurrent modification).
    #[error("State conflict: {message}")]
    StateConflict { message: String },

    /// Voucher has no transactions but one was required for archiving.
    #[error("Cannot archive voucher with no transactions")]
    CannotArchiveEmpty,

    /// Proof import failed with typed reason.
    #[error("Proof import error: {reason}")]
    ProofImportFailed { reason: String },
}
