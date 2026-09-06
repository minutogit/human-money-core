//! # src/error/app.rs
//!
//! App-service (facade) typed errors.
//! Replaces `Error::Generic` strings that originated in `AppService`
//! (session handling, instance-id trap, profile lifecycle).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed app-layer errors.
#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum AppError {
    /// Session timed out.
    #[error("Session timed out: {reason}")]
    SessionExpired { reason: String },

    /// Password required but no active session.
    #[error("Password required: {reason}")]
    SessionNotActive { reason: String },

    /// Critical security violation (e.g. instance_id stored in wallet dir).
    #[error("Security violation: {reason}")]
    SecurityViolation { reason: String },

    /// Profile not found.
    #[error("Profile not found: {reason}")]
    ProfileNotFound { reason: String },

    /// Profile already exists.
    #[error("Profile already exists: {reason}")]
    ProfileAlreadyExists { reason: String },

    /// Wallet is locked.
    #[error("Wallet is locked")]
    WalletLocked,

    /// Feature not implemented.
    #[error("Feature not implemented: {feature}")]
    NotImplemented { feature: String },

    /// Invariant violation at app layer.
    #[error("Invariant violation: {message}")]
    InvariantViolation { message: String },

    /// Generic state conflict at app layer.
    #[error("State conflict: {message}")]
    StateConflict { message: String },

    /// Lock timeout at app layer.
    #[error("Lock timeout: {reason}")]
    LockTimeout { reason: String },

    // --- Phase 4: Typed app-service validation (replacing Error::ValidationFailed ad-hoc) ---

    /// Invalid payload type for voucher signing bundle.
    #[error("Invalid payload type: expected VoucherForSigning")]
    InvalidPayloadTypeVoucherForSigning,

    /// Invalid payload type for voucher standard definition.
    #[error("Invalid payload type: expected VoucherStandardDefinition")]
    InvalidPayloadTypeVoucherStandardDefinition,

    /// Container does not contain a Double-Spend-Proof.
    #[error("Container does not contain a Double-Spend-Proof.")]
    ContainerDoesNotContainDoubleSpendProof,

    /// No transactions found in voucher (challenge derivation).
    #[error("No transactions found in voucher")]
    NoTransactionsFoundInVoucher,

    /// Voucher has no transactions (status query).
    #[error("Voucher has no transactions")]
    VoucherHasNoTransactions,

    /// No transactions found (L2 evaluation).
    #[error("No transactions found")]
    NoTransactionsFound,

    /// No seal found. Cannot repair integrity without seal.
    #[error("No seal found. Cannot repair integrity without seal.")]
    MissingSealForIntegrityRepair,

    /// No seal found. Recovery may be required.
    #[error("No seal found. Recovery may be required.")]
    MissingSealForRecovery,

    /// No local seal found. Recovery required.
    #[error("No local seal found. Recovery required.")]
    MissingLocalSeal,

    /// Remote seal integrity check failed.
    #[error("Remote seal integrity check failed: {details}")]
    RemoteSealIntegrityFailed { details: String },

    /// Seal integrity check failed.
    #[error("Seal integrity check failed: {details}")]
    SealIntegrityFailed { details: String },

    /// Invalid UTF-8 in container payload.
    #[error("Invalid UTF-8 in container payload: {reason}")]
    InvalidUtf8InContainerPayload { reason: String },

    /// Invalid UTF-8 in standard file.
    #[error("Invalid UTF-8 in standard file: {reason}")]
    InvalidUtf8InStandardFile { reason: String },

    /// Invalid standard uuid: path separators not permitted.
    #[error("Invalid standard uuid '{uuid}': path separators and traversal tokens are not permitted.")]
    InvalidStandardUuid { uuid: String },

    /// Conflict: different standard already installed under uuid.
    #[error("Conflict: a different standard is already installed under uuid '{uuid}'. Refusing to overwrite it silently.")]
    StandardAlreadyInstalled { uuid: String },

    /// Invalid standard ID for deletion.
    #[error("Invalid standard ID for deletion.")]
    InvalidStandardIdForDeletion,

    /// Standard cannot be deleted because it is still in use.
    #[error("Standard cannot be deleted because it is still in use by {count} voucher(s).")]
    StandardInUse { count: usize },

    /// Failed to reload wallet.
    #[error("Failed to reload wallet: {reason}")]
    ReloadFailed { reason: String },

    /// Failed to reload wallet before L2 write.
    #[error("Failed to reload wallet before L2 write: {reason}")]
    ReloadFailedBeforeL2Write { reason: String },

    /// L2 server public key not configured in wallet profile.
    #[error("L2 server public key not configured in wallet profile")]
    L2ServerPubkeyNotConfigured,

    /// Device mismatch (seal bound to different device).
    #[error("{message}")]
    DeviceMismatch { message: String },
}
