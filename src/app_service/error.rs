//! # src/app_service/error.rs
//!
//! Structured, type-safe errors returned by the AppService facade.
//! Models all potential error scenarios for client-side applications (like Tauri/React)
//! to support translation, structured messaging, and proper error handling.

use crate::error::{VoucherCoreError, ValidationError, StandardDefinitionError};
use crate::storage::StorageError;
use thiserror::Error;

/// Central error type for the AppService facade.
/// Serialized with a "type" tag and "message" content for easy client-side processing.
#[derive(Debug, Clone, Error, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "message", rename_all = "camelCase")]
pub enum AppFacadeError {
    /// The wallet is locked.
    #[error("Wallet is locked.")]
    WalletLocked(String),

    /// A profile folder or metadata could not be found.
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    /// A profile already exists.
    #[error("Profile already exists: {0}")]
    ProfileAlreadyExists(String),

    /// An active session has expired.
    #[error("Session expired.")]
    SessionExpired(String),

    /// No session is currently active.
    #[error("Session not active: {0}")]
    SessionNotActive(String),

    /// Validation error for vouchers, transactions, or standard definitions.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Underlying storage or file system errors.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Cryptographic operation failures (e.g. decryption, verification).
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// A voucher was not found in the wallet.
    #[error("Voucher not found: {0}")]
    VoucherNotFound(String),

    /// The voucher is not in an active state.
    #[error("Voucher not active: {0}")]
    VoucherNotActive(String),

    /// A double-spend attempt was detected and blocked.
    #[error("Double spend attempt blocked: {0}")]
    DoubleSpendAttemptBlocked(String),

    /// No security seal found, requiring a recovery process.
    #[error("Security recovery required: {0}")]
    RequiresSealRecovery(String),

    /// A rollback or state manipulation was detected.
    #[error("State rollback detected: {0}")]
    StateRollbackDetected(String),

    /// A multi-device sync conflict / seal fork was detected.
    #[error("Seal fork detected: {0}")]
    SealForkDetected(String),

    /// The wallet was persistently locked due to a fork detection.
    #[error("Wallet locked due to fork: {0}")]
    WalletLockedDueToFork(String),

    /// A race condition occurred during seal synchronization.
    #[error("Sync race condition: {0}")]
    SealSyncRaceCondition(String),

    /// JSON serialization or deserialization failed.
    #[error("JSON processing error: {0}")]
    JsonError(String),

    /// A generic or unspecified error.
    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<VoucherCoreError> for AppFacadeError {
    fn from(err: VoucherCoreError) -> Self {
        match err {
            VoucherCoreError::WalletLocked => AppFacadeError::WalletLocked("Wallet is locked.".to_string()),
            VoucherCoreError::VoucherNotFound(id) => AppFacadeError::VoucherNotFound(id),
            VoucherCoreError::VoucherNotActive(status) => AppFacadeError::VoucherNotActive(format!("Action requires an active voucher, but its status is {:?}", status)),
            VoucherCoreError::DoubleSpendAttemptBlocked { local_instance_id } => {
                AppFacadeError::DoubleSpendAttemptBlocked(local_instance_id)
            }
            VoucherCoreError::RequiresSealRecovery => AppFacadeError::RequiresSealRecovery("Security Alert: No local security seal found. Recovery is required to re-anchor the wallet.".to_string()),
            VoucherCoreError::StateRollbackDetected => AppFacadeError::StateRollbackDetected("Critical Error: Wallet state manipulation or outdated backup detected. The local transaction data does not match the security seal.".to_string()),
            VoucherCoreError::SealForkDetected => AppFacadeError::SealForkDetected("Sync Conflict: The hash chain of the remote seal does not align with the local seal, indicating a multi-device fork.".to_string()),
            VoucherCoreError::WalletLockedDueToFork => AppFacadeError::WalletLockedDueToFork("Security Lockdown: Wallet is locked due to a detected fork in the transaction history. Recovery required.".to_string()),
            VoucherCoreError::SealSyncRaceCondition => AppFacadeError::SealSyncRaceCondition("Seal sync race condition: A new transaction occurred during the upload. The acknowledgement is outdated.".to_string()),
            VoucherCoreError::Validation(e) => AppFacadeError::ValidationError(e.to_string()),
            VoucherCoreError::ValidationFailed(e) => AppFacadeError::ValidationError(e),
            VoucherCoreError::Storage(e) => AppFacadeError::StorageError(e.to_string()),
            VoucherCoreError::Json(e) => AppFacadeError::JsonError(e.to_string()),
            other => AppFacadeError::Generic(other.to_string()),
        }
    }
}

impl From<StorageError> for AppFacadeError {
    fn from(err: StorageError) -> Self {
        AppFacadeError::StorageError(err.to_string())
    }
}

impl From<ValidationError> for AppFacadeError {
    fn from(err: ValidationError) -> Self {
        AppFacadeError::ValidationError(err.to_string())
    }
}

impl From<StandardDefinitionError> for AppFacadeError {
    fn from(err: StandardDefinitionError) -> Self {
        AppFacadeError::ValidationError(err.to_string())
    }
}

impl From<String> for AppFacadeError {
    fn from(err: String) -> Self {
        if err.contains("Wallet is locked.") {
            AppFacadeError::WalletLocked(err)
        } else if err.contains("Profile directory not found") || err.contains("Profile not found") {
            AppFacadeError::ProfileNotFound(err)
        } else if err.contains("Session expired") {
            AppFacadeError::SessionExpired(err)
        } else if err.contains("Session not active") || err.contains("Password required") {
            AppFacadeError::SessionNotActive(err)
        } else {
            AppFacadeError::Generic(err)
        }
    }
}

impl From<&str> for AppFacadeError {
    fn from(err: &str) -> Self {
        AppFacadeError::from(err.to_string())
    }
}

impl From<std::io::Error> for AppFacadeError {
    fn from(err: std::io::Error) -> Self {
        AppFacadeError::StorageError(err.to_string())
    }
}

impl From<serde_json::Error> for AppFacadeError {
    fn from(err: serde_json::Error) -> Self {
        AppFacadeError::JsonError(err.to_string())
    }
}
