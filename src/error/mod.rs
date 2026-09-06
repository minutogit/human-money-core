//! # `src/error/mod.rs`
//!
//! Central error taxonomy for `human_money_core`.
//! Streamline Phase 3 splits the former monolithic `error.rs` into
//! `validation.rs`, `storage.rs`, `wallet.rs` and `app.rs` submodules.
//! The public facade `crate::Error` (alias `VoucherCoreError` / `AppFacadeError`)
//! retains `#[serde(tag = "type", content = "payload", rename_all = "camelCase")]`
//! so WASM / JS clients keep wire compatibility. Sub-errors are bound via
//! `#[from]` / `#[source]` for ergonomic `?` propagation.

pub mod app;
pub mod storage;
pub mod validation;
pub mod wallet;

pub use app::AppError;
pub use storage::StorageError;
pub use validation::{StandardDefinitionError, ValidationError};
pub use wallet::WalletError;

use crate::services::crypto::{GetPubkeyError, SymmetricEncryptionError};
use crate::wallet::instance::VoucherStatus;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The central error type for all operations in the `human_money_core` library.
#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum Error {
    // --- Validation & Verification Errors (bound via #[from]) ---

    /// Error wrapper for schema and logic validation errors.
    #[error("Validation Error: {0}")]
    Validation(#[from] ValidationError),

    /// Standard definition validation or loading error.
    #[error("Standard Definition Error: {0}")]
    Standard(#[from] StandardDefinitionError),

    /// Underlying storage (file system, database) error.
    #[error("Storage Error: {0}")]
    Storage(#[from] StorageError),

    /// Wallet-domain typed errors (replaces former `Generic` strings).
    #[error("Wallet Error: {0}")]
    Wallet(#[from] WalletError),

    /// App-service typed errors (replaces former `Generic` strings).
    #[error("App Error: {0}")]
    App(#[from] AppError),

    /// Symmetric encryption or decryption (e.g. ChaCha20) failed.
    #[error("Symmetric Encryption Error: {0}")]
    SymmetricEncryption(#[from] SymmetricEncryptionError),

    // --- Flat legacy variants kept for wire compatibility ---
    // (Generic / VoucherManagerGeneric are retained for deserialization of
    //  historical payloads but are no longer constructed in `src/`.)

    /// General validation failure wrapper.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// Cryptographic signature metadata mismatch.
    #[error("Mismatched signature data: {0}")]
    MismatchedSignatureData(String),

    /// The hash format of a given string is invalid.
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    // --- Transaction & Bundle Lifecycle Errors ---

    /// The transaction bundle has already been processed and rejected previously.
    #[error("Bundle has already been processed and was rejected. Bundle ID: {bundle_id}")]
    BundleAlreadyProcessed { bundle_id: String },

    /// The transaction fingerprint is already registered, indicating a potential replay attack.
    #[error(
        "Transaction fingerprint is already known, indicating a potential replay attack. Fingerprint Hash: {fingerprint_hash}"
    )]
    TransactionFingerprintAlreadyKnown { fingerprint_hash: String },

    /// The transaction bundle was sent to this wallet but is intended for another recipient.
    #[error(
        "Bundle Recipient Mismatch: This bundle was not intended for this wallet. Expected recipient: {expected}, but last transaction was for: {found}"
    )]
    BundleRecipientMismatch { expected: String, found: String },

    /// An offline double-spend attempt was detected and blocked.
    #[error(
        "Double spend attempt blocked for voucher {local_instance_id}: A transaction has already been issued from this voucher state."
    )]
    DoubleSpendAttemptBlocked { local_instance_id: String },

    /// The transaction is missing the required identity trap data.
    #[error("Missing trap data in transaction")]
    MissingTrapData,

    /// Error deserializing transaction or protocol payload.
    #[error("L2 Payload Deserialization Error: {0}")]
    DeserializationError(String),

    // --- Voucher Lifecycle Errors ---

    /// The voucher is quarantined and cannot be transferred or used due to conflicts.
    #[error("Action aborted: The voucher is quarantined due to a detected double-spend conflict.")]
    VoucherInQuarantine,

    /// The requested voucher instance is not present in local storage.
    #[error("Voucher with local instance ID '{0}' not found in wallet. It may have been fully spent, deleted, or transferred.")]
    VoucherNotFound(String),

    /// The operation requires an active voucher, but the voucher status is not active.
    #[error("Action requires an active voucher, but its status is {0:?}.")]
    VoucherNotActive(VoucherStatus),

    /// Verification of the wallet's ownership of the voucher failed.
    #[error("Ownership validation failed: {0}")]
    VoucherOwnershipNotFound(String),

    /// The operation can only be performed by the creator of the voucher.
    #[error("Only the creator of the voucher can remove signatures.")]
    NotTheCreator,

    /// Signatures cannot be removed because the voucher has already been spent or circulated.
    #[error("Cannot remove signatures from a voucher that is already in circulation (has more than one transaction).")]
    VoucherAlreadyInCirculation,

    /// The creator's signature is mandatory and cannot be removed.
    #[error("Cannot remove the creator's signature from a voucher.")]
    CannotRemoveCreatorSignature,

    /// Signatures can only be removed while the voucher is in draft/incomplete status.
    #[error("Signatures can only be removed while the voucher is in status 'Incomplete'. Current status: {0:?}")]
    SignatureRemovalRequiresIncomplete(VoucherStatus),

    /// The voucher is locked until the specified timestamp.
    #[error("Voucher is locked until '{until}'. Current time: '{now}'. Remaining wait: {wait_duration}.")]
    VoucherLockedUntil {
        until: String,
        now: String,
        wait_duration: String,
    },

    // --- Security Seal & Rollback Guard Errors ---

    /// The local security seal (seal.json) is missing. Normal startup and transactions
    /// are not allowed. The user must start the recovery flow.
    #[error("Security Alert: No local security seal found. Recovery is required to re-anchor the wallet.")]
    RequiresSealRecovery,

    /// The state_hash in the seal does not match the loaded OwnFingerprints store.
    /// Local storage was tampered with, corrupted, or reset via an old backup.
    #[error("Critical Error: Wallet state manipulation or outdated backup detected. The local transaction data does not match the security seal.")]
    StateRollbackDetected,

    /// The hash chain of the remote seal does not match the local seal,
    /// indicating a serious multi-device conflict.
    #[error("Sync Conflict: The hash chain of the remote seal does not align with the local seal, indicating a multi-device fork.")]
    SealForkDetected,

    /// A fork was detected and the wallet is now persistently locked.
    /// No transactions can be received or sent.
    /// Only `recover_wallet_and_set_new_password` can lift this lock.
    #[error("Security Lockdown: Wallet is locked due to a detected fork in the transaction history. Recovery required.")]
    WalletLockedDueToFork,

    /// Zone 2: Bundle timestamp is 5 minutes to 24 hours before the epoch_start_time.
    /// Potential double-spend trap. Requires explicit user confirmation.
    #[error("Warning: This transaction occurred shortly before the recent wallet recovery. Confirm with force_accept_tolerance_bundle.")]
    BundleInRecoveryToleranceZone,

    /// Zone 3: Bundle timestamp is 24 hours to 28 days before the epoch_start_time.
    /// High risk of serious double-spending. Requires critical user confirmation.
    #[error("CRITICAL WARNING: This transaction is up to 4 weeks old relative to the last recovery. High double-spend risk.")]
    BundleInExtendedRecoveryToleranceZone,

    /// Zone 4: Bundle timestamp is older than 28 days before the epoch_start_time.
    /// Hard rejection. No bypass possible.
    #[error("Transaction Rejected: This transaction is too old relative to the last wallet recovery date. Permanently rejected.")]
    BundlePredatesCurrentEpoch,

    /// Race condition protection: The acknowledge_seal_sync was called with a hash
    /// that no longer matches the latest local seal (new transaction during upload).
    #[error("Seal sync race condition: A new transaction occurred during the upload. The acknowledgement is outdated.")]
    SealSyncRaceCondition,

    // --- Cryptographic & Key Errors ---

    /// Failed to retrieve or parse a public key from a user identity.
    #[error("User ID or Key Error: {0}")]
    KeyOrId(String),

    /// General cryptographic error.
    #[error("Cryptography error: {0}")]
    Crypto(String),

    /// Trap derivation failed or produced invalid scalar parameters.
    #[error("Invalid trap derivation: {0}")]
    InvalidTrapDerivation(String),

    /// Base58 encoding/decoding failed.
    #[error("Base58 decode error: {0}")]
    Bs58Decode(String),

    /// Base64 encoding/decoding failed.
    #[error("Base64 decode error: {0}")]
    Base64(String),

    /// Underlying Ed25519 signature algorithm error.
    #[error("Ed25519 crypto error: {0}")]
    Ed25519(String),

    // --- Secure Container Errors ---

    /// The current user is not in the list of recipients for this container.
    #[error("The current user is not in the list of recipients for this container.")]
    NotAnIntendedRecipient,

    /// Key derivation for container key encryption failed.
    #[error("Failed to derive key for key encryption: {0}")]
    KeyDerivationError(String),

    /// Security violation: Plaintext encryption is not allowed for financial payloads.
    #[error("Security violation: Plaintext encryption is not allowed for financial payloads (TransactionBundle).")]
    PlaintextNotAllowedForFinancialPayload,

    /// Password required for symmetric encryption.
    #[error("Password required for symmetric encryption.")]
    PasswordRequired,

    /// Invalid encryption configuration.
    #[error("Invalid encryption configuration.")]
    InvalidEncryptionConfig,

    // --- Voucher Manager / Business Logic Errors (flattened) ---

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

    /// The voucher does not allow partial transfers according to its standard.
    #[error("Voucher does not allow partial transfers according to its standard.")]
    VoucherPartialTransferNotAllowed,

    /// Generic voucher manager error (retained for wire compat, no longer constructed).
    #[error("Voucher Manager Error: {0}")]
    VoucherManagerGeneric(String),

    // --- Session & Profile Errors (flattened from AppService layer) ---

    /// The requested profile folder or metadata could not be found.
    #[error("Profile not found: {0}")]
    ProfileNotFound(String),

    /// A profile already exists.
    #[error("Profile already exists: {0}")]
    ProfileAlreadyExists(String),

    /// An active session has expired.
    #[error("{0}")]
    SessionExpired(String),

    /// No session is currently active.
    #[error("Session not active: {0}")]
    SessionNotActive(String),

    // --- System Errors ---

    /// JSON serialization/deserialization error.
    #[error("JSON Processing Error: {0}")]
    Json(String),

    /// TOML parsing or serialization error.
    #[error("TOML Deserialization Error: {0}")]
    Toml(String),

    /// Decimal number processing or parsing error.
    #[error("Amount Conversion Error: {0}")]
    AmountConversion(String),

    /// System I/O error.
    #[error("I/O error: {0}")]
    Io(String),

    /// Generic error string for unclassified conditions (retained for wire compat).
    #[error("Generic error: {0}")]
    Generic(String),

    /// Payload type inside the secure container is invalid or unrecognized.
    #[error("Invalid payload type in secure container.")]
    InvalidPayloadType,

    /// The wallet is currently locked, preventing state changes.
    #[error("Wallet is locked.")]
    WalletLocked,

    /// The requested feature is not implemented.
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),

    // --- Fingerprint & Proof specific typed errors (reduce Generic usage) ---

    /// Fingerprint creation or verification failed.
    #[error("Fingerprint error: {0}")]
    Fingerprint(String),

    /// Proof import or verification failed.
    #[error("Proof import error: {0}")]
    ProofImport(String),

    /// Timestamp parsing or validation failed.
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(String),
}

/// Backward compatibility alias for the central error type.
pub type VoucherCoreError = Error;

/// Backward compatibility alias for the AppService facade error type.
pub type AppFacadeError = Error;

impl From<GetPubkeyError> for Error {
    fn from(err: GetPubkeyError) -> Self {
        Error::KeyOrId(err.to_string())
    }
}

impl From<bs58::decode::Error> for Error {
    fn from(err: bs58::decode::Error) -> Self {
        Error::Bs58Decode(err.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        Error::Ed25519(err.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::Toml(err.to_string())
    }
}

impl From<rust_decimal::Error> for Error {
    fn from(err: rust_decimal::Error) -> Self {
        Error::AmountConversion(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Error::Base64(err.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::DeserializationError(err.to_string())
    }
}
