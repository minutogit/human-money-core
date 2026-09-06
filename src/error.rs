//! # `src/error.rs`
//!
//! Defines the central error type for the entire `human_money_core` library.
//! Uses `thiserror` for easy creation of meaningful errors
//! and automatic conversion of subordinate error types.

use crate::wallet::instance::VoucherStatus;
use crate::{
    services::crypto::{GetPubkeyError, SymmetricEncryptionError},
    storage::StorageError,
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Defines errors that can occur during the processing of a `VoucherStandardDefinition`.
#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum StandardDefinitionError {
    /// The `[signature]` block is missing from the definition.
    #[error("The [signature] block is missing from the standard definition.")]
    MissingSignatureBlock,
    /// The cryptographic signature of the standard definition is invalid.
    #[error("The signature of the standard definition is invalid.")]
    InvalidSignature,
    /// The standard definition hash in the voucher does not match the hash of the loaded standard.
    #[error("The standard definition hash in the voucher does not match the loaded standard.")]
    StandardHashMismatch,
    /// Error during signature decoding (e.g. Base58).
    #[error("Failed to decode signature: {0}")]
    SignatureDecode(String),
    /// The specified privacy mode in the standard is invalid.
    #[error("Invalid privacy mode: {0}")]
    InvalidMode(String),
    /// SECURITY (AUDIT-W4-CEL-102): the definition is self-consistently
    /// signed, but its issuer identity does not match the caller's pinned
    /// issuer for this standard uuid (trust-on-first-use violation — the
    /// file was re-signed under a foreign key after installation).
    #[error("The standard definition was re-signed by a different issuer than the pinned one (issuer pin violation).")]
    IssuerPinViolation,
}

/// Defines the various errors that can occur during validation.
/// These errors are specific to verifying a voucher against its standard.
#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum ValidationError {
    // --- Data-driven validation errors ---
    /// A quantitative rule was violated (e.g. too many or too few signatures).
    #[error(
        "Count for '{field}' is out of bounds. Expected min: {min}, max: {max}, but found: {found}."
    )]
    CountOutOfBounds {
        field: String,
        min: u32,
        max: u32,
        found: usize,
    },

    /// A signature required by the standard is missing or invalid.
    #[error("A required signature is missing for role: '{role}'.")]
    MissingRequiredSignature { role: String },

    /// The value of a field does not match the value defined in the standard.
    #[error("Field '{field}' has a mismatched value. Expected: {expected}, Found: {found}.")]
    FieldValueMismatch {
        field: String,
        expected: serde_json::Value,
        found: serde_json::Value,
    },

    /// The value of a field is not included in the list of allowed values.
    #[error(
        "Field '{field}' has a value that is not in the allowed list. Found: {found}, Allowed: {allowed:?}."
    )]
    FieldValueNotAllowed {
        field: String,
        found: serde_json::Value,
        allowed: Vec<serde_json::Value>,
    },

    /// The value of a field does not match the required regex pattern.
    #[error(
        "Field '{field}' does not match the required pattern '{pattern}'. Found value: '{found}'."
    )]
    FieldRegexMismatch {
        field: String,
        pattern: String,
        found: String,
    },

    /// The transaction type (`t_type`) is not permitted according to the standard.
    #[error("Transaction type '{t_type}' is not allowed. Allowed types are: {allowed:?}.")]
    TransactionTypeNotAllowed {
        t_type: String,
        allowed: Vec<String>,
    },

    /// A value under a path had an unexpected data type.
    #[error("Invalid data type at path '{path}', expected {expected}")]
    InvalidDataType { path: String, expected: String },

    /// A field value in a group of objects did not occur with the expected frequency (min/max).
    #[error(
        "Field group validation failed for field '{field}' at path '{path}': Expected value '{value}' to appear between {min} and {max} times, but found {found}."
    )]
    FieldValueCountOutOfBounds {
        path: String,
        field: String,
        value: String,
        min: u32,
        max: u32,
        found: u32,
    },

    /// An attempt was made to split a non-divisible voucher.
    #[error("The voucher is not divisible and a split transaction was attempted.")]
    VoucherPartialTransferNotAllowed,

    /// The voucher's validity duration exceeds the maximum duration defined in the standard.
    #[error(
        "Voucher validity duration exceeds the maximum allowed. Max allowed: '{max_allowed}', Found: '{found}'."
    )]
    ValidityDurationExceeded { max_allowed: String, found: String },

    /// A JSON path could not be found in the voucher object.
    #[error("Content rule failed: Path '{path}' could not be resolved in the voucher.")]
    PathNotFound { path: String },

    /// A dynamic CEL rule was violated.
    #[error("Business rule violated: {0}")]
    BusinessRuleViolated(String),

    // --- Logical & cryptographic validation errors ---
    /// The UUID of the standard in the voucher does not match the UUID of the validation definition.
    #[error("Voucher standard UUID mismatch. Expected: {expected}, Found: {found}")]
    StandardUuidMismatch { expected: String, found: String },

    /// The creator's signature is invalid.
    #[error("Creator signature is invalid for creator {creator_id} and data hash {data_hash}")]
    InvalidCreatorSignature {
        creator_id: String,
        data_hash: String,
    },

    /// The creator's User ID is invalid or the public key cannot be extracted.
    #[error("Invalid creator ID: {0}")]
    InvalidCreatorId(String),

    /// Private Mode: An identity signature was found even though the mode mandates anonymity.
    #[error(
        "Privacy Leak: Transaction '{t_id}' contains a sender_identity_signature in private mode."
    )]
    PrivateSignatureLeak { t_id: String },

    /// Privacy Mode: The standard's privacy mode was violated (identity disclosure).
    #[error("Privacy Mode Violation in transaction '{t_id}': {reason}")]
    PrivacyModeViolation { t_id: String, reason: String },

    /// Flexible Mode: An identity signature is present, but the sender_id is missing (inconsistency).
    #[error(
        "Data Hygiene: Transaction '{t_id}' contains a signature but no sender_id in flexible mode."
    )]
    FlexibleModeIdentityInconsistency { t_id: String },

    /// Trap Data: The blinded_id (trap) has an invalid format or contains suspicious data.
    #[error("Trap Integrity: Transaction '{t_id}' has invalid or suspicious blinded_id format.")]
    TrapDataInvalid { t_id: String },

    /// The sender declared in the privacy_guard does not match the bundle sender.
    #[error("Privacy Guard Integrity: Declared sender '{declared}' does not match bundle signer '{actual}'.")]
    MismatchedPrivacySenderId { declared: String, actual: String },

    /// The privacy_guard could not be decrypted or parsed.
    #[error("Privacy Guard decryption or parsing failed: {0}")]
    PrivacyGuardDecryptionFailed(String),

    /// The voucher_id in a signature does not match the voucher's voucher_id.
    #[error("Signature references wrong voucher. Expected ID: {expected}, Found ID: {found}")]
    MismatchedVoucherIdInSignature { expected: String, found: String },

    /// The signature ID is invalid, suggesting tampered signature metadata.
    #[error("The signature ID {0} is invalid or data was tampered with")]
    InvalidSignatureId(String),

    /// A signature is cryptographically invalid.
    #[error("Invalid signature for signer {signer_id}")]
    InvalidSignature { signer_id: String },

    /// The transaction chain is invalid (e.g. incorrect prev_hash or signature).
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// The `voucher_id` (hash of master data) does not match the master data.
    #[error(
        "Voucher hash mismatch: The voucher's data hash (voucher_id) does not match its content."
    )]
    InvalidVoucherHash,

    /// A transaction signature is invalid.
    #[error("Invalid signature for transaction '{t_id}' from sender '{sender_id}'")]
    InvalidTransactionSignature { t_id: String, sender_id: String },

    /// A TransactionBundle signature is invalid.
    #[error("The signature of the transaction bundle is invalid.")]
    InvalidBundleSignature,

    /// The digital signature of the SecureContainer is invalid.
    #[error("The digital signature of the secure container is invalid.")]
    InvalidContainerSignature,

    /// Error during signature decoding (e.g. Base58).
    #[error("Failed to decode signature: {0}")]
    SignatureDecodeError(String),

    /// The amount has more decimal places than permitted by the standard.
    #[error("Invalid amount precision. Allowed up to {allowed} decimal places, but found {found}")]
    TooManyDecimalPlaces { allowed: u32, found: u32 },

    /// The amount of the `init` transaction does not match the nominal value of the voucher.
    #[error(
        "Initial transaction amount must match nominal value. Expected: {expected}, Found: {found}"
    )]
    InitAmountMismatch { expected: String, found: String },

    // --- New validation errors from 'test_advanced_validation' ---
    /// The validity date is before the creation date.
    #[error(
        "Invalid date logic: valid_until ('{valid_until}') cannot be before creation_date ('{creation}')."
    )]
    InvalidDateLogic {
        creation: String,
        valid_until: String,
    },

    /// A signer attempted to sign multiple times for the same role.
    #[error("Duplicate signature found for signer: {signer_id}. A signer can only sign once per role.")]
    DuplicateSignature { signer_id: String },

    /// An identity (public key) was used multiple times as creator or signer, even if the ID differs.
    #[error("Duplicate identity detected for signer: {signer_id}. The underlying cryptographic key is already in use for this voucher.")]
    DuplicateIdentityDetected { signer_id: String },

    /// A timestamp in the chain is not chronologically correct.
    #[error(
        "Invalid time order for {entity} '{id}': timestamp '{time2}' is not after previous timestamp '{time1}'."
    )]
    InvalidTimeOrder {
        entity: String,
        id: String,
        time1: String,
        time2: String,
    },

    /// The sender or recipient of the 'init' transaction is not the creator of the voucher.
    #[error("Initial transaction party mismatch: expected '{expected}', found '{found}'.")]
    InitPartyMismatch { expected: String, found: String },

    /// The t_id of a transaction does not match the hash of its content.
    #[error(
        "Transaction ID mismatch for transaction '{t_id}'. The content may have been tampered with."
    )]
    MismatchedTransactionId { t_id: String },

    /// The divisibility property of the voucher does not match that of the standard.
    #[error(
        "Divisibility mismatch: voucher is '{from_voucher}' but standard requires '{from_standard}'."
    )]
    IncorrectDivisibility {
        from_voucher: bool,
        from_standard: bool,
    },

    /// An amount in a transaction is negative or zero.
    #[error("Transaction amount must be positive, but found '{amount}'.")]
    NegativeOrZeroAmount { amount: String },

    /// In a full transfer, the transaction amount does not match the sender's balance.
    #[error(
        "Full transfer amount mismatch: Sender's balance is '{expected}', but transaction amount is '{found}'."
    )]
    FullTransferAmountMismatch { expected: String, found: String },

    /// Insufficient funds were detected during the transaction chain verification.
    #[error(
        "Insufficient funds found in transaction chain for user '{user_id}'. Needed: {needed}, Available: {available}"
    )]
    InsufficientFundsInChain {
        user_id: String,
        needed: String,
        available: String,
    },

    /// The voucher's validity duration is shorter than required by the standard.
    #[error(
        "The voucher's effective validity duration is shorter than the minimum required by the standard."
    )]
    ValidityDurationTooShort,

    /// The nominal value unit in the voucher does not match the standard definition.
    #[error("Nominal unit mismatch. Expected: '{expected}', Found: '{found}'.")]
    NominalUnitMismatch { expected: String, found: String },

    /// The voucher's validity duration exceeds the maximum allowed by the standard.
    #[error("Voucher validity duration is too long. Maximum allowed is {max_allowed}.")]
    ValidityDurationTooLong { max_allowed: String },

    /// An amount string could not be parsed into a valid Decimal number.
    #[error("Failed to parse amount string at path '{path}': Found '{found}'.")]
    InvalidAmountFormat { path: String, found: String },

    /// An amount field has more decimal places than the standard allows.
    #[error(
        "Invalid amount precision at path '{path}'. Standard allows max {max_places} decimal places, but found {found}."
    )]
    InvalidAmountPrecision {
        path: String,
        max_places: u8,
        found: u32,
    },

    /// The creator of the voucher is also listed as an additional signer.
    #[error("The creator of the voucher ('{creator_id}') cannot also be an additional signer.")]
    CreatorAsAdditionalSigner { creator_id: String },

    /// JSON parsing error within validation context
    #[error("JSON validation error: {0}")]
    Json(String),

    /// A timestamp is too far in the future.
    #[error("Rejection: {entity} '{id}' has a timestamp '{timestamp}' that is too far in the future (Limit: {limit}). Please wait {wait_duration} before importing.")]
    FutureTimestampRejected {
        entity: String,
        id: String,
        timestamp: String,
        limit: String,
        wait_duration: String,
    },

    /// The voucher uses a name (currency or standard) that simulates test money, even though it is declared as real money.
    #[error("Anti-Spoofing: Genuine voucher uses deceptive 'TEST' prefix in currency or standard name: {reason}")]
    DeceptiveNaming { reason: String },

    // --- User ID & Identity validation errors ---
    /// The prefix is too long (maximum 63 characters allowed).
    #[error("Prefix is too long: {0} characters (maximum is 63).")]
    PrefixTooLong(usize),

    /// The prefix contains invalid characters.
    #[error("Prefix contains invalid characters. Only lowercase letters (a-z), numbers (0-9), and hyphens (-) are allowed.")]
    InvalidPrefixChars,

    /// The prefix must not start or end with a hyphen.
    #[error("Prefix must not start or end with a hyphen.")]
    InvalidPrefixStartEnd,

    /// The prefix must not contain two consecutive hyphens.
    #[error("Prefix contains consecutive separators (- or :)")]
    PrefixHasConsecutiveSeparators,
}

impl From<GetPubkeyError> for ValidationError {
    fn from(err: GetPubkeyError) -> Self {
        ValidationError::InvalidCreatorId(err.to_string())
    }
}

impl From<serde_json::Error> for ValidationError {
    fn from(err: serde_json::Error) -> Self {
        ValidationError::Json(err.to_string())
    }
}

/// The central error type for all operations in the `human_money_core` library.
#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum Error {
    // --- Validation & Verification Errors ---

    /// Error wrapper for schema and logic validation errors.
    #[error("Validation Error: {0}")]
    Validation(#[from] ValidationError),

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

    /// Symmetric encryption or decryption (e.g. ChaCha20) failed.
    #[error("Symmetric Encryption Error: {0}")]
    SymmetricEncryption(#[from] SymmetricEncryptionError),

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

    /// Generic voucher manager error.
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

    /// Underlying storage (file system, database) error.
    #[error("Storage Error: {0}")]
    Storage(#[from] StorageError),

    /// Standard definition validation or loading error.
    #[error("Standard Definition Error: {0}")]
    Standard(#[from] StandardDefinitionError),

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

    /// Generic error string for unclassified conditions.
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

