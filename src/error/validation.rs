//! # src/error/validation.rs
//!
//! Validation and standard-definition errors.
//! Extracted from `error.rs` (Streamline Phase 3) to isolate
//! schema and cryptographic validation concerns.

use crate::services::crypto::GetPubkeyError;
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

    // --- Phase 4: Typed transaction / chain errors (replacing InvalidTransaction(String) ad-hoc) ---

    /// Init transaction must always have a sender_id (creator).
    #[error("Init transaction must always have a sender_id (creator).")]
    MissingInitSenderId,

    /// Transaction has recipient_id with leading/trailing whitespace (obfuscation attempt).
    #[error("Transaction {t_id} has recipient_id with leading/trailing whitespace (obfuscation attempt).")]
    RecipientWhitespace { t_id: String },

    /// Transaction has non-DID recipient in public mode.
    #[error("Transaction {t_id} has non-DID recipient in 'public' mode.")]
    NonDidRecipientInPublicMode { t_id: String },

    /// Transaction list is empty.
    #[error("Transaction list is empty.")]
    EmptyTransactionList,

    /// Invalid voucher_nonce format.
    #[error("Invalid voucher_nonce format")]
    InvalidVoucherNonceFormat,

    /// Invalid voucher_id format.
    #[error("Invalid voucher_id format")]
    InvalidVoucherIdFormat,

    /// Initial transaction has invalid prev_hash.
    #[error("Initial transaction has invalid prev_hash.")]
    InvalidInitialPrevHash,

    /// Initial (init) transaction must not contain non-trivial trap_data.
    #[error("Initial ('init') transaction must not contain non-trivial trap_data.")]
    NonTrivialTrapInInit,

    /// Transaction chain broken: prev_hash does not match hash of previous transaction.
    #[error("Transaction chain broken: prev_hash does not match hash of previous transaction.")]
    BrokenTransactionChain,

    /// P2PKH chain broken: sender_ephemeral_pub does not match any previous anchor.
    #[error("P2PKH chain broken: sender_ephemeral_pub does not match any previous anchor.")]
    BrokenP2pkhChain,

    /// A transfer transaction must not have a sender_remaining_amount.
    #[error("A 'transfer' transaction must not have a sender_remaining_amount.")]
    TransferWithRemainingAmount,

    /// Split transaction must commit DISTINCT anchors for the receiver and change outputs.
    #[error("Split transaction must commit DISTINCT anchors for the receiver and change outputs (anchor overlap detected).")]
    SplitAnchorOverlap,

    /// Split transaction must have a sender_remaining_amount.
    #[error("Split transaction must have a sender_remaining_amount.")]
    SplitMissingRemainingAmount,

    /// Impossible split: sent amount plus remaining amount overflows max representable value.
    #[error("Impossible split: sent amount ({sent}) plus remaining amount ({remaining}) overflows the maximum representable value.")]
    SplitAmountOverflow { sent: String, remaining: String },

    /// Invalid split balance: previous balance does not equal sent + remaining.
    #[error("Invalid split balance: previous balance ({previous}) does not equal sent amount ({sent}) + remaining amount ({remaining}).")]
    InvalidSplitBalance {
        previous: String,
        sent: String,
        remaining: String,
    },

    /// First transaction must be of type init.
    #[error("First transaction must be of type 'init'.")]
    FirstTransactionNotInit,

    /// Found subsequent transaction with invalid type init.
    #[error("Found subsequent transaction with invalid type 'init'.")]
    SubsequentInitTransaction,

    /// Sender and recipient cannot be the same in a non-init transaction.
    #[error("Sender and recipient cannot be the same in a non-init transaction.")]
    SenderEqualsRecipient,

    /// Transaction of type split must have a sender_remaining_amount.
    #[error("Transaction of type 'split' must have a sender_remaining_amount.")]
    SplitRequiresRemainingAmount,

    /// Transaction of type transfer must not have a sender_remaining_amount.
    #[error("Transaction of type 'transfer' must not have a sender_remaining_amount.")]
    TransferForbidsRemainingAmount,

    /// Unknown transaction type.
    #[error("Unknown transaction type: {t_type}")]
    UnknownTransactionType { t_type: String },

    /// Missing trap_data for non-init transaction.
    #[error("Missing trap_data for non-init transaction")]
    MissingTrapDataForNonInit,

    /// Invalid layer2_signature (Technical Proof).
    #[error("Invalid layer2_signature (Technical Proof)")]
    InvalidLayer2Signature,

    /// Missing sender_ephemeral_pub for L2 signature.
    #[error("Missing sender_ephemeral_pub for L2 signature")]
    MissingSenderEphemeralPubForL2,

    /// Missing layer2_signature.
    #[error("Missing layer2_signature")]
    MissingLayer2Signature,

    /// Missing sender_identity_signature for public sender.
    #[error("Missing sender_identity_signature for public sender")]
    MissingSenderIdentitySignature,

    /// Invalid sender_identity_signature.
    #[error("Invalid sender_identity_signature")]
    InvalidSenderIdentitySignature,

    /// Voucher has no transactions.
    #[error("Voucher has no transactions")]
    VoucherHasNoTransactions,

    /// Received voucher has no transactions.
    #[error("Received voucher has no transactions.")]
    ReceivedVoucherHasNoTransactions,

    /// Voucher must have at least one (init) transaction.
    #[error("Voucher must have at least one (init) transaction.")]
    VoucherMustHaveInitTransaction,

    /// Payment rejected: transaction carries an SST trap shard but no privacy guard (R5).
    #[error("Payment rejected: transaction carries an SST trap shard but no privacy guard with the private witness (R5 fail-closed handover enforcement).")]
    TrapWithoutPrivacyGuard,

    /// Payment rejected: transaction carries a trap shard but private SST witness is incomplete.
    #[error("Payment rejected: transaction carries a trap shard but the private SST witness (trap_r_sig/trap_s_sig/trap_m_r/trap_m_s) is incomplete.")]
    IncompleteSstWitness,

    /// Payment rejected: missing sender_ephemeral_pub for SST witness check.
    #[error("Payment rejected: missing sender_ephemeral_pub for SST witness check.")]
    MissingSenderEphemeralPubForSst,

    /// Payment rejected: invalid sender_ephemeral_pub encoding.
    #[error("Payment rejected: invalid sender_ephemeral_pub encoding.")]
    InvalidSenderEphemeralPubEncoding,

    /// Payment rejected: sender_ephemeral_pub must be 32 bytes.
    #[error("Payment rejected: sender_ephemeral_pub must be 32 bytes.")]
    SenderEphemeralPubWrongLength,

    /// Payment rejected: SST trap witness verification failed.
    #[error("Payment rejected: SST trap witness verification failed ({reason}).")]
    SstWitnessVerificationFailed { reason: String },

    // --- Phase 4: Typed L2 gateway errors (replacing Error::ValidationFailed ad-hoc) ---

    /// Invalid server public key.
    #[error("Invalid server public key")]
    InvalidServerPublicKey,

    /// Server signature is invalid (authenticity failed).
    #[error("Server-Signatur ist ungültig (Authentizität fehlgeschlagen)")]
    ServerSignatureInvalid,

    /// Voucher ID mix-up: L2 server reports proof for a different voucher.
    #[error("Voucher ID Mix-up erkannt: L2-Server meldet Beweis für einen anderen Gutschein ({found} != {expected})")]
    VoucherIdMixup { found: String, expected: String },

    /// Invalid ephemeral key in lock entry.
    #[error("Invalid ephemeral key in lock entry")]
    InvalidEphemeralKeyInLockEntry,

    /// Cryptographic proof of L2 server is invalid.
    #[error("Kryptografischer Beweis des L2-Servers ist ungültig")]
    InvalidL2Proof,

    /// Foreign key proof: L2 server reports double-spend with foreign key.
    #[error("Gefälschter Beweis erkannt: L2-Server meldet Double-Spend mit einem fremden Key ({actual} != {expected})")]
    ForeignKeyProof { actual: String, expected: String },

    /// L2 server rejected request.
    #[error("L2 server rejected request: {reason}")]
    L2Rejected { reason: String },
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
