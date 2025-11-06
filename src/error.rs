//! # src/error.rs
//!
//! Definiert den zentralen Fehlertyp für die gesamte voucher_core-Bibliothek.
//! Verwendet `thiserror` zur einfachen Erstellung von aussagekräftigen Fehlern
//! und zur automatischen Konvertierung von untergeordneten Fehlertypen.

use thiserror::Error;
use crate::{
    services::{
        crypto_utils::{GetPubkeyError, SymmetricEncryptionError},
        secure_container_manager::ContainerManagerError,
        voucher_manager::VoucherManagerError,
    },
    storage::StorageError,
};
use crate::wallet::instance::VoucherStatus;

/// Definiert Fehler, die bei der Verarbeitung einer `VoucherStandardDefinition` auftreten können.
#[derive(Error, Debug)]
pub enum StandardDefinitionError {
    /// Der `[signature]`-Block fehlt in der Definition.
    #[error("The [signature] block is missing from the standard definition.")]
    MissingSignatureBlock,
    /// Die kryptographische Signatur der Standard-Definition ist ungültig.
    #[error("The signature of the standard definition is invalid.")]
    InvalidSignature,
    /// Der Hash des Standards im Gutschein stimmt nicht mit dem Hash des geladenen Standards überein.
    #[error("The standard definition hash in the voucher does not match the loaded standard.")]
    StandardHashMismatch,
    /// Fehler bei der Dekodierung der Signatur (z.B. Base58).
    #[error("Failed to decode signature: {0}")]
    SignatureDecode(String),
}

/// Definiert die verschiedenen Fehler, die während der Validierung auftreten können.
/// Diese Fehler sind spezifisch für die Überprüfung eines Gutscheins gegen seinen Standard.
#[derive(Error, Debug)]
pub enum ValidationError {
    // --- Datengesteuerte Validierungsfehler ---

    /// Eine quantitative Regel wurde verletzt (z.B. zu viele oder zu wenige Signaturen).
    #[error("Count for '{field}' is out of bounds. Expected min: {min}, max: {max}, but found: {found}.")]
    CountOutOfBounds {
        field: String,
        min: u32,
        max: u32,
        found: usize,
    },

    /// Eine im Standard als zwingend erforderliche Signatur fehlt oder ist ungültig.
    #[error("A required signature is missing for role: '{role}'.")]
    MissingRequiredSignature { role: String },

    /// Der Wert eines Feldes entspricht nicht dem im Standard festgeschriebenen Wert.
    #[error("Field '{field}' has a mismatched value. Expected: {expected}, Found: {found}.")]
    FieldValueMismatch {
        field: String,
        expected: serde_json::Value,
        found: serde_json::Value,
    },

    /// Der Wert eines Feldes ist in der Liste der erlaubten Werte nicht enthalten.
    #[error("Field '{field}' has a value that is not in the allowed list. Found: {found}, Allowed: {allowed:?}.")]
    FieldValueNotAllowed {
        field: String,
        found: serde_json::Value,
        allowed: Vec<serde_json::Value>,
    },

    /// Der Wert eines Feldes entspricht nicht dem geforderten Regex-Muster.
    #[error("Field '{field}' does not match the required pattern '{pattern}'. Found value: '{found}'.")]
    FieldRegexMismatch {
        field: String,
        pattern: String,
        found: String,
    },

    /// Der Transaktionstyp (`t_type`) ist laut Standard nicht zulässig.
    #[error("Transaction type '{t_type}' is not allowed. Allowed types are: {allowed:?}.")]
    TransactionTypeNotAllowed {
        t_type: String,
        allowed: Vec<String>,
    },

    /// Ein Wert unter einem Pfad hatte einen unerwarteten Datentyp.
    #[error("Invalid data type at path '{path}', expected {expected}")]
    InvalidDataType {
        path: String,
        expected: String,
    },

    /// Ein Feldwert in einer Gruppe von Objekten kam nicht in der erwarteten Häufigkeit (min/max) vor.
    #[error("Field group validation failed for field '{field}' at path '{path}': Expected value '{value}' to appear between {min} and {max} times, but found {found}.")]
    FieldValueCountOutOfBounds {
        path: String,
        field: String,
        value: String,
        min: u32,
        max: u32,
        found: u32,
    },

    /// Es wurde versucht, einen nicht teilbaren Gutschein zu teilen.
    #[error("The voucher is not divisible and a split transaction was attempted.")]
    VoucherNotDivisible,

    /// Die Gültigkeitsdauer des Gutscheins überschreitet die im Standard definierte Maximaldauer.
    #[error("Voucher validity duration exceeds the maximum allowed. Max allowed: '{max_allowed}', Found: '{found}'.")]
    ValidityDurationExceeded {
        max_allowed: String,
        found: String,
    },

    /// Ein JSON-Pfad konnte im Gutschein-Objekt nicht gefunden werden.
    #[error("Content rule failed: Path '{path}' could not be resolved in the voucher.")]
    PathNotFound { path: String },

    // --- Logische & kryptographische Validierungsfehler ---

    /// Die UUID des Standards im Gutschein stimmt nicht mit der UUID der Validierungsdefinition überein.
    #[error("Voucher standard UUID mismatch. Expected: {expected}, Found: {found}")]
    StandardUuidMismatch { expected: String, found: String },

    /// Die Signatur des Erstellers ist ungültig.
    #[error("Creator signature is invalid for creator {creator_id} and data hash {data_hash}")]
    InvalidCreatorSignature {
        creator_id: String,
        data_hash: String,
    },

    /// Die User ID des Erstellers ist ungültig oder der Public Key kann nicht extrahiert werden.
    #[error("Invalid creator ID: {0}")]
    InvalidCreatorId(#[from] GetPubkeyError),

    /// Die voucher_id in einer Signatur stimmt nicht mit der des Gutscheins überein.
    #[error("Signature references wrong voucher. Expected ID: {expected}, Found ID: {found}")]
    MismatchedVoucherIdInSignature { expected: String, found: String },

    /// Die Signatur-ID ist ungültig, was auf manipulierte Signatur-Metadaten hindeutet.
    #[error("The signature ID {0} is invalid or data was tampered with")]
    InvalidSignatureId(String),

    /// Eine Signatur ist kryptographisch ungültig.
    #[error("Invalid signature for signer {signer_id}")]
    InvalidSignature { signer_id: String },

    /// Die Transaktionskette ist ungültig (z.B. falscher prev_hash oder Signatur).
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Die Signatur einer Transaktion ist ungültig.
    #[error("Invalid signature for transaction '{t_id}' from sender '{sender_id}'")]
    InvalidTransactionSignature { t_id: String, sender_id: String },

    /// Die Signatur eines TransactionBundle ist ungültig.
    #[error("The signature of the transaction bundle is invalid.")]
    InvalidBundleSignature,

    /// Die digitale Signatur des SecureContainers ist ungültig.
    #[error("The digital signature of the secure container is invalid.")]
    InvalidContainerSignature,

    /// Fehler bei der Dekodierung einer Signatur (z.B. Base58).
    #[error("Failed to decode signature: {0}")]
    SignatureDecodeError(String),

    /// Der Betrag hat mehr Nachkommastellen als vom Standard erlaubt.
    #[error("Invalid amount precision. Allowed up to {allowed} decimal places, but found {found}")]
    TooManyDecimalPlaces { allowed: u32, found: u32 },

    /// Der Betrag der `init`-Transaktion stimmt nicht mit dem Nennwert des Gutscheins überein.
    #[error("Initial transaction amount must match nominal value. Expected: {expected}, Found: {found}")]
    InitAmountMismatch { expected: String, found: String },

    // --- Neue Validierungsfehler aus 'test_advanced_validation' ---

    /// Das Gültigkeitsdatum liegt vor dem Erstellungsdatum.
    #[error("Invalid date logic: valid_until ('{valid_until}') cannot be before creation_date ('{creation}').")]
    InvalidDateLogic { creation: String, valid_until: String },

    /// Ein Bürge hat versucht, mehrfach für denselben Gutschein zu bürgen.
    #[error("Duplicate guarantor found: {guarantor_id}. Each guarantor can only sign once.")]
    DuplicateGuarantor { guarantor_id: String },

    /// Ein Zeitstempel in der Kette ist nicht chronologisch korrekt.
    #[error("Invalid time order for {entity} '{id}': timestamp '{time2}' is not after previous timestamp '{time1}'.")]
    InvalidTimeOrder { entity: String, id: String, time1: String, time2: String },

    /// Sender oder Empfänger der 'init'-Transaktion ist nicht der Ersteller des Gutscheins.
    #[error("Initial transaction party mismatch: expected '{expected}', found '{found}'.")]
    InitPartyMismatch { expected: String, found: String },

    /// Die t_id einer Transaktion stimmt nicht mit dem Hash ihres Inhalts überein.
    #[error("Transaction ID mismatch for transaction '{t_id}'. The content may have been tampered with.")]
    MismatchedTransactionId { t_id: String },

    /// Die Teilbarkeitseigenschaft des Gutscheins stimmt nicht mit der des Standards überein.
    #[error("Divisibility mismatch: voucher is '{from_voucher}' but standard requires '{from_standard}'.")]
    IncorrectDivisibility { from_voucher: bool, from_standard: bool },

    /// Ein Betrag in einer Transaktion ist negativ oder null.
    #[error("Transaction amount must be positive, but found '{amount}'.")]
    NegativeOrZeroAmount { amount: String },

    /// Bei einem vollen Transfer stimmt der Transaktionsbetrag nicht mit dem Guthaben des Senders überein.
    #[error("Full transfer amount mismatch: Sender's balance is '{expected}', but transaction amount is '{found}'.")]
    FullTransferAmountMismatch { expected: String, found: String },

    /// Während der Überprüfung der Transaktionskette wurden unzureichende Mittel festgestellt.
    #[error("Insufficient funds found in transaction chain for user '{user_id}'. Needed: {needed}, Available: {available}")]
    InsufficientFundsInChain { user_id: String, needed: String, available: String },

    /// Die Gültigkeitsdauer des Gutscheins ist kürzer als vom Standard gefordert.
    #[error("The voucher's effective validity duration is shorter than the minimum required by the standard.")]
    ValidityDurationTooShort,

    /// Die im Gutschein gespeicherte Mindestgültigkeitsregel stimmt nicht mit der des Standards überein.
    #[error("The minimum validity duration rule stored in the voucher does not match the standard. Expected: {expected}, Found: {found}")]
    MismatchedMinimumValidity {
        expected: String,
        found: String,
    },

    /// The voucher's validity duration exceeds the maximum allowed by the standard.
    #[error("Voucher validity duration is too long. Maximum allowed is {max_allowed}.")]
    ValidityDurationTooLong { max_allowed: String },

    /// An amount string could not be parsed into a valid Decimal number.
    #[error("Failed to parse amount string at path '{path}': Found '{found}'.")]
    InvalidAmountFormat { path: String, found: String },

    /// An amount field has more decimal places than the standard allows.
    #[error("Invalid amount precision at path '{path}'. Standard allows max {max_places} decimal places, but found {found}.")]
    InvalidAmountPrecision {
        path: String,
        max_places: u8,
        found: u32,
    },

    /// The creator of the voucher is also listed as a guarantor.
    #[error("The voucher creator ('{creator_id}') cannot also be a guarantor.")]
    CreatorAsGuarantor { creator_id: String },
}


/// Der zentrale Fehlertyp für alle Operationen in der `voucher_core`-Bibliothek.
#[derive(Error, Debug)]
pub enum VoucherCoreError {
    #[error("Validation Error: {0}")]
    Validation(#[from] ValidationError),
    #[error("Bundle has already been processed and was rejected. Bundle ID: {bundle_id}")]
    BundleAlreadyProcessed { bundle_id: String },
    #[error("Transaction fingerprint is already known, indicating a potential replay attack. Fingerprint Hash: {fingerprint_hash}")]
    TransactionFingerprintAlreadyKnown { fingerprint_hash: String },
    #[error("Bundle Recipient Mismatch: This bundle was not intended for this wallet. Expected recipient: {expected}, but last transaction was for: {found}")]
    BundleRecipientMismatch { expected: String, found: String },
    #[error("Voucher Manager Error: {0}")]
    Manager(#[from] VoucherManagerError),
    #[error("Storage Error: {0}")]
    Storage(#[from] StorageError),
    #[error("Secure Container Error: {0}")]
    Container(#[from] ContainerManagerError),
    #[error("Standard Definition Error: {0}")]
    Standard(#[from] StandardDefinitionError),
    #[error("Archive error: {0}")]
    Archive(#[from] crate::archive::ArchiveError),
    #[error("JSON Processing Error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML Deserialization Error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Amount Conversion Error: {0}")]
    AmountConversion(#[from] rust_decimal::Error),
    #[error("Symmetric Encryption Error: {0}")]
    SymmetricEncryption(#[from] SymmetricEncryptionError),
    #[error("User ID or Key Error: {0}")]
    KeyOrId(#[from] GetPubkeyError),
    #[error("Cryptography error: {0}")]
    Crypto(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("Invalid payload type in secure container.")]
    InvalidPayloadType,
    #[error("Action aborted: The voucher is quarantined due to a detected double-spend conflict.")]
    VoucherInQuarantine,
    #[error("Operation failed because the wallet is locked.")]
    WalletLocked,
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),
    #[error("Voucher with local instance ID '{0}' not found in wallet.")]
    VoucherNotFound(String),
    #[error("Action requires an active voucher, but its status is {0:?}.")]
    VoucherNotActive(VoucherStatus),
    #[error("Ownership validation failed: {0}")]
    VoucherOwnershipNotFound(String),
    #[error("Double spend attempt blocked: A transaction has already been issued from this voucher state.")]
    DoubleSpendAttemptBlocked,
    #[error("Base58 decode error: {0}")]
    Bs58Decode(#[from] bs58::decode::Error),
    #[error("Base64 decode error: {0}")]
    Base64(String),
    #[error("Ed25519 crypto error: {0}")]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error("Mismatched signature data: {0}")]
    MismatchedSignatureData(String),
}