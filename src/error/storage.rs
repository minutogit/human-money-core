//! # src/error/storage.rs
//!
//! Storage-layer error taxonomy.
//! Extracted from `storage/mod.rs` (Streamline Phase 3).
//! All `Generic(String)` usages have been eliminated in favour of typed
//! variants (`InvalidItemName`, `EmptyPassword`, `EncryptionFailed`, etc.).

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A typed error for all storage operations.
#[derive(Debug, Clone, Error, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum StorageError {
    #[error("Authentication failed: Invalid password or recovery identity.")]
    AuthenticationFailed,

    #[error("Data not found for the given identifier.")]
    NotFound,

    #[error("Data is corrupted or has an invalid format: {0}")]
    InvalidFormat(String),

    #[error("Archived or stored data failed integrity verification: {0}")]
    IntegrityViolation(String),

    #[error("Underlying I/O error: {0}")]
    Io(String),

    #[error("Data could not be (de)serialized: {0}")]
    Serialization(String),

    #[error("State conflict: {0}")]
    StateConflict(String),

    #[error("Wallet-Sperre fehlgeschlagen: {0}")]
    LockFailed(String),

    #[error("Veraltete Sperre (Stale Lock) gefunden und entfernt: {0}")]
    StaleLock(String),

    // --- Typed replacements for former Generic(String) ---

    /// Item name contains traversal or is otherwise invalid.
    #[error("Invalid item name '{name}': {reason}")]
    InvalidItemName { name: String, reason: String },

    /// Generic data-block name is invalid (flat namespace).
    #[error("Invalid data block name '{name}'")]
    InvalidDataBlockName { name: String },

    /// Zero-entropy password rejected before any key derivation.
    #[error("Refusing to operate with an empty password (zero-entropy key material)")]
    EmptyPassword,

    /// Auth method is not supported for this operation.
    #[error("Invalid auth method: {reason}")]
    InvalidAuthMethod { reason: String },

    /// Encryption or decryption of a store payload failed.
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    /// Key derivation (Argon2 / SHA) failed.
    #[error("Key derivation failed for {method}: {reason}")]
    KeyDerivationFailed { method: String, reason: String },

    /// Lock acquisition failed beyond timeout.
    #[error("Lock timeout: {reason}")]
    LockTimeout { reason: String },

    /// Lock acquisition failed (generic file lock error).
    #[error("Lock acquisition failed: {reason}")]
    LockAcquisitionFailed { reason: String },

    /// Invariant violation detected (logic error).
    #[error("Invariant violation: {message}")]
    InvariantViolation { message: String },
}

impl From<std::io::Error> for StorageError {
    fn from(err: std::io::Error) -> Self {
        StorageError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}
