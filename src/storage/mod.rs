//! # src/storage/mod.rs
//!
//! Concrete persistence layer for wallet data.
//!
//! The core library is **not** abstracted behind a generic `Storage` trait.
//! Instead, `FileStorage` is the single, concrete, encrypted-file backend used
//! by `Wallet` and `AppService`. All file I/O is target-gated via
//! `cfg(not(target_arch = "wasm32"))`, so the crate remains WASM-compatible.
//! The former "trait abstraction" wording in older docs is obsolete.

use crate::models::profile::UserIdentity;
pub mod file_storage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A generic error type for all storage operations.
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

    #[error("An unexpected error occurred: {0}")]
    Generic(String),

    #[error("Wallet-Sperre fehlgeschlagen: {0}")]
    LockFailed(String),

    #[error("Veraltete Sperre (Stale Lock) gefunden und entfernt: {0}")]
    StaleLock(String),

    #[error("State conflict: {0}")]
    StateConflict(String),
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

/// Authentication method for storage access.
///
/// This enum is the single entry point for all credential types. Each variant
/// is self-contained and panic-free: helpers return `StorageError` instead of
/// unwrapping, and key derivation failures surface as typed errors.
pub enum AuthMethod<'a> {
    /// The password of the user (used for key derivation).
    Password(&'a str),
    /// An already derived session key (skips key derivation).
    SessionKey([u8; 32]),
    /// Authentication via a mnemonic phrase (for recovery).
    Mnemonic(&'a str, Option<&'a str>, crate::services::mnemonic::MnemonicLanguage),
    /// Authentication via the cryptographic identity (for recovery).
    RecoveryIdentity(&'a UserIdentity),
}

impl<'a> AuthMethod<'a> {
    /// Extracts the password as `&str` if the method is `Password`.
    pub fn get_password(&self) -> Result<&'a str, StorageError> {
        match self {
            AuthMethod::Password(p) => Ok(p),
            _ => Err(StorageError::Generic(
                "Password not available for this auth method".to_string(),
            )),
        }
    }

    /// Extracts the session key if the method is `SessionKey`.
    pub fn get_session_key(&self) -> Result<[u8; 32], StorageError> {
        match self {
            AuthMethod::SessionKey(key) => Ok(*key),
            _ => Err(StorageError::Generic(
                "Session key not available for this auth method".to_string(),
            )),
        }
    }
}

pub use file_storage::FileStorage;

// --- RAII Lock Guard ---

/// An RAII guard that ensures a lock is automatically
/// released when the guard goes out of scope.
///
/// This guard should be used for *transactional* operations like `create_transfer_bundle`
/// or `receive_bundle`.
///
/// The guard never panics: `Drop` swallows I/O errors and logs them, and
/// `new` returns a typed `StorageError::LockFailed` instead of panicking.
pub struct WalletLockGuard {
    lock_file_path: std::path::PathBuf,
    was_already_locked: bool,
}

impl WalletLockGuard {
    /// Creates a new guard and immediately attempts to acquire the lock.
    pub fn new(storage: &FileStorage) -> Result<Self, StorageError> {
        let is_newly_locked = storage.lock()?; // Acquire lock upon creation
        let lock_file_path = storage.get_lock_file_path().clone();
        Ok(Self {
            lock_file_path,
            was_already_locked: !is_newly_locked,
        })
    }
}

    /// Automatically called when the `_lock_guard` variable leaves the scope.
impl Drop for WalletLockGuard {
    fn drop(&mut self) {
        use std::fs;
        // Delete the file ONLY if we created it ourselves (was_already_locked == false)
        if !self.was_already_locked && self.lock_file_path.exists()
            && let Err(e) = fs::remove_file(&self.lock_file_path) {
                // IMPORTANT: Never panic in `drop`!
                eprintln!(
                    "Schwerwiegender Fehler: Wallet-Sperre konnte nicht freigegeben werden: {:?}",
                    e
                );
            }
    }
}
