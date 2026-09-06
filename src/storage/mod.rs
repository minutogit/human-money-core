//! # src/storage/mod.rs
//!
//! Concrete persistence layer for wallet data.
//!
//! The core library is **not** abstracted behind a generic `Storage` trait.
//! Instead, `FileStorage` is the single, concrete, encrypted-file backend used
//! by `Wallet` and `AppService`. All file I/O is target-gated via
//! `cfg(not(target_arch = "wasm32"))`, so the crate remains WASM-compatible.
//! The former "trait abstraction" wording in older docs is obsolete.
//!
//! Streamline Phase-2 splits `FileStorage` into focused submodules
//! (`key_manager`, `encrypted_store`, `event_store`, `lock`, `integrity`) that
//! are orchestrated by the slim `file_storage` facade. The public API remains
//! identical; submodules are `pub(crate)` implementation detail re-exported
//! where needed for backward compatibility.

use crate::models::profile::UserIdentity;
pub mod encrypted_store;
pub mod event_store;
pub mod file_storage;
pub mod integrity;
pub mod key_manager;
pub mod lock;
pub mod seal_service;
// Re-export StorageError from the centralized error module (Phase 3).
pub use crate::error::storage::StorageError;

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
            _ => Err(StorageError::InvalidAuthMethod {
                reason: "Password not available for this auth method".to_string(),
            }),
        }
    }

    /// Extracts the session key if the method is `SessionKey`.
    pub fn get_session_key(&self) -> Result<[u8; 32], StorageError> {
        match self {
            AuthMethod::SessionKey(key) => Ok(*key),
            _ => Err(StorageError::InvalidAuthMethod {
                reason: "Session key not available for this auth method".to_string(),
            }),
        }
    }
}

pub use file_storage::FileStorage;
pub use lock::WalletLockGuard;
