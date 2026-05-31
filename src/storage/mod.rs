//! # src/storage/mod.rs
//!
//! Defines the abstraction for persistent storage of wallet data.
//! This decouples the core logic from the concrete storage method.

use crate::models::conflict::{
    CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore,
};
use crate::models::profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore};
pub mod file_storage;
use thiserror::Error;

/// A generic error type for all storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Authentication failed: Invalid password or recovery identity.")]
    AuthenticationFailed,

    #[error("Data not found for the given identifier.")]
    NotFound,

    #[error("Data is corrupted or has an invalid format: {0}")]
    InvalidFormat(String),

    #[error("Underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("An unexpected error occurred: {0}")]
    Generic(String),

    #[error("Wallet-Sperre fehlgeschlagen: {0}")]
    LockFailed(String),

    #[error("Veraltete Sperre (Stale Lock) gefunden und entfernt: {0}")]
    StaleLock(String),

    #[error("State conflict: {0}")]
    StateConflict(String),
}

/// Authentication method for storage access
pub enum AuthMethod<'a> {
    /// The password of the user (used for key derivation)
    Password(&'a str),
    /// An already derived session key (skips key derivation)
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

/// The interface for persistent storage.
/// Each method is an atomic operation for a complete wallet.
pub trait Storage {
    /// Derives the storage key (SessionKey) from the password.
    fn derive_key_for_session(&self, password: &str) -> Result<[u8; 32], StorageError>;

    /// Loads and decrypts the core wallet (profile and VoucherStore).
    fn load_wallet(
        &self,
        auth: &AuthMethod,
    ) -> Result<(UserProfile, VoucherStore, UserIdentity), StorageError>;

    /// Saves and encrypts the core wallet (profile and VoucherStore).
    /// Must also receive the `UserIdentity` to create the recovery key during the first save.
    fn save_wallet(
        &mut self,
        profile: &UserProfile,
        store: &VoucherStore,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError>;

    /// Resets the password by recreating the password lock with the recovery key.
    fn reset_password(
        &mut self,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError>;

    /// Checks if a profile already exists at the storage location.
    fn profile_exists(&self) -> bool;

    /// Loads and decrypts the `KnownFingerprints` store.
    fn load_known_fingerprints(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<KnownFingerprints, StorageError>;

    /// Saves and encrypts the `KnownFingerprints` store.
    fn save_known_fingerprints(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        fingerprints: &KnownFingerprints,
    ) -> Result<(), StorageError>;

    /// Loads and decrypts the critical `OwnFingerprints` store.
    fn load_own_fingerprints(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<OwnFingerprints, StorageError>;

    /// Saves and encrypts the critical `OwnFingerprints` store.
    fn save_own_fingerprints(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        fingerprints: &OwnFingerprints,
    ) -> Result<(), StorageError>;

    /// Loads and decrypts transaction bundle metadata.
    fn load_bundle_metadata(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<BundleMetadataStore, StorageError>;

    /// Saves and encrypts transaction bundle metadata.
    fn save_bundle_metadata(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        metadata: &BundleMetadataStore,
    ) -> Result<(), StorageError>;

    /// Loads and decrypts the ProofStore.
    fn load_proofs(&self, user_id: &str, auth: &AuthMethod) -> Result<ProofStore, StorageError>;

    /// Saves and encrypts the ProofStore.
    fn save_proofs(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        proof_store: &ProofStore,
    ) -> Result<(), StorageError>;

    /// Loads the canonical store for fingerprint metadata.
    fn load_fingerprint_metadata(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<CanonicalMetadataStore, StorageError>;

    /// Saves the canonical store for fingerprint metadata.
    fn save_fingerprint_metadata(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        metadata: &CanonicalMetadataStore,
    ) -> Result<(), StorageError>;

    /// Saves any named data block encrypted.
    ///
    /// This function allows the application to securely store its own data in the context of the
    /// wallet, without having to manage its own keys.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to whom the data is associated.
    /// * `auth` - The authentication method for encryption.
    /// * `name` - A unique name for the data block (e.g. "app_settings").
    /// * `data` - The raw data to be encrypted.
    fn save_arbitrary_data(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        name: &str,
        data: &[u8],
    ) -> Result<(), StorageError>;

    /// Loads any named and encrypted data block.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to whom the data is associated.
    /// * `auth` - The authentication method for decryption.
    /// * `name` - The name of the data block to be loaded.
    fn load_arbitrary_data(
        &self,
        user_id: &str,
        auth: &AuthMethod,
        name: &str,
    ) -> Result<Vec<u8>, StorageError>;

    /// Verifies whether a derived session key is valid by attempting to
    /// access encrypted data with it.
    fn test_session_key(&self, session_key: &[u8; 32]) -> Result<(), StorageError>;

    /// Saves the seal wrapper strictly locally (outside of cloud sync folders).
    ///
    /// The `LocalSealRecord` contains the cryptographic seal plus local metadata
    /// (SyncStatus, fork lock). This data must never be sent to the server.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    /// * `auth` - The authentication method for encryption.
    /// * `record` - The seal wrapper to be stored.
    fn save_seal(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        record: &crate::models::seal::LocalSealRecord,
    ) -> Result<(), StorageError>;

    /// Loads the local seal wrapper.
    ///
    /// Returns `Ok(None)` if no seal exists yet (e.g. during migration
    /// of existing wallets without a seal).
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    /// * `auth` - The authentication method for decryption.
    fn load_seal(
        &self,
        user_id: &str,
        auth: &AuthMethod,
    ) -> Result<Option<crate::models::seal::LocalSealRecord>, StorageError>;

    /// Computes the SHA3-256 hash of an element in the wallet storage.
    ///
    /// # Arguments
    /// * `name` - The name of the element/table/file (e.g. "profile.enc").
    fn get_item_hash(&self, name: &str) -> Result<String, StorageError>;

    /// Saves the storage integrity record.
    /// The integrity record is plain text but cryptographically signed.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    /// * `record` - The integrity record to be stored.
    fn save_integrity(
        &mut self,
        user_id: &str,
        record: &crate::models::storage_integrity::LocalIntegrityRecord,
    ) -> Result<(), StorageError>;

    /// Loads the storage integrity record.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    fn load_integrity(
        &self,
        user_id: &str,
    ) -> Result<Option<crate::models::storage_integrity::LocalIntegrityRecord>, StorageError>;

    /// Computes the hashes of all relevant logical storage elements.
    fn get_all_item_hashes(&self) -> Result<std::collections::HashMap<String, String>, StorageError>;

    /// Appends a batch of wallet events to the persisted event log.
    ///
    /// The implementation should load/decrypt the existing file,
    /// append the new events, and write them back encrypted in one go.
    fn append_events(
        &mut self,
        user_id: &str,
        auth: &AuthMethod,
        events: &[crate::models::wallet_event::WalletEvent],
    ) -> Result<(), StorageError>;

    /// Loads a paginated view of the persisted event log.
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user.
    /// * `auth` - The authentication method for decryption.
    /// * `offset` - The offset for pagination.
    /// * `limit` - The maximum number of events to return.
    fn load_events(
        &self,
        user_id: &str,
        auth: &AuthMethod,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<crate::models::wallet_event::WalletEvent>, StorageError>;

    /// Attempts to acquire an exclusive, process-wide lock for the wallet storage.
    /// Must implement "stale lock" checking (e.g. PID).
    ///
    /// Returns `Ok(true)` if a new lock was successfully acquired.
    /// Returns `Ok(false)` if the lock is already held by OURSELVES (re-entrancy).
    /// Returns `Err(StorageError::LockFailed)` if the lock is actively held by
    /// *another live* process.
    fn lock(&self) -> Result<bool, StorageError>;

    /// Releases the exclusive lock.
    /// This method should only be called during a clean logout.
    /// The `WalletLockGuard` should be used for operations.
    fn unlock(&self) -> Result<(), StorageError>;

    /// Returns the path to the lock file (for the RAII guard).
    fn get_lock_file_path(&self) -> &std::path::PathBuf;

    /// Reads the current generation counter from the disk.
    /// If the file does not exist, 0 is returned.
    fn read_generation(&self) -> Result<u64, StorageError>;

    /// Writes the new generation counter to the disk.
    /// Atomically checks if the current counter matches the expected value.
    fn write_generation(&mut self, expected: u64, new: u64) -> Result<(), StorageError>;
}

// --- RAII Lock Guard ---

/// An RAII guard that ensures a lock is automatically
/// released when the guard goes out of scope.
///
/// This guard should be used for *transactional* operations like `create_transfer_bundle`
/// or `receive_bundle`.
pub struct WalletLockGuard {
    lock_file_path: std::path::PathBuf,
    was_already_locked: bool,
}

impl WalletLockGuard {
    /// Creates a new guard and immediately attempts to acquire the lock.
    pub fn new(storage: &dyn Storage) -> Result<Self, StorageError> {
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
        if !self.was_already_locked && self.lock_file_path.exists() {
            if let Err(e) = fs::remove_file(&self.lock_file_path) {
                // IMPORTANT: Never panic in `drop`!
                eprintln!(
                    "Schwerwiegender Fehler: Wallet-Sperre konnte nicht freigegeben werden: {:?}",
                    e
                );
            }
        }
    }
}
