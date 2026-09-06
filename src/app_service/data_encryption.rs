//! # src/app_service/data_encryption.rs
//!
//! Contains the `AppService` methods for encrypting and decrypting
//! arbitrary, application-specific data.

use super::{AppService, AppState, AppFacadeError};
use crate::storage::{AuthMethod, Storage, WalletLockGuard};

impl AppService {
    // --- Generic Data Encryption ---

    /// Saves an arbitrary byte slice encrypted on the disk.
    ///
    /// This method uses the same secure encryption mechanism as the wallet itself.
    /// It is ideal to store application-specific data (e.g. configurations, contacts)
    /// securely without the app having to manage its own keys.
    ///
    /// # Arguments
    /// * `name` - A unique name for the data, serves as the filename (e.g. "settings").
    /// * `data` - The `&[u8]` slice to be stored.
    /// * `password` - The current password of the user for encryption.
    ///
    /// # Errors
    /// Fails if the wallet is locked or the write operation fails.
    pub fn save_encrypted_data(
        &mut self,
        name: &str,
        data: &[u8],
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        return match password {
            Some(pwd_str) => {
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => {
                        // CORRECTION: Mode A uses AuthMethod::Password
                        let auth_method = AuthMethod::Password(pwd_str);
                        let result = {
                            // --- ACQUIRE LOCK (RAII) ---
                            let _lock_guard =
                                WalletLockGuard::new(storage).map_err(AppFacadeError::from)?;
                            // --- END LOCK ---
                            storage
                                .save_arbitrary_data(&identity.user_id, &auth_method, name, data)
                                .map_err(AppFacadeError::from)
                        };

                        // Update seal and integrity (except for the session anchor, as it is ignored)
                        // SECURITY (AUDIT-W4-WC-004): never swallow a failed
                        // seal/integrity phase. A silent failure would leave
                        // the integrity record stale (cleanup-on-login disabled
                        // forever, tampering reported where none exists).
                        if result.is_ok() && name != "__storage_session_anchor" {
                            if let Err(seal_err) =
                                self.update_seal_after_state_change(Some(pwd_str))
                            {
                                return Err(seal_err);
                            }
                        }
                        result
                    }
                    AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
                }
            }
            None => {
                let session_key = self.get_session_key()?;
                let auth_method = AuthMethod::SessionKey(session_key);
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => {
                        let result = {
                            // --- ACQUIRE LOCK (RAII) ---
                            let _lock_guard =
                                WalletLockGuard::new(storage).map_err(AppFacadeError::from)?;
                            // --- END LOCK ---
                            storage
                                .save_arbitrary_data(&identity.user_id, &auth_method, name, data)
                                .map_err(AppFacadeError::from)
                        };

                        // Update seal and integrity (via session key) (except for the session anchor)
                        // SECURITY (AUDIT-W4-WC-004): see password branch above —
                        // seal-phase failures must fail loudly.
                        if result.is_ok() && name != "__storage_session_anchor" {
                            if let Err(seal_err) = self.update_seal_after_state_change(None) {
                                return Err(seal_err);
                            }
                        }
                        result
                    }
                    AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
                }
            }
        };
    }

    /// Loads and decrypts a previously saved, arbitrary data block.
    ///
    /// # Arguments
    /// * `name` - The name of the data to be loaded.
    /// * `password` - The password of the user. For security reasons, the password
    ///   is required for each read operation to derive the decryption key.
    ///
    /// # Returns
    /// The decrypted data as `Vec<u8>`.
    ///
    /// # Errors
    /// Fails if the wallet is locked, the password is incorrect, or the data cannot be found.
    pub fn load_encrypted_data(
        &mut self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>, AppFacadeError> {
        return match password {
            Some(pwd_str) => {
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => {
                        // CORRECTION: Mode A uses AuthMethod::Password
                        let auth_method = AuthMethod::Password(pwd_str);
                        storage
                            .load_arbitrary_data(&identity.user_id, &auth_method, name)
                            .map_err(AppFacadeError::from)
                    }
                    AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
                }
            }
            None => {
                let session_key = self.get_session_key()?;
                let auth_method = AuthMethod::SessionKey(session_key);
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => storage
                        .load_arbitrary_data(&identity.user_id, &auth_method, name)
                        .map_err(AppFacadeError::from),
                    AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
                }
            }
        };
    }
}
