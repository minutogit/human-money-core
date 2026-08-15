//! # src/app_service/lifecycle.rs
//!
//! Contains all functions controlling the lifecycle of `AppService`,
//! such as initialization, login/logout, and recovery.

use super::{AppService, AppState, ProfileInfo, AppFacadeError};
use crate::models::seal::{LocalSealRecord, SyncStatus};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage, file_storage::FileStorage};
use crate::wallet::Wallet;
use crate::services::mnemonic::MnemonicLanguage;
use crate::services::crypto_utils::{generate_mnemonic, validate_mnemonic_phrase, get_hash};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

const PROFILES_INDEX_FILE: &str = "profiles.json";

impl AppService {
    // --- Lifecycle Management ---

    /// Initializes a new `AppService` in the `Locked` state.
    ///
    /// # Arguments
    /// * `base_storage_path` - The path to the base directory where all
    ///   profile subdirectories and `profiles.json` are stored.
    pub fn new(base_storage_path: &Path) -> Result<Self, AppFacadeError> {
        fs::create_dir_all(base_storage_path)
            .map_err(|e| AppFacadeError::StorageError(format!("Failed to create base storage directory: {}", e)))?;
        Ok(AppService {
            base_storage_path: base_storage_path.to_path_buf(),
            state: AppState::Locked,
        })
    }

    /// Returns true if the service is in the `Unlocked` state.
    pub fn is_wallet_unlocked(&self) -> bool {
        matches!(self.state, AppState::Unlocked { .. })
    }

    /// Lists all available profiles configured in the base directory.
    ///
    /// Reads the central `profiles.json` file and returns a list of `ProfileInfo`
    /// objects suitable for display in a login screen.
    ///
    /// # Returns
    /// A `Result` containing a vector of `ProfileInfo` or an error message
    /// if the index file cannot be read or parsed.
    pub fn list_profiles(&self) -> Result<Vec<ProfileInfo>, AppFacadeError> {
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        if !index_path.exists() {
            return Ok(Vec::new()); // No profiles exist, not an error.
        }

        let content = fs::read_to_string(index_path)
            .map_err(|e| AppFacadeError::StorageError(format!("Could not read profiles index file: {}", e)))?;
        if content.trim().is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_str(&content)
            .map_err(|e| AppFacadeError::JsonError(format!("Could not parse profiles index file: {}", e)))
    }

    /// Generates a new BIP-39 mnemonic phrase (seed words).
    ///
    /// This method is static and can be called without a loaded wallet.
    pub fn generate_mnemonic(word_count: u32, language: MnemonicLanguage) -> Result<String, AppFacadeError> {
        generate_mnemonic(word_count as usize, language)
            .map_err(|e| AppFacadeError::CryptoError(e.to_string()))
    }

    /// Returns the word list for a specific language.
    pub fn get_mnemonic_wordlist(language: MnemonicLanguage) -> Vec<&'static str> {
        crate::services::mnemonic::MnemonicProcessor::get_wordlist(language)
    }

    /// Validates a BIP-39 mnemonic phrase entered by the user.
    ///
    /// This method is static and can be called without a loaded wallet.
    pub fn validate_mnemonic(mnemonic: &str, language: MnemonicLanguage) -> Result<(), AppFacadeError> {
        validate_mnemonic_phrase(mnemonic, language)
            .map_err(|e| AppFacadeError::CryptoError(e.to_string()))
    }

    /// Creates a completely new user profile and wallet and stores it encrypted.
    ///
    /// This function derives an anonymous folder name from secrets, stores
    /// the wallet in this folder, and adds an entry to the central `profiles.json`.
    /// On success, the service transitions to the `Unlocked` state.
    ///
    /// # Arguments
    /// * `profile_name` - The human-readable name for the new profile. Must be unique.
    /// * `mnemonic` - The BIP-39 mnemonic phrase for generating master keys.
    /// * `passphrase` - An optional additional passphrase for the mnemonic.
    /// * `user_prefix` - An optional prefix for the `did:key`-based user ID.
    /// * `password` - The password used to encrypt the new wallet.
    pub fn create_profile(
        &mut self,
        profile_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
        password: &str,
        language: MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let mut profiles = self.list_profiles()?;
        if profiles.iter().any(|p| p.profile_name == profile_name) {
            return Err(AppFacadeError::ProfileAlreadyExists(format!(
                "A profile with the name '{}' already exists.",
                profile_name
            )));
        }

        let folder_name = Self::derive_folder_name(mnemonic, passphrase, user_prefix);
        let profile_path = self.base_storage_path.join(&folder_name);

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        if profile_path.exists() {
            return Err(AppFacadeError::ProfileAlreadyExists(
                "A profile with these secrets already exists (folder collision).".to_string()
            ));
        }

        let mut storage = FileStorage::new(profile_path);

        let (mut wallet, identity) = Wallet::new_from_mnemonic(mnemonic, passphrase, user_prefix, language, local_instance_id.clone())
            .map_err(AppFacadeError::from)?;

        wallet
            .save(&mut storage, &identity, &AuthMethod::Password(password))
            .map_err(AppFacadeError::from)?;

        // --- WALLET SEAL: Create initial seal (Epoch 0) ---
        let state_hash = {
            let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                .map_err(AppFacadeError::from)?;
            get_hash(canonical.as_bytes())
        };
        let initial_seal = SealManager::create_initial_seal(
            &identity.user_id,
            &identity,
            &state_hash,
            &local_instance_id,
        ).map_err(AppFacadeError::from)?;

        let seal_record = LocalSealRecord {
            seal: initial_seal,
            sync_status: SyncStatus::PendingUpload,
            is_locked_due_to_fork: false,
        };
        storage
            .save_seal(&identity.user_id, &AuthMethod::Password(password), &seal_record)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL END ---

        // Acquire lock
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        // Add the new profile to the index file
        profiles.push(ProfileInfo {
            profile_name: profile_name.to_string(),
            folder_name,
        });
        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(AppFacadeError::from)?;
        fs::write(index_path, updated_index)
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        // BUG-FIX: Initialize the "session anchor".
        let _ = self.save_encrypted_data("__storage_session_anchor", b"init", Some(password));

        // --- INTEGRITY & SEAL UPDATE ---
        // This must occur AFTER all initial write operations (including the anchor).
        let _ = self.update_seal_after_state_change(Some(password));

        Ok(())
    }

    /// Unlocks an existing wallet and loads it into memory.
    ///
    /// # Arguments
    /// * `folder_name` - The anonymous folder name of the profile to load.
    /// * `password` - The password to decrypt the wallet.
    ///
    /// # Errors
    /// Fails if the profile does not exist, password is incorrect, or
    /// wallet files cannot be read.
    pub fn login(
        &mut self,
        folder_name: &str,
        password: &str,
        cleanup_on_login: bool,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);

        // --- WALLET SEAL: Load seal and verify RAW state hash ---
        let needs_legacy_binding = Self::verify_seal_on_login(&storage, password, &local_instance_id)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL: Pre-Check END ---

        let (mut wallet, identity) = Wallet::load(&storage, &AuthMethod::Password(password), local_instance_id)
            .map_err(|e| AppFacadeError::CryptoError(format!("Login failed (check password): {}", e)))?;

        // --- EVENT FLUSH ---
        if !wallet.pending_events.is_empty() {
            wallet
                .save(&mut storage, &identity, &AuthMethod::Password(password))
                .map_err(AppFacadeError::from)?;
        }

        if cleanup_on_login {
            // Before cleaning up, check integrity.
            let auth = AuthMethod::Password(password);
            let integrity_record = storage.load_integrity("").unwrap_or(None);
            let seal_record = storage.load_seal(&identity.user_id, &auth).unwrap_or(None);
            let hashes = storage.get_all_item_hashes().unwrap_or_default();

            let is_valid = match (integrity_record, seal_record) {
                (Some(ir), Some(ref s)) => {
                    matches!(
                        crate::services::integrity_manager::IntegrityManager::verify_integrity(&ir, &s.seal, hashes, &identity.user_id),
                        Ok(crate::models::storage_integrity::IntegrityReport::Valid)
                    )
                }
                (None, _) => true, // Migration: we allow cleanup.
                _ => false,
            };

            if is_valid {
                let report = wallet
                    .run_storage_cleanup(None, super::DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS)
                    .map_err(AppFacadeError::from)?;
                
                if report.expired_fingerprints_removed > 0 
                    || report.limit_based_fingerprints_removed > 0 
                    || report.archived_items_removed > 0 
                {
                    wallet
                        .save(&mut storage, &identity, &auth)
                        .map_err(AppFacadeError::from)?;
                    
                    let new_hashes = storage.get_all_item_hashes().unwrap_or_default();
                    let seal = storage.load_seal(&identity.user_id, &auth).unwrap_or(None).map(|s| s.seal);
                    if let Some(s) = seal {
                        if let Ok(ir) = crate::services::integrity_manager::IntegrityManager::create_integrity_record(&identity, &s, new_hashes) {
                            let _ = storage.save_integrity(&identity.user_id, &ir);
                        }
                    }
                }
            } else {
                eprintln!("Skipping storage cleanup during login because integrity is compromised.");
            }
        }

        // --- WALLET SEAL: Migration for existing wallets without seal or without InstanceID ---
        Self::migrate_seal_on_login(&mut storage, &wallet, &identity, password, needs_legacy_binding)
            .map_err(AppFacadeError::from)?;
        // --- WALLET SEAL END ---

        // Acquire lock
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        // BUG-FIX: Initialize the "session anchor". (See create_profile)
        // This ensures that Mode A / Mode B operations work after a
        // login.
        let _ = self.save_encrypted_data("__storage_session_anchor", b"init", Some(password));

        Ok(())
    }

    /// Recovers a wallet using the mnemonic phrase and sets a new password.
    ///
    /// # Arguments
    /// * `folder_name` - The anonymous folder name of the profile to recover.
    /// * `mnemonic` - The mnemonic phrase for wallet recovery.
    /// * `passphrase` - Optional passphrase used during creation.
    /// * `new_password` - The new password with which to encrypt the wallet.
    pub fn recover_wallet_and_set_new_password(
        &mut self,
        folder_name: &str,
        mnemonic: &str,
        passphrase: Option<&str>,
        new_password: &str,
        language: MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // --- SECURITY GUARD: Detect bad instance_id storage ---
        self.check_instance_id_trap(&profile_path)?;

        let mut storage = FileStorage::new(profile_path);

        // 1. Load the wallet with the mnemonic phrase (opens the "second lock").
        let auth_method = AuthMethod::Mnemonic(mnemonic, passphrase, language);
        let (mut wallet, identity) = Wallet::load(&storage, &auth_method, local_instance_id.clone()).map_err(|e| {
            AppFacadeError::CryptoError(format!(
                "Recovery failed (check mnemonic phrase and passphrase): {}",
                e
            ))
        })?;

        // --- EVENT FLUSH ---
        if !wallet.pending_events.is_empty() {
            // Note: We still use mnemonic auth here because the new password 
            // is only set in the next step.
            wallet
                .save(&mut storage, &identity, &auth_method)
                .map_err(AppFacadeError::from)?;
        }

        // 2. Reset the password by opening the mnemonic lock and rewriting the password lock.
        Wallet::reset_password(&mut storage, &identity, new_password)
            .map_err(AppFacadeError::from)?;

        // --- WALLET SEAL: Initiate new epoch (Recovery) ---
        {
            let auth_for_seal = AuthMethod::Password(new_password);
            let existing_seal = storage
                .load_seal(&identity.user_id, &auth_for_seal)
                .ok()
                .flatten();

            let current_state_hash = {
                let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                    .map_err(AppFacadeError::from)?;
                get_hash(canonical.as_bytes())
            };

            let recovered_seal = SealManager::recover_seal_epoch(
                existing_seal.as_ref().map(|r| &r.seal),
                &identity.user_id,
                &identity,
                &current_state_hash,
                &local_instance_id,
            ).map_err(AppFacadeError::from)?;

            let new_record = LocalSealRecord {
                seal: recovered_seal,
                sync_status: SyncStatus::PendingUpload,
                is_locked_due_to_fork: false, // Recovery lifts the fork lock!
            };
            storage
                .save_seal(&identity.user_id, &auth_for_seal, &new_record)
                .map_err(AppFacadeError::from)?;

            // --- INTEGRITY UPDATE ---
            // After recovering the seal, we must update the Integrity Record,
            // since seal.enc has changed. Otherwise, the next login will warn of tampering.
            let item_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
            let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
                &identity,
                &new_record.seal,
                item_hashes,
            ).map_err(AppFacadeError::from)?;

            storage
                .save_integrity(&identity.user_id, &integrity_record)
                .map_err(AppFacadeError::from)?;
        }
        // --- WALLET SEAL END ---

        // Acquire lock
        storage
            .lock()
            .map_err(AppFacadeError::from)?;

        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        Ok(())
    }

    /// Locks the wallet and removes sensitive data (private key, session key) from memory.
    ///
    /// Resets state back to `Locked`. This operation cannot fail.
    pub fn logout(&mut self) {
        if let AppState::Unlocked { storage, .. } = &self.state {
            let _ = storage.unlock(); // Ignore errors during unlock
        }
        self.state = AppState::Locked;
    }

    /// Activates the "remember password" feature for a specified duration (in seconds).
    ///
    /// Verifies the password, derives the storage key, and keeps it in memory.
    /// This is the prerequisite for performing actions without re-entering password.
    ///
    /// # Arguments
    /// * `password` - Password for verification and key derivation.
    /// * `duration_seconds` - Session duration in seconds.
    pub fn unlock_session(&mut self, password: &str, duration_seconds: u64) -> Result<(), AppFacadeError> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                // Verify the password by trying to derive the session key
                let session_key = storage.derive_key_for_session(password)
                    .map_err(AppFacadeError::from)?;

                // Test whether the derived key is valid by using it
                // to decrypt the encrypted file key.
                // This validates that the password was correct.
                storage
                    .test_session_key(&session_key)
                    .map_err(AppFacadeError::from)?;

                // Create the session cache
                *session_cache = Some(super::SessionCache {
                    session_key,
                    session_duration: Duration::from_secs(duration_seconds),
                    last_activity: Instant::now(),
                });

                Ok(())
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked. Please login first.".to_string())),
        }
    }

    /// Deactivates the "remember password" feature immediately and clears the cached storage key from RAM.
    ///
    /// `AppService` remains `Unlocked` (read access works), but actions now require `unlock_session` or a `password` argument.
    pub fn lock_session(&mut self) {
        if let AppState::Unlocked { session_cache, .. } = &mut self.state {
            *session_cache = None;
        }
    }

    /// Resets the inactivity timer of the "remember password" session.
    ///
    /// Ideal to call on UI activity (clicks, mouse movement) so the session does not expire while the user is active.
    ///
    /// # Returns
    /// * `Ok(())` - If the session was active and was successfully extended.
    /// * `Err(...)` - If the session was already expired (will be locked), no session is active, or wallet is locked.
    pub fn refresh_session_activity(&mut self) -> Result<(), AppFacadeError> {
        if let AppState::Unlocked { session_cache, .. } = &mut self.state {
            // Check if a session exists at all
            if let Some(cache) = session_cache {
                // BUGFIX: Validate if the session is physically expired
                if cache.last_activity.elapsed() > cache.session_duration {
                    // Session expired: Clear cache and return error
                    *session_cache = None;
                    return Err(AppFacadeError::SessionExpired("Session expired.".to_string()));
                } else {
                    // Session valid: Renew timer.
                    cache.last_activity = Instant::now();
                    return Ok(());
                }
            }
            return Err(AppFacadeError::SessionNotActive("No active session to refresh.".to_string()));
        }
        Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()))
    }

    /// Forces binding of the wallet to the current device (handover).
    /// Called when login fails due to `DeviceMismatch`.
    pub fn handover_to_this_device(
        &mut self,
        folder_name: &str,
        password: &str,
        local_instance_id: String,
    ) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        let mut storage = FileStorage::new(profile_path);
        let auth = AuthMethod::Password(password);

        // 1. Load wallet
        let (mut wallet, identity) = Wallet::load(&storage, &auth, local_instance_id)
            .map_err(|e| AppFacadeError::CryptoError(format!("Loading for handover failed: {}", e)))?;

        // 2. Perform handover
        let new_seal = wallet.force_device_handover(&mut storage, &identity, &auth)
            .map_err(AppFacadeError::from)?;

        // --- INTEGRITY UPDATE ---
        let item_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
        let integrity_record = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
            &identity,
            &new_seal,
            item_hashes,
        ).map_err(AppFacadeError::from)?;

        storage
            .save_integrity(&identity.user_id, &integrity_record)
            .map_err(AppFacadeError::from)?;

        // 3. Perform login
        storage.lock().map_err(AppFacadeError::from)?;
        
        self.state = AppState::Unlocked {
            storage,
            wallet,
            identity,
            session_cache: None,
        };

        Ok(())
    }

    /// Checks whether the app developer stored `instance_id` insecurely as a file.
    /// Also check the parent directory to catch typical Tauri/Electron AppData folders.
    fn check_instance_id_trap(&self, profile_path: &Path) -> Result<(), AppFacadeError> {
        let mut bad_paths = vec![
            self.base_storage_path.join("instance_id"),
            profile_path.join("instance_id"),
        ];

        // Also check the parent directory
        if let Some(parent) = self.base_storage_path.parent() {
            bad_paths.push(parent.join("instance_id"));
        }

        for path in bad_paths {
            if path.exists() {
                return Err(AppFacadeError::Generic(
                    "CRITICAL SECURITY VIOLATION: The App Developer has stored the 'instance_id' inside the application data directory. \
                    This defeats the cloning protection! The instance_id MUST be stored securely in the OS Keyring or a separate isolated Config directory. \
                    Execution halted to protect user funds.".to_string()
                ));
            }
        }
        Ok(())
    }

    /// Permanently deletes a user profile from the device.
    /// Requires password confirmation.
    pub fn delete_profile(&mut self, folder_name: &str, password: &str) -> Result<(), AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        // 1. Verify password
        // We use a temporary instance of FileStorage to check if we can load the wallet.
        let storage = FileStorage::new(profile_path.clone());
        let auth = AuthMethod::Password(password);
        
        // Try to load the wallet to check the password.
        // The instance_id is of secondary importance here for the mere password check,
        // we use a placeholder to bypass DeviceMismatch checks if possible,
        // but Wallet::load() itself does not perform a seal check (only AppService::login does).
        let _ = Wallet::load(&storage, &auth, "password_check".to_string())
            .map_err(|e| AppFacadeError::CryptoError(format!("Password verification failed (check password): {}", e)))?;

        // 2. Remove profile from the index (profiles.json)
        let mut profiles = self.list_profiles()?;
        let original_len = profiles.len();
        profiles.retain(|p| p.folder_name != folder_name);
        
        if profiles.len() == original_len {
             return Err(AppFacadeError::ProfileNotFound("Profile not found in index.".to_string()));
        }

        let index_path = self.base_storage_path.join(PROFILES_INDEX_FILE);
        let updated_index = serde_json::to_string_pretty(&profiles)
            .map_err(AppFacadeError::from)?;
        fs::write(index_path, updated_index)
            .map_err(AppFacadeError::from)?;

        // 3. Physically delete directory
        fs::remove_dir_all(profile_path)
            .map_err(AppFacadeError::from)?;

        Ok(())
    }

    /// Verifies profile password and returns the user ID (DID).
    /// Useful for security confirmations before critical actions (such as deletion).
    pub fn get_profile_id_with_password(&self, folder_name: &str, password: &str) -> Result<String, AppFacadeError> {
        let profile_path = self.base_storage_path.join(folder_name);
        if !profile_path.exists() {
            return Err(AppFacadeError::ProfileNotFound("Profile directory not found.".to_string()));
        }

        let storage = FileStorage::new(profile_path);
        let auth = AuthMethod::Password(password);
        
        // Try to load the wallet to get the identity.
        let (_, identity) = Wallet::load(&storage, &auth, "password_check".to_string())
            .map_err(|e| AppFacadeError::CryptoError(format!("Password verification failed: {}", e)))?;

        Ok(identity.user_id.clone())
    }
}
