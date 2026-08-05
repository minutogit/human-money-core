//! # src/app_service/mod.rs
//!
//! Defines the `AppService`, a facade over the `Wallet` to simplify
//! the core logic for client applications (e.g., GUIs).
//!
//! This layer manages the application state (Locked/Unlocked), encapsulates
//! the `UserIdentity`, and ensures that state changes in the wallet
//! are automatically saved.
//!
//! ## Concept: Profile Management
//!
//! The `AppService` supports multiple, separate user profiles.
//! Each profile is stored in its own, anonymously named subdirectory.
//! A central `profiles.json` file in the base directory maps user-friendly
//! profile names to the anonymous folders to facilitate login.
//!
//! ## Example: Typical Lifecycle
//!
//! ```no_run
//! use human_money_core::app_service::AppService;
//! use human_money_core::MnemonicLanguage;
//! use std::path::Path;
//! # use human_money_core::services::voucher_manager::NewVoucherData;
//! # use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
//!
//! // 1. Initialize the service with a base storage path.
//! let storage_path = Path::new("/tmp/my_wallets");
//! let mut app = AppService::new(storage_path).expect("Service could not be created.");
//!
//! // 2. Create a new profile (this unlocks the wallet).
//! let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! app.create_profile("My Wallet", &mnemonic, None, Some("user"), "secure-password-123", MnemonicLanguage::English, "device-id".to_string())
//!    .expect("Profile could not be created.");
//!
//! // 3. Perform an action (e.g., check balance).
//! let balance = app.get_total_balance_by_currency().unwrap();
//! assert!(balance.is_empty());
//!
//! // 4. Lock the wallet (Logout).
//! app.logout();
//!
//! // 5. Retrieve profiles for the login screen.
//! let profiles = app.list_profiles().expect("Profiles could not be loaded.");
//! let profile_to_load = profiles.first().unwrap();
//!
//! // 6. Log in again using the profile's folder name and password.
//! app.login(&profile_to_load.folder_name, "secure-password-123", false, "device-id".to_string())
//!    .expect("Login failed.");
//!
//! // 7. Retrieve the User ID.
//! let user_id = app.get_user_id().unwrap();
//! println!("Logged in as: {}", user_id);
//! ```

use crate::models::profile::UserIdentity;
use crate::services::{bundle_processor, crypto_utils};
use crate::services::crypto_constants::ARGON2_PROFILE_FOLDER_SALT;
use crate::storage::{Storage, file_storage::FileStorage};
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS: i64 = 2;

pub mod error;
pub use error::AppFacadeError;

// Declaration of the new handlers as public sub-modules.
// Each file contains an `impl AppService` block for its specific area.
pub mod app_profile_handler;
pub mod app_queries;
pub mod app_signature_handler;
pub mod command_handler;
pub mod conflict_handler;
pub mod data_encryption;
pub mod l2_facade;
pub mod lifecycle;
pub mod seal_handler;
pub mod standard_container_handler;

/// Represents the publicly visible information of a profile.
/// Used to pass a list of available profiles to the frontend.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProfileInfo {
    /// The user-chosen, human-readable name of the profile.
    #[serde(rename = "profileName")]
    pub profile_name: String,
    /// The anonymous, derived name of the folder where the profile data is stored.
    #[serde(rename = "folderName")]
    pub folder_name: String,
}

/// Cache for the "Remember password" function.
pub struct SessionCache {
    /// The derived storage key.
    session_key: [u8; 32],
    /// The configured duration of inactivity (e.g., 900 sec).
    session_duration: Duration,
    /// The time of the last detected activity (for "Sliding Window").
    last_activity: Instant,
}

/// Represents the core state of the application.
pub enum AppState {
    /// No wallet is loaded and no `UserIdentity` is in memory.
    Locked,
    /// A wallet is loaded and the `UserIdentity` (including private key)
    /// is available for operations.
    Unlocked {
        storage: FileStorage,
        wallet: Wallet,
        identity: UserIdentity,
        /// The cache for the "Remember password" function.
        /// If Some(...), actions without password entry are possible.
        session_cache: Option<SessionCache>,
    },
}

/// The `AppService` facade.
///
/// Serves as the primary interface for client applications. It simplifies
/// interaction with the `human_money_core` library by encapsulating state management
/// and persistence processes.
pub struct AppService {
    /// The base path where the anonymous wallet directories are stored.
    base_storage_path: PathBuf,
    /// The current state of the service (Locked or Unlocked).
    state: AppState,
}

/// Represents the result of a mutating transaction, instructing the orchestrator
/// on how to finalize the state changes.
pub(super) enum TransactionOutcome<T, E> {
    /// Indicates a successful operation. The temporary wallet state is saved to disk,
    /// the cryptographic seal is updated, the main memory state is updated, and the successful
    /// value `T` is returned.
    Commit(T),
    /// Indicates an error occurred, but the modified wallet state must still be persisted.
    /// This is used for self-healing, garbage-collection, or database maintenance tasks
    /// where an error needs to be reported to the caller, but the structural updates (e.g., fixing integrity
    /// issues or marking state transitions) must not be rolled back. The state is saved to disk,
    /// seal is updated, and the error `E` is returned.
    CommitAndReturnError(E),
    /// Indicates the transaction must be aborted. All modifications made to the temporary
    /// wallet state are discarded. No files are written, no seals are updated, and the error `E`
    /// is returned. The memory state remains unchanged.
    Rollback(E),
}

impl AppService {
    /// Derives the anonymous folder name from user secrets.
    ///
    /// This method encapsulates the logic for generating a cryptographically secure,
    /// anonymous, and unique folder name for a new profile.
    fn derive_folder_name(
        mnemonic: &str,
        passphrase: Option<&str>,
        prefix: Option<&str>,
    ) -> String {
        // 1. Create the unique, secret string for this account.
        let secret_string = format!(
            "{}{}{}",
            mnemonic,
            passphrase.unwrap_or(""),
            prefix.unwrap_or("")
        );

        // 2. Use Argon2id key stretching for the anonymous folder name (Mobile/WASM tuned).
        // This provides significantly higher protection against brute-force attacks on the folder name.
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), ARGON2_PROFILE_FOLDER_SALT)
            .unwrap_or_else(|_| crypto_utils::get_hash(secret_string.as_bytes()))
    }

    /// Validates all vouchers within an encrypted bundle.
    /// This method is called by the `command_handler` before processing a bundle
    /// and therefore remains centrally available here.
    fn validate_vouchers_in_bundle(
        identity: &UserIdentity,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
    ) -> Result<(), AppFacadeError> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, bundle_data)
            .map_err(AppFacadeError::from)?;

        for voucher in &bundle.vouchers {
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard_toml = standard_definitions_toml
                .get(standard_uuid)
                .ok_or_else(|| {
                    AppFacadeError::ValidationError(format!(
                        "Required standard definition for UUID '{}' not provided.",
                        standard_uuid
                    ))
                })?;

            let (verified_standard, _) =
                crate::services::standard_manager::verify_and_parse_standard(standard_toml)
                    .map_err(AppFacadeError::from)?;

            crate::services::voucher_validation::validate_voucher_against_standard(
                voucher,
                &verified_standard,
            )
            .map_err(AppFacadeError::from)?;
        }
        Ok(())
    }


    /// Resolves the authentication method (password or session key).
    /// Also checks the session timeout.
    pub(super) fn resolve_auth_method<'a>(
        password: Option<&'a str>,
        session_cache: &Option<SessionCache>,
    ) -> Result<crate::storage::AuthMethod<'a>, crate::error::VoucherCoreError> {
        match password {
            Some(pwd) => Ok(crate::storage::AuthMethod::Password(pwd)),
            None => match session_cache {
                Some(cache) => {
                    if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                        Err(crate::error::VoucherCoreError::Generic(
                            "Session timed out. Please provide password.".to_string(),
                        ))
                    } else {
                        Ok(crate::storage::AuthMethod::SessionKey(cache.session_key))
                    }
                }
                None => Err(crate::error::VoucherCoreError::Generic(
                    "Password required. Please use 'unlock_session'.".to_string(),
                )),
            },
        }
    }

    /// Helper method for read-only access to the wallet.
    pub(super) fn get_wallet(&self) -> Result<&Wallet, AppFacadeError> {
        match &self.state {
            AppState::Unlocked { wallet, .. } => Ok(wallet),
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Helper method for access to the identity.
    pub(super) fn get_identity(&self) -> Result<&UserIdentity, AppFacadeError> {
        match &self.state {
            AppState::Unlocked { identity, .. } => Ok(identity),
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Encapsulates read access to the unlocked wallet.
    pub(super) fn with_unlocked_ref<F, R>(&self, f: F) -> Result<R, AppFacadeError>
    where
        F: FnOnce(&Wallet, &UserIdentity, &FileStorage) -> Result<R, AppFacadeError>,
    {
        match &self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                ..
            } => f(wallet, identity, storage),
            AppState::Locked => Err(AppFacadeError::WalletLocked("AppService is locked.".to_string())),
        }
    }

    /// Orchestrates the lifecycle of a mutating transaction on the wallet state.
    ///
    /// This method is the central safety boundary for state changes in the `AppService`.
    /// It coordinates concurrent access control, memory isolation, file persistence, 
    /// cryptographic signing (sealing), and automatic rollback in case of execution errors.
    ///
    /// # Architecture & Transaction Security Model
    ///
    /// In an offline-first system, preventing local database corruption, double-spends,
    /// or race conditions during multi-threaded UI events is critical. `with_transactional_mut`
    /// enforces transactional safety through a multi-layered verification and state isolation sequence.
    ///
    /// # The 7-Step Transaction Lifecycle
    ///
    /// 1. **Fork-Lock Verification:**
    ///    Ensures that the local wallet state is not running on an invalid or outdated epoch chain.
    ///    This checks if any fork or epoch mismatch occurred on the device to prevent double-spending
    ///    or out-of-sync writes.
    ///
    /// 2. **State Isolation (Unpacking):**
    ///    To satisfy Rust's strict mutability borrowing rules and prevent poisoned states in case of panics,
    ///    the `state` of the `AppService` is temporarily replaced with `AppState::Locked`. If a panic occurs
    ///    during execution, the wallet remains safely locked instead of leaving behind a corrupted memory reference.
    ///
    /// 3. **Physical File Locking:**
    ///    Acquires an exclusive, process-wide RAII file lock (`WalletLockGuard`) on the underlying profile storage.
    ///    This prevents concurrent database modifications from another thread or separate application process.
    ///
    /// 4. **Authentication & Generation Verification (Reload-Before-Write):**
    ///    Resolves the `AuthMethod` (either via explicit password or valid session key). It then reads the wallet's
    ///    generation number directly from storage and compares it to the memory-loaded version. If the disk generation
    ///    differs (e.g. because another process wrote to it), the wallet is reloaded from disk into memory before
    ///    continuing, preventing the clobbering of concurrent changes.
    ///
    /// 5. **Atomic Isolation (Cloning):**
    ///    Clones the current `Wallet` state. The closure `f` operates exclusively on this isolated, temporary clone.
    ///    If the transaction is aborted or rolls back, the original state is preserved and restored.
    ///
    /// 6. **Closure Execution:**
    ///    Invokes the provided closure `f`, yielding a [`TransactionOutcome`].
    ///
    /// 7. **Outcome Evaluation:**
    ///    - [`TransactionOutcome::Commit`]: Saves the mutated clone to disk, updates the active memory state,
    ///      recomputes/updates the cryptographic `WalletSeal` to guarantee integrity, and returns the result.
    ///      If persistence fails during the save operation, it safely rolls back to the original unmodified state.
    ///      
    ///    - [`TransactionOutcome::CommitAndReturnError`]: Saves the mutated clone to disk and updates the active
    ///      memory state/seal, but still returns the application-level error. This is crucial for self-healing
    ///      actions where we want to persist structural corrections even if a specific logic query failed.
    ///      If save fails, it also falls back to the original memory state.
    ///      
    ///    - [`TransactionOutcome::Rollback`]: Instantly discards the mutated clone, restores the original
    ///      unmodified state in memory, and returns the error without writing any changes to disk or updating the seal.
    ///
    /// # Errors
    ///
    /// Returns an [`AppFacadeError`] if:
    /// - The wallet is locked ([`AppFacadeError::WalletLocked`])
    /// - The fork-lock check fails
    /// - Authentication fails (e.g. session expired or wrong password)
    /// - Reloading or saving the wallet storage fails
    /// - The closure itself returns a failure outcome
    pub(super) fn with_transactional_mut<F, R>(
        &mut self,
        password: Option<&str>,
        f: F,
    ) -> Result<R, AppFacadeError>
    where
        F: FnOnce(
            &mut Wallet,
            &UserIdentity,
            &mut FileStorage,
            &crate::storage::AuthMethod,
        ) -> TransactionOutcome<R, AppFacadeError>,
    {
        // 1. Check fork-lock
        self.check_fork_lock(password).map_err(AppFacadeError::from)?;

        // 2. Unpack state (temporarily replace with Locked)
        let old_state = std::mem::replace(&mut self.state, AppState::Locked);

        match old_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // 3. Request file-lock (RAII)
                let _lock =
                    crate::storage::WalletLockGuard::new(&storage).map_err(AppFacadeError::from)?;

                // 4. Resolve authentication
                let auth = match Self::resolve_auth_method(password, &session_cache) {
                    Ok(a) => a,
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::from(e));
                    }
                };

                // NEW: Check if our RAM state is up to date (Reload-Before-Write)
                let mut current_wallet = wallet;
                let disk_generation = match storage.read_generation() {
                    Ok(gen_val) => gen_val,
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet: current_wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::from(e));
                    }
                };

                if disk_generation != current_wallet.loaded_generation {
                    let local_instance_id = current_wallet.local_instance_id.clone();
                    match Wallet::load(&storage, &auth, local_instance_id) {
                        Ok((fresh_wallet, _)) => {
                            current_wallet = fresh_wallet;
                        }
                        Err(e) => {
                            self.state = AppState::Unlocked {
                                storage,
                                wallet: current_wallet,
                                identity,
                                session_cache,
                            };
                            return Err(AppFacadeError::ValidationError(format!("Failed to reload wallet: {}", e)));
                        }
                    }
                }

                // 5. Establish atomicity (cloning)
                let mut temp_wallet = current_wallet.clone();

                // 6. Execute closure
                let outcome = f(&mut temp_wallet, &identity, &mut storage, &auth);

                // 7. Evaluate outcome
                match outcome {
                    TransactionOutcome::Commit(res) => {
                        if let Err(e) = temp_wallet.save(&mut storage, &identity, &auth) {
                            self.state = AppState::Unlocked {
                                storage,
                                wallet: current_wallet,
                                identity,
                                session_cache,
                            };
                            return Err(AppFacadeError::from(e));
                        }
                        self.state = AppState::Unlocked {
                            storage,
                            wallet: temp_wallet,
                            identity,
                            session_cache,
                        };
                        self.update_seal_after_state_change(password)?;
                        Ok(res)
                    }
                    TransactionOutcome::CommitAndReturnError(err) => {
                        if let Err(e) = temp_wallet.save(&mut storage, &identity, &auth) {
                            self.state = AppState::Unlocked {
                                storage,
                                wallet: current_wallet,
                                identity,
                                session_cache,
                            };
                            return Err(AppFacadeError::from(e));
                        }
                        self.state = AppState::Unlocked {
                            storage,
                            wallet: temp_wallet,
                            identity,
                            session_cache,
                        };
                        self.update_seal_after_state_change(password)?;
                        Err(err)
                    }
                    TransactionOutcome::Rollback(err) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet: current_wallet,
                            identity,
                            session_cache,
                        };
                        Err(err)
                    }
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("AppService is locked.".to_string())),
        }
    }

    /// Checks the "Remember password" session, manages the timeout
    /// and the "sliding window" (resets 'last_activity').
    pub fn get_session_key(&mut self) -> Result<[u8; 32], AppFacadeError> {
        match &mut self.state {
            AppState::Unlocked {
                storage: _,
                wallet: _,
                identity: _,
                session_cache,
            } => {
                if let Some(cache) = session_cache {
                    let now = Instant::now();
                    if now > cache.last_activity + cache.session_duration {
                        // --- Timeout! ---
                        *session_cache = None; // Clear key
                        Err(AppFacadeError::SessionExpired("Session timed out. Please provide password.".to_string()))
                    } else {
                        // --- OK, activity detected ---
                        cache.last_activity = now; // "Sliding Window"
                        Ok(cache.session_key)
                    }
                } else {
                    Err(AppFacadeError::SessionNotActive("Password required. Please use 'unlock_session'.".to_string()))
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Checks if a "Remember password" session is currently active,
    /// without resetting the inactivity timer.
    pub fn is_session_active(&self) -> bool {
        match &self.state {
            AppState::Unlocked {
                session_cache: Some(cache),
                ..
            } => {
                let now = std::time::Instant::now();
                now <= cache.last_activity + cache.session_duration
            }
            _ => false,
        }
    }
}

// --- Internal helper methods for tests ---
// `#[cfg(debug_assertions)]`, so that these functions are visible for integration tests
// (e.g., in `tests/wallet_api/`), but not in release builds.
#[cfg(debug_assertions)]
impl AppService {
    /// Adds a voucher *directly* to the in-memory wallet state and
    /// ONLY FOR TESTS.
    pub fn get_wallet_for_test(&self) -> Option<&crate::wallet::Wallet> {
        if let AppState::Unlocked { wallet, .. } = &self.state {
            Some(wallet)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the internal wallet.
    /// ONLY FOR TESTS.
    pub fn get_wallet_mut(&mut self) -> Option<&mut crate::wallet::Wallet> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            Some(wallet)
        } else {
            None
        }
    }

    /// A helper method only for tests to get access to the internal identity.
    #[doc(hidden)]
    pub fn get_unlocked_mut_for_test(&mut self) -> (&mut Wallet, &UserIdentity) {
        match &mut self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => panic!("Service must be unlocked for this test helper"),
        }
    }
}

