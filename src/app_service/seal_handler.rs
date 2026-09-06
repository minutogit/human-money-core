//! # src/app_service/seal_handler.rs
//!
//! Contains the WalletSeal orchestration logic of the `AppService`.
//! Manages the lifecycle of the seal, local sync tracking,
//! and fork detection with Hard Lock.

use super::{AppService, AppState, AppFacadeError};
use crate::error::VoucherCoreError;
use crate::models::seal::{LocalSealRecord, SealSyncState, SyncStatus, WalletSeal};
use crate::services::integrity_manager::IntegrityManager;
use crate::services::seal_manager::SealManager;
use crate::storage::file_storage::FileStorage;
use crate::storage::{AuthMethod, Storage};
use crate::services::crypto_utils::get_hash;

impl AppService {
    /// Checks the integrity of all storage items against the Storage Integrity Record.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn check_integrity(
        &mut self,
        password: Option<&str>,
    ) -> Result<crate::models::storage_integrity::IntegrityReport, AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)
                    .map_err(AppFacadeError::from)?;

                let integrity_record = storage.load_integrity("").map_err(AppFacadeError::from)?;
                let seal_record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?;

                match (integrity_record, seal_record) {
                    (Some(ir), Some(s)) => {
                        let actual_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
                        IntegrityManager::verify_integrity(
                            &ir,
                            &s.seal,
                            actual_hashes,
                            &identity.user_id,
                        )
                        .map_err(AppFacadeError::from)
                    }
                    (None, Some(_)) => Ok(crate::models::storage_integrity::IntegrityReport::MissingIntegrityRecord),
                    (Some(_), None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Should not happen
                    (None, None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Migration
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Repairs the Storage Integrity Record by accepting the current state of the files as "correct".
    ///
    /// This method should only be called if the user has explicitly confirmed the integrity
    /// warning (e.g., "OK, I accept these changes").
    /// Creates a new, signed Integrity Record for all currently existing records.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn repair_integrity(&mut self, password: Option<&str>) -> Result<(), AppFacadeError> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)
                    .map_err(AppFacadeError::from)?;

                // 1. Load current seal (base point for the integrity record)
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?
                    .ok_or_else(|| AppFacadeError::ValidationError("No seal found. Cannot repair integrity without seal.".to_string()))?;

                // 2. Read current hashes from disk
                let hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;

                // 3. Create a new integrity record
                let integrity_record = IntegrityManager::create_integrity_record(
                    identity,
                    &record.seal,
                    hashes,
                ).map_err(AppFacadeError::from)?;

                // 4. Save
                storage
                    .save_integrity(&identity.user_id, &integrity_record)
                    .map_err(AppFacadeError::from)?;

                Ok(())
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    // --- B) Local Sync Tracking (Upload Workflow for Client Apps) ---

    /// Returns the current sync status of the local seal.
    pub fn get_seal_sync_status(&self) -> Result<SyncStatus, AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?;

                match record {
                    Some(r) => Ok(r.sync_status),
                    None => Err(AppFacadeError::ValidationError("No seal found. Recovery may be required.".to_string())),
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Returns the raw `WalletSeal` (without metadata!) as a JSON byte array for upload.
    pub fn get_seal_for_upload(&self) -> Result<Option<Vec<u8>>, AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?;

                match record {
                    Some(r) => match r.sync_status {
                        SyncStatus::PendingUpload => {
                            let seal_bytes = serde_json::to_vec(&r.seal)
                                .map_err(|e| AppFacadeError::JsonError(format!("Failed to serialize seal: {}", e)))?;
                            Ok(Some(seal_bytes))
                        }
                        SyncStatus::Synced => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Acknowledges the successful upload of a seal to the server.
    pub fn acknowledge_seal_sync(
        &mut self,
        uploaded_seal_hash: &str,
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let auth_method = match Self::resolve_auth_method(password, &session_cache) {
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

                let record_opt = match storage
                    .load_seal(&identity.user_id, &auth_method)
                    .map_err(AppFacadeError::from) {
                        Ok(r) => r,
                        Err(e) => {
                            self.state = AppState::Unlocked {
                                storage,
                                wallet,
                                identity,
                                session_cache,
                            };
                            return Err(e);
                        }
                    };

                match record_opt {
                    Some(mut record) => {
                        let current_hash = match SealManager::compute_seal_hash(&record.seal).map_err(AppFacadeError::from) {
                            Ok(h) => h,
                            Err(e) => {
                                self.state = AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                };
                                return Err(e);
                            }
                        };

                        if current_hash != uploaded_seal_hash {
                            (
                                Err(AppFacadeError::from(VoucherCoreError::SealSyncRaceCondition)),
                                AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                },
                            )
                        } else {
                            record.sync_status = SyncStatus::Synced;
                            match storage.save_seal(&identity.user_id, &auth_method, &record) {
                                Ok(_) => {
                                    (
                                        Ok(()),
                                        AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        },
                                    )
                                }
                                Err(e) => (
                                    Err(AppFacadeError::from(e)),
                                    AppState::Unlocked {
                                        storage,
                                        wallet,
                                        identity,
                                        session_cache,
                                    },
                                ),
                            }
                        }
                    }
                    None => (
                        Err(AppFacadeError::from(VoucherCoreError::RequiresSealRecovery)),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                }
            }
            AppState::Locked => (
                Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
                AppState::Locked,
            ),
        };

        self.state = new_state;
        result
    }

    // --- C) Remote Sync Check & Hard Lock ---

    /// Compares a seal downloaded from the server with the local seal.
    pub fn compare_remote_seal(
        &mut self,
        remote_seal_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<SealSyncState, AppFacadeError> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let auth_method = match Self::resolve_auth_method(password, &session_cache) {
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

                let remote_seal: WalletSeal = match serde_json::from_slice(remote_seal_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::JsonError(format!("Failed to parse remote seal: {}", e)));
                    }
                };

                match SealManager::verify_seal_integrity(
                    &remote_seal,
                    &identity.user_id,
                    &identity.user_id,
                    &wallet.local_instance_id,
                ) {
                    Ok(crate::models::seal::SealValidationResult::Valid) => {},
                    Ok(crate::models::seal::SealValidationResult::LegacyValid) => {},
                    Ok(crate::models::seal::SealValidationResult::DeviceMismatch { .. }) => {
                        // Remote seal from other device is OK for comparison (indicator for fork check)
                    },
                    Ok(other) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::ValidationError(format!("Remote seal integrity check failed: {:?}", other)));
                    },
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::from(e));
                    }
                }

                let record = match storage.load_seal(&identity.user_id, &auth_method) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(AppFacadeError::ValidationError("No local seal found. Recovery required.".to_string()));
                    }
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

                let sync_state = SealManager::compare_seals(&record.seal, &remote_seal);

                if sync_state == SealSyncState::ForkDetected {
                    let mut locked_record = record;
                    locked_record.is_locked_due_to_fork = true;
                    let _ = storage.save_seal(&identity.user_id, &auth_method, &locked_record);
                }

                (
                    Ok(sync_state),
                    AppState::Unlocked {
                        storage,
                        wallet,
                        identity,
                        session_cache,
                    },
                )
            }
            AppState::Locked => (Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())), AppState::Locked),
        };

        self.state = new_state;
        result
    }

    // --- Internal helper methods ---

    fn get_read_auth(
        &self,
        session_cache: &Option<super::SessionCache>,
    ) -> Result<AuthMethod<'_>, AppFacadeError> {
        match session_cache {
            Some(cache) => {
                if cache.last_activity.elapsed() > cache.session_duration {
                    Err(AppFacadeError::SessionExpired("Session timed out. Please provide password.".to_string()))
                } else {
                    Ok(AuthMethod::SessionKey(cache.session_key))
                }
            }
            None => Err(AppFacadeError::SessionNotActive("Password required. Please use 'unlock_session'.".to_string())),
        }
    }

    pub(super) fn verify_seal_on_login(
        storage: &FileStorage,
        password: &str,
        local_instance_id: &str,
    ) -> Result<bool, AppFacadeError> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage.load_seal("", &auth).ok().flatten();

        if let Some(record) = &seal_record {
            // Check fork lock
            if record.is_locked_due_to_fork {
                return Err(AppFacadeError::WalletLockedDueToFork("Security Lockdown: Wallet is locked due to a detected fork. Recovery required.".to_string()));
            }

            // Check seal integrity and instance ID
            let validation = SealManager::verify_seal_integrity(
                &record.seal,
                &record.seal.payload.user_id,
                &record.seal.payload.user_id,
                local_instance_id,
            )
            .map_err(AppFacadeError::from)?;

            match validation {
                crate::models::seal::SealValidationResult::Valid => {}
                crate::models::seal::SealValidationResult::LegacyValid => {
                    println!("Legacy Wallet detected. Will bind to this device after login.");
                    return Ok(true); // needs_legacy_binding = true
                }
                crate::models::seal::SealValidationResult::DeviceMismatch { expected, actual } => {
                    let err_msg = format!(
                        "Device Mismatch: This wallet is bound to device '{}', but you are on '{}'. \
                        To prevent double-spending and permanent reputation loss, a wallet profile (specific User Prefix) \
                        must only be active on ONE device at a time.\n\n\
                        - OPTION A (Move): Perform a 'Device Handover' to permanently move the wallet here. \
                        IMPORTANT: Once handed over, you MUST NOT use this profile on the old device anymore. Please delete the wallet folder on the old device to prevent accidental usage.\n\
                        - OPTION B (Concurrent): Create a NEW profile on this device \
                        with the same Seed Phrase but a DIFFERENT 'User Prefix', then transfer vouchers between them.",
                        expected, actual
                    );
                    return Err(AppFacadeError::ValidationError(err_msg));
                }
                other => {
                    return Err(AppFacadeError::ValidationError(format!("Seal integrity check failed: {:?}", other)));
                }
            }

            // Load the RAW own_fingerprints store directly from storage
            let raw_own_fingerprints = storage
                .load_own_fingerprints("", &auth)
                .map_err(AppFacadeError::from)?;

            let current_state_hash = {
                let canonical = crate::services::utils::to_canonical_json(&raw_own_fingerprints)
                    .map_err(AppFacadeError::from)?;
                get_hash(canonical.as_bytes())
            };

            if record.seal.payload.state_hash != current_state_hash {
                return Err(AppFacadeError::StateRollbackDetected("Critical Error: Wallet state does not match the security seal. Possible rollback or corruption detected. Recovery required.".to_string()));
            }
        }
        Ok(false)
    }

    pub(super) fn migrate_seal_on_login(
        storage: &mut FileStorage,
        wallet: &crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        password: &str,
        needs_legacy_binding: bool,
    ) -> Result<(), AppFacadeError> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage
            .load_seal(&identity.user_id, &auth)
            .map_err(AppFacadeError::from)?;

        // Only migrate if necessary (legacy binding or no seal present)
        if needs_legacy_binding || seal_record.is_none() {
            let state_hash = {
                let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                    .map_err(AppFacadeError::from)?;
                get_hash(canonical.as_bytes())
            };

            let migrated_seal = if needs_legacy_binding && seal_record.is_some() {
                // Legacy Migration: Update existing seal to preserve the tx_nonce
                let existing_record = seal_record.unwrap();
                SealManager::update_seal(
                    &existing_record.seal,
                    identity,
                    &state_hash,
                    &wallet.local_instance_id,
                )
                .map_err(AppFacadeError::from)?
            } else {
                // Completely new seal (Genesis)
                SealManager::create_initial_seal(
                    &identity.user_id,
                    identity,
                    &state_hash,
                    &wallet.local_instance_id,
                )
                .map_err(AppFacadeError::from)?
            };

            let new_record = LocalSealRecord {
                seal: migrated_seal.clone(),
                sync_status: SyncStatus::PendingUpload,
                is_locked_due_to_fork: false,
            };
            storage
                .save_seal(&identity.user_id, &auth, &new_record)
                .map_err(AppFacadeError::from)?;

            // Initialize integrity for the new migrated seal
            let hashes = storage.get_all_item_hashes().unwrap_or_default();
            if let Ok(ir) = crate::services::integrity_manager::IntegrityManager::create_integrity_record(
                identity,
                &migrated_seal,
                hashes,
            ) {
                let _ = storage.save_integrity(&identity.user_id, &ir);
            }
        }
        Ok(())
    }

    pub(crate) fn check_fork_lock(&self, password: Option<&str>) -> Result<(), AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)
                    .map_err(AppFacadeError::from)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?;

                match record {
                    Some(r) if r.is_locked_due_to_fork => Err(AppFacadeError::WalletLockedDueToFork("Security Lockdown: Wallet is locked due to a detected fork. Recovery required.".to_string())),
                    _ => Ok(()),
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    pub(crate) fn get_epoch_info(
        &self,
        password: Option<&str>,
    ) -> Result<Option<(String, u32)>, AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)
                    .map_err(AppFacadeError::from)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(AppFacadeError::from)?;

                match record {
                    Some(r) => Ok(Some((
                        r.seal.payload.epoch_start_time.clone(),
                        r.seal.payload.epoch,
                    ))),
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Verifies that a freshly loaded wallet state is covered by the current
    /// cryptographic seal before it may be operated on.
    ///
    /// This is the same state-hash discipline as [`Self::verify_seal_on_login`],
    /// applied to the mid-session "Reload-Before-Write" path: if an external
    /// writer (sync conflict, backup tooling) replaced the persisted stores,
    /// the reloaded state is only trusted when its own_fingerprints hash
    /// matches `seal.payload.state_hash`. Otherwise the command must fail hard
    /// instead of silently resurrecting spent vouchers. Wallets without a seal
    /// (legacy migration case) are exempt, mirroring login behavior.
    pub(crate) fn verify_state_matches_seal(
        storage: &FileStorage,
        auth: &crate::storage::AuthMethod<'_>,
        wallet: &crate::wallet::Wallet,
    ) -> Result<(), AppFacadeError> {
        let record_opt = storage
            .load_seal("", auth)
            .map_err(AppFacadeError::from)?;

        if let Some(record) = record_opt {
            let canonical = crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                .map_err(AppFacadeError::from)?;
            let current_state_hash = get_hash(canonical.as_bytes());

            if record.seal.payload.state_hash != current_state_hash {
                return Err(AppFacadeError::StateRollbackDetected(
                    "Reloaded wallet state does not match the security seal. \
                     Possible external rollback or corruption detected. Command rejected."
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn update_seal_after_state_change(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)
                    .map_err(AppFacadeError::from)?;
                Self::persist_seal_for_wallet_state(storage, identity, &auth, wallet)
            }
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Persists the WalletSeal and the Integrity Record for the given wallet
    /// state without touching the AppService's in-memory state.
    ///
    /// This is the pure storage-level core of
    /// [`Self::update_seal_after_state_change`], factored out so that the
    /// transactional orchestrator (`with_transactional_mut`) can advance the
    /// seal for a NOT-yet-published temporary wallet and compensate cleanly
    /// if this step fails after the wallet data was already persisted.
    pub(crate) fn persist_seal_for_wallet_state(
        storage: &mut FileStorage,
        identity: &crate::models::profile::UserIdentity,
        auth: &crate::storage::AuthMethod<'_>,
        wallet: &crate::wallet::Wallet,
    ) -> Result<(), AppFacadeError> {
        let record_opt = storage
            .load_seal(&identity.user_id, auth)
            .map_err(AppFacadeError::from)?;

        let current_state_hash = {
            let canonical =
                crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                    .map_err(AppFacadeError::from)?;
            get_hash(canonical.as_bytes())
        };

        let updated_seal = match record_opt {
            Some(mut record) => {
                let seal = SealManager::update_seal(
                    &record.seal,
                    identity,
                    &current_state_hash,
                    &wallet.local_instance_id,
                )
                .map_err(AppFacadeError::from)?;

                record.seal = seal.clone();
                record.sync_status = SyncStatus::PendingUpload;

                storage
                    .save_seal(&identity.user_id, auth, &record)
                    .map_err(AppFacadeError::from)?;
                seal
            }
            None => {
                let seal = SealManager::create_initial_seal(
                    &identity.user_id,
                    identity,
                    &current_state_hash,
                    &wallet.local_instance_id,
                )
                .map_err(AppFacadeError::from)?;

                let new_record = crate::models::seal::LocalSealRecord {
                    seal: seal.clone(),
                    sync_status: SyncStatus::PendingUpload,
                    is_locked_due_to_fork: false,
                };
                storage
                    .save_seal(&identity.user_id, auth, &new_record)
                    .map_err(AppFacadeError::from)?;
                seal
            }
        };

        // --- INTEGRITY UPDATE ---
        let item_hashes = storage.get_all_item_hashes().map_err(AppFacadeError::from)?;
        let integrity_record = IntegrityManager::create_integrity_record(
            identity,
            &updated_seal,
            item_hashes,
        )
        .map_err(AppFacadeError::from)?;

        storage
            .save_integrity(&identity.user_id, &integrity_record)
            .map_err(AppFacadeError::from)?;

        Ok(())
    }
}
