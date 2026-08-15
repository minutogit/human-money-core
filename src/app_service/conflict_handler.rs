//! # src/app_service/conflict_handler.rs
//!
//! Contains all `AppService` functions related to the management of
//! double-spend conflicts.

use super::{AppService, AppState, AppFacadeError};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::wallet::CleanupReport;

impl AppService {
    // --- Conflict Management ---

    /// Returns a list of summaries of all known double-spend conflicts.
    ///
    /// # Errors
    /// Fails if the wallet is locked (`Locked`).
    pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, AppFacadeError> {
        Ok(self.get_wallet()?.list_conflicts())
    }

    /// Retrieves a complete `ProofOfDoubleSpend` by its ID.
    ///
    /// Ideal for displaying the details of a conflict or exporting it for
    /// manual exchange.
    ///
    /// # Errors
    /// Fails if the wallet is locked or no proof with this ID exists.
    pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, AppFacadeError> {
        self.get_wallet()?
            .get_proof_of_double_spend(proof_id)
            .map_err(AppFacadeError::from)
    }

    /// Creates a signed resolution endorsement (`ResolutionEndorsement`) for a conflict.
    ///
    /// This operation does not change the wallet state. It generates a
    /// signed object that can be sent to other parties to signal that
    /// the conflict has been resolved from the perspective of the wallet owner (the victim).
    ///
    /// # Errors
    /// Fails if the wallet is locked or the referenced proof does not exist.
    pub fn create_resolution_endorsement(
        &self,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, AppFacadeError> {
        match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => wallet
                .create_resolution_endorsement(identity, proof_id, notes)
                .map_err(AppFacadeError::from),
            AppState::Locked => Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())),
        }
    }

    /// Sets the local override for a specific conflict.
    ///
    /// # Errors
    /// Fails if the wallet is locked or the proof does not exist.
    pub fn set_conflict_local_override(
        &mut self,
        proof_id: &str,
        value: bool,
        note: Option<String>,
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        // --- FORK-LOCK CHECK ---
        self.check_fork_lock(password).map_err(AppFacadeError::from)?;

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        if let AppState::Unlocked { mut storage, wallet, identity, mut session_cache } = current_state {
            let _lock_guard = match crate::storage::WalletLockGuard::new(&storage) {
                Ok(guard) => guard,
                Err(e) => {
                    self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                    return Err(AppFacadeError::from(e));
                }
            };

            let mut temp_wallet = wallet;
            if let Err(e) = temp_wallet.set_conflict_local_override(proof_id, value, note) {
                self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                return Err(AppFacadeError::from(e));
            }

            let auth_method = match password {
                Some(pwd_str) => crate::storage::AuthMethod::Password(pwd_str),
                None => {
                    match &mut session_cache {
                        Some(cache) => {
                            if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                                self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                                return Err(AppFacadeError::SessionExpired("Session timed out or password required.".to_string()));
                            } else {
                                cache.last_activity = std::time::Instant::now();
                                crate::storage::AuthMethod::SessionKey(cache.session_key)
                            }
                        }
                        None => {
                            self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                            return Err(AppFacadeError::SessionNotActive("Session timed out or password required.".to_string()));
                        }
                    }
                }
            };

            let save_result = temp_wallet.save(&mut storage, &identity, &auth_method);
            self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
            save_result.map_err(AppFacadeError::from)
        } else {
            self.state = current_state;
            Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()))
        }
    }

    /// Imports a proof directly as an object.
    pub fn import_proof(&mut self, proof: ProofOfDoubleSpend, password: Option<&str>) -> Result<(), AppFacadeError> {
        // --- FORK-LOCK CHECK ---
        self.check_fork_lock(password).map_err(AppFacadeError::from)?;

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        if let AppState::Unlocked { mut storage, wallet, identity, mut session_cache } = current_state {
            let _lock_guard = match crate::storage::WalletLockGuard::new(&storage) {
                Ok(guard) => guard,
                Err(e) => {
                    self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                    return Err(AppFacadeError::from(e));
                }
            };

            let mut temp_wallet = wallet;
            if let Err(e) = temp_wallet.import_proof(proof) {
                self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                return Err(AppFacadeError::from(e));
            }

            let auth_method = match password {
                Some(pwd_str) => crate::storage::AuthMethod::Password(pwd_str),
                None => {
                    match &mut session_cache {
                        Some(cache) => {
                            if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                                self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                                return Err(AppFacadeError::SessionExpired("Session timed out or password required.".to_string()));
                            } else {
                                cache.last_activity = std::time::Instant::now();
                                crate::storage::AuthMethod::SessionKey(cache.session_key)
                            }
                        }
                        None => {
                            self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
                            return Err(AppFacadeError::SessionNotActive("Session timed out or password required.".to_string()));
                        }
                    }
                }
            };

            let save_result = temp_wallet.save(&mut storage, &identity, &auth_method);
            self.state = AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache };
            save_result.map_err(AppFacadeError::from)
        } else {
            self.state = current_state;
            Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()))
        }
    }

    /// Imports a proof from a Base64-encoded JSON string (plain text export).
    pub fn import_proof_from_json(&mut self, json_base64: &str, password: Option<&str>) -> Result<(), AppFacadeError> {
        let json_bytes = bs58::decode(json_base64)
            .into_vec()
            .map_err(|e| AppFacadeError::ValidationError(format!("Invalid base64 encoding: {}", e)))?;
        let proof: ProofOfDoubleSpend =
            serde_json::from_slice(&json_bytes).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;

        self.import_proof(proof, password)
    }

    /// Imports a proof from a `SecureContainer` (secure exchange).
    pub fn import_proof_from_container(&mut self, container_bytes: &[u8], password: Option<&str>) -> Result<(), AppFacadeError> {
        let proof = {
            if let AppState::Unlocked { identity, .. } = &self.state {
                let container: crate::models::secure_container::SecureContainer =
                    serde_json::from_slice(container_bytes).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;

                if container.c != crate::models::secure_container::PayloadType::ProofOfDoubleSpend {
                    return Err(AppFacadeError::ValidationError("Container does not contain a Double-Spend-Proof.".to_string()));
                }

                // Wallet identity is required to open the container
                let decrypted_payload = crate::services::secure_container_manager::open_secure_container(
                    &container,
                    identity,
                    None,
                )
                .map_err(AppFacadeError::from)?;

                let parsed_proof: ProofOfDoubleSpend =
                    serde_json::from_slice(&decrypted_payload).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;
                
                parsed_proof
            } else {
                return Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()));
            }
        };

        self.import_proof(proof, password)
    }

    /// Performs storage cleanup for fingerprints and their metadata.
    ///
    /// This method implements the logic defined in the architecture specification:
    /// 1. Delete all expired fingerprints.
    /// 2. If the storage limit (`MAX_FINGERPRINTS`) is still exceeded,
    ///    fingerprints with the highest `depth` (and oldest `t_time`)
    ///    are deleted until the limit is no longer exceeded.
    ///
    /// # Returns
    /// A `Result` with a `CleanupReport` containing details about the cleanup,
    /// or an error if the process fails.
    pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, AppFacadeError> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            let report = wallet.run_storage_cleanup(None, super::DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS)?;
            // Note: Saving the wallet after cleanup is left to the caller
            // (e.g. at the end of an operation) to avoid multiple writes.
            Ok(report)
        } else {
            Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string()))
        }
    }

    /// Finds the associated double-spend conflict proof ID for a voucher using cascading match strategies.
    ///
    /// # Errors
    /// Returns an error if the wallet is locked.
    pub fn get_proof_id_for_voucher(&self, local_id: &str) -> Result<Option<String>, AppFacadeError> {
        Ok(self.get_wallet()?.get_proof_id_for_voucher(local_id))
    }
}

