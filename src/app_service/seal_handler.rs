//! # src/app_service/seal_handler.rs
//!
//! Enthält die WalletSeal-Orchestrierungslogik des `AppService`.
//! Verwaltet den Lebenszyklus des Siegels, das lokale Sync-Tracking
//! und die Fork-Erkennung mit Hard Lock.

use super::{AppService, AppState};
use crate::error::VoucherCoreError;
use crate::models::seal::{SealSyncState, SyncStatus, WalletSeal};
use crate::services::integrity_manager::IntegrityManager;
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage};

impl AppService {
    /// Prüft die Integrität aller Speicher-Items gegen den Storage Integrity Record.
    ///
    /// # Arguments
    /// * `password` - Optional, für die Authentifizierung.
    pub fn check_integrity(
        &mut self,
        password: Option<&str>,
    ) -> Result<crate::models::storage_integrity::IntegrityReport, String> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = match Self::resolve_auth(password, session_cache) {
                    Ok(a) => a,
                    Err(e) => return Err(e.to_string()),
                };

                let integrity_record = storage.load_integrity("").map_err(|e| e.to_string())?;
                let seal_record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(|e| e.to_string())?;

                match (integrity_record, seal_record) {
                    (Some(ir), Some(s)) => {
                        let actual_hashes = storage.get_all_item_hashes().map_err(|e| e.to_string())?;
                        IntegrityManager::verify_integrity(
                            &ir,
                            &s.seal,
                            actual_hashes,
                            &identity.user_id,
                        )
                        .map_err(|e| e.to_string())
                    }
                    (None, Some(_)) => Ok(crate::models::storage_integrity::IntegrityReport::MissingIntegrityRecord),
                    (Some(_), None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Sollte nicht vorkommen
                    (None, None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Migration
                }
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Repariert den Storage Integrity Record, indem der aktuelle Zustand der Dateien als "korrekt" akzeptiert wird.
    ///
    /// Diese Methode sollte nur aufgerufen werden, wenn der Nutzer die Integritätswarnung
    /// explizit bestätigt hat (z.B. "OK, ich akzeptiere diese Änderungen").
    /// Erzeugt einen neuen, signierten Integrity Record für alle aktuell vorhandenen Datensätze.
    ///
    /// # Arguments
    /// * `password` - Optional, für die Authentifizierung.
    pub fn repair_integrity(&mut self, password: Option<&str>) -> Result<(), String> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity,
                session_cache,
                ..
            } => {
                let auth = match Self::resolve_auth(password, session_cache) {
                    Ok(a) => a,
                    Err(e) => return Err(e.to_string()),
                };

                // 1. Aktuelles Siegel laden (Basispunkt für den Integrity Record)
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| "No seal found. Cannot repair integrity without seal.".to_string())?;

                // 2. Aktuelle Hashes von der Platte lesen
                let hashes = storage.get_all_item_hashes().map_err(|e| e.to_string())?;

                // 3. Neuen Integrity Record erstellen
                let integrity_record = IntegrityManager::create_integrity_record(
                    identity,
                    &record.seal,
                    hashes,
                ).map_err(|e| e.to_string())?;

                // 4. Speichern
                storage
                    .save_integrity(&identity.user_id, &integrity_record)
                    .map_err(|e| e.to_string())?;

                Ok(())
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    // --- B) Lokales Sync-Tracking (Upload-Workflow für Client-Apps) ---

    /// Gibt den aktuellen Sync-Status des lokalen Siegels zurück.
    pub fn get_seal_sync_status(&self) -> Result<SyncStatus, String> {
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
                    .map_err(|e| e.to_string())?;

                match record {
                    Some(r) => Ok(r.sync_status),
                    None => Err("No seal found. Recovery may be required.".to_string()),
                }
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Liefert das reine `WalletSeal` (ohne Metadaten!) als JSON-Byte-Array für den Upload.
    pub fn get_seal_for_upload(&self) -> Result<Option<Vec<u8>>, String> {
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
                    .map_err(|e| e.to_string())?;

                match record {
                    Some(r) => match r.sync_status {
                        SyncStatus::PendingUpload => {
                            let seal_bytes = serde_json::to_vec(&r.seal)
                                .map_err(|e| format!("Failed to serialize seal: {}", e))?;
                            Ok(Some(seal_bytes))
                        }
                        SyncStatus::Synced => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }

    /// Bestätigt den erfolgreichen Upload eines Siegels an den Server.
    pub fn acknowledge_seal_sync(
        &mut self,
        uploaded_seal_hash: &str,
        password: Option<&str>,
    ) -> Result<(), VoucherCoreError> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let auth_method = Self::resolve_auth(password, &session_cache)?;

                let record_opt = storage
                    .load_seal(&identity.user_id, &auth_method)
                    .map_err(VoucherCoreError::Storage)?;

                match record_opt {
                    Some(mut record) => {
                        let current_hash = SealManager::compute_seal_hash(&record.seal)?;

                        if current_hash != uploaded_seal_hash {
                            (
                                Err(VoucherCoreError::SealSyncRaceCondition),
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
                                    Err(VoucherCoreError::Storage(e)),
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
                        Err(VoucherCoreError::RequiresSealRecovery),
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
                Err(VoucherCoreError::Generic("Wallet is locked.".to_string())),
                AppState::Locked,
            ),
        };

        self.state = new_state;
        result
    }

    // --- C) Remote Sync Prüfung & Hard Lock ---

    /// Vergleicht ein vom Server heruntergeladenes Siegel mit dem lokalen Siegel.
    pub fn compare_remote_seal(
        &mut self,
        remote_seal_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<SealSyncState, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let auth_method = match Self::resolve_auth(password, &session_cache) {
                    Ok(a) => a,
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e.to_string());
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
                        return Err(format!("Failed to parse remote seal: {}", e));
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
                        // Remote-Siegel von anderem Gerät ist für Vergleich OK (Indikator für Fork-Check)
                    },
                    Ok(other) => {
                         self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(format!("Remote seal integrity check failed: {:?}", other));
                    },
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(format!("Remote seal verification error: {}", e));
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
                        return Err("No local seal found. Recovery required.".to_string());
                    }
                    Err(e) => {
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(format!("Failed to load local seal: {}", e));
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
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };

        self.state = new_state;
        result
    }

    // --- Interne Hilfsmethoden ---

    fn get_read_auth(
        &self,
        session_cache: &Option<super::SessionCache>,
    ) -> Result<AuthMethod<'_>, String> {
        match session_cache {
            Some(cache) => {
                if cache.last_activity.elapsed() > cache.session_duration {
                    Err("Session timed out. Please provide password.".to_string())
                } else {
                    Ok(AuthMethod::SessionKey(cache.session_key))
                }
            }
            None => Err("Password required. Please use 'unlock_session'.".to_string()),
        }
    }

    fn resolve_auth<'a>(
        password: Option<&'a str>,
        session_cache: &Option<super::SessionCache>,
    ) -> Result<AuthMethod<'a>, VoucherCoreError> {
        match password {
            Some(pwd) => Ok(AuthMethod::Password(pwd)),
            None => match session_cache {
                Some(cache) => {
                    if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                        Err(VoucherCoreError::Generic(
                            "Session timed out. Please provide password.".to_string(),
                        ))
                    } else {
                        Ok(AuthMethod::SessionKey(cache.session_key))
                    }
                }
                None => Err(VoucherCoreError::Generic(
                    "Password required. Please use 'unlock_session'.".to_string(),
                )),
            },
        }
    }

    pub(crate) fn check_fork_lock(&self, password: Option<&str>) -> Result<(), VoucherCoreError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth(password, session_cache)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(VoucherCoreError::Storage)?;

                match record {
                    Some(r) if r.is_locked_due_to_fork => Err(VoucherCoreError::WalletLockedDueToFork),
                    _ => Ok(()),
                }
            }
            AppState::Locked => Err(VoucherCoreError::Generic("Wallet is locked.".to_string())),
        }
    }

    pub(crate) fn get_epoch_info(
        &self,
        password: Option<&str>,
    ) -> Result<Option<(String, u32)>, VoucherCoreError> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth(password, session_cache)?;
                let record = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(VoucherCoreError::Storage)?;

                match record {
                    Some(r) => Ok(Some((
                        r.seal.payload.epoch_start_time.clone(),
                        r.seal.payload.epoch,
                    ))),
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(VoucherCoreError::Generic("Wallet is locked.".to_string())),
        }
    }

    pub(crate) fn update_seal_after_state_change(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), String> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                session_cache,
                ..
            } => {
                let auth = match Self::resolve_auth(password, session_cache) {
                    Ok(a) => a,
                    Err(e) => return Err(e.to_string()),
                };

                let record_opt = storage
                    .load_seal(&identity.user_id, &auth)
                    .map_err(|e| e.to_string())?;

                let current_state_hash = {
                    let canonical =
                        crate::services::utils::to_canonical_json(&wallet.own_fingerprints)
                            .map_err(|e| e.to_string())?;
                    crate::services::crypto_utils::get_hash(canonical.as_bytes())
                };

                let updated_seal = match record_opt {
                    Some(mut record) => {
                        let seal = SealManager::update_seal(
                            &record.seal,
                            identity,
                            &current_state_hash,
                            &wallet.local_instance_id,
                        )
                        .map_err(|e| e.to_string())?;

                        record.seal = seal.clone();
                        record.sync_status = SyncStatus::PendingUpload;

                        storage
                            .save_seal(&identity.user_id, &auth, &record)
                            .map_err(|e| e.to_string())?;
                        seal
                    }
                    None => {
                        let seal = SealManager::create_initial_seal(
                            &identity.user_id,
                            identity,
                            &current_state_hash,
                            &wallet.local_instance_id,
                        )
                        .map_err(|e| e.to_string())?;

                        let new_record = crate::models::seal::LocalSealRecord {
                            seal: seal.clone(),
                            sync_status: SyncStatus::PendingUpload,
                            is_locked_due_to_fork: false,
                        };
                        storage
                            .save_seal(&identity.user_id, &auth, &new_record)
                            .map_err(|e| e.to_string())?;
                        seal
                    }
                };

                // --- INTEGRITY UPDATE ---
                let item_hashes = storage.get_all_item_hashes().map_err(|e| e.to_string())?;
                let integrity_record = IntegrityManager::create_integrity_record(
                    identity,
                    &updated_seal,
                    item_hashes,
                )
                .map_err(|e| e.to_string())?;

                storage
                    .save_integrity(&identity.user_id, &integrity_record)
                    .map_err(|e| e.to_string())?;

                Ok(())
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}
