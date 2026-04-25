//! # src/app_service/seal_handler.rs
//!
//! Enthält die WalletSeal-Orchestrierungslogik des `AppService`.
//! Verwaltet den Lebenszyklus des Siegels, das lokale Sync-Tracking
//! und die Fork-Erkennung mit Hard Lock.

use super::{AppService, AppState};
use crate::error::VoucherCoreError;
use crate::models::seal::{SealSyncState, SyncStatus, WalletSeal};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage};

impl AppService {
    // --- B) Lokales Sync-Tracking (Upload-Workflow für Client-Apps) ---

    /// Gibt den aktuellen Sync-Status des lokalen Siegels zurück.
    ///
    /// Kann von der GUI verwendet werden, um ein "Synced" bzw.
    /// "Wartet auf Sync"-Icon anzuzeigen.
    ///
    /// # Returns
    /// - `Ok(SyncStatus)` bei Erfolg.
    /// - `Err` wenn das Wallet gesperrt ist oder kein Siegel existiert.
    pub fn get_seal_sync_status(&self) -> Result<SyncStatus, String> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                // Wir brauchen einen Auth-Kontext, um das Siegel zu laden.
                // Da dies ein reiner Lesezugriff ist, verwenden wir den Session-Key wenn vorhanden.
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

    /// Liefert das reine `WalletSeal` (ohne Metadaten!) als JSON-Byte-Array
    /// für den Upload an den Server.
    ///
    /// - Gibt `Ok(Some(bytes))` zurück, wenn der Status `PendingUpload` ist.
    /// - Gibt `Ok(None)` zurück, wenn der Status bereits `Synced` ist (nichts zu tun).
    ///
    /// # Wichtig
    /// Das Ergebnis enthält **nur** das innere `WalletSeal`, **nicht** den
    /// `LocalSealRecord`-Wrapper. Die GUI kann die Bytes sicher an den Server senden.
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
    ///
    /// # Race-Condition-Schutz
    /// Es muss zwingend der Hash des erfolgreich hochgeladenen Siegels übergeben werden.
    /// Der Core ändert den `sync_status` nur dann auf `Synced`, wenn der Hash exakt
    /// mit dem Hash des aktuellsten, lokalen Siegels übereinstimmt. Geschah während
    /// eines langsamen Uploads eine neue Transaktion (neues lokales Siegel), wird das
    /// Acknowledge mit `SealSyncRaceCondition` abgelehnt — der Status bleibt `PendingUpload`.
    ///
    /// # Arguments
    /// * `uploaded_seal_hash` - Der Base58-Hash des erfolgreich hochgeladenen `WalletSeal`.
    /// * `password` - Optional, für die Entschlüsselung des Siegel-Stores.
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
                        // Hash des aktuellen lokalen Siegels berechnen
                        let current_hash = SealManager::compute_seal_hash(&record.seal)?;

                        if current_hash != uploaded_seal_hash {
                            // Race Condition: Eine neue Transaktion hat das Siegel
                            // zwischenzeitlich aktualisiert. Der Upload war für ein
                            // veraltetes Siegel → ablehnen.
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
                                Ok(_) => (
                                    Ok(()),
                                    AppState::Unlocked {
                                        storage,
                                        wallet,
                                        identity,
                                        session_cache,
                                    },
                                ),
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
    ///
    /// # Lockdown-Trigger
    /// Wenn das Ergebnis `SealSyncState::ForkDetected` ist, setzt der AppService
    /// sofort `is_locked_due_to_fork = true` im `LocalSealRecord` und speichert
    /// dies auf der Festplatte. Ab diesem Moment sind alle Transaktionen blockiert
    /// bis `recover_wallet_and_set_new_password` ausgeführt wird.
    ///
    /// # Arguments
    /// * `remote_seal_bytes` - Die JSON-serialisierten Bytes des Remote-`WalletSeal`.
    /// * `password` - Optional, für die Entschlüsselung.
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
                        let state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        self.state = state;
                        return Err(e.to_string());
                    }
                };

                // 1. Remote-Siegel parsen
                let remote_seal: WalletSeal = match serde_json::from_slice(remote_seal_bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        let state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        self.state = state;
                        return Err(format!("Failed to parse remote seal: {}", e));
                    }
                };

                // 2. Remote-Siegel-Signatur verifizieren
                if let Err(e) = SealManager::verify_seal_integrity(
                    &remote_seal,
                    &identity.user_id,
                    &identity.user_id,
                ) {
                    let state = AppState::Unlocked {
                        storage,
                        wallet,
                        identity,
                        session_cache,
                    };
                    self.state = state;
                    return Err(format!("Remote seal integrity check failed: {}", e));
                }

                // 3. Lokales Siegel laden
                let record = match storage.load_seal(&identity.user_id, &auth_method) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        let state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        self.state = state;
                        return Err("No local seal found. Recovery required.".to_string());
                    }
                    Err(e) => {
                        let state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        self.state = state;
                        return Err(format!("Failed to load local seal: {}", e));
                    }
                };

                // 4. Vergleichen
                let sync_state = SealManager::compare_seals(&record.seal, &remote_seal);

                // 5. Bei Fork: Hard Lock aktivieren
                if sync_state == SealSyncState::ForkDetected {
                    let mut locked_record = record;
                    locked_record.is_locked_due_to_fork = true;
                    if let Err(e) =
                        storage.save_seal(&identity.user_id, &auth_method, &locked_record)
                    {
                        eprintln!(
                            "CRITICAL: Failed to save fork lock to disk: {}",
                            e
                        );
                    }
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

    /// Erstellt eine Auth-Methode für reine Lesezugriffe (ohne Passwort-Pflicht).
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

    /// Löst die Authentifizierungsmethode aus Passwort oder Session-Cache auf.
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

    /// Prüft den Fork-Lock-Status und gibt einen Fehler zurück, wenn das Wallet gesperrt ist.
    /// Wird von `create_transfer_bundle`, `receive_bundle` etc. aufgerufen.
    pub(crate) fn check_fork_lock(
        &self,
        password: Option<&str>,
    ) -> Result<(), VoucherCoreError> {
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
                    Some(r) if r.is_locked_due_to_fork => {
                        Err(VoucherCoreError::WalletLockedDueToFork)
                    }
                    _ => Ok(()),
                }
            }
            AppState::Locked => Err(VoucherCoreError::Generic("Wallet is locked.".to_string())),
        }
    }

    /// Berechnet den state_hash (Hash des OwnFingerprints-Stores) für das Siegel.
    pub(crate) fn compute_state_hash_from_wallet(
        &self,
    ) -> Result<String, VoucherCoreError> {
        match &self.state {
            AppState::Unlocked { wallet, .. } => {
                let canonical =
                    crate::services::utils::to_canonical_json(&wallet.own_fingerprints)?;
                Ok(crate::services::crypto_utils::get_hash(
                    canonical.as_bytes(),
                ))
            }
            AppState::Locked => Err(VoucherCoreError::Generic("Wallet is locked.".to_string())),
        }
    }

    /// Aktualisiert das Siegel nach einer erfolgreichen Zustandsänderung.
    ///
    /// Wird intern von den Command-Handlern nach jedem erfolgreichen `wallet.save()` aufgerufen.
    /// Inkrementiert den `tx_nonce`, aktualisiert den `state_hash` und die Hash-Kette.
    ///
    /// # Arguments
    /// * `password` - Optional, für die Authentifizierung.
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

                match record_opt {
                    Some(mut record) => {
                        let updated_seal = SealManager::update_seal(
                            &record.seal,
                            identity,
                            &current_state_hash,
                        ).map_err(|e| e.to_string())?;

                        record.seal = updated_seal;
                        record.sync_status = SyncStatus::PendingUpload;

                        storage
                            .save_seal(&identity.user_id, &auth, &record)
                            .map_err(|e| e.to_string())?;
                    }
                    None => {
                        // Kein Siegel vorhanden (sollte nach Login nicht vorkommen)
                        // Erstelle ein initiales Siegel als Fallback
                        let initial_seal = SealManager::create_initial_seal(
                            &identity.user_id,
                            identity,
                            &current_state_hash,
                        ).map_err(|e| e.to_string())?;

                        let new_record = crate::models::seal::LocalSealRecord {
                            seal: initial_seal,
                            sync_status: SyncStatus::PendingUpload,
                            is_locked_due_to_fork: false,
                        };
                        storage
                            .save_seal(&identity.user_id, &auth, &new_record)
                            .map_err(|e| e.to_string())?;
                    }
                }

                Ok(())
            }
            AppState::Locked => Err("Wallet is locked.".to_string()),
        }
    }
}
