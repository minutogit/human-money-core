//! # src/app_service/conflict_handler.rs
//!
//! Enthält alle `AppService`-Funktionen, die sich auf das Management von
//! Double-Spend-Konflikten beziehen.

use super::{AppService, AppState, AppFacadeError};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::wallet::CleanupReport;

impl AppService {
    // --- Konflikt-Management ---

    /// Gibt eine Liste von Zusammenfassungen aller bekannten Double-Spend-Konflikte zurück.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt (`Locked`) ist.
    pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, AppFacadeError> {
        Ok(self.get_wallet()?.list_conflicts())
    }

    /// Ruft einen vollständigen `ProofOfDoubleSpend` anhand seiner ID ab.
    ///
    /// Ideal, um die Details eines Konflikts anzuzeigen oder ihn für den
    /// manuellen Austausch zu exportieren.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder kein Beweis mit dieser ID existiert.
    pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, AppFacadeError> {
        self.get_wallet()?
            .get_proof_of_double_spend(proof_id)
            .map_err(AppFacadeError::from)
    }

    /// Erstellt eine signierte Beilegungserklärung (`ResolutionEndorsement`) für einen Konflikt.
    ///
    /// Diese Operation verändert den Wallet-Zustand nicht. Sie erzeugt ein
    /// signiertes Objekt, das an andere Parteien gesendet werden kann, um zu
    /// signalisieren, dass der Konflikt aus Sicht des Wallet-Inhabers (des Opfers)
    /// gelöst wurde.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der referenzierte Beweis nicht existiert.
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

    /// Setzt den lokalen Override für einen spezifischen Konflikt.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der Beweis nicht existiert.
    pub fn set_conflict_local_override(
        &mut self,
        proof_id: &str,
        value: bool,
        note: Option<String>,
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        // --- FORK-LOCK PRÜFUNG ---
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

    /// Importiert einen Beweis direkt als Objekt.
    pub fn import_proof(&mut self, proof: ProofOfDoubleSpend, password: Option<&str>) -> Result<(), AppFacadeError> {
        // --- FORK-LOCK PRÜFUNG ---
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

    /// Importiert einen Beweis aus einem Base64-kodierten JSON-String (Klartext-Export).
    ///
    pub fn import_proof_from_json(&mut self, json_base64: &str, password: Option<&str>) -> Result<(), AppFacadeError> {
        let json_bytes = bs58::decode(json_base64)
            .into_vec()
            .map_err(|e| AppFacadeError::ValidationError(format!("Invalid base64 encoding: {}", e)))?;
        let proof: ProofOfDoubleSpend =
            serde_json::from_slice(&json_bytes).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;

        self.import_proof(proof, password)
    }

    /// Importiert einen Beweis aus einem `SecureContainer` (Sicherer Austausch).
    pub fn import_proof_from_container(&mut self, container_bytes: &[u8], password: Option<&str>) -> Result<(), AppFacadeError> {
        let proof = {
            if let AppState::Unlocked { identity, .. } = &self.state {
                let container: crate::models::secure_container::SecureContainer =
                    serde_json::from_slice(container_bytes).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;

                if container.c != crate::models::secure_container::PayloadType::ProofOfDoubleSpend {
                    return Err(AppFacadeError::ValidationError("Container does not contain a Double-Spend-Proof.".to_string()));
                }

                // Wallet-Identity wird benötigt, um den Container zu öffnen
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

    /// Führt die Speicherbereinigung für Fingerprints und deren Metadaten durch.
    ///
    /// Diese Methode implementiert die in der Architektur-Spezifikation definierte
    /// Logik:
    /// 1. Löschen aller abgelaufenen Fingerprints.
    /// 2. Wenn das Speicherlimit (`MAX_FINGERPRINTS`) immer noch überschritten ist,
    ///    werden die Fingerprints mit der höchsten `depth` (und ältestem `t_time`)
    ///    gelöscht, bis das Limit wieder unterschritten ist.
    ///
    /// # Returns
    /// Ein `Result` mit einem `CleanupReport`, der Details über die Bereinigung
    /// enthält, oder einen Fehler, falls der Prozess fehlschlägt.
    pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, AppFacadeError> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            let report = wallet.run_storage_cleanup(None, super::DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS)?;
            // Hinweis: Das Speichern des Wallets nach dem Cleanup wird dem Aufrufer
            // überlassen (z.B. am Ende einer Operation), um mehrfaches Schreiben
            // zu vermeiden.
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

