//! # src/app_service/data_encryption.rs
//!
//! Enthält die `AppService`-Methoden zur Ver- und Entschlüsselung von
//! beliebigen, anwendungsspezifischen Daten.

use super::{AppService, AppState};
use crate::storage::{AuthMethod, Storage, WalletLockGuard};

impl AppService {
    // --- Generische Datenverschlüsselung ---

    /// Speichert einen beliebigen Byte-Slice verschlüsselt auf der Festplatte.
    ///
    /// Diese Methode nutzt den gleichen sicheren Verschlüsselungsmechanismus wie das Wallet selbst.
    /// Sie ist ideal, um anwendungsspezifische Daten (z.B. Konfigurationen, Kontakte)
    /// sicher abzulegen, ohne dass die App eigene Schlüssel verwalten muss.
    ///
    /// # Arguments
    /// * `name` - Ein eindeutiger Name für die Daten, dient als Dateiname (z.B. "settings").
    /// * `data` - Der `&[u8]`-Slice, der gespeichert werden soll.
    /// * `password` - Das aktuelle Passwort des Benutzers zum Verschlüsseln.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist oder der Schreibvorgang misslingt.
    pub fn save_encrypted_data(
        &mut self,
        name: &str,
        data: &[u8],
        password: Option<&str>,
    ) -> Result<(), String> {
        return match password {
            Some(pwd_str) => {
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => {
                        // KORREKTUR: Modus A verwendet AuthMethod::Password
                        let auth_method = AuthMethod::Password(pwd_str);
                        let result = {
                            // --- SPERRE ERLANGEN (RAII) ---
                            let _lock_guard =
                                WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
                            // --- SPERRE ENDE ---
                            storage
                                .save_arbitrary_data(&identity.user_id, &auth_method, name, data)
                                .map_err(|e| e.to_string())
                        };
                        result
                    }
                    AppState::Locked => Err("Wallet is locked.".to_string()),
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
                            // --- SPERRE ERLANGEN (RAII) ---
                            let _lock_guard =
                                WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
                            // --- SPERRE ENDE ---
                            storage
                                .save_arbitrary_data(&identity.user_id, &auth_method, name, data)
                                .map_err(|e| {
                                    e.to_string()
                                })
                        };
                        result
                    }
                    AppState::Locked => Err("Wallet is locked.".to_string()),
                }
            }
        };
    }

    /// Lädt und entschlüsselt einen zuvor gespeicherten, beliebigen Datenblock.
    ///
    /// # Arguments
    /// * `name` - Der Name der zu ladenden Daten.
    /// * `password` - Das Passwort des Benutzers. Aus Sicherheitsgründen wird das Passwort
    ///   für jede Leseoperation benötigt, um den Entschlüsselungsschlüssel abzuleiten.
    ///
    /// # Returns
    /// Die entschlüsselten Daten als `Vec<u8>`.
    ///
    /// # Errors
    /// Schlägt fehl, wenn das Wallet gesperrt ist, das Passwort falsch ist oder die Daten nicht gefunden werden können.
    pub fn load_encrypted_data(
        &mut self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        return match password {
            Some(pwd_str) => {
                match &mut self.state {
                    AppState::Unlocked {
                        storage, identity, ..
                    } => {
                        // KORREKTUR: Modus A verwendet AuthMethod::Password
                        let auth_method = AuthMethod::Password(pwd_str);
                        storage
                            .load_arbitrary_data(&identity.user_id, &auth_method, name)
                            .map_err(|e| {
                                e.to_string()
                            })
                    }
                    AppState::Locked => Err("Wallet is locked.".to_string()),
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
                        .map_err(|e| {
                            e.to_string()
                        }),
                    AppState::Locked => Err("Wallet is locked.".to_string()),
                }
            }
        };
    }
}
