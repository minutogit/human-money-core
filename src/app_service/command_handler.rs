//! # src/app_service/command_handler.rs
//!
//! Enthält die zentralen, schreibenden Aktionen (Commands) des `AppService`,
//! die den Zustand des Wallets verändern und persistieren.

use super::{AppState, AppService};
use crate::archive::VoucherArchive;
use crate::storage::WalletLockGuard; // Importiere den RAII Guard
use crate::models::conflict::ResolutionEndorsement;
use crate::models::voucher::Voucher;
use crate::wallet::instance::VoucherStatus;
use crate::services::voucher_validation;
use crate::{AuthMethod, ValidationFailureReason, VoucherCoreError};
use crate::error::ValidationError;
use crate::services::{standard_manager, voucher_manager::NewVoucherData};
use crate::wallet::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};

use std::collections::HashMap;

impl AppService {
    // --- Aktionen (Commands) ---

    /// Erstellt einen brandneuen Gutschein, fügt ihn zum Wallet hinzu und speichert den Zustand.
    pub fn create_new_voucher(
        &mut self,
        standard_toml_content: &str,
        lang_preference: &str,
        data: NewVoucherData,
        password: Option<&str>,
    ) -> Result<Voucher, String> {
        println!("[DEBUG CMD] create_new_voucher called.");
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity, session_cache } => {

                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand manuell wiederherstellen und Funktion verlassen
                        self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                    Ok((verified_standard, standard_hash)) => {
                        match crate::services::voucher_manager::create_voucher(
                            data,
                            &verified_standard,
                            &standard_hash,
                            &identity.signing_key,
                            lang_preference,
                        ) {
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                            Ok(new_voucher) => {
                                // Validierung und Status-Ermittlung
                                let validation_result = voucher_validation::validate_voucher_against_standard(&new_voucher, &verified_standard);

                                let (operation_result, initial_status) = match validation_result {
                                    Ok(_) => (Ok(new_voucher.clone()), VoucherStatus::Active),

                                    // Fall 1: Incomplete
                                    Err(VoucherCoreError::Validation(ref validation_err @ ValidationError::FieldValueCountOutOfBounds { ref path, ref field, .. }))
                                    if path == "signatures" && (field == "role" || field == "details.gender") =>
                                        {
                                            let reasons = vec![ValidationFailureReason::RequiredSignatureMissing { role_description: validation_err.to_string() }];
                                            (Ok(new_voucher.clone()), VoucherStatus::Incomplete { reasons })
                                        },
                                    Err(VoucherCoreError::Validation(validation_err @ ValidationError::MissingRequiredSignature { .. })) =>
                                        {
                                            let reasons = vec![ValidationFailureReason::RequiredSignatureMissing { role_description: validation_err.to_string() }];
                                            (Ok(new_voucher.clone()), VoucherStatus::Incomplete { reasons })
                                        },

                                    // Fall 2: Fataler Fehler
                                    Err(fatal_error) => (Err(fatal_error.to_string()), VoucherStatus::Quarantined { reason: fatal_error.to_string() })
                                };

                                match operation_result {
                                    Err(e) => (Err(e), AppState::Unlocked { storage, wallet, identity, session_cache }),
                                    Ok(voucher_to_return) => {
                                        // Authentifizierung ermitteln
                                        let auth_method = match password {
                                            Some(pwd_str) => AuthMethod::Password(pwd_str),
                                            None => {
                                                match &session_cache {
                                                    Some(cache) => {
                                                        if std::time::Instant::now() > cache.last_activity + cache.session_duration {
                                                            // Timeout Fallback placeholder
                                                            AuthMethod::SessionKey([0u8; 32])
                                                        } else {
                                                            AuthMethod::SessionKey(cache.session_key)
                                                        }
                                                    },
                                                    None => AuthMethod::SessionKey([0u8; 32]),
                                                }
                                            }
                                        };

                                        // Expliziter Check für Auth-Fehler vor dem Speichern
                                        if let AuthMethod::SessionKey(k) = auth_method {
                                            if k == [0u8; 32] {
                                                // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                                self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                                return Err("Session timed out or password required.".to_string());
                                            }
                                        }

                                        // 1. Kopie erstellen
                                        let mut temp_wallet = wallet.clone();
                                        let local_id = crate::wallet::Wallet::calculate_local_instance_id(&new_voucher, &identity.user_id).unwrap();
                                        temp_wallet.add_voucher_instance(local_id, new_voucher.clone(), initial_status);

                                        // 2. Abgeleitete Stores aktualisieren & Speichern
                                        match temp_wallet.rebuild_derived_stores() {
                                            Ok(_) => {
                                                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                                                    Ok(_) => (Ok(voucher_to_return), AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache }),
                                                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                                                }
                                            }
                                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache })
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), current_state),
        };

        self.state = new_state;
        result
    }

    /// Erstellt ein Transfer-Bundle für eine oder mehrere Transaktionen und speichert den neuen Wallet-Zustand.
    pub fn create_transfer_bundle(
        &mut self,
        request: MultiTransferRequest,
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: Option<&str>,
    ) -> Result<CreateBundleResult, String> {
        println!("[DEBUG CMD] create_transfer_bundle called.");
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        // Parse die TOML-Definitionen hier
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            match standard_manager::verify_and_parse_standard(toml_content) {
                Ok((def, _hash)) => {
                    verified_definitions.insert(uuid.clone(), def);
                }
                Err(e) => return Err(e.to_string()),
            }
        }

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity, session_cache } => {

                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                let auth_method;

                match password {
                    Some(pwd_str) => {
                        auth_method = AuthMethod::Password(pwd_str);
                    },
                    None => {
                        let session_key = match &session_cache {
                            Some(cache) => {
                                let now = std::time::Instant::now();
                                if now > cache.last_activity + cache.session_duration {
                                    // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                    self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                    return Err("Session timed out. Please provide password.".to_string());
                                } else {
                                    cache.session_key
                                }
                            },
                            None => {
                                // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                return Err("Password required. Please use 'unlock_session'.".to_string());
                            }
                        };
                        auth_method = AuthMethod::SessionKey(session_key);
                    }
                }

                // Wallet Operation
                let mut temp_wallet = wallet.clone();
                match temp_wallet.execute_multi_transfer_and_bundle(
                    &identity,
                    &verified_definitions,
                    request,
                    archive,
                ) {
                    Ok(create_result) => {
                        match temp_wallet.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Ok(create_result),
                                AppState::Unlocked { storage, wallet: temp_wallet, identity, session_cache },
                            ),
                            Err(e) => (
                                Err(e.to_string()),
                                AppState::Unlocked { storage, wallet, identity, session_cache },
                            ),
                        }
                    }
                    // --- SELBSTHEILUNG ---
                    Err(crate::error::VoucherCoreError::DoubleSpendAttemptBlocked { local_instance_id }) => {
                        let mut wallet_to_correct = wallet; // Nimm das Original

                        wallet_to_correct.update_voucher_status(
                            &local_instance_id,
                            crate::wallet::instance::VoucherStatus::Quarantined {
                                reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                            },
                        );

                        match wallet_to_correct.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Err(format!("Action blocked and wallet state corrected: Voucher {} was internally inconsistent and is now in quarantine.", local_instance_id)),
                                AppState::Unlocked { storage, wallet: wallet_to_correct, identity, session_cache }
                            ),
                            Err(save_err) => (
                                Err(format!("Critical Error: Failed to save wallet correction. Error: {}", save_err)),
                                AppState::Unlocked { storage, wallet: wallet_to_correct, identity, session_cache }
                            )
                        }
                    }
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }

    /// Verarbeitet ein empfangenes Transaktions- oder Signatur-Bundle.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: Option<&str>,
    ) -> Result<ProcessBundleResult, String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity, session_cache } => {

                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                let mut verified_definitions = HashMap::new();
                for (uuid, toml_content) in standard_definitions_toml {
                    match standard_manager::verify_and_parse_standard(toml_content) {
                        Ok((def, _hash)) => {
                            verified_definitions.insert(uuid.clone(), def);
                        }
                        Err(e) => return Err(e.to_string()),
                    }
                }

                match self.validate_vouchers_in_bundle(
                    &identity,
                    bundle_data,
                    standard_definitions_toml,
                ) {
                    Err(e) => (Err(e), AppState::Unlocked { storage, wallet, identity, session_cache }),
                    Ok(_) => {
                        let auth_method;

                        match password {
                            Some(pwd_str) => {
                                auth_method = AuthMethod::Password(pwd_str);
                            },
                            None => {
                                let session_key = match &session_cache {
                                    Some(cache) => {
                                        let now = std::time::Instant::now();
                                        if now > cache.last_activity + cache.session_duration {
                                            // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                            self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                            return Err("Session timed out. Please provide password.".to_string());
                                        } else {
                                            cache.session_key
                                        }
                                    },
                                    None => {
                                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                        self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                        return Err("Password required. Please use 'unlock_session'.".to_string());
                                    }
                                };
                                auth_method = AuthMethod::SessionKey(session_key);
                            }
                        }
                        // TRANSANKTIONALER ANSATZ:
                        let mut temp_wallet = wallet.clone();
                        match temp_wallet
                            .process_encrypted_transaction_bundle(&identity, bundle_data, archive, &verified_definitions)
                        {
                            Ok(proc_result) => {
                                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                                    Ok(_) => (
                                        Ok(proc_result),
                                        AppState::Unlocked {
                                            storage,
                                            wallet: temp_wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                    Err(e) => (
                                        Err(e.to_string()),
                                        AppState::Unlocked { storage, wallet, identity, session_cache },
                                    ),
                                }
                            }
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                        }
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }

    /// Importiert eine Beilegungserklärung.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: Option<&str>,
    ) -> Result<(), String> {
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        let (result, new_state) = match current_state {
            AppState::Unlocked { mut storage, wallet, identity, session_cache } => {

                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                let auth_method;

                match password {
                    Some(pwd_str) => {
                        auth_method = AuthMethod::Password(pwd_str);
                    },
                    None => {
                        let session_key = match &session_cache {
                            Some(cache) => {
                                let now = std::time::Instant::now();
                                if now > cache.last_activity + cache.session_duration {
                                    // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                    self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                    return Err("Session timed out. Please provide password.".to_string());
                                } else {
                                    cache.session_key
                                }
                            },
                            None => {
                                // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                self.state = AppState::Unlocked { storage, wallet, identity, session_cache };
                                return Err("Password required. Please use 'unlock_session'.".to_string());
                            }
                        };
                        auth_method = AuthMethod::SessionKey(session_key);
                    }
                }
                // TRANSANKTIONALER ANSATZ:
                let mut temp_wallet = wallet.clone();
                match temp_wallet.add_resolution_endorsement(endorsement) {
                    Ok(_) => {
                        match temp_wallet.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Ok(()),
                                AppState::Unlocked {
                                    storage,
                                    wallet: temp_wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                        }
                    }
                    Err(e) => (Err(e.to_string()), AppState::Unlocked { storage, wallet, identity, session_cache }),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        result
    }
}