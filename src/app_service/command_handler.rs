//! # src/app_service/command_handler.rs
//!
//! Enthält die zentralen, schreibenden Aktionen (Commands) des `AppService`,
//! die den Zustand des Wallets verändern und persistieren.

use super::{AppService, AppState};
use crate::archive::VoucherArchive;
use crate::models::conflict::ResolutionEndorsement;
use crate::models::voucher::Voucher;
use crate::services::standard_manager;
use crate::services::voucher_manager::NewVoucherData;
use crate::storage::WalletLockGuard; // Importiere den RAII Guard
use crate::wallet::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::{AuthMethod, VoucherCoreError};

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
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(password).map_err(|e| e.to_string())?;
        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand manuell wiederherstellen und Funktion verlassen
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (
                        Err(e.to_string()),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok((verified_standard, standard_hash)) => {
                        // 1. Kopie erstellen
                        let mut temp_wallet = wallet.clone();

                        // 2. Erstellung via Wallet (enthält Validierung, ID-Berechnung und Event-Logging)
                        match temp_wallet.create_new_voucher(
                            &identity,
                            &verified_standard,
                            &standard_hash,
                            lang_preference,
                            data,
                        ) {
                            Err(e) => (
                                Err(e.to_string()),
                                AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Ok(new_voucher) => {
                                // Authentifizierung ermitteln
                                let auth_method = match password {
                                    Some(pwd_str) => AuthMethod::Password(pwd_str),
                                    None => {
                                        match &session_cache {
                                            Some(cache) => {
                                                if std::time::Instant::now()
                                                    > cache.last_activity
                                                        + cache.session_duration
                                                {
                                                    AuthMethod::SessionKey([0u8; 32])
                                                } else {
                                                    AuthMethod::SessionKey(cache.session_key)
                                                }
                                            }
                                            None => AuthMethod::SessionKey([0u8; 32]),
                                        }
                                    }
                                };

                                // Expliziter Check für Auth-Fehler vor dem Speichern
                                if let AuthMethod::SessionKey(k) = auth_method {
                                    if k == [0u8; 32] {
                                        self.state = AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        };
                                        return Err("Session timed out or password required.".to_string());
                                    }
                                }

                                // 3. Speichern
                                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                                    Ok(_) => (
                                        Ok(new_voucher),
                                        AppState::Unlocked {
                                            storage,
                                            wallet: temp_wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                    Err(e) => (
                                        Err(e.to_string()),
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
                    }
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), current_state),
        };

        self.state = new_state;
        // Siegel aktualisieren, wenn die Aktion erfolgreich war
        if result.is_ok() {
            if let Err(e) = self.update_seal_after_state_change(password) {
                eprintln!("Warning: Failed to update seal after voucher creation: {}", e);
            }
        }
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
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(password).map_err(|e| e.to_string())?;

        // Parse die TOML-Definitionen BEVOR der State bewegt wird,
        // damit ein Fehler hier den State nicht verwaist.
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            match standard_manager::verify_and_parse_standard(toml_content) {
                Ok((def, _hash)) => {
                    verified_definitions.insert(uuid.clone(), def);
                }
                Err(e) => return Err(e.to_string()),
            }
        }

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                let auth_method;

                match password {
                    Some(pwd_str) => {
                        auth_method = AuthMethod::Password(pwd_str);
                    }
                    None => {
                        let session_key =
                            match &session_cache {
                                Some(cache) => {
                                    let now = std::time::Instant::now();
                                    if now > cache.last_activity + cache.session_duration {
                                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                        self.state = AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        };
                                        return Err("Session timed out. Please provide password."
                                            .to_string());
                                    } else {
                                        cache.session_key
                                    }
                                }
                                None => {
                                    // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                    self.state = AppState::Unlocked {
                                        storage,
                                        wallet,
                                        identity,
                                        session_cache,
                                    };
                                    return Err("Password required. Please use 'unlock_session'."
                                        .to_string());
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
                                AppState::Unlocked {
                                    storage,
                                    wallet: temp_wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Err(e) => (
                                Err(e.to_string()),
                                AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                        }
                    }
                    // --- SELBSTHEILUNG ---
                    Err(crate::error::VoucherCoreError::DoubleSpendAttemptBlocked {
                        local_instance_id,
                    }) => {
                        let mut wallet_to_correct = wallet; // Nimm das Original

                        wallet_to_correct.update_voucher_status(
                            &local_instance_id,
                            crate::wallet::instance::VoucherStatus::Quarantined {
                                reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                            },
                        );

                        match wallet_to_correct.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Err(format!(
                                    "Action blocked and wallet state corrected: Voucher {} was internally inconsistent and is now in quarantine.",
                                    local_instance_id
                                )),
                                AppState::Unlocked {
                                    storage,
                                    wallet: wallet_to_correct,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Err(save_err) => (
                                Err(format!(
                                    "Critical Error: Failed to save wallet correction. Error: {}",
                                    save_err
                                )),
                                AppState::Unlocked {
                                    storage,
                                    wallet: wallet_to_correct,
                                    identity,
                                    session_cache,
                                },
                            ),
                        }
                    }
                    Err(e) => (
                        Err(e.to_string()),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        // Siegel aktualisieren, wenn die Aktion erfolgreich war
        if result.is_ok() {
            if let Err(e) = self.update_seal_after_state_change(password) {
                eprintln!("Warning: Failed to update seal after transfer bundle creation: {}", e);
            }
        }
        result
    }

    /// Verarbeitet ein empfangenes Transaktions- oder Signatur-Bundle.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: Option<&str>,
        force_accept_tolerance_bundle: bool,
    ) -> Result<ProcessBundleResult, String> {
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(password).map_err(|e| e.to_string())?;

        // --- ZONEN-MODELL: Prüfung gegen Pre-Epoch Bundles ---
        // Nur relevant, wenn eine Recovery stattgefunden hat (epoch > 0).
        // Die Logik schützt davor, dass ein Angreifer nach einer Recovery alte
        // Bundles einspielt, die vor der Recovery erstellt wurden.
        if let Ok(Some((epoch_start_time, epoch))) = self.get_epoch_info(password) {
            if epoch > 0 {
                // Bundle entschlüsseln, um den Transaktionszeitstempel zu extrahieren
                let max_tx_time = match &self.state {
                    AppState::Unlocked { identity, .. } => {
                        let bundle = crate::services::bundle_processor::open_and_verify_bundle(
                            identity,
                            bundle_data,
                        ).map_err(|e| e.to_string())?;

                        // Finde den maximalen (jüngsten) Transaktionszeitstempel
                        let mut max_dt: Option<chrono::DateTime<chrono::Utc>> = None;
                        for voucher in &bundle.vouchers {
                            if let Some(last_tx) = voucher.transactions.last() {
                                if let Ok(tx_dt) = chrono::DateTime::parse_from_rfc3339(&last_tx.t_time) {
                                    let tx_utc = tx_dt.with_timezone(&chrono::Utc);
                                    match max_dt {
                                        None => max_dt = Some(tx_utc),
                                        Some(m) if tx_utc > m => max_dt = Some(tx_utc),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        max_dt
                    }
                    _ => None, // Sollte nicht vorkommen nach fork-lock check
                };

                if let Some(bundle_max_dt) = max_tx_time {
                    if let Ok(epoch_dt) = chrono::DateTime::parse_from_rfc3339(&epoch_start_time) {
                        let epoch_utc = epoch_dt.with_timezone(&chrono::Utc);

                        // Nur prüfen, wenn das Bundle VOR der aktuellen Epoche liegt
                        if bundle_max_dt < epoch_utc {
                            let delta = epoch_utc - bundle_max_dt;

                            // Zone 1: < 15 Minuten → Auto-Accept (kein Fehler)
                            // Zone 2: 15 Min – 24h → Warnung, Nutzerbestätigung nötig
                            // Zone 3: 24h – 28 Tage → Kritische Warnung
                            // Zone 4: > 28 Tage → Harte Ablehnung
                            const ZONE_1_LIMIT_MINUTES: i64 = 15;
                            const ZONE_2_LIMIT_HOURS: i64 = 24;
                            const ZONE_3_LIMIT_DAYS: i64 = 28;

                            if delta > chrono::Duration::days(ZONE_3_LIMIT_DAYS) {
                                // Zone 4: Harte Ablehnung (Flag wird IGNORIERT)
                                return Err(VoucherCoreError::BundlePredatesCurrentEpoch.to_string());
                            } else if delta > chrono::Duration::hours(ZONE_2_LIMIT_HOURS) {
                                // Zone 3: Kritische Warnung
                                if !force_accept_tolerance_bundle {
                                    return Err(VoucherCoreError::BundleInExtendedRecoveryToleranceZone.to_string());
                                }
                            } else if delta > chrono::Duration::minutes(ZONE_1_LIMIT_MINUTES) {
                                // Zone 2: Warnung
                                if !force_accept_tolerance_bundle {
                                    return Err(VoucherCoreError::BundleInRecoveryToleranceZone.to_string());
                                }
                            }
                            // Zone 1: < 15 Min → Auto-Accept, kein Fehler
                        }
                    }
                }
            }
        }
        // --- ZONEN-MODELL ENDE ---

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
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
                        Err(e) => {
                            // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                            self.state = AppState::Unlocked {
                                storage,
                                wallet,
                                identity,
                                session_cache,
                            };
                            return Err(e.to_string());
                        }
                    }
                }

                match self.validate_vouchers_in_bundle(
                    &identity,
                    bundle_data,
                    standard_definitions_toml,
                ) {
                    Err(e) => (
                        Err(e),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok(_) => {
                        let auth_method;

                        match password {
                            Some(pwd_str) => {
                                auth_method = AuthMethod::Password(pwd_str);
                            }
                            None => {
                                let session_key = match &session_cache {
                                    Some(cache) => {
                                        let now = std::time::Instant::now();
                                        if now > cache.last_activity + cache.session_duration {
                                            // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                            self.state = AppState::Unlocked {
                                                storage,
                                                wallet,
                                                identity,
                                                session_cache,
                                            };
                                            return Err(
                                                "Session timed out. Please provide password."
                                                    .to_string(),
                                            );
                                        } else {
                                            cache.session_key
                                        }
                                    }
                                    None => {
                                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                        self.state = AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        };
                                        return Err(
                                            "Password required. Please use 'unlock_session'."
                                                .to_string(),
                                        );
                                    }
                                };
                                auth_method = AuthMethod::SessionKey(session_key);
                            }
                        }
                        // TRANSANKTIONALER ANSATZ:
                        let mut temp_wallet = wallet.clone();
                        match temp_wallet.process_encrypted_transaction_bundle(
                            &identity,
                            bundle_data,
                            archive,
                            &verified_definitions,
                        ) {
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
                                        AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                }
                            }
                            Err(e) => (
                                Err(e.to_string()),
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
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        // Siegel aktualisieren, wenn die Aktion erfolgreich war
        if result.is_ok() {
            if let Err(e) = self.update_seal_after_state_change(password) {
                eprintln!("Warning: Failed to update seal after receiving bundle: {}", e);
            }
        }
        result
    }
    /// Importiert eine Beilegungserklärung.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: Option<&str>,
    ) -> Result<(), String> {
        // --- FORK-LOCK PRÜFUNG ---
        self.check_fork_lock(password).map_err(|e| e.to_string())?;

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);
        let (result, new_state) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // --- SPERRE ERLANGEN (RAII) ---
                let _lock_guard = match WalletLockGuard::new(&storage) {
                    Ok(guard) => guard,
                    Err(e) => {
                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                        self.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e.to_string());
                    }
                };
                // --- SPERRE ENDE ---

                let auth_method;

                match password {
                    Some(pwd_str) => {
                        auth_method = AuthMethod::Password(pwd_str);
                    }
                    None => {
                        let session_key =
                            match &session_cache {
                                Some(cache) => {
                                    let now = std::time::Instant::now();
                                    if now > cache.last_activity + cache.session_duration {
                                        // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                        self.state = AppState::Unlocked {
                                            storage,
                                            wallet,
                                            identity,
                                            session_cache,
                                        };
                                        return Err("Session timed out. Please provide password."
                                            .to_string());
                                    } else {
                                        cache.session_key
                                    }
                                }
                                None => {
                                    // FEHLERBEHEBUNG: Zustand wiederherstellen & Return
                                    self.state = AppState::Unlocked {
                                        storage,
                                        wallet,
                                        identity,
                                        session_cache,
                                    };
                                    return Err("Password required. Please use 'unlock_session'."
                                        .to_string());
                                }
                            };
                        auth_method = AuthMethod::SessionKey(session_key);
                    }
                }
                // TRANSANKTIONALER ANSATZ:
                let mut temp_wallet = wallet.clone();
                match temp_wallet.add_resolution_endorsement(endorsement) {
                    Ok(_) => match temp_wallet.save(&mut storage, &identity, &auth_method) {
                        Ok(_) => (
                            Ok(()),
                            AppState::Unlocked {
                                storage,
                                wallet: temp_wallet,
                                identity,
                                session_cache,
                            },
                        ),
                        Err(e) => (
                            Err(e.to_string()),
                            AppState::Unlocked {
                                storage,
                                wallet,
                                identity,
                                session_cache,
                            },
                        ),
                    },
                    Err(e) => (
                        Err(e.to_string()),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                }
            }
            AppState::Locked => (Err("Wallet is locked.".to_string()), AppState::Locked),
        };
        self.state = new_state;
        // Siegel aktualisieren, wenn die Aktion erfolgreich war
        if result.is_ok() {
            if let Err(e) = self.update_seal_after_state_change(password) {
                eprintln!("Warning: Failed to update seal after resolution endorsement: {}", e);
            }
        }
        result
    }
}
