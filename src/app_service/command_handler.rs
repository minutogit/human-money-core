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
use crate::VoucherCoreError;

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

        // Vorab-Validierung (ohne Lock möglich)
        let (verified_standard, standard_hash) =
            standard_manager::verify_and_parse_standard(standard_toml_content)
                .map_err(|e| e.to_string())?;

        let result = self.with_unlocked_mut(|wallet, identity, storage, session_cache| {
            let _lock = WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
            let auth = Self::resolve_auth_method(password, session_cache).map_err(|e| e.to_string())?;

            let mut temp_wallet = wallet.clone();
            let new_voucher = temp_wallet
                .create_new_voucher(
                    identity,
                    &verified_standard,
                    &standard_hash,
                    lang_preference,
                    data,
                )
                .map_err(|e| e.to_string())?;

            temp_wallet
                .save(storage, identity, &auth)
                .map_err(|e| e.to_string())?;

            *wallet = temp_wallet;
            Ok(new_voucher)
        });

        if result.is_ok() {
            let _ = self.update_seal_after_state_change(password);
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

        // Parse die TOML-Definitionen BEVOR der Lock/State-Swap passiert
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = standard_manager::verify_and_parse_standard(toml_content)
                .map_err(|e| e.to_string())?;
            verified_definitions.insert(uuid.clone(), def);
        }

        let result = self.with_unlocked_mut(|wallet, identity, storage, session_cache| {
            let _lock = WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
            let auth = Self::resolve_auth_method(password, session_cache).map_err(|e| e.to_string())?;

            let mut temp_wallet = wallet.clone();
            match temp_wallet.execute_multi_transfer_and_bundle(
                identity,
                &verified_definitions,
                request,
                archive,
            ) {
                Ok(create_result) => {
                    temp_wallet.save(storage, identity, &auth).map_err(|e| e.to_string())?;
                    *wallet = temp_wallet;
                    Ok(create_result)
                }
                // --- SELBSTHEILUNG ---
                Err(crate::error::VoucherCoreError::DoubleSpendAttemptBlocked { local_instance_id }) => {
                    wallet.update_voucher_status(
                        &local_instance_id,
                        crate::wallet::instance::VoucherStatus::Quarantined {
                            reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                        },
                    );
                    wallet.save(storage, identity, &auth).map_err(|e| e.to_string())?;
                    Err(format!(
                        "Action blocked and wallet state corrected: Voucher {} was internally inconsistent and is now in quarantine.",
                        local_instance_id
                    ))
                }
                Err(e) => Err(e.to_string()),
            }
        });

        if result.is_ok() {
            let _ = self.update_seal_after_state_change(password);
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
        if let Ok(Some((epoch_start_time, epoch))) = self.get_epoch_info(password) {
            if epoch > 0 {
                let max_tx_time = match &self.state {
                    AppState::Unlocked { identity, .. } => {
                        let bundle = crate::services::bundle_processor::open_and_verify_bundle(
                            identity,
                            bundle_data,
                        )
                        .map_err(|e| e.to_string())?;

                        let mut max_dt: Option<chrono::DateTime<chrono::Utc>> = None;
                        for voucher in &bundle.vouchers {
                            if let Some(last_tx) = voucher.transactions.last() {
                                if let Ok(tx_dt) =
                                    chrono::DateTime::parse_from_rfc3339(&last_tx.t_time)
                                {
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
                    _ => None,
                };

                if let Some(bundle_max_dt) = max_tx_time {
                    if let Ok(epoch_dt) = chrono::DateTime::parse_from_rfc3339(&epoch_start_time) {
                        let epoch_utc = epoch_dt.with_timezone(&chrono::Utc);

                        if bundle_max_dt < epoch_utc {
                            let delta = epoch_utc - bundle_max_dt;
                            const ZONE_1_LIMIT_MINUTES: i64 = 15;
                            const ZONE_2_LIMIT_HOURS: i64 = 24;
                            const ZONE_3_LIMIT_DAYS: i64 = 28;

                            if delta > chrono::Duration::days(ZONE_3_LIMIT_DAYS) {
                                return Err(VoucherCoreError::BundlePredatesCurrentEpoch.to_string());
                            } else if delta > chrono::Duration::hours(ZONE_2_LIMIT_HOURS) {
                                if !force_accept_tolerance_bundle {
                                    return Err(
                                        VoucherCoreError::BundleInExtendedRecoveryToleranceZone
                                            .to_string(),
                                    );
                                }
                            } else if delta > chrono::Duration::minutes(ZONE_1_LIMIT_MINUTES) {
                                if !force_accept_tolerance_bundle {
                                    return Err(
                                        VoucherCoreError::BundleInRecoveryToleranceZone.to_string()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Parse die TOML-Definitionen
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = standard_manager::verify_and_parse_standard(toml_content)
                .map_err(|e| e.to_string())?;
            verified_definitions.insert(uuid.clone(), def);
        }

        let result = self.with_unlocked_mut(|wallet, identity, storage, session_cache| {
            let _lock = WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
            let auth = Self::resolve_auth_method(password, session_cache).map_err(|e| e.to_string())?;

            Self::validate_vouchers_in_bundle(identity, bundle_data, standard_definitions_toml)?;

            let mut temp_wallet = wallet.clone();
            let proc_result = temp_wallet
                .process_encrypted_transaction_bundle(
                    identity,
                    bundle_data,
                    archive,
                    &verified_definitions,
                )
                .map_err(|e| e.to_string())?;

            temp_wallet.save(storage, identity, &auth).map_err(|e| e.to_string())?;
            *wallet = temp_wallet;
            Ok(proc_result)
        });

        if result.is_ok() {
            let _ = self.update_seal_after_state_change(password);
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

        let result = self.with_unlocked_mut(|wallet, identity, storage, session_cache| {
            let _lock = WalletLockGuard::new(storage).map_err(|e| e.to_string())?;
            let auth =
                Self::resolve_auth_method(password, session_cache).map_err(|e| e.to_string())?;

            let mut temp_wallet = wallet.clone();
            temp_wallet
                .add_resolution_endorsement(endorsement)
                .map_err(|e| e.to_string())?;
            temp_wallet
                .save(storage, identity, &auth)
                .map_err(|e| e.to_string())?;

            *wallet = temp_wallet;
            Ok(())
        });

        if result.is_ok() {
            let _ = self.update_seal_after_state_change(password);
        }
        result
    }
}
