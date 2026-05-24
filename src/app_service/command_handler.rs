//! # src/app_service/command_handler.rs
//!
//! Contains the central write actions (Commands) of the `AppService`
//! that modify and persist the state of the wallet.

use super::{AppService, AppState, TransactionOutcome, AppFacadeError};
use crate::archive::VoucherArchive;
use crate::models::conflict::ResolutionEndorsement;
use crate::models::voucher::Voucher;
use crate::services::standard_manager;
use crate::services::voucher_manager::NewVoucherData;
use crate::wallet::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::VoucherCoreError;

use std::collections::HashMap;

impl AppService {
    // --- Actions (Commands) ---

    /// Creates a brand new voucher, adds it to the wallet, and saves the state.
    pub fn create_new_voucher(
        &mut self,
        standard_toml_content: &str,
        lang_preference: &str,
        data: NewVoucherData,
        password: Option<&str>,
    ) -> Result<Voucher, AppFacadeError> {
        // Pre-validation (possible without lock)
        let (verified_standard, standard_hash) =
            standard_manager::verify_and_parse_standard(standard_toml_content)
                .map_err(AppFacadeError::from)?;

        self.with_transactional_mut(password, |temp_wallet, identity, _, _| {
            match temp_wallet.create_new_voucher(
                identity,
                &verified_standard,
                &standard_hash,
                lang_preference,
                data,
            ) {
                Ok(new_voucher) => TransactionOutcome::Commit(new_voucher),
                Err(e) => TransactionOutcome::Rollback(AppFacadeError::from(e)),
            }
        })
    }

    /// Creates a transfer bundle for one or more transactions and saves the new wallet state.
    pub fn create_transfer_bundle(
        &mut self,
        request: MultiTransferRequest,
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: Option<&str>,
    ) -> Result<CreateBundleResult, AppFacadeError> {
        // Parse the TOML definitions BEFORE the lock/state swap occurs
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = standard_manager::verify_and_parse_standard(toml_content)
                .map_err(AppFacadeError::from)?;
            verified_definitions.insert(uuid.clone(), def);
        }

        self.with_transactional_mut(password, |temp_wallet, identity, _, _| {
            match temp_wallet.execute_multi_transfer_and_bundle(
                identity,
                &verified_definitions,
                request,
                archive,
            ) {
                Ok(create_result) => TransactionOutcome::Commit(create_result),
                // --- SELF-HEALING ---
                Err(crate::error::VoucherCoreError::DoubleSpendAttemptBlocked { local_instance_id }) => {
                    temp_wallet.update_voucher_status(
                        &local_instance_id,
                        crate::wallet::instance::VoucherStatus::Quarantined {
                            reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                        },
                    );
                    TransactionOutcome::CommitAndReturnError(AppFacadeError::DoubleSpendAttemptBlocked(local_instance_id))
                }
                Err(e) => TransactionOutcome::Rollback(AppFacadeError::from(e)),
            }
        })
    }

    /// Processes a received transaction or signature bundle.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&dyn VoucherArchive>,
        password: Option<&str>,
        force_accept_tolerance_bundle: bool,
    ) -> Result<ProcessBundleResult, AppFacadeError> {
        // --- EPOCH ZONE MODEL: Check against Pre-Epoch Bundles ---
        self.check_bundle_against_epoch_zones(bundle_data, password, force_accept_tolerance_bundle)?;

        // Parse TOML definitions
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = standard_manager::verify_and_parse_standard(toml_content)
                .map_err(AppFacadeError::from)?;
            verified_definitions.insert(uuid.clone(), def);
        }

        self.with_transactional_mut(password, |temp_wallet, identity, _, _| {
            if let Err(e) = Self::validate_vouchers_in_bundle(identity, bundle_data, standard_definitions_toml) {
                return TransactionOutcome::Rollback(e);
            }

            match temp_wallet.process_encrypted_transaction_bundle(
                identity,
                bundle_data,
                archive,
                &verified_definitions,
            ) {
                Ok(proc_result) => TransactionOutcome::Commit(proc_result),
                Err(e) => TransactionOutcome::Rollback(AppFacadeError::from(e)),
            }
        })
    }

    /// Imports a resolution endorsement.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: Option<&str>,
    ) -> Result<(), AppFacadeError> {
        self.with_transactional_mut(password, |temp_wallet, _, _, _| {
            match temp_wallet.add_resolution_endorsement(endorsement) {
                Ok(_) => TransactionOutcome::Commit(()),
                Err(e) => TransactionOutcome::Rollback(AppFacadeError::from(e)),
            }
        })
    }

    /// Internal helper to validate a bundle against epoch rollback zones.
    fn check_bundle_against_epoch_zones(
        &self,
        bundle_data: &[u8],
        password: Option<&str>,
        force_accept: bool,
    ) -> Result<(), AppFacadeError> {
        if let Ok(Some((epoch_start_time, epoch))) = self.get_epoch_info(password) {
            if epoch > 0 {
                let max_tx_time = match &self.state {
                    AppState::Unlocked { identity, .. } => {
                        let bundle = crate::services::bundle_processor::open_and_verify_bundle(
                            identity,
                            bundle_data,
                        )
                        .map_err(AppFacadeError::from)?;

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
                                return Err(AppFacadeError::from(VoucherCoreError::BundlePredatesCurrentEpoch));
                            } else if delta > chrono::Duration::hours(ZONE_2_LIMIT_HOURS) {
                                if !force_accept {
                                    return Err(AppFacadeError::from(
                                        VoucherCoreError::BundleInExtendedRecoveryToleranceZone
                                    ));
                                }
                            } else if delta > chrono::Duration::minutes(ZONE_1_LIMIT_MINUTES) {
                                if !force_accept {
                                    return Err(AppFacadeError::from(
                                        VoucherCoreError::BundleInRecoveryToleranceZone,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
