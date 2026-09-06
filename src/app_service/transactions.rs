//! # src/app_service/transactions.rs
//!
//! Contains the transaction-related `AppService` operations:
//! voucher creation, multi-transfer bundles, bundle reception,
//! signature workflows (request/attach/remove) and endorsement import.
//! Consolidates the former `command_handler.rs` and `app_signature_handler.rs`.

use super::{AppService, AppState, TransactionOutcome};
use crate::archive::FileVoucherArchive;
use crate::error::ValidationError;
use crate::models::conflict::ResolutionEndorsement;
use crate::models::secure_container::ContainerConfig;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{NewVoucherData, Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_validation;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::Error;
use std::collections::HashMap;

impl AppService {
    // --- Voucher & Bundle Commands (from command_handler) ---

    /// Creates a brand new voucher, adds it to the wallet, and saves the state.
    pub fn create_new_voucher(
        &mut self,
        standard_toml_content: &str,
        data: NewVoucherData,
        password: Option<&str>,
    ) -> Result<Voucher, Error> {
        // Pre-validation (possible without lock)
        let (verified_standard, standard_hash) =
            VoucherStandardDefinition::from_toml(standard_toml_content)?;

        self.with_transactional_mut(password, |temp_wallet, identity, _, _| {
            match temp_wallet.create_new_voucher(
                identity,
                &verified_standard,
                &standard_hash,
                data,
            ) {
                Ok(new_voucher) => TransactionOutcome::Commit(new_voucher),
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Creates a transfer bundle for one or more transactions and saves the new wallet state.
    pub fn create_transfer_bundle(
        &mut self,
        request: MultiTransferRequest,
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&FileVoucherArchive>,
        password: Option<&str>,
    ) -> Result<CreateBundleResult, Error> {
        // Parse the TOML definitions BEFORE the lock/state swap occurs
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = VoucherStandardDefinition::from_toml(toml_content)?;
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
                Err(Error::DoubleSpendAttemptBlocked { local_instance_id }) => {
                    temp_wallet.update_voucher_status(
                        &local_instance_id,
                        crate::wallet::instance::VoucherStatus::Quarantined {
                            reason: "Self-healing: Detected state inconsistency during transfer attempt.".to_string(),
                        },
                    );
                    TransactionOutcome::CommitAndReturnError(Error::DoubleSpendAttemptBlocked { local_instance_id })
                }
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Processes a received transaction or signature bundle.
    pub fn receive_bundle(
        &mut self,
        bundle_data: &[u8],
        standard_definitions_toml: &HashMap<String, String>,
        archive: Option<&FileVoucherArchive>,
        password: Option<&str>,
        force_accept_tolerance_bundle: bool,
    ) -> Result<ProcessBundleResult, Error> {
        // --- EPOCH ZONE MODEL: Check against Pre-Epoch Bundles ---
        self.check_bundle_against_epoch_zones(bundle_data, password, force_accept_tolerance_bundle)?;

        // Parse TOML definitions
        let mut verified_definitions = HashMap::new();
        for (uuid, toml_content) in standard_definitions_toml {
            let (def, _) = VoucherStandardDefinition::from_toml(toml_content)?;
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
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Imports a resolution endorsement.
    pub fn import_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
        password: Option<&str>,
    ) -> Result<(), Error> {
        self.with_transactional_mut(password, |temp_wallet, _, _, _| {
            match temp_wallet.add_resolution_endorsement(endorsement) {
                Ok(_) => TransactionOutcome::Commit(()),
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Internal helper to validate a bundle against epoch rollback zones.
    fn check_bundle_against_epoch_zones(
        &self,
        bundle_data: &[u8],
        password: Option<&str>,
        force_accept: bool,
    ) -> Result<(), Error> {
        if let Ok(Some((epoch_start_time, epoch))) = self.get_epoch_info(password)
            && epoch > 0 {
                let max_tx_time = match &self.state {
                    AppState::Unlocked { identity, .. } => {
                        let bundle = crate::services::bundle_processor::open_and_verify_bundle(
                            identity,
                            bundle_data,
                        )?;

                        let mut max_dt: Option<chrono::DateTime<chrono::Utc>> = None;
                        for voucher in &bundle.vouchers {
                            if let Some(last_tx) = voucher.transactions.last()
                                && let Ok(tx_dt) =
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
                        max_dt
                    }
                    _ => None,
                };

                if let Some(bundle_max_dt) = max_tx_time
                    && let Ok(epoch_dt) = chrono::DateTime::parse_from_rfc3339(&epoch_start_time) {
                        let epoch_utc = epoch_dt.with_timezone(&chrono::Utc);

                        if bundle_max_dt < epoch_utc {
                            let delta = epoch_utc - bundle_max_dt;
                            const ZONE_1_LIMIT_MINUTES: i64 = 15;
                            const ZONE_2_LIMIT_HOURS: i64 = 24;
                            const ZONE_3_LIMIT_DAYS: i64 = 28;

                            if delta > chrono::Duration::days(ZONE_3_LIMIT_DAYS) {
                                return Err(Error::BundlePredatesCurrentEpoch);
                            } else if delta > chrono::Duration::hours(ZONE_2_LIMIT_HOURS) {
                                if !force_accept {
                                    return Err(Error::BundleInExtendedRecoveryToleranceZone);
                                }
                            } else if delta > chrono::Duration::minutes(ZONE_1_LIMIT_MINUTES)
                                && !force_accept {
                                    return Err(Error::BundleInRecoveryToleranceZone);
                                }
                        }
                    }
            }
        Ok(())
    }

    // --- Signature Workflow (from app_signature_handler) ---

    /// Creates a bundle to send a voucher for signing to another participant (e.g. guarantor, notary).
    ///
    /// This operation does not modify wallet state and requires no saving.
    ///
    /// # Returns
    /// Serialized bytes of the `SecureContainer`, ready for transmission to the signer.
    ///
    /// # Errors
    /// Fails if the wallet is locked or the requested voucher does not exist.
    pub fn create_signing_request_bundle(
        &self,
        local_instance_id: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, Error> {
        self.with_unlocked_ref(|wallet, identity, _| {
            wallet
                .create_signing_request(identity, local_instance_id, config)
        })
    }

    /// Opens a received `SecureContainer` containing a signing request,
    /// and returns the voucher for review (preview).
    ///
    /// This operation does not modify wallet state.
    ///
    /// # Returns
    /// The `Voucher` object to be signed.
    pub fn open_voucher_signing_request(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<Voucher, Error> {
        self.with_unlocked_ref(|_, identity, _| {
            let container: crate::models::secure_container::SecureContainer =
                serde_json::from_slice(container_bytes).map_err(Error::from)?;

            if !matches!(
                container.c,
                crate::models::secure_container::PayloadType::VoucherForSigning
            ) {
                return Err(Error::ValidationFailed("Invalid payload type: expected VoucherForSigning".to_string()));
            }

            // HMSEC-SA06-09: Strict envelope validation BEFORE payload processing.
            container.verify_integrity()?;

            let payload = container.open(
                identity, password,
            )?;

            let voucher: Voucher = serde_json::from_slice(&payload).map_err(Error::from)?;
            Ok(voucher)
        })
    }

    /// Creates a detached signature in response to a signing request.
    ///
    /// This operation is called by the signer and stores the witnessed voucher
    /// in the local wallet under `Endorsed` status as an audit log.
    ///
    /// # Returns
    /// Serialized bytes of the `SecureContainer` with the signature, ready for return transmission.
    ///
    /// # Errors
    /// Fails if the signer's wallet is locked or saving fails.
    pub fn create_detached_signature_response_bundle(
        &mut self,
        voucher_to_sign: &Voucher,
        role: &str,
        include_details: bool,
        config: ContainerConfig,
        password: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        self.with_transactional_mut(password, |temp_wallet, identity, _, _| {
            // Create wrapper object with metadata
            let signature_data = DetachedSignature::Signature(VoucherSignature {
                role: role.to_string(),
                ..Default::default()
            });

            // Create signature
            let bundle_bytes = match temp_wallet.create_detached_signature_response(
                identity,
                voucher_to_sign,
                signature_data,
                include_details,
                config,
            ) {
                Ok(bytes) => bytes,
                Err(e) => return TransactionOutcome::Rollback(e),
            };

            // Store witnessed voucher in local wallet
            use crate::services::crypto::get_hash_from_slices;
            let voucher_id_bytes = voucher_to_sign.voucher_id.as_bytes();
            let signer_id_bytes = temp_wallet.profile.user_id.as_bytes();
            let role_bytes = role.as_bytes();
            let local_id = get_hash_from_slices(&[voucher_id_bytes, signer_id_bytes, role_bytes]);
            temp_wallet.add_voucher_instance(
                local_id,
                voucher_to_sign.clone(),
                crate::wallet::instance::VoucherStatus::Endorsed {
                    role: role.to_string(),
                },
            );

            TransactionOutcome::Commit(bundle_bytes)
        })
    }

    /// Processes a received detached signature, attaches it to the local voucher, and saves state.
    ///
    /// # Arguments
    /// * `container_bytes` - Raw bytes of the `SecureContainer` containing the signature.
    /// * `standard_toml_content` - Standard content for validation.
    /// * `container_password` - Optional password to open container (for symmetric encryption).
    /// * `wallet_password` - Password to save updated wallet state.
    ///
    /// # Errors
    /// Fails if the wallet is locked, signature is invalid, associated voucher is not found,
    /// or storage access fails.
    pub fn process_and_attach_signature(
        &mut self,
        container_bytes: &[u8],
        standard_toml_content: &str,
        container_password: Option<&str>,
        wallet_password: Option<&str>,
    ) -> Result<String, Error> {
        let (verified_standard, _) = VoucherStandardDefinition::from_toml(
            standard_toml_content,
        )?;

        self.with_transactional_mut(wallet_password, |temp_wallet, identity, _, _| {
            // 1. Attach signature to temporary wallet instance.
            let updated_instance_id = match temp_wallet.process_and_attach_signature(
                identity,
                container_bytes,
                container_password,
            ) {
                Ok(id) => id,
                Err(e) => return TransactionOutcome::Rollback(e),
            };

            // 2. Determine new status based on result.
            let instance = match temp_wallet.get_voucher_instance(&updated_instance_id).cloned() {
                Some(inst) => inst,
                None => {
                    return TransactionOutcome::Rollback(Error::VoucherNotFound(
                        updated_instance_id,
                    ));
                }
            };
            let previous_status = instance.status.clone();

            let validation_result =
                voucher_validation::validate_voucher_against_standard(
                    &instance.voucher,
                    &verified_standard,
                );

            let (operation_outcome, new_status) = match validation_result {
                Ok(_) => {
                    // Validation successful! The voucher is now Active.
                    (Ok(updated_instance_id.clone()), VoucherStatus::Active)
                }
                Err(Error::Validation(
                    validation_err @ ValidationError::InvalidTimeOrder { .. },
                )) => {
                    // SECURITY (AUDIT-W4-WC-003 regression pin):
                    // time-ordering violations are STRUCTURAL
                    // chain corruption (unparseable/inconsistent
                    // timestamps), not a benign "signatures still
                    // missing" state. Fail closed into quarantine
                    // like other fatal validation errors.
                    (
                        Err(Error::Validation(validation_err.clone())),
                        VoucherStatus::Quarantined {
                            reason: validation_err.to_string(),
                        },
                    )
                }
                Err(Error::Validation(validation_err)) => {
                    // This is NOT a fatal error. Operation succeeded,
                    // voucher simply remains incomplete.
                    let reasons = vec![
                        crate::ValidationFailureReason::RequiredSignatureMissing {
                            role_description: validation_err.to_string(),
                        },
                    ];
                    (Ok(updated_instance_id.clone()), VoucherStatus::Incomplete { reasons })
                }
                Err(fatal_error) => {
                    // THIS is a fatal error (e.g. standard mismatch, crypto error).
                    (
                        Err(fatal_error.clone()),
                        VoucherStatus::Quarantined {
                            reason: fatal_error.to_string(),
                        },
                    )
                }
            };

            // SECURITY (AUDIT-W4-WC-003): status transitions
            // triggered by a detached-signature attachment
            // are only legitimate for vouchers the wallet
            // itself holds in the issuance/completion flow
            // (Active/Incomplete). A witness copy stored as
            // `Endorsed` (e.g. from a third-party signing
            // request) must never be activated by a mere
            // voucher_id match — that would bypass every
            // receive-path ownership gate. Adjudicated
            // (`Quarantined`) and historical (`Archived`)
            // states stay final as well (F15 monotonicity).
            let final_status = if matches!(
                previous_status,
                VoucherStatus::Active | VoucherStatus::Incomplete { .. }
            ) {
                new_status
            } else {
                previous_status
            };

            temp_wallet.update_voucher_status(&updated_instance_id, final_status);

            match operation_outcome {
                Ok(res) => TransactionOutcome::Commit(res),
                Err(err) => TransactionOutcome::CommitAndReturnError(err),
            }
        })
    }

    /// Evaluates the impact of a proposed signature (role and the user's current profile)
    ///
    /// # Returns
    /// The `SignatureImpact` detailing if the role is allowed, and any resulting conflicts, resolved rules, or gentle hints.
    pub fn evaluate_signature_suitability(
        &self,
        voucher: &Voucher,
        role: &str,
        standard_toml_content: &str,
    ) -> Result<voucher_validation::SignatureImpact, Error> {
        let (verified_standard, _) = VoucherStandardDefinition::from_toml(
            standard_toml_content,
        )?;

        let profile = self.with_wallet(|w| w.profile.to_public_profile())?;

        voucher_validation::evaluate_signature_impact(
            voucher,
            &verified_standard,
            role,
            &profile,
        )
    }

    /// Removes an additional signature (e.g. from guarantors or witnesses) from a voucher.
    ///
    /// This operation may only be performed by the voucher creator and only
    /// while the voucher is not yet in circulation (only one init transaction present).
    ///
    /// # Arguments
    /// * `local_instance_id` - ID of the voucher in the local wallet.
    /// * `signature_id` - ID of the signature to remove.
    /// * `wallet_password` - Password to save updated wallet state.
    ///
    /// # Returns
    /// A `Result` returning `Ok(())` on success.
    ///
    /// # Errors
    /// Fails if the wallet is locked, signature cannot be removed
    /// (e.g. because voucher is already in circulation or requesting identity is not the creator),
    /// or storage access fails.
    pub fn remove_voucher_signature(
        &mut self,
        local_instance_id: &str,
        signature_id: &str,
        wallet_password: Option<&str>,
    ) -> Result<(), Error> {
        self.with_transactional_mut(wallet_password, |temp_wallet, identity, _, _| {
            match temp_wallet.remove_signature(identity, local_instance_id, signature_id) {
                Ok(()) => TransactionOutcome::Commit(()),
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }
}
