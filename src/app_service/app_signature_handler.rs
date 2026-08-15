//! # src/app_service/app_signature_handler.rs
//!
//! Contains all `AppService` functions related to the signature workflow,
//! such as requesting, creating, and attaching detached signatures.

use super::{AppService, AppState, AppFacadeError};
use crate::models::secure_container::ContainerConfig;
use crate::models::signature::DetachedSignature;
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::services::voucher_validation;
use crate::wallet::instance::VoucherStatus;
use crate::{ValidationFailureReason, VoucherCoreError};

impl AppService {
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
    ) -> Result<Vec<u8>, AppFacadeError> {
        let wallet = self.get_wallet()?;
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())),
        };
        wallet
            .create_signing_request(identity, local_instance_id, config)
            .map_err(AppFacadeError::from)
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
    ) -> Result<Voucher, AppFacadeError> {
        let identity = match &self.state {
            AppState::Unlocked { identity, .. } => identity,
            AppState::Locked => return Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())),
        };

        let container: crate::models::secure_container::SecureContainer =
            serde_json::from_slice(container_bytes).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;

        if !matches!(
            container.c,
            crate::models::secure_container::PayloadType::VoucherForSigning
        ) {
            return Err(AppFacadeError::ValidationError("Invalid payload type: expected VoucherForSigning".to_string()));
        }

        let payload = crate::services::secure_container_manager::open_secure_container(
            &container, identity, password,
        )
        .map_err(AppFacadeError::from)?;

        let voucher: Voucher = serde_json::from_slice(&payload).map_err(|e| AppFacadeError::JsonError(e.to_string()))?;
        Ok(voucher)
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
    ) -> Result<Vec<u8>, AppFacadeError> {
        // --- FORK-LOCK CHECK ---
        self.check_fork_lock(password).map_err(AppFacadeError::from)?;

        // BUG-FIX: Determine AuthMethod BEFORE state replacement
        let auth_method = match password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key()?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state): (Result<Vec<u8>, AppFacadeError>, AppState) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                // Create wrapper object with metadata
                let signature_data = DetachedSignature::Signature(VoucherSignature {
                    role: role.to_string(),
                    ..Default::default()
                });

                // Create signature
                let bundle_bytes = wallet
                    .create_detached_signature_response(
                        &identity,
                        voucher_to_sign,
                        signature_data,
                        include_details,
                        config,
                    )
                    .map_err(AppFacadeError::from);

                match bundle_bytes {
                    Ok(bytes) => {
                        // Store witnessed voucher in local wallet
                        let mut temp_wallet = wallet.clone();
                        // For Endorsed vouchers we use different ID generation,
                        // since signer has no ownership history for voucher.
                        // We use voucher_id + signer_id + role as deterministic ID.
                        use crate::services::crypto_utils::get_hash_from_slices;
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

                        // Save wallet state
                        match temp_wallet.save(&mut storage, &identity, &auth_method) {
                            Ok(_) => (
                                Ok(bytes),
                                AppState::Unlocked {
                                    storage,
                                    wallet: temp_wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Err(e) => (
                                Err(AppFacadeError::from(e)),
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
                        Err(e),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                }
            }
            AppState::Locked => (Err(AppFacadeError::WalletLocked("Wallet is locked".to_string())), AppState::Locked),
        };

        self.state = new_state;
        // Update seal if action succeeded
        if result.is_ok() {
            let _ = self.update_seal_after_state_change(password);
        }
        result
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
    ) -> Result<String, AppFacadeError> {
        // --- FORK-LOCK CHECK ---
        self.check_fork_lock(wallet_password).map_err(AppFacadeError::from)?;

        // BUG-FIX: Determine AuthMethod BEFORE state replacement
        let auth_method = match wallet_password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key()?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state): (Result<String, AppFacadeError>, AppState) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                match crate::services::standard_manager::verify_and_parse_standard(
                    standard_toml_content,
                ) {
                    Err(e) => (
                        Err(AppFacadeError::from(e)),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok((verified_standard, _)) => {
                        // --- BEGIN TRANSACTION ---
                        let mut temp_wallet = wallet.clone();

                        // 1. Attach signature to temporary wallet instance.
                        match temp_wallet.process_and_attach_signature(&identity, container_bytes, container_password) {
                            Err(e) => (
                                Err(AppFacadeError::from(e)),
                                AppState::Unlocked {
                                    storage,
                                    wallet,
                                    identity,
                                    session_cache,
                                },
                            ),
                            Ok(updated_instance_id) => {
                                // 2. Determine new status based on result.
                                let instance = temp_wallet
                                    .get_voucher_instance(&updated_instance_id)
                                    .cloned()
                                    .unwrap(); // Must exist

                                // --- START REPLACED LOGIC ---
                                // The old logic called `self.determine_voucher_status`, which
                                // incorrectly treated incompleteness as a fatal error.
                                // We now call validation directly and interpret result correctly.

                                let validation_result =
                                    voucher_validation::validate_voucher_against_standard(
                                        &instance.voucher,
                                        &verified_standard,
                                    );

                                let (operation_result, new_status) = match validation_result {
                                    Ok(_) => {
                                        // Validation successful! The voucher is now Active.
                                        (Ok(updated_instance_id.clone()), VoucherStatus::Active)
                                    }
                                    Err(VoucherCoreError::Validation(validation_err)) => {
                                        // This is NOT a fatal error. Operation succeeded,
                                        // voucher simply remains incomplete.
                                        // Convert ValidationError manually to ValidationFailureReason,
                                        // since no `From` implementation exists.
                                        let reasons = vec![
                                            ValidationFailureReason::RequiredSignatureMissing {
                                                role_description: validation_err.to_string(),
                                            },
                                        ];
                                        (Ok(updated_instance_id.clone()), VoucherStatus::Incomplete { reasons })
                                    }
                                    Err(fatal_error) => {
                                        // THIS is a fatal error (e.g. standard mismatch, crypto error).
                                        temp_wallet.update_voucher_status(
                                            &updated_instance_id,
                                            VoucherStatus::Quarantined {
                                                reason: fatal_error.to_string(),
                                            },
                                        );
                                        (
                                             Err(AppFacadeError::ValidationError(format!(
                                                "Voucher quarantined due to fatal validation error: {}",
                                                fatal_error
                                            ))),
                                            VoucherStatus::Quarantined {
                                                reason: fatal_error.to_string(),
                                            },
                                        )
                                    }
                                };

                                temp_wallet.update_voucher_status(&updated_instance_id, new_status);
                                // 3. Attempt to save changes ("Commit").
                                match temp_wallet.save(&mut storage, &identity, &auth_method) {
                                    Ok(_) => (
                                        // Success: Return operation result and set new wallet instance.
                                        operation_result,
                                        AppState::Unlocked {
                                            storage,
                                            wallet: temp_wallet,
                                            identity,
                                            session_cache,
                                        },
                                    ),
                                    Err(e) => (
                                        // Error: Discard changes and return storage error.
                                        Err(AppFacadeError::from(e)),
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
            AppState::Locked => (Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())), AppState::Locked),
        };

        self.state = new_state;
        // Update seal if action succeeded
        if result.is_ok() {
            let _ = self.update_seal_after_state_change(wallet_password);
        }
        result
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
    ) -> Result<crate::services::signature_manager::SignatureImpact, AppFacadeError> {
        let (verified_standard, _) = crate::services::standard_manager::verify_and_parse_standard(
            standard_toml_content,
        )
        .map_err(AppFacadeError::from)?;

        let profile = self.get_public_profile()?;
        
        crate::services::signature_manager::evaluate_signature_impact(
            voucher,
            &verified_standard,
            role,
            &profile,
        )
        .map_err(AppFacadeError::from)
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
    ) -> Result<(), AppFacadeError> {
        // --- FORK-LOCK CHECK ---
        self.check_fork_lock(wallet_password).map_err(AppFacadeError::from)?;

        // Determine AuthMethod BEFORE state replacement
        let auth_method = match wallet_password {
            Some(pwd_str) => crate::AuthMethod::Password(pwd_str),
            None => {
                let session_key = self.get_session_key()?;
                crate::AuthMethod::SessionKey(session_key)
            }
        };

        let current_state = std::mem::replace(&mut self.state, AppState::Locked);

        let (result, new_state): (Result<(), AppFacadeError>, AppState) = match current_state {
            AppState::Unlocked {
                mut storage,
                wallet,
                identity,
                session_cache,
            } => {
                let mut temp_wallet = wallet.clone();

                match temp_wallet.remove_signature(&identity, local_instance_id, signature_id) {
                    Err(e) => (
                        Err(AppFacadeError::from(e)),
                        AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        },
                    ),
                    Ok(_) => {
                        // Attempt to save changes
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
                            Err(e) => (
                                Err(AppFacadeError::from(e)),
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
            AppState::Locked => (Err(AppFacadeError::WalletLocked("Wallet is locked.".to_string())), AppState::Locked),
        };

        self.state = new_state;
        // Update seal if action succeeded
        if result.is_ok() {
            let _ = self.update_seal_after_state_change(wallet_password);
        }
        result
    }
}
