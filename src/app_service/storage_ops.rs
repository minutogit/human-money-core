//! # src/app_service/storage_ops.rs
//!
//! Contains the `AppService` operations for storage-related concerns:
//! seals, storage integrity, standard-container import/export/delete,
//! and generic encrypted data storage.
//! Consolidates the former `seal_handler.rs`, `standard_container_handler.rs`
//! and `data_encryption.rs`.

use super::{AppService, AppState};
use crate::app_service::orchestrator::TransactionOrchestrator;
use crate::models::profile::UserIdentity;
use crate::models::seal::{LocalSealRecord, SealSyncState, SyncStatus, WalletSeal};
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::storage_integrity::StorageIntegrityRecord;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::storage::{AuthMethod, FileStorage, WalletLockGuard};
use crate::Error;
use std::fs;
use std::path::Path;

impl AppService {
    // --- Seal & Integrity (from seal_handler) ---

    /// Checks the integrity of all storage items against the Storage Integrity Record.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn check_integrity(
        &mut self,
        password: Option<&str>,
    ) -> Result<crate::models::storage_integrity::IntegrityReport, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;

                let integrity_record = storage.load_integrity()?;
                let seal_record = storage
                    .load_seal(&auth)?;

                match (integrity_record, seal_record) {
                    (Some(ir), Some(s)) => {
                        let actual_hashes = storage.get_all_item_hashes()?;
                        ir.verify(
                            &s.seal,
                            actual_hashes,
                            &identity.user_id,
                        )}
                    (None, Some(_)) => Ok(crate::models::storage_integrity::IntegrityReport::MissingIntegrityRecord),
                    (Some(_), None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Should not happen
                    (None, None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Migration
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Repairs the Storage Integrity Record by accepting the current state of the files as "correct".
    ///
    /// This method should only be called if the user has explicitly confirmed the integrity
    /// warning (e.g., "OK, I accept these changes").
    /// Creates a new, signed Integrity Record for all currently existing records.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn repair_integrity(&mut self, password: Option<&str>) -> Result<(), Error> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;

                // 1. Load current seal (base point for the integrity record)
                let record = storage
                    .load_seal(&auth)?
                    .ok_or_else(|| Error::App(crate::error::AppError::MissingSealForIntegrityRepair))?;

                // 2. Read current hashes from disk
                let hashes = storage.get_all_item_hashes()?;

                // 3. Create a new integrity record
                let integrity_record = StorageIntegrityRecord::create_record(
                    identity,
                    &record.seal,
                    hashes,
                )?;

                // 4. Save
                storage
                    .save_integrity(&integrity_record)?;

                Ok(())
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    // --- B) Local Sync Tracking (Upload Workflow for Client Apps) ---

    /// Returns the current sync status of the local seal.
    #[allow(unused_variables)]
    pub fn get_seal_sync_status(&self) -> Result<SyncStatus, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => Ok(r.sync_status),
                    None => Err(Error::App(crate::error::AppError::MissingSealForRecovery)),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Returns the raw `WalletSeal` (without metadata!) as a JSON byte array for upload.
    #[allow(unused_variables)]
    pub fn get_seal_for_upload(&self) -> Result<Option<Vec<u8>>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => match r.sync_status {
                        SyncStatus::PendingUpload => {
                            let seal_bytes = serde_json::to_vec(&r.seal)?;
                            Ok(Some(seal_bytes))
                        }
                        SyncStatus::Synced => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Acknowledges the successful upload of a seal to the server.
    ///
    /// Standardized via [`TransactionOrchestrator`] with [`MutationScope::SealMetadataOnly`]:
    /// only `storage.save_seal` is performed without a wallet generation bump,
    /// under the same fork-lock, file-lock and seal-gate discipline as all
    /// other mutating commands.
    pub fn acknowledge_seal_sync(
        &mut self,
        uploaded_seal_hash: &str,
        password: Option<&str>,
    ) -> Result<(), Error> {
        let uploaded = uploaded_seal_hash.to_string();
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            let record_opt = storage.load_seal(auth)?;
            match record_opt {
                Some(mut record) => {
                    let current_hash = record.seal.compute_hash()?;
                    if current_hash != uploaded {
                        return Err(Error::SealSyncRaceCondition);
                    }
                    record.sync_status = SyncStatus::Synced;
                    storage.save_seal(auth, &record)?;
                    Ok(())
                }
                None => Err(Error::RequiresSealRecovery),
            }
        })
    }

    // --- C) Remote Sync Check & Hard Lock ---

    /// Compares a seal downloaded from the server with the local seal.
    ///
    /// Standardized via [`TransactionOrchestrator`] with [`MutationScope::SealMetadataOnly`]:
    /// only `storage.save_seal` is performed when a fork is detected, without
    /// a wallet generation bump, under the same fork-lock and file-lock discipline.
    pub fn compare_remote_seal(
        &mut self,
        remote_seal_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<SealSyncState, Error> {
        let remote_bytes = remote_seal_bytes.to_vec();
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, wallet, identity| {
            let remote_seal: WalletSeal = serde_json::from_slice(&remote_bytes)?;

            match remote_seal.verify_integrity(
                &identity.user_id,
                &identity.user_id,
                &wallet.local_instance_id,
            ) {
                Ok(crate::models::seal::SealValidationResult::Valid) => {},
                Ok(crate::models::seal::SealValidationResult::LegacyValid) => {},
                Ok(crate::models::seal::SealValidationResult::DeviceMismatch { .. }) => {
                    // Remote seal from other device is OK for comparison (indicator for fork check)
                },
                Ok(other) => {
                    return Err(Error::App(
                        crate::error::AppError::RemoteSealIntegrityFailed {
                            details: format!("{:?}", other),
                        },
                    ));
                }
                Err(e) => return Err(e),
            }

            let record = match storage.load_seal(auth)? {
                Some(r) => r,
                None => {
                    return Err(Error::App(crate::error::AppError::MissingLocalSeal))
                }
            };

            let sync_state = record.seal.compare_with(&remote_seal);

            if sync_state == SealSyncState::ForkDetected {
                let mut locked_record = record;
                locked_record.is_locked_due_to_fork = true;
                let _ = storage.save_seal(auth, &locked_record);
            }

            Ok(sync_state)
        })
    }

    // --- Internal helper methods (Seal) ---

    fn get_read_auth(
        &self,
        session_cache: &Option<super::SessionCache>,
    ) -> Result<AuthMethod<'_>, Error> {
        match session_cache {
            Some(cache) => {
                if cache.last_activity.elapsed() > cache.session_duration {
                    Err(Error::SessionExpired("Session timed out. Please provide password.".to_string()))
                } else {
                    Ok(AuthMethod::SessionKey(cache.session_key))
                }
            }
            None => Err(Error::SessionNotActive("Password required. Please use 'unlock_session'.".to_string())),
        }
    }

    pub(super) fn verify_seal_on_login(
        storage: &FileStorage,
        password: &str,
        local_instance_id: &str,
    ) -> Result<bool, Error> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage.load_seal(&auth).ok().flatten();

        if let Some(record) = &seal_record {
            // Check fork lock
            if record.is_locked_due_to_fork {
                return Err(Error::WalletLockedDueToFork);
            }

            // Check seal integrity and instance ID
            let validation = record.seal.verify_integrity(
                &record.seal.payload.user_id,
                &record.seal.payload.user_id,
                local_instance_id,
            )?;

            match validation {
                crate::models::seal::SealValidationResult::Valid => {}
                crate::models::seal::SealValidationResult::LegacyValid => {
                    println!("Legacy Wallet detected. Will bind to this device after login.");
                    return Ok(true); // needs_legacy_binding = true
                }
                crate::models::seal::SealValidationResult::DeviceMismatch { expected, actual } => {
                    let err_msg = format!(
                        "Device Mismatch: This wallet is bound to device '{}', but you are on '{}'. \
                        To prevent double-spending and permanent reputation loss, a wallet profile (specific User Prefix) \
                        must only be active on ONE device at a time.\n\n\
                        - OPTION A (Move): Perform a 'Device Handover' to permanently move the wallet here. \
                        IMPORTANT: Once handed over, you MUST NOT use this profile on the old device anymore. Please delete the wallet folder on the old device to prevent accidental usage.\n\
                        - OPTION B (Concurrent): Create a NEW profile on this device \
                        with the same Seed Phrase but a DIFFERENT 'User Prefix', then transfer vouchers between them.",
                        expected, actual
                    );
                    return Err(Error::App(crate::error::AppError::DeviceMismatch {
                        message: err_msg,
                    }));
                }
                other => {
                    return Err(Error::App(crate::error::AppError::SealIntegrityFailed {
                        details: format!("{:?}", other),
                    }));
                }
            }

            // Load the RAW own_fingerprints store directly from storage
            let raw_own_fingerprints = storage.load_own_fingerprints(&auth)?;

            let current_state_hash =
                crate::storage::seal_service::SealService::calculate_state_hash(&raw_own_fingerprints)?;

            if record.seal.payload.state_hash != current_state_hash {
                return Err(Error::StateRollbackDetected);
            }
        }
        Ok(false)
    }

    pub(super) fn migrate_seal_on_login(
        storage: &mut FileStorage,
        wallet: &crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        password: &str,
        needs_legacy_binding: bool,
    ) -> Result<(), Error> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage
            .load_seal(&auth)?;

        // Only migrate if necessary (legacy binding or no seal present)
        if needs_legacy_binding || seal_record.is_none() {
            let state_hash =
                crate::storage::seal_service::SealService::calculate_state_hash(&wallet.own_fingerprints)?;

            let migrated_seal = if needs_legacy_binding {
                if let Some(existing_record) = seal_record {
                    // Legacy Migration: Update existing seal to preserve the tx_nonce
                    existing_record.seal.update(
                        identity,
                        &state_hash,
                        &wallet.local_instance_id,
                    )?
                } else {
                    // Completely new seal (Genesis)
                    WalletSeal::create_initial(
                        &identity.user_id,
                        identity,
                        &state_hash,
                        &wallet.local_instance_id,
                    )?
                }
            } else {
                // Completely new seal (Genesis)
                WalletSeal::create_initial(
                    &identity.user_id,
                    identity,
                    &state_hash,
                    &wallet.local_instance_id,
                )?
            };

            let new_record = LocalSealRecord {
                seal: migrated_seal.clone(),
                sync_status: SyncStatus::PendingUpload,
                is_locked_due_to_fork: false,
            };
            storage
                .save_seal(&auth, &new_record)?;

            // Initialize integrity for the new migrated seal
            let hashes = storage.get_all_item_hashes().unwrap_or_default();
            if let Ok(ir) = StorageIntegrityRecord::create_record(
                identity,
                &migrated_seal,
                hashes,
            ) {
                let _ = storage.save_integrity(&ir);
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    pub(crate) fn check_fork_lock(&self, password: Option<&str>) -> Result<(), Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) if r.is_locked_due_to_fork => Err(Error::WalletLockedDueToFork),
                    _ => Ok(()),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    #[allow(unused_variables)]
    pub(crate) fn get_epoch_info(
        &self,
        password: Option<&str>,
    ) -> Result<Option<(String, u32)>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => Ok(Some((
                        r.seal.payload.epoch_start_time.clone(),
                        r.seal.payload.epoch,
                    ))),
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Verifies that a freshly loaded wallet state is covered by the current
    /// cryptographic seal before it may be operated on.
    ///
    /// Delegates to [`crate::storage::seal_service::SealService::verify_state_matches_seal`].
    #[allow(dead_code)]
    pub(crate) fn verify_state_matches_seal(
        storage: &FileStorage,
        auth: &crate::storage::AuthMethod<'_>,
        wallet: &crate::wallet::Wallet,
    ) -> Result<(), Error> {
        crate::storage::seal_service::SealService::verify_state_matches_seal(storage, auth, wallet)
    }

    pub(crate) fn update_seal_after_state_change(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), Error> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;
                crate::storage::seal_service::SealService::persist_seal_for_wallet_state(
                    storage, identity, &auth, wallet,
                )
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Persists the WalletSeal and the Integrity Record for the given wallet
    /// state without touching the AppService's in-memory state.
    ///
    /// Delegates to [`crate::storage::seal_service::SealService::persist_seal_for_wallet_state`].
    #[allow(dead_code)]
    pub(crate) fn persist_seal_for_wallet_state(
        storage: &mut FileStorage,
        identity: &crate::models::profile::UserIdentity,
        auth: &crate::storage::AuthMethod<'_>,
        wallet: &crate::wallet::Wallet,
    ) -> Result<(), Error> {
        crate::storage::seal_service::SealService::persist_seal_for_wallet_state(
            storage, identity, auth, wallet,
        )
    }

    // --- Standard Container Handler (from standard_container_handler) ---

    /// Exports a `VoucherStandardDefinition` (TOML content) as a serialized `SecureContainer` (`.standard` file).
    pub fn export_voucher_standard(
        &self,
        standard_toml: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, Error> {
        // 1. Verify that the TOML content is a valid, signed standard definition.
        let _ = VoucherStandardDefinition::from_toml(standard_toml)?;

        // 2. Ensure wallet is unlocked to get sender identity.
        let identity = self.get_identity()?;

        // 3. Create the secure container with VoucherStandardDefinition payload type.
        let container = SecureContainer::seal(
            identity,
            &config,
            standard_toml.as_bytes(),
            PayloadType::VoucherStandardDefinition,
        )?;

        // 4. Serialize container to JSON bytes.
        serde_json::to_vec(&container).map_err(Error::from)
    }

    /// Inspects a `.standard` container file (`SecureContainer` JSON bytes) without saving it.
    pub fn inspect_voucher_standard_container(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<VoucherStandardDefinition, Error> {
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(Error::App(
                        crate::error::AppError::InvalidPayloadTypeVoucherStandardDefinition,
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = container.open(identity, password)?;

                String::from_utf8(payload_bytes).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InContainerPayload {
                        reason: e.to_string(),
                    })
                })?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec()).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InStandardFile {
                        reason: e.to_string(),
                    })
                })?
            }
        };

        let (verified_standard, _) = VoucherStandardDefinition::from_toml(&toml_str)?;
        Ok(verified_standard)
    }

    /// Imports a `.standard` container file or a raw `standard.toml` file into `voucher_standards/`.
    pub fn import_voucher_standard(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
        target_dir: &Path,
    ) -> Result<String, Error> {
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(Error::App(
                        crate::error::AppError::InvalidPayloadTypeVoucherStandardDefinition,
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = container.open(identity, password)?;

                String::from_utf8(payload_bytes).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InContainerPayload {
                        reason: e.to_string(),
                    })
                })?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec()).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InStandardFile {
                        reason: e.to_string(),
                    })
                })?
            }
        };

        let (verified_standard, _) = VoucherStandardDefinition::from_toml(&toml_str)?;
        let standard_uuid = verified_standard.immutable.identity.uuid;

        if standard_uuid.is_empty()
            || standard_uuid.contains('/')
            || standard_uuid.contains('\\')
            || standard_uuid.contains("..")
        {
            return Err(Error::App(crate::error::AppError::InvalidStandardUuid {
                uuid: standard_uuid,
            }));
        }

        let standard_folder = target_dir.join(&standard_uuid);
        fs::create_dir_all(&standard_folder)
            .map_err(Error::from)?;

        let file_path = standard_folder.join("standard.toml");

        if file_path.exists() {
            let existing_content = fs::read_to_string(&file_path).map_err(|e| {
                crate::storage::StorageError::Io(format!(
                    "Installed standard.toml for uuid '{}' exists but cannot be read: {}",
                    standard_uuid, e
                ))
            })?;
            if existing_content != toml_str {
                return Err(Error::App(crate::error::AppError::StandardAlreadyInstalled {
                    uuid: standard_uuid.clone(),
                }));
            }
            return Ok(standard_uuid);
        }

        let temp_path = standard_folder.join("standard.toml.tmp");
        fs::write(&temp_path, &toml_str)
            .map_err(Error::from)?;
        fs::rename(&temp_path, &file_path)
            .map_err(Error::from)?;

        Ok(standard_uuid)
    }

    /// Deletes a voucher standard directory if no vouchers referencing it exist in the wallet.
    pub fn delete_voucher_standard(
        &self,
        standard_id: &str,
        target_dir: &Path,
    ) -> Result<(), Error> {
        // 1. Path-traversal validation
        if standard_id.is_empty()
            || standard_id.contains('/')
            || standard_id.contains('\\')
            || standard_id.contains("..")
        {
            return Err(Error::App(
                crate::error::AppError::InvalidStandardIdForDeletion,
            ));
        }

        let standard_folder = target_dir.join(standard_id);
        if !standard_folder.exists() {
            return Ok(());
        }

        // 2. Enforce wallet unlock to verify active vouchers
        let wallet = self.get_wallet()?;
        let identity = self.get_identity()?;

        // 3. Determine standard UUIDs to check
        let mut uuid_to_check = vec![standard_id.to_string()];
        let toml_file = standard_folder.join("standard.toml");
        if toml_file.exists()
            && let Ok(toml_str) = fs::read_to_string(&toml_file)
                && let Ok((def, _)) = VoucherStandardDefinition::from_toml(&toml_str) {
                    let parsed_uuid = def.immutable.identity.uuid;
                    if parsed_uuid != standard_id {
                        uuid_to_check.push(parsed_uuid);
                    }
                }

        // 4. Query wallet vouchers matching resolved UUIDs
        let matching_vouchers = wallet.list_vouchers(
            Some(identity),
            Some(&uuid_to_check),
            None,
            None,
        );

        if !matching_vouchers.is_empty() {
            return Err(Error::App(crate::error::AppError::StandardInUse {
                count: matching_vouchers.len(),
            }));
        }

        // 5. Delete directory
        fs::remove_dir_all(&standard_folder)
            .map_err(Error::from)?;

        Ok(())
    }

    // --- Generic Data Encryption (from data_encryption) ---

    /// Saves an arbitrary byte slice encrypted on the disk.
    #[allow(unused_variables)]
    pub fn save_encrypted_data(
        &mut self,
        name: &str,
        data: &[u8],
        password: Option<&str>,
    ) -> Result<(), Error> {
        let auth_method = match password {
            Some(pwd) => AuthMethod::Password(pwd),
            None => AuthMethod::SessionKey(self.get_session_key()?),
        };
        match &mut self.state {
            AppState::Unlocked {
                storage, identity, ..
            } => {
                let _lock_guard =
                    WalletLockGuard::new(storage)?;
                storage
                    .save_arbitrary_data(&auth_method, name, data)?;
                if name != "__storage_session_anchor" {
                    self.update_seal_after_state_change(password)?;
                }
                Ok(())
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Loads and decrypts a previously saved, arbitrary data block.
    #[allow(unused_variables)]
    pub fn load_encrypted_data(
        &mut self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let auth_method = match password {
            Some(pwd) => AuthMethod::Password(pwd),
            None => AuthMethod::SessionKey(self.get_session_key()?),
        };
        match &self.state {
            AppState::Unlocked {
                storage, identity, ..
            } => storage
                .load_arbitrary_data(&auth_method, name)
                .map_err(Error::from),
            AppState::Locked => Err(Error::WalletLocked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MnemonicLanguage;
    use std::path::PathBuf;

    fn setup_test_app(dir_name: &str) -> (AppService, PathBuf) {
        let temp_dir = std::env::temp_dir().join(dir_name);
        if temp_dir.exists() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        let _ = fs::create_dir_all(&temp_dir);

        let mut app = AppService::new(&temp_dir).unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        app.create_profile(
            "Test Profile",
            mnemonic,
            None,
            Some("test"),
            "password123",
            MnemonicLanguage::English,
            "device-id".to_string(),
        )
        .unwrap();

        (app, temp_dir)
    }

    const SAMPLE_TOML: &str = r#"
[immutable.identity]
uuid = "test-standard-uuid-12345"
name = "Test Currency Standard"
abbreviation = "TCS"

[immutable.blueprint]
unit = "TestUnit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init", "transfer"]

[immutable.issuance]
validity_duration_range = ["P1M", "P1Y"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["issuer"]

[mutable.metadata]
issuer_name = "Test Issuer"

[signature]
issuer_id = "0:riw@did:key:z6Mki8QqVMb66hjtTwcceVXbZuSHTk61jqiprRvEhuotZmSA"
signature = "5aomSjj76rEb4VVjhAd6p6qvmU79wkkTpj84AnY3D9p8xRDNfxBqKL4EbEHTKfPevggafJeJuzhgYV4rvhLgMs5m"
"#;

    #[test]
    fn test_export_inspect_import_standard_cleartext() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_cleartext");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Cleartext)
            .expect("Export cleartext standard failed");
        assert!(!container_bytes.is_empty());

        let def = app
            .inspect_voucher_standard_container(&container_bytes, None)
            .expect("Inspect standard failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");
        assert_eq!(def.immutable.identity.name, "Test Currency Standard");

        let uuid = app
            .import_voucher_standard(&container_bytes, None, &target_standards_dir)
            .expect("Import standard failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());
        let content = fs::read_to_string(&saved_file).unwrap();
        assert!(content.contains("test-standard-uuid-12345"));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_export_inspect_import_standard_password() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_password");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let password = "SecretStandardPassword123";
        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Password(password.to_string()))
            .expect("Export password standard failed");

        let wrong_inspect = app.inspect_voucher_standard_container(&container_bytes, Some("WrongPassword"));
        assert!(wrong_inspect.is_err());

        let def = app
            .inspect_voucher_standard_container(&container_bytes, Some(password))
            .expect("Inspect with correct password failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        let uuid = app
            .import_voucher_standard(&container_bytes, Some(password), &target_standards_dir)
            .expect("Import with correct password failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_invalid_payload_type() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, _) = setup_test_app("test_standard_invalid_payload");
        let identity = app.get_identity().unwrap();

        let container = SecureContainer::seal(
            identity,
            &ContainerConfig::Cleartext,
            SAMPLE_TOML.as_bytes(),
            PayloadType::VoucherForSigning,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&container).unwrap();

        let result = app.inspect_voucher_standard_container(&bytes, None);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Invalid payload type"),
            "Expected error containing 'Invalid payload type', got: {}",
            err_str
        );

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_import_raw_toml() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_raw_toml");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let raw_toml_bytes = SAMPLE_TOML.as_bytes();

        let def = app
            .inspect_voucher_standard_container(raw_toml_bytes, None)
            .expect("Inspect raw TOML failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        let uuid = app
            .import_voucher_standard(raw_toml_bytes, None, &target_standards_dir)
            .expect("Import raw TOML failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_success_when_no_vouchers() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_delete_standard_success");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");
        let standard_folder = target_standards_dir.join(&uuid);
        assert!(standard_folder.exists());

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(result.is_ok());
        assert!(!standard_folder.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_vouchers_exist() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_vouchers_exist");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");
        assert!(target_standards_dir.join(&uuid).exists());

        let (def, def_hash) = VoucherStandardDefinition::from_toml(SAMPLE_TOML).unwrap();
        let identity = app.get_identity().unwrap();
        let creator_profile = crate::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            ..Default::default()
        };
        let voucher_data = crate::test_utils::voucher_setup::create_minuto_voucher_data(creator_profile);
        let voucher = crate::test_utils::voucher_setup::create_voucher_for_manipulation(
            voucher_data,
            &def,
            &def_hash,
            &identity.signing_key,
        );

        {
            let (wallet, _) = app.get_unlocked_mut_for_test();
            wallet.add_voucher_instance("test_inst_1".to_string(), voucher, crate::wallet::instance::VoucherStatus::Active);
        }

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("still in use"),
            "Expected error containing 'still in use', got: {}",
            err_str
        );

        assert!(target_standards_dir.join(&uuid).exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_folder_name_differs_from_uuid() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_folder_mismatch");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let custom_folder = target_standards_dir.join("minuto_v1");
        fs::create_dir_all(&custom_folder).unwrap();
        fs::write(custom_folder.join("standard.toml"), SAMPLE_TOML).unwrap();

        let (def, def_hash) = VoucherStandardDefinition::from_toml(SAMPLE_TOML).unwrap();
        let identity = app.get_identity().unwrap();
        let creator_profile = crate::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            ..Default::default()
        };
        let voucher_data = crate::test_utils::voucher_setup::create_minuto_voucher_data(creator_profile);
        let voucher = crate::test_utils::voucher_setup::create_voucher_for_manipulation(
            voucher_data,
            &def,
            &def_hash,
            &identity.signing_key,
        );

        {
            let (wallet, _) = app.get_unlocked_mut_for_test();
            wallet.add_voucher_instance("test_inst_2".to_string(), voucher, crate::wallet::instance::VoucherStatus::Active);
        }

        let result = app.delete_voucher_standard("minuto_v1", &target_standards_dir);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("still in use"),
            "Expected error containing 'still in use', got: {}",
            err_str
        );

        assert!(custom_folder.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_wallet_locked() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_locked");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");

        app.logout();

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(matches!(result, Err(Error::WalletLocked)));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_rejects_path_traversal() {
        let (app, temp_dir) = setup_test_app("test_delete_standard_traversal");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let result = app.delete_voucher_standard("../other_dir", &target_standards_dir);
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Invalid standard ID"),
            "Expected error containing 'Invalid standard ID', got: {}",
            err_str
        );
    }

    #[test]
    fn test_delete_non_existent_standard() {
        let (app, temp_dir) = setup_test_app("test_delete_non_existent");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let result = app.delete_voucher_standard("non_existent_id", &target_standards_dir);
        assert!(result.is_ok());
    }
}
