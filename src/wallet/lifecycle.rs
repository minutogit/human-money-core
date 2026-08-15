//! # src/wallet/lifecycle.rs
//!
//! Contains all methods dealing with the wallet "lifecycle"
//! (creation, loading, saving) and the creation of new vouchers.

use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::models::{
    conflict::{CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore},
    profile::{BundleMetadataStore, UserIdentity, UserProfile, VoucherStore},
};
use crate::services::crypto_utils::create_user_id;
use crate::services::voucher_manager::NewVoucherData;
use crate::services::{voucher_manager, voucher_validation};
use crate::services::seal_manager::SealManager;
use crate::storage::{AuthMethod, Storage, StorageError};
use crate::wallet::Wallet;
use crate::wallet::instance::{ValidationFailureReason, VoucherStatus};

impl Wallet {
    /// Helper method to create a new event and add it to the RAM buffer.
    pub fn emit_event(
        &mut self,
        event_type: crate::models::wallet_event::WalletEventType,
        local_instance_id: &str,
        voucher_id: &str,
        bff_data: crate::models::wallet_event::EventBffData,
    ) {
        let event = crate::models::wallet_event::WalletEvent::new(
            local_instance_id.to_string(),
            voucher_id.to_string(),
            event_type,
            bff_data,
        );
        self.pending_events.push(event);
    }

    /// Creates a brand-new, empty wallet from a mnemonic phrase.
    ///
    /// # ⚠️ CRITICAL SECURITY REQUIREMENT: `local_instance_id`
    /// The `local_instance_id` prevents users from accidentally cloning their wallet 
    /// folder to another device, which would cause state forks and double-spends.
    /// 
    /// **AS AN APP DEVELOPER, YOU MUST NOT STORE THIS ID IN THE WALLET DIRECTORY!**
    /// If you store the ID next to the wallet files, a user copying the folder will 
    /// also copy the ID, completely bypassing the cloning protection.
    /// 
    /// **Correct Usage:** Store this ID in the OS Keychain (e.g., via the `keyring` crate),
    /// or derive it deterministically from hardware (e.g., `/etc/machine-id`).
    pub fn new_from_mnemonic(
        mnemonic_phrase: &str,
        passphrase: Option<&str>,
        user_prefix: Option<&str>,
        language: crate::services::mnemonic::MnemonicLanguage,
        local_instance_id: String,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (public_key, signing_key) =
            crate::services::crypto_utils::derive_ed25519_keypair(mnemonic_phrase, passphrase, language)?;

        let user_id = create_user_id(&public_key, user_prefix)
            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;

        let identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };

        let profile = UserProfile {
            user_id,
            first_name: None,
            last_name: None,
            organization: None,
            community: None,
            address: None,
            gender: None,
            email: None,
            phone: None,
            coordinates: None,
            url: None,
            service_offer: None,
            needs: None,
            picture_url: None,
            l2_server_pubkey: None,
        };

        let voucher_store = VoucherStore::default();
        let bundle_meta_store = BundleMetadataStore::default();
        let known_fingerprints = KnownFingerprints::default();
        let own_fingerprints = OwnFingerprints::default();
        let proof_store = ProofStore::default();
        let fingerprint_metadata = CanonicalMetadataStore::default();

        let wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
            local_instance_id,
            pending_events: Vec::new(),
            loaded_generation: 0,
        };

        Ok((wallet, identity))
    }

    /// Loads an existing wallet from a `Storage` backend.
    /// Returns the wallet and the decrypted UserIdentity.
    pub fn load<S: Storage>(
        storage: &S,
        auth: &AuthMethod,
        local_instance_id: String,
    ) -> Result<(Self, UserIdentity), VoucherCoreError> {
        let (profile, voucher_store, identity) = storage.load_wallet(auth)?;

        if let AuthMethod::Mnemonic(..) = auth {
            println!(
                "[Debug Wallet::load] Recovery successful! Decrypted identity with Mnemonic. User ID: {}",
                identity.user_id
            );
        }

        let bundle_meta_store = storage.load_bundle_metadata(&identity.user_id, auth)?;
        let known_fingerprints = storage.load_known_fingerprints(&identity.user_id, auth)?;
        let own_fingerprints = storage.load_own_fingerprints(&identity.user_id, auth)?;
        let proof_store = storage.load_proofs(&identity.user_id, auth)?;
        let fingerprint_metadata = storage.load_fingerprint_metadata(&identity.user_id, auth)?;

        // Security check to ensure that the decrypted identity
        // matches the profile data.
        if profile.user_id != identity.user_id {
            return Err(StorageError::AuthenticationFailed.into());
        }

        let loaded_generation = storage.read_generation()?;

        let mut wallet = Wallet {
            profile,
            voucher_store,
            bundle_meta_store,
            known_fingerprints,
            own_fingerprints,
            proof_store,
            fingerprint_metadata,
            local_instance_id,
            pending_events: Vec::new(),
            loaded_generation,
        };

        // --- EXPIRATION SWEEP ---
        // After deserialization, but before returning: Check all vouchers
        // for expiration and generate VoucherExpired events.
        let now = chrono::Utc::now();
        let expired_local_ids: Vec<(String, String, crate::models::wallet_event::EventBffData)> = {
            let mut expired = Vec::new();
            for instance in wallet.voucher_store.vouchers.values() {
                if matches!(instance.status, VoucherStatus::Active | VoucherStatus::Incomplete { .. }) {
                    if let Ok(valid_until) = chrono::DateTime::parse_from_rfc3339(&instance.voucher.valid_until) {
                        if now > valid_until.with_timezone(&chrono::Utc) {
                            let bff_data = crate::models::wallet_event::EventBffData {
                                display_currency: crate::wallet::format_bff_name(
                                    instance.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&instance.voucher.nominal_value.unit),
                                    instance.voucher.non_redeemable_test_voucher,
                                ),
                                amount: instance.voucher.nominal_value.amount.clone(),
                                is_test_voucher: instance.voucher.non_redeemable_test_voucher,
                                counterparty_id: None,
                                counterparty_name: None,
                            };
                            expired.push((
                                instance.local_instance_id.clone(),
                                instance.voucher.voucher_id.clone(),
                                bff_data,
                            ));
                        }
                    }
                }
            }
            expired
        };

        for (local_id, voucher_id, bff_data) in expired_local_ids {
            if let Some(instance) = wallet.voucher_store.vouchers.get_mut(&local_id) {
                instance.status = VoucherStatus::Expired;
            }
            wallet.emit_event(
                crate::models::wallet_event::WalletEventType::VoucherExpired,
                &local_id,
                &voucher_id,
                bff_data,
            );
        }
        // --- END EXPIRATION SWEEP ---

        wallet.rebuild_derived_stores()?;
        Ok((wallet, identity))
    }

    /// Saves the current wallet state in a `Storage` backend.
    ///
    /// **Important:** Order is critical for data safety.
    /// First UserProfile, VoucherStore, BundleMetadataStore, and all
    /// fingerprint stores are saved. Finally `pending_events`
    /// are appended to the event log. Only if ALL operations succeed
    /// is `self.pending_events.clear()` called.
    pub fn save<S: Storage>(
        &mut self,
        storage: &mut S,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<(), StorageError> {
        let current_generation = storage.read_generation()?;
        if current_generation != self.loaded_generation {
            return Err(StorageError::StateConflict(
                "State was modified externally!".to_string(),
            ));
        }
        let new_generation = current_generation + 1;
        storage.write_generation(current_generation, new_generation)?;
        self.loaded_generation = new_generation;

        storage.save_wallet(&self.profile, &self.voucher_store, identity, auth)?;
        storage.save_bundle_metadata(&identity.user_id, auth, &self.bundle_meta_store)?;
        storage.save_known_fingerprints(&identity.user_id, auth, &self.known_fingerprints)?;
        storage.save_own_fingerprints(&identity.user_id, auth, &self.own_fingerprints)?;
        storage.save_proofs(&identity.user_id, auth, &self.proof_store)?;
        storage.save_fingerprint_metadata(&identity.user_id, auth, &self.fingerprint_metadata)?;

        // Finally: Persist events. Only clear on complete success.
        if !self.pending_events.is_empty() {
            storage.append_events(&identity.user_id, auth, &self.pending_events)?;
            self.pending_events.clear();
        }

        Ok(())
    }

    /// Resets the password for a wallet in a `Storage` backend.
    pub fn reset_password<S: Storage>(
        storage: &mut S,
        identity: &UserIdentity,
        new_password: &str,
    ) -> Result<(), StorageError> {
        storage.reset_password(identity, new_password)
    }

    /// Creates a brand-new voucher and adds it directly to the wallet.
    ///
    /// This method orchestrates the creation of a new voucher based on
    /// a standard, signs it with the creator's identity, and stores
    /// it immediately in the `VoucherStore` with `Active` status.
    ///
    /// # Arguments
    /// * `identity` - The identity of the creator, containing the signing key.
    /// * `verified_standard` - The rules and templates of the voucher standard.
    /// * `standard_hash` - The hash of the standard.
    /// * `data` - Specific data for the new voucher (e.g. amount).
    ///
    /// # Returns
    /// A `Result` containing the fully created `Voucher` on success.
    pub fn create_new_voucher(
        &mut self,
        identity: &UserIdentity,
        // The signature is expanded to preserve the verified data
        verified_standard: &VoucherStandardDefinition,
        standard_hash: &str,
        data: NewVoucherData,
    ) -> Result<crate::models::voucher::Voucher, VoucherCoreError> {
        let new_voucher = voucher_manager::create_voucher(
            data,
            verified_standard,
            standard_hash,
            &identity.signing_key,
        )?;

        // CORRECT STATE MANAGEMENT LOGIC:
        // 1. Calculate the correct local ID based on the `init` transaction.
        let local_id = Self::calculate_local_instance_id(&new_voucher, &identity.user_id)?;

        // 2. Determine the initial status through immediate validation.
        let initial_status = match voucher_validation::validate_voucher_against_standard(
            &new_voucher,
            verified_standard,
        ) {
            Ok(_) => VoucherStatus::Active,
            
            // Case 1: Missing signatures (Incomplete)
            Err(VoucherCoreError::Validation(ref validation_err @ ValidationError::FieldValueCountOutOfBounds { ref path, ref field, .. }))
            if path == "signatures" && (field == "role" || field == "details.gender") =>
            {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::RequiredSignatureMissing { 
                        role_description: validation_err.to_string() 
                    }],
                }
            },
            Err(VoucherCoreError::Validation(ref validation_err @ ValidationError::MissingRequiredSignature { .. })) =>
            {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::RequiredSignatureMissing { 
                        role_description: validation_err.to_string() 
                    }],
                }
            },
            
            // Case 2: Business rules violated (Incomplete)
            Err(VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))) => {
                VoucherStatus::Incomplete {
                    reasons: vec![ValidationFailureReason::BusinessRule {
                        message: msg,
                    }],
                }
            }
            // Any other validation error during creation is a fatal error.
            Err(e) => return Err(e),
        };

        // 3. Add the instance with the correct ID and status.
        self.add_voucher_instance(local_id.clone(), new_voucher.clone(), initial_status);

        // 4. Generate event for the UI history.
        let bff_data = crate::models::wallet_event::EventBffData {
            display_currency: crate::wallet::format_bff_name(
                new_voucher.nominal_value.abbreviation.as_deref().unwrap_or(&new_voucher.nominal_value.unit),
                new_voucher.non_redeemable_test_voucher,
            ),
            amount: new_voucher.nominal_value.amount.clone(),
            is_test_voucher: new_voucher.non_redeemable_test_voucher,
            counterparty_id: None,
            counterparty_name: None,
        };
        self.emit_event(
            crate::models::wallet_event::WalletEventType::VoucherCreated,
            &local_id,
            &new_voucher.voucher_id,
            bff_data,
        );

        // 5. IMPORTANT: Rebuild the derived stores (fingerprints, metadata).
        self.rebuild_derived_stores()?;

        Ok(new_voucher)
    }

    /// Forces binding of the wallet to the current device (handover).
    /// Increments the epoch and sets the new instance_id in the seal.
    pub fn force_device_handover<S: Storage>(
        &mut self,
        storage: &mut S,
        identity: &UserIdentity,
        auth: &AuthMethod,
    ) -> Result<crate::models::seal::WalletSeal, VoucherCoreError> {
        // 1. Load old seal
        let record = storage.load_seal(&identity.user_id, auth)
            .map_err(VoucherCoreError::Storage)?
            .ok_or_else(|| VoucherCoreError::RequiresSealRecovery)?;

        // 2. Create new seal with increased epoch and new instance_id
        // We use SealManager::recover_seal_epoch for this, since it does exactly that (Epoch + 1)
        let state_hash = {
            let canonical = crate::services::utils::to_canonical_json(&self.own_fingerprints)?;
            crate::services::crypto_utils::get_hash(canonical.as_bytes())
        };

        let new_seal = SealManager::recover_seal_epoch(
            Some(&record.seal),
            &identity.user_id,
            identity,
            &state_hash,
            &self.local_instance_id,
        )?;

        // 3. Save
        let new_record = crate::models::seal::LocalSealRecord {
            seal: new_seal.clone(),
            sync_status: crate::models::seal::SyncStatus::PendingUpload,
            is_locked_due_to_fork: false,
        };

        storage.save_seal(&identity.user_id, auth, &new_record)
            .map_err(VoucherCoreError::Storage)?;

        Ok(new_seal)
    }
}

