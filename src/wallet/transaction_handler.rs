//! # src/wallet/transaction_handler.rs
//!
//! Contains the core logic for creating and processing
//! transactions and bundles.

use super::conflict_handler::resolve_conflict_offline;
use super::types::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::{TransactionBundleHeader, TransactionDirection, UserIdentity};
use crate::models::secure_container::{PayloadType, SecureContainer};
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::get_hash;
use crate::services::utils::to_canonical_json;
use crate::services::{bundle_processor, conflict_manager};
use crate::wallet::Wallet;
use crate::wallet::instance::VoucherStatus;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rust_decimal::Decimal;
use sha2::Sha256;
use std::collections::HashMap;
use std::str::FromStr;

impl Wallet {
    /// Creates a `TransactionBundle`, packages it, and updates the wallet state.
    /// This is now a private helper method.
    pub fn create_and_encrypt_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        vouchers: Vec<Voucher>,
        recipient_id: &str,
        notes: Option<String>,
        forwarded_fingerprints: Vec<crate::models::conflict::TransactionFingerprint>,
        fingerprint_depths: HashMap<String, i8>,
        sender_profile_name: Option<String>,
    ) -> Result<(Vec<u8>, TransactionBundleHeader), VoucherCoreError> {
        for v in &vouchers {
            let local_id = Self::calculate_local_instance_id(v, &identity.user_id)?;
            if let Some(instance) = self.voucher_store.vouchers.get(&local_id) {
                if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    return Err(VoucherCoreError::VoucherInQuarantine);
                }
            }
        }

        let (container_bytes, bundle) = bundle_processor::create_and_encrypt_bundle(
            identity,
            vouchers.clone(),
            recipient_id,
            notes,
            forwarded_fingerprints,
            fingerprint_depths,
            sender_profile_name,
        )?;

        let header = bundle.to_header(TransactionDirection::Sent);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        Ok((container_bytes, header))
    }

    /// Processes a serialized `SecureContainer` containing a `TransactionBundle`.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&dyn VoucherArchive>,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let bundle = bundle_processor::open_and_verify_bundle(identity, container_bytes)?;

        // --- LAYER 0: BUNDLE-RECIPIENT CHECK ---
        // Prevents a wallet from accepting a bundle explicitly addressed to another
        // instance (e.g. mobile vs. PC) of the same user (SAI).
        if bundle.recipient_id != identity.user_id && bundle.recipient_id != crate::models::voucher::ANONYMOUS_ID {
             return Err(VoucherCoreError::BundleRecipientMismatch {
                expected: identity.user_id.clone(),
                found: bundle.recipient_id.clone(),
            });
        }

        // --- LAYER 1: BUNDLE-ID REPLAY PROTECTION ---
        // Immediately rejects an identical bundle that has already been processed.
        if self
            .bundle_meta_store
            .history
            .contains_key(&bundle.bundle_id)
        {
            return Err(VoucherCoreError::BundleAlreadyProcessed {
                bundle_id: bundle.bundle_id.clone(),
            });
        }

        // --- LAYER 2: FINGERPRINT REPLAY PROTECTION ---
        // Rejects a NEW bundle containing vouchers whose latest transaction
        // (fingerprint) is already known. Prevents modified replay attacks.
        self.check_bundle_fingerprints_against_history(&bundle.vouchers)?;
        // --- END REPLAY PROTECTION ---

        // --- ADDITIONAL SECURITY CHECK ---
        // Ensure that every voucher in the bundle was actually sent to THIS
        // wallet (identity.user_id) as a valid recipient
        // and no timestamps lie far in the future.
        let own_user_id = &identity.user_id;
        // 1. Check timestamps (Hard Reject)
        // We take the transaction time of the vouchers as an absolute reference (the maximum thereof).
        let mut max_tx_dt: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut max_tx_time = String::new();
        let mut max_tx_id = String::new();

        for voucher in &bundle.vouchers {
            if let Some(last_tx) = voucher.transactions.last() {
                let tx_dt = chrono::DateTime::parse_from_rfc3339(&last_tx.t_time)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| {
                        VoucherCoreError::Generic(format!("Failed to parse transaction time: {}", e))
                    })?;

                match max_tx_dt {
                    None => {
                        max_tx_dt = Some(tx_dt);
                        max_tx_time = last_tx.t_time.clone();
                        max_tx_id = last_tx.t_id.clone();
                    }
                    Some(m_dt) if tx_dt > m_dt => {
                        max_tx_dt = Some(tx_dt);
                        max_tx_time = last_tx.t_time.clone();
                        max_tx_id = last_tx.t_id.clone();
                    }
                    _ => {}
                }
            }
        }

        if !max_tx_time.is_empty() {
            crate::services::utils::verify_not_far_in_future(
                &max_tx_time,
                "Transaction",
                &max_tx_id,
            )?;
        }

        // Also check signatures individually (Hard Reject)
        for voucher in &bundle.vouchers {
            for sig in &voucher.signatures {
                crate::services::utils::verify_not_far_in_future(
                    &sig.signature_time,
                    "Signature",
                    &sig.signature_id,
                )?;
            }
        }

        for voucher in &bundle.vouchers {
            // 2. Check recipient
            if let Some(last_tx) = voucher.transactions.last() {
                // Security fuse: Does the recipient match our wallet?
                if last_tx.recipient_id != *own_user_id
                    && last_tx.recipient_id != crate::models::voucher::ANONYMOUS_ID
                {
                    return Err(VoucherCoreError::BundleRecipientMismatch {
                        expected: own_user_id.clone(),
                        found: last_tx.recipient_id.clone(),
                    });
                }

                // If anonymous, enforce successful decryption of the Privacy Guard
                if last_tx.recipient_id == crate::models::voucher::ANONYMOUS_ID {
                    let owns_voucher = if let Some(guard_base64) = &last_tx.privacy_guard {
                        crate::services::crypto_utils::decrypt_recipient_payload(
                            guard_base64,
                            &identity.signing_key,
                            &identity.user_id,
                        )
                        .is_ok()
                    } else {
                        false
                    };

                    if !owns_voucher {
                        return Err(VoucherCoreError::BundleRecipientMismatch {
                            expected: own_user_id.clone(),
                            found: "anonymous_but_payload_decryption_failed".to_string(),
                        });
                    }
                }
            } else {
                // A voucher without transactions is inherently invalid.
                return Err(VoucherCoreError::Validation(
                    ValidationError::InvalidTransaction(
                        "Received voucher has no transactions.".to_string(),
                    ),
                ));
            }
        }
        // --- End of security check ---

        // Copy data before 'bundle' is moved
        let forwarded_fingerprints = bundle.forwarded_fingerprints.clone();
        let fingerprint_depths = bundle.fingerprint_depths.clone();
        let received_vouchers = bundle.vouchers.clone();

        // Initialize the new result structures
        let mut transfer_summary = super::types::TransferSummary::default();
        let mut involved_vouchers = Vec::new();
        let mut involved_vouchers_details = Vec::new();

        for voucher in bundle.vouchers.clone() {
            // --- VALIDATION AGAINST STANDARD ---
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard = standard_definitions.get(standard_uuid).ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Standard definition not found for UUID: {}",
                    standard_uuid
                ))
            })?;

            crate::services::voucher_validation::validate_voucher_against_standard(
                &voucher, standard,
            )?;

            // CORRECTION: The `retain` logic was removed. It was the cause of
            // failed double-spend detection, as it incorrectly removed one of the two
            // conflicting voucher instances.
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;

            // --- NEW: Privacy Key Handling (Stateless) ---
            // We still check for the payload, but store NOTHING in state anymore.
            // The check only serves for logging/warning.
            /*
            let mut current_seed = None;
            */
            if let Some(last_tx) = voucher.transactions.last() {
                if let Some(guard_base64) = &last_tx.privacy_guard {
                    // STRICT INGESTION: If a privacy_guard is present, it MUST
                    // be successfully decrypted and parsed.
                    let decrypted_payload_bytes =
                        crate::services::crypto_utils::decrypt_recipient_payload(
                            guard_base64,
                            &identity.signing_key,
                            &identity.user_id,
                        ).map_err(|e| {
                            VoucherCoreError::Validation(
                                ValidationError::PrivacyGuardDecryptionFailed(
                                    format!("Decryption failed: {}", e)
                                )
                            )
                        })?;

                    let payload = serde_json::from_slice::<
                        crate::models::voucher::RecipientPayload,
                    >(&decrypted_payload_bytes).map_err(|e| {
                        VoucherCoreError::Validation(
                            ValidationError::PrivacyGuardDecryptionFailed(
                                format!("JSON parsing failed: {}", e)
                            )
                        )
                    })?;

                    // SECURITY CHECK: Does the declared sender in the guard
                    // match the actual signer of the bundle?
                    if payload.sender_permanent_did != bundle.sender_id {
                        return Err(ValidationError::MismatchedPrivacySenderId {
                            declared: payload.sender_permanent_did,
                            actual: bundle.sender_id.clone(),
                        }.into());
                    }

                    // Verify DLEQ Proof and deterministic trap derivation if proof fields are present
                    let sender_pubkey = crate::services::crypto_utils::get_pubkey_from_user_id(&payload.sender_permanent_did)?;
                    let id_point = crate::services::crypto_utils::ed25519_pk_to_curve_point(&sender_pubkey)?;

                    if let Some(trap) = &last_tx.trap_data {
                        let u_bytes = bs58::decode(&trap.u)
                            .into_vec()
                            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
                        let u = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
                            u_bytes.try_into().map_err(|_| {
                                VoucherCoreError::Crypto("Invalid Scalar U length".to_string())
                            })?,
                        );

                        let blinded_id_bytes = bs58::decode(&trap.blinded_id)
                            .into_vec()
                            .map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
                        let v_point = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&blinded_id_bytes)
                            .map_err(|_| VoucherCoreError::Crypto("Invalid Blinded-ID (V)".to_string()))?
                            .decompress()
                            .ok_or_else(|| VoucherCoreError::Crypto("Failed to decompress Blinded-ID V".to_string()))?;

                        let prev_hash_bytes = bs58::decode(&last_tx.prev_hash)
                            .into_vec()
                            .unwrap_or_else(|_| last_tx.prev_hash.as_bytes().to_vec());
                        let p_point = crate::services::crypto_utils::hash_to_curve(&prev_hash_bytes);

                        if let (Some(k_str), Some(c_str), Some(s_str)) = (
                            &payload.trap_k_point,
                            &payload.dleq_c,
                            &payload.dleq_s,
                        ) {
                            // 1. Decode K, c, s
                            let k_bytes = bs58::decode(k_str)
                                .into_vec()
                                .map_err(|e| VoucherCoreError::Crypto(format!("Invalid K point Base58: {}", e)))?;
                            let c_bytes = bs58::decode(c_str)
                                .into_vec()
                                .map_err(|e| VoucherCoreError::Crypto(format!("Invalid c Base58: {}", e)))?;
                            let s_bytes = bs58::decode(s_str)
                                .into_vec()
                                .map_err(|e| VoucherCoreError::Crypto(format!("Invalid s Base58: {}", e)))?;

                            let k_point = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&k_bytes)
                                .map_err(|_| VoucherCoreError::Crypto("Invalid K point bytes".to_string()))?
                                .decompress()
                                .ok_or_else(|| VoucherCoreError::Crypto("Failed to decompress K point".to_string()))?;

                            let c_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
                                c_bytes.try_into().map_err(|_| {
                                    VoucherCoreError::Crypto("Invalid c scalar length".to_string())
                                })?,
                            );
                            let s_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
                                s_bytes.try_into().map_err(|_| {
                                    VoucherCoreError::Crypto("Invalid s scalar length".to_string())
                                })?,
                            );

                            // 2. Perform DLEQ verification
                            crate::services::crypto_utils::verify_dleq_proof(
                                &id_point,
                                &p_point,
                                &k_point,
                                &c_scalar,
                                &s_scalar,
                            )?;

                            // 3. Verify trap identity derivation
                            let m_expected = crate::services::trap_manager::hash_to_scalar(&k_point.compress().to_bytes());
                            let v_expected = (u * m_expected) * curve25519_dalek::constants::ED25519_BASEPOINT_POINT + id_point;

                            if v_expected != v_point {
                                return Err(VoucherCoreError::InvalidTrapDerivation(
                                    "Trap V point mismatch: slope m was not derived deterministically from the permanent key.".to_string()
                                ));
                            }
                        }
                    }

                    // Check target_prefix (Simple validation)
                    if !identity.user_id.starts_with(&payload.target_prefix) {
                        // Optional: Warning or Error if not addressed to us?
                        // For now we allow it if we could decrypt it, but we log it.
                    }
                }
            }

            self.add_voucher_instance(local_id.clone(), voucher.clone(), VoucherStatus::Active);

            // STATELESS: We do NOT store the seed anymore.
            // if let Some(seed) = current_seed { ... }

            // --- NEW: TransferSummary logic ---
            // 1. Collect the local ID
            involved_vouchers.push(local_id.clone());

            // 2. Find the relevant standard
            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard = standard_definitions.get(standard_uuid).ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Standard definition not found for UUID: {}",
                    standard_uuid
                ))
            })?;

            // 3. Find the last transaction to determine the received amount
            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Generic("Received voucher has no transactions.".to_string())
            })?;

            // 4. Determine the display unit (BFF pattern)
            let display_currency = super::format_bff_name(
                voucher.nominal_value.abbreviation.as_deref().unwrap_or(&voucher.nominal_value.unit),
                voucher.non_redeemable_test_voucher
            );

            // 5. Accumulate value based on fungibility rule (balances_are_summable)
            // Fungible currency units are summed; non-fungible items are counted as distinct certificates.
            if standard.immutable.features.balances_are_summable {
                let current_sum = transfer_summary
                    .summable_amounts
                    .entry(display_currency)
                    .or_insert_with(|| "0.0".to_string());

                // Use decimal_utils to safely add strings
                // CORRECTION: Use rust_decimal::Decimal for addition
                let val1 = Decimal::from_str(current_sum).map_err(|e| {
                    VoucherCoreError::Generic(format!("Invalid decimal amount in summary: {}", e))
                })?;
                let val2 = Decimal::from_str(&last_tx.amount).map_err(|e| {
                    VoucherCoreError::Generic(format!(
                        "Invalid decimal amount in transaction: {}",
                        e
                    ))
                })?;

                *current_sum = (val1 + val2).to_string();
            } else {
                let count = transfer_summary.countable_items.entry(display_currency).or_insert(0);
                *count += 1;
            }

            // --- NEW: Create InvolvedVoucherInfo ---
            involved_vouchers_details.push(super::types::InvolvedVoucherInfo {
                local_instance_id: local_id.clone(),
                voucher_id: voucher.voucher_id.clone(),
                standard_name: standard.immutable.identity.name.clone(),
                unit: voucher.nominal_value.unit.clone(),
                amount: last_tx.amount.clone(),
                allow_partial_transfers: standard.immutable.features.allow_partial_transfers,
                is_test_voucher: voucher.non_redeemable_test_voucher,
                display_currency: super::format_bff_name(
                    voucher.nominal_value.abbreviation.as_deref().unwrap_or(&voucher.nominal_value.unit),
                    voucher.non_redeemable_test_voucher
                ),
                display_standard_name: super::format_bff_name(
                    &voucher.voucher_standard.name,
                    voucher.non_redeemable_test_voucher
                ),
                counterparty_id: Self::extract_sender_from_transaction(last_tx, identity),
                counterparty_name: bundle.sender_profile_name.clone(),
            });
            // --- End TransferSummary logic ---
        }

        // Generate TransferReceived events for each successfully received voucher.
        for info in &involved_vouchers_details {
            let bff_data = crate::models::wallet_event::EventBffData {
                display_currency: info.display_currency.clone(),
                amount: info.amount.clone(),
                is_test_voucher: info.is_test_voucher,
                counterparty_id: info.counterparty_id.clone().or_else(|| Some(bundle.sender_id.clone())),
                counterparty_name: info.counterparty_name.clone(),
            };
            self.emit_event(
                crate::models::wallet_event::WalletEventType::TransferReceived,
                &info.local_instance_id,
                &info.voucher_id,
                bff_data,
            );
        }

        // The 'bundle' variable is still available here because `bundle.vouchers.clone()`
        // was used. Create the header (which contains `sender_profile_name`,
        // as `to_header` was adjusted in patch 1).
        let header = bundle.to_header(TransactionDirection::Received);
        self.bundle_meta_store
            .history
            .insert(header.bundle_id.clone(), header.clone());

        // NEW: Process all received fingerprints (active and implicit)
        self.process_received_fingerprints(
            &header,
            &received_vouchers,
            &forwarded_fingerprints,
            &fingerprint_depths,
        )?;

        // Fingerprint stores are rebuilt from the VoucherStore on every change.
        // IMPORTANT: Use the Wallet method that preserves history.
        self.scan_and_rebuild_fingerprints()?;

        // If a signature is received, the voucher status must be updated
        if let Ok(deserialized_container) =
            serde_json::from_slice::<SecureContainer>(container_bytes)
        {
            if matches!(deserialized_container.c, PayloadType::DetachedSignature) {
                self.process_and_attach_signature(identity, container_bytes, None)?;
                return Ok(ProcessBundleResult::default());
            }
        }

        let check_result = conflict_manager::check_for_double_spend(
            &self.own_fingerprints,
            &self.known_fingerprints,
        );


        // Collect all conflicts (both verifiable and warnings) for processing.
        let mut all_conflicts = check_result.verifiable_conflicts.clone();
        for (hash, fps) in &check_result.unverifiable_warnings {
            all_conflicts.insert(hash.clone(), fps.clone());
        }

        // Collect quarantine events during conflict resolution.
        let mut quarantined_events: Vec<(String, String, crate::models::wallet_event::EventBffData)> = Vec::new();

        for (_conflict_hash, fingerprints) in &all_conflicts {
            // find_transaction_in_stores first searches the local voucher_store.
            // Since both conflicting transactions exist locally, the archive
            // is not required as a fallback. A NoOpArchive serves as a placeholder.
            let noop = crate::archive::file_archive::NoOpArchive;
            let archive_ref: &dyn VoucherArchive = match archive {
                Some(a) => a,
                None => &noop,
            };
            
            let verified_proof =
                self.verify_and_create_proof(identity, fingerprints, archive_ref)?;

                if let Some(proof) = verified_proof {
                    // Logic for processing an L2 verdict
                    if let Some(verdict) = &proof.layer2_verdict {
                        for tx in &proof.conflicting_transactions {
                            let instance_id_opt = self
                                .find_local_voucher_by_tx_id(&tx.t_id)
                                .map(|i| i.local_instance_id.clone());
                            if let Some(instance_id) = instance_id_opt {
                                if let Some(instance_mut) =
                                    self.voucher_store.vouchers.get_mut(&instance_id)
                                {
                                    let prev_status = instance_mut.status.clone();
                                    instance_mut.status = if tx.t_id == verdict.valid_transaction_id
                                    {
                                        VoucherStatus::Active
                                    } else {
                                        VoucherStatus::Quarantined {
                                            reason: "L2 verdict".to_string(),
                                        }
                                    };
                                    // If this voucher freshly entered quarantine, collect event.
                                    if !matches!(prev_status, VoucherStatus::Quarantined { .. })
                                        && matches!(instance_mut.status, VoucherStatus::Quarantined { .. })
                                    {
                                        let bff_data = crate::models::wallet_event::EventBffData {
                                            display_currency: crate::wallet::format_bff_name(
                                                instance_mut.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&instance_mut.voucher.nominal_value.unit),
                                                instance_mut.voucher.non_redeemable_test_voucher,
                                            ),
                                            amount: instance_mut.voucher.nominal_value.amount.clone(),
                                            is_test_voucher: instance_mut.voucher.non_redeemable_test_voucher,
                                            counterparty_id: None,
                                            counterparty_name: None,
                                        };
                                        quarantined_events.push((
                                            instance_mut.local_instance_id.clone(),
                                            instance_mut.voucher.voucher_id.clone(),
                                            bff_data,
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        // Offline conflict resolution if no L2 verdict is present
                        let pre_statuses: std::collections::HashMap<String, VoucherStatus> = self.voucher_store.vouchers.iter()
                            .filter(|(_, inst)| fingerprints.iter().any(|fp| fp.ds_tag == inst.voucher.voucher_id || inst.voucher.transactions.iter().any(|tx| tx.t_id == fp.t_id)))
                            .map(|(lid, inst)| (lid.clone(), inst.status.clone()))
                            .collect();
                        resolve_conflict_offline(&mut self.voucher_store, fingerprints);
                        for (lid, prev_status) in pre_statuses {
                            if let Some(inst) = self.voucher_store.vouchers.get(&lid) {
                                if !matches!(prev_status, VoucherStatus::Quarantined { .. })
                                    && matches!(inst.status, VoucherStatus::Quarantined { .. })
                                {
                                    let bff_data = crate::models::wallet_event::EventBffData {
                                        display_currency: crate::wallet::format_bff_name(
                                            inst.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&inst.voucher.nominal_value.unit),
                                            inst.voucher.non_redeemable_test_voucher,
                                        ),
                                        amount: inst.voucher.nominal_value.amount.clone(),
                                        is_test_voucher: inst.voucher.non_redeemable_test_voucher,
                                        counterparty_id: None,
                                        counterparty_name: None,
                                    };
                                    quarantined_events.push((
                                        inst.local_instance_id.clone(),
                                        inst.voucher.voucher_id.clone(),
                                        bff_data,
                                    ));
                                }
                            }
                        }
                    }

                    // --- Role determination (victim vs. witness) ---
                    // REFINEMENT: We are only a victim if we have NO active voucher for this
                    // conflict tag, but at least one exists (which is now in quarantine).
                    let mut has_active = false;
                    let mut has_quarantined = false;
                    
                    for tx in &proof.conflicting_transactions {
                        if let Some(instance) = self.find_local_voucher_by_tx_id(&tx.t_id) {
                            if matches!(instance.status, VoucherStatus::Active) {
                                has_active = true;
                            } else if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                                has_quarantined = true;
                            }
                        }
                    }
                    
                    let conflict_role = if has_quarantined && !has_active {
                        crate::models::conflict::ConflictRole::Victim
                    } else {
                        crate::models::conflict::ConflictRole::Witness
                    };

                    // IMPORTANT: Persistently store the created proof in the wrapper.
                    let entry = crate::models::conflict::ProofStoreEntry {
                        proof: proof.clone(),
                        local_override: false,
                        local_note: None,
                        conflict_role,
                    };
                    
                    self.proof_store
                        .proofs
                        .insert(proof.proof_id.clone(), entry);
                } else {
                // Fallback: If no strict cryptographic proof can be created
                // (e.g. because data is missing), local cleanup MUST still be performed.
                let pre_statuses: std::collections::HashMap<String, VoucherStatus> = self.voucher_store.vouchers.iter()
                    .filter(|(_, inst)| fingerprints.iter().any(|fp| fp.ds_tag == inst.voucher.voucher_id || inst.voucher.transactions.iter().any(|tx| tx.t_id == fp.t_id)))
                    .map(|(lid, inst)| (lid.clone(), inst.status.clone()))
                    .collect();
                resolve_conflict_offline(&mut self.voucher_store, fingerprints);
                for (lid, prev_status) in pre_statuses {
                    if let Some(inst) = self.voucher_store.vouchers.get(&lid) {
                        if !matches!(prev_status, VoucherStatus::Quarantined { .. })
                            && matches!(inst.status, VoucherStatus::Quarantined { .. })
                        {
                            let bff_data = crate::models::wallet_event::EventBffData {
                                display_currency: crate::wallet::format_bff_name(
                                    inst.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&inst.voucher.nominal_value.unit),
                                    inst.voucher.non_redeemable_test_voucher,
                                ),
                                amount: inst.voucher.nominal_value.amount.clone(),
                                is_test_voucher: inst.voucher.non_redeemable_test_voucher,
                                counterparty_id: None,
                                counterparty_name: None,
                            };
                            quarantined_events.push((
                                inst.local_instance_id.clone(),
                                inst.voucher.voucher_id.clone(),
                                bff_data,
                            ));
                        }
                    }
                }
            }
        }

        // Record emitted VoucherQuarantined events into pending_events.
        for (local_id, voucher_id, bff_data) in quarantined_events {
            self.emit_event(
                crate::models::wallet_event::WalletEventType::VoucherQuarantined,
                &local_id,
                &voucher_id,
                bff_data,
            );
        }

        Ok(ProcessBundleResult {
            header,
            check_result,
            transfer_summary,
            involved_vouchers,
            involved_vouchers_details,
        })
    }

    /// Performs the state transition for ONE voucher in the wallet.
    ///
    /// This function is the core logic of the transfer. It does NOT perform bundling.
    pub(super) fn _execute_single_transfer(
        &mut self,
        identity: &UserIdentity,
        standard_definition: &VoucherStandardDefinition,
        local_instance_id: &str,
        recipient_id: &str,
        amount_to_send: &str,
        archive: Option<&dyn VoucherArchive>,
        use_privacy_mode: Option<bool>,
        counterparty_id: Option<String>,
        counterparty_name: Option<String>,
    ) -> Result<Voucher, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;
        if !matches!(instance.status, VoucherStatus::Active) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }

        // --- NEW: Lock for vouchers in the (near) future ---
        if let Some(last_tx) = instance.voucher.transactions.last() {
            let now_str = crate::services::utils::get_current_timestamp();
            if last_tx.t_time > now_str {
                let now = chrono::DateTime::parse_from_rfc3339(&now_str).unwrap();
                let until = chrono::DateTime::parse_from_rfc3339(&last_tx.t_time).unwrap();
                let diff = until.signed_duration_since(now);
                let wait_duration = format!(
                    "{}h {}m {}s",
                    diff.num_hours(),
                    diff.num_minutes() % 60,
                    diff.num_seconds() % 60
                );
                return Err(VoucherCoreError::VoucherLockedUntil {
                    until: last_tx.t_time.clone(),
                    now: now_str,
                    wait_duration,
                });
            }
        }

        let voucher_to_spend = instance.voucher.clone();

        let last_tx = voucher_to_spend.transactions.last().ok_or_else(|| {
            VoucherCoreError::Generic("Cannot spend voucher with no transactions.".to_string())
        })?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);

        // Privacy Key Logic: RE-DERIVATION (Stateless)
        // We derive the seed directly from Voucher + Identity instead of storing it.
        // IMPORTANT: We must do this BEFORE the double-spend check to know the ephemeral key.
        let sender_ephemeral_key = self.rederive_secret_seed(&voucher_to_spend, identity)?;
        let ephem_pub_str =
            bs58::encode(sender_ephemeral_key.verifying_key().to_bytes()).into_string();

        // CHECK AGAINST ALL KNOWN FINGERPRINTS:
        // We use the 'ds_tag', which is calculated identically in voucher_manager
        // (now independent of prefix).
        // This makes proactive checking 100% consistent with the mathematical trap.
        let ds_tag = {
            let prev_hash_bytes = bs58::decode(&prev_hash)
                .into_vec()
                .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
            let ephem_pub_bytes = bs58::decode(&ephem_pub_str).into_vec().map_err(|_| {
                VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string())
            })?;
            crate::services::crypto_utils::get_hash_from_slices(&[
                &prev_hash_bytes,
                &ephem_pub_bytes,
            ])
        };

        if self
            .own_fingerprints
            .active_fingerprints
            .contains_key(&ds_tag)
            || self.own_fingerprints.history.contains_key(&ds_tag)
        {
            // SELF-HEALING: Return the ID of the voucher that caused the inconsistency.
            // The calling AppService can then move this voucher to quarantine.
            return Err(VoucherCoreError::DoubleSpendAttemptBlocked {
                local_instance_id: local_instance_id.to_string(),
            });
        }

        let (new_voucher_state, _secrets) = crate::services::voucher_manager::create_transaction(
            &voucher_to_spend,
            standard_definition,
            &identity.user_id,
            &identity.signing_key,
            &sender_ephemeral_key,
            recipient_id,
            amount_to_send,
            use_privacy_mode,
        )?;

        // CORRECT LOGIC FOR STATE MANAGEMENT:
        // 1. Remove the old instance that was just spent.
        self.voucher_store.vouchers.remove(local_instance_id);

        // 2. Determine the status of the new voucher state for the sender.
        if let Some(last_tx) = new_voucher_state.transactions.last() {
            // We are the sender if our ID matches OR if the transaction is anonymous
            // (since we just created it ourselves via _execute_single_transfer).
            let is_sender = last_tx.sender_id.as_ref() == Some(&identity.user_id) 
                || (last_tx.sender_id.is_none() && last_tx.recipient_id == crate::models::voucher::ANONYMOUS_ID);

            let (new_status, owner_id) = if is_sender && last_tx.sender_remaining_amount.is_some() {
                // It is a split; the sender retains an active remaining amount.
                (VoucherStatus::Active, &identity.user_id)
            } else {
                // It is a full transfer; the sender's copy is archived.
                (VoucherStatus::Archived, &identity.user_id)
            };

            // 3. A new state ALWAYS receives a new local ID.
            let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, owner_id)?;

            // 4. Add the new instance with the NEW ID and the correct status.
            self.add_voucher_instance(new_local_id.clone(), new_voucher_state.clone(), new_status);

            // 5. STATELESS: We do NOT store the change seed anymore. It is now deterministic.
            /*
            if let Some(change_seed) = secrets.change_seed {
                 if let Some(instance) = self.voucher_store.vouchers.get_mut(&new_local_id) {
                     instance.current_secret_seed = Some(change_seed);
                 }
            }
            */
        }

        if let Some(archive_backend) = archive {
            archive_backend.archive_voucher(
                &new_voucher_state,
                &identity.user_id,
                standard_definition,
            )?;
        }

        // Fingerprint creation and storage in the *historical* store
        let created_tx = new_voucher_state.transactions.last().unwrap();
        let fingerprint =
            conflict_manager::create_fingerprint_for_transaction(created_tx, &new_voucher_state)?;

        let history_entry = self
            .own_fingerprints
            .history
            .entry(fingerprint.ds_tag.clone())
            .or_default();
        if !history_entry.contains(&fingerprint) {
            history_entry.push(fingerprint.clone());
        }

        // Generate TransferSent event for UI history.
        let bff_data = crate::models::wallet_event::EventBffData {
            display_currency: crate::wallet::format_bff_name(
                new_voucher_state.nominal_value.abbreviation.as_deref().unwrap_or(&new_voucher_state.nominal_value.unit),
                new_voucher_state.non_redeemable_test_voucher,
            ),
            amount: amount_to_send.to_string(),
            is_test_voucher: new_voucher_state.non_redeemable_test_voucher,
            counterparty_id,
            counterparty_name,
        };
        if let Some(_last_tx) = new_voucher_state.transactions.last() {
            let new_local_id = Self::calculate_local_instance_id(&new_voucher_state, &identity.user_id)?;
            self.emit_event(
                crate::models::wallet_event::WalletEventType::TransferSent,
                &new_local_id,
                &new_voucher_state.voucher_id,
                bff_data,
            );
        }

        // IMPORTANT: NO BUNDLE, ONLY THE MUTATED VOUCHER IS RETURNED
        Ok(new_voucher_state)
    }

    /// Performs a 1-to-N transaction (multi-transfer) and creates a single bundle.
    pub fn execute_multi_transfer_and_bundle(
        &mut self,
        identity: &UserIdentity,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
        request: MultiTransferRequest,
        archive: Option<&dyn VoucherArchive>,
    ) -> Result<CreateBundleResult, VoucherCoreError> {
        // TRANSACTIONAL APPROACH:
        // 1. Create a temporary copy of the wallet. All changes are
        //    initially performed on this copy.
        let mut temp_wallet = self.clone();
        let mut vouchers_for_bundle: Vec<Voucher> = Vec::new();
        // NEW: Initialize list for source details
        let mut involved_sources_details: Vec<super::types::InvolvedVoucherInfo> = Vec::new();

        // 2. **Orchestration:** Execute `_execute_single_transfer` for each source on the copy.
        for source in request.sources {
            let instance = temp_wallet
                .voucher_store
                .vouchers
                .get(&source.local_instance_id)
                .ok_or_else(|| {
                    VoucherCoreError::VoucherNotFound(source.local_instance_id.clone())
                })?;

            let standard_uuid = instance.voucher.voucher_standard.uuid.clone();
            let standard_definition =
                standard_definitions.get(&standard_uuid).ok_or_else(|| {
                    VoucherCoreError::Generic(format!(
                        "Standard with UUID '{}' not found in provided definitions.",
                        standard_uuid
                    ))
                })?;

            // NEW: Create InvolvedVoucherInfo for the source (BEFORE the transfer)
            involved_sources_details.push(super::types::InvolvedVoucherInfo {
                local_instance_id: source.local_instance_id.clone(),
                voucher_id: instance.voucher.voucher_id.clone(),
                standard_name: standard_definition.immutable.identity.name.clone(),
                unit: instance.voucher.nominal_value.unit.clone(),
                amount: source.amount_to_send.clone(),
                allow_partial_transfers: standard_definition.immutable.features.allow_partial_transfers,
                is_test_voucher: instance.voucher.non_redeemable_test_voucher,
                display_currency: super::format_bff_name(
                    instance.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&instance.voucher.nominal_value.unit),
                    instance.voucher.non_redeemable_test_voucher
                ),
                display_standard_name: super::format_bff_name(
                    &instance.voucher.voucher_standard.name,
                    instance.voucher.non_redeemable_test_voucher
                ),
                counterparty_id: Some(request.recipient_id.clone()),
                counterparty_name: None,
            });

            // Execute the core operation on the temporary wallet instance.
            let new_voucher = temp_wallet._execute_single_transfer(
                identity,
                standard_definition,
                &source.local_instance_id,
                &request.recipient_id,
                &source.amount_to_send,
                archive,
                request.use_privacy_mode,
                Some(request.recipient_id.clone()),
                request.sender_profile_name.clone(),
            )?;

            vouchers_for_bundle.push(new_voucher);
        }

        // 3. **Bundling:** Create a single SecureContainer bundle.
        let (fingerprints_to_send, depths_to_send) = temp_wallet
            .select_fingerprints_for_bundle(&request.recipient_id, &vouchers_for_bundle)?;

        let (container_bytes, header) = temp_wallet.create_and_encrypt_transaction_bundle(
            identity,
            vouchers_for_bundle,
            &request.recipient_id,
            request.notes,
            // NEW: Additional arguments
            fingerprints_to_send,
            depths_to_send,
            request.sender_profile_name,
        )?;

        // 4. **Commit:** If all operations were successful, replace the
        //    original wallet state with that of the temporary instance.
        *self = temp_wallet;

        Ok(CreateBundleResult {
            bundle_bytes: container_bytes,
            bundle_id: header.bundle_id,
            involved_sources_details,
        })
    }

    /// Helper function for stateless seed recovery.
    /// Attempts to restore the required ephemeral key for the LAST transaction.
    /// - Case A (Split): Deterministic via HKDF from Identity.
    /// - Case B (Received): Decrypting the Privacy Guard via Identity.
    pub fn rederive_secret_seed(
        &self,
        voucher: &Voucher,
        identity: &UserIdentity,
    ) -> Result<SigningKey, VoucherCoreError> {
        let last_tx = voucher.transactions.last().ok_or_else(|| {
            VoucherCoreError::Generic(
                "Cannot rederive seed: Voucher has no transactions.".to_string(),
            )
        })?;

        // 1. Check if we are the SENDER (change) via crypto matching
        // We attempt to derive the change key deterministically and compare the hash.
        let sender_id_prefix = crate::services::crypto_utils::get_prefix_from_user_id(&identity.user_id);
        let ikm = identity.signing_key.to_bytes();
        let prev_hash = &last_tx.prev_hash;

        let (prk, _) = Hkdf::<Sha256>::extract(Some(prev_hash.as_bytes()), &ikm);
        if let Ok(hkdf) = Hkdf::<Sha256>::from_prk(&prk) {
            // Info string for change seed: "[prefix]change_seed" or "change_seed" for root accounts
            let info = if let Some(p) = sender_id_prefix {
                format!("{}change_seed", p)
            } else {
                "change_seed".to_string()
            };
            let mut change_seed = [0u8; 32];
            if hkdf.expand(info.as_bytes(), &mut change_seed).is_ok() {
                let candidate_key = SigningKey::from_bytes(&change_seed);
                let candidate_hash = crate::services::crypto_utils::get_hash(candidate_key.verifying_key().to_bytes());
                
                if Some(&candidate_hash) == last_tx.change_ephemeral_pub_hash.as_ref() {
                    return Ok(candidate_key);
                }
            }
        }

        // 2. Check if we are the RECIPIENT (received) via Privacy Guard
        if let Some(guard_base64) = &last_tx.privacy_guard {
            if let Ok(decrypted_payload_bytes) = crate::services::crypto_utils::decrypt_recipient_payload(
                guard_base64,
                &identity.signing_key,
                &identity.user_id,
            ) {
                if let Ok(payload) = serde_json::from_slice::<crate::models::voucher::RecipientPayload>(&decrypted_payload_bytes) {
                    if let Ok(seed_bytes) = bs58::decode(&payload.next_key_seed).into_vec() {
                        if let Ok(seed_arr) = seed_bytes.try_into() {
                            let candidate_key = SigningKey::from_bytes(&seed_arr);
                            let candidate_hash = crate::services::crypto_utils::get_hash(candidate_key.verifying_key().to_bytes());
                            
                            if Some(&candidate_hash) == last_tx.receiver_ephemeral_pub_hash.as_ref() {
                                return Ok(candidate_key);
                            }
                        }
                    }
                }
            }
        }

        // 3. Fallback: Public Mode / Init
        if last_tx.sender_id.as_ref() == Some(&identity.user_id) && last_tx.sender_remaining_amount.is_some() {
             let (prk, _) = Hkdf::<Sha256>::extract(Some(prev_hash.as_bytes()), &ikm);
             let hkdf = Hkdf::<Sha256>::from_prk(&prk).map_err(|_| VoucherCoreError::Crypto("Invalid PRK".to_string()))?;
             // Info string for change seed: "[prefix]change_seed" or "change_seed" for root accounts
             let info = if let Some(p) = sender_id_prefix {
                 format!("{}change_seed", p)
             } else {
                 "change_seed".to_string()
             };
             let mut change_seed = [0u8; 32];
             hkdf.expand(info.as_bytes(), &mut change_seed).map_err(|e| VoucherCoreError::Crypto(e.to_string()))?;
             return Ok(SigningKey::from_bytes(&change_seed));
        }

        // Case C: Init (creator)
        if last_tx.t_type == "init" && last_tx.sender_id.as_ref() == Some(&identity.user_id) {
            let nonce_bytes = bs58::decode(&voucher.voucher_nonce)
                .into_vec()
                .map_err(|_| VoucherCoreError::Generic("Invalid nonce".to_string()))?;

            let sender_id_prefix = crate::services::crypto_utils::get_prefix_from_user_id(&identity.user_id);

            let (holder_secret, _) = crate::services::crypto_utils::derive_ephemeral_key_pair(
                &identity.signing_key,
                &nonce_bytes,
                "holder",
                sender_id_prefix,
            )?;
            return Ok(holder_secret);
        }

        Err(VoucherCoreError::Generic(
            "Could not rederive secret seed: No valid ownership strategy found (neither Change nor Receiver hash matches).".to_string(),
        ))
    }

    /// Extracts the sender identity (DID) from a transaction.
    /// Considers both public mode (sender_id in plaintext)
    /// and stealth mode (decryption of the Privacy Guard).
    fn extract_sender_from_transaction(
        tx: &crate::models::voucher::Transaction,
        identity: &UserIdentity,
    ) -> Option<String> {
        // Case 1: Public Mode - sender ID is directly present in plaintext
        if let Some(sender_id) = &tx.sender_id {
            if sender_id != crate::models::voucher::ANONYMOUS_ID {
                return Some(sender_id.clone());
            }
        }

        // Case 2: Stealth Mode - DID is encrypted in the Privacy Guard
        if let Some(guard_base64) = &tx.privacy_guard {
            if let Ok(decrypted_payload_bytes) = crate::services::crypto_utils::decrypt_recipient_payload(
                guard_base64,
                &identity.signing_key,
                &identity.user_id,
            ) {
                if let Ok(payload) = serde_json::from_slice::<crate::models::voucher::RecipientPayload>(
                    &decrypted_payload_bytes,
                ) {
                    return Some(payload.sender_permanent_did);
                }
            }
        }

        None
    }
}

