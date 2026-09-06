//! # src/wallet/transactions.rs
//!
//! Contains the core logic for creating and processing
//! transactions and bundles (bundle creation, bundle reception,
//! single/multi transfers) as well as the signature workflow
//! (requesting, creating, processing signatures).
//! This module consolidates the former `transaction_handler.rs` and
//! `signature_handler.rs` into a single coherent domain.
//!
//! **Decoupled persistence (Phase 2):** All methods in this module are
//! pure in-memory state machines. They mutate only `Wallet` fields
//! (`voucher_store`, `*_fingerprints`, `pending_events`, …) and take
//! **no** `&mut FileStorage`. Durable 2-phase commit (staging →
//! `store_binding_hash` → `write_generation`) is owned exclusively by
//! `FileStorage::commit_wallet_atomic` / `save_wallet_transaction`.

use super::types::{CreateBundleResult, MultiTransferRequest, ProcessBundleResult};
use crate::archive::FileVoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::{TransactionBundleHeader, TransactionDirection, UserIdentity};
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::signature::DetachedSignature;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto::get_hash;
use crate::services::utils::to_canonical_json;
use crate::services::voucher_validation::{StandardRegistry, ValidationPipeline};
use crate::services::{bundle_processor, conflict_manager};
use crate::wallet::Wallet;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::conflicts::resolve_conflict_offline;
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::str::FromStr;


const MAX_COUNTERPARTY_NAME_CHARS: usize = 64;

/// HMSEC-SA06-10: True for Unicode format/invisible characters that are
/// commonly abused for spoofing or rendering manipulation (zero-width
/// characters, joiners, bidi embedding/overrides, BOM-class marks).
fn is_invisible_format_char(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F       // ZWSP, ZWNJ, ZWJ, LRM, RLM
        | 0x202A..=0x202E     // bidi embedding & pop-directional formats
        | 0x2060..=0x206F     // word joiner & invisible operators
        | 0xFEFF              // zero-width no-break space / BOM
    )
}

/// HMSEC-SA06-10: Sanitizes an attacker-supplied display name before it is
/// stored in the local event feed (`EventBffData.counterparty_name`) or the
/// persistent bundle metadata history. Control characters and invisible
/// format characters are stripped and the length is bounded. This preserves
/// the display purpose of the field while removing injection and log-bloat
/// vectors. It deliberately does NOT touch `counterparty_id`, whose
/// retention is protected intentional design for offline forensics
/// (HMSEC-SA06-05).
fn sanitize_display_name(raw: Option<String>) -> Option<String> {
    let cleaned: String = raw?
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format_char(*c))
        .take(MAX_COUNTERPARTY_NAME_CHARS)
        .collect();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

// ---------------------------------------------------------------------------
// Helper functions for de-nesting and deduplication (refactoring plan)
// ---------------------------------------------------------------------------

/// Derives the deterministic change key via HKDF from the identity's IKM and the
/// transaction's `prev_hash`.
///
/// Delegates to the canonical implementation in `crate::services::crypto`.
fn derive_deterministic_change_key(
    identity: &UserIdentity,
    prev_hash: &str,
) -> Result<SigningKey, VoucherCoreError> {
    crate::services::crypto::derive_deterministic_change_key(
        &identity.signing_key,
        &identity.user_id,
        prev_hash,
    )
}

impl Wallet {
    /// Creates a `TransactionBundle`, packages it, and updates the wallet state.
    /// This is now a private helper method.
    #[allow(clippy::too_many_arguments)]
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
            if let Some(instance) = self.voucher_store.vouchers.get(&local_id)
                && matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    return Err(VoucherCoreError::VoucherInQuarantine);
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
    ///
    /// SECURITY (HMSEC-SA04-04): Receiving a bundle must be an all-or-nothing
    /// operation. The ingestion loop below commits voucher instances
    /// incrementally; if a LATER member of the bundle fails validation
    /// (unknown standard UUID, standard violation, undecryptable privacy
    /// guard), the already-committed members would otherwise persist as
    /// phantom vouchers while the Layer-1 replay gate (`bundle_meta_store`)
    /// and the event log never learn about them. Mirroring the send path's
    /// temporary-wallet transactional pattern, we snapshot the wallet before
    /// any mutation and roll back completely when processing returns `Err`.
    pub fn process_encrypted_transaction_bundle(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&FileVoucherArchive>,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        // Transactional approach (see HMSEC-SA04-04): operate on a snapshot so
        // every error path below restores the exact pre-processing state.
        let rollback_snapshot = self.clone();
        match self.process_encrypted_transaction_bundle_inner(
            identity,
            container_bytes,
            archive,
            standard_definitions,
        ) {
            Ok(result) => Ok(result),
            Err(err) => {
                *self = rollback_snapshot;
                Err(err)
            }
        }
    }

    /// Inner implementation of [`Wallet::process_encrypted_transaction_bundle`]
    /// running on `&mut self`; wrapped for atomic rollback by the public method.
    /// Uses [`StandardRegistry`] + [`ValidationPipeline`] for the linear 4-step
    /// audited validation, reusing the single `open_and_verify_bundle` result.
    fn process_encrypted_transaction_bundle_inner(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&FileVoucherArchive>,
        standard_definitions: &HashMap<String, VoucherStandardDefinition>,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        // Build registry once from the already-verified map (no re-parsing, no re-verification).
        let registry = StandardRegistry::from_verified_ref(standard_definitions);
        self.process_bundle_with_registry_inner(
            identity,
            container_bytes,
            archive,
            &registry,
            None,
            0,
            false,
        )
    }

    /// Registry-aware inner that performs a single `open_and_verify_bundle`
    /// and delegates to [`ValidationPipeline::validate_incoming_bundle`] for the
    /// 4-step linearized validation (reusing the decrypted bundle).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn process_bundle_with_registry_inner(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        archive: Option<&FileVoucherArchive>,
        registry: &StandardRegistry,
        epoch_start_time: Option<&str>,
        epoch: u32,
        force_accept: bool,
    ) -> Result<ProcessBundleResult, VoucherCoreError> {
        let mut bundle = bundle_processor::open_and_verify_bundle(identity, container_bytes)?;

        // HMSEC-SA06-10: The sender_profile_name is attacker-controlled
        // display metadata. Sanitize it ONCE at the ingestion point (after
        // all cryptographic verification) so every downstream consumer —
        // event feed, bundle metadata history, transfer summary details —
        // only ever sees a bounded, control-character-free name. This is a
        // local-storage/display transformation and does not interfere with
        // the already-completed bundle signature verification.
        bundle.sender_profile_name = sanitize_display_name(bundle.sender_profile_name);

        // HMSEC-AUDIT-W4-PRIV-701: The notes field is attacker-controlled free-text
        // metadata. Sanitize and bound it ONCE at network ingestion after cryptographic
        // verification, before bundle metadata history is persisted.
        bundle.notes = sanitize_display_name(bundle.notes);

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

        // --- LINEAR VALIDATION PIPELINE (Phase 1) ---
        // Centralized 4-step audited validation reusing the single decrypted bundle
        // and the cached registry (no repeated TOML parsing, no repeated standard
        // signature verification per uuid, no second bundle decryption).
        ValidationPipeline::validate_incoming_bundle(
            &bundle,
            identity,
            registry,
            epoch_start_time,
            epoch,
            force_accept,
        )?;

        // --- LAYER 2: FINGERPRINT REPLAY PROTECTION ---
        // Rejects a NEW bundle containing vouchers whose latest transaction
        // (fingerprint) is already known. Prevents modified replay attacks.
        self.check_bundle_fingerprints_against_history(&bundle.vouchers)?;
        // --- END REPLAY PROTECTION ---

        // Take ownership of gossip data without cloning (streamlining).
        let forwarded_fingerprints = std::mem::take(&mut bundle.forwarded_fingerprints);
        let fingerprint_depths = std::mem::take(&mut bundle.fingerprint_depths);
        let received_vouchers = bundle.vouchers.clone();
        // Capture sender metadata before consuming `bundle.vouchers` via `into_iter()`.
        let bundle_sender_id = bundle.sender_id.clone();
        let bundle_sender_profile_name = bundle.sender_profile_name.clone();

        // Initialize the new result structures
        let mut transfer_summary = super::types::TransferSummary::default();
        let mut involved_vouchers = Vec::new();
        let mut involved_vouchers_details = Vec::new();

        // Header must be created before consuming `bundle.vouchers` (into_iter moves the vec).
        let header = bundle.to_header(TransactionDirection::Received);

        // --- INGESTION PASS (Phase 2) ---
        // Consumes the bundle's vouchers exactly once via `into_iter()`, adding them
        // to the store and building the transfer summary. Uses cached standards.
        for voucher in bundle.vouchers.into_iter() {
            // CORRECTION: The `retain` logic was removed. It was the cause of
            // failed double-spend detection, as it incorrectly removed one of the two
            // conflicting voucher instances.
            let local_id = Self::calculate_local_instance_id(&voucher, &identity.user_id)?;

            self.add_voucher_instance(local_id.clone(), voucher.clone(), VoucherStatus::Active);

            // --- TransferSummary logic ---
            involved_vouchers.push(local_id.clone());

            let standard_uuid = &voucher.voucher_standard.uuid;
            let standard = registry.get(standard_uuid).expect(
                "Standard must have been validated and cached in registry; missing entry is a logic error",
            );

            let last_tx = voucher.transactions.last().ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::MissingTransactions)
            })?;

            let display_currency = super::format_bff_name(
                voucher.nominal_value.abbreviation.as_deref().unwrap_or(&voucher.nominal_value.unit),
                voucher.non_redeemable_test_voucher
            );

            // Fungible currency units are summed; non-fungible items are counted as distinct certificates.
            if standard.immutable.features.balances_are_summable {
                let current_sum = transfer_summary
                    .summable_amounts
                    .entry(display_currency)
                    .or_insert_with(|| "0.0".to_string());

                let val1 = Decimal::from_str(current_sum).map_err(|e| {
                    crate::Error::Wallet(crate::error::WalletError::InvalidAmount { reason: format!("Invalid decimal amount in summary: {}", e) })
                })?;
                let val2 = Decimal::from_str(&last_tx.amount).map_err(|e| {
                    crate::Error::Wallet(crate::error::WalletError::InvalidAmount { reason: format!("Invalid decimal amount in transaction: {}", e) })
                })?;

                // SECURITY (HMC-SEC-04-01): checked_add to avoid panic on overflow.
                let new_sum = val1.checked_add(val2).ok_or_else(|| {
                    crate::Error::Wallet(crate::error::WalletError::AmountOverflow { details: "Amount overflow while aggregating received voucher amounts.".to_string() })
                })?;
                *current_sum = new_sum.to_string();
            } else {
                let count = transfer_summary.countable_items.entry(display_currency).or_insert(0);
                *count += 1;
            }

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
                counterparty_id: Self::extract_sender_from_transaction(last_tx, identity)
                    .or_else(|| Some(bundle_sender_id.clone())),
                counterparty_name: bundle_sender_profile_name.clone(),
            });
        }

        // Generate TransferReceived events for each successfully received voucher.
        for info in &involved_vouchers_details {
            let bff_data = crate::models::wallet_event::EventBffData {
                display_currency: info.display_currency.clone(),
                amount: info.amount.clone(),
                is_test_voucher: info.is_test_voucher,
                counterparty_id: info.counterparty_id.clone().or_else(|| Some(bundle_sender_id.clone())),
                counterparty_name: info.counterparty_name.clone(),
            };
            self.emit_event(
                crate::models::wallet_event::WalletEventType::TransferReceived,
                &info.local_instance_id,
                &info.voucher_id,
                bff_data,
            );
        }

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
            && matches!(deserialized_container.c, PayloadType::DetachedSignature) {
                self.process_and_attach_signature(identity, container_bytes, None)?;
                return Ok(ProcessBundleResult::default());
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

        // Collect quarantine events during conflict resolution via unified helper.
        let mut quarantined_events: Vec<(String, String, crate::models::wallet_event::EventBffData)> = Vec::new();

        for fingerprints in all_conflicts.values() {
            let verified_proof =
                self.verify_and_create_proof(identity, fingerprints, archive)?;

            self.handle_conflicts_and_quarantine(
                fingerprints,
                verified_proof,
                &mut quarantined_events,
            );
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

    /// Unified conflict and quarantine handler.
    ///
    /// Handles the duplicated logic for L2 verdict application, offline
    /// conflict resolution (`resolve_conflict_offline`), role determination
    /// (Victim vs. Witness) and quarantine-event collection.
    fn handle_conflicts_and_quarantine(
        &mut self,
        fingerprints: &[crate::models::conflict::TransactionFingerprint],
        proof_opt: Option<crate::models::conflict::ProofOfDoubleSpend>,
        quarantined_events: &mut Vec<(String, String, crate::models::wallet_event::EventBffData)>,
    ) {
        if let Some(proof) = proof_opt {
            // --- L2 verdict vs. offline resolution ---
            if let Some(verdict) = &proof.layer2_verdict {
                // Logic for processing an L2 verdict
                for tx in &proof.conflicting_transactions {
                    let instance_id_opt = self
                        .find_local_voucher_by_tx_id(&tx.t_id)
                        .map(|i| i.local_instance_id.clone());
                    if let Some(instance_id) = instance_id_opt
                        && let Some(instance_mut) =
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
            } else {
                // Offline conflict resolution if no L2 verdict is present
                Self::apply_offline_resolution_and_collect(
                    &mut self.voucher_store,
                    fingerprints,
                    quarantined_events,
                );
            }

            // --- Role determination (victim vs. witness) ---
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
            Self::apply_offline_resolution_and_collect(
                &mut self.voucher_store,
                fingerprints,
                quarantined_events,
            );
        }
    }

    /// Offline resolution helper that captures pre-statuses, runs the
    /// `Earliest Wins` heuristic, and collects newly quarantined events.
    fn apply_offline_resolution_and_collect(
        voucher_store: &mut crate::models::profile::VoucherStore,
        fingerprints: &[crate::models::conflict::TransactionFingerprint],
        quarantined_events: &mut Vec<(String, String, crate::models::wallet_event::EventBffData)>,
    ) {
        let pre_statuses: HashMap<String, VoucherStatus> = voucher_store
            .vouchers
            .iter()
            .filter(|(_, inst)| {
                fingerprints.iter().any(|fp| {
                    fp.ds_tag == inst.voucher.voucher_id
                        || inst.voucher.transactions.iter().any(|tx| tx.t_id == fp.t_id)
                })
            })
            .map(|(lid, inst)| (lid.clone(), inst.status.clone()))
            .collect();

        resolve_conflict_offline(voucher_store, fingerprints);

        for (lid, prev_status) in pre_statuses {
            if let Some(inst) = voucher_store.vouchers.get(&lid)
                && !matches!(prev_status, VoucherStatus::Quarantined { .. })
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

    /// Performs the state transition for ONE voucher in the wallet.
    ///
    /// This function is the core logic of the transfer. It does NOT perform
    /// bundling and does NOT write to the forensic archive: archive side
    /// effects are performed by the orchestrating caller strictly after its
    /// atomic commit point (HMC-SEC-04-03).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn _execute_single_transfer(
        &mut self,
        identity: &UserIdentity,
        standard_definition: &VoucherStandardDefinition,
        local_instance_id: &str,
        recipient_id: &str,
        amount_to_send: &str,
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
            crate::Error::Wallet(crate::error::WalletError::MissingTransactions)
        })?;
        let prev_hash = get_hash(to_canonical_json(last_tx)?);

        // Privacy Key Logic: RE-DERIVATION (Stateless)
        // We derive the seed directly from Voucher + Identity instead of storing it.
        // IMPORTANT: We must do this BEFORE the double-spend check to know the ephemeral key.
        let sender_ephemeral_key = self.rederive_secret_seed(&voucher_to_spend, identity)?;
        let ephem_pub_str =
            bs58::encode(sender_ephemeral_key.verifying_key().to_bytes()).into_string();

        // CHECK AGAINST ALL KNOWN FINGERPRINTS:
        // We use the 'ds_tag', which is calculated identically in voucher_math
        // (now independent of prefix).
        // This makes proactive checking 100% consistent with the mathematical trap.
        let ds_tag = crate::services::crypto::get_ds_tag(&prev_hash, &ephem_pub_str)?;

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

        let (new_voucher_state, _secrets) = voucher_to_spend.create_transaction(
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

        // NOTE (HMC-SEC-04-03): No archive writes here. This method may run on
        // a temporary wallet clone inside a simulated transaction; archiving is
        // a side effect that cannot be rolled back and therefore happens in
        // `execute_multi_transfer_and_bundle` only AFTER the commit succeeded.

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
        // ARCHITECTURAL DESIGN REQUIREMENT (Offline Forensics & Hop-by-Hop Traceability):
        // In Stealth/Privacy Mode, the direct sender's local, encrypted wallet event log
        // MUST retain the intended recipient DID (`counterparty_id`), even if the voucher's
        // on-chain transaction is anonymous. If an offline double-spend is investigated later,
        // the local wallet owner must be able to prove and trace to whom they sent the voucher.
        // This is strictly local to the user's sealed storage and is an intentional forensic feature,
        // NOT a security leak.
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
        archive: Option<&FileVoucherArchive>,
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
                    crate::Error::Wallet(crate::error::WalletError::StandardNotFound { uuid: standard_uuid.clone() })
                })?;

            // NEW: Create InvolvedVoucherInfo for the source (BEFORE the transfer)
            // ARCHITECTURAL DESIGN REQUIREMENT (Offline Forensics):
            // We retain the counterparty_id here so the user has an accurate record of
            // the intended destination for each individual voucher in the bundle.
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
                request.use_privacy_mode,
                Some(request.recipient_id.clone()),
                request.sender_profile_name.clone(),
            )?;

            vouchers_for_bundle.push(new_voucher);
        }

        // 3. **Bundling:** Create a single SecureContainer bundle.
        let (fingerprints_to_send, depths_to_send) = temp_wallet
            .select_fingerprints_for_bundle(&request.recipient_id, &vouchers_for_bundle)?;

        // Snapshot of the transferred voucher states for the post-commit
        // archiving pass (the bundle creation below consumes the originals).
        let transferred_states = vouchers_for_bundle.clone();

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

        // 5. **Post-commit archiving (HMC-SEC-04-03):** Archive writes are
        //    side effects that cannot be rolled back with the wallet state,
        //    so they are performed strictly AFTER the atomic commit point.
        //    An aborted operation therefore never leaves ghost entries in the
        //    forensic archive.
        //
        //    AUDIT-00-WILDCARD-02: failures INSIDE this phase must not be
        //    reported as operation failures. The transfer is already
        //    committed and the bundle bytes are irrevocably produced;
        //    propagating an Err from here would (a) let callers believe the
        //    send did not happen (retry -> double send) while the AppService
        //    rollback leaves ghost entries for states the authoritative
        //    wallet says never existed, and (b) violate the Err => no commit
        //    contract. Archiving is therefore BEST-EFFORT in this phase:
        //    individual failures are logged and skipped (forensic gap), the
        //    operation itself remains successful.
        //
        //    SECURITY (AUDIT-W4-INT-503): a forensic gap is never SILENT.
        //    Every voucher state that could not be archived is reported to
        //    the caller via `CreateBundleResult::forensic_archive_incomplete`
        //    so hosts can warn/journal the incomplete custody chain.
        let mut forensic_archive_incomplete: Vec<String> = Vec::new();
        if let Some(archive_backend) = archive {
            for voucher in &transferred_states {
                let standard_uuid = voucher.voucher_standard.uuid.clone();
                let standard_definition = match standard_definitions.get(&standard_uuid) {
                    Some(def) => def,
                    None => {
                        eprintln!(
                            "Forensic archiving skipped: standard '{}' not found in provided definitions.",
                            standard_uuid
                        );
                        forensic_archive_incomplete.push(voucher.voucher_id.clone());
                        continue;
                    }
                };
                if let Err(e) = archive_backend.archive_voucher(
                    voucher,
                    &identity.user_id,
                    standard_definition,
                ) {
                    eprintln!(
                        "Forensic archiving failed for a committed voucher state (best effort): {}",
                        e
                    );
                    forensic_archive_incomplete.push(voucher.voucher_id.clone());
                }
            }
        }

        Ok(CreateBundleResult {
            bundle_bytes: container_bytes,
            bundle_id: header.bundle_id,
            involved_sources_details,
            forensic_archive_incomplete,
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
            crate::Error::Wallet(crate::error::WalletError::MissingTransactions)
        })?;

        // 1. Check if we are the SENDER (change) via crypto matching
        // We attempt to derive the change key deterministically and compare the hash.
        let prev_hash = &last_tx.prev_hash;
        if let Ok(candidate_key) = derive_deterministic_change_key(identity, prev_hash) {
            let candidate_hash = crate::services::crypto::get_hash(candidate_key.verifying_key().to_bytes());
            if Some(&candidate_hash) == last_tx.change_ephemeral_pub_hash.as_ref() {
                return Ok(candidate_key);
            }
        }

        // 2. Check if we are the RECIPIENT (received) via Privacy Guard
        if let Some(guard_base64) = &last_tx.privacy_guard
            && let Ok(decrypted_payload_bytes) = crate::services::crypto::decrypt_recipient_payload(
                guard_base64,
                &identity.signing_key,
                &identity.user_id,
            )
                && let Ok(payload) = serde_json::from_slice::<crate::models::voucher::RecipientPayload>(&decrypted_payload_bytes)
                    && let Ok(seed_arr) = crate::services::crypto::decode_bs58_fixed::<32>(&payload.next_key_seed, "next_key_seed") {
                            let candidate_key = SigningKey::from_bytes(&seed_arr);
                            let candidate_hash = crate::services::crypto::get_hash(candidate_key.verifying_key().to_bytes());
                            
                            if Some(&candidate_hash) == last_tx.receiver_ephemeral_pub_hash.as_ref() {
                                return Ok(candidate_key);
                            }
                        }

        // 3. Fallback: Public Mode / Init
        if last_tx.sender_id.as_ref() == Some(&identity.user_id) && last_tx.sender_remaining_amount.is_some() {
             let candidate_key = derive_deterministic_change_key(identity, prev_hash)?;
             return Ok(candidate_key);
        }

        // Case C: Init (creator)
        if last_tx.t_type == "init" && last_tx.sender_id.as_ref() == Some(&identity.user_id) {
            let nonce_bytes = bs58::decode(&voucher.voucher_nonce)
                .into_vec()
                .map_err(|_| crate::Error::Wallet(crate::error::WalletError::InvalidNonce { reason: "Invalid nonce".to_string() }))?;

            let sender_id_prefix = crate::services::crypto::get_prefix_from_user_id(&identity.user_id);

            let (holder_secret, _) = crate::services::crypto::derive_ephemeral_key_pair(
                &identity.signing_key,
                &nonce_bytes,
                "holder",
                sender_id_prefix,
            )?;
            return Ok(holder_secret);
        }

        Err(crate::Error::Wallet(crate::error::WalletError::SeedDerivationFailed { reason: "Could not rederive secret seed: No valid ownership strategy found (neither Change nor Receiver hash matches).".to_string() }))
    }

    /// Extracts the sender identity (DID) from a transaction.
    /// Considers both public mode (sender_id in plaintext)
    /// and stealth mode (decryption of the Privacy Guard).
    fn extract_sender_from_transaction(
        tx: &crate::models::voucher::Transaction,
        identity: &UserIdentity,
    ) -> Option<String> {
        // Case 1: Public Mode - sender ID is directly present in plaintext
        if let Some(sender_id) = &tx.sender_id
            && sender_id != crate::models::voucher::ANONYMOUS_ID {
                return Some(sender_id.clone());
            }

        // Case 2: Stealth Mode - DID is encrypted in the Privacy Guard
        if let Some(guard_base64) = &tx.privacy_guard
            && let Ok(decrypted_payload_bytes) = crate::services::crypto::decrypt_recipient_payload(
                guard_base64,
                &identity.signing_key,
                &identity.user_id,
            )
                && let Ok(payload) = serde_json::from_slice::<crate::models::voucher::RecipientPayload>(
                    &decrypted_payload_bytes,
                ) {
                    return Some(payload.sender_permanent_did);
                }

        None
    }
}


impl Wallet {
    /// Creates a `SecureContainer` to send a voucher for signing.
    ///
    /// This function does not modify wallet state. It only serves to package a request.
    ///
    /// # Arguments
    /// * `identity` - The identity of the requesting voucher owner.
    /// * `local_instance_id` - The ID of the voucher in the local `voucher_store`.
    /// * `config` - The encryption configuration (TargetDid, Password, or Cleartext).
    ///
    /// # Returns
    /// The serialized bytes of the `SecureContainer`.
    pub fn create_signing_request(
        &self,
        identity: &UserIdentity,
        local_instance_id: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        let instance = self.voucher_store.vouchers.get(local_instance_id).ok_or(
            VoucherCoreError::VoucherNotFound(local_instance_id.to_string()),
        )?;

        // BUGFIX: Add missing status check. A signature request is
        // only meaningful for active or incomplete vouchers.
        if !matches!(
            instance.status,
            VoucherStatus::Active | VoucherStatus::Incomplete { .. }
        ) {
            return Err(VoucherCoreError::VoucherNotActive(instance.status.clone()));
        }
        let payload = to_canonical_json(&instance.voucher)?;

        let container = SecureContainer::seal(
            identity,
            &config,
            payload.as_bytes(),
            PayloadType::VoucherForSigning,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Creates a `DetachedSignature` for a voucher and packages it in a
    /// `SecureContainer` for return transmission.
    ///
    /// # Arguments
    /// * `identity` - The identity of the signer.
    /// * `voucher_to_sign` - The voucher to be signed (validated by client).
    /// * `signature_data` - Signature metadata prepared by the client.
    /// * `include_details` - Whether the signer's `PublicProfile` data should be embedded.
    /// * `config` - The encryption configuration (TargetDid, Password, or Cleartext).
    ///
    /// # Returns
    /// The serialized bytes of the `SecureContainer` containing the signature.
    pub fn create_detached_signature_response(
        &self,
        identity: &UserIdentity,
        voucher_to_sign: &Voucher,
        signature_data: DetachedSignature,
        include_details: bool,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        // Assemble optional profile details
        let details = if include_details {
            Some(self.profile.to_public_profile_with_id(false))
        } else {
            None
        };

        // HMC-SEC-06-04: The voucher originates from an external signing
        // request. Indexing `transactions[0]` directly on unvalidated remote
        // input is a remotely reachable panic that aborts the host process.
        let init_t_id = &voucher_to_sign
            .transactions
            .first()
            .ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::VoucherHasNoTransactions)
            })?
            .t_id;

        let signed_signature = signature_data.complete_and_sign(
            identity,
            details,
            &voucher_to_sign.voucher_id,
            init_t_id,
        )?;

        let payload = to_canonical_json(&signed_signature)?;

        let container = SecureContainer::seal(
            identity,
            &config,
            payload.as_bytes(),
            PayloadType::DetachedSignature,
        )?;

        Ok(serde_json::to_vec(&container)?)
    }

    /// Processes a `SecureContainer` containing a `DetachedSignature`
    /// and attaches it to the corresponding local voucher.
    ///
    /// # Arguments
    /// * `identity` - The identity of the recipient.
    /// * `container_bytes` - The received container data.
    /// * `password` - Optional password for symmetric encryption.
    ///
    /// # Returns
    /// A `Result` containing the updated instance ID on success.
    pub fn process_and_attach_signature(
        &mut self,
        identity: &UserIdentity,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<String, VoucherCoreError> {
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;
        let payload =
            container.open(identity, password)?;

        // HMSEC-SA06-09: Rebind the integrity id `i` to the received bytes
        // before acting on the payload. Placed AFTER decryption so AEAD
        // authentication errors keep precedence (established error contract);
        // for validly encrypted containers this is the gate that rejects
        // stolen `(i, signature)` pairs and mutated AEAD-exempt envelope
        // fields (`unprotected`, `salt`, `et`, `c`).
        container.verify_integrity()?;

        if !matches!(container.c, PayloadType::DetachedSignature) {
            return Err(VoucherCoreError::InvalidPayloadType);
        }

        let signature: DetachedSignature = serde_json::from_slice(&payload)?;
        let signature_obj_inner = signature.inner();

        // We must find the voucher to obtain init_t_id for validation
        let target_instance_for_val = self
            .voucher_store
            .vouchers
            .values()
            .find(|instance| instance.voucher.voucher_id == signature_obj_inner.voucher_id)
            .ok_or_else(|| {
                VoucherCoreError::VoucherNotFound(format!(
                    "No voucher found matching signature's voucher_id: {}",
                    signature_obj_inner.voucher_id
                ))
            })?;

        // HMC-SEC-06-04: Graceful error instead of an index panic if the
        // stored voucher has an empty transaction chain.
        let init_t_id = &target_instance_for_val
            .voucher
            .transactions
            .first()
            .ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::VoucherHasNoTransactions)
            })?
            .t_id;
        signature.validate(init_t_id)?;

        let signature_obj = signature.into_inner();

        // Find a voucher that is expecting this signature
        let target_instance = self
            .voucher_store
            .vouchers
            .values_mut()
            .find(|instance| instance.voucher.voucher_id == signature_obj.voucher_id)
            .ok_or_else(|| {
                VoucherCoreError::VoucherNotFound(format!(
                    "No voucher found matching signature's voucher_id: {}",
                    signature_obj.voucher_id
                ))
            })?;

        // (Optional, but recommended) Check if signature is already present
        if target_instance
            .voucher
            .signatures
            .iter()
            .any(|sig| sig.signature_id == signature_obj.signature_id)
        {
            // Silently ignore or return error
            return Err(VoucherCoreError::MismatchedSignatureData(
                format!(
                    "Signature {} already attached to voucher {} [LOCAL_ID:{}]",
                    signature_obj.signature_id, signature_obj.voucher_id, target_instance.local_instance_id
                ),
            ));
        }

        target_instance.voucher.signatures.push(signature_obj);

        Ok(target_instance.local_instance_id.clone())
    }

    /// Removes an additional signature (e.g. from guarantors or witnesses) from a voucher.
    ///
    /// This operation may only be performed by the voucher creator and only
    /// while the voucher is not yet in circulation (only one init transaction present).
    ///
    /// # Arguments
    /// * `identity` - The identity of the requesting user (must be the creator).
    /// * `local_instance_id` - The ID of the voucher in the local `voucher_store`.
    /// * `signature_id` - The ID of the signature to be removed.
    ///
    /// # Returns
    /// A `Result` returning `Ok(())` on success.
    ///
    /// # Errors
    /// * `VoucherNotFound` - The voucher was not found.
    /// * `SignatureRemovalRequiresIncomplete` - Removal only allowed in 'Incomplete' status.
    /// * `NotTheCreator` - The requesting identity is not the voucher creator.
    /// * `VoucherAlreadyInCirculation` - The voucher already has more than one transaction (is in circulation).
    /// * `CannotRemoveCreatorSignature` - An attempt was made to remove the creator's core signature.
    pub fn remove_signature(
        &mut self,
        identity: &UserIdentity,
        local_instance_id: &str,
        signature_id: &str,
    ) -> Result<(), VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .get_mut(local_instance_id)
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(local_instance_id.to_string()))?;

        // 1. Status check: Only Incomplete allowed
        if !matches!(instance.status, VoucherStatus::Incomplete { .. }) {
            return Err(VoucherCoreError::SignatureRemovalRequiresIncomplete(
                instance.status.clone(),
            ));
        }

        // 2. History check: Only one init transaction allowed
        if instance.voucher.transactions.len() != 1 {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }
        let first_transaction = &instance.voucher.transactions[0];
        if first_transaction.t_type != "init" {
            return Err(VoucherCoreError::VoucherAlreadyInCirculation);
        }

        // 3. Identity check: Only the creator may remove signatures
        let creator_id = instance
            .voucher
            .creator_profile
            .id
            .as_ref()
            .ok_or_else(|| crate::Error::Wallet(crate::error::WalletError::MissingCreatorId))?;
        if &identity.user_id != creator_id {
            return Err(VoucherCoreError::NotTheCreator);
        }

        // 4. Role check: Find signature and check if it is allowed to be removed
        let signature_to_remove = instance
            .voucher
            .signatures
            .iter()
            .find(|sig| sig.signature_id == signature_id)
            .ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::SignatureNotFound { signature_id: signature_id.to_string() })
            })?;

        if signature_to_remove.role == "creator" {
            return Err(VoucherCoreError::CannotRemoveCreatorSignature);
        }

        // 5. Remove signature
        instance
            .voucher
            .signatures
            .retain(|sig| sig.signature_id != signature_id);

        // 6. Status re-evaluation: If required signatures are missing, set to Incomplete
        // Note: Full validation against standard requires access to the standard,
        // which is not available at this layer. We conservatively set to Incomplete
        // when signatures are removed. The AppService layer can revalidate as needed.
        if !matches!(instance.status, VoucherStatus::Incomplete { .. }) {
            instance.status = VoucherStatus::Incomplete {
                reasons: vec![crate::ValidationFailureReason::RequiredSignatureMissing {
                    role_description: "Signature removed, validation against standard required".to_string(),
                }],
            };
        }

        Ok(())
    }
}
