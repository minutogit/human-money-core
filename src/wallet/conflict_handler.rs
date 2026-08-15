//! # src/wallet/conflict_handler.rs
//!
//! Contains the implementation of `Wallet` methods responsible for
//! double-spend detection and management.

use super::{DoubleSpendCheckResult, Wallet};
use crate::archive::VoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::VoucherStore;
use crate::models::{
    conflict::{
        ProofOfDoubleSpend, ResolutionEndorsement, TransactionFingerprint,
    },
    profile::{TransactionBundleHeader, UserIdentity},
    voucher::Voucher,
};
use crate::services::conflict_manager;
use crate::services::crypto_utils::get_short_hash_from_user_id;
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::wallet::instance::VoucherStatus;
use std::collections::HashMap;

/// Methods for managing the fingerprint store and double-spending logic.
impl Wallet {
    /// Scans all own vouchers and updates the `own_fingerprints` store.
    /// IMPORTANT: This function preserves already imported `foreign_fingerprints`.
    pub fn scan_and_rebuild_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        let (own, mut known) = conflict_manager::scan_and_rebuild_fingerprints(
            &self.voucher_store,
            &self.profile.user_id,
        )?;
        // Preserve existing histories, as these cannot be (fully) reconstructed from the
        // local `voucher_store` (e.g. after archiving).
        known.foreign_fingerprints =
            std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);
        
        // NEW: Also preserve/merge local_history
        let old_local_history = std::mem::take(&mut self.known_fingerprints.local_history);
        for (hash, fps) in old_local_history {
            let entry = known.local_history.entry(hash).or_default();
            for fp in fps {
                if !entry.iter().any(|e| e.t_id == fp.t_id) {
                    entry.push(fp);
                }
            }
        }

        self.own_fingerprints = own;
        self.known_fingerprints = known;
        Ok(())
    }

    /// Performs a full double-spend check.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(&self.own_fingerprints, &self.known_fingerprints)
    }

    /// Removes all expired fingerprints from storage.
    /// Returns the number of removed entries.
    pub fn cleanup_expired_fingerprints(&mut self) -> usize {
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints)
    }

    /// Serializes own fingerprints for export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.own_fingerprints)
    }

    /// Imports and merges foreign fingerprints into storage.
    pub fn import_foreign_fingerprints(&mut self, data: &[u8]) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.known_fingerprints, data)
    }

    /// Returns a list of summaries of all known double-spend conflicts.
    ///
    /// This method iterates through the `proof_store` and creates a simplified
    /// `ProofOfDoubleSpendSummary` for each `ProofStoreEntry`.
    /// The status (`is_resolved`, `has_l2_verdict`) is determined dynamically.
    pub fn list_conflicts(&self) -> Vec<ProofOfDoubleSpendSummary> {
        self.proof_store
            .proofs
            .values()
            .map(|entry| {
                let proof = &entry.proof;
                ProofOfDoubleSpendSummary {
                    proof_id: proof.proof_id.clone(),
                    offender_id: proof.offender_id.clone(),
                    fork_point_prev_hash: proof.fork_point_prev_hash.clone(),
                    report_timestamp: proof.report_timestamp.clone(),
                    is_resolved: proof.resolutions.as_ref().map_or(false, |v| !v.is_empty()),
                    has_l2_verdict: proof.layer2_verdict.is_some(),
                    local_override: entry.local_override,
                    local_note: entry.local_note.clone(),
                    conflict_role: entry.conflict_role,
                    affected_voucher_name: proof.affected_voucher_name.clone(),
                    display_affected_voucher_name: proof.affected_voucher_name.as_ref().map(|n| {
                        super::format_bff_name(n, proof.non_redeemable_test_voucher)
                    }),
                    voucher_standard_uuid: proof.voucher_standard_uuid.clone(),
                    is_test_voucher: proof.non_redeemable_test_voucher,
                }
            })
            .collect()
    }

    /// Retrieves a complete `ProofOfDoubleSpend` by its ID.
    ///
    /// # Arguments
    /// * `proof_id` - The deterministic ID of the proof to search for.
    pub fn get_proof_of_double_spend(
        &self,
        proof_id: &str,
    ) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
        self.proof_store
            .proofs
            .get(proof_id)
            .map(|entry| entry.proof.clone())
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!("Proof with ID '{}' not found.", proof_id))
            })
    }

    /// Finds the associated double-spend conflict proof ID for a voucher using cascading match strategies.
    pub fn get_proof_id_for_voucher(&self, local_id: &str) -> Option<String> {
        // Direct lookup of the voucher instance
        let instance = self.voucher_store.vouchers.get(local_id)?;
        let voucher_txs = &instance.voucher.transactions;

        for entry in self.proof_store.proofs.values() {
            let proof = &entry.proof;

            // Match 1: Direct transaction ID match (Checks all transactions in the voucher)
            let has_tx_match = proof.conflicting_transactions.iter().any(|tx| {
                voucher_txs.iter().any(|vtx| vtx.t_id == tx.t_id)
            });
            if has_tx_match {
                log::info!("  ✅ Match 1 (t_id) found!");
                return Some(proof.proof_id.clone());
            }

            // Match 2: DS-Tag match (Very robust)
            let proof_ds_tags: Vec<&str> = proof.conflicting_transactions.iter()
                .filter_map(|tx| tx.trap_data.as_ref().map(|td| td.ds_tag.as_str()))
                .collect();
            let has_ds_tag_match = voucher_txs.iter().any(|vtx| {
                vtx.trap_data.as_ref().map(|td| proof_ds_tags.contains(&td.ds_tag.as_str())).unwrap_or(false)
            });
            if has_ds_tag_match {
                log::info!("  ✅ Match 2 (ds_tag) found!");
                return Some(proof.proof_id.clone());
            }

            // Match 3: Deep Fork Point match (Scans entire chain)
            let has_deep_fork_match = voucher_txs.iter().any(|vtx| {
                vtx.prev_hash == proof.fork_point_prev_hash || vtx.t_id == proof.fork_point_prev_hash
            });
            let has_any_history_match = voucher_txs.iter().any(|vtx| {
                 vtx.prev_hash == proof.fork_point_prev_hash
            });
            if has_deep_fork_match || has_any_history_match {
                log::info!("  ✅ Match 3 (fork_point) found!");
                return Some(proof.proof_id.clone());
            }

            // Match 4: Offender & Chain Link (The most aggressive fallback)
            let is_offender_involved = voucher_txs.iter().any(|vtx| {
                vtx.sender_id.as_deref() == Some(proof.offender_id.as_str())
            });
            if is_offender_involved {
                log::info!("  ✅ Match 4 (offender involvement) found!");
                return Some(proof.proof_id.clone());
            }

            // Match 5: Recipient match (Targeted at the victim)
            let voucher_last_recipient = voucher_txs.last().map(|tx| tx.recipient_id.as_str());
            let has_recipient_match = proof.conflicting_transactions.iter().any(|tx| {
                voucher_last_recipient == Some(tx.recipient_id.as_str())
            });
            if has_recipient_match {
                log::info!("  ✅ Match 5 (recipient_id) found!");
                return Some(proof.proof_id.clone());
            }
        }

        log::warn!("=== No proof found for quarantined voucher {} after checking {} conflicts ===", local_id, self.proof_store.proofs.len());
        None
    }


    /// Creates a signed resolution endorsement (`ResolutionEndorsement`) for a conflict.
    ///
    /// This method does not mutate the wallet state, but only creates the
    /// signed object which can then be transmitted to other parties.
    ///
    /// # Arguments
    /// * `identity` - The identity of the wallet owner (the victim) signing the resolution.
    /// * `proof_id` - The ID of the conflict being resolved.
    /// * `notes` - An optional human-readable note.
    pub fn create_resolution_endorsement(
        &self,
        identity: &UserIdentity,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, VoucherCoreError> {
        // Ensure that the proof exists before creating an endorsement.
        if !self.proof_store.proofs.contains_key(proof_id) {
            return Err(VoucherCoreError::Generic(format!(
                "Cannot create endorsement: Proof with ID '{}' not found.",
                proof_id
            )));
        }
        conflict_manager::create_and_sign_resolution_endorsement(proof_id, identity, notes)
    }

    /// Adds an (externally received) resolution endorsement to an existing conflict proof.
    pub fn add_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
    ) -> Result<(), VoucherCoreError> {
        let entry = self
            .proof_store
            .proofs
            .get_mut(&endorsement.proof_id)
            .ok_or_else(|| {
                VoucherCoreError::Generic(format!(
                    "Cannot add endorsement: Proof with ID '{}' not found.",
                    endorsement.proof_id
                ))
            })?;
        let resolutions = entry.proof.resolutions.get_or_insert_with(Vec::new);
        if !resolutions
            .iter()
            .any(|e| e.endorsement_id == endorsement.endorsement_id)
        {
            resolutions.push(endorsement);
        }
        Ok(())
    }

    /// Sets the local override for a conflict.
    /// This allows the user to locally re-trust an offender despite an existing proof.
    pub fn set_conflict_local_override(
        &mut self,
        proof_id: &str,
        value: bool,
        note: Option<String>,
    ) -> Result<(), VoucherCoreError> {
        let entry = self.proof_store.proofs.get_mut(proof_id).ok_or_else(|| {
            VoucherCoreError::Generic(format!("Proof with ID '{}' not found.", proof_id))
        })?;
        entry.local_override = value;
        entry.local_note = note;
        Ok(())
    }

    /// Imports an external proof into the ProofStore.
    ///
    /// # Immunity Rule (MVP):
    /// If the proof already exists locally, the import is ignored.
    /// This prevents external data from overwriting local decisions (overrides).
    pub fn import_proof(&mut self, proof: ProofOfDoubleSpend) -> Result<(), VoucherCoreError> {
        if self.proof_store.proofs.contains_key(&proof.proof_id) {
            // Already known -> Ignore (immunity of local decisions)
            return Ok(());
        }

        // --- Conflict resolution (determine offline winner and quarantine losers) ---
        let mut winner_tx_id: Option<String> = None;
        let mut earliest_dt: Option<chrono::DateTime<chrono::FixedOffset>> = None;

        for tx in &proof.conflicting_transactions {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&tx.t_time) {
                match earliest_dt {
                    None => {
                        earliest_dt = Some(dt);
                        winner_tx_id = Some(tx.t_id.clone());
                    }
                    Some(e_dt) if dt < e_dt => {
                        earliest_dt = Some(dt);
                        winner_tx_id = Some(tx.t_id.clone());
                    }
                    _ => {}
                }
            }
        }

        let tx_ids: std::collections::HashSet<_> = proof.conflicting_transactions.iter().map(|tx| &tx.t_id).collect();
        let mut quarantined_events = Vec::new();

        if let Some(winner_id) = winner_tx_id {
            for instance in self.voucher_store.vouchers.values_mut() {
                if let Some(tx) = instance
                    .voucher
                    .transactions
                    .iter()
                    .find(|tx| tx_ids.contains(&tx.t_id))
                {
                    let prev_status = instance.status.clone();
                    instance.status = if tx.t_id == winner_id {
                        VoucherStatus::Active
                    } else {
                        VoucherStatus::Quarantined {
                            reason: "Lost race in imported proof".to_string(),
                        }
                    };

                    if !matches!(prev_status, VoucherStatus::Quarantined { .. })
                        && matches!(instance.status, VoucherStatus::Quarantined { .. })
                    {
                        let bff_data = crate::models::wallet_event::EventBffData {
                            display_currency: super::format_bff_name(
                                instance.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&instance.voucher.nominal_value.unit),
                                instance.voucher.non_redeemable_test_voucher,
                            ),
                            amount: instance.voucher.nominal_value.amount.clone(),
                            is_test_voucher: instance.voucher.non_redeemable_test_voucher,
                            counterparty_id: None,
                            counterparty_name: None,
                        };
                        quarantined_events.push((
                            instance.local_instance_id.clone(),
                            instance.voucher.voucher_id.clone(),
                            bff_data,
                        ));
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

        let entry = crate::models::conflict::ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role,
        };

        self.proof_store.proofs.insert(entry.proof.proof_id.clone(), entry);
        Ok(())
    }

    // --- NEWLY ADDED FROM MOD.RS ---

    /// Verifies a conflict and creates a proof. Internal method.
    pub(super) fn verify_and_create_proof(
        &self,
        identity: &UserIdentity,
        fingerprints: &[TransactionFingerprint],
        archive: &dyn VoucherArchive,
    ) -> Result<Option<crate::models::conflict::ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();
        let mut missing_t_ids = Vec::new();

        // 1. Find the complete transactions corresponding to the fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            } else {
                missing_t_ids.push(fp.t_id.clone());
            }
        }

        if conflicting_transactions.is_empty() {
            // FIX: For pure gossip conflicts, the local wallet never has the transactions
            // in its store. If we have >= 2 fingerprints with distinct
            // t_ids, we can still create a "Gossip Soft Proof".
            if fingerprints.len() >= 2 {
                let unique_t_ids: std::collections::HashSet<_> =
                    fingerprints.iter().map(|fp| &fp.t_id).collect();
                if unique_t_ids.len() >= 2 {
                    // Create synthetic transactions from fingerprint data.
                    // The offender_id can only be set to ANONYMOUS, as full
                    // mathematical identity recovery (V = u·M + ID)
                    // is only possible with real TrapData (u, blinded_id) — but
                    // the gossip recipient has enough data for a soft proof.
                    let offender_id = crate::models::voucher::ANONYMOUS_ID.to_string();
                    // Use ds_tag as a proxy for fork_point_prev_hash,
                    // as the actual prev_hash is not available.
                    let fork_point_prev_hash = fingerprints[0].ds_tag.clone();

                    for fp in fingerprints {
                        let mut synthetic_tx = crate::models::voucher::Transaction::default();
                        synthetic_tx.t_id = fp.t_id.clone();
                        synthetic_tx.sender_id = Some(offender_id.clone());
                        synthetic_tx.prev_hash = fork_point_prev_hash.clone();
                        synthetic_tx.t_type = "gossip_soft_placeholder".to_string();
                        synthetic_tx.amount = "0.00 (Gossip)".to_string();
                        conflicting_transactions.push(synthetic_tx);
                    }

                    // Skip missing generation (all already covered)
                    missing_t_ids.clear();
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

        // 2. Extract core data from the FIRST found transaction.
        let mut offender_id = conflicting_transactions[0]
            .sender_id
            .clone()
            .unwrap_or(crate::models::voucher::ANONYMOUS_ID.to_string());

        // --- MATHEMATICAL DE-ANONYMIZATION ---
        // If the identity is anonymous (stealth mode or gossip soft proof), we try to
        // mathematically recover it from the trap data of the fingerprints.
        if offender_id == crate::models::voucher::ANONYMOUS_ID && fingerprints.len() >= 2 {
            let f1 = &fingerprints[0];
            let f2 = &fingerprints[1];
            // Only if these are real mathematical traps (not 'init' fingerprints)
            if f1.u != "none" && f2.u != "none" {
                if let Ok(point) = crate::services::trap_manager::extract_id_point_from_raw_data(
                    &f1.ds_tag,
                    &f1.u,
                    &f1.blinded_id,
                    &f2.ds_tag,
                    &f2.u,
                    &f2.blinded_id,
                ) {
                    let pk_bytes = point.compress().to_bytes();
                    if let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
                        // Create a DID-Key ID (in root account format without prefix)
                        if let Ok(did_id) = crate::services::crypto_utils::create_user_id(&pk, None)
                        {
                            offender_id = did_id;
                        }
                    }
                }
            }
        }

        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();
        
        for t_id in missing_t_ids {
            let mut synthetic_tx = crate::models::voucher::Transaction::default();
            synthetic_tx.t_id = t_id;
            synthetic_tx.sender_id = Some(offender_id.clone());
            synthetic_tx.prev_hash = fork_point_prev_hash.clone();
            synthetic_tx.t_type = "soft_placeholder".to_string();
            synthetic_tx.amount = "0.00 (Synthetic)".to_string();
            conflicting_transactions.push(synthetic_tx);
        }

        // 5. Attempt L2 verification for all available transactions.
        let mut _verified_tx_count = 0;
        let mut voucher_valid_until = "unknown".to_string();
        let mut affected_voucher_name = None;
        let mut voucher_standard_uuid = None;
        let mut is_test_voucher = false;

        if let Some(voucher) = self.find_voucher_for_transaction(&conflicting_transactions[0].t_id, archive)? {
            voucher_valid_until = voucher.valid_until.clone();
            affected_voucher_name = Some(voucher.voucher_standard.name.clone());
            voucher_standard_uuid = Some(voucher.voucher_standard.uuid.clone());
            is_test_voucher = voucher.non_redeemable_test_voucher;

            if let Ok(layer2_voucher_id) = crate::services::l2_gateway::extract_layer2_voucher_id(&voucher) {
                for (_i, tx) in conflicting_transactions.iter().filter(|t| t.t_type != "soft_placeholder").enumerate() {
                    match crate::services::voucher_validation::verify_transaction_integrity_and_signature(
                        tx,
                        &layer2_voucher_id,
                    ) {
                        Ok(()) => {
                            _verified_tx_count += 1;
                        }
                        Err(_e) => {
                        }
                    }
                }
            }
        }


        // 6. Create the proof object.
        // IMPORTANT: We NOW ALWAYS create the proof if we have >= 2 candidates,
        // even if they could not be fully cryptographically verified ("Soft Proof").
        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        let mut proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
            is_test_voucher,
        )?;

        // Set metadata
        proof.affected_voucher_name = affected_voucher_name;
        proof.voucher_standard_uuid = voucher_standard_uuid;

        // If we already know the proof and have an L2 verdict or resolutions, adopt them!
        if let Some(existing_entry) = self.proof_store.proofs.get(&proof.proof_id) {
            proof.layer2_verdict = existing_entry.proof.layer2_verdict.clone();
            proof.resolutions = existing_entry.proof.resolutions.clone();
        }

        Ok(Some(proof))
    }

    /// Internal helper function for Layer 2 replay protection.
    ///
    /// Checks the fingerprints of the latest transactions of all incoming vouchers
    /// in a bundle against the entire known fingerprint history of the wallet.
    ///
    /// # Errors
    /// Returns `VoucherCoreError::TransactionFingerprintAlreadyKnown` if
    /// one of the fingerprints is already present in `own_fingerprints` or `known_fingerprints`
    /// (both `local_history` and `foreign_fingerprints`) AND
    /// the `t_id` also matches (replay attack).
    ///
    /// A double-spend (same `fingerprint_hash`, but NEW `t_id`) is
    /// *intentionally permitted* so that it can be handled by the downstream
    /// conflict resolution logic ("Earliest Wins").
    pub(super) fn check_bundle_fingerprints_against_history(
        &self,
        vouchers: &[Voucher],
    ) -> Result<(), VoucherCoreError> {
        for voucher in vouchers {
            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                    "Received voucher has no transactions.".to_string(),
                ))
            })?;

            // Calculate the relevant fingerprint (the "collision ID")
            let fingerprint =
                conflict_manager::create_fingerprint_for_transaction(last_tx, voucher)?;
            let fingerprint_hash = fingerprint.ds_tag;

            // --- CORRECTED LOGIC: Distinguish replay vs. double spend ---

            // 1. Collect all known t_ids for this fingerprint hash
            let mut known_t_ids = std::collections::HashSet::new();

            if let Some(t_ids_vec) = self.own_fingerprints.history.get(&fingerprint_hash) {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }
            if let Some(t_ids_vec) = self.known_fingerprints.local_history.get(&fingerprint_hash) {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }
            if let Some(t_ids_vec) = self
                .known_fingerprints
                .foreign_fingerprints
                .get(&fingerprint_hash)
            {
                for fp in t_ids_vec {
                    known_t_ids.insert(&fp.t_id);
                }
            }

            // 2. Check if the fingerprint hash is known at all.
            if !known_t_ids.is_empty() {
                // The fingerprint hash is known.
                // 3. Check if the *specific t_id* is also known.
                let incoming_t_id = &last_tx.t_id;

                if known_t_ids.contains(incoming_t_id) {
                    // --- CASE A (True replay) ---
                    // We have seen THIS EXACT transaction (same hash, same t_id)
                    // before. This is a replay attack.
                    return Err(VoucherCoreError::TransactionFingerprintAlreadyKnown {
                        fingerprint_hash,
                    });
                }
                // --- CASE B (Double spend) ---
                // The hash is known, but the t_id is NEW.
                // This is a double spend. We let it pass so that
                // the "Earliest Wins" heuristic can catch it.
            }
        }

        Ok(())
    }

    /// Selects fingerprints for forwarding in a bundle, based on the heuristic.
    ///
    /// # Logic
    /// 1. Marks all fingerprints of the voucher being sent as implicitly known to the recipient.
    /// 2. Prioritizes negative "VIP" fingerprints (fraud detection).
    /// 3. Iterates upward through all known positive fingerprints.
    /// 4. Selects up to `MAX_FINGERPRINTS_TO_SEND` candidates.
    ///
    /// # Returns
    /// A tuple of (`Vec<TransactionFingerprint>`, `HashMap<String, i8>`) for the bundle.
    pub fn select_fingerprints_for_bundle(
        &mut self,
        recipient_id: &str,
        vouchers_in_bundle: &[Voucher],
    ) -> Result<(Vec<TransactionFingerprint>, HashMap<String, i8>), VoucherCoreError> {
        const MAX_FINGERPRINTS_TO_SEND: usize = 150;

        // Use memory-efficient short hash (returns [u8; 4])
        let recipient_short_hash = get_short_hash_from_user_id(recipient_id);

        let mut selected_fingerprints = Vec::new();
        let mut selected_depths = HashMap::new();

        // Step 1: Mark implicitly known fingerprints of the current transfer
        for voucher in vouchers_in_bundle {
            for tx in &voucher.transactions {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;
                if let Some(meta) = self.fingerprint_metadata.get_mut(&fingerprint.ds_tag) {
                    meta.known_by_peers.insert(recipient_short_hash);
                }
            }
        }

        // Step 2: Collect all known fingerprints
        let mut all_known_fingerprints: Vec<TransactionFingerprint> = self
            .own_fingerprints
            .history
            .values()
            .flatten()
            .chain(self.known_fingerprints.local_history.values().flatten())
            .chain(
                self.known_fingerprints
                    .foreign_fingerprints
                    .values()
                    .flatten(),
            )
            .cloned()
            .collect();

        // Sorting: Calculate "effective depth" for organic displacement
        all_known_fingerprints.sort_by(|a, b| {
            let depth_a = self.fingerprint_metadata.get(&a.ds_tag).map(|m| m.depth).unwrap_or(0);
            let depth_b = self.fingerprint_metadata.get(&b.ds_tag).map(|m| m.depth).unwrap_or(0);
            
            // Calculation: VIPs get a 2-hop lead.
            // Cast to i16 to avoid underflow risks on (1 - 2) = -1.
            let eff_a = if depth_a < 0 { (depth_a.abs() as i16) - 2 } else { depth_a as i16 };
            let eff_b = if depth_b < 0 { (depth_b.abs() as i16) - 2 } else { depth_b as i16 };
            
            eff_a.cmp(&eff_b).then_with(|| a.ds_tag.cmp(&b.ds_tag))
        });

        for fp in all_known_fingerprints {
            if selected_fingerprints.len() >= MAX_FINGERPRINTS_TO_SEND {
                break;
            }

            if let Some(meta) = self.fingerprint_metadata.get_mut(&fp.ds_tag) {
                // Only if the recipient does not know it yet
                if !meta.known_by_peers.contains(&recipient_short_hash) {
                    meta.known_by_peers.insert(recipient_short_hash);
                    selected_fingerprints.push(fp.clone());
                    selected_depths.insert(fp.ds_tag.clone(), meta.depth);
                }
            }
        }

        Ok((selected_fingerprints, selected_depths))
    }

    /// Processes received fingerprints (active and implicit) and updates metadata.
    pub(super) fn process_received_fingerprints(
        &mut self,
        bundle_header: &TransactionBundleHeader,
        vouchers: &[Voucher],
        forwarded_fingerprints: &[TransactionFingerprint],
        fingerprint_depths: &HashMap<String, i8>,
    ) -> Result<(), VoucherCoreError> {
        // Use memory-efficient short hash
        let sender_short_hash = get_short_hash_from_user_id(&bundle_header.sender_id);

        // Phase 1: Active exchange (from the bundle)
        // Group fingerprints by ds_tag to perform symmetry check for VIPs.
        let mut ds_groups: HashMap<String, Vec<(&TransactionFingerprint, i8)>> = HashMap::new();
        for fp in forwarded_fingerprints {
            if let Some(&depth) = fingerprint_depths.get(&fp.ds_tag) {
                ds_groups.entry(fp.ds_tag.clone()).or_default().push((fp, depth));
            }
        }

        for (ds_tag, group) in ds_groups {
            if group.is_empty() { continue; }
            
            let mut received_depth = group[0].1;

            // --- Symmetry check for VIP fingerprints ---
            if received_depth < 0 {
                // A negative VIP fingerprint must always come as a partner pair (symmetry).
                // And both must have the exact same depth.
                let is_symmetric = group.len() >= 2 && group.iter().all(|(_, d)| *d == received_depth);
                
                if !is_symmetric {
                    // Asymmetric VIP spam: Normalize to positive penalty (e.g. 1)
                    received_depth = 1;
                }
            }

            // --- Loop protection & aging ---
            let meta = self.fingerprint_metadata.entry(ds_tag.clone()).or_default();
            
            // Loop protection: If the fingerprint is already locally known as VIP,
            // ignore further negative updates from gossip to prevent replay loops.
            // Local aging / initial discovery takes precedence.
            if meta.depth < 0 && received_depth < 0 {
                continue;
            } else if meta.depth > 0 && received_depth < 0 {
                // Transition from normal to VIP: Adopt VIP status.
                let new_depth = received_depth.saturating_sub(1);
                meta.depth = new_depth;
            } else {
                // Min-Merge / update for all other cases (normal to normal, new to VIP, etc.)
                let new_depth = if received_depth < 0 {
                    // VIP aging: saturating_sub(1) makes it more negative (-1 -> -2 -> ... -> -128)
                    received_depth.saturating_sub(1)
                } else {
                    // Normal aging
                    received_depth.saturating_add(1)
                };

                if meta.depth == 0 || new_depth < meta.depth {
                    meta.depth = new_depth;
                }
            }
            meta.known_by_peers.insert(sender_short_hash);

            // FIX: Persistently store gossip fingerprints in foreign_fingerprints.
            // Previously only metadata was updated; the TransactionFingerprint objects
            // themselves were never stored. Without this persistence, check_for_double_spend()
            // cannot detect collisions based solely on gossip data.
            for (fp, _depth) in &group {
                let entry = self
                    .known_fingerprints
                    .foreign_fingerprints
                    .entry(fp.ds_tag.clone())
                    .or_default();
                if !entry.iter().any(|existing| existing.t_id == fp.t_id) {
                    entry.push((*fp).clone());
                }
            }
        }

        // Phase 2: Implicit confirmation (from voucher chain)
        for voucher in vouchers {
            let tx_count = voucher.transactions.len();
            for (i, tx) in voucher.transactions.iter().enumerate() {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;

                let depth_in_chain = (tx_count - 1 - i) as i8;

                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.ds_tag.clone())
                    .or_default();
                meta.depth = depth_in_chain;
                meta.known_by_peers.insert(sender_short_hash);
            }
        }
        Ok(())
    }
}

/// Encapsulated offline conflict resolution via "Earliest Wins" heuristic.
pub(super) fn resolve_conflict_offline(
    voucher_store: &mut VoucherStore,
    fingerprints: &[crate::models::conflict::TransactionFingerprint],
) {
    let tx_ids: std::collections::HashSet<_> = fingerprints.iter().map(|fp| &fp.t_id).collect();

    // --- 1. Read phase: Find the winner without mutating the store ---
    let conflicting_txs: Vec<_> = voucher_store
        .vouchers
        .values()
        .flat_map(|inst| &inst.voucher.transactions)
        .filter(|tx| tx_ids.contains(&tx.t_id))
        .collect();

    if conflicting_txs.is_empty() {
        return;
    }

    // Since all conflicting transactions branch from the same fork point, they share the same prev_hash.
    let prev_hash = &conflicting_txs[0].prev_hash;
    let mut winner_id: Option<String> = None;
    let mut earliest_time = u128::MAX;

    for fp in fingerprints {
        // Construct a synthetic transaction to decrypt the timestamp
        let mut tx = crate::models::voucher::Transaction::default();
        tx.t_id = fp.t_id.clone();
        tx.prev_hash = prev_hash.clone();

        if let Ok(decrypted_nanos) =
            conflict_manager::decrypt_transaction_timestamp(&tx, fp.encrypted_timestamp)
        {
            if decrypted_nanos < earliest_time {
                earliest_time = decrypted_nanos;
                winner_id = Some(fp.t_id.clone());
            }
        }
    }

    // --- 2. Write phase: Update status based on winner ID ---
    if let Some(winner_id) = winner_id {
        for instance in voucher_store.vouchers.values_mut() {
            // Check if this instance contains one of the conflicting transactions.
            if let Some(tx) = instance
                .voucher
                .transactions
                .iter()
                .find(|tx| tx_ids.contains(&tx.t_id))
            {
                instance.status = if tx.t_id == winner_id {
                    VoucherStatus::Active
                } else {
                    VoucherStatus::Quarantined {
                        reason: "Lost offline race".to_string(),
                    }
                };
            }
        }
    }
}
