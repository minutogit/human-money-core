//! # src/wallet/conflicts/proofs.rs
//!
//! Proof handling for double-spend conflicts:
//! listing, retrieval, endorsement creation and validation.

use super::super::Wallet;
use crate::error::VoucherCoreError;
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::models::profile::UserIdentity;
use crate::services::conflict_manager;
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::wallet::format_bff_name;


impl Wallet {
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
                    is_resolved: proof.resolutions.as_ref().is_some_and(|v| !v.is_empty()),
                    has_l2_verdict: proof.layer2_verdict.is_some(),
                    local_override: entry.local_override,
                    local_note: entry.local_note.clone(),
                    conflict_role: entry.conflict_role,
                    affected_voucher_name: proof.affected_voucher_name.clone(),
                    display_affected_voucher_name: proof.affected_voucher_name.as_ref().map(|n| {
                        format_bff_name(n, proof.non_redeemable_test_voucher)
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

            // Match 4: Fork-point & DS-Tag linkage (restricted - not blind offender match)
// Only match if the proof's fork point prev_hash is in the voucher's
// transaction prev_hashes, OR the ds_tag matches between proof and voucher.
            let fork_point_match = voucher_txs.iter().any(|vtx| {
                vtx.prev_hash == proof.fork_point_prev_hash
            });
            let ds_tag_match = voucher_txs.iter().any(|vtx| {
                vtx.trap_data.as_ref().map(|td| {
                    let proof_ds_tags: Vec<&str> = proof.conflicting_transactions.iter()
                        .filter_map(|tx| tx.trap_data.as_ref().map(|td| td.ds_tag.as_str()))
                        .collect();
                    proof_ds_tags.contains(&td.ds_tag.as_str())
                }).unwrap_or(false)
            });
            let has_fork_point_or_ds_tag_match = fork_point_match || ds_tag_match;
            if has_fork_point_or_ds_tag_match {
                log::info!("  ✅ Match 4 (fork-point/ds_tag) found!");
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
    ///
    /// # Security (HMSEC-SA06-12)
    /// The endorsement's `victim_signature` MUST verify over `endorsement_id`
    /// with the permanent identity key referenced by `victim_id` before the
    /// endorsement is accepted. Without this gate anyone holding a proof ID
    /// could attach a self-signed endorsement while CLAIMING a real victim
    /// identity, flipping `check_reputation` from `KnownOffender` to
    /// `Resolved` (network-wide reputation laundering through unverified
    /// signatures).
    ///
    /// # Security (HMSEC-SA04: endorsement replay / cross-proof attachment)
    /// The `endorsement_id` MUST equal the canonical content hash of the
    /// endorsement's own fields (`proof_id`, `victim_id`,
    /// `resolution_timestamp`, `notes`). Without this integrity gate a
    /// validly signed endorsement minted for one conflict could be replayed
    /// verbatim onto a DIFFERENT proof (cross-proof attachment), since the
    /// signature only binds `endorsement_id` itself and never re-derives it.
    pub fn add_resolution_endorsement(
        &mut self,
        endorsement: ResolutionEndorsement,
    ) -> Result<(), VoucherCoreError> {
        // --- Content-hash gate: endorsement_id MUST be the canonical hash of the
        // endorsement's own content fields (proof_id, victim_id,
        // resolution_timestamp, notes). Without this gate a validly signed
        // endorsement minted for one conflict can be replayed verbatim onto a
        // different proof (cross-proof attachment), since the signature only binds
        // endorsement_id itself.
        let expected_endorsement_id = crate::services::crypto::get_hash(
            crate::services::utils::to_canonical_json(&serde_json::json!({
                "proof_id": endorsement.proof_id,
                "victim_id": endorsement.victim_id,
                "resolution_timestamp": endorsement.resolution_timestamp,
                "notes": endorsement.notes,
            }))?,
        );
        if endorsement.endorsement_id != expected_endorsement_id {
            return Err(VoucherCoreError::Generic(
                "Cannot add endorsement: endorsement_id does not match canonical hash of endorsement fields".to_string(),
            ));
        }

        // --- Signature gate: victim_signature over endorsement_id ---
        let victim_pk = crate::services::crypto::get_pubkey_from_user_id(
            &endorsement.victim_id,
        )
        .map_err(|_| {
            VoucherCoreError::Generic(format!(
                "Cannot add endorsement: victim_id '{}' is not a resolvable DID identity.",
                endorsement.victim_id
            ))
        })?;
        let sig_bytes = bs58::decode(&endorsement.victim_signature)
            .into_vec()
            .map_err(|e| {
                VoucherCoreError::Generic(format!(
                    "Cannot add endorsement: invalid victim_signature encoding: {}",
                    e
                ))
            })?;
        let signature = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().map_err(|_| {
                VoucherCoreError::Generic(
                    "Cannot add endorsement: invalid victim_signature length.".to_string(),
                )
            })?,
        );
        if !crate::services::crypto::verify_ed25519(
            &victim_pk,
            endorsement.endorsement_id.as_bytes(),
            &signature,
        ) {
            return Err(VoucherCoreError::Generic(
                "Cannot add endorsement: victim_signature does not verify over \
                 endorsement_id for the claimed victim identity."
                    .to_string(),
            ));
        }

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

}
