//! # src/wallet/maintenance.rs
//!
//! Collects all methods for internal management, maintenance, cleanup,
//! and helper functions of the wallet.

use super::types::CleanupReport;
use crate::archive::VoucherArchive;
use crate::error::VoucherCoreError;
use crate::models::conflict::{
    CanonicalMetadataStore, FingerprintMetadata, KnownFingerprints, OwnFingerprints,
};
use crate::models::voucher::{Transaction, Voucher};
use crate::services::conflict_manager;
use crate::services::crypto_utils::get_hash;
use crate::wallet::Wallet;
use crate::wallet::instance::{VoucherInstance, VoucherStatus};
use chrono::{DateTime, Duration, Utc};

impl Wallet {
    /// Performs complete storage cleanup for fingerprints, metadata, and archive data.
    ///
    /// This function implements a multi-stage cleanup process:
    ///
    /// **Phase 1: Deletion of expired entries**
    /// First, all fingerprints from histories and their associated metadata whose
    /// `valid_until` date lies in the past are removed.
    ///
    /// **Phase 2: Selective, limit-based cleanup**
    /// If the total number of fingerprints exceeds a hard limit (`MAX_FINGERPRINTS`),
    /// a percentage-based reduction (`CLEANUP_PERCENTAGE`) is performed (based on depth and age).
    ///
    /// **Phase 3: Archive cleanup**
    /// Removes outdated voucher instances and double-spend proofs from the archive
    /// once they have exceeded a configurable grace period (`archive_grace_period_years`).
    ///
    /// # Arguments
    /// * `max_fingerprints_override` - Optional value to override the fingerprint limit (for tests).
    /// * `archive_grace_period_years` - Retention period for archive data in years.
    ///
    /// # Returns
    /// A `CleanupReport` summarizing the number of removed entries across all phases.
    pub fn run_storage_cleanup(
        &mut self,
        max_fingerprints_override: Option<usize>,
        archive_grace_period_years: i64,
    ) -> Result<CleanupReport, VoucherCoreError> {
        const MAX_FINGERPRINTS_CONST: usize = 20_000;
        const CLEANUP_PERCENTAGE: f32 = 0.10;

        let mut report = CleanupReport::default();
        let now = Utc::now();

        // --- Phase 1: Deletion of expired entries ---
        let mut expired_keys = std::collections::HashSet::new();

        // Collect all expired keys from all relevant stores
        for fp in self
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
        {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.deletable_at) {
                if valid_until.with_timezone(&Utc) < now {
                    expired_keys.insert(fp.ds_tag.clone());
                }
            }
        }

        if !expired_keys.is_empty() {
            report.expired_fingerprints_removed = expired_keys.len();

            // Remove expired entries from all stores
            self.own_fingerprints
                .history
                .retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints
                .local_history
                .retain(|k, _| !expired_keys.contains(k));
            self.known_fingerprints
                .foreign_fingerprints
                .retain(|k, _| !expired_keys.contains(k));
            self.fingerprint_metadata
                .retain(|k, _| !expired_keys.contains(k));
        }

        // --- Phase 2: Selective deletion by depth and recency ---
        let current_total_count = self.own_fingerprints.history.len()
            + self.known_fingerprints.local_history.len()
            + self.known_fingerprints.foreign_fingerprints.len();

        let max_fingerprints = max_fingerprints_override.unwrap_or(MAX_FINGERPRINTS_CONST);
        if current_total_count > max_fingerprints {
            let target_removal_count =
                (current_total_count as f32 * CLEANUP_PERCENTAGE).ceil() as usize;

            // Collect all fingerprints with metadata for sorting
            let mut candidates_for_removal = Vec::new();
            let all_fingerprints = self
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
                );

            for fp in all_fingerprints {
                if let Some(meta) = self.fingerprint_metadata.get(&fp.ds_tag) {
                    candidates_for_removal.push((meta.depth, fp.t_id.clone(), fp.ds_tag.clone()));
                }
            }

            // Sort: Highest 'depth' first, then oldest 't_id' first
            candidates_for_removal.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));

            let keys_to_remove: std::collections::HashSet<String> = candidates_for_removal
                .into_iter()
                .take(target_removal_count)
                .map(|(_, _, key)| key)
                .collect();

            report.limit_based_fingerprints_removed = keys_to_remove.len();

            // Remove selected entries from all stores
            self.own_fingerprints
                .history
                .retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints
                .local_history
                .retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints
                .foreign_fingerprints
                .retain(|k, _| !keys_to_remove.contains(k));
            self.fingerprint_metadata
                .retain(|k, _| !keys_to_remove.contains(k));
        }

        // --- Phase 3: Archive cleanup ---
        let grace_period = Duration::days(archive_grace_period_years * 365);
        let mut archived_removed = 0;

        // 1. Clean up volatile stores via ConflictManager (uses internal grace period)
        archived_removed += conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints);
        archived_removed += conflict_manager::cleanup_expired_histories(
            &mut self.own_fingerprints,
            &mut self.known_fingerprints,
            &now,
            &grace_period,
        );

        // 2. Clean up voucher instances in archive
        let before_vouchers = self.voucher_store.vouchers.len();
        self.voucher_store.vouchers.retain(|_, instance| {
            if !matches!(instance.status, VoucherStatus::Archived) {
                return true;
            }
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&instance.voucher.valid_until) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                return now < purge_date;
            }
            true
        });
        archived_removed += before_vouchers - self.voucher_store.vouchers.len();

        // 3. Clean up old double-spend proofs
        let before_proofs = self.proof_store.proofs.len();
        self.proof_store.proofs.retain(|_, entry| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&entry.proof.deletable_at) {
                let purge_date = valid_until.with_timezone(&Utc) + grace_period;
                return now < purge_date;
            }
            true
        });
        archived_removed += before_proofs - self.proof_store.proofs.len();
        
        report.archived_items_removed = archived_removed;

        Ok(report)
    }

    /// Rebuilds all derived stores (`fingerprints`, `metadata`) from the `VoucherStore`.
    ///
    /// This method serves as the core of the recovery logic. It ensures that the
    /// state of fingerprints and their metadata is always consistent with the "source of truth"
    /// (the vouchers stored in the wallet).
    ///
    /// # Process
    /// 1. Clears existing `own_fingerprints`, `known_fingerprints`, and `fingerprint_metadata` stores.
    /// 2. Iterates over every voucher and every transaction in `voucher_store`.
    /// 3. Generates a fingerprint for each transaction.
    /// 4. Categorizes the fingerprint as "own" or "known" and stores it.
    /// 5. Reinitializes metadata (`depth`, `known_by_peers`) for each fingerprint.
    pub fn rebuild_derived_stores(&mut self) -> Result<(), VoucherCoreError> {
        // Step 1: Clear existing derived stores
        self.own_fingerprints = OwnFingerprints::default();
        self.known_fingerprints = KnownFingerprints::default();
        self.fingerprint_metadata = CanonicalMetadataStore::default();

        // Step 2: Iterate over ALL instances so no fingerprints are lost.
        // The correct depth is determined by the "min(depth) wins" rule.
        for instance in self.voucher_store.vouchers.values() {
            // SECURITY (AUDIT-W4-WC-002): mirror the Endorsed-exclusion of
            // [`conflict_manager::scan_and_rebuild_fingerprints`]. Endorsed
            // witness copies do not belong to the user and must not contribute
            // to double-spend detection — at receive-time AND at load-time.
            // A diverging filter here let remote signing-request vouchers
            // poison `own_fingerprints` (and gossip) on every login. This also
            // guarantees (AUDIT-W4-WC-001) that a malformed Endorsed copy can
            // never fail the whole load/login via fingerprint parsing.
            if matches!(
                instance.status,
                crate::wallet::instance::VoucherStatus::Endorsed { .. }
            ) {
                continue;
            }
            let tx_count = instance.voucher.transactions.len();
            for (i, tx) in instance.voucher.transactions.iter().enumerate() {
                // Step 3 & 4: Generate and categorize fingerprint
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, &instance.voucher)?;

                // SECURITY (WH3-00-903): use the canonical is_sender
                // definition (see
                // [`conflict_manager::is_own_transaction`]) so the load-time
                // rebuild classifies anonymous stealth/flexible spends as own
                // exactly like the receive-time scan does. A diverging filter
                // here would wipe the stealth history at every login.
                if conflict_manager::is_own_transaction(tx, &self.profile.user_id) {
                    let entry = self
                        .own_fingerprints
                        .history
                        .entry(fingerprint.ds_tag.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                } else {
                    let entry = self
                        .known_fingerprints
                        .local_history
                        .entry(fingerprint.ds_tag.clone())
                        .or_default();
                    if !entry.contains(&fingerprint) {
                        entry.push(fingerprint.clone());
                    }
                }

                // Step 5: Initialize metadata or update with "min wins" rule
                let depth_in_chain = (tx_count - 1 - i) as i8;
                let meta = self
                    .fingerprint_metadata
                    .entry(fingerprint.ds_tag)
                    .or_insert_with(FingerprintMetadata::default);

                // Apply "lowest depth wins" rule. A smaller value means
                // a shorter, more relevant path in the network. The value 0 is the
                // initial default and is always overwritten.
                // NOTE: VIP fingerprints (negative) always win over positive ones.
                if meta.depth == 0 || depth_in_chain < meta.depth {
                    meta.depth = depth_in_chain;
                }
                meta.known_by_peers = std::collections::HashSet::new(); // Reset `known_by_peers`
            }
        }
        Ok(())
    }

    pub fn add_voucher_instance(
        &mut self,
        local_id: String,
        voucher: Voucher,
        status: VoucherStatus,
    ) {
        let instance = VoucherInstance {
            voucher,
            status,
            local_instance_id: local_id.clone(),
        };
        self.voucher_store.vouchers.insert(local_id, instance);
    }

    pub fn get_voucher_instance(&self, local_instance_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store.vouchers.get(local_instance_id)
    }

    pub fn update_voucher_status(&mut self, local_instance_id: &str, new_status: VoucherStatus) {
        let event_info = if let Some(instance) = self.voucher_store.vouchers.get_mut(local_instance_id) {
            let old_status = std::mem::replace(&mut instance.status, new_status.clone());

            // Event logging on important status changes
            let event_type = match (&old_status, &new_status) {
                // From Incomplete to Active
                (VoucherStatus::Incomplete { .. }, VoucherStatus::Active) => {
                    Some(crate::models::wallet_event::WalletEventType::VoucherActivated)
                }
                // Freshly quarantined (unless already quarantined before)
                (_, VoucherStatus::Quarantined { .. })
                    if !matches!(old_status, VoucherStatus::Quarantined { .. }) =>
                {
                    Some(crate::models::wallet_event::WalletEventType::VoucherQuarantined)
                }
                _ => None,
            };

            if let Some(et) = event_type {
                let voucher = &instance.voucher;
                let bff_data = crate::models::wallet_event::EventBffData {
                    display_currency: crate::wallet::format_bff_name(
                        voucher.nominal_value.abbreviation.as_deref().unwrap_or(&voucher.nominal_value.unit),
                        voucher.non_redeemable_test_voucher,
                    ),
                    amount: voucher.nominal_value.amount.clone(),
                    is_test_voucher: voucher.non_redeemable_test_voucher,
                    counterparty_id: None,
                    counterparty_name: None,
                };
                Some((et, voucher.voucher_id.clone(), bff_data))
            } else {
                None
            }
        } else {
            None
        };

        if let Some((et, voucher_id, bff_data)) = event_info {
            self.emit_event(
                et,
                local_instance_id,
                &voucher_id,
                bff_data,
            );
        }
    }

    /// Computes a deterministic, local ID for a voucher instance.
    pub fn calculate_local_instance_id(
        voucher: &Voucher,
        profile_owner_id: &str,
    ) -> Result<String, VoucherCoreError> {
        let mut defining_transaction_id: Option<String> = None;

        // The defining transaction is simply the last one in which the user
        // appears as sender or recipient.
        // NOTE: In Privacy Mode, recipient_id="anonymous". We accept this
        // as a match for the current profile owner (profile_owner_id), since
        // actual receipt authorization was already verified during bundle decryption.
        for tx in voucher.transactions.iter().rev() {
            if tx.recipient_id == profile_owner_id
                || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID
                || tx.sender_id.as_deref() == Some(profile_owner_id)
            {
                defining_transaction_id = Some(tx.t_id.clone());
                break;
            }
        }

        if let Some(t_id) = defining_transaction_id {
            Ok(get_hash(format!(
                "{}{}{}",
                voucher.voucher_id, t_id, profile_owner_id
            )))
        } else {
            Err(VoucherCoreError::VoucherOwnershipNotFound(format!(
                "User '{}' has no ownership history for voucher '{}'",
                profile_owner_id, voucher.voucher_id
            )))
        }
    }

    /// Searches for a transaction by its ID (`t_id`), first in the active
    /// `voucher_store` and then in the `VoucherArchive`.
    pub(super) fn find_transaction_in_stores(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Transaction>, VoucherCoreError> {
        // Search active store first
        for instance in self.voucher_store.vouchers.values() {
            if let Some(tx) = instance
                .voucher
                .transactions
                .iter()
                .find(|t| t.t_id == t_id)
            {
                return Ok(Some(tx.clone()));
            }
        }

        // Then search archive
        let result = archive.find_transaction_by_id(t_id)?;
        Ok(result.map(|(_, tx)| tx))
    }

    /// Searches for a voucher by a contained transaction ID (`t_id`).
    /// Searches first the active `voucher_store` and then the `VoucherArchive`.
    pub(super) fn find_voucher_for_transaction(
        &self,
        t_id: &str,
        archive: &dyn VoucherArchive,
    ) -> Result<Option<Voucher>, VoucherCoreError> {
        // Search active store first
        for instance in self.voucher_store.vouchers.values() {
            if instance.voucher.transactions.iter().any(|t| t.t_id == t_id) {
                return Ok(Some(instance.voucher.clone()));
            }
        }

        // Then search archive
        Ok(archive.find_voucher_by_tx_id(t_id)?)
    }

    /// Finds the local ID and status of a voucher by a contained transaction ID.
    pub(super) fn find_local_voucher_by_tx_id(&self, tx_id: &str) -> Option<&VoucherInstance> {
        self.voucher_store.vouchers.values().find(|instance| {
            instance
                .voucher
                .transactions
                .iter()
                .any(|tx| tx.t_id == tx_id)
        })
    }
}

