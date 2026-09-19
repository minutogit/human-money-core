//! # src/wallet/conflicts/maintenance.rs
//!
//! Storage maintenance, cleanup and helper utilities for fingerprint management.

use super::super::types::CleanupReport;
use super::super::Wallet;
use crate::error::VoucherCoreError;
use crate::models::conflict::{KnownFingerprints, OwnFingerprints, TransactionFingerprint};
use crate::services::conflict_manager;
use crate::wallet::instance::VoucherStatus;
use chrono::{DateTime, Duration, Utc};

impl Wallet {
    /// Removes all expired fingerprints from storage.
    /// Returns the number of removed entries.
    pub fn cleanup_expired_fingerprints(&mut self) -> usize {
        conflict_manager::cleanup_known_fingerprints(&mut self.known_fingerprints)
    }

    /// Performs complete storage cleanup for fingerprints and archive data.
    ///
    /// This function implements a multi-stage cleanup process:
    ///
    /// **Phase 1: Deletion of expired entries**
    /// First, all fingerprints from histories whose `valid_until` date lies in the past are removed.
    ///
    /// **Phase 2: Selective, limit-based cleanup**
    /// If the total number of fingerprints exceeds a hard limit (`MAX_FINGERPRINTS`),
    /// a percentage-based reduction (`CLEANUP_PERCENTAGE`) is performed.
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
        const MAX_FINGERPRINTS_CONST: usize = 50_000;
        const CLEANUP_PERCENTAGE: f32 = 0.10;

        let mut report = CleanupReport::default();
        let now = Utc::now();

        // --- Phase 1: Deletion of expired entries ---
        let mut expired_keys = std::collections::HashSet::new();

        // Collect all expired keys from all relevant stores (3-way helper)
        for fp in self.all_fingerprints() {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.deletable_at)
                && valid_until.with_timezone(&Utc) < now
            {
                expired_keys.insert(fp.ds_tag.clone());
            }
        }

        if !expired_keys.is_empty() {
            report.expired_fingerprints_removed = expired_keys.len();

            // Remove expired entries from all stores (3-way helper)
            self.retain_fingerprints(|k| !expired_keys.contains(k));
            self.active_gossip
                .direct_queue
                .retain(|d| !expired_keys.contains(&d.fingerprint.ds_tag));
            self.active_gossip
                .fresh_gossip_pool
                .retain(|fp| !expired_keys.contains(&fp.ds_tag));
            self.active_gossip
                .quarantine_direct_queue
                .retain(|q| !expired_keys.contains(&q.pair[0].ds_tag));
            self.active_gossip
                .quarantine_relay_pool
                .retain(|pair| !expired_keys.contains(&pair[0].ds_tag));
        }

        // --- Phase 2: Selective deletion by recency ---
        // ARCHITECTURE (KISS-Immune): Only volatile foreign and local history caches participate
        // in opportunistic capacity trimming. `own_fingerprints.history` is the user's authoritative
        // ledger to prevent accidental double-spends and must never be trimmed opportunistically.
        let current_total_count = self.known_fingerprints.local_history.len()
            + self.known_fingerprints.foreign_fingerprints.len();

        let max_fingerprints = max_fingerprints_override.unwrap_or(MAX_FINGERPRINTS_CONST);
        if current_total_count > max_fingerprints {
            let target_removal_count =
                (current_total_count as f32 * CLEANUP_PERCENTAGE).ceil() as usize;

            let mut candidates: Vec<(String, String, String)> = Vec::new();
            for (tag, fps) in &self.known_fingerprints.foreign_fingerprints {
                for fp in fps {
                    candidates.push((fp.t_id.clone(), tag.clone(), fp.deletable_at.clone()));
                }
            }
            for (tag, fps) in &self.known_fingerprints.local_history {
                for fp in fps {
                    candidates.push((fp.t_id.clone(), tag.clone(), fp.deletable_at.clone()));
                }
            }
            // Sort chronologically: oldest deletable_at first, t_id tie-breaker for determinism
            candidates.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));

            let keys_to_remove: std::collections::HashSet<String> = candidates
                .into_iter()
                .take(target_removal_count)
                .map(|(_, tag, _)| tag)
                .collect();

            report.limit_based_fingerprints_removed = keys_to_remove.len();

            // Remove selected entries only from foreign and local history caches
            self.known_fingerprints
                .local_history
                .retain(|k, _| !keys_to_remove.contains(k));
            self.known_fingerprints
                .foreign_fingerprints
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

    /// Rebuilds derived stores from the `VoucherStore`.
    ///
    /// Ensures that the state of own and known local fingerprints is consistent
    /// with the stored vouchers.
    pub fn rebuild_derived_stores(&mut self) -> Result<(), VoucherCoreError> {
        let preserved_foreign_fingerprints = std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);

        self.own_fingerprints = OwnFingerprints::default();
        self.known_fingerprints = KnownFingerprints::default();

        for instance in self.voucher_store.vouchers.values() {
            if matches!(
                instance.status,
                crate::wallet::instance::VoucherStatus::Endorsed { .. }
            ) {
                continue;
            }
            for tx in &instance.voucher.transactions {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, &instance.voucher)?;

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
            }
        }

        self.known_fingerprints.foreign_fingerprints = preserved_foreign_fingerprints;
        Ok(())
    }
}

impl Wallet {
    /// Iterator over *all* fingerprints from the three canonical stores
    /// (`own.history`, `known.local_history`, `known.foreign_fingerprints`).
    pub(crate) fn all_fingerprints(&self) -> impl Iterator<Item = &TransactionFingerprint> + '_ {
        self.own_fingerprints
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
    }

    /// Iterator over fingerprints for a single `ds_tag` across the three stores.
    pub(crate) fn fingerprints_for_tag(
        &self,
        ds_tag: &str,
    ) -> impl Iterator<Item = &TransactionFingerprint> + '_ {
        self.own_fingerprints
            .history
            .get(ds_tag)
            .into_iter()
            .flatten()
            .chain(
                self.known_fingerprints
                    .local_history
                    .get(ds_tag)
                    .into_iter()
                    .flatten(),
            )
            .chain(
                self.known_fingerprints
                    .foreign_fingerprints
                    .get(ds_tag)
                    .into_iter()
                    .flatten(),
            )
    }

    /// Retains only entries whose key satisfies `keep` in all three
    /// fingerprint-related maps (`own.history`, `known.local_history`, `known.foreign_fingerprints`).
    pub(crate) fn retain_fingerprints<F>(&mut self, mut keep: F)
    where
        F: FnMut(&String) -> bool,
    {
        self.own_fingerprints.history.retain(|k, _| keep(k));
        self.known_fingerprints
            .local_history
            .retain(|k, _| keep(k));
        self.known_fingerprints
            .foreign_fingerprints
            .retain(|k, _| keep(k));
    }
}

