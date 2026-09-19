//! # src/wallet/conflicts/gossip.rs
//!
//! Gossip-related Wallet methods for fingerprint exchange.
//! Contains export and selection logic for forwarding fingerprints in bundles.

use super::super::Wallet;
use crate::error::VoucherCoreError;
use crate::models::conflict::TransactionFingerprint;
use crate::models::voucher::Voucher;
use crate::services::conflict_manager;
use crate::services::crypto::get_short_hash_from_user_id;
use rand::Rng;
use std::collections::{HashSet, VecDeque};

impl Wallet {
    /// Serializes own fingerprints for export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.own_fingerprints)
    }

    /// Selects fingerprints and quarantine pairs for forwarding in a bundle,
    /// according to the proportional 30/70 KISS-Gossip protocol.
    ///
    /// # Proportional Budget
    /// - Standard fingerprints budget $M = V \times 10$ (30% direct tips + 70% fresh gossip pool).
    /// - Emergency quarantine pairs budget = Max $V \times 3$ pairs on-top.
    ///
    /// # Returns
    /// A tuple of (`Vec<TransactionFingerprint>`, `Vec<[TransactionFingerprint; 2]>`) for the bundle.
    pub fn select_fingerprints_for_bundle(
        &mut self,
        recipient_id: &str,
        vouchers_in_bundle: &[Voucher],
    ) -> Result<(Vec<TransactionFingerprint>, Vec<[TransactionFingerprint; 2]>), VoucherCoreError> {
        let v_count = vouchers_in_bundle.len();
        let v_eff = if v_count == 0 { 1 } else { v_count };

        let m_standard = v_eff * 10;
        let m_direct = v_eff * 3;
        let m_quarantine = v_eff * 3;

        let recipient_short_hash = get_short_hash_from_user_id(recipient_id);

        // Collect all ds_tags of vouchers in the current bundle
        let mut bundle_ds_tags = HashSet::new();
        for voucher in vouchers_in_bundle {
            for tx in &voucher.transactions {
                let fingerprint =
                    conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;
                bundle_ds_tags.insert(fingerprint.ds_tag);
            }
        }

        // --- Step 1: DirectQueue (Direct tips, up to 30% / m_direct) ---
        let mut selected_direct = Vec::new();
        for entry in self.active_gossip.direct_queue.iter_mut() {
            if selected_direct.len() >= m_direct {
                break;
            }
            if bundle_ds_tags.contains(&entry.fingerprint.ds_tag) {
                continue;
            }
            if entry.sent_to.contains(&recipient_short_hash) {
                continue;
            }
            let mut fp = entry.fingerprint.clone();
            fp.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
            selected_direct.push(fp);
            entry.sent_to.push(recipient_short_hash);
        }
        self.active_gossip
            .direct_queue
            .retain(|entry| entry.sent_to.len() < 3);

        // --- Step 2: Fresh Gossip Pool (FIFO drain lottery with preservation) ---
        let target_gossip_slots = m_standard.saturating_sub(selected_direct.len());
        let mut selected_gossip = Vec::new();
        let mut remaining_pool = VecDeque::new();
        let mut rng = rand::thread_rng();

        while let Some(fp) = self.active_gossip.fresh_gossip_pool.pop_front() {
            if bundle_ds_tags.contains(&fp.ds_tag) {
                // Preservation: do not roll coin, preserve chance for later transfers!
                remaining_pool.push_back(fp);
                continue;
            }

            if selected_gossip.len() >= target_gossip_slots {
                // Budget full: stays untouched in pool
                remaining_pool.push_back(fp);
                continue;
            }

            if rng.gen_bool(0.70) {
                let mut fp_out = fp;
                fp_out.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                selected_gossip.push(fp_out);
            }
        }
        self.active_gossip.fresh_gossip_pool = remaining_pool;

        let mut all_standard_fingerprints = selected_direct;
        all_standard_fingerprints.extend(selected_gossip);

        // --- Step 3: Quarantine Pairs on-top (Max m_quarantine) ---
        let mut selected_quarantine = Vec::new();

        // 3a. Origin direct queue (3x guaranteed delivery to distinct peers)
        for q_entry in self.active_gossip.quarantine_direct_queue.iter_mut() {
            if selected_quarantine.len() >= m_quarantine {
                break;
            }
            if !q_entry.sent_to.contains(&recipient_short_hash) {
                let mut p0 = q_entry.pair[0].clone();
                let mut p1 = q_entry.pair[1].clone();
                p0.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                p1.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                selected_quarantine.push([p0, p1]);
                q_entry.sent_to.push(recipient_short_hash);
            }
        }
        self.active_gossip
            .quarantine_direct_queue
            .retain(|q| q.sent_to.len() < 3);

        // 3b. Relay pool (70% one-shot lottery)
        let mut remaining_relay = VecDeque::new();
        while let Some(pair) = self.active_gossip.quarantine_relay_pool.pop_front() {
            if selected_quarantine.len() >= m_quarantine {
                remaining_relay.push_back(pair);
                continue;
            }
            if rng.gen_bool(0.70) {
                let mut p0 = pair[0].clone();
                let mut p1 = pair[1].clone();
                p0.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                p1.deletable_at = conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                selected_quarantine.push([p0, p1]);
            }
        }
        self.active_gossip.quarantine_relay_pool = remaining_relay;

        Ok((all_standard_fingerprints, selected_quarantine))
    }
}
