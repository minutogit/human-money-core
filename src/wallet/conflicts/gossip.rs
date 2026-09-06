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
use std::collections::HashMap;

impl Wallet {
    /// Serializes own fingerprints for export.
    pub fn export_own_fingerprints(&self) -> Result<Vec<u8>, VoucherCoreError> {
        conflict_manager::export_own_fingerprints(&self.own_fingerprints)
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

        // Step 2: Collect all known fingerprints (3-way helper + V2 export filter)
        // V2 Protocol (Gossip Export Filter): genesis ('init') fingerprints
        // carry no trap components and no detection value — they are excluded
        // from gossip export.
        let mut all_known_fingerprints: Vec<TransactionFingerprint> = self
            .all_fingerprints()
            .filter(|fp| !conflict_manager::is_init_fingerprint(fp))
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
                    let mut fp_out = fp.clone();
                    // SECURITY (HMSEC-SA06-15): egress neutralization — the
                    // gossip wire format must not carry the voucher-derived
                    // retention deadline (family linkability). Receivers
                    // assign their own uniform local retention at ingress.
                    fp_out.deletable_at =
                        conflict_manager::NEUTRAL_WIRE_DEADLINE.to_string();
                    selected_fingerprints.push(fp_out);
                    selected_depths.insert(fp.ds_tag.clone(), meta.depth);
                }
            }
        }

        Ok((selected_fingerprints, selected_depths))
    }
}
