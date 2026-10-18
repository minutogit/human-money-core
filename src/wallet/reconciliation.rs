//! # src/wallet/reconciliation.rs
//!
//! Two-Tier Ingress Safety and Voucher Reconciliation logic for Layer 2.
//!
//! ## Two-Tier Ingress Safety Architecture:
//! - **Tier 1 (Macro-Check - WalletSeal / State Anchor):**
//!   On startup or sync, the wallet checks its State Anchor (`build_anchor_status_query`).
//!   If `AnchorSyncVerdict::Synchronized`, the entire wallet (all vouchers bound in
//!   `voucher_merkle_root`) is guaranteed to be consistent with Layer-2 in O(1).
//!   No per-voucher checks are needed.
//! - **Tier 2 (Micro-Check - Voucher-Level Reconciliation):**
//!   If Tier 1 detects a rollback (`AnchorSyncVerdict::RollbackDetected`, e.g. after
//!   restoring a backup), or when performing a targeted pre-payment check at checkout,
//!   individual voucher outputs are queried via `POST /v1/status`.
//!   - `UnspentSafe` (HTTP 404): No successor lock exists. The voucher output is unspent and safe to use.
//!   - `AlreadySpent` (HTTP 200): A child lock exists. The voucher was already spent.
//!     The wallet marks it as `VoucherStatus::Archived` and updates balances.

use crate::error::VoucherCoreError;
use crate::models::layer2_api::{
    L2AuthPayload, L2LockEntry, L2StatusQuery, VoucherReconciliationResult,
};
use crate::services::l2_gateway;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::Wallet;
use rand_core::{OsRng, RngCore};

impl Wallet {
    /// Builds an `L2StatusQuery` (read query) for the current status of an individual voucher.
    ///
    /// Locates the voucher instance in `self.voucher_store.vouchers` (matching either
    /// `local_instance_id` or `voucher.voucher_id`), extracts its `layer2_voucher_id`,
    /// derives the `challenge_ds_tag` from the latest transaction, generates locator prefixes
    /// for LCA resolution, and packs the query with a fresh ephemeral auth key.
    pub fn build_voucher_status_query(
        &self,
        voucher_id_or_local_id: &str,
        read_quorum: u8,
    ) -> Result<L2StatusQuery, VoucherCoreError> {
        let instance = self
            .voucher_store
            .vouchers
            .values()
            .find(|v| {
                v.local_instance_id == voucher_id_or_local_id
                    || v.voucher.voucher_id == voucher_id_or_local_id
            })
            .or_else(|| self.voucher_store.vouchers.get(voucher_id_or_local_id))
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id_or_local_id.to_string()))?;

        let layer2_voucher_id = l2_gateway::extract_layer2_voucher_id(&instance.voucher)?;

        let last_tx = instance
            .voucher
            .transactions
            .last()
            .ok_or_else(|| crate::Error::Wallet(crate::error::WalletError::MissingTransactions))?;

        let challenge_ds_tag = l2_gateway::derive_challenge_tag(last_tx)?;
        let locator_prefixes = l2_gateway::generate_locator_prefixes(&instance.voucher);

        let mut ephemeral_key = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_key);
        let auth = L2AuthPayload {
            ephemeral_pubkey: ephemeral_key,
            auth_signature: None,
        };

        Ok(L2StatusQuery {
            auth,
            layer2_voucher_id,
            challenge_ds_tag,
            locator_prefixes,
            read_quorum,
        })
    }

    /// Reconciles an individual voucher's status against the outcome of a Layer-2 status query.
    ///
    /// # Two-Tier Ingress Safety Architecture:
    /// In Tier 1, a `WalletSeal` (State Anchor) check verifies wallet-wide synchronization in O(1).
    /// When Tier 1 detects a rollback (e.g. after restoring an outdated backup), or when performing
    /// an explicit pre-spend safety check, Tier 2 executes targeted voucher status queries.
    ///
    /// - `successor_lock == None` (HTTP 404): No successor lock exists on Layer 2. The voucher
    ///   output is unspent and safe to use. Status remains [`VoucherStatus::Active`].
    /// - `successor_lock == Some(lock)` (HTTP 200): A successor lock exists on Layer 2. The voucher
    ///   output was already spent remotely. The wallet transitions the voucher to
    ///   [`VoucherStatus::Archived`], immediately removing it from available balances and future
    ///   spending pipelines.
    pub fn reconcile_voucher_state(
        &mut self,
        voucher_id_or_local_id: &str,
        successor_lock: Option<&L2LockEntry>,
    ) -> Result<VoucherReconciliationResult, VoucherCoreError> {
        let (local_id, _instance_status) = self
            .voucher_store
            .vouchers
            .iter()
            .find(|(k, v)| {
                *k == voucher_id_or_local_id || v.voucher.voucher_id == voucher_id_or_local_id
            })
            .map(|(k, v)| (k.clone(), v.status.clone()))
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id_or_local_id.to_string()))?;

        match successor_lock {
            None => {
                // Case A: 404 Not Found -> No successor lock exists.
                // The voucher remains VoucherStatus::Active (safe to spend).
                Ok(VoucherReconciliationResult::UnspentSafe)
            }
            Some(lock) => {
                // Case B: 200 OK -> Child lock exists. The voucher was already spent remotely.
                let successor_t_id = bs58::encode(lock.t_id).into_string();
                self.update_voucher_status(&local_id, VoucherStatus::Archived);
                Ok(VoucherReconciliationResult::AlreadySpent { successor_t_id })
            }
        }
    }
}
