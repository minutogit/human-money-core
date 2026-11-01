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
    L2AuthPayload, L2LockEntry, L2StatusQuery, L2Verdict, VoucherReconciliationResult,
};
use crate::models::profile::UserIdentity;
use crate::services::l2_gateway;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::Wallet;
use rand_core::{OsRng, RngCore};

impl Wallet {
    /// Builds an `L2StatusQuery` (read query) for the current status of an individual voucher.
    ///
    /// Locates the voucher instance in `self.voucher_store.vouchers` (matching either
    /// `local_instance_id` or `voucher.voucher_id`), extracts its `layer2_voucher_id`,
    /// derives the next outgoing spend `ds_tag` from the latest transaction and current holder identity,
    /// generates locator prefixes for LCA resolution, and packs the query with a fresh ephemeral auth key.
    pub fn build_voucher_status_query(
        &self,
        identity: &UserIdentity,
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

        let prev_hash = crate::services::crypto::get_hash(
            crate::services::utils::to_canonical_json(last_tx)?,
        );
        let holder_ephem = self.rederive_secret_seed(&instance.voucher, identity)?;
        let holder_pub_bs58 =
            bs58::encode(holder_ephem.verifying_key().to_bytes()).into_string();
        let challenge_ds_tag = crate::services::crypto::get_ds_tag(&prev_hash, &holder_pub_bs58)?;
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
    ///   output was already spent remotely. Cryptographically verifies the successor proof against
    ///   the expected outgoing spend `ds_tag` and holder public key before transitioning the voucher to
    ///   [`VoucherStatus::Archived`], immediately removing it from available balances and future
    ///   spending pipelines (preserving [`VoucherStatus::Quarantined`] if already quarantined).
    pub fn reconcile_voucher_state(
        &mut self,
        identity: &UserIdentity,
        voucher_id_or_local_id: &str,
        successor_lock: Option<&L2LockEntry>,
    ) -> Result<VoucherReconciliationResult, VoucherCoreError> {
        let (local_id, instance) = self
            .voucher_store
            .vouchers
            .iter()
            .find(|(k, v)| {
                *k == voucher_id_or_local_id || v.voucher.voucher_id == voucher_id_or_local_id
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id_or_local_id.to_string()))?;

        match successor_lock {
            None => {
                // Case A: 404 Not Found -> No successor lock exists.
                // The voucher remains VoucherStatus::Active (safe to spend).
                Ok(VoucherReconciliationResult::UnspentSafe)
            }
            Some(lock) => {
                // Case B: 200 OK -> Child lock exists. The voucher was already spent remotely.
                let last_tx = instance
                    .voucher
                    .transactions
                    .last()
                    .ok_or_else(|| crate::Error::Wallet(crate::error::WalletError::MissingTransactions))?;

                let lock_t_id_str = bs58::encode(lock.t_id).into_string();
                if lock_t_id_str == last_tx.t_id {
                    return Err(VoucherCoreError::Validation(
                        crate::error::ValidationError::SecurityViolation(
                            "successor lock cannot match current transaction id".into(),
                        ),
                    ));
                }

                let expected_l2_voucher_id =
                    l2_gateway::extract_layer2_voucher_id(&instance.voucher)?;
                let prev_hash = crate::services::crypto::get_hash(
                    crate::services::utils::to_canonical_json(last_tx)?,
                );
                let holder_ephem = self.rederive_secret_seed(&instance.voucher, identity)?;
                let expected_holder_pub =
                    bs58::encode(holder_ephem.verifying_key().to_bytes()).into_string();
                let expected_outgoing_ds_tag =
                    crate::services::crypto::get_ds_tag(&prev_hash, &expected_holder_pub)?;

                l2_gateway::verify_lock_entry_proof(
                    lock,
                    &expected_l2_voucher_id,
                    Some(&expected_holder_pub),
                    &expected_outgoing_ds_tag,
                )?;

                if !matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    self.update_voucher_status(&local_id, VoucherStatus::Archived);
                }
                Ok(VoucherReconciliationResult::AlreadySpent {
                    successor_t_id: lock_t_id_str,
                })
            }
        }
    }

    /// Reconciles an individual voucher's status when Layer 2 returns `MissingLocks`.
    ///
    /// If `anchor_lock` is attached, verifies its cryptographic proof against the historical
    /// transaction matching `sync_point`. If the anchor lock's transaction ID diverges from
    /// our local history at that hop, an upstream double-spend is detected: the voucher is
    /// immediately quarantined and `VoucherReconciliationResult::ConflictDetected` is returned.
    /// If the anchor lock matches or `anchor_lock` is `None`, returns `VoucherReconciliationResult::UnspentSafe`.
    pub fn reconcile_voucher_missing_locks(
        &mut self,
        _identity: &UserIdentity,
        voucher_id_or_local_id: &str,
        sync_point: &str,
        anchor_lock: Option<&L2LockEntry>,
    ) -> Result<VoucherReconciliationResult, VoucherCoreError> {
        let (local_id, instance) = self
            .voucher_store
            .vouchers
            .iter()
            .find(|(k, v)| {
                *k == voucher_id_or_local_id || v.voucher.voucher_id == voucher_id_or_local_id
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .ok_or_else(|| VoucherCoreError::VoucherNotFound(voucher_id_or_local_id.to_string()))?;

        let Some(entry) = anchor_lock else {
            return Ok(VoucherReconciliationResult::UnspentSafe);
        };

        let expected_l2_voucher_id = l2_gateway::extract_layer2_voucher_id(&instance.voucher)?;

        let hop_tx = if sync_point == "genesis" {
            instance.voucher.transactions.first()
        } else {
            instance.voucher.transactions.iter().find(|tx| {
                tx.t_id == sync_point
                    || tx.trap_data.as_ref().is_some_and(|td| td.ds_tag == sync_point)
                    || tx.t_id.starts_with(sync_point)
                    || tx.trap_data.as_ref().is_some_and(|td| td.ds_tag.starts_with(sync_point))
            })
        }
        .ok_or_else(|| {
            VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(
                format!("sync_point '{}' not found in voucher history", sync_point),
            ))
        })?;

        let challenge_ds_tag = l2_gateway::derive_challenge_tag(hop_tx)?;

        l2_gateway::verify_lock_entry_proof(
            entry,
            &expected_l2_voucher_id,
            hop_tx.sender_ephemeral_pub.as_deref(),
            &challenge_ds_tag,
        )?;

        let local_hop_t_id =
            crate::services::crypto::decode_bs58_fixed::<32>(&hop_tx.t_id, "hop_tx.t_id")?;

        if entry.t_id != local_hop_t_id {
            self.update_voucher_status(
                &local_id,
                VoucherStatus::Quarantined {
                    reason: format!(
                        "Upstream double-spend detected via L2 anchor_lock at sync_point {}",
                        sync_point
                    ),
                },
            );
            Ok(VoucherReconciliationResult::ConflictDetected {
                conflicting_lock: entry.clone(),
            })
        } else {
            Ok(VoucherReconciliationResult::UnspentSafe)
        }
    }

    /// Reconciles an individual voucher's status directly against any `L2Verdict`.
    ///
    /// Dispatches to `reconcile_voucher_missing_locks` for `MissingLocks`,
    /// or `reconcile_voucher_state` for `Verified`, `Conflict`, and `UnknownVoucher`.
    pub fn reconcile_voucher_verdict(
        &mut self,
        identity: &UserIdentity,
        voucher_id_or_local_id: &str,
        verdict: &L2Verdict,
    ) -> Result<VoucherReconciliationResult, VoucherCoreError> {
        match verdict {
            L2Verdict::MissingLocks {
                sync_point,
                anchor_lock,
            } => self.reconcile_voucher_missing_locks(
                identity,
                voucher_id_or_local_id,
                sync_point,
                anchor_lock.as_ref(),
            ),
            L2Verdict::Verified { lock_entry } => {
                self.reconcile_voucher_state(identity, voucher_id_or_local_id, Some(lock_entry))
            }
            L2Verdict::Conflict { existing_lock } => {
                self.reconcile_voucher_state(identity, voucher_id_or_local_id, Some(existing_lock))
            }
            L2Verdict::UnknownVoucher => {
                self.reconcile_voucher_state(identity, voucher_id_or_local_id, None)
            }
            L2Verdict::Confirmed { .. } | L2Verdict::Ok { .. } => {
                self.reconcile_voucher_state(identity, voucher_id_or_local_id, None)
            }
            L2Verdict::Rejected { reason } => {
                Err(VoucherCoreError::Validation(crate::error::ValidationError::SecurityViolation(
                    format!("Layer 2 verdict rejected: {}", reason),
                )))
            }
        }
    }
}
