//! # src/app_service/conflicts.rs
//!
//! Contains all `AppService` functions related to double-spend conflicts,
//! proof management, resolution endorsements, VIP-gossip and the L2 facade.
//! Consolidates the former `conflict_handler.rs` and `l2_facade.rs`.

use super::{AppService, AppState, TransactionOutcome};
use crate::app_service::orchestrator::{ReloadPolicy, TransactionOrchestrator};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::models::layer2_api::{L2LockEntry, VoucherReconciliationResult};
use crate::services::l2_gateway::{self, VerdictAction};
use crate::wallet::instance::VoucherStatus;
use crate::wallet::CleanupReport;
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::Error;
use rand_core::{OsRng, RngCore};

impl AppService {
    // --- Conflict Management (from conflict_handler) ---

    /// Returns a list of summaries of all known double-spend conflicts.
    ///
    /// # Errors
    /// Fails if the wallet is locked (`Locked`).
    pub fn list_conflicts(&self) -> Result<Vec<ProofOfDoubleSpendSummary>, Error> {
        self.with_unlocked_ref(|wallet, _, _| Ok(wallet.list_conflicts()))
    }

    /// Retrieves a complete `ProofOfDoubleSpend` by its ID.
    ///
    /// Ideal for displaying the details of a conflict or exporting it for
    /// manual exchange.
    ///
    /// # Errors
    /// Fails if the wallet is locked or no proof with this ID exists.
    pub fn get_proof_of_double_spend(&self, proof_id: &str) -> Result<ProofOfDoubleSpend, Error> {
        self.with_unlocked_ref(|wallet, _, _| {
            wallet.get_proof_of_double_spend(proof_id)
        })
    }

    /// Checks the reputation / trust status of a user identity based on the local proof store.
    ///
    /// # Errors
    /// Fails if the wallet is locked (`Locked`).
    pub fn check_reputation(
        &self,
        offender_id: &str,
    ) -> Result<crate::models::conflict::TrustStatus, Error> {
        self.with_unlocked_ref(|wallet, _, _| Ok(wallet.check_reputation(offender_id)))
    }

    /// Creates a signed resolution endorsement (`ResolutionEndorsement`) for a conflict.
    ///
    /// This operation does not change the wallet state. It generates a
    /// signed object that can be sent to other parties to signal that
    /// the conflict has been resolved from the perspective of the wallet owner (the victim).
    ///
    /// # Errors
    /// Fails if the wallet is locked or the referenced proof does not exist.
    pub fn create_resolution_endorsement(
        &self,
        proof_id: &str,
        notes: Option<String>,
    ) -> Result<ResolutionEndorsement, Error> {
        self.with_unlocked_ref(|wallet, identity, _| {
            wallet.create_resolution_endorsement(identity, proof_id, notes)
        })
    }

    /// Sets the local override for a specific conflict.
    ///
    /// # Errors
    /// Fails if the wallet is locked or the proof does not exist.
    pub fn set_conflict_local_override(
        &mut self,
        proof_id: &str,
        value: bool,
        note: Option<String>,
        password: Option<&str>,
    ) -> Result<(), Error> {
        self.with_transactional_mut(password, |temp_wallet, _, _, _| {
            match temp_wallet.set_conflict_local_override(proof_id, value, note) {
                Ok(()) => TransactionOutcome::Commit(()),
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Imports a proof directly as an object.
    pub fn import_proof(&mut self, proof: ProofOfDoubleSpend, password: Option<&str>) -> Result<(), Error> {
        self.with_transactional_mut(password, |temp_wallet, _, _, _| {
            match temp_wallet.import_proof(proof) {
                Ok(()) => TransactionOutcome::Commit(()),
                Err(e) => TransactionOutcome::Rollback(e),
            }
        })
    }

    /// Imports a proof from a bs58-encoded JSON string (plain text export).
    pub fn import_proof_from_json(&mut self, json_bs58: &str, password: Option<&str>) -> Result<(), Error> {
        let json_bytes = bs58::decode(json_bs58)
            .into_vec()
            .map_err(|e| Error::Bs58Decode(e.to_string()))?;
        let proof: ProofOfDoubleSpend =
            serde_json::from_slice(&json_bytes).map_err(Error::from)?;

        self.import_proof(proof, password)
    }

    /// Imports a proof from a `SecureContainer` (secure exchange).
    pub fn import_proof_from_container(&mut self, container_bytes: &[u8], password: Option<&str>) -> Result<(), Error> {
        let proof = {
            if let AppState::Unlocked { identity, .. } = &self.state {
                let container: crate::models::secure_container::SecureContainer =
                    serde_json::from_slice(container_bytes).map_err(Error::from)?;

                if container.c != crate::models::secure_container::PayloadType::ProofOfDoubleSpend {
                    return Err(Error::App(crate::error::AppError::ContainerDoesNotContainDoubleSpendProof));
                }

                // Verify container integrity (header signature and payload binding)
                container.verify_integrity().map_err(Error::from)?;

                // Wallet identity is required to open the container
                let decrypted_payload = container.open(
                    identity,
                    None,
                )?;

                let parsed_proof: ProofOfDoubleSpend =
                    serde_json::from_slice(&decrypted_payload).map_err(Error::from)?;
                
                parsed_proof
            } else {
                return Err(Error::WalletLocked);
            }
        };

        self.import_proof(proof, password)
    }

    /// Performs storage cleanup for fingerprints and their metadata.
    ///
    /// This method implements the logic defined in the architecture specification:
    /// 1. Delete all expired fingerprints (past `deletable_at`).
    /// 2. If the storage limit (`MAX_FINGERPRINTS`) is still exceeded,
    ///    fingerprints with the oldest `deletable_at` retention deadline
    ///    are deleted until the limit is no longer exceeded.
    ///
    /// # Returns
    /// A `Result` with a `CleanupReport` containing details about the cleanup,
    /// or an error if the process fails.
    pub fn run_storage_cleanup(&mut self) -> Result<CleanupReport, Error> {
        if let AppState::Unlocked { wallet, .. } = &mut self.state {
            let report = wallet.run_storage_cleanup(None, super::DEFAULT_ARCHIVE_GRACE_PERIOD_YEARS)?;
            // Note: Saving the wallet after cleanup is left to the caller
            // (e.g. at the end of an operation) to avoid multiple writes.
            Ok(report)
        } else {
            Err(Error::WalletLocked)
        }
    }

    /// Finds the associated double-spend conflict proof ID for a voucher using cascading match strategies.
    ///
    /// # Errors
    /// Returns an error if the wallet is locked.
    pub fn get_proof_id_for_voucher(&self, local_id: &str) -> Result<Option<String>, Error> {
        self.with_unlocked_ref(|wallet, _, _| Ok(wallet.get_proof_id_for_voucher(local_id)))
    }

    // --- L2 Facade (from l2_facade) ---

    /// Generates a serialized JSON [`L2LockRequest`](crate::models::layer2_api::L2LockRequest)
    /// for the latest transaction of a voucher.
    ///
    /// # Gateway Retry & Multi-Homing Invariant (Client & Tauri Guide):
    /// The returned byte vector is **strictly immutable**. Application clients (e.g. Tauri frontend)
    /// **MUST reuse this exact byte vector identically** when retrying failed HTTP calls or falling
    /// back to alternate gateway nodes in the cluster.
    ///
    /// **NEVER call this function again for a retry of the same transfer!**
    ///
    /// Rationale:
    /// 1. `created_at_ms` deterministically maps the lock to a 5-minute bucket (`floor(created_at_ms / 300_000)`).
    ///    Re-generating a fresh request on retry could cross bucket boundaries, creating split-bucket divergence.
    /// 2. Layer-2 nodes recognize repeated requests with identical `t_id` and return `200 OK (Verified)`
    ///    under Rule 3 hot-path idempotency without redundant consensus.
    /// 3. Resending the identical payload keeps the request within the 30-second clock-drift acceptance window.
    pub fn generate_l2_lock_request(&self, local_instance_id: &str) -> Result<Vec<u8>, Error> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => return Err(Error::WalletLocked),
        };

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| Error::VoucherNotFound(local_instance_id.to_string()))?;

        let transaction = instance
            .voucher
            .transactions
            .last()
            .ok_or_else(|| Error::App(crate::error::AppError::NoTransactionsFoundInVoucher))?;

        // In the new Layer 2 semantics, the voucher id is derived from the first (init) transaction.
        let l2_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])?;

        let mut ephemeral_key = [0u8; 32];
        OsRng.fill_bytes(&mut ephemeral_key);
        let request =
            l2_gateway::generate_lock_request(&l2_voucher_id, transaction, &ephemeral_key)?;

        serde_json::to_vec(&request).map_err(Error::from)
    }

    /// Generates an L2StatusQuery (read query) for the current status of a voucher.
    pub fn generate_l2_status_query(&self, local_instance_id: &str) -> Result<Vec<u8>, Error> {
        let (wallet, _identity) = match &self.state {
            AppState::Unlocked {
                wallet, identity, ..
            } => (wallet, identity),
            _ => return Err(Error::WalletLocked),
        };

        let query = wallet.build_voucher_status_query(local_instance_id, 1)?;
        serde_json::to_vec(&query).map_err(Error::from)
    }

    /// Reconciles an individual voucher's status against Layer-2 status query results.
    ///
    /// # Two-Tier Ingress Safety Architecture:
    /// - **Tier 1 (Macro-Check - WalletSeal / State Anchor):**
    ///   On startup or periodic synchronization, the wallet verifies its State Anchor
    ///   via `build_anchor_status_query`. If `AnchorSyncVerdict::Synchronized`, the entire
    ///   wallet (all vouchers bound in `voucher_merkle_root`) is confirmed consistent with
    ///   Layer-2 in O(1). No individual voucher checks are required.
    /// - **Tier 2 (Micro-Check - Voucher-Level Reconciliation):**
    ///   If Tier 1 detects a rollback (`AnchorSyncVerdict::RollbackDetected`, e.g. after
    ///   restoring a backup), or when performing a targeted pre-payment safety check before checkout,
    ///   `reconcile_voucher_state` synchronizes individual voucher outputs.
    ///   - If `successor_lock.is_none()` (HTTP 404), the voucher is unspent and safe to spend.
    ///     The voucher remains [`VoucherStatus::Active`].
    ///   - If `successor_lock.is_some()` (HTTP 200), a child lock exists on Layer-2 and the voucher
    ///     was already spent remotely. It is transitioned to [`VoucherStatus::Archived`], committed
    ///     transactionally via [`TransactionOrchestrator`], and removed from available balances.
    pub fn reconcile_voucher_state(
        &mut self,
        local_instance_id: &str,
        successor_lock: Option<&L2LockEntry>,
        password: Option<&str>,
    ) -> Result<VoucherReconciliationResult, Error> {
        let local_id = local_instance_id.to_string();
        TransactionOrchestrator::execute_with_policy(
            self,
            password,
            ReloadPolicy::ReconcileReload,
            move |temp_wallet, _identity, _storage, _auth| {
                match temp_wallet.reconcile_voucher_state(&local_id, successor_lock) {
                    Ok(result) => TransactionOutcome::Commit(result),
                    Err(e) => TransactionOutcome::Rollback(Error::from(e)),
                }
            },
        )
    }

    /// Processes an L2Verdict and executes the corresponding action on the wallet.
    ///
    /// Standardized via [`TransactionOrchestrator`] with
    /// [`ReloadPolicy::Always`] to enforce the full transactional discipline:
    /// fork-lock, file-lock, unconditional Reload-Before-Write with seal-gate
    /// and [`StateMergeHook`](crate::app_service::orchestrator::StateMergeHook),
    /// sealed commit with compensation — identical to `with_transactional_mut`.
    pub fn process_l2_response(
        &mut self,
        local_id: String,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<crate::models::layer2_api::L2ProcessingOutcome, Error> {
        self.process_l2_response_internal(local_id, response_bytes, password, None)
    }

    /// Processes an original receipt using recipient-established frozen committee authority.
    pub fn process_l2_response_with_authority(
        &mut self, local_id: String, response_bytes: &[u8], password: Option<&str>, authority: l2_gateway::CheckoutAuthority,
    ) -> Result<crate::models::layer2_api::L2ProcessingOutcome, Error> {
        self.process_l2_response_internal(local_id, response_bytes, password, Some(authority))
    }

    fn process_l2_response_internal(
        &mut self, local_id: String, response_bytes: &[u8], password: Option<&str>, authority: Option<l2_gateway::CheckoutAuthority>,
    ) -> Result<crate::models::layer2_api::L2ProcessingOutcome, Error> {
        let response = response_bytes.to_vec();
        TransactionOrchestrator::execute_with_policy(
            self,
            password,
            ReloadPolicy::Always,
            move |temp_wallet, _identity, _storage, _auth| {
                let action = match Self::evaluate_l2_action(temp_wallet, &local_id, &response, authority.as_ref()) {
                    Ok(a) => a,
                    Err(e) => return TransactionOutcome::Rollback(e),
                };
                match action {
                    VerdictAction::ConfirmLocal => TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::Found),
                    VerdictAction::ConfirmProvisional { .. } => TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::Provisional),
                    VerdictAction::ConfirmFinal { .. } => {
                        if authority.is_some() {
                            TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::Confirmed)
                        } else {
                            TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::Found)
                        }
                    }
                    VerdictAction::TriggerSync { sync_point } => {
                        TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::SyncRequired { sync_point })
                    }
                    VerdictAction::TriggerQuarantine(conflicting_t_id) => {
                        let reason = format!(
                            "Double spend detected for transaction {}",
                            conflicting_t_id
                        );
                        temp_wallet.update_voucher_status(
                            &local_id,
                            VoucherStatus::Quarantined {
                                reason: reason.clone(),
                            },
                        );
                        TransactionOutcome::Commit(crate::models::layer2_api::L2ProcessingOutcome::Quarantined { reason })
                    }
                }
            },
        )
    }

    /// Evaluates the L2 verdict against the given (verified) wallet state.
    fn evaluate_l2_action(
        wallet: &crate::wallet::Wallet,
        local_instance_id: &str,
        response_bytes: &[u8],
        authority: Option<&l2_gateway::CheckoutAuthority>,
    ) -> Result<VerdictAction, Error> {
        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| Error::VoucherNotFound(local_instance_id.to_string()))?;

        let last_tx = instance.voucher.transactions.last().ok_or_else(|| {
            Error::App(crate::error::AppError::NoTransactionsFound)
        })?;
        let last_t_id = last_tx.t_id.clone();
        let challenge_ds_tag =
            l2_gateway::derive_challenge_tag(last_tx)?;
        let expected_ephemeral_pub = last_tx.sender_ephemeral_pub.as_deref();
        let expected_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])?;

        let server_pubkey = wallet.profile.l2_server_pubkey.ok_or_else(|| {
            Error::App(crate::error::AppError::L2ServerPubkeyNotConfigured)
        })?;

        if let Some(authority) = authority {
            l2_gateway::process_l2_verdict_with_authority(response_bytes, &server_pubkey, &last_t_id, &challenge_ds_tag, expected_ephemeral_pub, &expected_voucher_id, authority).map_err(Error::from)
        } else {
            l2_gateway::process_l2_verdict(response_bytes, &server_pubkey, &last_t_id, &challenge_ds_tag, expected_ephemeral_pub, &expected_voucher_id).map_err(Error::from)
        }
    }

    /// Evaluates goods release for a verified checkout outcome under the merchant approval contract.
    pub fn evaluate_checkout_release(
        &self,
        outcome: crate::models::layer2_api::L2ProcessingOutcome,
        explicit_merchant_approval: bool,
    ) -> crate::models::layer2_api::CheckoutReleaseVerdict {
        crate::models::layer2_api::CheckoutReleaseVerdict::new(outcome, explicit_merchant_approval)
    }

    /// Verifies that an ephemeral live-state proof confirms the voucher lock with full 14/20 quorum
    /// and recipient challenge binding, producing an authorized goods release verdict.
    pub fn verify_live_checkout_proof(
        &self,
        proof: &humoco_proto::live::LiveStateProof,
        expected: &humoco_proto::live::LiveStateContext,
        explicit_merchant_approval: bool,
    ) -> Result<crate::models::layer2_api::CheckoutReleaseVerdict, Error> {
        if expected.recipient_nonce == [0; 32] {
            return Err(Error::Validation(crate::error::ValidationError::InvalidL2Proof));
        }
        l2_gateway::verify_current_checkout(proof, expected)?;
        Ok(crate::models::layer2_api::CheckoutReleaseVerdict::new(
            crate::models::layer2_api::L2ProcessingOutcome::Confirmed,
            explicit_merchant_approval,
        ))
    }

    /// Processes an original write receipt with authority and evaluates goods release under merchant approval rules.
    pub fn verify_checkout_response_with_authority(
        &mut self,
        local_id: String,
        response_bytes: &[u8],
        password: Option<&str>,
        authority: l2_gateway::CheckoutAuthority,
        explicit_merchant_approval: bool,
    ) -> Result<crate::models::layer2_api::CheckoutReleaseVerdict, Error> {
        let outcome = self.process_l2_response_with_authority(local_id, response_bytes, password, authority)?;
        Ok(crate::models::layer2_api::CheckoutReleaseVerdict::new(outcome, explicit_merchant_approval))
    }

    /// Processes an unauthenticated or legacy L2 response and evaluates goods release (which will never authorize automatically).
    pub fn verify_checkout_response_unauthenticated(
        &mut self,
        local_id: String,
        response_bytes: &[u8],
        password: Option<&str>,
        explicit_merchant_approval: bool,
    ) -> Result<crate::models::layer2_api::CheckoutReleaseVerdict, Error> {
        let outcome = self.process_l2_response(local_id, response_bytes, password)?;
        Ok(crate::models::layer2_api::CheckoutReleaseVerdict::new(outcome, explicit_merchant_approval))
    }
}

#[cfg(test)]
mod checkout_release_tests {
    use super::*;
    use crate::models::layer2_api::{CheckoutReleaseVerdict, L2ProcessingOutcome};
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_proto::live::{LiveStateContext, LiveStateProof};
    use humoco_proto::AttestationVote;

    #[test]
    fn confirmed_outcome_authorizes_automatic_goods_release() {
        let verdict = CheckoutReleaseVerdict::new(L2ProcessingOutcome::Confirmed, false);
        assert!(verdict.can_release_goods_automatically);
        assert!(!verdict.requires_merchant_approval);
        assert!(verdict.is_goods_release_authorized);
        assert!(verdict.merchant_warning.is_none());
    }

    #[test]
    fn provisional_and_found_require_explicit_merchant_approval() {
        for outcome in [
            L2ProcessingOutcome::Found,
            L2ProcessingOutcome::Provisional,
            L2ProcessingOutcome::SyncRequired { sync_point: "sync_01".to_string() },
        ] {
            let verdict_no_approval = CheckoutReleaseVerdict::new(outcome.clone(), false);
            assert!(!verdict_no_approval.can_release_goods_automatically);
            assert!(verdict_no_approval.requires_merchant_approval);
            assert!(!verdict_no_approval.is_goods_release_authorized);
            assert!(verdict_no_approval.merchant_warning.is_some());

            let verdict_approved = CheckoutReleaseVerdict::new(outcome, true);
            assert!(!verdict_approved.can_release_goods_automatically);
            assert!(verdict_approved.requires_merchant_approval);
            assert!(verdict_approved.is_goods_release_authorized);
        }
    }

    #[test]
    fn quarantined_never_authorizes_goods_release_even_with_merchant_approval() {
        let outcome = L2ProcessingOutcome::Quarantined { reason: "collision".to_string() };
        let verdict = CheckoutReleaseVerdict::new(outcome, true);
        assert!(!verdict.can_release_goods_automatically);
        assert!(!verdict.is_goods_release_authorized);
        assert!(verdict.merchant_warning.is_some());
    }

    #[test]
    fn live_checkout_proof_requires_recipient_challenge_and_14_of_20_quorum() {
        let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let committee: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();
        let lookup_tag = "tag123".to_string();
        let parent_lock = *blake3::hash(lookup_tag.as_bytes()).as_bytes();

        let valid_context = LiveStateContext {
            version: 1,
            network: 0,
            shard_id: 5,
            voucher_id: "v_123".to_string(),
            lookup_tag,
            parent_lock,
            child_lock: [7; 32],
            root_valid_until: 100_000,
            state_digest: [8; 32],
            recipient_nonce: [9; 32], // Valid recipient challenge
            committee: committee.clone(),
        };

        let digest = humoco_proto::live::live_state_digest(&valid_context).unwrap();
        let votes: Vec<AttestationVote> = keys.iter().take(14).map(|key| {
            AttestationVote {
                signer_pubkey: key.verifying_key().to_bytes(),
                signature: key.sign(&digest).to_bytes(),
            }
        }).collect();

        let valid_proof = LiveStateProof {
            context: valid_context.clone(),
            votes: votes.clone(),
        };

        // AppService helper can verify the proof directly
        let temp_dir = std::env::temp_dir().join(format!("humoco_test_{}", uuid::Uuid::new_v4()));
        let app = AppService::new(&temp_dir).unwrap();
        let res = app.verify_live_checkout_proof(&valid_proof, &valid_context, false);
        assert!(res.is_ok(), "14/20 valid signatures with challenge must succeed");
        let verdict = res.unwrap();
        assert_eq!(verdict.outcome, L2ProcessingOutcome::Confirmed);
        assert!(verdict.can_release_goods_automatically);
        assert!(verdict.is_goods_release_authorized);

        // Zero recipient challenge must be rejected
        let mut zero_nonce_context = valid_context.clone();
        zero_nonce_context.recipient_nonce = [0; 32];
        let mut zero_nonce_proof = valid_proof.clone();
        zero_nonce_proof.context = zero_nonce_context.clone();
        let res_zero = app.verify_live_checkout_proof(&zero_nonce_proof, &zero_nonce_context, false);
        assert!(res_zero.is_err(), "Zero recipient challenge must fail");

        // 13 signatures (sub-quorum) must be rejected
        let short_votes = votes[..13].to_vec();
        let short_proof = LiveStateProof {
            context: valid_context.clone(),
            votes: short_votes,
        };
        let res_short = app.verify_live_checkout_proof(&short_proof, &valid_context, false);
        assert!(res_short.is_err(), "13/20 sub-quorum must fail");

        // Duplicate signer must be rejected
        let mut dup_votes = votes.clone();
        dup_votes[13] = dup_votes[0].clone();
        let dup_proof = LiveStateProof {
            context: valid_context.clone(),
            votes: dup_votes,
        };
        let res_dup = app.verify_live_checkout_proof(&dup_proof, &valid_context, false);
        assert!(res_dup.is_err(), "Duplicate votes must fail");

        // Forged signature must be rejected
        let mut forged_votes = votes.clone();
        forged_votes[0].signature = [0; 64];
        let forged_proof = LiveStateProof {
            context: valid_context.clone(),
            votes: forged_votes,
        };
        let res_forged = app.verify_live_checkout_proof(&forged_proof, &valid_context, false);
        assert!(res_forged.is_err(), "Forged signature must fail");
    }
}
