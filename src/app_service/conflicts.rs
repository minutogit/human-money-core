//! # src/app_service/conflicts.rs
//!
//! Contains all `AppService` functions related to double-spend conflicts,
//! proof management, resolution endorsements, VIP-gossip and the L2 facade.
//! Consolidates the former `conflict_handler.rs` and `l2_facade.rs`.

use super::{AppService, AppState, TransactionOutcome};
use crate::app_service::orchestrator::{ReloadPolicy, TransactionOrchestrator};
use crate::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use crate::models::layer2_api::{L2AuthPayload, L2StatusQuery};
use crate::services::l2_gateway::{self, VerdictAction};
use crate::wallet::instance::VoucherStatus;
use crate::wallet::CleanupReport;
use crate::wallet::ProofOfDoubleSpendSummary;
use crate::Error;

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
    /// 1. Delete all expired fingerprints.
    /// 2. If the storage limit (`MAX_FINGERPRINTS`) is still exceeded,
    ///    fingerprints with the highest `depth` (and oldest `t_time`)
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

        // TODO: In the future, derive a proper ephemeral key. For now, use dummy bytes.
        let ephemeral_key = [0u8; 32];
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

        let instance = wallet
            .get_voucher_instance(local_instance_id)
            .ok_or_else(|| Error::VoucherNotFound(local_instance_id.to_string()))?;

        let layer2_voucher_id =
            l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])?;

        let challenge_ds_tag = if let Some(last_tx) = instance.voucher.transactions.last() {
            l2_gateway::derive_challenge_tag(last_tx)?
        } else {
            return Err(Error::App(crate::error::AppError::VoucherHasNoTransactions));
        };

        let locator_prefixes = l2_gateway::generate_locator_prefixes(&instance.voucher);

        // TODO: derive proper ephemeral key
        let ephemeral_key = [0u8; 32];
        let auth = L2AuthPayload {
            ephemeral_pubkey: ephemeral_key,
            auth_signature: None,
        };

        let query = L2StatusQuery {
            auth,
            layer2_voucher_id,
            challenge_ds_tag,
            locator_prefixes,
        };

        serde_json::to_vec(&query).map_err(Error::from)
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
        local_instance_id: &str,
        response_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<(), Error> {
        let local_id = local_instance_id.to_string();
        let response = response_bytes.to_vec();
        TransactionOrchestrator::execute_with_policy(
            self,
            password,
            ReloadPolicy::Always,
            move |temp_wallet, _identity, _storage, _auth| {
                let action = match Self::evaluate_l2_action(temp_wallet, &local_id, &response) {
                    Ok(a) => a,
                    Err(e) => return TransactionOutcome::Rollback(e),
                };
                match action {
                    VerdictAction::ConfirmLocal => TransactionOutcome::Commit(()),
                    VerdictAction::TriggerSync { sync_point } => {
                        println!("Sync needed from: {}", sync_point);
                        TransactionOutcome::Commit(())
                    }
                    VerdictAction::TriggerQuarantine(conflicting_t_id) => {
                        temp_wallet.update_voucher_status(
                            &local_id,
                            VoucherStatus::Quarantined {
                                reason: format!(
                                    "Double spend detected for transaction {}",
                                    conflicting_t_id
                                ),
                            },
                        );
                        TransactionOutcome::Commit(())
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

        l2_gateway::process_l2_verdict(
            response_bytes,
            &server_pubkey,
            &last_t_id,
            &challenge_ds_tag,
            expected_ephemeral_pub,
            &expected_voucher_id,
        )
    }
}
