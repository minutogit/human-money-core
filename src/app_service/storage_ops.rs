//! # src/app_service/storage_ops.rs
//!
//! Contains the `AppService` operations for storage-related concerns:
//! seals, storage integrity, standard-container import/export/delete,
//! and generic encrypted data storage.
//! Consolidates the former `seal_handler.rs`, `standard_container_handler.rs`
//! and `data_encryption.rs`.

use super::{AppService, AppState, TransactionOutcome};
use crate::app_service::orchestrator::TransactionOrchestrator;
use crate::models::profile::UserIdentity;
use crate::models::seal::{LocalSealRecord, SealSyncState, SyncStatus, WalletSeal};
use crate::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use crate::models::storage_integrity::StorageIntegrityRecord;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::storage::{AuthMethod, FileStorage, WalletLockGuard};
use crate::Error;
use std::fs;
use std::path::Path;

impl AppService {
    // --- Seal & Integrity (from seal_handler) ---

    /// Checks the integrity of all storage items against the Storage Integrity Record.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn check_integrity(
        &mut self,
        password: Option<&str>,
    ) -> Result<crate::models::storage_integrity::IntegrityReport, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;

                let integrity_record = storage.load_integrity()?;
                let seal_record = storage
                    .load_seal(&auth)?;

                match (integrity_record, seal_record) {
                    (Some(ir), Some(s)) => {
                        let actual_hashes = storage.get_all_item_hashes()?;
                        ir.verify(
                            &s.seal,
                            actual_hashes,
                            &identity.user_id,
                        )}
                    (None, Some(_)) => Ok(crate::models::storage_integrity::IntegrityReport::MissingIntegrityRecord),
                    (Some(_), None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Should not happen
                    (None, None) => Ok(crate::models::storage_integrity::IntegrityReport::Valid), // Migration
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Repairs the Storage Integrity Record by accepting the current state of the files as "correct".
    ///
    /// This method should only be called if the user has explicitly confirmed the integrity
    /// warning (e.g., "OK, I accept these changes").
    /// Creates a new, signed Integrity Record for all currently existing records.
    ///
    /// # Arguments
    /// * `password` - Optional, for authentication.
    pub fn repair_integrity(&mut self, password: Option<&str>) -> Result<(), Error> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet: _,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;

                // 1. Load current seal (base point for the integrity record)
                let record = storage
                    .load_seal(&auth)?
                    .ok_or_else(|| Error::App(crate::error::AppError::MissingSealForIntegrityRepair))?;

                // 2. Read current hashes from disk
                let hashes = storage.get_all_item_hashes()?;

                // 3. Create a new integrity record
                let integrity_record = StorageIntegrityRecord::create_record(
                    identity,
                    &record.seal,
                    hashes,
                )?;

                // 4. Save
                storage
                    .save_integrity(&integrity_record)?;

                Ok(())
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    // --- B) Local Sync Tracking (Upload Workflow for Client Apps) ---

    /// Returns the current sync status of the local seal.
    #[allow(unused_variables)]
    pub fn get_seal_sync_status(&self) -> Result<SyncStatus, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => Ok(r.sync_status),
                    None => Err(Error::App(crate::error::AppError::MissingSealForRecovery)),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Returns the raw `WalletSeal` (without metadata!) as a JSON byte array for upload.
    #[allow(unused_variables)]
    pub fn get_seal_for_upload(&self) -> Result<Option<Vec<u8>>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = self.get_read_auth(session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => match r.sync_status {
                        SyncStatus::PendingUpload => {
                            let seal_bytes = serde_json::to_vec(&r.seal)?;
                            Ok(Some(seal_bytes))
                        }
                        SyncStatus::Synced => Ok(None),
                    },
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Acknowledges the successful upload of a seal to the server.
    ///
    /// Standardized via [`TransactionOrchestrator`]:
    /// only `storage.save_seal` is performed without a wallet generation bump,
    /// under the same fork-lock, file-lock and seal-gate discipline as all
    /// other mutating commands.
    pub fn acknowledge_seal_sync(
        &mut self,
        uploaded_seal_hash: &str,
        password: Option<&str>,
    ) -> Result<(), Error> {
        let uploaded = uploaded_seal_hash.to_string();
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            let record_opt = storage.load_seal(auth)?;
            match record_opt {
                Some(mut record) => {
                    let current_hash = record.seal.compute_hash()?;
                    if current_hash != uploaded {
                        return Err(Error::SealSyncRaceCondition);
                    }
                    record.sync_status = SyncStatus::Synced;
                    storage.save_seal(auth, &record)?;
                    Ok(())
                }
                None => Err(Error::RequiresSealRecovery),
            }
        })
    }

    // --- C) Remote Sync Check & Hard Lock ---

    /// Compares a seal downloaded from the server with the local seal.
    ///
    /// Standardized via [`TransactionOrchestrator`]:
    /// only `storage.save_seal` is performed when a fork is detected, without
    /// a wallet generation bump, under the same fork-lock and file-lock discipline.
    pub fn compare_remote_seal(
        &mut self,
        remote_seal_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<SealSyncState, Error> {
        let remote_bytes = remote_seal_bytes.to_vec();
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, wallet, identity| {
            let remote_seal: WalletSeal = serde_json::from_slice(&remote_bytes)?;

            match remote_seal.verify_integrity(
                &identity.user_id,
                &identity.user_id,
                &wallet.local_instance_id,
            ) {
                Ok(crate::models::seal::SealValidationResult::Valid) => {},
                Ok(crate::models::seal::SealValidationResult::DeviceMismatch { .. }) => {
                    // Remote seal from other device is OK for comparison (indicator for fork check)
                },
                Ok(other) => {
                    return Err(Error::App(
                        crate::error::AppError::RemoteSealIntegrityFailed {
                            details: format!("{:?}", other),
                        },
                    ));
                }
                Err(e) => return Err(e),
            }

            let record = match storage.load_seal(auth)? {
                Some(r) => r,
                None => {
                    return Err(Error::App(crate::error::AppError::MissingLocalSeal))
                }
            };

            let sync_state = record.seal.compare_with(&remote_seal);

            if sync_state == SealSyncState::ForkDetected {
                let mut locked_record = record;
                locked_record.lock_reason = Some(crate::models::seal::SealLockReason::ForkDetected);
                storage.save_seal(auth, &locked_record)?;
            }

            Ok(sync_state)
        })
    }

    // --- 2-Tier Trigger Discipline & Rollback Reconciliation ---

    /// Immediate synchronization of the state anchor seal with L2 (tier-1: spend).
    pub fn sync_anchor_immediate(&mut self, password: Option<&str>) -> Result<(), Error> {
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                record.sync_status = SyncStatus::Synced;
                storage.save_seal(auth, &record)?;
            }
            Ok(())
        })
    }

    /// Schedules/marks the anchor seal for debounced upload (tier-2: create, receive, archive).
    pub fn schedule_anchor_sync_debounced(&mut self, password: Option<&str>) -> Result<(), Error> {
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                record.sync_status = SyncStatus::PendingUpload;
                storage.save_seal(auth, &record)?;
            }
            Ok(())
        })
    }
}

/// Step for uploading a tombstone lock to Layer 2.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TombstoneUploadStep {
    pub old_epoch: u32,
    pub chain_request: crate::models::layer2_api::L2ChainLockRequest,
    pub expected_slot: u64,
    pub expected_challenge_tag: String,
}

/// Plan for uploading pending wallet state anchors to Layer 2.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorSyncUploadPlan {
    pub tombstone_plans: Vec<TombstoneUploadStep>,
    pub active_chain_request: Option<crate::models::layer2_api::L2ChainLockRequest>,
    pub target_checkpoint: crate::models::seal::SyncedAnchorCheckpoint,
}

/// Context for querying and verifying the next outgoing anchor slot against Layer 2.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorStatusQueryContext {
    pub query: crate::models::layer2_api::L2StatusQuery,
    pub local_t_id: [u8; 32],
    pub challenge_tag: String,
    pub epoch: u64,
    pub step_nonce: u64,
    pub expected_step_pub: [u8; 32],
    pub anchor_id: String,
}

/// A candidate probe item: (candidate_epoch, epoch_valid_until, status_query).
pub type ColdRecoveryProbe = (u32, String, crate::models::layer2_api::L2StatusQuery);

/// Result of preparing cold recovery probes: (target_epoch, candidate_probes).
pub type ColdRecoveryProbesResult = (u32, Vec<ColdRecoveryProbe>);

impl AppService {
    /// Prepares an upload plan for pending anchor state to Layer 2.
    pub fn prepare_anchor_sync_upload(&self) -> Result<Option<AnchorSyncUploadPlan>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                wallet,
                ..
            } => {
                let auth = match self.get_read_auth(session_cache) {
                    Ok(a) => a,
                    Err(_) => crate::storage::AuthMethod::RecoveryIdentity(identity),
                };
                let record = storage
                    .load_seal(&auth)?
                    .ok_or(Error::App(crate::error::AppError::MissingLocalSeal))?;

                if record.sync_status != SyncStatus::PendingUpload
                    && record.pending_tombstones.is_empty()
                {
                    return Ok(None);
                }

                let mut tombstone_plans = Vec::new();
                for tombstone in &record.pending_tombstones {
                    let old_epoch = tombstone.old_epoch as u64;
                    let anchor_id = crate::models::seal::derive_l2_anchor_id(
                        identity,
                        old_epoch,
                        &tombstone.old_epoch_valid_until,
                    );

                    let (chain, expected_slot, expected_challenge_tag) =
                        match &tombstone.last_known_checkpoint {
                            Some(cp) => {
                                let target_slot = cp.l2_slot.checked_add(1).ok_or_else(|| {
                                    Error::Crypto("l2_slot counter overflow".to_string())
                                })?;
                                let (_sk, pk) = crate::models::seal::derive_anchor_step_key(
                                    identity,
                                    old_epoch,
                                    target_slot,
                                );
                                let challenge_tag =
                                    crate::models::seal::derive_anchor_canonical_ds_tag(
                                        &cp.causal_state_hash,
                                        &pk.to_bytes(),
                                    );
                                let hop = crate::services::l2_gateway::build_anchor_step_lock(
                                    identity,
                                    old_epoch,
                                    &tombstone.old_epoch_valid_until,
                                    target_slot,
                                    &cp.causal_state_hash,
                                    tombstone.kind,
                                    tombstone.target_epoch,
                                    &wallet.local_instance_id,
                                    &[0u8; 32],
                                )?;
                                (vec![hop], target_slot, challenge_tag)
                            }
                            None => {
                                let hop_0 = crate::services::l2_gateway::build_anchor_genesis_lock(
                                    identity,
                                    old_epoch,
                                    &tombstone.old_epoch_valid_until,
                                    &wallet.local_instance_id,
                                )?;
                                let genesis_causal =
                                    crate::models::seal::derive_anchor_genesis_causal_state_hash(
                                        identity, old_epoch,
                                    );
                                let (_sk1, pk1) = crate::models::seal::derive_anchor_step_key(
                                    identity, old_epoch, 1,
                                );
                                let challenge_tag =
                                    crate::models::seal::derive_anchor_canonical_ds_tag(
                                        &genesis_causal,
                                        &pk1.to_bytes(),
                                    );
                                let hop_1 = crate::services::l2_gateway::build_anchor_step_lock(
                                    identity,
                                    old_epoch,
                                    &tombstone.old_epoch_valid_until,
                                    1,
                                    &genesis_causal,
                                    tombstone.kind,
                                    tombstone.target_epoch,
                                    &wallet.local_instance_id,
                                    &[0u8; 32],
                                )?;
                                (vec![hop_0, hop_1], 1, challenge_tag)
                            }
                        };

                    let last_ephem = chain
                        .last()
                        .map(|l| l.sender_ephemeral_pub)
                        .unwrap_or_default();
                    let chain_request = crate::models::layer2_api::L2ChainLockRequest {
                        auth: crate::models::layer2_api::L2AuthPayload {
                            ephemeral_pubkey: last_ephem,
                            auth_signature: None,
                        },
                        layer2_voucher_id: anchor_id,
                        chain,
                    };

                    tombstone_plans.push(TombstoneUploadStep {
                        old_epoch: tombstone.old_epoch,
                        chain_request,
                        expected_slot,
                        expected_challenge_tag,
                    });
                }

                let current_seal_hash = record.seal.compute_hash()?;
                let target_state_bytes =
                    crate::models::seal::seal_state_hash_bytes(&record.seal.payload.state_hash);
                let epoch = record.seal.payload.epoch as u64;
                let epoch_valid_until = &record.seal.payload.epoch_valid_until;
                let anchor_id =
                    crate::models::seal::derive_l2_anchor_id(identity, epoch, epoch_valid_until);

                let (active_chain, active_target_checkpoint) =
                    if record.sync_status == SyncStatus::PendingUpload {
                        match &record.last_synced_anchor {
                            Some(cp) if cp.epoch == record.seal.payload.epoch => {
                                let target_slot = cp.l2_slot.checked_add(1).ok_or_else(|| {
                                    Error::Crypto("l2_slot counter overflow".to_string())
                                })?;
                                let leap_lock = crate::services::l2_gateway::build_anchor_step_lock(
                                    identity,
                                    epoch,
                                    epoch_valid_until,
                                    target_slot,
                                    &cp.causal_state_hash,
                                    crate::models::seal::AnchorLockKind::RegularStateUpdate,
                                    record.seal.payload.epoch,
                                    &wallet.local_instance_id,
                                    &target_state_bytes,
                                )?;
                                let causal_state_hash = leap_lock
                                    .causal_output
                                    .as_ref()
                                    .map(|c| c.state_hash)
                                    .unwrap_or_default();
                                let target_cp = crate::models::seal::SyncedAnchorCheckpoint {
                                    epoch: record.seal.payload.epoch,
                                    tx_nonce: record.seal.payload.tx_nonce,
                                    l2_slot: target_slot,
                                    seal_hash: current_seal_hash.clone(),                                    state_hash: record.seal.payload.state_hash.clone(),
                                    causal_state_hash,
                                    epoch_valid_until: epoch_valid_until.clone(),
                                };
                                (Some(vec![leap_lock]), target_cp)
                            }
                            _ => {
                                let hop_0 = crate::services::l2_gateway::build_anchor_genesis_lock(
                                    identity,
                                    epoch,
                                    epoch_valid_until,
                                    &wallet.local_instance_id,
                                )?;
                                let genesis_causal =
                                    crate::models::seal::derive_anchor_genesis_causal_state_hash(
                                        identity, epoch,
                                    );
                                let hop_1 = crate::services::l2_gateway::build_anchor_step_lock(
                                    identity,
                                    epoch,
                                    epoch_valid_until,
                                    1,
                                    &genesis_causal,
                                    crate::models::seal::AnchorLockKind::RegularStateUpdate,
                                    record.seal.payload.epoch,
                                    &wallet.local_instance_id,
                                    &target_state_bytes,
                                )?;
                                let causal_state_hash = hop_1
                                    .causal_output
                                    .as_ref()
                                    .map(|c| c.state_hash)
                                    .unwrap_or_default();
                                let target_cp = crate::models::seal::SyncedAnchorCheckpoint {
                                    epoch: record.seal.payload.epoch,
                                    tx_nonce: record.seal.payload.tx_nonce,
                                    l2_slot: 1,
                                    seal_hash: current_seal_hash.clone(),
                                    state_hash: record.seal.payload.state_hash.clone(),
                                    causal_state_hash,
                                    epoch_valid_until: epoch_valid_until.clone(),
                                };
                                (Some(vec![hop_0, hop_1]), target_cp)
                            }
                        }
                    } else {
                        let fallback_cp = record.last_synced_anchor.clone().unwrap_or_else(|| {
                            crate::models::seal::SyncedAnchorCheckpoint {
                                epoch: record.seal.payload.epoch,
                                tx_nonce: record.seal.payload.tx_nonce,
                                l2_slot: 0,
                                seal_hash: current_seal_hash.clone(),
                                state_hash: record.seal.payload.state_hash.clone(),
                                causal_state_hash: [0u8; 32],
                                epoch_valid_until: epoch_valid_until.clone(),
                            }
                        });
                        (None, fallback_cp)
                    };

                let active_chain_request = active_chain.map(|chain| {
                    let last_ephem = chain
                        .last()
                        .map(|l| l.sender_ephemeral_pub)
                        .unwrap_or_default();
                    crate::models::layer2_api::L2ChainLockRequest {
                        auth: crate::models::layer2_api::L2AuthPayload {
                            ephemeral_pubkey: last_ephem,
                            auth_signature: None,
                        },
                        layer2_voucher_id: anchor_id,
                        chain,
                    }
                });

                Ok(Some(AnchorSyncUploadPlan {
                    tombstone_plans,
                    active_chain_request,
                    target_checkpoint: active_target_checkpoint,
                }))
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Completes anchor sync upload after Layer 2 confirmation, marking Synced and saving checkpoint.
    pub fn complete_anchor_sync_upload(
        &mut self,
        checkpoint: crate::models::seal::SyncedAnchorCheckpoint,
        password: Option<&str>,
    ) -> Result<bool, Error> {
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                record.sync_status = SyncStatus::Synced;
                record.last_synced_anchor = Some(checkpoint);
                record.pending_tombstones.clear();
                storage.save_seal(auth, &record)?;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Flushes any pending anchor sync to L2 (e.g. on backgrounding or before close).
    pub fn flush_pending_anchor_sync(&mut self, password: Option<&str>) -> Result<bool, Error> {
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, wallet, identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                if record.sync_status == SyncStatus::PendingUpload {
                    record.sync_status = SyncStatus::Synced;
                    let current_seal_hash = record.seal.compute_hash().unwrap_or_default();
                    let target_state_bytes = crate::models::seal::seal_state_hash_bytes(&record.seal.payload.state_hash);
                    let target_slot = record.last_synced_anchor.as_ref().map(|cp| cp.l2_slot + 1).unwrap_or(1);
                    let origin_device_fp48 = crate::models::seal::derive_anchor_device_fp48(identity, &wallet.local_instance_id);
                    let t_id = crate::models::seal::derive_anchor_step_t_id(
                        identity,
                        record.seal.payload.epoch as u64,
                        target_slot,
                        crate::models::seal::AnchorLockKind::RegularStateUpdate,
                        record.seal.payload.epoch,
                        &origin_device_fp48,
                        &target_state_bytes,
                    );
                    let causal_state_hash = crate::models::seal::derive_anchor_step_causal_hash(
                        identity,
                        record.seal.payload.epoch as u64,
                        target_slot,
                        &t_id,
                    );

                    record.last_synced_anchor = Some(crate::models::seal::SyncedAnchorCheckpoint {                        epoch: record.seal.payload.epoch,
                        tx_nonce: record.seal.payload.tx_nonce,
                        l2_slot: target_slot,
                        seal_hash: current_seal_hash,
                        state_hash: record.seal.payload.state_hash.clone(),
                        causal_state_hash,
                        epoch_valid_until: record.seal.payload.epoch_valid_until.clone(),
                    });
                    storage.save_seal(auth, &record)?;
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Prepares context and L2StatusQuery for state anchor synchronization.
    pub fn prepare_anchor_status_query_context(&self) -> Result<AnchorStatusQueryContext, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                wallet,
                session_cache,
                ..
            } => {
                let auth = match self.get_read_auth(session_cache) {
                    Ok(a) => a,
                    Err(_) => crate::storage::AuthMethod::RecoveryIdentity(identity),
                };
                let record = storage
                    .load_seal(&auth)?
                    .ok_or(Error::App(crate::error::AppError::MissingLocalSeal))?;
                let epoch = record.seal.payload.epoch as u64;
                let epoch_valid_until = &record.seal.payload.epoch_valid_until;
                let anchor_id = crate::models::seal::derive_l2_anchor_id(identity, epoch, epoch_valid_until);

                let (step_nonce, challenge_tag, locator_prefixes) = match &record.last_synced_anchor {
                    Some(cp) if cp.epoch == record.seal.payload.epoch => {
                        let nonce = cp.l2_slot.checked_add(1).ok_or_else(|| {
                            Error::Crypto("l2_slot counter overflow".to_string())
                        })?;
                        let (_sk, pk) = crate::models::seal::derive_anchor_step_key(identity, epoch, nonce);
                        let tag = crate::models::seal::derive_anchor_canonical_ds_tag(
                            &cp.causal_state_hash,
                            &pk.to_bytes(),
                        );
                        let prefix: String = bs58::encode(cp.causal_state_hash)
                            .into_string()
                            .chars()
                            .take(10)
                            .collect();
                        (nonce, tag, vec![prefix])
                    }
                    _ => {
                        let nonce = 1;
                        let genesis_causal = crate::models::seal::derive_anchor_genesis_causal_state_hash(identity, epoch);
                        let (_sk, pk) = crate::models::seal::derive_anchor_step_key(identity, epoch, 1);
                        let tag = crate::models::seal::derive_anchor_canonical_ds_tag(
                            &genesis_causal,
                            &pk.to_bytes(),
                        );
                        (nonce, tag, vec![])
                    }
                };

                let (_sk, pk) = crate::models::seal::derive_anchor_step_key(
                    identity,
                    epoch,
                    step_nonce,
                );
                let expected_step_pub = pk.to_bytes();
                let query = crate::services::l2_gateway::build_anchor_status_query(
                    identity,
                    epoch,
                    epoch_valid_until,
                    step_nonce,
                    &challenge_tag,
                    locator_prefixes,
                    1,
                )?;

                let target_state_bytes = crate::models::seal::seal_state_hash_bytes(&record.seal.payload.state_hash);
                let origin_device_fp48 = crate::models::seal::derive_anchor_device_fp48(identity, &wallet.local_instance_id);
                let expected_t_id = crate::models::seal::derive_anchor_step_t_id(
                    identity,
                    epoch,
                    step_nonce,
                    crate::models::seal::AnchorLockKind::RegularStateUpdate,
                    record.seal.payload.epoch,
                    &origin_device_fp48,
                    &target_state_bytes,
                );

                Ok(AnchorStatusQueryContext {
                    query,
                    local_t_id: expected_t_id,
                    challenge_tag,
                    epoch,
                    step_nonce,
                    expected_step_pub,
                    anchor_id,
                })
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Prepares an L2StatusQuery for state anchor synchronization.
    /// Returns (query, local_t_id, challenge_ds_tag).
    pub fn prepare_anchor_status_query(&self) -> Result<(crate::models::layer2_api::L2StatusQuery, [u8; 32], String), Error> {
        let ctx = self.prepare_anchor_status_query_context()?;
        Ok((ctx.query, ctx.local_t_id, ctx.challenge_tag))
    }

    /// Evaluates multi-gateway responses for a state anchor query with zero-trust cryptographic verification.
    pub fn evaluate_verified_anchor_envelopes(
        &self,
        envelopes: &[crate::models::layer2_api::L2ResponseEnvelope],
    ) -> Result<crate::services::l2_gateway::AnchorSyncVerdict, Error> {
        let ctx = self.prepare_anchor_status_query_context()?;
        let (record, identity, wallet) = match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                wallet,
                session_cache,
                ..
            } => {
                let auth = match self.get_read_auth(session_cache) {
                    Ok(a) => a,
                    Err(_) => crate::storage::AuthMethod::RecoveryIdentity(identity),
                };
                let r = storage
                    .load_seal(&auth)?
                    .ok_or(Error::App(crate::error::AppError::MissingLocalSeal))?;
                (r, identity, wallet)
            }
            AppState::Locked => return Err(Error::WalletLocked),
        };

        let expected_step_pub_bs58 = bs58::encode(ctx.expected_step_pub).into_string();
        let local_fp = crate::models::seal::derive_anchor_device_fp48(identity, &wallet.local_instance_id);

        // 1. Mandatory cryptographic proof check on all Verified / Conflict entries
        for env in envelopes {
            let entry_opt = match &env.verdict {
                crate::models::layer2_api::L2Verdict::Verified { lock_entry } => Some(lock_entry),
                crate::models::layer2_api::L2Verdict::Conflict { existing_lock } => Some(existing_lock),
                _ => None,
            };

            if let Some(entry) = entry_opt {
                if crate::services::l2_gateway::verify_lock_entry_proof(
                    entry,
                    &ctx.anchor_id,
                    Some(&expected_step_pub_bs58),
                    &ctx.challenge_tag,
                )
                .is_ok()
                {
                    // Valid positive cryptographic signature proof!
                    if entry.t_id == ctx.local_t_id {
                        return Ok(crate::services::l2_gateway::AnchorSyncVerdict::Synchronized);
                    }

                    // Decode AnchorLockDescriptor from encrypted_timestamp!
                    let desc_opt = crate::models::seal::AnchorLockDescriptor::decode_encrypted_timestamp(
                        identity,
                        &ctx.anchor_id,                        ctx.epoch,
                        ctx.step_nonce,
                        &entry.t_id,
                        entry.encrypted_timestamp,
                    );

                    if let Some(desc) = desc_opt {
                        match desc.kind {
                            crate::models::seal::AnchorLockKind::HandoverTombstone
                            | crate::models::seal::AnchorLockKind::SeedRecoveryTombstone => {
                                if desc.origin_device_fp48 != local_fp {
                                    let is_seed_recovery = desc.kind == crate::models::seal::AnchorLockKind::SeedRecoveryTombstone;
                                    return Ok(crate::services::l2_gateway::AnchorSyncVerdict::SupersededByHandover {
                                        target_epoch: desc.target_epoch,
                                        is_seed_recovery,
                                        lock_entry: entry.clone(),
                                    });
                                }
                            }
                            crate::models::seal::AnchorLockKind::RegularStateUpdate => {
                                if desc.origin_device_fp48 == local_fp {
                                    return Ok(crate::services::l2_gateway::AnchorSyncVerdict::SameDeviceRollback {
                                        remote_t_id: entry.t_id,
                                        lock_entry: entry.clone(),
                                    });
                                } else {
                                    return Ok(crate::services::l2_gateway::AnchorSyncVerdict::ConcurrentCloneDetected {
                                        remote_t_id: entry.t_id,
                                        lock_entry: entry.clone(),
                                    });
                                }
                            }
                        }
                    }

                    return Ok(crate::services::l2_gateway::AnchorSyncVerdict::RollbackDetected {
                        remote_t_id: entry.t_id,
                        lock_entry: entry.clone(),
                    });
                }
            }
        }

        // 2. Check for MissingLocks or UnknownVoucher
        let mut missing_locks_point = None;
        let mut unknown_voucher = false;

        for env in envelopes {
            match &env.verdict {
                crate::models::layer2_api::L2Verdict::MissingLocks { sync_point, .. } => {
                    missing_locks_point = Some(sync_point.clone());
                }
                crate::models::layer2_api::L2Verdict::UnknownVoucher => {
                    unknown_voucher = true;
                }
                _ => {}
            }
        }

        if let Some(sync_point) = missing_locks_point {
            if record.sync_status == SyncStatus::PendingUpload {
                return Ok(crate::services::l2_gateway::AnchorSyncVerdict::PendingLeapLock {
                    sync_point,
                });
            } else {
                return Ok(crate::services::l2_gateway::AnchorSyncVerdict::Synchronized);
            }
        }

        if unknown_voucher {
            return Ok(crate::services::l2_gateway::AnchorSyncVerdict::GenesisRequired);
        }

        Ok(crate::services::l2_gateway::AnchorSyncVerdict::Inconclusive)
    }

    /// Evaluates a single verified response envelope for an anchor query.
    pub fn verify_and_evaluate_anchor_envelope(
        &self,
        envelope: &crate::models::layer2_api::L2ResponseEnvelope,
    ) -> Result<crate::services::l2_gateway::AnchorSyncVerdict, Error> {
        self.evaluate_verified_anchor_envelopes(std::slice::from_ref(envelope))
    }

    /// Evaluates multi-gateway responses and immediately enforces persistent fail-closed locks on disk if
    /// a Handover, ConcurrentClone, or Rollback condition is detected.
    pub fn apply_verified_anchor_envelopes(
        &mut self,
        envelopes: &[crate::models::layer2_api::L2ResponseEnvelope],
        password: Option<&str>,
    ) -> Result<crate::services::l2_gateway::AnchorSyncVerdict, Error> {
        let verdict = self.evaluate_verified_anchor_envelopes(envelopes)?;
        match &verdict {
            crate::services::l2_gateway::AnchorSyncVerdict::SupersededByHandover {
                target_epoch,
                is_seed_recovery,
                ..
            } => {
                let reason = crate::models::seal::SealLockReason::SupersededByHandover {
                    target_epoch: *target_epoch,
                    is_seed_recovery: *is_seed_recovery,
                    detected_at: crate::services::utils::get_current_timestamp(),
                };
                let _ = self.persist_seal_lock_reason(reason, password);
            }
            crate::services::l2_gateway::AnchorSyncVerdict::ConcurrentCloneDetected { .. } => {
                let reason = crate::models::seal::SealLockReason::ConcurrentCloneDetected {
                    detected_at: crate::services::utils::get_current_timestamp(),
                };
                let _ = self.persist_seal_lock_reason(reason, password);
            }
            crate::services::l2_gateway::AnchorSyncVerdict::RollbackDetected { .. }
            | crate::services::l2_gateway::AnchorSyncVerdict::SameDeviceRollback { .. } => {
                let reason = crate::models::seal::SealLockReason::ForkDetected;
                let _ = self.persist_seal_lock_reason(reason, password);
            }
            _ => {}
        }
        Ok(verdict)
    }

    /// Persists an explicit lock reason into the local seal record on disk.
    pub fn persist_seal_lock_reason(
        &mut self,
        reason: crate::models::seal::SealLockReason,
        password: Option<&str>,
    ) -> Result<bool, Error> {
        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                record.lock_reason = Some(reason);
                storage.save_seal(auth, &record)?;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Reads the active seal lock reason from storage, if any.
    pub fn get_seal_lock_reason(
        &self,
        password: Option<&str>,
    ) -> Result<Option<crate::models::seal::SealLockReason>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                session_cache,
                identity,
                ..
            } => {
                let auth = match Self::resolve_auth_method(password, session_cache) {                    Ok(a) => a,
                    Err(_) => crate::storage::AuthMethod::RecoveryIdentity(identity),
                };
                let r = storage.load_seal(&auth)?;
                Ok(r.and_then(|rec| rec.lock_reason))
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Advances a pending tombstone to the tip of an epoch using a verified conflict response from L2.
    ///
    /// When attempting to decommission a predecessor epoch, if L2 returns a 409 Conflict, this updates the
    /// pending tombstone's `last_known_checkpoint` using the causal state hash from the conflict entry's
    /// proof, allowing the tombstone upload to advance to the actual tip of the old epoch.
    pub fn advance_pending_tombstone_from_conflict(
        &mut self,
        old_epoch: u32,
        conflict_entry: &crate::models::layer2_api::L2LockEntry,
        password: Option<&str>,
    ) -> Result<bool, Error> {
        let proof = conflict_entry
            .causal_output
            .as_ref()
            .ok_or_else(|| Error::Crypto("Conflict entry missing CausalOutputProof".to_string()))?;

        TransactionOrchestrator::execute_seal_only(self, password, |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                let mut found = false;
                for tombstone in &mut record.pending_tombstones {
                    if tombstone.old_epoch == old_epoch {
                        let next_slot = match &tombstone.last_known_checkpoint {
                            Some(cp) => cp.l2_slot.checked_add(1).ok_or_else(|| {
                                Error::Crypto("Slot counter overflow".to_string())
                            })?,
                            None => 1,
                        };
                        tombstone.last_known_checkpoint = Some(crate::models::seal::SyncedAnchorCheckpoint {
                            epoch: old_epoch,
                            tx_nonce: 0,
                            l2_slot: next_slot,
                            seal_hash: "".to_string(),
                            state_hash: "".to_string(),
                            causal_state_hash: proof.state_hash,
                            epoch_valid_until: tombstone.old_epoch_valid_until.clone(),
                        });
                        found = true;
                        break;
                    }
                }
                if found {
                    storage.save_seal(auth, &record)?;
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// Prepares Layer 2 status probe queries for cold recovery.
    ///
    /// For each candidate epoch, constructs slot 1 challenge query using the deterministic
    /// genesis causal state hash. Requires zero knowledge of local historical state.
    pub fn prepare_cold_recovery_probe_queries(
        identity: &crate::models::profile::UserIdentity,
        candidate_epochs: &[u32],
        epoch_valid_until: &str,
    ) -> Result<Vec<(u32, crate::models::layer2_api::L2StatusQuery)>, Error> {
        let mut queries = Vec::with_capacity(candidate_epochs.len());
        for &epoch in candidate_epochs {
            let epoch_u64 = epoch as u64;
            let genesis_causal = crate::models::seal::derive_anchor_genesis_causal_state_hash(identity, epoch_u64);
            let (_sk, pk) = crate::models::seal::derive_anchor_step_key(identity, epoch_u64, 1);
            let challenge_tag = crate::models::seal::derive_anchor_canonical_ds_tag(
                &genesis_causal,
                &pk.to_bytes(),
            );
            let query = crate::services::l2_gateway::build_anchor_status_query(
                identity,
                epoch_u64,
                epoch_valid_until,
                1,
                &challenge_tag,
                vec![],
                1,
            )?;
            queries.push((epoch, query));
        }
        Ok(queries)
    }

    /// Prepares Layer 2 status probe queries for cold recovery based on the unlocked wallet state.
    /// Returns (target_epoch, list of (candidate_epoch, epoch_valid_until, status_query)).
    pub fn prepare_cold_recovery_probes(
        &self,
        max_epochs: u32,
    ) -> Result<ColdRecoveryProbesResult, Error> {
        match &self.state {
            AppState::Unlocked {
                identity,
                storage,
                session_cache,
                ..
            } => {
                let auth = match self.get_read_auth(session_cache) {
                    Ok(a) => a,
                    Err(_) => crate::storage::AuthMethod::RecoveryIdentity(identity),
                };
                let record = storage
                    .load_seal(&auth)?
                    .ok_or(Error::App(crate::error::AppError::MissingLocalSeal))?;
                let target_epoch = record.seal.payload.epoch;
                let epoch_valid_until = record.seal.payload.epoch_valid_until.clone();
                let start_epoch = target_epoch.saturating_sub(max_epochs);
                let candidate_epochs: Vec<u32> = (start_epoch..target_epoch).collect();
                let queries = Self::prepare_cold_recovery_probe_queries(identity, &candidate_epochs, &epoch_valid_until)?;
                let list = queries.into_iter().map(|(ep, q)| (ep, epoch_valid_until.clone(), q)).collect();
                Ok((target_epoch, list))
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Queues a seed recovery tombstone for a discovered active epoch during cold recovery.
    pub fn queue_cold_recovery_tombstone(
        &mut self,
        old_epoch: u32,
        old_epoch_valid_until: &str,
        target_epoch: u32,
        last_checkpoint: Option<crate::models::seal::SyncedAnchorCheckpoint>,
        password: Option<&str>,
    ) -> Result<bool, Error> {
        let valid_until = old_epoch_valid_until.to_string();
        TransactionOrchestrator::execute_seal_only(self, password, move |storage, auth, _wallet, _identity| {
            if let Some(mut record) = storage.load_seal(auth)? {
                record.pending_tombstones.push(crate::models::seal::PendingEpochTombstone {
                    old_epoch,
                    old_epoch_valid_until: valid_until.clone(),
                    target_epoch,
                    kind: crate::models::seal::AnchorLockKind::SeedRecoveryTombstone,
                    last_known_checkpoint: last_checkpoint.clone(),
                });
                record.sync_status = SyncStatus::PendingUpload;
                storage.save_seal(auth, &record)?;
                return Ok(true);
            }
            Ok(false)
        })
    }

    /// Explicitly archives a voucher and marks the state for debounced anchor update.
    pub fn archive_voucher(
        &mut self,
        local_instance_id: &str,
        password: Option<&str>,
    ) -> Result<(), Error> {
        let local_id = local_instance_id.to_string();
        self.with_transactional_mut(password, |temp_wallet, _, _, _| {
            temp_wallet.update_voucher_status(&local_id, crate::wallet::instance::VoucherStatus::Archived);
            TransactionOutcome::Commit(())
        })
    }

    /// Explicitly triggers a transaction rollback for testing failure paths and state merge.
    #[doc(hidden)]
    pub fn rollback_transaction_for_test(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), Error> {
        self.with_transactional_mut(password, |_temp_wallet, _, _, _| {
            TransactionOutcome::Rollback(Error::App(crate::error::AppError::ReloadFailed {
                reason: "Simulated test rollback".to_string(),
            }))
        })
    }

    /// Reconciles local wallet state after an L2 rollback is detected.
    ///
    /// Scans vouchers, quarantines/archives already-spent vouchers on L2, retains unspent
    /// vouchers, advances local nonce to match L2 reality, and consolidates the state hash.
    pub fn reconcile_rollback(&mut self) -> Result<crate::models::seal::RollbackReconciliationReport, Error> {
        self.reconcile_rollback_with_diagnostics(&[], None, None)
    }

    /// Reconciles local wallet state with explicit diagnostics / spent voucher list and remote nonce.
    pub fn reconcile_rollback_with_diagnostics(
        &mut self,
        spent_voucher_ids: &[String],
        remote_nonce: Option<u64>,
        password: Option<&str>,
    ) -> Result<crate::models::seal::RollbackReconciliationReport, Error> {
        let spent_ids = spent_voucher_ids.to_vec();
        TransactionOrchestrator::execute_reconciliation(self, password, move |temp_wallet, identity, storage, auth| {
            let mut archived = Vec::new();
            let mut retained = Vec::new();
            let mut quarantined = Vec::new();

            for (id, instance) in &mut temp_wallet.voucher_store.vouchers {
                if matches!(instance.status, crate::wallet::instance::VoucherStatus::Quarantined { .. }) {
                    quarantined.push(id.clone());
                } else if spent_ids.contains(id)
                    || spent_ids.contains(&instance.voucher.voucher_id)
                {
                    instance.status = crate::wallet::instance::VoucherStatus::Archived;
                    archived.push(id.clone());
                } else if matches!(instance.status, crate::wallet::instance::VoucherStatus::Active) {
                    retained.push(id.clone());
                }
            }

            // Load existing seal to advance nonce and chain
            let record_opt = storage.load_seal(auth)?;
            let (epoch, next_nonce, prev_hash) = match record_opt {
                Some(r) => {
                    let ep = r.seal.payload.epoch as u64;
                    let target_nonce = remote_nonce.unwrap_or(r.seal.payload.tx_nonce + 1);
                    let h = r.seal.compute_hash().unwrap_or_else(|_| "".to_string());
                    (ep, target_nonce, h)
                }
                None => (0, remote_nonce.unwrap_or(1), "".to_string()),
            };

            let merkle_root = crate::models::seal::calculate_voucher_merkle_root(&temp_wallet.voucher_store.vouchers);
            let of_hash = crate::storage::seal_service::SealService::calculate_state_hash(&temp_wallet.own_fingerprints)?;
            let consolidated_hash = crate::storage::seal_service::SealService::calculate_comprehensive_state_hash(
                epoch,
                next_nonce,
                &merkle_root,
                &of_hash,
            );

            // Create updated seal matching L2 reality
            let updated_seal = match storage.load_seal(auth)? {
                Some(record) => {
                    let mut s = record.seal.clone();
                    s.payload.tx_nonce = next_nonce;
                    s.payload.state_hash = consolidated_hash.clone();
                    s.payload.timestamp = crate::services::utils::get_current_timestamp();
                    s.payload.prev_seal_hash = prev_hash;
                    // Re-sign with updated payload
                    let canonical = crate::services::utils::to_canonical_json(&s.payload)?;
                    let hash = crate::services::crypto::get_hash(canonical.as_bytes());
                    let sig = crate::services::crypto::sign_ed25519(&identity.signing_key, hash.as_bytes());
                    s.signature = bs58::encode(sig.to_bytes()).into_string();
                    s
                }
                None => {
                    crate::models::seal::WalletSeal::create_initial(
                        &identity.user_id,
                        identity,
                        &consolidated_hash,
                        &temp_wallet.local_instance_id,
                    )?
                }
            };

            let seal_hash = updated_seal.compute_hash().unwrap_or_default();
            let new_record = crate::models::seal::LocalSealRecord {
                seal: updated_seal.clone(),
                sync_status: SyncStatus::Synced,
                lock_reason: None,
                pending_tombstones: Vec::new(),
                last_synced_anchor: Some(crate::models::seal::SyncedAnchorCheckpoint {
                    epoch: updated_seal.payload.epoch,
                    tx_nonce: updated_seal.payload.tx_nonce,
                    l2_slot: remote_nonce.unwrap_or(0),
                    seal_hash,
                    state_hash: updated_seal.payload.state_hash.clone(),
                    causal_state_hash: [0u8; 32],
                    epoch_valid_until: updated_seal.payload.epoch_valid_until.clone(),
                }),
            };
            storage.save_seal(auth, &new_record)?;

            let item_hashes = storage.get_all_item_hashes()?;
            let integrity_record = StorageIntegrityRecord::create_record(
                identity,
                &updated_seal,
                item_hashes,
            )?;
            storage.save_integrity(&integrity_record)?;

            let report = crate::models::seal::RollbackReconciliationReport {
                quarantined_voucher_ids: quarantined,
                archived_voucher_ids: archived.clone(),
                retained_voucher_ids: retained,
                new_tx_nonce: next_nonce,
                consolidated_state_hash: consolidated_hash,
                message: format!(
                    "Backup successfully reconciled with network: {} spent voucher(s) archived, remaining balance secured.",
                    archived.len()
                ),
            };

            Ok(report)
        })
    }

    // --- Internal helper methods (Seal) ---

    fn get_read_auth(
        &self,
        session_cache: &Option<super::SessionCache>,
    ) -> Result<AuthMethod<'_>, Error> {
        match session_cache {
            Some(cache) => {
                if cache.last_activity.elapsed() > cache.session_duration {
                    Err(Error::SessionExpired("Session timed out. Please provide password.".to_string()))
                } else {
                    Ok(AuthMethod::SessionKey(cache.session_key))
                }
            }
            None => Err(Error::SessionNotActive("Password required. Please use 'unlock_session'.".to_string())),
        }
    }

    pub(super) fn verify_seal_on_login(
        storage: &FileStorage,
        password: &str,
        local_instance_id: &str,
    ) -> Result<(), Error> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage.load_seal(&auth).ok().flatten();

        if let Some(record) = &seal_record {
            // Check fork / handover / concurrent clone lock
            if record.is_locked() {
                if let Some(reason) = &record.lock_reason {
                    match reason {
                        crate::models::seal::SealLockReason::SupersededByHandover { target_epoch, .. } => {
                            return Err(Error::WalletSupersededByHandover {
                                target_epoch: *target_epoch,
                                is_seed_recovery: false,
                            });
                        }
                        crate::models::seal::SealLockReason::ConcurrentCloneDetected { .. } => {
                            return Err(Error::WalletConcurrentCloneDetected);
                        }
                        crate::models::seal::SealLockReason::ForkDetected => {
                            return Err(Error::WalletLockedDueToFork);
                        }
                    }
                }
                return Err(Error::WalletLockedDueToFork);
            }

            // Check seal integrity and instance ID
            let validation = record.seal.verify_integrity(
                &record.seal.payload.user_id,
                &record.seal.payload.user_id,
                local_instance_id,
            )?;

            match validation {
                crate::models::seal::SealValidationResult::Valid => {}
                crate::models::seal::SealValidationResult::DeviceMismatch { expected, actual } => {
                    let err_msg = format!(
                        "Device Mismatch: This wallet is bound to device '{}', but you are on '{}'. \
                        To prevent double-spending and permanent reputation loss, a wallet profile (specific User Prefix) \
                        must only be active on ONE device at a time.\n\n\
                        - OPTION A (Move): Perform a 'Device Handover' to permanently move the wallet here. \
                        IMPORTANT: Once handed over, you MUST NOT use this profile on the old device anymore. Please delete the wallet folder on the old device to prevent accidental usage.\n\
                        - OPTION B (Concurrent): Create a NEW profile on this device \
                        with the same Seed Phrase but a DIFFERENT 'User Prefix', then transfer vouchers between them.",
                        expected, actual
                    );
                    return Err(Error::App(crate::error::AppError::DeviceMismatch {
                        message: err_msg,
                    }));
                }
                other => {
                    return Err(Error::App(crate::error::AppError::SealIntegrityFailed {
                        details: format!("{:?}", other),
                    }));
                }
            }

            // Load the RAW own_fingerprints store directly from storage
            let raw_own_fingerprints = storage.load_own_fingerprints(&auth)?;

            let own_fp_hash =
                crate::storage::seal_service::SealService::calculate_state_hash(&raw_own_fingerprints)?;

            let (_, voucher_store, _) = storage.load_wallet(&auth)?;
            let merkle_root = crate::models::seal::calculate_voucher_merkle_root(&voucher_store.vouchers);
            let comp_hash = crate::storage::seal_service::SealService::calculate_comprehensive_state_hash(
                record.seal.payload.epoch as u64,
                record.seal.payload.tx_nonce,
                &merkle_root,
                &own_fp_hash,
            );

            if record.seal.payload.state_hash != comp_hash {
                return Err(Error::StateRollbackDetected);
            }
        }
        Ok(())
    }

    pub(super) fn initialize_seal_if_missing(
        storage: &mut FileStorage,
        wallet: &crate::wallet::Wallet,
        identity: &crate::models::profile::UserIdentity,
        password: &str,
    ) -> Result<(), Error> {
        let auth = AuthMethod::Password(password);
        let seal_record = storage
            .load_seal(&auth)?;

        if seal_record.is_none() {
            let merkle_root = crate::models::seal::calculate_voucher_merkle_root(&wallet.voucher_store.vouchers);
            let own_fp_hash =
                crate::storage::seal_service::SealService::calculate_state_hash(&wallet.own_fingerprints)?;

            let genesis_hash = crate::storage::seal_service::SealService::calculate_comprehensive_state_hash(
                0,
                0,
                &merkle_root,
                &own_fp_hash,
            );
            // Completely new seal (Genesis)
            let new_seal = WalletSeal::create_initial(
                &identity.user_id,
                identity,
                &genesis_hash,
                &wallet.local_instance_id,
            )?;

            let new_record = LocalSealRecord {
                seal: new_seal.clone(),
                sync_status: SyncStatus::PendingUpload,
                lock_reason: None,
                pending_tombstones: Vec::new(),
                last_synced_anchor: None,
            };
            storage
                .save_seal(&auth, &new_record)?;

            // Initialize integrity for the new seal
            let hashes = storage.get_all_item_hashes().unwrap_or_default();
            if let Ok(ir) = StorageIntegrityRecord::create_record(
                identity,
                &new_seal,
                hashes,
            ) {
                let _ = storage.save_integrity(&ir);
            }
        }
        Ok(())
    }

    #[allow(unused_variables)]
    pub(crate) fn get_epoch_info(
        &self,
        password: Option<&str>,
    ) -> Result<Option<(String, u32)>, Error> {
        match &self.state {
            AppState::Unlocked {
                storage,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;
                let record = storage
                    .load_seal(&auth)?;

                match record {
                    Some(r) => Ok(Some((
                        r.seal.payload.epoch_start_time.clone(),
                        r.seal.payload.epoch,
                    ))),
                    None => Ok(None),
                }
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    pub fn update_seal_after_state_change(
        &mut self,
        password: Option<&str>,
    ) -> Result<(), Error> {
        match &mut self.state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                session_cache,
                ..
            } => {
                let auth = Self::resolve_auth_method(password, session_cache)?;
                let tx = storage.begin_wallet_transaction(&auth)?;
                let step = (|| -> Result<(), Error> {
                    storage.commit_wallet_atomic(wallet, identity, &auth)?;
                    crate::storage::seal_service::SealService::persist_seal_for_wallet_state(
                        storage, identity, &auth, wallet,
                    )?;
                    Ok(())
                })();
                if let Err(e) = step {
                    let _ = tx.abort(storage);
                    return Err(e);
                }
                tx.commit(storage)?;
                Ok(())
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    // --- Standard Container Handler (from standard_container_handler) ---

    /// Exports a `VoucherStandardDefinition` (TOML content) as a serialized `SecureContainer` (`.standard` file).
    pub fn export_voucher_standard(
        &self,
        standard_toml: &str,
        config: ContainerConfig,
    ) -> Result<Vec<u8>, Error> {
        // 1. Verify that the TOML content is a valid, signed standard definition.
        let _ = VoucherStandardDefinition::from_toml(standard_toml)?;

        // 2. Ensure wallet is unlocked to get sender identity.
        let identity = self.get_identity()?;

        // 3. Create the secure container with VoucherStandardDefinition payload type.
        let container = SecureContainer::seal(
            identity,
            &config,
            standard_toml.as_bytes(),
            PayloadType::VoucherStandardDefinition,
        )?;

        // 4. Serialize container to JSON bytes.
        serde_json::to_vec(&container).map_err(Error::from)
    }

    /// Inspects a `.standard` container file (`SecureContainer` JSON bytes) without saving it.
    pub fn inspect_voucher_standard_container(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
    ) -> Result<VoucherStandardDefinition, Error> {
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(Error::App(
                        crate::error::AppError::InvalidPayloadTypeVoucherStandardDefinition,
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = container.open(identity, password)?;

                String::from_utf8(payload_bytes).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InContainerPayload {
                        reason: e.to_string(),
                    })
                })?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec()).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InStandardFile {
                        reason: e.to_string(),
                    })
                })?
            }
        };

        let (verified_standard, _) = VoucherStandardDefinition::from_toml(&toml_str)?;
        Ok(verified_standard)
    }

    /// Imports a `.standard` container file or a raw `standard.toml` file into `voucher_standards/`.
    pub fn import_voucher_standard(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
        target_dir: &Path,
    ) -> Result<String, Error> {
        // SECURITY (AUDIT-00-WILDCARD-39): Validate target_dir does not contain relative path traversal
        if target_dir.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(Error::Validation(crate::error::ValidationError::InvalidTransaction(
                "target_dir contains relative path traversal (..)".to_string(),
            )));
        }
        let toml_str = match serde_json::from_slice::<SecureContainer>(container_bytes) {
            Ok(container) => {
                if container.c != PayloadType::VoucherStandardDefinition {
                    return Err(Error::App(
                        crate::error::AppError::InvalidPayloadTypeVoucherStandardDefinition,
                    ));
                }

                let dummy_identity = UserIdentity::default();
                let identity = match &self.state {
                    AppState::Unlocked { identity, .. } => identity,
                    AppState::Locked => &dummy_identity,
                };

                let payload_bytes = container.open(identity, password)?;

                String::from_utf8(payload_bytes).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InContainerPayload {
                        reason: e.to_string(),
                    })
                })?
            }
            Err(_) => {
                String::from_utf8(container_bytes.to_vec()).map_err(|e| {
                    Error::App(crate::error::AppError::InvalidUtf8InStandardFile {
                        reason: e.to_string(),
                    })
                })?
            }
        };

        let (verified_standard, _) = VoucherStandardDefinition::from_toml(&toml_str)?;
        let standard_uuid = verified_standard.immutable.identity.uuid;

        if standard_uuid.is_empty()
            || standard_uuid.contains('/')
            || standard_uuid.contains('\\')
            || standard_uuid.contains("..")
        {
            return Err(Error::App(crate::error::AppError::InvalidStandardUuid {
                uuid: standard_uuid,
            }));
        }

        let standard_folder = target_dir.join(&standard_uuid);
        fs::create_dir_all(&standard_folder)
            .map_err(Error::from)?;

        let file_path = standard_folder.join("standard.toml");

        if file_path.exists() {
            let existing_content = fs::read_to_string(&file_path).map_err(|e| {
                crate::storage::StorageError::Io(format!(
                    "Installed standard.toml for uuid '{}' exists but cannot be read: {}",
                    standard_uuid, e
                ))
            })?;
            if existing_content != toml_str {
                return Err(Error::App(crate::error::AppError::StandardAlreadyInstalled {
                    uuid: standard_uuid.clone(),
                }));
            }
            return Ok(standard_uuid);
        }

        let temp_path = standard_folder.join("standard.toml.tmp");
        fs::write(&temp_path, &toml_str)
            .map_err(Error::from)?;
        fs::rename(&temp_path, &file_path)
            .map_err(Error::from)?;

        Ok(standard_uuid)
    }

    /// Deletes a voucher standard directory if no vouchers referencing it exist in the wallet.
    pub fn delete_voucher_standard(
        &self,
        standard_id: &str,
        target_dir: &Path,
    ) -> Result<(), Error> {
        // SECURITY (AUDIT-00-WILDCARD-39): Validate target_dir does not contain relative path traversal
        if target_dir.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(Error::Validation(crate::error::ValidationError::InvalidTransaction(
                "target_dir contains relative path traversal (..)".to_string(),
            )));
        }

        // 1. Path-traversal validation
        if standard_id.is_empty()
            || standard_id.contains('/')
            || standard_id.contains('\\')
            || standard_id.contains("..")
        {
            return Err(Error::App(
                crate::error::AppError::InvalidStandardIdForDeletion,
            ));
        }

        let standard_folder = target_dir.join(standard_id);
        if !standard_folder.exists() {
            return Ok(());
        }

        // 2. Enforce wallet unlock to verify active vouchers
        let wallet = self.get_wallet()?;
        let identity = self.get_identity()?;

        // 3. Determine standard UUIDs to check
        let mut uuid_to_check = vec![standard_id.to_string()];
        let toml_file = standard_folder.join("standard.toml");
        if toml_file.exists()
            && let Ok(toml_str) = fs::read_to_string(&toml_file)
                && let Ok((def, _)) = VoucherStandardDefinition::from_toml(&toml_str) {
                    let parsed_uuid = def.immutable.identity.uuid;
                    if parsed_uuid != standard_id {
                        uuid_to_check.push(parsed_uuid);
                    }
                }

        // 4. Query wallet vouchers matching resolved UUIDs
        let matching_vouchers = wallet.list_vouchers(
            Some(identity),
            Some(&uuid_to_check),
            None,
            None,
        );

        if !matching_vouchers.is_empty() {
            return Err(Error::App(crate::error::AppError::StandardInUse {
                count: matching_vouchers.len(),
            }));
        }

        // 5. Delete directory
        fs::remove_dir_all(&standard_folder)
            .map_err(Error::from)?;

        Ok(())
    }

    // --- Generic Data Encryption (from data_encryption) ---

    /// Saves an arbitrary byte slice encrypted on the disk.
    #[allow(unused_variables)]
    pub fn save_encrypted_data(
        &mut self,
        name: &str,
        data: &[u8],
        password: Option<&str>,
    ) -> Result<(), Error> {
        let auth_method = match password {
            Some(pwd) => AuthMethod::Password(pwd),
            None => AuthMethod::SessionKey(self.get_session_key()?),
        };
        match &mut self.state {
            AppState::Unlocked {
                storage, identity, ..
            } => {
                let _lock_guard =
                    WalletLockGuard::new(storage)?;
                storage
                    .save_arbitrary_data(&auth_method, name, data)?;
                if name != "__storage_session_anchor" {
                    self.update_seal_after_state_change(password)?;
                }
                Ok(())
            }
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    /// Loads and decrypts a previously saved, arbitrary data block.
    #[allow(unused_variables)]
    pub fn load_encrypted_data(
        &mut self,
        name: &str,
        password: Option<&str>,
    ) -> Result<Vec<u8>, Error> {
        let auth_method = match password {
            Some(pwd) => AuthMethod::Password(pwd),
            None => AuthMethod::SessionKey(self.get_session_key()?),
        };
        match &self.state {
            AppState::Unlocked {
                storage, identity, ..
            } => storage
                .load_arbitrary_data(&auth_method, name)
                .map_err(Error::from),
            AppState::Locked => Err(Error::WalletLocked),
        }
    }

    // --- Web-of-Trust Container Helpers ---

    /// Seals and signs a .wot trust container payload.
    /// Trust containers MUST be encrypted (TargetDid, TargetDids, or Password);
    /// Cleartext configuration is rejected (CWE-311/CWE-347 prevention).
    pub fn seal_trust_container(
        &self,
        payload: &[u8],
        config: ContainerConfig,
    ) -> Result<Vec<u8>, Error> {
        if matches!(config, ContainerConfig::Cleartext) {
            return Err(Error::PlaintextNotAllowedForFinancialPayload);
        }

        let identity = self.get_identity()?;
        let container = SecureContainer::seal(
            identity,
            &config,
            payload,
            PayloadType::TrustAssertion,
        )?;

        serde_json::to_vec(&container).map_err(Error::from)
    }

    /// Opens, decrypts, and cryptographically authenticates a .wot trust container.
    ///
    /// CWE-347 Prevention: SecureContainer::open only decrypts the AEAD ciphertext;
    /// this function additionally verifies container integrity and validates
    /// the container's Ed25519 envelope signature against the extracted sender ID.
    pub fn open_trust_container<F>(
        &self,
        container_bytes: &[u8],
        password: Option<&str>,
        extract_sender_id: F,
    ) -> Result<Vec<u8>, Error>
    where
        F: FnOnce(&[u8]) -> Result<String, Error>,
    {
        if container_bytes.len() > crate::services::bundle_processor::MAX_CONTAINER_BYTES {
            return Err(Error::Validation(
                crate::error::ValidationError::InvalidTransaction(format!(
                    "Container exceeds maximum size ({} > {} bytes)",
                    container_bytes.len(),
                    crate::services::bundle_processor::MAX_CONTAINER_BYTES
                )),
            ));
        }

        let identity = self.get_identity()?;
        let container: SecureContainer = serde_json::from_slice(container_bytes)?;

        if container.c != PayloadType::TrustAssertion {
            return Err(Error::InvalidPayloadType);
        }

        if container.et == crate::models::secure_container::EncryptionType::None {
            return Err(Error::PlaintextNotAllowedForFinancialPayload);
        }

        container.verify_integrity()?;

        let plaintext = container.open(identity, password)?;

        let sender_id = extract_sender_id(&plaintext)?;

        if container.signature.is_empty() {
            return Err(Error::Validation(
                crate::error::ValidationError::InvalidContainerSignature,
            ));
        }

        container.verify_container_signature(&sender_id)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MnemonicLanguage;
    use std::path::PathBuf;

    fn setup_test_app(dir_name: &str) -> (AppService, PathBuf) {
        let temp_dir = std::env::temp_dir().join(dir_name);
        if temp_dir.exists() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        let _ = fs::create_dir_all(&temp_dir);

        let mut app = AppService::new(&temp_dir).unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        app.create_profile(
            "Test Profile",
            mnemonic,
            None,
            Some("test"),
            "password123",
            MnemonicLanguage::English,
            "device-id".to_string(),
        )
        .unwrap();

        (app, temp_dir)
    }

    const SAMPLE_TOML: &str = r#"
[immutable.identity]
uuid = "test-standard-uuid-12345"
name = "Test Currency Standard"
abbreviation = "TCS"

[immutable.blueprint]
unit = "TestUnit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init", "transfer"]

[immutable.issuance]
validity_duration_range = ["P1M", "P1Y"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["issuer"]

[mutable.metadata]
issuer_name = "Test Issuer"

[signature]
issuer_id = "0:riw@did:key:z6Mki8QqVMb66hjtTwcceVXbZuSHTk61jqiprRvEhuotZmSA"
signature = "5aomSjj76rEb4VVjhAd6p6qvmU79wkkTpj84AnY3D9p8xRDNfxBqKL4EbEHTKfPevggafJeJuzhgYV4rvhLgMs5m"
"#;

    #[test]
    fn test_export_inspect_import_standard_cleartext() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_cleartext");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Cleartext)
            .expect("Export cleartext standard failed");
        assert!(!container_bytes.is_empty());

        let def = app
            .inspect_voucher_standard_container(&container_bytes, None)
            .expect("Inspect standard failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");
        assert_eq!(def.immutable.identity.name, "Test Currency Standard");

        let uuid = app
            .import_voucher_standard(&container_bytes, None, &target_standards_dir)
            .expect("Import standard failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());
        let content = fs::read_to_string(&saved_file).unwrap();
        assert!(content.contains("test-standard-uuid-12345"));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_export_inspect_import_standard_password() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_password");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let password = "SecretStandardPassword123";
        let container_bytes = app
            .export_voucher_standard(SAMPLE_TOML, ContainerConfig::Password(password.to_string()))
            .expect("Export password standard failed");

        let wrong_inspect = app.inspect_voucher_standard_container(&container_bytes, Some("WrongPassword"));
        assert!(wrong_inspect.is_err());

        let def = app
            .inspect_voucher_standard_container(&container_bytes, Some(password))
            .expect("Inspect with correct password failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        let uuid = app
            .import_voucher_standard(&container_bytes, Some(password), &target_standards_dir)
            .expect("Import with correct password failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_invalid_payload_type() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, _) = setup_test_app("test_standard_invalid_payload");
        let identity = app.get_identity().unwrap();

        let container = SecureContainer::seal(
            identity,
            &ContainerConfig::Cleartext,
            SAMPLE_TOML.as_bytes(),
            PayloadType::VoucherForSigning,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&container).unwrap();

        let result = app.inspect_voucher_standard_container(&bytes, None);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Invalid payload type"),
            "Expected error containing 'Invalid payload type', got: {}",
            err_str
        );

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_inspect_import_raw_toml() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_standard_raw_toml");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let raw_toml_bytes = SAMPLE_TOML.as_bytes();

        let def = app
            .inspect_voucher_standard_container(raw_toml_bytes, None)
            .expect("Inspect raw TOML failed");
        assert_eq!(def.immutable.identity.uuid, "test-standard-uuid-12345");

        let uuid = app
            .import_voucher_standard(raw_toml_bytes, None, &target_standards_dir)
            .expect("Import raw TOML failed");
        assert_eq!(uuid, "test-standard-uuid-12345");

        let saved_file = target_standards_dir
            .join("test-standard-uuid-12345")
            .join("standard.toml");
        assert!(saved_file.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_success_when_no_vouchers() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (app, temp_dir) = setup_test_app("test_delete_standard_success");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");
        let standard_folder = target_standards_dir.join(&uuid);
        assert!(standard_folder.exists());

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(result.is_ok());
        assert!(!standard_folder.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_vouchers_exist() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_vouchers_exist");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");
        assert!(target_standards_dir.join(&uuid).exists());

        let (def, def_hash) = VoucherStandardDefinition::from_toml(SAMPLE_TOML).unwrap();
        let identity = app.get_identity().unwrap();
        let creator_profile = crate::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            ..Default::default()
        };
        let voucher_data = crate::test_utils::voucher_setup::create_minuto_voucher_data(creator_profile);
        let voucher = crate::test_utils::voucher_setup::create_voucher_for_manipulation(
            voucher_data,
            &def,
            &def_hash,
            &identity.signing_key,
        );

        {
            let (wallet, _) = app.get_unlocked_mut_for_test();
            wallet.add_voucher_instance("test_inst_1".to_string(), voucher, crate::wallet::instance::VoucherStatus::Active);
        }

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("still in use"),
            "Expected error containing 'still in use', got: {}",
            err_str
        );

        assert!(target_standards_dir.join(&uuid).exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_folder_name_differs_from_uuid() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_folder_mismatch");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let custom_folder = target_standards_dir.join("minuto_v1");
        fs::create_dir_all(&custom_folder).unwrap();
        fs::write(custom_folder.join("standard.toml"), SAMPLE_TOML).unwrap();

        let (def, def_hash) = VoucherStandardDefinition::from_toml(SAMPLE_TOML).unwrap();
        let identity = app.get_identity().unwrap();
        let creator_profile = crate::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            ..Default::default()
        };
        let voucher_data = crate::test_utils::voucher_setup::create_minuto_voucher_data(creator_profile);
        let voucher = crate::test_utils::voucher_setup::create_voucher_for_manipulation(
            voucher_data,
            &def,
            &def_hash,
            &identity.signing_key,
        );

        {
            let (wallet, _) = app.get_unlocked_mut_for_test();
            wallet.add_voucher_instance("test_inst_2".to_string(), voucher, crate::wallet::instance::VoucherStatus::Active);
        }

        let result = app.delete_voucher_standard("minuto_v1", &target_standards_dir);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("still in use"),
            "Expected error containing 'still in use', got: {}",
            err_str
        );

        assert!(custom_folder.exists());

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_fails_when_wallet_locked() {
        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(true);

        let (mut app, temp_dir) = setup_test_app("test_delete_standard_locked");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let uuid = app
            .import_voucher_standard(SAMPLE_TOML.as_bytes(), None, &target_standards_dir)
            .expect("Import standard failed");

        app.logout();

        let result = app.delete_voucher_standard(&uuid, &target_standards_dir);
        assert!(matches!(result, Err(Error::WalletLocked)));

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);
    }

    #[test]
    fn test_delete_standard_rejects_path_traversal() {
        let (app, temp_dir) = setup_test_app("test_delete_standard_traversal");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let result = app.delete_voucher_standard("../other_dir", &target_standards_dir);
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("Invalid standard ID"),
            "Expected error containing 'Invalid standard ID', got: {}",
            err_str
        );
    }

    #[test]
    fn test_delete_non_existent_standard() {
        let (app, temp_dir) = setup_test_app("test_delete_non_existent");
        let target_standards_dir = temp_dir.join("voucher_standards");

        let result = app.delete_voucher_standard("non_existent_id", &target_standards_dir);
        assert!(result.is_ok());
    }

    #[test]
    fn test_seal_open_trust_container_target_did() {
        let (alice, _alice_dir) = setup_test_app("test_wot_target_did_alice");
        let dir_bob = std::env::temp_dir().join("test_wot_target_did_bob");
        if dir_bob.exists() {
            let _ = fs::remove_dir_all(&dir_bob);
        }
        let _ = fs::create_dir_all(&dir_bob);
        let mut bob = AppService::new(&dir_bob).unwrap();
        let bob_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        bob.create_profile(
            "Bob Profile",
            bob_mnemonic,
            None,
            Some("bob"),
            "password123",
            MnemonicLanguage::English,
            "device-bob".to_string(),
        )
        .unwrap();

        let alice_id = alice.get_identity().unwrap().user_id.clone();
        let bob_id = bob.get_identity().unwrap().user_id.clone();

        let payload = br#"{"version":1,"claims":[{"sub":"did:key:z123","level":2}]}"#;

        let container_bytes = alice
            .seal_trust_container(
                payload,
                ContainerConfig::TargetDid(bob_id.clone(), crate::models::secure_container::PrivacyMode::TrialDecryption),
            )
            .expect("Alice seal trust container must succeed");

        let decrypted = bob
            .open_trust_container(&container_bytes, None, |_| Ok(alice_id.clone()))
            .expect("Bob open trust container must succeed");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_seal_open_trust_container_password() {
        let (alice, _alice_dir) = setup_test_app("test_wot_pwd_alice");
        let dir_bob = std::env::temp_dir().join("test_wot_pwd_bob");
        if dir_bob.exists() {
            let _ = fs::remove_dir_all(&dir_bob);
        }
        let _ = fs::create_dir_all(&dir_bob);
        let mut bob = AppService::new(&dir_bob).unwrap();
        let bob_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        bob.create_profile(
            "Bob Profile",
            bob_mnemonic,
            None,
            Some("bob"),
            "password123",
            MnemonicLanguage::English,
            "device-bob".to_string(),
        )
        .unwrap();

        let alice_id = alice.get_identity().unwrap().user_id.clone();
        let payload = br#"{"symmetric_wot_sync":true}"#;
        let password = "WotContainerPassword999";

        let container_bytes = alice
            .seal_trust_container(payload, ContainerConfig::Password(password.to_string()))
            .expect("Alice seal trust container with password must succeed");

        // Wrong password fails
        let wrong_open = bob.open_trust_container(&container_bytes, Some("WrongPassword"), |_| Ok(alice_id.clone()));
        assert!(wrong_open.is_err());

        // Correct password succeeds
        let decrypted = bob
            .open_trust_container(&container_bytes, Some(password), |_| Ok(alice_id.clone()))
            .expect("Bob open trust container with correct password must succeed");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_seal_open_trust_container_spoofed_sender_rejected() {
        let (alice, _alice_dir) = setup_test_app("test_wot_spoof_alice");
        let dir_bob = std::env::temp_dir().join("test_wot_spoof_bob");
        if dir_bob.exists() {
            let _ = fs::remove_dir_all(&dir_bob);
        }
        let _ = fs::create_dir_all(&dir_bob);
        let mut bob = AppService::new(&dir_bob).unwrap();
        let bob_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        bob.create_profile(
            "Bob Profile",
            bob_mnemonic,
            None,
            Some("bob"),
            "password123",
            MnemonicLanguage::English,
            "device-bob".to_string(),
        )
        .unwrap();

        let bob_id = bob.get_identity().unwrap().user_id.clone();
        let payload = br#"{"claimed_sender":"did:key:zBob","payload":"tampered"}"#;
        let password = "WotContainerPassword999";

        // Alice seals container
        let container_bytes = alice
            .seal_trust_container(payload, ContainerConfig::Password(password.to_string()))
            .expect("Alice seal container must succeed");

        // Bob opens container, but extract_sender_id claims the sender was Bob!
        // Signature verification MUST fail because container was signed by Alice!
        let result = bob.open_trust_container(&container_bytes, Some(password), |_| Ok(bob_id.clone()));
        assert!(result.is_err(), "Spoofed sender DID must fail signature verification");
        let err = result.unwrap_err();
        assert!(
            matches!(err, Error::Validation(crate::error::ValidationError::InvalidContainerSignature)),
            "Expected InvalidContainerSignature, got: {:?}",
            err
        );
    }

    #[test]
    fn test_seal_trust_container_rejects_cleartext() {
        let (alice, _alice_dir) = setup_test_app("test_wot_cleartext");
        let result = alice.seal_trust_container(b"cleartext_data", ContainerConfig::Cleartext);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::PlaintextNotAllowedForFinancialPayload
        ));
    }
}
