//! Durable exact-byte send intents. No transport or outcome guess can free an
//! uncertain output; matching retained originals are observations, not clearance.
use super::{AppService, TransactionOutcome};
use crate::{Error, models::layer2_api::L2LockRequest};
use serde::Deserialize;

pub use crate::models::l2_intent::{IntentTerminalResolution, L2SendIntent};
use rand_core::RngCore;
fn invalid(reason: &str) -> Error {
    Error::Validation(crate::error::ValidationError::SecurityViolation(
        reason.into(),
    ))
}
fn terminal_resolved_at(resolution: &IntentTerminalResolution) -> u64 {
    match resolution {
        IntentTerminalResolution::Confirmed { resolved_at_ms }
        | IntentTerminalResolution::Conflicted { resolved_at_ms, .. }
        | IntentTerminalResolution::Expired { resolved_at_ms } => *resolved_at_ms,
    }
}
impl AppService {
    /// Authenticates, reloads and durably commits exact bytes BEFORE a host may
    /// begin HTTP. An existing intent is returned unchanged even after timeout.
    pub fn prepare_l2_send_intent(
        &mut self,
        local_id: &str,
        network: u8,
        password: Option<&str>,
    ) -> Result<L2SendIntent, Error> {
        self.with_transactional_mut(password, |wallet, _, _, _| {
            let result = if let Some(intent) = wallet.profile.l2_send_intents.get(local_id) {
                if intent.network == network { Ok(intent.clone()) } else { Err(invalid("pending intent network cannot change")) }
            } else {
                let voucher = wallet.get_voucher_instance(local_id)
                    .ok_or_else(|| Error::VoucherNotFound(local_id.into()))
                    .map(|instance|instance.voucher.clone());
                voucher.and_then(|voucher|wallet.stage_l2_send_intent(local_id,&voucher,network))
            };
            match result {
                Ok(intent) => TransactionOutcome::Commit(intent),
                Err(error) => TransactionOutcome::Rollback(error),
            }
        })
    }
    /// Reads committed intent bytes. This method never creates a fresh request.
    pub fn pending_l2_send_intent(&self, local_id: &str) -> Result<L2SendIntent, Error> {
        self.get_wallet()?
            .profile
            .l2_send_intents
            .get(local_id)
            .cloned()
            .ok_or_else(|| invalid("pending intent missing"))
    }
    /// Enumerates every intent whose outcome is still unresolved in a stable order.
    pub fn unresolved_l2_send_intents(&self) -> Result<Vec<L2SendIntent>, Error> {
        let wallet = self.get_wallet()?;
        let mut intents: Vec<L2SendIntent> = wallet
            .profile
            .l2_send_intents
            .values()
            .filter(|intent| intent.terminal_resolution.is_none())
            .cloned()
            .collect();
        intents.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.local_instance_id.cmp(&b.local_instance_id))
        });
        Ok(intents)
    }
    /// Returns the original lookup target after thirty seconds. A host performs
    /// the read; Core stays network-free and never synthesizes a new wallet T0.
    pub fn retained_choice_target(&self, local_id: &str, now_ms: u64) -> Result<String, Error> {
        let intent = self.pending_l2_send_intent(local_id)?;
        if now_ms < intent.created_at_ms.saturating_add(30_000) {
            return Err(invalid("intent reconciliation is not due"));
        }
        let request: L2LockRequest = serde_json::from_slice(&intent.request_bytes)?;
        if request.is_genesis {
            Ok(bs58::encode(request.transaction_hash).into_string())
        } else {
            request
                .ds_tag
                .ok_or_else(|| invalid("intent parent missing"))
        }
    }
    /// Validates exact retained original bytes as first-party evidence. This is
    /// deliberately not an authority/quorum check and does not free the output.
    pub fn record_retained_choice_observation(
        &mut self,
        local_id: &str,
        response: &[u8],
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<bool, Error> {
        if response.len() > 65_536 {
            return Err(invalid("retained response too large"));
        }
        #[derive(Deserialize)]
        struct Retained {
            found: bool,
            #[serde(default)]
            network: u8,
            #[serde(default)]
            lookup_tag: String,
            #[serde(default)]
            child: String,
            #[serde(default)]
            node_pubkey: String,
            #[serde(default)]
            purpose: String,
            #[serde(default)]
            version: u8,
            #[serde(default)]
            final_approval: Option<String>,
            #[serde(default)]
            provisional_approval: Option<String>,
        }
        let value: Retained = serde_json::from_slice(response)?;
        if !value.found {
            return Ok(false);
        }
        let intent = self.pending_l2_send_intent(local_id)?;
        let tag = self.retained_choice_target(local_id, now_ms)?;
        let request: L2LockRequest = serde_json::from_slice(&intent.request_bytes)?;
        if value.network != intent.network
            || value.lookup_tag != tag
            || value.child != hex::encode(request.transaction_hash)
            || value.purpose != "original_approval"
            || value.version != 1
            || now_ms >= intent.root_valid_until_ms
        {
            return Err(invalid("retained context mismatch"));
        }
        let (status, raw) = if let Some(raw) = value.final_approval {
            (1, raw)
        } else if let Some(raw) = value.provisional_approval {
            (0, raw)
        } else {
            return Err(invalid("retained original missing"));
        };
        let bytes = hex::decode(raw).map_err(|_| invalid("invalid retained bytes"))?;
        let approval: crate::models::layer2_api::AttestationDto =
            bincode::deserialize(&bytes).map_err(|_| invalid("invalid retained approval"))?;
        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
        if approval.node_pubkey != value.node_pubkey
            || approval.lock_id != value.child
            || approval.parent_lock != hex::encode(parent)
            || approval.shard_id != intent.shard_id
        {
            return Err(invalid("retained approval transplant"));
        }
        let key = approval
            .node_pubkey_bytes()
            .ok_or_else(|| invalid("retained signer missing"))?;
        let sig: [u8; 64] = hex::decode(&approval.signature)
            .map_err(|_| invalid("retained signature malformed"))?
            .try_into()
            .map_err(|_| invalid("retained signature malformed"))?;
        let digest = humoco_proto::live::original_approval_digest(
            intent.network,
            intent.shard_id,
            status,
            &parent,
            &request.transaction_hash,
        )
        .map_err(invalid)?;
        ed25519_dalek::VerifyingKey::from_bytes(&key)
            .map_err(|_| invalid("retained key malformed"))?
            .verify_strict(&digest, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| invalid("retained signature invalid"))?;
        self.with_transactional_mut(password, |wallet, _, _, _| {
            let Some(current) = wallet.profile.l2_send_intents.get_mut(local_id) else {
                return TransactionOutcome::Rollback(invalid("intent disappeared"));
            };
            if current.request_bytes != intent.request_bytes || current.network != intent.network {
                return TransactionOutcome::Rollback(invalid(
                    "intent changed during reconciliation",
                ));
            }
            current.retained_original_observed = true;
            TransactionOutcome::Commit(true)
        })
    }

    /// Initiates authenticated live-state quorum reconciliation for a pending intent.
    /// Available 30 seconds after intent creation, binds an unpredictable fresh challenge,
    /// and derives the required committee from the wallet's regional mesh policy.
    pub fn begin_intent_reconciliation(
        &mut self,
        local_id: &str,
        views: &[humoco_proto::mesh::RegionalMeshView],
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<humoco_proto::live::LiveStateContext, Error> {
        let intent = self.pending_l2_send_intent(local_id)?;
        if now_ms < intent.created_at_ms.saturating_add(30_000) {
            return Err(invalid("intent reconciliation is not due"));
        }
        if now_ms >= intent.root_valid_until_ms {
            return Err(invalid("intent root expired"));
        }
        let request: L2LockRequest = serde_json::from_slice(&intent.request_bytes)?;
        let tag = if request.is_genesis {
            bs58::encode(request.transaction_hash).into_string()
        } else {
            request.ds_tag.clone().ok_or_else(|| invalid("intent parent missing"))?
        };
        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
        let entry = crate::models::layer2_api::L2LockEntry::from(&request);
        let state_digest = *blake3::hash(&serde_json::to_vec(&entry)?).as_bytes();

        let mut nonce = [0u8; 32];
        rand_core::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| invalid("reconciliation entropy unavailable"))?;
        if nonce == [0u8; 32] {
            return Err(invalid("invalid reconciliation entropy"));
        }

        self.with_transactional_mut(password, |wallet, _, _, _| {
            let result = (|| {
                let policy = wallet
                    .profile
                    .l2_regional_mesh_policy
                    .as_ref()
                    .ok_or_else(|| invalid("reconciliation authority missing"))?;
                let committee =
                    humoco_proto::mesh::regional_committee(policy, views, intent.shard_id, now_ms)
                        .map_err(invalid)?;
                let current = wallet.profile.l2_send_intents.get_mut(local_id)
                    .ok_or_else(|| invalid("intent disappeared"))?;
                if current.request_bytes != intent.request_bytes || current.network != intent.network {
                    return Err(invalid("intent changed during reconciliation"));
                }
                current.stored_challenge = Some(nonce);

                let context = humoco_proto::live::LiveStateContext {
                    version: 1,
                    network: intent.network,
                    shard_id: intent.shard_id,
                    voucher_id: request.layer2_voucher_id.clone(),
                    lookup_tag: tag.clone(),
                    parent_lock: parent,
                    child_lock: request.transaction_hash,
                    root_valid_until: intent.root_valid_until_ms,
                    state_digest,
                    recipient_nonce: nonce,
                    committee,
                };
                Ok(context)
            })();
            match result {
                Ok(context) => TransactionOutcome::Commit(context),
                Err(error) => TransactionOutcome::Rollback(error),
            }
        })
    }

    /// Verifies current live-state quorum proof against the stored fresh challenge and
    /// the intent's context. Terminally resolves the intent as Confirmed upon valid 14/20 quorum.
    pub fn complete_intent_reconciliation(
        &mut self,
        local_id: &str,
        proof: &humoco_proto::live::LiveStateProof,
        views: &[humoco_proto::mesh::RegionalMeshView],
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<IntentTerminalResolution, Error> {
        self.with_transactional_mut(password, |wallet, _, _, _| {
            let Some(intent) = wallet.profile.l2_send_intents.get_mut(local_id) else {
                return TransactionOutcome::Rollback(invalid("intent disappeared"));
            };
            if let Some(res) = &intent.terminal_resolution {
                return TransactionOutcome::Commit(res.clone());
            }
            let stored_nonce = match intent.stored_challenge {
                Some(n) => n,
                None => return TransactionOutcome::Rollback(invalid("stored reconciliation challenge missing")),
            };
            if proof.context.recipient_nonce != stored_nonce {
                return TransactionOutcome::Rollback(invalid("reconciliation challenge mismatch"));
            }
            if now_ms >= intent.root_valid_until_ms {
                let res = IntentTerminalResolution::Expired { resolved_at_ms: now_ms };
                intent.terminal_resolution = Some(res.clone());
                return TransactionOutcome::Commit(res);
            }
            let request: L2LockRequest = match serde_json::from_slice(&intent.request_bytes) {
                Ok(r) => r,
                Err(e) => return TransactionOutcome::Rollback(invalid(&e.to_string())),
            };
            let tag = if request.is_genesis {
                bs58::encode(request.transaction_hash).into_string()
            } else {
                match &request.ds_tag {
                    Some(t) => t.clone(),
                    None => return TransactionOutcome::Rollback(invalid("intent parent missing")),
                }
            };
            let parent = *blake3::hash(tag.as_bytes()).as_bytes();
            let entry = crate::models::layer2_api::L2LockEntry::from(&request);
            let state_digest = match serde_json::to_vec(&entry) {
                Ok(bytes) => *blake3::hash(&bytes).as_bytes(),
                Err(e) => return TransactionOutcome::Rollback(invalid(&e.to_string())),
            };
            let policy = match wallet.profile.l2_regional_mesh_policy.as_ref() {
                Some(p) => p,
                None => return TransactionOutcome::Rollback(invalid("reconciliation authority missing")),
            };
            let committee = match humoco_proto::mesh::regional_committee(policy, views, intent.shard_id, now_ms) {
                Ok(c) => c,
                Err(e) => return TransactionOutcome::Rollback(invalid(e)),
            };
            let expected_context = humoco_proto::live::LiveStateContext {
                version: 1,
                network: intent.network,
                shard_id: intent.shard_id,
                voucher_id: request.layer2_voucher_id,
                lookup_tag: tag,
                parent_lock: parent,
                child_lock: request.transaction_hash,
                root_valid_until: intent.root_valid_until_ms,
                state_digest,
                recipient_nonce: stored_nonce,
                committee,
            };
            let res = if proof.context.child_lock == request.transaction_hash {
                if let Err(e) =
                    humoco_proto::live::verify_live_state_proof(proof, &expected_context)
                {
                    return TransactionOutcome::Rollback(invalid(e));
                }
                IntentTerminalResolution::Confirmed { resolved_at_ms: now_ms }
            } else {
                let expected_conflict_context = humoco_proto::live::LiveStateContext {
                    child_lock: proof.context.child_lock,
                    state_digest: proof.context.state_digest,
                    ..expected_context
                };
                if let Err(e) =
                    humoco_proto::live::verify_live_state_proof(proof, &expected_conflict_context)
                {
                    return TransactionOutcome::Rollback(invalid(e));
                }
                intent.retained_original_observed = false;
                IntentTerminalResolution::Conflicted {
                    resolved_at_ms: now_ms,
                    observed_child: hex::encode(proof.context.child_lock),
                }
            };
            intent.terminal_resolution = Some(res.clone());
            intent.stored_challenge = None;
            TransactionOutcome::Commit(res)
        })
    }

    /// Records a quorum-proven conflicting child spend for the intent's parent lock.
    /// Delegates verification to reconciliation and requires a Conflicted outcome.
    pub fn record_intent_conflict(
        &mut self,
        local_id: &str,
        proof: &humoco_proto::live::LiveStateProof,
        views: &[humoco_proto::mesh::RegionalMeshView],
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<IntentTerminalResolution, Error> {
        let resolution =
            self.complete_intent_reconciliation(local_id, proof, views, now_ms, password)?;
        match resolution {
            IntentTerminalResolution::Conflicted { .. } => Ok(resolution),
            _ => Err(invalid("proof did not establish a conflicting choice")),
        }
    }

    /// Checks and marks the intent Expired if physical root validity has passed.
    pub fn expire_intent_if_overdue(
        &mut self,
        local_id: &str,
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<Option<IntentTerminalResolution>, Error> {
        self.with_transactional_mut(password, |wallet, _, _, _| {
            let Some(intent) = wallet.profile.l2_send_intents.get_mut(local_id) else {
                return TransactionOutcome::Commit(None);
            };
            if let Some(res) = &intent.terminal_resolution {
                return TransactionOutcome::Commit(Some(res.clone()));
            }
            if now_ms >= intent.root_valid_until_ms {
                let res = IntentTerminalResolution::Expired { resolved_at_ms: now_ms };
                intent.terminal_resolution = Some(res.clone());
                intent.stored_challenge = None;
                TransactionOutcome::Commit(Some(res))
            } else {
                TransactionOutcome::Commit(None)
            }
        })
    }

    /// Cleans up terminally resolved intents that have reached the end of their retention
    /// window or physical root validity plus grace period.
    pub fn cleanup_terminal_intents(
        &mut self,
        max_retain_ms: u64,
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<usize, Error> {
        let needs_cleanup = self.get_wallet()?.profile.l2_send_intents.values().any(|intent| {
            intent.terminal_resolution.as_ref().is_some_and(|res| {
                now_ms >= terminal_resolved_at(res).saturating_add(max_retain_ms)
            }) || now_ms >= intent.root_valid_until_ms.saturating_add(30_000)
        });
        if !needs_cleanup {
            return Ok(0);
        }
        self.with_transactional_mut(password, |wallet, _, _, _| {
            let initial_count = wallet.profile.l2_send_intents.len();
            wallet.profile.l2_send_intents.retain(|_, intent| {
                if let Some(res) = &intent.terminal_resolution {
                    if now_ms >= terminal_resolved_at(res).saturating_add(max_retain_ms) {
                        return false;
                    }
                }
                if now_ms >= intent.root_valid_until_ms.saturating_add(30_000) {
                    return false;
                }
                true
            });
            let removed = initial_count.saturating_sub(wallet.profile.l2_send_intents.len());
            if removed == 0 {
                TransactionOutcome::Abort(0)
            } else {
                TransactionOutcome::Commit(removed)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NewVoucherData,
        models::{profile::PublicProfile, voucher::ValueDefinition},
        test_utils::{self, ACTORS},
    };
    #[test]
    fn exact_intent_is_durable_before_transport_and_blocks_replacement_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let password = "durable-intent-password";
        let (mut app, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Intent",
            password,
        );
        let user = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        let standard = test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        app.create_new_voucher(
            &standard,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(user),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();
        let local_id = app
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();
        let intent = app
            .prepare_l2_send_intent(&local_id, 0, Some(password))
            .unwrap();
        assert_eq!(
            app.prepare_l2_send_intent(&local_id, 0, Some(password))
                .unwrap(),
            intent
        );
        let request: L2LockRequest = serde_json::from_slice(&intent.request_bytes).unwrap();
        assert_eq!(request.created_at_ms, intent.created_at_ms);
        assert!(!intent.transaction_bytes.is_empty());
        assert!(
            app.retained_choice_target(&local_id, intent.created_at_ms + 29_999)
                .is_err()
        );
        assert!(
            app.retained_choice_target(&local_id, intent.created_at_ms + 30_000)
                .is_ok()
        );
        assert!(
            !serde_json::to_string(&app.get_wallet().unwrap().profile.to_public_profile())
                .unwrap()
                .contains("l2_send_intents")
        );
        app.logout();
        drop(app);
        let mut app = AppService::new(dir.path()).unwrap();
        app.login(&profile.folder_name, password, false, "test-id".into())
            .unwrap();
        assert_eq!(app.pending_l2_send_intent(&local_id).unwrap(), intent);
        assert_eq!(
            app.prepare_l2_send_intent(&local_id, 0, Some(password))
                .unwrap()
                .request_bytes,
            intent.request_bytes
        );
        use ed25519_dalek::Signer;
        let node = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
        let tag = app
            .retained_choice_target(&local_id, intent.created_at_ms + 30_000)
            .unwrap();
        let parent = *blake3::hash(tag.as_bytes()).as_bytes();
        let digest = humoco_proto::live::original_approval_digest(
            0,
            intent.shard_id,
            1,
            &parent,
            &request.transaction_hash,
        )
        .unwrap();
        let mut approval = crate::models::layer2_api::AttestationDto {
            lock_id: hex::encode(request.transaction_hash),
            parent_lock: hex::encode(parent),
            node_id: 77,
            node_pubkey: hex::encode(node.verifying_key().to_bytes()),
            timestamp: intent.created_at_ms,
            signature: hex::encode([0; 64]),
            shard_id: intent.shard_id,
        };
        let response = |att: &crate::models::layer2_api::AttestationDto| {
            serde_json::to_vec(&serde_json::json!({
            "found":true,"network":0,"lookup_tag":tag,"child":att.lock_id,"node_pubkey":att.node_pubkey,
            "purpose":"original_approval","version":1,"final_approval":hex::encode(bincode::serialize(att).unwrap())
        })).unwrap()
        };
        assert!(
            app.record_retained_choice_observation(
                &local_id,
                &response(&approval),
                intent.created_at_ms + 30_000,
                Some(password)
            )
            .is_err()
        );
        assert!(
            !app.pending_l2_send_intent(&local_id)
                .unwrap()
                .retained_original_observed
        );
        approval.signature = hex::encode(node.sign(&digest).to_bytes());
        assert!(
            app.record_retained_choice_observation(
                &local_id,
                &response(&approval),
                intent.created_at_ms + 30_000,
                Some(password)
            )
            .unwrap()
        );
        assert!(
            app.pending_l2_send_intent(&local_id)
                .unwrap()
                .retained_original_observed
        );
        // Even a genuine retained original from one node is no current quorum:
        // the exact output remains pending and cannot fund a replacement.
        let result = app.create_transfer_bundle(
            crate::wallet::MultiTransferRequest {
                recipient_id: ACTORS.bob.user_id.clone(),
                sources: vec![crate::wallet::SourceTransfer {
                    local_instance_id: local_id,
                    amount_to_send: "1".into(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            &std::collections::HashMap::new(),
            None,
            Some(password),
        );
        assert!(
            matches!(result,Err(Error::Validation(crate::error::ValidationError::SecurityViolation(ref reason))) if reason.contains("unresolved durable L2 send intent")),
            "{result:?}"
        );
    }

    #[test]
    fn terminal_reconciliation_verifies_quorum_rejects_conflicts_and_cleans_up() {
        use ed25519_dalek::{Signer, SigningKey};
        use humoco_proto::{AttestationVote, live::LiveStateProof, mesh::{RegionalMeshMember, RegionalMeshPolicy, RegionalMeshView}};

        let dir = tempfile::tempdir().unwrap();
        let password = "terminal-reconcile-test";
        let (mut app, _profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "ReconcileSender",
            password,
        );
        let user = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        let standard = test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        let voucher = app.create_new_voucher(
            &standard,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(user),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();
        let local_id = app
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();

        let standards = std::collections::HashMap::from([(voucher.voucher_standard.uuid.clone(), standard)]);
        let _bundle = app.create_transfer_bundle_with_l2_intents(
            crate::wallet::MultiTransferRequest {
                recipient_id: ACTORS.bob.user_id.clone(),
                sources: vec![crate::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "10".into(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: Some(false),
            },
            &standards,
            None,
            Some(password),
            0,
        )
        .unwrap();

        let intent = app.pending_l2_send_intent(&local_id).unwrap();
        let now_ms = intent.created_at_ms;

        // 1. Before 30s, reconciliation is rejected
        let source = SigningKey::from_bytes(&[101; 32]);
        let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let mut members: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| RegionalMeshMember {
                node_pubkey: key.verifying_key().to_bytes(),
                hrw_routing_id: [i as u8; 32],
            })
            .collect();
        members.sort_by_key(|m| m.node_pubkey);
        let mut view = RegionalMeshView {
            version: 1,
            network: 0,
            source_key: source.verifying_key().to_bytes(),
            issued_at_ms: now_ms,
            valid_until_ms: now_ms + 60_000,
            members,
            signature: [0; 64],
        };
        view.signature = source.sign(&view.digest().unwrap()).to_bytes();

        app.configure_regional_mesh_authority(
            RegionalMeshPolicy {
                network: 0,
                source_keys: vec![view.source_key],
            },
            Some(password),
        )
        .unwrap();

        assert!(
            app.begin_intent_reconciliation(&local_id, std::slice::from_ref(&view), now_ms + 10_000, Some(password))
                .is_err()
        );

        // 2. After 30s, reconciliation context is generated with stored fresh challenge
        let context = app
            .begin_intent_reconciliation(&local_id, std::slice::from_ref(&view), now_ms + 30_000, Some(password))
            .unwrap();
        assert_ne!(context.recipient_nonce, [0; 32]);
        assert_eq!(
            app.pending_l2_send_intent(&local_id).unwrap().stored_challenge,
            Some(context.recipient_nonce)
        );

        // 3. Mathematical quorum proof verification
        let digest = humoco_proto::live::live_state_digest(&context).unwrap();
        let votes: Vec<_> = context.committee[..14]
            .iter()
            .map(|public| {
                let key = keys
                    .iter()
                    .find(|k| k.verifying_key().to_bytes() == *public)
                    .unwrap();
                AttestationVote {
                    signer_pubkey: *public,
                    signature: key.sign(&digest).to_bytes(),
                }
            })
            .collect();
        let proof = LiveStateProof {
            context: context.clone(),
            votes,
        };

        // Forged/mismatched nonce must fail
        let mut forged_proof = proof.clone();
        forged_proof.context.recipient_nonce = [99; 32];
        assert!(
            app.complete_intent_reconciliation(
                &local_id,
                &forged_proof,
                std::slice::from_ref(&view),
                now_ms + 30_500,
                Some(password)
            )
            .is_err()
        );

        // Valid proof completes reconciliation as Confirmed
        let resolution = app
            .complete_intent_reconciliation(
                &local_id,
                &proof,
                std::slice::from_ref(&view),
                now_ms + 30_500,
                Some(password)
            )
            .unwrap();
        assert_eq!(
            resolution,
            IntentTerminalResolution::Confirmed { resolved_at_ms: now_ms + 30_500 }
        );
        let updated_intent = app.pending_l2_send_intent(&local_id).unwrap();
        assert_eq!(updated_intent.terminal_resolution, Some(resolution));
        assert_eq!(updated_intent.stored_challenge, None);

        // 4. Bounded journal cleanup prunes after max_retain_ms
        assert_eq!(
            app.cleanup_terminal_intents(60_000, now_ms + 31_000, Some(password)).unwrap(),
            0
        );
        assert_eq!(
            app.cleanup_terminal_intents(60_000, now_ms + 95_000, Some(password)).unwrap(),
            1
        );
        assert!(app.pending_l2_send_intent(&local_id).is_err());
    }

    use ed25519_dalek::{Signer, SigningKey};
    use humoco_proto::{
        AttestationVote,
        live::{LiveStateContext, LiveStateProof},
        mesh::{RegionalMeshMember, RegionalMeshPolicy, RegionalMeshView},
    };

    fn signed_live_proof(context: &LiveStateContext, keys: &[SigningKey]) -> LiveStateProof {
        let digest = humoco_proto::live::live_state_digest(context).unwrap();
        let votes = context.committee[..14]
            .iter()
            .map(|public| {
                let key = keys
                    .iter()
                    .find(|k| k.verifying_key().to_bytes() == *public)
                    .unwrap();
                AttestationVote {
                    signer_pubkey: *public,
                    signature: key.sign(&digest).to_bytes(),
                }
            })
            .collect();
        LiveStateProof {
            context: context.clone(),
            votes,
        }
    }

    fn reconciliation_fixture(
        dir: &tempfile::TempDir,
        password: &str,
    ) -> (AppService, String, u64, Vec<SigningKey>, RegionalMeshView) {
        let (mut app, _profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "ConflictSender",
            password,
        );
        let user = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        let standard = test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        let voucher = app
            .create_new_voucher(
                &standard,
                NewVoucherData {
                    creator_profile: PublicProfile {
                        id: Some(user),
                        ..Default::default()
                    },
                    nominal_value: ValueDefinition {
                        amount: "100".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                Some(password),
            )
            .unwrap();
        let local_id = app
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();
        let standards =
            std::collections::HashMap::from([(voucher.voucher_standard.uuid.clone(), standard)]);
        app.create_transfer_bundle_with_l2_intents(
            crate::wallet::MultiTransferRequest {
                recipient_id: ACTORS.bob.user_id.clone(),
                sources: vec![crate::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "10".into(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: Some(false),
            },
            &standards,
            None,
            Some(password),
            0,
        )
        .unwrap();
        let intent = app.pending_l2_send_intent(&local_id).unwrap();
        let now_ms = intent.created_at_ms;
        let source = SigningKey::from_bytes(&[101; 32]);
        let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let mut members: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| RegionalMeshMember {
                node_pubkey: key.verifying_key().to_bytes(),
                hrw_routing_id: [i as u8; 32],
            })
            .collect();
        members.sort_by_key(|m| m.node_pubkey);
        let mut view = RegionalMeshView {
            version: 1,
            network: 0,
            source_key: source.verifying_key().to_bytes(),
            issued_at_ms: now_ms,
            valid_until_ms: now_ms + 60_000,
            members,
            signature: [0; 64],
        };
        view.signature = source.sign(&view.digest().unwrap()).to_bytes();
        app.configure_regional_mesh_authority(
            RegionalMeshPolicy {
                network: 0,
                source_keys: vec![view.source_key],
            },
            Some(password),
        )
        .unwrap();
        (app, local_id, now_ms, keys, view)
    }

    #[test]
    fn unresolved_intents_are_enumerated_until_terminal_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let password = "unresolved-intents";
        let (mut app, local_id, now_ms, keys, view) = reconciliation_fixture(&dir, password);

        let unresolved = app.unresolved_l2_send_intents().unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].local_instance_id, local_id);

        let context = app
            .begin_intent_reconciliation(
                &local_id,
                std::slice::from_ref(&view),
                now_ms + 30_000,
                Some(password),
            )
            .unwrap();
        let proof = signed_live_proof(&context, &keys);
        app.complete_intent_reconciliation(
            &local_id,
            &proof,
            std::slice::from_ref(&view),
            now_ms + 30_500,
            Some(password),
        )
        .unwrap();

        assert!(app.unresolved_l2_send_intents().unwrap().is_empty());
    }

    #[test]
    fn verified_conflicting_live_state_proof_resolves_conflicted() {
        let dir = tempfile::tempdir().unwrap();
        let password = "verified-conflict";
        let (mut app, local_id, now_ms, keys, view) = reconciliation_fixture(&dir, password);

        let context = app
            .begin_intent_reconciliation(
                &local_id,
                std::slice::from_ref(&view),
                now_ms + 30_000,
                Some(password),
            )
            .unwrap();
        let mut conflict_context = context.clone();
        conflict_context.child_lock = [42; 32];
        conflict_context.state_digest = [43; 32];
        let proof = signed_live_proof(&conflict_context, &keys);

        let resolution = app
            .complete_intent_reconciliation(
                &local_id,
                &proof,
                std::slice::from_ref(&view),
                now_ms + 30_500,
                Some(password),
            )
            .unwrap();
        let expected = IntentTerminalResolution::Conflicted {
            resolved_at_ms: now_ms + 30_500,
            observed_child: hex::encode([42; 32]),
        };
        assert_eq!(resolution, expected);
        let intent = app.pending_l2_send_intent(&local_id).unwrap();
        assert_eq!(intent.terminal_resolution, Some(expected));
        assert_eq!(intent.stored_challenge, None);
        assert!(!intent.retained_original_observed);
    }

    #[test]
    fn forged_conflicting_live_state_proof_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let password = "forged-conflict";
        let (mut app, local_id, now_ms, keys, view) = reconciliation_fixture(&dir, password);

        let context = app
            .begin_intent_reconciliation(
                &local_id,
                std::slice::from_ref(&view),
                now_ms + 30_000,
                Some(password),
            )
            .unwrap();
        let mut conflict_context = context.clone();
        conflict_context.child_lock = [42; 32];
        conflict_context.state_digest = [43; 32];
        let mut proof = signed_live_proof(&conflict_context, &keys);
        proof.context.child_lock = [44; 32];

        assert!(
            app.complete_intent_reconciliation(
                &local_id,
                &proof,
                std::slice::from_ref(&view),
                now_ms + 30_500,
                Some(password),
            )
            .is_err()
        );
        let intent = app.pending_l2_send_intent(&local_id).unwrap();
        assert_eq!(intent.terminal_resolution, None);
        assert_eq!(intent.stored_challenge, Some(context.recipient_nonce));
    }

    #[test]
    fn record_intent_conflict_resolves_verified_conflicting_proof() {
        let dir = tempfile::tempdir().unwrap();
        let password = "record-conflict";
        let (mut app, local_id, now_ms, keys, view) = reconciliation_fixture(&dir, password);

        let context = app
            .begin_intent_reconciliation(
                &local_id,
                std::slice::from_ref(&view),
                now_ms + 30_000,
                Some(password),
            )
            .unwrap();
        let mut conflict_context = context.clone();
        conflict_context.child_lock = [42; 32];
        conflict_context.state_digest = [43; 32];
        let proof = signed_live_proof(&conflict_context, &keys);

        let resolution = app
            .record_intent_conflict(
                &local_id,
                &proof,
                std::slice::from_ref(&view),
                now_ms + 30_500,
                Some(password),
            )
            .unwrap();
        assert_eq!(
            resolution,
            IntentTerminalResolution::Conflicted {
                resolved_at_ms: now_ms + 30_500,
                observed_child: hex::encode([42; 32]),
            }
        );
        assert_eq!(
            app.record_intent_conflict(
                &local_id,
                &proof,
                std::slice::from_ref(&view),
                now_ms + 30_600,
                Some(password),
            )
            .unwrap(),
            resolution
        );
    }

    #[test]
    fn cleanup_terminal_intents_skips_disk_write_when_idle_and_stage_prunes_inline() {
        let dir = tempfile::tempdir().unwrap();
        let password = "no-op-cleanup-and-inline-prune";
        let (mut app, local_id, now_ms, _keys, _view) = reconciliation_fixture(&dir, password);

        // When no intent is due for cleanup, calling cleanup_terminal_intents with an invalid
        // password must still succeed with Ok(0) because it returns early before opening a write transaction.
        assert_eq!(
            app.cleanup_terminal_intents(60_000, now_ms + 1_000, Some("wrong-password-would-fail-write"))
                .unwrap(),
            0
        );

        // Fill wallet profile with 256 terminally resolved intents that are past their retention window,
        // then verify stage_l2_send_intent prunes them inline instead of failing with capacity exhaustion.
        let template = app.pending_l2_send_intent(&local_id).unwrap();
        app.with_transactional_mut(Some(password), |wallet, _, _, _| {
            let voucher = wallet
                .voucher_store
                .vouchers
                .values()
                .next()
                .expect("fixture voucher present")
                .voucher
                .clone();
            wallet.profile.l2_send_intents.clear();
            for i in 0..256 {
                let mut item = template.clone();
                item.local_instance_id = format!("terminal-{i}");
                item.created_at_ms = 1_000;
                item.root_valid_until_ms = 5_000;
                item.terminal_resolution = Some(IntentTerminalResolution::Confirmed {
                    resolved_at_ms: 2_000,
                });
                wallet.profile.l2_send_intents.insert(item.local_instance_id.clone(), item);
            }
            wallet
                .stage_l2_send_intent("fresh-intent-after-inline-prune", &voucher, 0)
                .expect("inline pruning must free expired terminal intents before enforcing the 256 cap");
            assert_eq!(wallet.profile.l2_send_intents.len(), 1);
            crate::app_service::TransactionOutcome::Commit(())
        })
        .unwrap();
    }
}
