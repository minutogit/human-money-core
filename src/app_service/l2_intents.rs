//! Durable exact-byte send intents. No transport or outcome guess can free an
//! uncertain output; matching retained originals are observations, not clearance.
use super::{AppService, TransactionOutcome};
use crate::{Error, models::layer2_api::L2LockRequest, services::l2_gateway};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Backend-owned pending transport state, included in the authenticated wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct L2SendIntent {
    /// Exact local source, blocked from replacement while outcome is uncertain.
    pub local_instance_id: String,
    /// Exact serialized signed request, reused verbatim through every retry.
    pub request_bytes: Vec<u8>,
    /// Exact signed L1 transaction, including its original outputs.
    pub transaction_bytes: Vec<u8>,
    /// Signed wallet creation time, never regenerated on retry.
    pub created_at_ms: u64,
    /// Frozen transport domain and root-bound verification context.
    pub network: u8,
    pub shard_id: u16,
    pub root_valid_until_ms: u64,
    /// True once first-party retained evidence has been observed. This does not
    /// authorize goods release, a replacement spend or an automatic refund.
    #[serde(default)]
    pub retained_original_observed: bool,
}
fn invalid(reason: &str) -> Error {
    Error::Validation(crate::error::ValidationError::SecurityViolation(
        reason.into(),
    ))
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
            let result = (|| {
                if network > 1 {
                    return Err(invalid("invalid intent network"));
                }
                if let Some(intent) = wallet.profile.l2_send_intents.get(local_id) {
                    if intent.network != network {
                        return Err(invalid("pending intent network cannot change"));
                    }
                    return Ok(intent.clone());
                }
                if wallet.profile.l2_send_intents.len() >= 256 {
                    return Err(invalid("pending intent capacity exhausted"));
                }
                let instance = wallet
                    .get_voucher_instance(local_id)
                    .ok_or_else(|| Error::VoucherNotFound(local_id.into()))?;
                let transaction = instance
                    .voucher
                    .transactions
                    .last()
                    .ok_or_else(|| invalid("intent transaction missing"))?;
                let root = instance
                    .voucher
                    .transactions
                    .first()
                    .ok_or_else(|| invalid("intent root missing"))?;
                let voucher_id = l2_gateway::calculate_layer2_voucher_id(root)?;
                let mut auth = [0; 32];
                OsRng.fill_bytes(&mut auth);
                let mut request =
                    l2_gateway::generate_lock_request(&voucher_id, transaction, &auth)?;
                request.causal_output = wallet
                    .profile
                    .l2_causal_outputs
                    .get(&transaction.t_id)
                    .cloned();
                let request_bytes = serde_json::to_vec(&request)?;
                let transaction_bytes = serde_json::to_vec(transaction)?;
                let used: usize = wallet
                    .profile
                    .l2_send_intents
                    .values()
                    .map(|i| i.request_bytes.len() + i.transaction_bytes.len())
                    .sum();
                if request_bytes.len() > 65_536
                    || transaction_bytes.len() > 131_072
                    || used
                        .saturating_add(request_bytes.len())
                        .saturating_add(transaction_bytes.len())
                        > 8 * 1024 * 1024
                {
                    return Err(invalid("pending intent byte budget exhausted"));
                }
                let root_valid_until_ms =
                    crate::services::utils::parse_timestamp_ms(&instance.voucher.valid_until)?;
                let parent = *blake3::hash(root.t_id.as_bytes()).as_bytes();
                let intent = L2SendIntent {
                    local_instance_id: local_id.into(),
                    request_bytes,
                    transaction_bytes,
                    created_at_ms: request.created_at_ms,
                    network,
                    shard_id: u16::from_be_bytes([parent[0], parent[1]]),
                    root_valid_until_ms,
                    retained_original_observed: false,
                };
                wallet
                    .profile
                    .l2_send_intents
                    .insert(local_id.into(), intent.clone());
                Ok(intent)
            })();
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
}
