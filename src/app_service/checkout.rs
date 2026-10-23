//! Backend-owned recipient challenges and atomic L1/purchase completion.
use super::{AppService, TransactionOutcome};
use crate::{
    Error,
    models::layer2_api::{
        CheckoutReleaseVerdict, DurablePurchaseBinding, L2LockEntry, L2ProcessingOutcome,
    },
    services::{bundle_processor, l2_gateway, voucher_validation::StandardRegistry},
};
use humoco_proto::{
    live::{LiveStateContext, LiveStateProof, verify_live_state_proof},
    mesh::{RegionalMeshView, regional_committee},
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Private purchase binding. Never accepted from a proof or IPC outcome string.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckoutPurchase {
    pub bundle_hash: [u8; 32],
    pub context: LiveStateContext,
    pub expires_at_ms: u64,
    pub completed: bool,
}
/// Stable purchase identity lets a PoS distinguish idempotent completion from a
/// new release event. Only an installed wallet commit can produce this result.
#[derive(Debug)]
pub struct CheckoutCompletion {
    pub purchase_id: String,
    pub newly_committed: bool,
    pub verdict: CheckoutReleaseVerdict,
}
fn invalid(reason: &str) -> Error {
    Error::Validation(crate::error::ValidationError::SecurityViolation(
        reason.into(),
    ))
}
impl AppService {
    /// Creates and durably installs one unpredictable recipient challenge bound to
    /// the exact encrypted L1 bundle and purchase ID. No L1 import occurs yet.
    pub fn begin_checkout_purchase(
        &mut self,
        purchase_id: &str,
        bundle_data: &[u8],
        views: &[RegionalMeshView],
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<LiveStateContext, Error> {
        if purchase_id.is_empty()
            || purchase_id.len() > 128
            || bundle_data.len() > crate::services::bundle_processor::MAX_CONTAINER_BYTES
        {
            return Err(invalid("invalid purchase bounds"));
        }
        let bundle_hash = *blake3::hash(bundle_data).as_bytes();
        self.with_transactional_mut(password, |wallet, identity, _, _| {
            let result = (|| {
                if let Some(purchase) = wallet.profile.l2_checkout_purchases.get(purchase_id) {
                    if purchase.bundle_hash != bundle_hash {
                        return Err(invalid("purchase ID already binds another bundle"));
                    }
                    return Ok(purchase.context.clone());
                }
                if wallet.profile.l2_checkout_purchases.len() >= 256 {
                    return Err(invalid("purchase capacity exhausted"));
                }
                let bundle = bundle_processor::open_and_verify_bundle(identity, bundle_data)?;
                if bundle.recipient_id != identity.user_id || bundle.vouchers.len() != 1 {
                    return Err(invalid(
                        "automatic checkout requires one voucher addressed to this recipient",
                    ));
                }
                let voucher = &bundle.vouchers[0];
                let root = voucher
                    .transactions
                    .first()
                    .ok_or_else(|| invalid("purchase root missing"))?;
                let last = voucher
                    .transactions
                    .last()
                    .ok_or_else(|| invalid("purchase transaction missing"))?;
                let voucher_id = l2_gateway::calculate_layer2_voucher_id(root)?;
                let mut request = l2_gateway::generate_lock_request(&voucher_id, last, &[0; 32])?;
                request.causal_output = bundle.causal_outputs.get(&last.t_id).cloned();
                if let Some(proof) = &request.causal_output {
                    crate::services::l2_causality::validate_output_proof(voucher, last, proof)?;
                }
                let tag = if request.is_genesis {
                    bs58::encode(request.transaction_hash).into_string()
                } else {
                    request
                        .ds_tag
                        .clone()
                        .ok_or_else(|| invalid("purchase parent missing"))?
                };
                let parent = *blake3::hash(tag.as_bytes()).as_bytes();
                let genesis = *blake3::hash(root.t_id.as_bytes()).as_bytes();
                let shard = u16::from_be_bytes([genesis[0], genesis[1]]);
                let root_valid_until =
                    crate::services::utils::parse_timestamp_ms(&voucher.valid_until)?;
                if root_valid_until <= now_ms {
                    return Err(invalid("purchase root expired"));
                }
                let policy = wallet
                    .profile
                    .l2_regional_mesh_policy
                    .as_ref()
                    .ok_or_else(|| invalid("recipient authority missing"))?;
                let committee =
                    regional_committee(policy, views, shard, now_ms).map_err(invalid)?;
                let entry = L2LockEntry::from(&request);
                let mut nonce = [0; 32];
                OsRng
                    .try_fill_bytes(&mut nonce)
                    .map_err(|_| invalid("challenge entropy unavailable"))?;
                if nonce == [0; 32] {
                    return Err(invalid("invalid challenge entropy"));
                }
                let context = LiveStateContext {
                    version: 1,
                    network: policy.network,
                    shard_id: shard,
                    voucher_id,
                    lookup_tag: tag,
                    parent_lock: parent,
                    child_lock: request.transaction_hash,
                    root_valid_until,
                    state_digest: *blake3::hash(&serde_json::to_vec(&entry)?).as_bytes(),
                    recipient_nonce: nonce,
                    committee,
                };
                wallet.profile.l2_checkout_purchases.insert(
                    purchase_id.into(),
                    CheckoutPurchase {
                        bundle_hash,
                        context: context.clone(),
                        expires_at_ms: now_ms.saturating_add(30_000).min(root_valid_until),
                        completed: false,
                    },
                );
                Ok(context)
            })();
            match result {
                Ok(context) => TransactionOutcome::Commit(context),
                Err(error) => TransactionOutcome::Rollback(error),
            }
        })
    }
    /// Verifies current authority/challenge under the wallet lock and imports L1
    /// plus the consumed purchase in ONE managed transaction. No caller context
    /// can mint release; errors/uncertain commits return before capability minting.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_checkout_purchase(
        &mut self,
        purchase_id: &str,
        bundle_data: &[u8],
        proof: &LiveStateProof,
        views: &[RegionalMeshView],
        standards: &HashMap<String, String>,
        now_ms: u64,
        password: Option<&str>,
    ) -> Result<CheckoutCompletion, Error> {
        if bundle_data.len() > crate::services::bundle_processor::MAX_CONTAINER_BYTES {
            return Err(invalid("purchase bundle too large"));
        }
        let registry = StandardRegistry::from_toml_map(standards)?;
        let epoch_info = self.get_epoch_info(password)?.unwrap_or_default();
        let (epoch_start, epoch) = epoch_info;
        let hash = *blake3::hash(bundle_data).as_bytes();
        let newly_committed = self.with_transactional_mut(password, |wallet, identity, _, _| {
            let result = (|| {
                let purchase = wallet
                    .profile
                    .l2_checkout_purchases
                    .get(purchase_id)
                    .cloned()
                    .ok_or_else(|| invalid("purchase challenge missing"))?;
                if purchase.bundle_hash != hash {
                    return Err(invalid("purchase bundle mismatch"));
                }
                if purchase.completed {
                    return Ok(false);
                }
                if now_ms >= purchase.expires_at_ms || now_ms >= purchase.context.root_valid_until {
                    return Err(invalid("purchase challenge expired"));
                }
                let policy = wallet
                    .profile
                    .l2_regional_mesh_policy
                    .as_ref()
                    .ok_or_else(|| invalid("recipient authority missing"))?;
                let committee =
                    regional_committee(policy, views, purchase.context.shard_id, now_ms)
                        .map_err(invalid)?;
                if purchase.context.network != policy.network
                    || purchase.context.committee != committee
                {
                    return Err(invalid("purchase authority changed"));
                }
                verify_live_state_proof(proof, &purchase.context).map_err(invalid)?;
                let outcome = wallet.process_bundle_with_registry_inner(
                    identity,
                    bundle_data,
                    None,
                    &registry,
                    Some(epoch_start.as_str()),
                    epoch,
                    false,
                )?;
                if outcome.involved_vouchers.len() != 1 {
                    return Err(invalid("purchase did not import exactly one voucher"));
                }
                wallet
                    .profile
                    .l2_checkout_purchases
                    .get_mut(purchase_id)
                    .ok_or_else(|| invalid("purchase disappeared"))?
                    .completed = true;
                Ok(true)
            })();
            match result {
                Ok(value) => TransactionOutcome::Commit(value),
                Err(error) => TransactionOutcome::Rollback(error),
            }
        })?;
        Ok(CheckoutCompletion {
            purchase_id: purchase_id.into(),
            newly_committed,
            verdict: CheckoutReleaseVerdict::new(L2ProcessingOutcome::Confirmed, false)
                .with_durable_purchase_binding(DurablePurchaseBinding::backend_verified()),
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
        wallet::{MultiTransferRequest, SourceTransfer},
    };
    use ed25519_dalek::{Signer, SigningKey};
    use humoco_proto::{
        AttestationVote,
        mesh::{RegionalMeshMember, RegionalMeshPolicy},
    };
    #[test]
    fn purchase_commit_binds_real_l1_challenge_authority_and_idempotent_restart() {
        let dir = tempfile::tempdir().unwrap();
        let password = "atomic-checkout-test";
        let (mut sender, _) = test_utils::setup_service_with_profile(
            &dir.path().join("sender"),
            &ACTORS.alice,
            "Sender",
            password,
        );
        let (mut receiver, profile) = test_utils::setup_service_with_profile(
            &dir.path().join("receiver"),
            &ACTORS.bob,
            "Receiver",
            password,
        );
        let sender_id = sender.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        let recipient = receiver
            .with_wallet(|w| w.get_user_id().to_string())
            .unwrap();
        let standard = test_utils::generate_signed_standard_toml(
            "voucher_standards/freetaler_v1/standard.toml",
        );
        let voucher = sender
            .create_new_voucher(
                &standard,
                NewVoucherData {
                    creator_profile: PublicProfile {
                        id: Some(sender_id),
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
        let local = sender
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();
        let standards = HashMap::from([(voucher.voucher_standard.uuid.clone(), standard)]);
        let bundle = sender
            .create_transfer_bundle(
                MultiTransferRequest {
                    recipient_id: recipient,
                    sources: vec![SourceTransfer {
                        local_instance_id: local,
                        amount_to_send: "10".into(),
                    }],
                    notes: None,
                    sender_profile_name: None,
                    use_privacy_mode: Some(false),
                },
                &standards,
                None,
                Some(password),
            )
            .unwrap();
        receiver.with_wallet_and_identity(|_, identity| {
            let opened = bundle_processor::open_and_verify_bundle(identity, &bundle.bundle_bytes).unwrap();
            let voucher = &opened.vouchers[0];
            assert_eq!(opened.causal_outputs.len(), voucher.transactions.len());
            for transaction in &voucher.transactions {
                let proof = opened.causal_outputs.get(&transaction.t_id).unwrap();
                crate::services::l2_causality::validate_output_proof(voucher, transaction, proof).unwrap();
                let mut forged = proof.clone();
                forged.state_hash = [99; 32];
                assert!(crate::services::l2_causality::validate_output_proof(voucher, transaction, &forged).is_err());
            }
            let last = voucher.transactions.last().unwrap();
            let request = l2_gateway::generate_lock_request(&l2_gateway::calculate_layer2_voucher_id(&voucher.transactions[0]).unwrap(), last, &[0; 32]).unwrap();
            let chain = l2_gateway::build_voucher_lock_chain_with_outputs(voucher, None, request, &opened.causal_outputs).unwrap();
            assert!(chain.chain[0].is_genesis);
            assert!(chain.chain[0].causal_output.is_some());
            let previous = chain.chain[0].causal_output.as_ref().unwrap();
            let expected = crate::services::crypto::get_ds_tag(&bs58::encode(previous.state_hash).into_string(), last.sender_ephemeral_pub.as_ref().unwrap()).unwrap();
            assert_eq!(chain.chain[1].ds_tag.as_deref(), Some(expected.as_str()), "the real L1 SST formula must remain unchanged");
            assert_eq!(chain.chain[1].ds_tag.as_deref(), last.trap_data.as_ref().map(|trap| trap.ds_tag.as_str()));
        }).unwrap();
        let source = SigningKey::from_bytes(&[100; 32]);
        let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
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
            issued_at_ms: now,
            valid_until_ms: now + 60_000,
            members,
            signature: [0; 64],
        };
        view.signature = source.sign(&view.digest().unwrap()).to_bytes();
        receiver
            .configure_regional_mesh_authority(
                RegionalMeshPolicy {
                    network: 0,
                    source_keys: vec![view.source_key],
                },
                Some(password),
            )
            .unwrap();
        let context = receiver
            .begin_checkout_purchase(
                "sale-123",
                &bundle.bundle_bytes,
                std::slice::from_ref(&view),
                now,
                Some(password),
            )
            .unwrap();
        assert_ne!(context.recipient_nonce, [0; 32]);
        assert_eq!(
            receiver
                .begin_checkout_purchase(
                    "sale-123",
                    &bundle.bundle_bytes,
                    std::slice::from_ref(&view),
                    now,
                    Some(password)
                )
                .unwrap(),
            context
        );
        let digest = humoco_proto::live::live_state_digest(&context).unwrap();
        let votes: Vec<_> = context.committee[..14]
            .iter()
            .map(|public| {
                let key = keys
                    .iter()
                    .find(|key| key.verifying_key().to_bytes() == *public)
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
        let mut transplanted = proof.clone();
        transplanted.context.recipient_nonce = [7; 32];
        assert!(
            receiver
                .complete_checkout_purchase(
                    "sale-123",
                    &bundle.bundle_bytes,
                    &transplanted,
                    std::slice::from_ref(&view),
                    &standards,
                    now + 1,
                    Some(password)
                )
                .is_err()
        );
        assert!(
            receiver
                .with_wallet(|w| w.voucher_store.vouchers.is_empty())
                .unwrap()
        );
        assert!(
            receiver
                .complete_checkout_purchase(
                    "sale-123",
                    &bundle.bundle_bytes,
                    &proof,
                    std::slice::from_ref(&view),
                    &standards,
                    now + 30_000,
                    Some(password)
                )
                .is_err()
        );
        assert!(
            receiver
                .with_wallet(|w| w.voucher_store.vouchers.is_empty())
                .unwrap()
        );
        let completed = receiver
            .complete_checkout_purchase(
                "sale-123",
                &bundle.bundle_bytes,
                &proof,
                std::slice::from_ref(&view),
                &standards,
                now + 1,
                Some(password),
            )
            .unwrap();
        assert!(completed.newly_committed);
        assert!(completed.verdict.can_release_goods_automatically);
        assert_eq!(completed.purchase_id, "sale-123");
        assert_eq!(
            receiver
                .with_wallet(|w| w.voucher_store.vouchers.len())
                .unwrap(),
            1
        );
        receiver.logout();
        drop(receiver);
        let mut receiver = AppService::new(&dir.path().join("receiver")).unwrap();
        receiver
            .login(&profile.folder_name, password, false, "test-id".into())
            .unwrap();
        let replay = receiver
            .complete_checkout_purchase(
                "sale-123",
                &bundle.bundle_bytes,
                &proof,
                std::slice::from_ref(&view),
                &standards,
                now + 31_000,
                Some(password),
            )
            .unwrap();
        assert!(!replay.newly_committed);
        assert!(replay.verdict.can_release_goods_automatically);
        assert_eq!(
            receiver
                .with_wallet(|w| w.voucher_store.vouchers.len())
                .unwrap(),
            1
        );
    }
}
