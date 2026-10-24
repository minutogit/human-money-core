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

const MAX_ACTIVE_CHECKOUT_PURCHASES: usize = 256;
const CHECKOUT_CHALLENGE_TTL_MS: u64 = 30_000;

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

fn generate_recipient_nonce(previous: Option<[u8; 32]>) -> Result<[u8; 32], Error> {
    loop {
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| invalid("challenge entropy unavailable"))?;
        if nonce != [0; 32] && previous != Some(nonce) {
            return Ok(nonce);
        }
    }
}

fn completed_checkout_completion(purchase_id: &str) -> CheckoutCompletion {
    CheckoutCompletion {
        purchase_id: purchase_id.into(),
        newly_committed: false,
        verdict: CheckoutReleaseVerdict::new(L2ProcessingOutcome::Confirmed, false)
            .with_durable_purchase_binding(DurablePurchaseBinding::backend_verified()),
    }
}

impl AppService {
    /// Checks if a purchase ID has already been completed with the specified bundle.
    pub fn is_checkout_purchase_completed(
        &self,
        purchase_id: &str,
        bundle_data: &[u8],
    ) -> Result<bool, Error> {
        let bundle_hash = *blake3::hash(bundle_data).as_bytes();
        self.with_wallet(|wallet| {
            if let Some(purchase) = wallet.profile.l2_checkout_purchases.get(purchase_id) {
                if purchase.bundle_hash != bundle_hash {
                    return Err(invalid("purchase ID already binds another bundle"));
                }
                Ok(purchase.completed)
            } else {
                Ok(false)
            }
        })?
    }

    /// Evaluates replay of an already completed purchase without network dependency.
    /// Returns Some(CheckoutCompletion) with newly_committed = false and valid release capability
    /// if the purchase is already marked completed for this exact bundle hash.
    pub fn replay_checkout_purchase(
        &self,
        purchase_id: &str,
        bundle_data: &[u8],
    ) -> Result<Option<CheckoutCompletion>, Error> {
        if !self.is_checkout_purchase_completed(purchase_id, bundle_data)? {
            return Ok(None);
        }
        Ok(Some(completed_checkout_completion(purchase_id)))
    }

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
            let mut pruned = false;
            let mut mutated = false;
            let result = (|| {
                if let Some(purchase) = wallet
                    .profile
                    .l2_checkout_purchases
                    .get(purchase_id)
                    .cloned()
                {
                    if purchase.bundle_hash != bundle_hash {
                        return Err(invalid("purchase ID already binds another bundle"));
                    }
                    if purchase.completed {
                        return Ok(purchase.context.clone());
                    }
                    if now_ms < purchase.expires_at_ms && now_ms < purchase.context.root_valid_until
                    {
                        let committee = {
                            let policy = wallet
                                .profile
                                .l2_regional_mesh_policy
                                .as_ref()
                                .ok_or_else(|| invalid("recipient authority missing"))?;
                            regional_committee(policy, views, purchase.context.shard_id, now_ms)
                                .map_err(invalid)?
                        };
                        if committee != purchase.context.committee {
                            let stored = wallet
                                .profile
                                .l2_checkout_purchases
                                .get_mut(purchase_id)
                                .ok_or_else(|| invalid("purchase disappeared"))?;
                            stored.context.committee = committee;
                            mutated = true;
                            return Ok(stored.context.clone());
                        }
                        return Ok(purchase.context.clone());
                    }
                    if now_ms >= purchase.context.root_valid_until {
                        return Err(invalid("purchase root expired"));
                    }
                    let nonce = generate_recipient_nonce(Some(purchase.context.recipient_nonce))?;
                    let policy = wallet
                        .profile
                        .l2_regional_mesh_policy
                        .as_ref()
                        .ok_or_else(|| invalid("recipient authority missing"))?;
                    let committee =
                        regional_committee(policy, views, purchase.context.shard_id, now_ms)
                            .map_err(invalid)?;
                    let expires_at_ms = now_ms
                        .saturating_add(CHECKOUT_CHALLENGE_TTL_MS)
                        .min(purchase.context.root_valid_until);
                    let mut context = purchase.context;
                    context.recipient_nonce = nonce;
                    context.committee = committee;
                    let stored = wallet
                        .profile
                        .l2_checkout_purchases
                        .get_mut(purchase_id)
                        .ok_or_else(|| invalid("purchase disappeared"))?;
                    stored.context = context.clone();
                    stored.expires_at_ms = expires_at_ms;
                    mutated = true;
                    return Ok(context);
                }
                pruned = wallet.profile.prune_expired_checkout_purchases(now_ms);
                if wallet.profile.active_checkout_purchase_count(now_ms)
                    >= MAX_ACTIVE_CHECKOUT_PURCHASES
                {
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
                let nonce = generate_recipient_nonce(None)?;
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
                        expires_at_ms: now_ms
                            .saturating_add(CHECKOUT_CHALLENGE_TTL_MS)
                            .min(root_valid_until),
                        completed: false,
                    },
                );
                mutated = true;
                Ok(context)
            })();
            match result {
                Ok(context) if mutated || pruned => TransactionOutcome::Commit(context),
                Ok(context) => TransactionOutcome::Abort(context),
                Err(error) if pruned => TransactionOutcome::CommitAndReturnError(error),
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
        let hash = *blake3::hash(bundle_data).as_bytes();
        let stored_purchase = self.with_wallet(|wallet| {
            wallet
                .profile
                .l2_checkout_purchases
                .get(purchase_id)
                .map(|purchase| (purchase.bundle_hash, purchase.completed))
        })?;
        if let Some((stored_hash, completed)) = stored_purchase {
            if stored_hash != hash {
                return Err(invalid("purchase bundle mismatch"));
            }
            if completed {
                return Ok(completed_checkout_completion(purchase_id));
            }
        }
        let registry = StandardRegistry::from_toml_map(standards)?;
        let epoch_info = self.get_epoch_info(password)?.unwrap_or_default();
        let (epoch_start, epoch) = epoch_info;
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
                if !wallet.profile.mark_checkout_purchase_completed(purchase_id) {
                    return Err(invalid("purchase disappeared"));
                }
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

    struct CheckoutFixture {
        receiver: AppService,
        bundle_bytes: Vec<u8>,
        standards: HashMap<String, String>,
        view: RegionalMeshView,
        keys: Vec<SigningKey>,
        now: u64,
    }

    impl CheckoutFixture {
        fn proof(&self, context: &LiveStateContext) -> LiveStateProof {
            let digest = humoco_proto::live::live_state_digest(context).unwrap();
            let votes = context
                .committee
                .iter()
                .take(14)
                .map(|public| {
                    let key = self
                        .keys
                        .iter()
                        .find(|key| key.verifying_key().to_bytes() == *public)
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
    }

    fn checkout_fixture(dir: &std::path::Path) -> CheckoutFixture {
        let password = "checkout-lifecycle-test";
        let (mut sender, _) = test_utils::setup_service_with_profile(
            &dir.join("sender"),
            &ACTORS.alice,
            "Sender",
            password,
        );
        let (mut receiver, _) = test_utils::setup_service_with_profile(
            &dir.join("receiver"),
            &ACTORS.bob,
            "Receiver",
            password,
        );
        let sender_id = sender
            .with_wallet(|wallet| wallet.get_user_id().to_string())
            .unwrap();
        let recipient = receiver
            .with_wallet(|wallet| wallet.get_user_id().to_string())
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
            .with_wallet_and_identity(|wallet, identity| {
                wallet.list_vouchers(Some(identity), None, None, None)
            })
            .unwrap()[0]
            .local_instance_id
            .clone();
        let standards = HashMap::from([(voucher.voucher_standard.uuid.clone(), standard)]);
        let bundle = sender
            .create_transfer_bundle_with_l2_intents(
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
                0,
            )
            .unwrap();
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
        members.sort_by_key(|member| member.node_pubkey);
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
        CheckoutFixture {
            receiver,
            bundle_bytes: bundle.bundle_bytes,
            standards,
            view,
            keys,
            now,
        }
    }

    fn assert_security_error(error: &Error, expected: &str) {
        match error {
            Error::Validation(crate::error::ValidationError::SecurityViolation(reason)) => {
                assert_eq!(reason, expected);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn more_than_256_completed_purchases_remain_replayable_without_capacity_exhaustion() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = checkout_fixture(dir.path());
        let password = "checkout-lifecycle-test";
        let context = fixture
            .receiver
            .begin_checkout_purchase(
                "completed-0",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        let proof = fixture.proof(&context);
        let completion = fixture
            .receiver
            .complete_checkout_purchase(
                "completed-0",
                &fixture.bundle_bytes,
                &proof,
                std::slice::from_ref(&fixture.view),
                &fixture.standards,
                fixture.now + 1,
                Some(password),
            )
            .unwrap();
        assert!(completion.newly_committed);
        let completed = fixture
            .receiver
            .with_wallet(|wallet| {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .get("completed-0")
                    .cloned()
            })
            .unwrap()
            .unwrap();
        {
            let wallet = fixture.receiver.get_wallet_mut().unwrap();
            for index in 1..=256 {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .insert(format!("completed-{index}"), completed.clone());
            }
        }
        let dummy_proof = LiveStateProof {
            context: context.clone(),
            votes: Vec::new(),
        };
        for index in 0..=256 {
            let purchase_id = format!("completed-{index}");
            let replay = fixture
                .receiver
                .complete_checkout_purchase(
                    &purchase_id,
                    &fixture.bundle_bytes,
                    &dummy_proof,
                    std::slice::from_ref(&fixture.view),
                    &HashMap::new(),
                    fixture.now + 2,
                    Some(password),
                )
                .unwrap();
            assert!(!replay.newly_committed);
            assert!(replay.verdict.can_release_goods_automatically);
        }
        fixture
            .receiver
            .begin_checkout_purchase(
                "active-after-completed",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        fixture
            .receiver
            .with_wallet(|wallet| {
                assert_eq!(
                    wallet.profile.active_checkout_purchase_count(fixture.now),
                    1
                );
                assert_eq!(wallet.profile.l2_checkout_purchases.len(), 258);
            })
            .unwrap();
    }

    #[test]
    fn expired_active_reservation_renews_with_new_nonce_and_extended_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = checkout_fixture(dir.path());
        let password = "checkout-lifecycle-test";
        let first = fixture
            .receiver
            .begin_checkout_purchase(
                "renewable",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        let first_expiry = fixture
            .receiver
            .with_wallet(|wallet| {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .get("renewable")
                    .unwrap()
                    .expires_at_ms
            })
            .unwrap();
        let unchanged = fixture
            .receiver
            .begin_checkout_purchase(
                "renewable",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now + 1,
                Some(password),
            )
            .unwrap();
        assert_eq!(unchanged, first);
        let renewed = fixture
            .receiver
            .begin_checkout_purchase(
                "renewable",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                first_expiry + 1,
                Some(password),
            )
            .unwrap();
        assert_ne!(renewed.recipient_nonce, [0; 32]);
        assert_ne!(renewed.recipient_nonce, first.recipient_nonce);
        let (stored_expiry, stored_nonce, completed) = fixture
            .receiver
            .with_wallet(|wallet| {
                let purchase = wallet
                    .profile
                    .l2_checkout_purchases
                    .get("renewable")
                    .unwrap();
                (
                    purchase.expires_at_ms,
                    purchase.context.recipient_nonce,
                    purchase.completed,
                )
            })
            .unwrap();
        assert!(stored_expiry > first_expiry);
        assert_eq!(stored_nonce, renewed.recipient_nonce);
        assert!(!completed);
        let error = fixture
            .receiver
            .begin_checkout_purchase(
                "renewable",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                renewed.root_valid_until,
                Some(password),
            )
            .unwrap_err();
        assert_security_error(&error, "purchase root expired");
    }

    #[test]
    fn expired_challenge_renewal_refreshes_committee_and_accepts_new_roster() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = checkout_fixture(dir.path());
        let password = "checkout-lifecycle-test";
        let first = fixture
            .receiver
            .begin_checkout_purchase(
                "renew-authority",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        let first_expiry = fixture
            .receiver
            .with_wallet(|wallet| {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .get("renew-authority")
                    .unwrap()
                    .expires_at_ms
            })
            .unwrap();
        let source = SigningKey::from_bytes(&[100; 32]);
        let updated_keys: Vec<_> = (21..=40u8)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let mut updated_members: Vec<_> = updated_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RegionalMeshMember {
                node_pubkey: key.verifying_key().to_bytes(),
                hrw_routing_id: [(index + 21) as u8; 32],
            })
            .collect();
        updated_members.sort_by_key(|member| member.node_pubkey);
        let mut updated_view = RegionalMeshView {
            version: 1,
            network: 0,
            source_key: fixture.view.source_key,
            issued_at_ms: fixture.now,
            valid_until_ms: fixture.now + 60_000,
            members: updated_members,
            signature: [0; 64],
        };
        updated_view.signature = source.sign(&updated_view.digest().unwrap()).to_bytes();
        let renewal_now = first_expiry + 1;
        let expected_committee = fixture
            .receiver
            .with_wallet(|wallet| {
                let policy = wallet.profile.l2_regional_mesh_policy.as_ref().unwrap();
                regional_committee(
                    policy,
                    std::slice::from_ref(&updated_view),
                    first.shard_id,
                    renewal_now,
                )
                .unwrap()
            })
            .unwrap();
        assert_ne!(expected_committee, first.committee);
        let renewed = fixture
            .receiver
            .begin_checkout_purchase(
                "renew-authority",
                &fixture.bundle_bytes,
                std::slice::from_ref(&updated_view),
                renewal_now,
                Some(password),
            )
            .unwrap();
        assert_ne!(renewed.recipient_nonce, first.recipient_nonce);
        assert_eq!(renewed.committee, expected_committee);
        fixture
            .receiver
            .with_wallet(|wallet| {
                let stored = wallet
                    .profile
                    .l2_checkout_purchases
                    .get("renew-authority")
                    .unwrap();
                assert_eq!(stored.context.committee, expected_committee);
                assert_eq!(stored.context.recipient_nonce, renewed.recipient_nonce);
            })
            .unwrap();
        let digest = humoco_proto::live::live_state_digest(&renewed).unwrap();
        let votes = renewed
            .committee
            .iter()
            .map(|public| {
                let key = updated_keys
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
            context: renewed.clone(),
            votes,
        };
        let completed = fixture
            .receiver
            .complete_checkout_purchase(
                "renew-authority",
                &fixture.bundle_bytes,
                &proof,
                std::slice::from_ref(&updated_view),
                &fixture.standards,
                renewal_now + 1,
                Some(password),
            )
            .unwrap();
        assert!(completed.newly_committed);
        assert!(completed.verdict.can_release_goods_automatically);
    }

    #[test]
    fn intra_ttl_committee_change_refreshes_stored_authority() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = checkout_fixture(dir.path());
        let password = "checkout-lifecycle-test";
        let first = fixture
            .receiver
            .begin_checkout_purchase(
                "intra-ttl-authority",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        let source = SigningKey::from_bytes(&[100; 32]);
        let updated_keys: Vec<_> = (21..=40u8)
            .map(|seed| SigningKey::from_bytes(&[seed; 32]))
            .collect();
        let mut updated_members: Vec<_> = updated_keys
            .iter()
            .enumerate()
            .map(|(index, key)| RegionalMeshMember {
                node_pubkey: key.verifying_key().to_bytes(),
                hrw_routing_id: [(index + 21) as u8; 32],
            })
            .collect();
        updated_members.sort_by_key(|member| member.node_pubkey);
        let mut updated_view = RegionalMeshView {
            version: 1,
            network: 0,
            source_key: fixture.view.source_key,
            issued_at_ms: fixture.now,
            valid_until_ms: fixture.now + 60_000,
            members: updated_members,
            signature: [0; 64],
        };
        updated_view.signature = source.sign(&updated_view.digest().unwrap()).to_bytes();
        let change_now = fixture.now + 1;
        let expected_committee = fixture
            .receiver
            .with_wallet(|wallet| {
                let policy = wallet.profile.l2_regional_mesh_policy.as_ref().unwrap();
                regional_committee(
                    policy,
                    std::slice::from_ref(&updated_view),
                    first.shard_id,
                    change_now,
                )
                .unwrap()
            })
            .unwrap();
        assert_ne!(expected_committee, first.committee);
        let refreshed = fixture
            .receiver
            .begin_checkout_purchase(
                "intra-ttl-authority",
                &fixture.bundle_bytes,
                std::slice::from_ref(&updated_view),
                change_now,
                Some(password),
            )
            .unwrap();
        assert_eq!(refreshed.committee, expected_committee);
        assert_eq!(refreshed.recipient_nonce, first.recipient_nonce);
        fixture
            .receiver
            .with_wallet(|wallet| {
                let stored = wallet
                    .profile
                    .l2_checkout_purchases
                    .get("intra-ttl-authority")
                    .unwrap();
                assert_eq!(stored.context.committee, expected_committee);
                assert_eq!(stored.context.recipient_nonce, refreshed.recipient_nonce);
            })
            .unwrap();
        let digest = humoco_proto::live::live_state_digest(&refreshed).unwrap();
        let votes = refreshed
            .committee
            .iter()
            .map(|public| {
                let key = updated_keys
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
            context: refreshed.clone(),
            votes,
        };
        let completed = fixture
            .receiver
            .complete_checkout_purchase(
                "intra-ttl-authority",
                &fixture.bundle_bytes,
                &proof,
                std::slice::from_ref(&updated_view),
                &fixture.standards,
                change_now + 1,
                Some(password),
            )
            .unwrap();
        assert!(completed.newly_committed);
    }

    #[test]
    fn unexpired_active_reservations_are_bounded_and_expired_entries_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let mut fixture = checkout_fixture(dir.path());
        let password = "checkout-lifecycle-test";
        fixture
            .receiver
            .begin_checkout_purchase(
                "active-0",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        let template = fixture
            .receiver
            .with_wallet(|wallet| {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .get("active-0")
                    .cloned()
            })
            .unwrap()
            .unwrap();
        {
            let wallet = fixture.receiver.get_wallet_mut().unwrap();
            for index in 1..MAX_ACTIVE_CHECKOUT_PURCHASES {
                wallet
                    .profile
                    .l2_checkout_purchases
                    .insert(format!("active-{index}"), template.clone());
            }
        }
        let error = fixture
            .receiver
            .begin_checkout_purchase(
                "overflow",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap_err();
        assert_security_error(&error, "purchase capacity exhausted");
        fixture
            .receiver
            .get_wallet_mut()
            .unwrap()
            .profile
            .l2_checkout_purchases
            .get_mut("active-255")
            .unwrap()
            .expires_at_ms = fixture.now;
        fixture
            .receiver
            .begin_checkout_purchase(
                "replacement",
                &fixture.bundle_bytes,
                std::slice::from_ref(&fixture.view),
                fixture.now,
                Some(password),
            )
            .unwrap();
        fixture
            .receiver
            .with_wallet(|wallet| {
                assert_eq!(
                    wallet.profile.active_checkout_purchase_count(fixture.now),
                    MAX_ACTIVE_CHECKOUT_PURCHASES
                );
                assert!(
                    !wallet
                        .profile
                        .l2_checkout_purchases
                        .contains_key("active-255")
                );
            })
            .unwrap();
    }

    #[test]
    fn purchase_commit_binds_real_l1_challenge_authority_and_idempotent_restart() {
        let dir = tempfile::tempdir().unwrap();
        let password = "atomic-checkout-test";
        let (mut sender, sender_profile) = test_utils::setup_service_with_profile(
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
            .create_transfer_bundle_with_l2_intents(
                MultiTransferRequest {
                    recipient_id: recipient,
                    sources: vec![SourceTransfer {
                        local_instance_id: local.clone(),
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
        let intent = sender.pending_l2_send_intent(&local).unwrap();
        assert!(!intent.chain_request_bytes.is_empty());
        let chain: crate::models::layer2_api::L2ChainLockRequest =
            serde_json::from_slice(&intent.chain_request_bytes).unwrap();
        let request: crate::models::layer2_api::L2LockRequest =
            serde_json::from_slice(&intent.request_bytes).unwrap();
        assert_eq!(
            chain.chain.last().unwrap().transaction_hash,
            request.transaction_hash
        );
        assert_eq!(request.created_at_ms, intent.created_at_ms);
        sender.logout();
        drop(sender);
        let mut sender = AppService::new(&dir.path().join("sender")).unwrap();
        sender
            .login(
                &sender_profile.folder_name,
                password,
                false,
                "test-id".into(),
            )
            .unwrap();
        assert_eq!(
            sender.pending_l2_send_intent(&local).unwrap(),
            intent,
            "the transfer and exact intent survive the same managed commit"
        );
        receiver
            .with_wallet_and_identity(|_, identity| {
                let opened =
                    bundle_processor::open_and_verify_bundle(identity, &bundle.bundle_bytes)
                        .unwrap();
                let voucher = &opened.vouchers[0];
                assert_eq!(opened.causal_outputs.len(), voucher.transactions.len());
                for transaction in &voucher.transactions {
                    let proof = opened.causal_outputs.get(&transaction.t_id).unwrap();
                    crate::services::l2_causality::validate_output_proof(
                        voucher,
                        transaction,
                        proof,
                    )
                    .unwrap();
                    let mut forged = proof.clone();
                    forged.state_hash = [99; 32];
                    assert!(
                        crate::services::l2_causality::validate_output_proof(
                            voucher,
                            transaction,
                            &forged
                        )
                        .is_err()
                    );
                }
                let last = voucher.transactions.last().unwrap();
                let request = l2_gateway::generate_lock_request(
                    &l2_gateway::calculate_layer2_voucher_id(&voucher.transactions[0]).unwrap(),
                    last,
                    &[0; 32],
                )
                .unwrap();
                let chain = l2_gateway::build_voucher_lock_chain_with_outputs(
                    voucher,
                    None,
                    request,
                    &opened.causal_outputs,
                )
                .unwrap();
                assert!(chain.chain[0].is_genesis);
                assert!(chain.chain[0].causal_output.is_some());
                let previous = chain.chain[0].causal_output.as_ref().unwrap();
                let expected = crate::services::crypto::get_ds_tag(
                    &bs58::encode(previous.state_hash).into_string(),
                    last.sender_ephemeral_pub.as_ref().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    chain.chain[1].ds_tag.as_deref(),
                    Some(expected.as_str()),
                    "the real L1 SST formula must remain unchanged"
                );
                assert_eq!(
                    chain.chain[1].ds_tag.as_deref(),
                    last.trap_data.as_ref().map(|trap| trap.ds_tag.as_str())
                );
            })
            .unwrap();
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
        assert!(
            receiver
                .is_checkout_purchase_completed("sale-123", &bundle.bundle_bytes)
                .unwrap()
        );
        assert!(
            !receiver
                .is_checkout_purchase_completed("sale-999", &bundle.bundle_bytes)
                .unwrap()
        );
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
