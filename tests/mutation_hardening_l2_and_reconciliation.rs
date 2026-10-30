//! # tests/mutation_hardening_l2_and_reconciliation.rs
//!
//! Targeted mutation hardening tests for:
//! - `src/wallet/reconciliation.rs` (status queries, dual lookup by local_instance_id / voucher_id, and state reconciliation)
//! - `src/app_service/checkout.rs` (oversized container bounds, authority/committee validation, conflict fail-closed assertions)
//! - `src/app_service/l2_intents.rs` (proof verification before expiration window, selective conflict quarantine, terminal cleanup retention bounds)

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};

use human_money_core::app_service::AppService;
use human_money_core::models::l2_intent::{IntentTerminalResolution, L2SendIntent};
use human_money_core::models::layer2_api::{
    L2LockEntry, VoucherReconciliationResult,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{NewVoucherData, ValueDefinition};
use human_money_core::services::bundle_processor::MAX_CONTAINER_BYTES;
use human_money_core::services::l2_gateway::{
    extract_layer2_voucher_id, generate_lock_request,
};
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
use humoco_proto::live::{LiveStateContext, LiveStateProof};
use humoco_proto::mesh::{RegionalMeshMember, RegionalMeshPolicy, RegionalMeshView};
use humoco_proto::AttestationVote;

struct TestPoSFixture {
    sender: AppService,
    receiver: AppService,
    sender_pw: &'static str,
    receiver_pw: &'static str,
    bundle_bytes: Vec<u8>,
    standards: HashMap<String, String>,
    view: RegionalMeshView,
    keys: Vec<SigningKey>,
    source: SigningKey,
    now: u64,
}

impl TestPoSFixture {
    fn fresh_view_at(&self, at_ms: u64) -> RegionalMeshView {
        let mut v = self.view.clone();
        v.issued_at_ms = at_ms;
        v.valid_until_ms = at_ms + 60_000;
        v.signature = self.source.sign(&v.digest().unwrap()).to_bytes();
        v
    }

    fn proof_for_context(&self, context: &LiveStateContext) -> LiveStateProof {
        let digest = humoco_proto::live::live_state_digest(context).unwrap();
        let votes = context
            .committee
            .iter()
            .take(14)
            .map(|public| {
                let key = self
                    .keys
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
}

fn setup_pos_fixture(dir: &Path) -> TestPoSFixture {
    let sender_pw = "sender-pw-hardening";
    let receiver_pw = "receiver-pw-hardening";

    let (mut sender, _) = test_utils::setup_service_with_profile(
        &dir.join("sender"),
        &ACTORS.alice,
        "Sender",
        sender_pw,
    );
    let (mut receiver, _) = test_utils::setup_service_with_profile(
        &dir.join("receiver"),
        &ACTORS.bob,
        "Receiver",
        receiver_pw,
    );

    let sender_id = sender
        .with_wallet(|w| w.get_user_id().to_string())
        .unwrap();
    let recipient_id = receiver
        .with_wallet(|w| w.get_user_id().to_string())
        .unwrap();

    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let voucher = sender
        .create_new_voucher(
            &standard_str,
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
            Some(sender_pw),
        )
        .unwrap();

    let local_vid = sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let standards = HashMap::from([(voucher.voucher_standard.uuid.clone(), standard_str)]);

    let bundle = sender
        .create_transfer_bundle_with_l2_intents(
            MultiTransferRequest {
                recipient_id,
                sources: vec![SourceTransfer {
                    local_instance_id: local_vid,
                    amount_to_send: "10".into(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: Some(false),
            },
            &standards,
            None,
            Some(sender_pw),
            0,
        )
        .unwrap();

    let source = SigningKey::from_bytes(&[100; 32]);
    let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let now = u64::try_from(Utc::now().timestamp_millis()).unwrap();

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

    sender
        .configure_regional_mesh_authority(
            RegionalMeshPolicy {
                network: 0,
                source_keys: vec![view.source_key],
            },
            Some(sender_pw),
        )
        .unwrap();

    receiver
        .configure_regional_mesh_authority(
            RegionalMeshPolicy {
                network: 0,
                source_keys: vec![view.source_key],
            },
            Some(receiver_pw),
        )
        .unwrap();

    TestPoSFixture {
        sender,
        receiver,
        sender_pw,
        receiver_pw,
        bundle_bytes: bundle.bundle_bytes,
        standards,
        view,
        keys,
        source,
        now,
    }
}

// -----------------------------------------------------------------------------
// Mutation Hardening 1: Wallet Reconciliation by Local ID and Deed Voucher ID
// -----------------------------------------------------------------------------
#[test]
fn test_build_voucher_status_query_and_reconcile_state_by_deed_voucher_id_and_multi_voucher() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let pw = "hardening-recon-pw";
    let (mut alice_app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.alice,
        "Alice",
        pw,
    );

    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let standard_def = FREETALER_STANDARD.0.clone();
    let alice_id = alice_app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let v1 = alice_app.create_new_voucher(
        &standard_str,
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(alice_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "50".into(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(pw),
    ).unwrap();

    let v2 = alice_app.create_new_voucher(
        &standard_str,
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(alice_id),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "75".into(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(pw),
    ).unwrap();

    let (v1_local_id, v2_local_id) = alice_app.with_wallet(|w| {
        let id1 = w.voucher_store.vouchers.iter()
            .find(|(_, inst)| inst.voucher.voucher_id == v1.voucher_id)
            .map(|(k, _)| k.clone())
            .unwrap();
        let id2 = w.voucher_store.vouchers.iter()
            .find(|(_, inst)| inst.voucher.voucher_id == v2.voucher_id)
            .map(|(k, _)| k.clone())
            .unwrap();
        (id1, id2)
    }).unwrap();

    assert_ne!(v1.voucher_id, v1_local_id);
    assert_ne!(v2.voucher_id, v2_local_id);
    assert_ne!(v1_local_id, v2_local_id);

    let l2_id_1 = extract_layer2_voucher_id(&v1).unwrap();
    let l2_id_2 = extract_layer2_voucher_id(&v2).unwrap();

    // 1. Query by local_instance_id when multiple vouchers exist
    // Guards against: replacing `==` with `!=` in `reconciliation.rs:47`
    {
        let (wallet, identity) = alice_app.get_unlocked_for_test();
        let q = wallet.build_voucher_status_query(identity, &v2_local_id, 1).unwrap();
        assert_eq!(q.layer2_voucher_id, l2_id_2);
        assert_ne!(q.layer2_voucher_id, l2_id_1);
    }

    // 2. Query by deed voucher_id (not local_instance_id)
    // Guards against: replacing `||` with `&&` in `reconciliation.rs:48`
    // and replacing `==` with `!=` in `reconciliation.rs:48`
    {
        let (wallet, identity) = alice_app.get_unlocked_for_test();
        let q = wallet.build_voucher_status_query(identity, &v2.voucher_id, 1).unwrap();
        assert_eq!(q.layer2_voucher_id, l2_id_2);
        assert_ne!(q.layer2_voucher_id, l2_id_1);
    }

    // 3. Reconcile unspent voucher state by deed voucher_id
    // Guards against: replacing `==` with `!=` in `reconciliation.rs:111`
    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let res = wallet.reconcile_voucher_state(identity, &v2.voucher_id, None).unwrap();
        assert!(matches!(res, VoucherReconciliationResult::UnspentSafe));
        assert_eq!(wallet.voucher_store.vouchers.get(&v1_local_id).unwrap().status, VoucherStatus::Active);
        assert_eq!(wallet.voucher_store.vouchers.get(&v2_local_id).unwrap().status, VoucherStatus::Active);
    }

    // 4. Reconcile spent voucher state by deed voucher_id
    // Simulates remote L2 spend on v2, asserting v2 transitions to Archived while v1 remains Active
    let mut alice_clone = alice_app.get_wallet_for_test().unwrap().clone();
    let alice_identity = ACTORS.alice.identity.clone();
    let spent_voucher_t2 = alice_clone
        ._execute_single_transfer(
            &alice_identity,
            &standard_def,
            &v2_local_id,
            &ACTORS.bob.identity.user_id,
            "10.00",
            None,
            None,
            None,
        )
        .unwrap();
    let spend_tx_t2 = spent_voucher_t2.transactions.last().unwrap();
    let holder_signing_key = {
        let (wallet, identity) = alice_app.get_unlocked_for_test();
        wallet.rederive_secret_seed(&v2, identity).unwrap()
    };
    let req_t2 = generate_lock_request(
        &l2_id_2,
        spend_tx_t2,
        holder_signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    let lock_entry_t2 = L2LockEntry::from(req_t2);

    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let res = wallet
            .reconcile_voucher_state(identity, &v2.voucher_id, Some(&lock_entry_t2))
            .unwrap();
        assert!(matches!(res, VoucherReconciliationResult::AlreadySpent { .. }));
        assert_eq!(wallet.voucher_store.vouchers.get(&v2_local_id).unwrap().status, VoucherStatus::Archived);
        assert_eq!(wallet.voucher_store.vouchers.get(&v1_local_id).unwrap().status, VoucherStatus::Active);
    }
}

// -----------------------------------------------------------------------------
// Mutation Hardening 2: Checkout Boundary on Oversized Containers
// -----------------------------------------------------------------------------
#[test]
fn test_complete_checkout_purchase_oversized_bundle_boundary() {
    let dir = tempfile::TempDir::new().unwrap();
    let pw = "oversized-pw";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.alice,
        "Alice",
        pw,
    );

    // Guards against: replacing `>` with `==` in `checkout.rs:313`
    let oversized_bundle = vec![0u8; MAX_CONTAINER_BYTES + 1];
    let dummy_proof = LiveStateProof {
        context: LiveStateContext {
            version: 1,
            network: 0,
            shard_id: 0,
            voucher_id: String::new(),
            lookup_tag: String::new(),
            parent_lock: [0; 32],
            child_lock: [0; 32],
            root_valid_until: 0,
            state_digest: [0; 32],
            recipient_nonce: [0; 32],
            committee: vec![[0; 32]; 20],
        },
        votes: vec![],
    };
    let standards = HashMap::new();

    let res = app.complete_checkout_purchase(
        "any-purchase-id",
        &oversized_bundle,
        &dummy_proof,
        &[],
        &standards,
        1_000,
        Some(pw),
    );

    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("purchase bundle too large"));
}

// -----------------------------------------------------------------------------
// Mutation Hardening 3: Authority Mismatch via Network OR Committee
// -----------------------------------------------------------------------------
#[test]
fn test_complete_checkout_purchase_authority_mismatch_network_or_committee() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    let purchase_id = "authority-test-1";
    let views = vec![pos.view.clone()];
    let context = pos
        .receiver
        .begin_checkout_purchase(
            purchase_id,
            &pos.bundle_bytes,
            &views,
            pos.now + 1_000,
            Some(pos.receiver_pw),
        )
        .unwrap();

    let proof = pos.proof_for_context(&context);

    // Case 3A: Network matches, but committee differs (e.g. rotated validator set in views)
    // Guards against: replacing `||` with `&&` in `checkout.rs:355`
    let alt_keys: Vec<_> = (21..=40).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let mut alt_members: Vec<_> = alt_keys
        .iter()
        .enumerate()
        .map(|(i, key)| RegionalMeshMember {
            node_pubkey: key.verifying_key().to_bytes(),
            hrw_routing_id: [i as u8; 32],
        })
        .collect();
    alt_members.sort_by_key(|m| m.node_pubkey);

    let mut alt_view = RegionalMeshView {
        version: 1,
        network: 0,
        source_key: pos.source.verifying_key().to_bytes(),
        issued_at_ms: pos.now,
        valid_until_ms: pos.now + 60_000,
        members: alt_members,
        signature: [0; 64],
    };
    alt_view.signature = pos.source.sign(&alt_view.digest().unwrap()).to_bytes();

    let res_alt_committee = pos.receiver.complete_checkout_purchase(
        purchase_id,
        &pos.bundle_bytes,
        &proof,
        &[alt_view],
        &pos.standards,
        pos.now + 2_000,
        Some(pos.receiver_pw),
    );

    assert!(res_alt_committee.is_err());
    assert!(
        res_alt_committee.unwrap_err().to_string().contains("purchase authority changed"),
        "Different committee must be rejected with 'purchase authority changed' even if network matches"
    );
}

// -----------------------------------------------------------------------------
// Mutation Hardening 4: Fail-Closed on Double-Spend Conflicts or Warnings
// -----------------------------------------------------------------------------
#[test]
fn test_complete_checkout_purchase_fails_closed_on_conflicts_or_warnings() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let sender_pw = "sender-pw-conflict";
    let receiver_pw = "receiver-pw-conflict";

    let (mut sender, _) = test_utils::setup_service_with_profile(
        &dir.path().join("sender"),
        &ACTORS.alice,
        "Sender",
        sender_pw,
    );
    let (mut receiver, _) = test_utils::setup_service_with_profile(
        &dir.path().join("receiver"),
        &ACTORS.bob,
        "Receiver",
        receiver_pw,
    );

    let sender_id = sender.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let recipient_id = receiver.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let voucher = sender
        .create_new_voucher(
            &standard_str,
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
            Some(sender_pw),
        )
        .unwrap();

    let local_vid = sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let standards = HashMap::from([(voucher.voucher_standard.uuid.clone(), standard_str)]);

    // Clone the sender wallet snapshot before any transfer to create a fork
    let mut sender_wallet_snapshot = sender.get_wallet_for_test().unwrap().clone();

    // Transfer 1 -> bundle_1 via sender service
    let bundle_1 = sender
        .create_transfer_bundle_with_l2_intents(
            MultiTransferRequest {
                recipient_id: recipient_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: local_vid.clone(),
                    amount_to_send: "10".into(),
                }],
                notes: Some("Spend A".into()),
                sender_profile_name: None,
                use_privacy_mode: Some(false),
            },
            &standards,
            None,
            Some(sender_pw),
            0,
        )
        .unwrap();

    // Transfer 2 -> bundle_2 from snapshot (spends the exact same local_vid without L2 intent restrictions)
    let mut std_map = HashMap::new();
    std_map.insert(voucher.voucher_standard.uuid.clone(), FREETALER_STANDARD.0.clone());
    let bundle_2 = sender_wallet_snapshot
        .execute_multi_transfer_and_bundle(
            &ACTORS.alice.identity,
            &std_map,
            MultiTransferRequest {
                recipient_id: recipient_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: local_vid,
                    amount_to_send: "10".into(),
                }],
                notes: Some("Spend B".into()),
                sender_profile_name: None,
                use_privacy_mode: Some(false),
            },
            None,
        )
        .unwrap();

    let source = SigningKey::from_bytes(&[100; 32]);
    let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let now = u64::try_from(Utc::now().timestamp_millis()).unwrap();

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
            Some(receiver_pw),
        )
        .unwrap();

    // 1. Legitimate receive of bundle_1
    receiver
        .receive_bundle(
            &bundle_1.bundle_bytes,
            &standards,
            None,
            Some(receiver_pw),
            false,
        )
        .unwrap();

    // 2. Attacker attempts checkout with conflicting bundle_2 (different bundle ID, same spent parent)
    let purchase_id = "conflict-fail-closed-1";
    let views = vec![view.clone()];
    let context = receiver
        .begin_checkout_purchase(
            purchase_id,
            &bundle_2.bundle_bytes,
            &views,
            now + 1_000,
            Some(receiver_pw),
        )
        .unwrap();

    let digest = humoco_proto::live::live_state_digest(&context).unwrap();
    let votes = context
        .committee
        .iter()
        .take(14)
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
        context,
        votes,
    };

    // Guards against: replacing `||` with `&&` in `checkout.rs:378`
    // If skipped due to `&&` when warnings is empty, it would fall through to line 386 and return
    // "Invalid: imported purchase voucher is not active" instead of "Invalid: imported purchase bundle has conflicts or warnings".
    let result = receiver.complete_checkout_purchase(
        purchase_id,
        &bundle_2.bundle_bytes,
        &proof,
        &views,
        &standards,
        now + 2_000,
        Some(receiver_pw),
    );

    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("imported purchase bundle has conflicts or warnings"),
        "Must specifically fail with 'imported purchase bundle has conflicts or warnings'"
    );
}

// -----------------------------------------------------------------------------
// Mutation Hardening 5: Invalid Proof Handling Before vs At Expiration Window
// -----------------------------------------------------------------------------
#[test]
fn test_complete_intent_reconciliation_invalid_proof_before_root_valid_until_rolls_back() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    let local_id = pos
        .sender
        .with_wallet(|w| {
            w.profile
                .l2_send_intents
                .keys()
                .next()
                .unwrap()
                .clone()
        })
        .unwrap();

    let t_recon = pos.now + 31_000;
    let views = vec![pos.fresh_view_at(t_recon)];
    let recon_ctx = pos
        .sender
        .begin_intent_reconciliation(&local_id, &views, t_recon, Some(pos.sender_pw))
        .unwrap();

    // Construct a proof with a corrupted signature so verify_live_state_proof fails
    let mut corrupted_proof = pos.proof_for_context(&recon_ctx);
    corrupted_proof.votes[0].signature = [0xff; 64];

    // Guards against: replacing `>=` with `<` in `l2_intents.rs:381`
    // When now_ms < root_valid_until_ms, an invalid proof MUST roll back with error, NOT resolve to Expired!
    let now_ms = t_recon + 100;
    assert!(now_ms < recon_ctx.root_valid_until);

    let res = pos.sender.complete_intent_reconciliation(
        &local_id,
        &corrupted_proof,
        &views,
        now_ms,
        Some(pos.sender_pw),
    );

    assert!(
        res.is_err(),
        "Invalid proof before root_valid_until_ms MUST rollback with Err, not Expired!"
    );
}

// -----------------------------------------------------------------------------
// Mutation Hardening 6: Conflict Reconciliation Quarantines Only Matching Tx
// -----------------------------------------------------------------------------
#[test]
fn test_complete_intent_reconciliation_conflict_quarantines_only_matching_tx_id() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    let local_id = pos
        .sender
        .with_wallet(|w| {
            w.profile
                .l2_send_intents
                .keys()
                .next()
                .unwrap()
                .clone()
        })
        .unwrap();

    // Create an independent, unrelated voucher in sender's wallet
    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let sender_id = pos.sender.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let unrelated_voucher = pos
        .sender
        .create_new_voucher(
            &standard_str,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(sender_id),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "40".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(pos.sender_pw),
        )
        .unwrap();

    let unrelated_local_id = pos
        .sender
        .with_wallet(|w| {
            w.voucher_store
                .vouchers
                .iter()
                .find(|(_, inst)| inst.voucher.voucher_id == unrelated_voucher.voucher_id)
                .map(|(k, _)| k.clone())
                .unwrap()
        })
        .unwrap();

    pos.sender
        .with_wallet(|w| {
            assert_eq!(
                w.voucher_store.vouchers.get(&unrelated_local_id).unwrap().status,
                VoucherStatus::Active
            );
        })
        .unwrap();

    let t_recon = pos.now + 31_000;
    let views = vec![pos.fresh_view_at(t_recon)];
    let recon_ctx = pos
        .sender
        .begin_intent_reconciliation(&local_id, &views, t_recon, Some(pos.sender_pw))
        .unwrap();

    // Construct competing child_lock proof (simulates conflict)
    let conflict_ctx = LiveStateContext {
        child_lock: [0xabu8; 32],
        state_digest: [0xcdu8; 32],
        ..recon_ctx
    };
    let conflict_proof = pos.proof_for_context(&conflict_ctx);

    let res = pos.sender.complete_intent_reconciliation(
        &local_id,
        &conflict_proof,
        &views,
        t_recon + 200,
        Some(pos.sender_pw),
    ).unwrap();

    assert!(matches!(res, IntentTerminalResolution::Conflicted { .. }));

    // Guards against: replacing `==` with `!=` in `l2_intents.rs:423`
    // Unrelated voucher with DIFFERENT tx_id MUST remain Active and NOT be quarantined!
    pos.sender
        .with_wallet(|w| {
            let unrelated_inst = w.voucher_store.vouchers.get(&unrelated_local_id).unwrap();
            assert_eq!(
                unrelated_inst.status,
                VoucherStatus::Active,
                "Unrelated voucher MUST NOT be quarantined when intent conflicts!"
            );
        })
        .unwrap();
}

// -----------------------------------------------------------------------------
// Mutation Hardening 7: Terminal Intent Cleanup Retention Boundary
// -----------------------------------------------------------------------------
#[test]
fn test_cleanup_terminal_intents_exact_boundary_and_retention() {
    let dir = tempfile::TempDir::new().unwrap();
    let pw = "cleanup-hardening-pw";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.alice,
        "Alice",
        pw,
    );

    let dummy_intent = |local_id: &str, resolution: IntentTerminalResolution| L2SendIntent {
        local_instance_id: local_id.to_string(),
        request_bytes: vec![],
        chain_request_bytes: vec![],
        transaction_bytes: vec![],
        created_at_ms: 100,
        network: 0,
        shard_id: 0,
        root_valid_until_ms: 1_000,
        retained_original_observed: false,
        stored_challenge: None,
        challenge_expires_at_ms: None,
        stored_committee: None,
        created_change_local_id: None,
        terminal_resolution: Some(resolution),
    };

    // 1. Expired intent: resolved at 1_000
    // 2. Fresh intent: resolved at 5_000
    let intent_expired = dummy_intent(
        "intent_expired",
        IntentTerminalResolution::Confirmed { resolved_at_ms: 1_000 },
    );
    let intent_fresh = dummy_intent(
        "intent_fresh",
        IntentTerminalResolution::Confirmed { resolved_at_ms: 5_000 },
    );

    {
        let (wallet, _) = app.get_unlocked_mut_for_test();
        wallet
            .profile
            .l2_send_intents
            .insert("intent_expired".into(), intent_expired);
        wallet
            .profile
            .l2_send_intents
            .insert("intent_fresh".into(), intent_fresh);
    }

    let max_retain_ms = 1_000;
    // Exactly at the boundary for intent_expired: 1_000 + 1_000 = 2_000
    let now_ms = 2_000;

    // Guards against:
    // - replacing `<` with `<=` in `l2_intents.rs:520` (would keep intent_expired at boundary, returning 0)
    // - replacing `<` with `==` in `l2_intents.rs:520` (would drop intent_fresh, keeping only boundary)
    let removed = app
        .cleanup_terminal_intents(max_retain_ms, now_ms, Some(pw))
        .unwrap();

    assert_eq!(
        removed, 1,
        "Exactly 1 intent must be removed at the exact retention boundary"
    );

    let intents = app.with_wallet(|w| w.profile.l2_send_intents.clone()).unwrap();
    assert!(
        !intents.contains_key("intent_expired"),
        "Expired intent must be cleaned up"
    );
    assert!(
        intents.contains_key("intent_fresh"),
        "Fresh intent must be retained"
    );
}
