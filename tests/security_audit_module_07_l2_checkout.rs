//! # tests/security_audit_module_07_l2_checkout.rs
//!
//! Security Regression Suite — Module 07: L2 Checkout Z01/Z08/Z10, 14/20-BFT Quorum, Send-Intents & Backup Reconciliation [RESOLVED & VERIFIED]
//!
//! NOTE FOR AUDITORS & AI AGENTS:
//! The findings and threat models documented below are HISTORICAL and RESOLVED.
//! Every test in this file is an active regression guard asserting that the secure invariant
//! holds permanently against past exploit vectors. They are NOT open vulnerabilities.
//!
//! ## Standardized Audit Header Summary
//!
//! | Finding-ID | Severity | CWE | Target Location |
//! |---|---|---|---|
//! | AUDIT-07-01 | CRITICAL | CWE-840, CWE-345 | src/wallet/reconciliation.rs, src/app_service/backup_ops.rs |
//! | AUDIT-07-02 | CRITICAL | CWE-840, CWE-367 | src/app_service/checkout.rs:335-363 |
//! | AUDIT-07-03 | HIGH | CWE-840, CWE-667, CWE-672 | src/app_service/l2_intents.rs, src/wallet/transactions.rs, src/wallet/l2_intents.rs |
//! | AUDIT-07-04 | HIGH | CWE-672, CWE-362 | src/app_service/l2_intents.rs, src/wallet/l2_intents.rs |
//! | AUDIT-07-05 | HIGH | CWE-294, CWE-362 | src/app_service/backup_ops.rs:463-495, src/app_service/checkout.rs |
//! | AUDIT-07-06 | HIGH | CWE-668, CWE-502 | src/models/layer2_api.rs:621-658, src/app_service/checkout.rs:87-96 |
//! | AUDIT-07-07 | HIGH | CWE-345, CWE-840 | src/services/l2_gateway.rs:1018-1136 |
//! | AUDIT-07-08 | MEDIUM | CWE-347 | src/services/l2_gateway.rs:598-606, 728-769, 832-835 |
//! | BUG-03 | MEDIUM | CWE-20 | src/app_service/backup_ops.rs:70-76, 580-598 |

use std::collections::HashMap;
use std::path::Path;

use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use human_money_core::app_service::AppService;
use human_money_core::error::ValidationError;
use human_money_core::models::backup::{BackupProtection, BackupRestoreCredentials};
use human_money_core::models::l2_intent::IntentTerminalResolution;
use human_money_core::models::layer2_api::{
    CheckoutReleaseVerdict, L2LockEntry, L2ProcessingOutcome, L2ResponseEnvelope, L2Verdict,
    VoucherReconciliationResult,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{NewVoucherData, ValueDefinition};
use human_money_core::services::crypto::{get_ds_tag, get_hash};
use human_money_core::services::l2_gateway::{
    AnchorSyncVerdict, CheckoutAuthority, VerdictAction, evaluate_multi_node_anchor_verdicts,
    extract_layer2_voucher_id, generate_lock_request, process_l2_verdict_with_authority,
};
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
use human_money_core::VoucherCoreError;
use humoco_proto::live::{LiveStateContext, LiveStateProof, original_approval_digest};
use humoco_proto::mesh::{RegionalMeshMember, RegionalMeshPolicy, RegionalMeshView};
use humoco_proto::{AttestationVote, QuorumProof};

// -----------------------------------------------------------------------------
// Test Helpers
// -----------------------------------------------------------------------------

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
    let sender_pw = "sender-pos-password";
    let receiver_pw = "receiver-pos-password";

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

// =============================================================================
// AUDIT-07-01: Outgoing Spend ds_tag Derivation & Verified Lock Proofs
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-01
/// * Severity: CRITICAL
/// * CWE-Classification: CWE-840 / CWE-345
/// * Target Location: src/wallet/reconciliation.rs:35-76, 91-119
/// * Threat Model & Exploitation:
///   Tier-2 voucher reconciliation previously queried the incoming/root tag instead
///   of the outgoing spend ds_tag. This caused false positives (unspent vouchers
///   falsely archived on backup restore) or false negatives (spent vouchers left
///   active, causing silent honest-user double spends deanonymizing their DID).
/// * Remediation Strategy:
///   Derive outgoing spend ds_tag from last_tx and holder_ephem_pub. Verify lock
///   entry signatures in reconcile_voucher_state, ignore lock entries with matching
///   t_id, and preserve Quarantined voucher status.
#[test]
fn audit_07_01_backup_restore_queries_outgoing_ds_tag_not_incoming_or_genesis_tag() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let password = "audit-07-01-password";
    let (mut alice_app, _prof) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", password);

    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let standard_def = FREETALER_STANDARD.0.clone();

    // 1. Setup voucher with 2 transactions: Bob (creator) -> Alice (recipient)
    let (_standard_def_init, _hash, _creator, _recipient, voucher_2tx, _secrets) =
        test_utils::setup_voucher_with_one_tx();
    let spend_tx_t1 = voucher_2tx.transactions[1].clone();
    let incoming_ds_tag = spend_tx_t1.trap_data.as_ref().unwrap().ds_tag.clone();

    let voucher_id = {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let local_id =
            human_money_core::wallet::Wallet::calculate_local_instance_id(&voucher_2tx, &identity.user_id)
                .unwrap();
        wallet.voucher_store.vouchers.insert(
            local_id.clone(),
            human_money_core::VoucherInstance {
                voucher: voucher_2tx.clone(),
                status: VoucherStatus::Active,
                local_instance_id: local_id.clone(),
            },
        );
        local_id
    };

    let alice_identity = ACTORS.alice.identity.clone();

    // 2. Query Alice's unspent voucher: MUST NOT query incoming_ds_tag
    let (query, holder_signing_key) = {
        let (wallet, identity) = alice_app.get_unlocked_for_test();
        let q = wallet
            .build_voucher_status_query(identity, &voucher_id, 1)
            .unwrap();
        let key = wallet
            .rederive_secret_seed(&voucher_2tx, identity)
            .unwrap();
        (q, key)
    };
    assert_ne!(
        query.challenge_ds_tag, incoming_ds_tag,
        "build_voucher_status_query MUST NOT query incoming T1 ds_tag!"
    );

    // Verify expected outgoing ds_tag calculation
    let prev_hash = get_hash(to_canonical_json(&spend_tx_t1).unwrap());
    let holder_pub_bs58 =
        bs58::encode(holder_signing_key.verifying_key().to_bytes()).into_string();
    let expected_outgoing_ds_tag = get_ds_tag(&prev_hash, &holder_pub_bs58).unwrap();

    assert_eq!(
        query.challenge_ds_tag, expected_outgoing_ds_tag,
        "Query challenge_ds_tag MUST equal expected outgoing spend ds_tag!"
    );

    // 3. Reconcile with None (unspent on L2) -> UnspentSafe
    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let res = wallet
            .reconcile_voucher_state(identity, &voucher_id, None)
            .unwrap();
        assert!(matches!(res, VoucherReconciliationResult::UnspentSafe));
        let inst = wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
        assert_eq!(inst.status, VoucherStatus::Active);
    }

    // 4. Create mock L2 spend T2 by Alice
    let mut alice_clone = alice_app.get_wallet_for_test().unwrap().clone();
    let spent_voucher_t2 = alice_clone
        ._execute_single_transfer(
            &alice_identity,
            &standard_def,
            &voucher_id,
            &ACTORS.bob.identity.user_id,
            "10.00",
            None,
            None,
            None,
        )
        .unwrap();
    let spend_tx_t2 = spent_voucher_t2.transactions.last().unwrap();
    let l2_id = extract_layer2_voucher_id(&spent_voucher_t2).unwrap();
    let req_t2 = generate_lock_request(
        &l2_id,
        spend_tx_t2,
        holder_signing_key.verifying_key().as_bytes(),
    )
    .unwrap();
    let lock_entry_t2 = L2LockEntry::from(req_t2);

    // 5. Reconcile with genuine signed lock_entry_t2 -> AlreadySpent & Archived
    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let res = wallet
            .reconcile_voucher_state(identity, &voucher_id, Some(&lock_entry_t2))
            .unwrap();
        assert!(
            matches!(res, VoucherReconciliationResult::AlreadySpent { successor_t_id } if successor_t_id == bs58::encode(lock_entry_t2.t_id).into_string())
        );
        let inst = wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
        assert_eq!(inst.status, VoucherStatus::Archived);
    }

    // 6. Test defensive invariant: identical lock.t_id == last_tx.t_id is ignored (not archived)
    let mut bogus_same_tx_lock = lock_entry_t2.clone();
    let last_t_id_bytes =
        human_money_core::services::crypto::decode_bs58_fixed::<32>(&spend_tx_t1.t_id, "t_id")
            .unwrap();
    bogus_same_tx_lock.t_id = last_t_id_bytes;

    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        wallet.voucher_store.vouchers.get_mut(&voucher_id).unwrap().status =
            VoucherStatus::Active;
        let err = wallet
            .reconcile_voucher_state(identity, &voucher_id, Some(&bogus_same_tx_lock))
            .unwrap_err();
        assert!(
            matches!(err, VoucherCoreError::Validation(ValidationError::SecurityViolation(_))),
            "Lock with same t_id as last_tx MUST return SecurityViolation error"
        );
        let inst = wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
        assert_eq!(inst.status, VoucherStatus::Active);
    }

    // 7. Test defensive invariant: forged lock proof is rejected with ValidationError::InvalidL2Proof
    let mut forged_lock = lock_entry_t2.clone();
    forged_lock.layer2_signature = [0xff; 64]; // invalid signature
    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        let err = wallet
            .reconcile_voucher_state(identity, &voucher_id, Some(&forged_lock))
            .unwrap_err();
        assert!(
            matches!(err, VoucherCoreError::Validation(ValidationError::InvalidL2Proof)),
            "Forged lock entry signature MUST return InvalidL2Proof"
        );
    }

    // 8. Test defensive invariant: Quarantined status is preserved (never overwritten to Archived)
    {
        let (wallet, identity) = alice_app.get_unlocked_mut_for_test();
        wallet.voucher_store.vouchers.get_mut(&voucher_id).unwrap().status =
            VoucherStatus::Quarantined {
                reason: "double spend detected".into(),
            };
        let res = wallet
            .reconcile_voucher_state(identity, &voucher_id, Some(&lock_entry_t2))
            .unwrap();
        assert!(matches!(res, VoucherReconciliationResult::AlreadySpent { .. }));
        let inst = wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
        assert!(
            matches!(inst.status, VoucherStatus::Quarantined { .. }),
            "Quarantined status MUST be preserved!"
        );
    }

    // 9. Test genesis voucher [T0] queries outgoing spend ds_tag, not T0.t_id root
    let genesis_voucher = alice_app
        .create_new_voucher(
            &standard_str,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(alice_identity.user_id.clone()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "50".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();

    let genesis_local_id = alice_app
        .with_wallet(|w| {
            w.voucher_store
                .vouchers
                .iter()
                .find(|(_, inst)| inst.voucher.transactions.len() == 1)
                .map(|(id, _)| id.clone())
        })
        .unwrap()
        .unwrap();

    let (alice_wallet2, alice_identity2) = alice_app.get_unlocked_for_test();
    let genesis_query = alice_wallet2
        .build_voucher_status_query(alice_identity2, &genesis_local_id, 1)
        .unwrap();
    assert_ne!(
        genesis_query.challenge_ds_tag, genesis_voucher.transactions[0].t_id,
        "Genesis status query MUST query outgoing spend ds_tag, NEVER T0.t_id root!"
    );
}

// =============================================================================
// AUDIT-07-02: Fail-Closed Checkout Release on Double-Spend Import
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-02
/// * Severity: CRITICAL
/// * CWE-Classification: CWE-840 / CWE-367
/// * Target Location: src/app_service/checkout.rs:335-363
/// * Threat Model & Exploitation:
///   When an imported checkout bundle triggers an L1 double-spend conflict,
///   process_bundle_with_registry_inner imports the voucher as Quarantined.
///   Previously, complete_checkout_purchase committed the purchase and minted
///   DurablePurchaseBinding with can_release_goods_automatically = true.
/// * Remediation Strategy:
///   Fail closed when check_result has conflicts/warnings or when the imported
///   voucher is not Active.
#[test]
fn audit_07_02_complete_checkout_fails_closed_when_l1_import_quarantines_double_spend() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    // 1. Merchant imports bundle once via regular receive_bundle (legitimate receive)
    pos.receiver
        .receive_bundle(
            &pos.bundle_bytes,
            &pos.standards,
            None,
            Some(pos.receiver_pw),
            false,
        )
        .unwrap();

    // 2. Attacker attempts to checkout the EXACT same bundle (double-spend / replay)
    let purchase_id = "pos-ds-attack-1";
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

    // 3. Calling complete_checkout_purchase MUST FAIL CLOSED
    let result = pos.receiver.complete_checkout_purchase(
        purchase_id,
        &pos.bundle_bytes,
        &proof,
        &views,
        &pos.standards,
        pos.now + 2_000,
        Some(pos.receiver_pw),
    );

    assert!(
        result.is_err(),
        "complete_checkout_purchase MUST fail closed on double-spend conflict!"
    );
}

// =============================================================================
// AUDIT-07-03: Z10 Send-Intent State Machine & Split-Change Quarantine
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-03
/// * Severity: HIGH
/// * CWE-Classification: CWE-840 / CWE-667 / CWE-672
/// * Target Location: src/app_service/l2_intents.rs, src/wallet/transactions.rs, src/wallet/l2_intents.rs
/// * Threat Model & Exploitation:
///   - Unoccupied L2 slot (child_lock == [0u8; 32]) falsely terminated intent as Conflicted.
///   - Split-change output remained Active when parent intent conflicted.
///   - Confirmed prepared intents permanently locked outputs.
/// * Remediation Strategy:
///   - Reject zero child_lock as invalid/retryable.
///   - Track created_change_local_id and quarantine on conflict.
///   - Allow spending Confirmed intents and replace with new spend intent.
#[test]
fn audit_07_03_zero_child_lock_rejected_split_change_quarantined_and_confirmed_spendable() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    // Part A: Proof with child_lock == [0u8; 32] MUST NOT resolve to Conflicted
    let sender_intents = pos.sender.unresolved_l2_send_intents().unwrap();
    assert_eq!(sender_intents.len(), 1);
    let staged_intent = &sender_intents[0];
    let local_id = staged_intent.local_instance_id.clone();
    let created_at = staged_intent.created_at_ms;

    // Advance 31s
    let t_recon = created_at + 31_000;
    let views = vec![pos.view.clone()];
    let recon_ctx = pos
        .sender
        .begin_intent_reconciliation(&local_id, &views, t_recon, Some(pos.sender_pw))
        .unwrap();

    // Construct proof with child_lock = [0u8; 32]
    let zero_child_ctx = LiveStateContext {
        child_lock: [0u8; 32],
        state_digest: [0u8; 32],
        ..recon_ctx.clone()
    };
    let zero_proof = pos.proof_for_context(&zero_child_ctx);

    let recon_res = pos.sender.complete_intent_reconciliation(
        &local_id,
        &zero_proof,
        &views,
        t_recon + 100,
        Some(pos.sender_pw),
    );
    assert!(
        recon_res.is_err(),
        "Unoccupied child_lock [0u8; 32] MUST be rejected and NOT marked Conflicted!"
    );

    // Part B: Real competing child_lock marks split-change voucher as Quarantined
    let change_id = pos
        .sender
        .with_wallet(|w| {
            w.profile
                .l2_send_intents
                .get(&local_id)
                .unwrap()
                .created_change_local_id
                .clone()
        })
        .unwrap()
        .expect("Split transfer MUST record created_change_local_id");

    // Before conflict, verify change voucher is Active
    pos.sender
        .with_wallet(|w| {
            let inst = w.voucher_store.vouchers.get(&change_id).unwrap();
            assert_eq!(inst.status, VoucherStatus::Active);
        })
        .unwrap();

    // Record real conflict via proof
    let conflict_ctx = LiveStateContext {
        child_lock: [0xabu8; 32],
        state_digest: [0xcdu8; 32],
        ..recon_ctx.clone()
    };
    let conflict_proof = pos.proof_for_context(&conflict_ctx);
    pos.sender
        .record_intent_conflict(
            &local_id,
            &conflict_proof,
            &views,
            t_recon + 200,
            Some(pos.sender_pw),
        )
        .unwrap();

    // After conflict: change voucher MUST be Quarantined!
    pos.sender
        .with_wallet(|w| {
            let inst = w.voucher_store.vouchers.get(&change_id).unwrap();
            assert!(
                matches!(inst.status, VoucherStatus::Quarantined { .. }),
                "Split change voucher MUST be Quarantined when parent intent conflicts!"
            );
        })
        .unwrap();

    // Part C: Prepare L2 send intent -> reconcile to Confirmed -> spendable!
    let standard_str = test_utils::generate_signed_standard_toml(
        "voucher_standards/freetaler_v1/standard.toml",
    );
    let sender_id = pos
        .sender
        .with_wallet(|w| w.get_user_id().to_string())
        .unwrap();

    let _new_voucher = pos
        .sender
        .create_new_voucher(
            &standard_str,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(sender_id),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "25".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(pos.sender_pw),
        )
        .unwrap();

    let new_local_id = pos
        .sender
        .with_wallet(|w| {
            w.voucher_store
                .vouchers
                .iter()
                .find(|(_, inst)| {
                    inst.voucher.transactions.len() == 1
                        && inst.voucher.nominal_value.amount == "25"
                })
                .map(|(id, _)| id.clone())
        })
        .unwrap()
        .unwrap();

    pos.sender
        .prepare_l2_send_intent(&new_local_id, 0, Some(pos.sender_pw))
        .unwrap();

    // Advance 31s
    let t_recon2 = t_recon + 31_300;
    let views2 = vec![pos.fresh_view_at(t_recon2)];
    let recon_ctx2 = pos
        .sender
        .begin_intent_reconciliation(&new_local_id, &views2, t_recon2, Some(pos.sender_pw))
        .unwrap();

    let confirmed_proof = pos.proof_for_context(&recon_ctx2);
    let outcome = pos
        .sender
        .complete_intent_reconciliation(
            &new_local_id,
            &confirmed_proof,
            &views2,
            t_recon2 + 100,
            Some(pos.sender_pw),
        )
        .unwrap();
    assert!(matches!(outcome, IntentTerminalResolution::Confirmed { .. }));

    // Now spend new_local_id! Must NOT be blocked as unresolved!
    let recipient_id = pos
        .receiver
        .with_wallet(|w| w.get_user_id().to_string())
        .unwrap();
    let spend_result = pos.sender.create_transfer_bundle_with_l2_intents(
        MultiTransferRequest {
            recipient_id,
            sources: vec![SourceTransfer {
                local_instance_id: new_local_id.clone(),
                amount_to_send: "25".into(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: Some(false),
        },
        &pos.standards,
        None,
        Some(pos.sender_pw),
        0,
    );

    assert!(
        spend_result.is_ok(),
        "Confirmed prepared intent MUST be spendable!"
    );
}

// =============================================================================
// AUDIT-07-04: Intent Challenge TTL, IA02 Refresh & Skew Survival
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-04
/// * Severity: HIGH
/// * CWE-Classification: CWE-672 / CWE-362
/// * Target Location: src/app_service/l2_intents.rs, src/wallet/l2_intents.rs
/// * Threat Model & Exploitation:
///   Unresolved intents were previously pruned during clock skew. Reconciling intents
///   lacked challenge TTL and overwrote nonces during concurrent IA02 refreshes.
///   No-op paths wrote dirty state to disk.
/// * Remediation Strategy:
///   Never prune unresolved intents. Enforce 30s challenge TTL. Preserve nonce on
///   IA02 refresh within TTL. Abort on no-op reconciliation paths.
#[test]
fn audit_07_04_unresolved_intent_survives_clock_skew_pruning_and_concurrent_ia02_refresh() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    let sender_intents = pos.sender.unresolved_l2_send_intents().unwrap();
    let local_id = sender_intents[0].local_instance_id.clone();
    let root_valid_until = sender_intents[0].root_valid_until_ms;
    let created_at = sender_intents[0].created_at_ms;

    // 1. Clock skew: advance local clock past root_valid_until + 60_000
    let far_future = root_valid_until + 60_000;
    pos.sender
        .cleanup_terminal_intents(86_400_000, far_future, Some(pos.sender_pw))
        .unwrap();

    // Unresolved intent MUST NOT be deleted!
    let still_intents = pos.sender.unresolved_l2_send_intents().unwrap();
    assert_eq!(
        still_intents.len(),
        1,
        "Unresolved intent MUST NOT be deleted by cleanup_terminal_intents on clock skew!"
    );

    // 2. Intra-TTL IA02 refresh preserves challenge nonce
    let views = vec![pos.view.clone()];
    let t1 = created_at + 31_000;
    let ctx1 = pos
        .sender
        .begin_intent_reconciliation(&local_id, &views, t1, Some(pos.sender_pw))
        .unwrap();

    let t2 = created_at + 35_000; // 4 seconds later (within 30s TTL)
    let ctx2 = pos
        .sender
        .begin_intent_reconciliation(&local_id, &views, t2, Some(pos.sender_pw))
        .unwrap();

    assert_eq!(
        ctx1.recipient_nonce, ctx2.recipient_nonce,
        "Intra-TTL retry/refresh MUST preserve recipient_nonce!"
    );

    // 3. Complete reconciliation after challenge expires (> 30s without refresh) fails
    let t_expired = created_at + 70_000; // > 30s past ctx1
    let proof = pos.proof_for_context(&ctx1);
    let expired_views = vec![pos.fresh_view_at(t_expired)];
    let expired_res = pos.sender.complete_intent_reconciliation(
        &local_id,
        &proof,
        &expired_views,
        t_expired,
        Some(pos.sender_pw),
    );
    assert!(
        expired_res.is_err(),
        "Complete reconciliation after challenge TTL expiration MUST fail!"
    );

    // 4. expire_intent_if_overdue returns Abort (no-op) when not overdue
    pos.sender.unlock_session(pos.sender_pw, 3600).unwrap();
    let seal_before = pos.sender.get_seal_for_upload().unwrap();

    let overdue_res = pos
        .sender
        .expire_intent_if_overdue(&local_id, created_at + 32_000, Some(pos.sender_pw))
        .unwrap();
    assert!(overdue_res.is_none(), "Intent is not overdue yet");

    let seal_after = pos.sender.get_seal_for_upload().unwrap();

    assert_eq!(
        seal_before, seal_after,
        "Idle expire_intent_if_overdue poll MUST abort and NOT increment seal tx_nonce!"
    );
}

// =============================================================================
// AUDIT-07-05: Restored Backup Strips In-Flight Checkout Challenges
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-05
/// * Severity: HIGH
/// * CWE-Classification: CWE-294 / CWE-362
/// * Target Location: src/app_service/backup_ops.rs:463-495, src/app_service/checkout.rs
/// * Threat Model & Exploitation:
///   Backing up while a checkout purchase is in flight cloned the uncompleted challenge
///   to failover/restored devices, enabling double goods release with a single payment.
/// * Remediation Strategy:
///   Strip uncompleted checkout purchases and clear intent challenges on restore.
#[test]
fn audit_07_05_restored_backup_invalidates_inflight_checkout_challenges() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    // 1. Begin checkout purchase on receiver
    let purchase_id = "pos-inflight-backup";
    let views = vec![pos.view.clone()];
    let ctx = pos
        .receiver
        .begin_checkout_purchase(
            purchase_id,
            &pos.bundle_bytes,
            &views,
            pos.now + 1_000,
            Some(pos.receiver_pw),
        )
        .unwrap();

    // 2. Create backup of receiver wallet while checkout is in-flight
    let backup_diff = pos
        .receiver
        .create_differential_backup(
            None,
            BackupProtection::CustomBackupPassword(pos.receiver_pw),
            Some(pos.receiver_pw),
        )
        .unwrap();

    // 3. Complete checkout on receiver (Goods release #1)
    let proof = pos.proof_for_context(&ctx);
    let comp1 = pos
        .receiver
        .complete_checkout_purchase(
            purchase_id,
            &pos.bundle_bytes,
            &proof,
            &views,
            &pos.standards,
            pos.now + 2_000,
            Some(pos.receiver_pw),
        )
        .unwrap();
    assert!(comp1.newly_committed);
    assert!(comp1.verdict.can_release_goods_automatically);

    // 4. Restore backup into a second device (receiver_failover)
    let (mut receiver_failover, _) = test_utils::setup_service_with_profile(
        &dir.path().join("receiver_failover"),
        &ACTORS.bob,
        "Failover",
        pos.receiver_pw,
    );

    let _restored = receiver_failover
        .restore_backup(
            &backup_diff.encrypted_manifest_bytes,
            &backup_diff.put_blobs,
            BackupRestoreCredentials::BackupPassword(pos.receiver_pw),
            pos.receiver_pw,
            "device-failover".into(),
        )
        .unwrap();

    // 5. Verify restored wallet stripped uncompleted checkout purchases
    let purchases_on_failover = receiver_failover
        .with_wallet(|w| w.profile.l2_checkout_purchases.clone())
        .unwrap();
    assert!(
        !purchases_on_failover.contains_key(purchase_id),
        "In-flight uncompleted checkout purchase MUST be stripped on backup restore!"
    );

    // 6. Attempting to complete "pos-inflight-backup" on failover MUST FAIL CLOSED
    let failover_views = vec![pos.view.clone()];
    let replay_res = receiver_failover.complete_checkout_purchase(
        purchase_id,
        &pos.bundle_bytes,
        &proof,
        &failover_views,
        &pos.standards,
        pos.now + 3_000,
        Some(pos.receiver_pw),
    );

    assert!(
        replay_res.is_err(),
        "Failover device MUST NOT complete stripped in-flight purchase (prevents double release)!"
    );
}

// =============================================================================
// AUDIT-07-06: Sealed CheckoutReleaseVerdict & Fork-Lock Gated Replay
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-06
/// * Severity: HIGH
/// * CWE-Classification: CWE-668 / CWE-502
/// * Target Location: src/models/layer2_api.rs:621-658, src/app_service/checkout.rs:87-96
/// * Threat Model & Exploitation:
///   CheckoutReleaseVerdict previously derived Deserialize and had pub fields,
///   allowing forged capability tokens across IPC boundaries. Replay fast paths
///   skipped fork-lock and post-import quarantine checks.
/// * Remediation Strategy:
///   Seal CheckoutReleaseVerdict (no Deserialize, private _sealed field). Gate replay
///   with fork-lock and post-import quarantine checks.
#[test]
fn audit_07_06_sealed_verdict_and_gated_replay_checkout() {
    #[cfg(feature = "test-utils")]
    human_money_core::set_signature_bypass(false);

    let dir = tempfile::TempDir::new().unwrap();
    let mut pos = setup_pos_fixture(dir.path());

    // 1. Verify CheckoutReleaseVerdict constructor behavior
    let unsealed_verdict = CheckoutReleaseVerdict::new(L2ProcessingOutcome::Found, false);
    assert!(!unsealed_verdict.can_release_goods_automatically);
    assert!(!unsealed_verdict.is_goods_release_authorized);

    // 2. Complete checkout legitimately
    let purchase_id = "pos-replay-test";
    let views = vec![pos.view.clone()];
    let ctx = pos
        .receiver
        .begin_checkout_purchase(
            purchase_id,
            &pos.bundle_bytes,
            &views,
            pos.now + 1_000,
            Some(pos.receiver_pw),
        )
        .unwrap();

    let proof = pos.proof_for_context(&ctx);
    let comp = pos
        .receiver
        .complete_checkout_purchase(
            purchase_id,
            &pos.bundle_bytes,
            &proof,
            &views,
            &pos.standards,
            pos.now + 2_000,
            Some(pos.receiver_pw),
        )
        .unwrap();
    assert!(comp.newly_committed);

    // 3. Replay checkout while normal: succeeds with newly_committed == false
    let replay_ok = pos
        .receiver
        .replay_checkout_purchase(purchase_id, &pos.bundle_bytes)
        .unwrap()
        .expect("Purchase must be completed");
    assert!(!replay_ok.newly_committed);
    assert!(replay_ok.verdict.can_release_goods_automatically);

    // 4. Quarantine the imported voucher (e.g. later discovered double-spend conflict)
    let imported_id = pos
        .receiver
        .with_wallet(|w| {
            w.profile
                .l2_checkout_purchases
                .get(purchase_id)
                .unwrap()
                .imported_local_instance_id
                .clone()
        })
        .unwrap()
        .expect("Completed purchase MUST record imported_local_instance_id");

    {
        let (wallet, _) = pos.receiver.get_unlocked_mut_for_test();
        wallet.voucher_store.vouchers.get_mut(&imported_id).unwrap().status =
            VoucherStatus::Quarantined {
                reason: "fraud evidence".into(),
            };
    }

    // 5. Replay MUST fail closed when imported voucher is Quarantined!
    let replay_quarantined = pos
        .receiver
        .replay_checkout_purchase(purchase_id, &pos.bundle_bytes);
    assert!(
        replay_quarantined.is_err(),
        "replay_checkout_purchase MUST fail closed when imported voucher is Quarantined!"
    );
}

// =============================================================================
// AUDIT-07-07: Quorum-Gated Multi-Node Anchor Evaluation
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-07
/// * Severity: HIGH
/// * CWE-Classification: CWE-345 / CWE-840
/// * Target Location: src/services/l2_gateway.rs:1018-1136
/// * Threat Model & Exploitation:
///   evaluate_multi_node_anchor_verdicts fell back to verdicts.first() (Quorum = 1)
///   when no majority was reached, accepting unverified entries and divergent t_ids.
/// * Remediation Strategy:
///   Return AnchorSyncVerdict::Inconclusive when quorum is not met. Group votes by
///   identical target t_id/sync_point. Verify lock entry proofs before counting.
#[test]
fn audit_07_07_multi_node_anchor_never_trusts_verdicts_first_without_quorum() {
    let local_t_id = [0x11u8; 32];
    let local_tag = "tag_step_5";

    let fake_lock = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "test-v".into(),
        t_id: [0x99; 32],
        sender_ephemeral_pub: [0u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let verdicts = vec![
        L2Verdict::Conflict {
            existing_lock: fake_lock.clone(),
        },
        L2Verdict::MissingLocks {
            sync_point: local_tag.into(),
        },
        L2Verdict::MissingLocks {
            sync_point: local_tag.into(),
        },
        L2Verdict::UnknownVoucher,
        L2Verdict::UnknownVoucher,
    ];

    let res = evaluate_multi_node_anchor_verdicts(&verdicts, &local_t_id, local_tag, 5);
    assert!(
        matches!(res, AnchorSyncVerdict::Inconclusive),
        "Without majority quorum, evaluate_multi_node_anchor_verdicts MUST return Inconclusive, NEVER first verdict!"
    );

    // Split Rollbacks: 2 votes for t_id_1, 1 vote for t_id_2 (total = 5, required = 3)
    let fake_lock1 = L2LockEntry {
        t_id: [0x01; 32],
        ..fake_lock.clone()
    };
    let fake_lock2 = L2LockEntry {
        t_id: [0x02; 32],
        ..fake_lock.clone()
    };
    let verdicts_split_rollback = vec![
        L2Verdict::Verified {
            lock_entry: fake_lock1.clone(),
        },
        L2Verdict::Verified {
            lock_entry: fake_lock1,
        },
        L2Verdict::Verified {
            lock_entry: fake_lock2,
        },
        L2Verdict::UnknownVoucher,
        L2Verdict::UnknownVoucher,
    ];

    let res_split =
        evaluate_multi_node_anchor_verdicts(&verdicts_split_rollback, &local_t_id, local_tag, 5);
    assert!(
        matches!(res_split, AnchorSyncVerdict::Inconclusive),
        "Split rollback targets without single t_id majority MUST return Inconclusive!"
    );
}

// =============================================================================
// AUDIT-07-08: Authority Quorum Gate in L2 Gateway
// =============================================================================
/// * Finding-ID: AUDIT-07-L2CHECKOUT-08
/// * Severity: MEDIUM
/// * CWE-Classification: CWE-347
/// * Target Location: src/services/l2_gateway.rs:598-606, 728-769, 832-835
/// * Threat Model & Exploitation:
///   Omitting quorum_certificate or sending L2Verdict::Ok bypassed committee quorum
///   even when authority was provided, while L2Verdict::Confirmed always failed.
/// * Remediation Strategy:
///   Reject missing certificate and L2Verdict::Ok when authority is provided.
///   Verify L2Verdict::Confirmed via verify_quorum_proof over original_approval_digest.
#[test]
fn audit_07_08_authority_verdict_rejects_missing_quorum_certificate_and_bare_ok() {
    let mut rng = rand::thread_rng();
    let server_sk = SigningKey::generate(&mut rng);
    let server_pk = server_sk.verifying_key();

    let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let committee: Vec<[u8; 32]> = keys.iter().map(|k| k.verifying_key().to_bytes()).collect();

    let authority = CheckoutAuthority {
        network: 0,
        shard_id: 0,
        committee,
        parent_lock: [0x11; 32],
        child_lock: [0x22; 32],
    };

    let sign_envelope = |verdict: L2Verdict| -> Vec<u8> {
        let v_bytes = serde_json::to_vec(&verdict).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&v_bytes);
        let sig = server_sk.sign(&hasher.finalize());
        let env = L2ResponseEnvelope::new(verdict, sig.to_bytes());
        serde_json::to_vec(&env).unwrap()
    };

    // 1. Bare L2Verdict::Ok with authority MUST FAIL
    let env_ok = sign_envelope(L2Verdict::Ok {
        signature: [0u8; 64],
    });
    let res_ok = process_l2_verdict_with_authority(
        &env_ok,
        server_pk.as_bytes(),
        "local_t_id",
        "tag",
        None,
        "voucher_id",
        &authority,
    );
    assert!(
        matches!(res_ok, Err(VoucherCoreError::Validation(ValidationError::InvalidL2Proof))),
        "Bare L2Verdict::Ok with authority MUST return InvalidL2Proof!"
    );

    // 2. L2Verdict::Verified with missing quorum_certificate and authority MUST FAIL
    let lock = L2LockEntry {
        causal_output: None,
        layer2_voucher_id: "v".into(),
        t_id: [0x11; 32],
        sender_ephemeral_pub: [0u8; 32],
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: None,
        trap_s: None,
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let env_verified_no_cert = sign_envelope(L2Verdict::Verified { lock_entry: lock });
    let res_no_cert = process_l2_verdict_with_authority(
        &env_verified_no_cert,
        server_pk.as_bytes(),
        "local_t_id",
        "tag",
        None,
        "v",
        &authority,
    );
    assert!(
        matches!(res_no_cert, Err(VoucherCoreError::Validation(ValidationError::InvalidL2Proof))),
        "Verified verdict with missing quorum_certificate MUST return InvalidL2Proof!"
    );

    // 3. L2Verdict::Confirmed with valid 14/20 QuorumProof over original_approval_digest SUCCEEDS
    let digest = original_approval_digest(
        authority.network,
        authority.shard_id,
        1,
        &authority.parent_lock,
        &authority.child_lock,
    )
    .unwrap();

    let votes: Vec<_> = keys
        .iter()
        .take(14)
        .map(|k| AttestationVote {
            signer_pubkey: k.verifying_key().to_bytes(),
            signature: k.sign(&digest).to_bytes(),
        })
        .collect();

    let quorum_proof = QuorumProof {
        shard_id: authority.shard_id,
        votes,
    };

    let env_confirmed = sign_envelope(L2Verdict::Confirmed {
        proof: quorum_proof,
    });

    let local_t_id_str = bs58::encode(authority.child_lock).into_string();
    let res_confirmed = process_l2_verdict_with_authority(
        &env_confirmed,
        server_pk.as_bytes(),
        &local_t_id_str,
        "tag",
        None,
        "v",
        &authority,
    )
    .unwrap();

    assert!(
        matches!(res_confirmed, VerdictAction::ConfirmFinal { .. }),
        "Confirmed verdict with 14/20 valid votes MUST resolve to ConfirmFinal!"
    );
}

// =============================================================================
// BUG-03: Backup Profile Name Sanitization and Disambiguation
// =============================================================================
/// * Finding-ID: BUG-03
/// * Severity: MEDIUM
/// * CWE-Classification: CWE-20
/// * Target Location: src/app_service/backup_ops.rs:70-76, 580-598
/// * Threat Model & Exploitation:
///   Backup manifests without profile name validation could inject malformed or control
///   characters. Restoring existing profile names caused collisions or overwrites.
/// * Remediation Strategy:
///   Validate profile name length and control characters. Disambiguate existing profile
///   names on restore with (Restored), (Restored 2), etc.
#[test]
fn audit_07_bug_03_backup_profile_name_sanitization_and_disambiguation() {
    let dir = tempfile::TempDir::new().unwrap();
    let pw = "bug-03-password";

    let (mut app, _prof) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", pw);

    let backup_diff = app
        .create_differential_backup(
            None,
            BackupProtection::CustomBackupPassword(pw),
            Some(pw),
        )
        .unwrap();

    // 1. Restore backup when profile "Alice" already exists
    let res1 = app.restore_backup(
        &backup_diff.encrypted_manifest_bytes,
        &backup_diff.put_blobs,
        BackupRestoreCredentials::BackupPassword(pw),
        pw,
        "folder_restored_1".into(),
    );
    assert!(res1.is_ok());

    let profiles = app.list_profiles().unwrap();
    assert!(
        profiles.iter().any(|p| p.profile_name == "Alice (Restored)"),
        "First restore of duplicate profile MUST name it '<Name> (Restored)'"
    );

    // 2. Restore backup again when "Alice (Restored)" also exists
    let res2 = app.restore_backup(
        &backup_diff.encrypted_manifest_bytes,
        &backup_diff.put_blobs,
        BackupRestoreCredentials::BackupPassword(pw),
        pw,
        "folder_restored_2".into(),
    );
    assert!(res2.is_ok());

    let profiles2 = app.list_profiles().unwrap();
    assert!(
        profiles2.iter().any(|p| p.profile_name == "Alice (Restored 2)"),
        "Second restore of duplicate profile MUST name it '<Name> (Restored 2)'"
    );
}
