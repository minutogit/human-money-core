//! # Security Audit Regression Suite — v0.5.1 Conflicts, ProofStore, SAI & Fingerprints
//!
//! Fail-First regression suite covering confirmed vulnerabilities from
//! `docs/security/ai-audits/reports/01_02_sst_v4_and_sai_v051_report.md` (Group B).
//!
//! ## Standardized Finding Metadata
//!
//! ### AUDIT-01-V051-01 — SAI Prefix vs. Bare Root DID Desynchronization
//! * **Finding-ID:** AUDIT-01-V051-01
//! * **Severity:** High (Security Gate & Reputation Bypass)
//! * **CWE:** CWE-172 (Encoding / Canonicalization Error) / CWE-287 (Improper Authentication via Identifier Alias)
//! * **Target:** `src/wallet/queries.rs::check_reputation_with_provider`, `src/services/conflict_manager.rs::derive_proof_id`, `src/models/voucher.rs::spendable_balance_for_user`
//! * **Threat Model:** SST V4 unmasking records a bare root DID (`did:key:z6Mk...`). When an offender transacts using a prefixed SAI alias (`mallory:chk@did:key:z6Mk...`), raw string equality in `check_reputation` bypassed `KnownOffenderTransactionBlocked`. Similarly, `derive_proof_id` hashed multicodec bytes for prefixed SAIs but ASCII string for bare DIDs, permitting duplicate imports.
//! * **Impact:** Reputation evasion and proof deduplication bypass.
//! * **Root Cause:** Inconsistent identity canonicalization across DID formats.
//! * **Remediation:** Canonical Ed25519 public key resolution via `get_pubkey_from_user_id` across reputation, proof ID derivation, and balance calculation.
//! * **Test Semantics:** Fail-first. Asserts reputation blocking and proof ID equality across prefixed and root DID formats.
//!
//! ### AUDIT-01-V051-02 — Missing Victim Authorization in `add_resolution_endorsement`
//! * **Finding-ID:** AUDIT-01-V051-02
//! * **Severity:** High (Improper Authorization / Fraud State Laundering)
//! * **CWE:** CWE-285 (Improper Authorization) / CWE-345 (Insufficient Verification of Data Authenticity)
//! * **Target:** `src/wallet/conflicts/proofs.rs::add_resolution_endorsement`
//! * **Threat Model:** Any party, including the offender themselves or an unrelated Sybil, could sign an endorsement with their own key and flip an offender's status from `KnownOffender` to `Resolved`.
//! * **Impact:** Unilateral forgiveness of double-spending without victim consent.
//! * **Root Cause:** Missing check that `victim_id` is an actual victim in `conflicting_transactions` and not the offender.
//! * **Remediation:** Reject offender self-endorsement and require `victim_id` to match a recipient in `conflicting_transactions`.
//! * **Test Semantics:** Fail-first. Asserts rejection of offender and Sybil endorsements and acceptance of legitimate victim endorsements.
//!
//! ### AUDIT-01-V051-03 — `import_proof` Monotonic Status Violation & Predecessor Floor Bypass
//! * **Finding-ID:** AUDIT-01-V051-03
//! * **Severity:** High (State Resurrection & Historical Denial of Service)
//! * **CWE:** CWE-367 / CWE-754 (State-Transition & Timestamp Invariants)
//! * **Target:** `src/wallet/conflicts/ingress.rs::import_proof`
//! * **Threat Model:** `import_proof` resurrected non-Active vouchers (L2-quarantined, Archived, Endorsed) back to `Active` when winning the tie-breaker, and lacked a predecessor timestamp floor, allowing epoch-backdated (1970) sibling spends to quarantine genuine active vouchers.
//! * **Impact:** Overriding L2 adjudication and unauthenticated quarantine of historical vouchers.
//! * **Root Cause:** Missing monotonic status check and lack of predecessor timestamp floor in `import_proof`.
//! * **Remediation:** Only `Active` vouchers can transition to `Quarantined`; never resurrect non-Active vouchers. Disqualify transactions backdated before the predecessor timestamp floor.
//! * **Test Semantics:** Fail-first. Asserts non-Active vouchers are never resurrected and backdated transactions cannot quarantine active vouchers.
//!
//! ### AUDIT-01-V051-04 — `ProofStore` Eviction Poisoning via Unsigned `report_timestamp`
//! * **Finding-ID:** AUDIT-01-V051-04
//! * **Severity:** Medium (Resource Exhaustion / Reputation Laundering)
//! * **CWE:** CWE-345 / CWE-400 (Unauthenticated Data / Eviction Manipulation)
//! * **Target:** `src/wallet/conflicts/ingress.rs::import_proof`
//! * **Threat Model:** `report_timestamp` is unauthenticated and unbounded. Flooding proofs with `report_timestamp = 9999-...` evicted genuine `KnownOffender` and `Victim` proofs upon reaching `MAX_PROOFS`.
//! * **Impact:** Remote laundering of offender records via ephemeral soft proof flooding.
//! * **Root Cause:** Absence of timestamp clamping and untiered eviction in `ProofStore`.
//! * **Remediation:** Clamp `report_timestamp` to `<= now + 5 min` and implement tiered eviction favoring preservation of victim and permanent-DID offender proofs.
//! * **Test Semantics:** Fail-first. Asserts flood of ephemeral soft proofs does not evict permanent KnownOffender proofs.
//!
//! ### AUDIT-01-V051-05 & AUDIT-01-V051-06b — Fingerprint Dedup & Rebuild Guard Loss
//! * **Finding-ID:** AUDIT-01-V051-05 / AUDIT-01-V051-06b
//! * **Severity:** Medium / Low (Resource Exhaustion & Equivocation Evidence Loss)
//! * **CWE:** CWE-770 (Unbounded Allocation) / CWE-347 (Improper Verification)
//! * **Target:** `src/wallet/conflicts/ingress.rs::process_received_fingerprints`, `scan_and_rebuild_fingerprints`
//! * **Threat Model:** Microsecond `deletable_at` differences defeated `PartialEq` dedup in Phase 3 `quarantine_pairs`, growing buckets past `MAX_FOREIGN_BUCKET_CAP`. In `scan_and_rebuild_fingerprints`, deduplicating only by `t_id` dropped Same-ID Equivocation evidence.
//! * **Impact:** Unbounded memory growth in foreign fingerprints; loss of same-ID equivocation evidence.
//! * **Root Cause:** Inclusion of `deletable_at` in deduplication and omission of `privacy_guard_hash` in dedup predicates.
//! * **Remediation:** Deduplicate by `(t_id, privacy_guard_hash)` before assigning retention, enforce bucket caps, and preserve equivocation evidence across rebuilds.
//! * **Test Semantics:** Fail-first. Asserts repeated delivery of identical quarantine pairs deduplicates across time and respects caps.

use chrono::{Duration, Utc};
use human_money_core::error::{ValidationError, VoucherCoreError};
use human_money_core::models::conflict::{
    ConflictRole, ProofOfDoubleSpend, ProofStoreEntry, TransactionFingerprint, TrustStatus,
};
use human_money_core::models::profile::TransactionBundleHeader;
use human_money_core::models::voucher::{Transaction, ValueDefinition, Voucher};
use human_money_core::models::voucher_standard_definition::{PrivacyMode, VoucherStandardDefinition};
use human_money_core::services::conflict_manager::{
    self, create_and_sign_resolution_endorsement, derive_proof_id,
};
use human_money_core::services::crypto::{
    self, create_user_id, get_hash, sign_ed25519,
};
use human_money_core::services::trap_manager::generate_sst_trap;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{
    self, setup_in_memory_wallet, sign_proof_fingerprints, ACTORS, FREETALER_STANDARD,
};
use human_money_core::wallet::types::{CreateBundleResult, MultiTransferRequest, SourceTransfer};
use human_money_core::{NewVoucherData, UserIdentity, VoucherStatus};
use rust_decimal::Decimal;
use std::collections::HashMap;

// =============================================================================
// Helper: create a deterministic mock ProofOfDoubleSpend
// =============================================================================
fn build_test_proof(
    offender_id: &str,
    fork_point_prev_hash: &str,
    txs: Vec<Transaction>,
) -> ProofOfDoubleSpend {
    let reporter = &ACTORS.charlie;
    let proof_id = derive_proof_id(offender_id, fork_point_prev_hash).unwrap();
    let signature = sign_ed25519(&reporter.signing_key, proof_id.as_bytes());

    ProofOfDoubleSpend {
        fingerprints: Vec::new(),
        victim_witnesses: Vec::new(),
        proof_id,
        offender_id: offender_id.to_string(),
        suspected_identity: None,
        fork_point_prev_hash: fork_point_prev_hash.to_string(),
        conflicting_transactions: txs,
        deletable_at: (Utc::now() + Duration::days(90)).to_rfc3339(),
        reporter_id: reporter.user_id.clone(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
    }
}

fn create_test_voucher(identity: &UserIdentity) -> Voucher {
    let new_voucher_data = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    Voucher::create_with_key(
        new_voucher_data,
        standard,
        standard_hash,
        &identity.signing_key,
    )
    .expect("Voucher creation failed")
}

fn setup_public_standard() -> (
    VoucherStandardDefinition,
    String,
    HashMap<String, VoucherStandardDefinition>,
) {
    let mut standard_def = FREETALER_STANDARD.0.clone();
    standard_def.immutable.features.privacy_mode = PrivacyMode::Public;
    let standard_hash = get_hash(to_canonical_json(&standard_def.immutable).unwrap());

    let mut standards_map = HashMap::new();
    standards_map.insert(
        standard_def.immutable.identity.uuid.clone(),
        standard_def.clone(),
    );

    (standard_def, standard_hash, standards_map)
}

// =============================================================================
// [VULNERABILITY 1] AUDIT-01-V051-01: SAI Prefix vs. Bare Root DID Desynchronization
// =============================================================================

#[test]
fn test_v051_01_derive_proof_id_matches_bare_root_did_and_prefixed_sai() {
    let mallory = &ACTORS.hacker;
    let bare_did = create_user_id(&mallory.public_key, None).unwrap();
    let prefixed_sai_1 = create_user_id(&mallory.public_key, Some("mallory")).unwrap();
    let prefixed_sai_2 = create_user_id(&mallory.public_key, Some("mallory-shop")).unwrap();

    let fork_prev = bs58::encode([42u8; 32]).into_string();

    let id_bare = derive_proof_id(&bare_did, &fork_prev).unwrap();
    let id_prefix_1 = derive_proof_id(&prefixed_sai_1, &fork_prev).unwrap();
    let id_prefix_2 = derive_proof_id(&prefixed_sai_2, &fork_prev).unwrap();

    assert_eq!(
        id_bare, id_prefix_1,
        "derive_proof_id for bare DID and prefixed SAI must produce identical 34-byte multicodec hash"
    );
    assert_eq!(
        id_prefix_1, id_prefix_2,
        "derive_proof_id across different SAI aliases of the same key must produce identical hash"
    );
}

#[test]
fn test_v051_01_check_reputation_detects_offender_via_prefixed_sai_alias() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mallory = &ACTORS.hacker;
    let bare_mallory_did = create_user_id(&mallory.public_key, None).unwrap();
    let prefixed_mallory_sai = create_user_id(&mallory.public_key, Some("mallory")).unwrap();

    let fork = bs58::encode([99u8; 32]).into_string();
    let proof = build_test_proof(&bare_mallory_did, &fork, Vec::new());
    let proof_id = proof.proof_id.clone();

    wallet.proof_store.proofs.insert(
        proof_id.clone(),
        ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // Querying with bare DID must identify KnownOffender
    let status_bare = wallet.check_reputation(&bare_mallory_did);
    assert_eq!(
        status_bare,
        TrustStatus::KnownOffender(proof_id.clone()),
        "Bare DID must match stored proof"
    );

    // Querying with prefixed SAI MUST also identify KnownOffender!
    let status_prefixed = wallet.check_reputation(&prefixed_mallory_sai);
    assert_eq!(
        status_prefixed,
        TrustStatus::KnownOffender(proof_id),
        "Prefixed SAI alias must resolve to the same underlying public key and block offender"
    );
}

#[test]
fn test_v051_01_spendable_balance_matches_prefixed_sai_and_bare_did() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, _standard_hash, standards_map) = setup_public_standard();

    let mut alice_wallet = test_utils::setup_in_memory_wallet(&ACTORS.alice.identity);

    // Alice creates voucher of 100 in public mode
    let local_id = test_utils::add_voucher_to_wallet(
        &mut alice_wallet,
        &ACTORS.alice.identity,
        "100",
        &standard_def,
        true,
    )
    .expect("Voucher creation failed");

    let pub_init_voucher = alice_wallet
        .voucher_store
        .vouchers
        .get(&local_id)
        .unwrap()
        .voucher
        .clone();

    // Alice transfers 40 to Bob's prefixed SAI (bo:xxx@did:key:z6MkBob...)
    let mut bob_wallet = test_utils::setup_in_memory_wallet(&ACTORS.bob.identity);

    let CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(
            &ACTORS.alice.identity,
            &standards_map,
            MultiTransferRequest {
                recipient_id: ACTORS.bob.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: local_id,
                    amount_to_send: "40".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: Some(false),
                wot_sync_json: None,
            },
            None,
        )
        .expect("Alice transfer to Bob failed");

    bob_wallet
        .process_encrypted_transaction_bundle(
            &ACTORS.bob.identity,
            &bundle_bytes,
            None,
            &standards_map,
        )
        .unwrap();

    let bare_alice_did = create_user_id(&ACTORS.alice.public_key, None).unwrap();
    assert_eq!(
        pub_init_voucher
            .spendable_balance_for_user(&bare_alice_did, &standard_def, None)
            .unwrap(),
        Decimal::new(10000, 2),
        "Init creator balance must resolve across prefixed SAI and bare root DID"
    );
    assert_eq!(
        pub_init_voucher
            .spendable_balance_for_user("ephemeral:attacker", &standard_def, None)
            .unwrap(),
        Decimal::ZERO,
        "Non-DID colon strings must never collide via Option::None == Option::None"
    );

    let bob_voucher = &bob_wallet.voucher_store.vouchers.values().next().unwrap().voucher;
    let bare_bob_did = create_user_id(&ACTORS.bob.public_key, None).unwrap();

    // Querying Bob's spendable balance using his prefixed SAI succeeds, while Root sub-account stays isolated (SAI design invariant)
    let bal_with_prefixed_sai = bob_voucher
        .spendable_balance_for_user(&ACTORS.bob.user_id, &standard_def, None)
        .expect("balance query should succeed");
    assert_eq!(bal_with_prefixed_sai, Decimal::new(4000, 2));

    let bal_with_bare_did = bob_voucher
        .spendable_balance_for_user(&bare_bob_did, &standard_def, None)
        .expect("balance query should succeed");
    assert_eq!(
        bal_with_bare_did,
        Decimal::ZERO,
        "SAI sub-accounts remain isolated for spendable balances while sharing person-level reputation"
    );

    human_money_core::set_signature_bypass(false);
}

// =============================================================================
// [VULNERABILITY 2] AUDIT-01-V051-02: Missing Victim Authorization in add_resolution_endorsement
// =============================================================================

#[test]
fn test_v051_02_offender_cannot_self_forgive_via_resolution_endorsement() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mallory = &ACTORS.hacker;
    let victim = &ACTORS.victim;

    let mut tx1 = Transaction::default();
    tx1.t_id = "tx_branch_1".to_string();
    tx1.recipient_id = victim.user_id.clone();

    let mut tx2 = Transaction::default();
    tx2.t_id = "tx_branch_2".to_string();
    tx2.recipient_id = "did:key:z6MkOtherVictim...".to_string();

    let fork = bs58::encode([55u8; 32]).into_string();
    let proof = build_test_proof(&mallory.user_id, &fork, vec![tx1, tx2]);
    let proof_id = proof.proof_id.clone();

    wallet.proof_store.proofs.insert(
        proof_id.clone(),
        ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // Offender Mallory signs an endorsement forgiving herself!
    let self_endorsement = create_and_sign_resolution_endorsement(
        &proof_id,
        mallory,
        Some("I forgive myself".to_string()),
    )
    .unwrap();

    let err = wallet
        .add_resolution_endorsement(self_endorsement)
        .unwrap_err();

    match err {
        VoucherCoreError::Validation(ValidationError::SecurityViolation(msg)) => {
            assert!(
                msg.contains("offender cannot endorse"),
                "Expected offender self-forgiveness rejection, got: {}",
                msg
            );
        }
        other => panic!("Expected SecurityViolation error, got {:?}", other),
    }

    // Reputation MUST still be KnownOffender!
    assert_eq!(
        wallet.check_reputation(&mallory.user_id),
        TrustStatus::KnownOffender(proof_id)
    );
}

#[test]
fn test_v051_02_unrelated_sybil_cannot_resolve_conflict_proof() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mallory = &ACTORS.hacker;
    let victim = &ACTORS.victim;
    let sybil = &ACTORS.charlie;

    let mut tx1 = Transaction::default();
    tx1.t_id = "tx_branch_1".to_string();
    tx1.recipient_id = victim.user_id.clone();

    let mut tx2 = Transaction::default();
    tx2.t_id = "tx_branch_2".to_string();
    tx2.recipient_id = "did:key:z6MkDave...".to_string();

    let fork = bs58::encode([66u8; 32]).into_string();
    let proof = build_test_proof(&mallory.user_id, &fork, vec![tx1, tx2]);
    let proof_id = proof.proof_id.clone();

    wallet.proof_store.proofs.insert(
        proof_id.clone(),
        ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // Unrelated third-party Sybil Charlie signs an endorsement
    let sybil_endorsement = create_and_sign_resolution_endorsement(
        &proof_id,
        sybil,
        Some("Sybil says it is settled".to_string()),
    )
    .unwrap();

    let err = wallet
        .add_resolution_endorsement(sybil_endorsement)
        .unwrap_err();

    match err {
        VoucherCoreError::Validation(ValidationError::SecurityViolation(msg)) => {
            assert!(
                msg.contains("does not match any recipient"),
                "Expected unrelated Sybil rejection, got: {}",
                msg
            );
        }
        other => panic!("Expected SecurityViolation error, got {:?}", other),
    }
}

#[test]
fn test_v051_02_legitimate_victim_can_resolve_conflict_proof() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mallory = &ACTORS.hacker;
    let victim = &ACTORS.victim;

    let mut tx1 = Transaction::default();
    tx1.t_id = "tx_branch_1".to_string();
    tx1.recipient_id = victim.user_id.clone();

    let mut tx2 = Transaction::default();
    tx2.t_id = "tx_branch_2".to_string();
    tx2.recipient_id = "did:key:z6MkBob...".to_string();

    let fork = bs58::encode([77u8; 32]).into_string();
    let proof = build_test_proof(&mallory.user_id, &fork, vec![tx1, tx2]);
    let proof_id = proof.proof_id.clone();

    wallet.proof_store.proofs.insert(
        proof_id.clone(),
        ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // Legitimate victim signs endorsement
    let victim_endorsement = create_and_sign_resolution_endorsement(
        &proof_id,
        victim,
        Some("Fully reimbursed".to_string()),
    )
    .unwrap();

    wallet
        .add_resolution_endorsement(victim_endorsement)
        .expect("Legitimate victim endorsement must be accepted");

    // Reputation is now Resolved!
    match wallet.check_reputation(&mallory.user_id) {
        TrustStatus::Resolved {
            proof_id: resolved_id,
            ..
        } => {
            assert_eq!(resolved_id, proof_id);
        }
        other => panic!("Expected TrustStatus::Resolved, got {:?}", other),
    }
}

// =============================================================================
// [VULNERABILITY 3] AUDIT-01-V051-03: import_proof Monotonic Status & Predecessor Floor
// =============================================================================

#[test]
fn test_v051_03_import_proof_never_resurrects_quarantined_or_archived_voucher() {
    human_money_core::set_signature_bypass(true);

    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mut voucher = create_test_voucher(&alice.identity);

    let fork_prev = bs58::encode([88u8; 32]).into_string();
    let eph_pub = bs58::encode([77u8; 32]).into_string();

    let mut tx_early = Transaction::default();
    tx_early.t_id = bs58::encode([1u8; 32]).into_string();
    tx_early.t_time = "2026-06-01T10:00:00Z".to_string();
    tx_early.prev_hash = fork_prev.clone();
    tx_early.sender_ephemeral_pub = Some(eph_pub.clone());

    let mut tx_late = Transaction::default();
    tx_late.t_id = bs58::encode([2u8; 32]).into_string();
    tx_late.t_time = "2026-06-01T11:00:00Z".to_string();
    tx_late.prev_hash = fork_prev.clone();
    tx_late.sender_ephemeral_pub = Some(eph_pub);

    voucher.transactions.push(tx_early.clone());

    // Voucher was already quarantined (e.g. by an L2 verdict)
    let instance_id = "inst_quarantined_1".to_string();
    wallet.add_voucher_instance(
        instance_id.clone(),
        voucher.clone(),
        VoucherStatus::Quarantined {
            reason: "Prior Layer 2 Conflict Verdict".to_string(),
        },
    );

    // Import proof containing [tx_early, tx_late] where tx_early is the winner (earlier time)
    let proof = build_test_proof(
        &ACTORS.hacker.user_id,
        &fork_prev,
        vec![tx_early.clone(), tx_late.clone()],
    );

    wallet.import_proof(proof).expect("import_proof should succeed");

    let instance = wallet.voucher_store.vouchers.get(&instance_id).unwrap();
    assert!(
        matches!(instance.status, VoucherStatus::Quarantined { .. }),
        "Importing proof MUST NEVER resurrect a Quarantined voucher back to Active! Status was: {:?}",
        instance.status
    );

    // Test with Archived status as well
    let archived_id = "inst_archived_1".to_string();
    wallet.add_voucher_instance(
        archived_id.clone(),
        voucher,
        VoucherStatus::Archived,
    );

    let proof2 = build_test_proof(
        &ACTORS.hacker.user_id,
        &fork_prev,
        vec![tx_early, tx_late],
    );
    let _ = wallet.import_proof(proof2);

    let archived_inst = wallet.voucher_store.vouchers.get(&archived_id).unwrap();
    assert_eq!(
        archived_inst.status,
        VoucherStatus::Archived,
        "Importing proof MUST NOT mutate Archived voucher status"
    );

    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_v051_03_import_proof_disqualifies_epoch_backdated_transaction() {
    human_money_core::set_signature_bypass(true);

    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mut voucher = create_test_voucher(&alice.identity);
    voucher.creation_date = "2026-01-01T00:00:00Z".to_string();
    if !voucher.transactions.is_empty() {
        voucher.transactions[0].t_time = "2026-01-01T00:00:00Z".to_string();
    }

    let fork_prev = bs58::encode([89u8; 32]).into_string();
    let eph_pub = bs58::encode([78u8; 32]).into_string();

    let mut tx_honest = Transaction::default();
    tx_honest.t_id = bs58::encode([3u8; 32]).into_string();
    tx_honest.t_time = "2026-06-01T12:00:00Z".to_string();
    tx_honest.prev_hash = fork_prev.clone();
    tx_honest.sender_ephemeral_pub = Some(eph_pub.clone());

    voucher.transactions.push(tx_honest.clone());

    let instance_id = "inst_active_honest".to_string();
    wallet.add_voucher_instance(
        instance_id.clone(),
        voucher,
        VoucherStatus::Active,
    );

    // Attacker crafts an epoch-backdated sibling transaction ("1970-01-01")
    let mut tx_backdated = Transaction::default();
    tx_backdated.t_id = bs58::encode([4u8; 32]).into_string();
    tx_backdated.t_time = "1970-01-01T00:00:01Z".to_string();
    tx_backdated.prev_hash = fork_prev.clone();
    tx_backdated.sender_ephemeral_pub = Some(eph_pub);

    let proof = build_test_proof(
        &ACTORS.hacker.user_id,
        &fork_prev,
        vec![tx_honest, tx_backdated],
    );

    wallet.import_proof(proof).expect("import_proof should succeed");

    let instance = wallet.voucher_store.vouchers.get(&instance_id).unwrap();
    assert_eq!(
        instance.status,
        VoucherStatus::Active,
        "Active voucher must NOT be quarantined by an epoch-backdated sibling earlier than the predecessor floor!"
    );

    human_money_core::set_signature_bypass(false);
}

// =============================================================================
// [VULNERABILITY 4] AUDIT-01-V051-04: ProofStore Eviction Poisoning via Unsigned report_timestamp
// =============================================================================

#[test]
fn test_v051_04_proof_store_eviction_protects_known_offender_against_ephemeral_soft_proof_flood() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mallory_did = ACTORS.hacker.user_id.clone();
    let fork_legit = bs58::encode([90u8; 32]).into_string();
    let mut tx_a = Transaction::default();
    tx_a.t_id = bs58::encode([101u8; 32]).into_string();
    tx_a.prev_hash = fork_legit.clone();
    tx_a.sender_ephemeral_pub = Some(bs58::encode([102u8; 32]).into_string());

    let mut tx_b = Transaction::default();
    tx_b.t_id = bs58::encode([103u8; 32]).into_string();
    tx_b.prev_hash = fork_legit.clone();
    tx_b.sender_ephemeral_pub = Some(bs58::encode([102u8; 32]).into_string());

    let legit_proof = build_test_proof(&mallory_did, &fork_legit, vec![tx_a, tx_b]);
    let legit_id = legit_proof.proof_id.clone();

    wallet.proof_store.proofs.insert(
        legit_id.clone(),
        ProofStoreEntry {
            proof: legit_proof,
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // Pre-fill the proof store up to MAX_PROOFS (1000) using ephemeral soft proofs
    // with future timestamps ("9999-12-31T23:59:59Z")
    for i in 0..1005 {
        let mut eph_bytes = [0u8; 32];
        eph_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        let eph_str = bs58::encode(eph_bytes).into_string();
        let fake_eph_offender = format!("ephemeral:{}", eph_str);

        let mut fork_bytes = [0u8; 32];
        fork_bytes[0..4].copy_from_slice(&(i as u32).to_le_bytes());
        let fork_i = bs58::encode(fork_bytes).into_string();

        let mut tx1 = Transaction::default();
        tx1.t_id = bs58::encode([104u8; 32]).into_string();
        tx1.prev_hash = fork_i.clone();
        tx1.sender_ephemeral_pub = Some(eph_str.clone());

        let mut tx2 = Transaction::default();
        tx2.t_id = bs58::encode([106u8; 32]).into_string();
        tx2.prev_hash = fork_i.clone();
        tx2.sender_ephemeral_pub = Some(eph_str);

        let mut soft_proof = build_test_proof(&fake_eph_offender, &fork_i, vec![tx1, tx2]);
        soft_proof.report_timestamp = "9999-12-31T23:59:59Z".to_string();

        let _ = wallet.import_proof(soft_proof);
    }

    // Assert the legitimate permanent-DID KnownOffender proof was NOT evicted!
    assert!(
        wallet.proof_store.proofs.contains_key(&legit_id),
        "Legitimate KnownOffender proof must be protected by tiered eviction from ephemeral flood!"
    );
    assert_eq!(
        wallet.check_reputation(&mallory_did),
        TrustStatus::KnownOffender(legit_id)
    );
}

#[test]
fn test_v051_04_import_proof_clamps_future_report_timestamp() {
    human_money_core::set_signature_bypass(true);

    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let fork = bs58::encode([91u8; 32]).into_string();
    let eph_str = bs58::encode(ACTORS.bob.public_key.to_bytes()).into_string();

    let mut tx1 = Transaction::default();
    tx1.t_id = bs58::encode([107u8; 32]).into_string();
    tx1.prev_hash = fork.clone();
    tx1.sender_ephemeral_pub = Some(eph_str.clone());

    let mut tx2 = Transaction::default();
    tx2.t_id = bs58::encode([108u8; 32]).into_string();
    tx2.prev_hash = fork.clone();
    tx2.sender_ephemeral_pub = Some(eph_str.clone());

    let mut proof = build_test_proof(
        &format!("ephemeral:{}", eph_str),
        &fork,
        vec![tx1, tx2],
    );
    proof.report_timestamp = "9999-12-31T23:59:59Z".to_string();
    let proof_id = proof.proof_id.clone();

    wallet.import_proof(proof).unwrap();

    let stored = wallet.get_proof_of_double_spend(&proof_id).unwrap();
    assert_ne!(
        stored.report_timestamp, "9999-12-31T23:59:59Z",
        "Future report_timestamp must be clamped on import"
    );

    let parsed = chrono::DateTime::parse_from_rfc3339(&stored.report_timestamp)
        .expect("Clamped timestamp must be valid RFC3339");
    let now = Utc::now();
    assert!(
        parsed <= now + Duration::minutes(5),
        "Clamped timestamp must not exceed current wall clock"
    );

    human_money_core::set_signature_bypass(false);
}

// =============================================================================
// [VULNERABILITY 5 & 06b] AUDIT-01-V051-05 & 06b: Fingerprint Dedup & Rebuild Guard
// =============================================================================

#[test]
fn test_v051_05_quarantine_pairs_ingress_deduplicates_across_time_and_respects_bucket_cap() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let sender = &ACTORS.hacker.identity;
    let seed = [47u8; 32];
    let input = crypto::derive_owned_ephemeral_key(&sender.signing_key, &seed).unwrap();
    let eph = input.verifying_key().to_bytes();
    let tag = crypto::get_hash(b"test_quarantine_dedup_tag");

    let id1 = crypto::get_hash(b"test_spend_1");
    let id2 = crypto::get_hash(b"test_spend_2");

    let (trap1, _) = generate_sst_trap(&sender.signing_key, &tag, &eph, &id1, "", &seed).unwrap();
    let (trap2, _) = generate_sst_trap(&sender.signing_key, &tag, &eph, &id2, "", &seed).unwrap();

    let mut txs = vec![
        Transaction {
            t_id: id1.clone(),
            prev_hash: tag.clone(),
            t_type: "gossip_soft_placeholder".into(),
            t_time: "2026-01-01T00:00:00Z".into(),
            sender_ephemeral_pub: Some(bs58::encode(eph).into_string()),
            trap_data: Some(trap1),
            ..Default::default()
        },
        Transaction {
            t_id: id2.clone(),
            prev_hash: tag.clone(),
            t_type: "gossip_soft_placeholder".into(),
            t_time: "2026-01-02T00:00:00Z".into(),
            sender_ephemeral_pub: Some(bs58::encode(eph).into_string()),
            trap_data: Some(trap2),
            ..Default::default()
        },
    ];

    let signed_fps = sign_proof_fingerprints(&mut txs, &input);
    let fp1 = signed_fps[0].clone();
    let fp2 = signed_fps[1].clone();

    let header = TransactionBundleHeader::default();
    let test_voucher = create_test_voucher(&alice.identity);
    let vouchers = vec![test_voucher];

    // Deliver the exact same pair in 3 consecutive calls separated by 1ms
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(1));
        wallet
            .process_received_fingerprints(
                &header,
                &vouchers,
                &[],
                &[[fp1.clone(), fp2.clone()]],
            )
            .expect("processing should succeed");
    }

    let bucket = wallet
        .known_fingerprints
        .foreign_fingerprints
        .get(&tag)
        .expect("bucket should exist");

    assert_eq!(
        bucket.len(),
        2,
        "Exact duplicate quarantine pair must be deduplicated by (t_id, privacy_guard_hash) across time!"
    );

    // Deliver 200 distinct pairs to test MAX_FOREIGN_BUCKET_CAP (150)
    let dummy_vouchers: Vec<_> = (0..100)
        .map(|_| create_test_voucher(&alice.identity))
        .collect();

    for i in 0..200 {
        let mut f_a = fp1.clone();
        f_a.t_id = format!("tx_bulk_{}_a", i);
        let mut f_b = fp2.clone();
        f_b.t_id = format!("tx_bulk_{}_b", i);

        wallet
            .process_received_fingerprints(
                &header,
                &dummy_vouchers,
                &[],
                &[[f_a, f_b]],
            )
            .expect("bulk processing should succeed");
    }

    let bucket_after = wallet
        .known_fingerprints
        .foreign_fingerprints
        .get(&tag)
        .unwrap();

    assert!(
        bucket_after.len() <= conflict_manager::MAX_FOREIGN_BUCKET_CAP,
        "Bucket length ({}) must not exceed MAX_FOREIGN_BUCKET_CAP ({})",
        bucket_after.len(),
        conflict_manager::MAX_FOREIGN_BUCKET_CAP
    );
}

#[test]
fn test_v051_06b_scan_and_rebuild_fingerprints_preserves_same_id_equivocation() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let hash_key = "hash_key_equivocation".to_string();
    let mut fp1 = TransactionFingerprint::default();
    fp1.t_id = "same_tx_id".to_string();
    fp1.privacy_guard_hash = "guard_A".to_string();

    let mut fp2 = TransactionFingerprint::default();
    fp2.t_id = "same_tx_id".to_string();
    fp2.privacy_guard_hash = "guard_B".to_string();

    wallet
        .known_fingerprints
        .local_history
        .insert(hash_key.clone(), vec![fp1.clone(), fp2.clone()]);

    wallet
        .scan_and_rebuild_fingerprints()
        .expect("rebuild must succeed");

    let preserved = wallet
        .known_fingerprints
        .local_history
        .get(&hash_key)
        .expect("local_history entry must be preserved");

    assert_eq!(
        preserved.len(),
        2,
        "scan_and_rebuild_fingerprints must preserve both Same-ID Equivocation fingerprints!"
    );
}
