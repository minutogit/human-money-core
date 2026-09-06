//! # Security Audit Regression Suite: Double-Spend Trap, DS-Tags & Conflict Detection
//!
//! These tests document the vulnerabilities found during the security audit of:
//! - src/services/trap_manager.rs
//! - src/services/conflict_manager.rs
//! - src/services/voucher_validation/chain.rs (trap enforcement)
//! - src/wallet/conflict_handler.rs (import_proof)
//!
//! Each test proves that the corresponding finding is FIXED:
//! - VULN 1 (CRITICAL): Stealth trap evasion / third-party framing
//!   -> V3 SST attribution is EUF-CMA bound: two colliding shards reconstruct
//!      the underlying Schnorr signature, whose challenge binds it to exactly
//!      one `did:key`. Fabricated shards reconstruct to a point chosen by NO
//!      ONE (least of all a framed victim), and attribution claims require
//!      `verify_stored_trap_shards_against_identity` to pass. The canonical
//!      offender identifier remains the ephemeral-key linkage (unforgeable L2
//!      signatures).
//! - VULN 2 (HIGH): Identical-U double spend defeated extraction
//!   -> V3 shards are evaluated at tau = H(ds_tag || t_id); distinct forks
//!      have distinct t_ids, hence distinct evaluation points. The replay
//!      case (identical shard values) is rejected by an explicit guard.
//! - VULN 3 (MEDIUM): Non-canonical scalar encodings bypassed guards
//!   -> strict canonical scalar parsing in witness/shard handling.
//! - VULN 4 (HIGH): Unauthenticated proof import quarantined victims
//!   -> multi-gate verification before any state mutation.

use curve25519_dalek::scalar::Scalar;

use human_money_core::models::conflict::{ProofOfDoubleSpend, TransactionFingerprint};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::models::voucher_standard_definition::{PrivacyMode, VoucherStandardDefinition};
use human_money_core::services::crypto_utils::ed25519_pk_to_curve_point;
use human_money_core::services::trap_manager::{
    extract_sst_identity, generate_sst_trap, verify_stored_trap_shards_against_identity,
};
use human_money_core::services::voucher_manager::{create_transaction, create_voucher, NewVoucherData};
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::services::conflict_manager::{
    check_for_double_spend, create_fingerprint_for_transaction,
};
use human_money_core::test_utils::{
    add_voucher_to_wallet, create_custom_standard, derive_holder_key, ACTORS, FREETALER_STANDARD,
};
use human_money_core::{Transaction, UserIdentity, Voucher, VoucherStatus};

const AMOUNT_FULL: &str = "100.00";

/// Builds a fresh voucher (init only) whose creator holds 100.00 units.
fn fresh_voucher(standard: &VoucherStandardDefinition, standard_hash: &str) -> Voucher {
    let data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(ACTORS.alice.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: AMOUNT_FULL.to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };
    create_voucher(data, standard, standard_hash, &ACTORS.alice.identity.signing_key).unwrap()
}

/// Spends the FULL remaining balance from the genesis holder key to `recipient`.
/// Both branches are created from the same base state with the SAME ephemeral
/// key, so they collide on the same ds_tag (this is the double spend).
fn spend_full(
    base: &Voucher,
    standard: &VoucherStandardDefinition,
    holder_key: &ed25519_dalek::SigningKey,
    recipient: &UserIdentity,
    privacy: Option<bool>,
) -> Voucher {
    create_transaction(
        base,
        standard,
        &ACTORS.alice.user_id,
        &ACTORS.alice.identity.signing_key,
        holder_key,
        &recipient.user_id,
        AMOUNT_FULL,
        privacy,
    )
    .unwrap()
    .0
}

fn last_tx(v: &Voucher) -> &Transaction {
    v.transactions.last().unwrap()
}

// =============================================================================
// FIX 1 (was CRITICAL): Trap evasion + frame attack in stealth mode
// =============================================================================
// A stealth double-spender rewrote the published trap material in both forks
// to frame an innocent did:key identity (david). Under V3/SST she cannot
// anchor shards to a chosen victim anymore (that would be an EUF-CMA forgery
// against Schnorr/Ed25519). The best she can do is publish self-consistent
// garbage signed under her own key — which still passes stealth chain
// validation (no sender_id -> no verification anchor), but the reconstruction
// lands on HER key, never on david's. The defense lives at ATTRIBUTION time:
// `verify_stored_trap_shards_against_identity` only accepts claims matching
// the extracted identity point.
#[test]
fn audit_1_stealth_framing_is_rejected_by_proof_verification_gate() {
    // Stealth variant of the FreeTaler standard.
    let (standard, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = PrivacyMode::Stealth;
    });

    let base = fresh_voucher(&standard, &standard_hash);
    let holder_key = derive_holder_key(&base, &ACTORS.alice.identity.signing_key);

    // Two branches spending the SAME input state (same prev_hash + same
    // revealed ephemeral pubkey => same ds_tag).
    let mut branch_a = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, None);
    let mut branch_b = spend_full(&base, &standard, &holder_key, &ACTORS.charlie.identity, None);

    // --- Attack: replace the trap shards in BOTH branches ------------------
    // The attacker (holder of the voucher, NOT david) fabricates replacement
    // shards under her own key for both forks and re-derives t_id +
    // layer2_signature so chain validation stays green.
    let framed_point =
        ed25519_pk_to_curve_point(&ACTORS.david.identity.public_key).unwrap();
    let fabricator_point =
        ed25519_pk_to_curve_point(&ACTORS.hacker.identity.public_key).unwrap();

    // V3 Protocol (audit_02_11): the re-signed spend must bind the REAL hex
    // layer2_voucher_id of the voucher it belongs to, otherwise chain
    // validation rejects the manipulated branches for the wrong reason.
    let base_l2_vid = human_money_core::services::l2_gateway::extract_layer2_voucher_id(&base)
        .unwrap();

    for branch in [&mut branch_a, &mut branch_b] {
        let mut tx = branch.transactions.last().unwrap().clone();
        let old_trap = tx.trap_data.clone().expect("spend must carry trap shards");
        let eph: [u8; 32] = bs58::decode(tx.sender_ephemeral_pub.as_deref().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        // Fabrication: valid encodings, wrong signer. tau(t_id) stays bound
        // to the real transaction ids, so both shards remain collidable.
        let (forged_trap, _) = generate_sst_trap(
            &ACTORS.hacker.identity.signing_key,
            &old_trap.ds_tag,
            &eph,
            &tx.t_id,
        )
        .unwrap();
        tx.trap_data = Some(forged_trap);
        // NOTE: the attacker re-signs so the HMC_TX_AUTH_V3 digest covers the
        // forged shards — exactly like in the original exploit.
        let signed = human_money_core::test_utils::resign_transaction_ext(
            tx,
            &ACTORS.alice.identity.signing_key,
            &base_l2_vid,
            Some(&holder_key),
        );
        *branch.transactions.last_mut().unwrap() = signed;
    }

    // Both manipulated chains still pass standard validation: in stealth mode
    // there is NO sender identity to verify the trap against at chain level.
    // This residual gap is why attribution-time verification is mandatory.
    assert!(validate_voucher_against_standard(&branch_a, &standard).is_ok());
    assert!(validate_voucher_against_standard(&branch_b, &standard).is_ok());

    let fp_a = create_fingerprint_for_transaction(last_tx(&branch_a), &branch_a).unwrap();
    let fp_b = create_fingerprint_for_transaction(last_tx(&branch_b), &branch_b).unwrap();
    assert_eq!(fp_a.ds_tag, fp_b.ds_tag, "ds_tags must collide");
    assert_ne!(fp_a.t_id, fp_b.t_id, "distinct transactions required");

    // The raw mathematical extraction yields SOME point...
    let eph_bytes: [u8; 32] = bs58::decode(&fp_a.sender_ephemeral_pub)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let recovered = extract_sst_identity(&fp_a.ds_tag, &eph_bytes, &fp_a, &fp_b)
        .expect("well-formed shards always reconstruct");
    // ...but it is the FABRICATOR's key, NOT the framed party (anti-framing):
    // steering the reconstruction to a chosen victim is computationally
    // infeasible (EUF-CMA hardness of Schnorr/Ed25519).
    assert_ne!(
        recovered.compress().to_bytes(),
        framed_point.compress().to_bytes(),
        "raw extraction must NOT yield the framed party"
    );

    // ...and the anti-framing gate REFUSES the attribution claim because the
    // extracted identity does not match the claimed offender.
    let txs = [
        last_tx(&branch_a).clone(),
        last_tx(&branch_b).clone(),
    ];
    assert!(
        verify_stored_trap_shards_against_identity(&txs, &framed_point).is_err(),
        "framed did:key must be rejected as attribution"
    );

    // Positive control: the gate DOES attribute the fabricated shards to the
    // true signer behind them — the actual fraudster is caught, not the victim.
    assert!(
        verify_stored_trap_shards_against_identity(&txs, &fabricator_point).is_ok(),
        "shards must attribute to the key that actually produced them"
    );

    // Positive control: the HONEST traps verify against the true sender
    // identity point (V3 is prefix-free — no prefix parameter exists).
    let honest_a = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, None);
    let alice_point = ed25519_pk_to_curve_point(&ACTORS.alice.identity.public_key).unwrap();
    let honest_txs = [last_tx(&honest_a).clone()];
    // Single transaction is not enough (>= 2 required):
    assert!(
        verify_stored_trap_shards_against_identity(&honest_txs, &alice_point).is_err()
    );

    std::thread::sleep(std::time::Duration::from_millis(5));
    let honest_b = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, None);
    let honest_pair = [last_tx(&honest_a).clone(), last_tx(&honest_b).clone()];
    assert!(
        verify_stored_trap_shards_against_identity(&honest_pair, &alice_point).is_ok(),
        "honest double-spend traps MUST verify against the true sender identity"
    );
}

// =============================================================================
// POSITIVE CONTROL: Tampered trap shards ARE detected at chain level.
// =============================================================================
// Under V3 the trap shards are bound into the HMC_TX_AUTH_V3 layer2_signature
// digest. Any manipulation of trap_r/trap_s without re-signing breaks that
// signature — in EVERY privacy mode (the stealth gap of FIX 1 only opens when
// the attacker holds the ephemeral key AND re-signs; then the attribution
// gate above catches the frame attempt).
#[test]
fn audit_2_public_mode_rejects_tampered_trap_shards_control() {
    let (standard, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = PrivacyMode::Public;
    });

    let base = fresh_voucher(&standard, &standard_hash);
    let holder_key = derive_holder_key(&base, &ACTORS.alice.identity.signing_key);
    let mut branch = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, Some(false));
    assert!(validate_voucher_against_standard(&branch, &standard).is_ok());

    // Same class of tampering as in audit_1, but WITHOUT re-signing: flip a
    // bit inside the response shard s_i (keeps Base58 valid).
    {
        let tx = branch.transactions.last_mut().unwrap();
        let trap = tx.trap_data.as_mut().unwrap();
        let mut s_bytes = bs58::decode(&trap.trap_s).into_vec().unwrap();
        s_bytes[0] ^= 0x01;
        trap.trap_s = bs58::encode(s_bytes).into_string();
    }

    // The layer2 digest no longer matches the stored shards -> rejected.
    let result = validate_voucher_against_standard(&branch, &standard);
    assert!(
        result.is_err(),
        "Validation MUST reject tampered trap shard data"
    );
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.contains("layer2_signature"),
        "Expected layer2 digest rejection, got: {}",
        err_msg
    );
}

// =============================================================================
// FIX 2 (was HIGH): Identical-shard double spend defeats identity extraction
// =============================================================================
// Previously U depended only on (ds_tag, amount, receiver_anchor); a
// time-shifted clone produced different t_ids with IDENTICAL u, making
// delta_u == 0 and blocking unmasking forever. Under V3 every shard is
// evaluated at tau = H(ds_tag || t_id): two compliant forks ALWAYS produce
// distinct t_ids (t_time is part of the t_id preimage), hence distinct
// evaluation points, hence fully attributable shard pairs. Byte-identical
// shard values (replay) are rejected by an explicit degenerate-case guard.
#[test]
fn audit_3_time_shifted_double_spends_are_now_fully_attributable() {
    let (standard, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = PrivacyMode::Public;
    });

    let base = fresh_voucher(&standard, &standard_hash);
    let holder_key = derive_holder_key(&base, &ACTORS.alice.identity.signing_key);

    // Two genuine spends of the same input state, executed milliseconds apart
    // (=> distinct t_time => distinct t_id => distinct tau => distinct shards).
    let branch_a = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, Some(false));
    std::thread::sleep(std::time::Duration::from_millis(5));
    let branch_b = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, Some(false));

    // BOTH branches are fully compliant (incl. trap authentication).
    assert!(validate_voucher_against_standard(&branch_a, &standard).is_ok());
    assert!(validate_voucher_against_standard(&branch_b, &standard).is_ok());

    let fp_a = create_fingerprint_for_transaction(last_tx(&branch_a), &branch_a).unwrap();
    let fp_b = create_fingerprint_for_transaction(last_tx(&branch_b), &branch_b).unwrap();
    assert_eq!(fp_a.ds_tag, fp_b.ds_tag, "same input => same ds_tag");
    assert_ne!(fp_a.t_id, fp_b.t_id);
    assert_ne!(
        fp_a.trap_r, fp_b.trap_r,
        "FIX: distinct t_ids force distinct shard evaluation points"
    );
    assert_ne!(fp_a.trap_s, fp_b.trap_s);

    // The conflict is classified as verifiable...
    let own = human_money_core::models::conflict::OwnFingerprints {
        history: [(fp_a.ds_tag.clone(), vec![fp_a.clone()])].into_iter().collect(),
        ..Default::default()
    };
    let known = human_money_core::models::conflict::KnownFingerprints {
        local_history: [(fp_b.ds_tag.clone(), vec![fp_b.clone()])].into_iter().collect(),
        ..Default::default()
    };
    let result = check_for_double_spend(&own, &known);
    assert_eq!(result.verifiable_conflicts.len(), 1, "conflict detected");

    // ...and mathematical unmasking now SUCCEEDS, recovering the true sender.
    let eph_bytes: [u8; 32] = bs58::decode(&fp_a.sender_ephemeral_pub)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let recovered = extract_sst_identity(&fp_a.ds_tag, &eph_bytes, &fp_a, &fp_b)
        .expect("distinct t_ids guarantee successful extraction");
    let alice_point =
        ed25519_pk_to_curve_point(&ACTORS.alice.identity.public_key).unwrap();
    assert_eq!(
        recovered.compress().to_bytes(),
        alice_point.compress().to_bytes(),
        "the actual double-spender (alice) is unmasked"
    );
}

// =============================================================================
// FIX 3 (was MEDIUM): Non-canonical scalar encodings bypass identical-value
// guards
// =============================================================================
// x and x + l reduce to the same scalar but encode differently. Accepting
// non-canonical encodings lets two byte strings denote one scalar, defeating
// equality guards and enabling misattribution. V3 parses shard scalars
// strictly canonically and rejects malleated encodings outright.
#[test]
fn audit_4_non_canonical_scalar_is_rejected_instead_of_misattributing() {
    // Group order l, little-endian.
    const L_LE: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
        0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10,
    ];

    // y = 1 + l  =>  from_bytes_mod_order(y) == 1
    let mut y = [0u8; 32];
    let mut carry = 1u16; // add the constant ONE
    for i in 0..32 {
        let sum = L_LE[i] as u16 + carry;
        y[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0);
    let one = Scalar::ONE;
    assert_eq!(
        Scalar::from_bytes_mod_order(y),
        one,
        "non-canonical encoding reduces to the same scalar"
    );

    let sk = &ACTORS.alice.identity.signing_key;
    let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
    let ds_tag = "audit4_collision_tag".to_string();
    let eph = [42u8; 32];

    // Two honest shards for distinct forks.
    let (t1, _) = generate_sst_trap(sk, &ds_tag, &eph, "fork_one").unwrap();
    let (t2, _) = generate_sst_trap(sk, &ds_tag, &eph, "fork_two").unwrap();

    let fp = |t_id: &str, trap: &human_money_core::models::voucher::TrapData| {
        TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: t_id.to_string(),
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            ..Default::default()
        }
    };

    // Attacker re-encodes the response scalar of the second fork
    // NON-CANONICALLY (same reduced scalar, different bytes).
    let s2_bytes: [u8; 32] = bs58::decode(&t2.trap_s)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let mut carry = 0u16;
    let mut s2_plus_l = [0u8; 32];
    for i in 0..32 {
        let sum = s2_bytes[i] as u16 + L_LE[i] as u16 + carry;
        s2_plus_l[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "s < l implies no overflow");

    let mut fp_attack = fp("fork_two", &t2);
    fp_attack.trap_s = bs58::encode(s2_plus_l).into_string();
    let fp_one = fp("fork_one", &t1);
    assert_ne!(fp_one.trap_s, fp_attack.trap_s, "strings differ");

    // FIX: extraction REJECTS the non-canonical encoding outright instead of
    // silently returning a garbage identity.
    let result = extract_sst_identity(&ds_tag, &eph, &fp_one, &fp_attack);
    let err = result.expect_err("non-canonical scalars must be rejected");
    assert!(
        format!("{}", err).contains("canonical"),
        "unexpected error: {}",
        err
    );

    // Additional guard: byte-identical shard VALUES under two t_ids are a
    // replay artifact, not a fork, and error explicitly.
    let fp_replay = TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "fork_two".to_string(),
        trap_r: t1.trap_r.clone(),
        trap_s: t1.trap_s.clone(),
        ..Default::default()
    };
    let identical = extract_sst_identity(&ds_tag, &eph, &fp_one, &fp_replay);
    let err2 = identical.expect_err("identical shard values must abort extraction");
    assert!(
        format!("{}", err2).contains("identical trap shards"),
        "unexpected error: {}",
        err2
    );

    // Sanity: distinct honest forks still work end-to-end.
    let (t3, _) = generate_sst_trap(sk, &ds_tag, &eph, "fork_three").unwrap();
    let recovered = extract_sst_identity(&ds_tag, &eph, &fp_one, &fp("fork_three", &t3))
        .expect("honest pair must extract");
    assert_eq!(recovered.compress().to_bytes(), id_point.compress().to_bytes());
}

// =============================================================================
// FIX 4 (was HIGH): Unauthenticated proof import quarantines victims
// =============================================================================
// A forged proof (invalid reporter signature, inconsistent proof_id, garbage
// transactions, fabricated timestamps) used to remotely quarantine the
// victim's active voucher. Every import is now gated:
// structure -> reporter signature -> proof-id consistency -> attribution ->
// tx crypto.
#[test]
fn audit_5_forged_proof_import_is_rejected_and_victim_stays_active() {
    let (mut wallet, _victim_identity) =
        human_money_core::test_utils::create_test_wallet("audit-victim", "inst-1".to_string())
            .unwrap();
    let local_id = add_voucher_to_wallet(
        &mut wallet,
        &ACTORS.alice.identity,
        "50.00",
        &FREETALER_STANDARD.0,
        true,
    )
    .unwrap();

    // Victim voucher is active and healthy.
    let victim_tx_t_id = wallet.voucher_store.vouchers[&local_id]
        .voucher
        .transactions
        .last()
        .unwrap()
        .t_id
        .clone();
    assert!(matches!(
        wallet.voucher_store.vouchers[&local_id].status,
        VoucherStatus::Active
    ));

    // --- Attacker fabricates a "proof" --------------------------------------
    let mut fake_winner = Transaction::default();
    fake_winner.t_id = "FAKE_WINNING_TX_ID".to_string();
    fake_winner.prev_hash = "NOT_EVEN_VALID_BASE58".to_string();
    fake_winner.t_type = "transfer".to_string();
    fake_winner.t_time = "1970-01-01T00:00:00Z".to_string(); // wins the race

    let mut fake_loser = Transaction::default();
    fake_loser.t_id = victim_tx_t_id.clone();
    fake_loser.prev_hash = "ALSO_INVALID".to_string();
    fake_loser.t_time = "2026-01-01T00:00:00Z".to_string();

    let forged_proof = ProofOfDoubleSpend {
        proof_id: "FORGED_PROOF_ID".to_string(),
        offender_id: ACTORS.hacker.user_id.clone(),
        suspected_identity: None,
        fork_point_prev_hash: "FORGED_FORK".to_string(),
        conflicting_transactions: vec![fake_winner, fake_loser],
        deletable_at: "2099-12-31T23:59:59Z".to_string(),
        reporter_id: "did:key:zATTACKER".to_string(),
        report_timestamp: "2026-08-23T00:00:00Z".to_string(),
        reporter_signature: "INVALID_SIGNATURE_BYTES".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
    };

    // FIX: the forged proof is REJECTED, not applied.
    assert!(
        wallet.import_proof(forged_proof).is_err(),
        "forged proofs must never be accepted"
    );

    // The victim's voucher is untouched and still active.
    let status = wallet.voucher_store.vouchers[&local_id].status.clone();
    assert!(
        matches!(status, VoucherStatus::Active),
        "victim voucher must NOT be quarantined by a forged proof, got {:?}",
        status
    );
    assert!(
        wallet.list_conflicts().is_empty(),
        "no defamatory conflict may be persisted"
    );
}

/// Positive control for FIX 4: a genuinely created and properly signed proof
/// about a REAL double spend still quarantines the losing branch.
#[test]
fn audit_6_genuine_signed_proof_still_quarantines_the_loser() {
    use human_money_core::wallet::instance::VoucherInstance;

    let (standard, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = PrivacyMode::Public;
    });

    let base = fresh_voucher(&standard, &standard_hash);
    let holder_key = derive_holder_key(&base, &ACTORS.alice.identity.signing_key);

    // Real double spend: two compliant forks sharing prev_hash + ephemeral key.
    let branch_first = spend_full(&base, &standard, &holder_key, &ACTORS.bob.identity, Some(false));
    std::thread::sleep(std::time::Duration::from_millis(5));
    let branch_second = spend_full(&base, &standard, &holder_key, &ACTORS.charlie.identity, Some(false));

    let fork_prev = last_tx(&branch_first).prev_hash.clone();
    assert_eq!(fork_prev, last_tx(&branch_second).prev_hash);

    // Victim wallet holds the LATER branch (the loser of "earliest wins").
    let (mut wallet, _identity) =
        human_money_core::test_utils::create_test_wallet("audit-control", "ctrl-1".to_string())
            .unwrap();
    let instance = VoucherInstance {
        local_instance_id: "ctrl-1".to_string(),
        status: VoucherStatus::Active,
        voucher: branch_second.clone(),
        ..Default::default()
    };
    wallet.voucher_store.vouchers.insert("ctrl-1".to_string(), instance);

    // Bob (an honest third party) reports the conflict with a proper proof.
    let genuine_proof = human_money_core::services::conflict_manager::create_proof_of_double_spend(
        ACTORS.alice.user_id.clone(),
        fork_prev,
        vec![last_tx(&branch_first).clone(), last_tx(&branch_second).clone()],
        "2099-01-01T00:00:00Z".to_string(),
        &ACTORS.bob.identity,
        false,
    )
    .unwrap();

    wallet.import_proof(genuine_proof).expect("genuine proof must be accepted");

    // The loser held locally is quarantined by the authentic evidence.
    let status = wallet.voucher_store.vouchers["ctrl-1"].status.clone();
    assert!(
        matches!(status, VoucherStatus::Quarantined { .. }),
        "the losing branch must be quarantined by a genuine proof, got {:?}",
        status
    );

    let conflicts = wallet.list_conflicts();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].offender_id, ACTORS.alice.user_id);
}
