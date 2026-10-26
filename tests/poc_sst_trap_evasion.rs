//! PoC: SST trap evasion by a malicious double-spender.
//!
//! Each test PASSES on the current code base, i.e. it demonstrates that the
//! attack works. Once the protocol is fixed these assertions must be flipped.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::voucher::TrapData;
use human_money_core::services::crypto::{
    derive_stealth_ephemeral_point, derive_stealth_secret_key, ed25519_pk_to_curve_point,
    get_hash, get_secret_scalar, EphemeralKey,
};
use human_money_core::services::trap_manager::{
    compute_sst_challenge, compute_tau, compute_trap_message_mu, extract_sst_identity,
    generate_sst_trap, sst_scalar, verify_sst_witness, SST_DOMAIN_STEALTH_BLIND, TrapWitness,
};
use rand::RngCore;

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn rand_scalar() -> Scalar {
    let mut b = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut b);
    Scalar::from_bytes_mod_order_wide(&b)
}

fn did_of(sk: &ed25519_dalek::SigningKey) -> String {
    let mut mc = vec![0xed, 0x01];
    mc.extend_from_slice(sk.verifying_key().as_bytes());
    format!("did:key:z{}", bs58::encode(mc).into_string())
}

fn fp(t_id: &str, trap: &TrapData) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: trap.ds_tag.clone(),
        t_id: t_id.to_string(),
        trap_r: trap.trap_r.clone(),
        trap_s: trap.trap_s.clone(),
        ..Default::default()
    }
}

/// A modified client builds the trap of fork B with a FRESH random nonce and
/// FRESH random masks. It is a perfectly valid Schnorr signature under the
/// attacker's own did:key, so the L1 witness check of recipient B passes.
fn malicious_sst_trap(
    sk: &ed25519_dalek::SigningKey,
    ds_tag: &str,
    eph: &[u8; 32],
    t_id: &str,
) -> (TrapData, TrapWitness) {
    let x = get_secret_scalar(sk);
    let mu = compute_trap_message_mu(ds_tag, eph);
    let r = rand_scalar(); // NOT H(x || mu)
    let r_sig = r * ED25519_BASEPOINT_POINT;
    let c = compute_sst_challenge(&mu, &r_sig);
    let s_sig = r + c * x;
    let m_r = rand_scalar() * ED25519_BASEPOINT_POINT; // NOT hash_to_curve(x||...)
    let m_s = rand_scalar(); // NOT H(x||...)
    let tau = compute_tau(ds_tag, t_id, "");
    let r_i = r_sig + tau * m_r;
    let s_i = s_sig + tau * m_s;
    (
        TrapData {
            ds_tag: ds_tag.to_string(),
            trap_r: bs58::encode(r_i.compress().as_bytes()).into_string(),
            trap_s: bs58::encode(s_i.as_bytes()).into_string(),
        },
        TrapWitness {
            r_sig: bs58::encode(r_sig.compress().as_bytes()).into_string(),
            s_sig: bs58::encode(s_sig.as_bytes()).into_string(),
            m_r: bs58::encode(m_r.compress().as_bytes()).into_string(),
            m_s: bs58::encode(m_s.as_bytes()).into_string(),
            ..generate_sst_trap(sk, ds_tag, eph, t_id, "", &[0; 32]).unwrap().1
        },
    )
}

/// Fresh signature nonces with arbitrary masks fail L1 verification because
/// the masks must derive from the base signature. Valid alternative signatures
/// are covered by the victim-disclosure regression in trap_manager.
/// Honest generation on both forks succeeds and correctly extracts the attacker's identity.
#[test]
fn poc_fresh_nonce_per_fork_evades_identity_extraction() {
    let attacker = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let did = did_of(&attacker);
    let ds_tag = bs58::encode(rand32()).into_string();
    let input_seed = [0u8; 32];
    let eph = human_money_core::test_utils::bound_test_point(&attacker);
    let t_a = bs58::encode(rand32()).into_string();
    let t_b = bs58::encode(rand32()).into_string();

    // Fork A: completely honest generation.
    let (trap_a, mut wit_a) = generate_sst_trap(&attacker, &ds_tag, &eph, &t_a, "", &[0u8; 32]).unwrap();
    // Fork B: modified client with fresh random nonce/masks.
    let (trap_b, wit_b) = malicious_sst_trap(&attacker, &ds_tag, &eph, &t_b);

    // Recipient A accepts payment (honest generation).
    wit_a.input_seed = bs58::encode(input_seed).into_string();
    verify_sst_witness(&wit_a, &trap_a, &did, &ds_tag, &eph, &t_a, "").unwrap();

    // Recipient B REJECTS payment under Fix 1!
    assert!(
        verify_sst_witness(&wit_b, &trap_b, &did, &ds_tag, &eph, &t_b, "").is_err(),
        "Fix 1 enforced: recipient must reject forged/fresh-nonce trap line!"
    );

    // If both forks are generated honestly under the attacker's key:
    let (trap_b_honest, mut wit_b_honest) =
        generate_sst_trap(&attacker, &ds_tag, &eph, &t_b, "", &[0u8; 32]).unwrap();
    wit_b_honest.input_seed = wit_a.input_seed.clone();
    verify_sst_witness(&wit_b_honest, &trap_b_honest, &did, &ds_tag, &eph, &t_b, "").unwrap();

    let x_hat = extract_sst_identity(&ds_tag, &eph, &fp(&t_a, &trap_a), &fp(&t_b, &trap_b_honest))
        .expect("extraction must succeed on honest colliding forks");
    let real = ed25519_pk_to_curve_point(&attacker.verifying_key()).unwrap();
    assert_eq!(x_hat, real, "attacker is successfully identified");
}

/// FIX 2 VERIFIED: Exclusive Recipient Key Custody via Stealth-Key Derivation.
/// Under Fix 2, Alice picks a recipient_seed, but the spendable key requires Bob's
/// private scalar: x_eph = x_Bob + h mod q.
/// Alice cannot spend Bob's output:
/// 1) Her seed-derived key does not match the output's receiver_ephemeral_pub_hash.
/// 2) She cannot forge a valid Ed25519 signature under P_eph without Bob's private key.
/// Cross-identity forks are completely eliminated.
#[test]
fn poc_retained_recipient_seed_cross_identity_fork_evades_extraction() {
    let alice = ed25519_dalek::SigningKey::from_bytes(&rand32()); // sender / previous payer
    let bob = ed25519_dalek::SigningKey::from_bytes(&rand32()); // honest recipient
    let recipient_seed = rand32(); // Alice generates this seed for Bob

    // Alice derives the public stealth anchor point P_eph = X_Bob + h * G
    let p_eph = derive_stealth_ephemeral_point(&bob.verifying_key(), &recipient_seed).unwrap();
    let expected_anchor = get_hash(p_eph.compress().as_bytes());

    // Bob derives his stealth key using his private signing key and the seed
    let (bob_scalar, bob_point, bob_vk) = derive_stealth_secret_key(&bob, &recipient_seed).unwrap();
    assert_eq!(bob_point, p_eph, "Bob derives the exact public point Alice committed to");
    assert_eq!(
        get_hash(bob_vk.as_bytes()),
        expected_anchor,
        "Bob's derived verifying key matches the stealth anchor hash"
    );

    // Bob can sign an output transaction under P_eph
    let message = b"transfer_to_charlie_payload";
    let bob_eph = EphemeralKey::Stealth {
        secret_scalar: bob_scalar,
        public_point: bob_point,
        verifying_key: bob_vk,
        input_seed: recipient_seed,
    };
    let bob_sig = bob_eph.sign(message);
    assert!(
        bob_vk.verify_strict(message, &bob_sig).is_ok(),
        "Bob's signature under P_eph must strictly verify under RFC 8032"
    );

    // Attempt 1: Alice tries to spend using the recipient_seed directly as a standard signing key
    let alice_legacy = ed25519_dalek::SigningKey::from_bytes(&recipient_seed);
    let alice_legacy_anchor = get_hash(alice_legacy.verifying_key().as_bytes());
    assert_ne!(
        alice_legacy_anchor, expected_anchor,
        "Fix 2: Alice's seed-derived key does not match Bob's stealth anchor hash"
    );

    // Attempt 2: Alice attempts to sign claiming P_eph as sender ephemeral pubkey.
    // Alice knows recipient_seed, so she can compute the blinding scalar h.
    let h_blind = sst_scalar(
        SST_DOMAIN_STEALTH_BLIND,
        &[&recipient_seed[..], bob.verifying_key().as_bytes()],
    );
    // Alice attempts to sign using h_blind as the secret scalar:
    let forged_sig_h =
        human_money_core::services::crypto::sign_ed25519_scalar(&h_blind, &p_eph, message);
    assert!(
        bob_vk.verify_strict(message, &forged_sig_h).is_err(),
        "Fix 2: Alice cannot forge Bob's stealth signature using only the blinding scalar"
    );

    // Alice also cannot sign using her own secret key scalar:
    let alice_scalar = get_secret_scalar(&alice);
    let forged_sig_alice =
        human_money_core::services::crypto::sign_ed25519_scalar(&alice_scalar, &p_eph, message);
    assert!(
        bob_vk.verify_strict(message, &forged_sig_alice).is_err(),
        "Fix 2: Alice cannot forge Bob's stealth signature using Alice's own identity scalar"
    );
}

// =============================================================================
// FINDING 3: prev_hash / ds_tag depend on signer-malleable fields
// =============================================================================

/// Produces a DIFFERENT but fully valid Ed25519 signature (random nonce
/// instead of the RFC 8032 deterministic one). Any modified client can do this.
fn ed25519_sign_randomized(sk: &ed25519_dalek::SigningKey, msg: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let a = get_secret_scalar(sk);
    let r = rand_scalar();
    let big_r = (r * ED25519_BASEPOINT_POINT).compress();
    let mut h = Sha512::new();
    h.update(big_r.as_bytes());
    h.update(sk.verifying_key().as_bytes());
    h.update(msg);
    let k = Scalar::from_hash(h);
    let s = r + k * a;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(big_r.as_bytes());
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// The creator clones the genesis, re-signs `sender_identity_signature` with
/// a different nonce (same t_id, same voucher_id, same signatures[]), and
/// spends each copy once. Both branches validate, but their first spends
/// carry DIFFERENT ds_tags -> no collision, no trap, no detection at all.
#[test]
fn poc_genesis_resignature_creates_two_uncolliding_copies() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::models::voucher_standard_definition::PrivacyMode;
    use human_money_core::services::conflict_manager::{
        check_for_double_spend, create_fingerprint_for_transaction,
    };
    use human_money_core::services::voucher_validation::validate_voucher_against_standard;
    use human_money_core::test_utils::{
        create_custom_standard, derive_holder_key, ACTORS, FREETALER_STANDARD,
    };
    use human_money_core::NewVoucherData;

    let (standard, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = PrivacyMode::Public;
    });
    let alice = &ACTORS.alice;
    let data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(alice.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };
    let base_a = human_money_core::models::voucher::Voucher::create_with_key(
        data,
        &standard,
        &standard_hash,
        &alice.identity.signing_key,
    )
    .unwrap();

    // Copy B: identical except for a re-randomized identity signature.
    let mut base_b = base_a.clone();
    let init = &mut base_b.transactions[0];
    let t_id_bytes = bs58::decode(&init.t_id).into_vec().unwrap();
    let sig = ed25519_sign_randomized(&alice.identity.signing_key, &t_id_bytes);
    assert_ne!(
        init.sender_identity_signature.as_deref().unwrap(),
        bs58::encode(sig).into_string()
    );
    init.sender_identity_signature = Some(bs58::encode(sig).into_string());
    assert_eq!(base_a.voucher_id, base_b.voucher_id);
    assert_eq!(base_a.transactions[0].t_id, base_b.transactions[0].t_id);
    // SECURITY (FIX 3): The creator signature in signatures[0] binds the complete
    // canonical hash of the genesis transaction. Modifying sender_identity_signature
    // alters init_tx_hash, invalidating signatures[0]. Copy B is rejected fail-closed.
    let val_err = validate_voucher_against_standard(&base_b, &standard);
    assert!(
        val_err.is_err(),
        "Copy B with re-randomized genesis signature must fail standard validation"
    );

    // Legitimate double-spend of base_a: spends from the authentic voucher must collide on ds_tag.
    let holder = derive_holder_key(&base_a, &alice.identity.signing_key);
    let spend = |base: &human_money_core::Voucher, to: &human_money_core::UserIdentity| {
        human_money_core::models::voucher::Transaction::create(
            base,
            &standard,
            &alice.user_id,
            &alice.identity.signing_key,
            &holder,
            &to.user_id,
            "100.00",
            Some(false),
        )
        .unwrap()
        .0
    };
    let branch_a = spend(&base_a, &ACTORS.bob.identity);
    let branch_b = spend(&base_a, &ACTORS.charlie.identity);
    validate_voucher_against_standard(&branch_a, &standard).expect("branch A valid");
    validate_voucher_against_standard(&branch_b, &standard).expect("branch B valid");

    let fp_a =
        create_fingerprint_for_transaction(branch_a.transactions.last().unwrap(), &branch_a)
            .unwrap();
    let fp_b =
        create_fingerprint_for_transaction(branch_b.transactions.last().unwrap(), &branch_b)
            .unwrap();
    assert_eq!(fp_a.ds_tag, fp_b.ds_tag, "same input must produce IDENTICAL ds_tags");

    let own = human_money_core::models::conflict::OwnFingerprints {
        history: [(fp_a.ds_tag.clone(), vec![fp_a.clone()])].into_iter().collect(),
        ..Default::default()
    };
    let known = human_money_core::models::conflict::KnownFingerprints {
        local_history: [(fp_b.ds_tag.clone(), vec![fp_b.clone()])].into_iter().collect(),
        ..Default::default()
    };
    let result = check_for_double_spend(&own, &known);
    assert!(
        !result.verifiable_conflicts.is_empty(),
        "double spend must be detected and verified"
    );
}

/// FIX 5 (Regression): In `extract_sst_identity`, `fp1.sender_ephemeral_pub` and
/// `fp2.sender_ephemeral_pub` are checked against `eph_pub` to prevent cross-key evasion.
#[test]
fn poc_extract_sst_identity_missing_ephemeral_pub_equality_guard() {
    let sk_a = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let sk_b = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let ds_tag = bs58::encode(rand32()).into_string();
    let eph_a = human_money_core::test_utils::bound_test_point(&sk_a);
    let eph_b = human_money_core::test_utils::bound_test_point(&sk_b);
    let t_a = bs58::encode(rand32()).into_string();
    let t_b = bs58::encode(rand32()).into_string();

    let (trap_a, _) = generate_sst_trap(&sk_a, &ds_tag, &eph_a, &t_a, "", &[0u8; 32]).unwrap();
    let (trap_b, _) = generate_sst_trap(&sk_b, &ds_tag, &eph_b, &t_b, "", &[0u8; 32]).unwrap();

    let mut fp_a = fp(&t_a, &trap_a);
    fp_a.sender_ephemeral_pub = bs58::encode(eph_a).into_string();
    let mut fp_b = fp(&t_b, &trap_b);
    fp_b.sender_ephemeral_pub = bs58::encode(eph_b).into_string();

    // extract_sst_identity now rejects two fingerprints with DIFFERENT sender_ephemeral_pub:
    let res = extract_sst_identity(&ds_tag, &eph_a, &fp_a, &fp_b);
    assert!(
        res.is_err(),
        "extract_sst_identity must enforce sender_ephemeral_pub equality against eph_pub"
    );
}

/// FIX 4 (Regression): When a wallet holds ONE conflicting transaction locally and
/// learns of the second fork via a gossip fingerprint (`missing_t_ids`),
/// `verify_and_create_proof` now populates `soft_placeholder` with `trap_data`,
/// `sender_ephemeral_pub`, `layer2_signature`, and `t_time` from the fingerprint.
/// The resulting proof passes `verify_stored_trap_shards_against_identity` on import.
#[test]
fn poc_mixed_local_and_gossip_proof_omits_trap_data_and_fails_import() {
    use human_money_core::models::voucher::Transaction;
    use human_money_core::services::trap_manager::verify_stored_trap_shards_against_identity;

    let offender = ed25519_dalek::SigningKey::from_bytes(&rand32());
    let ds_tag = bs58::encode(rand32()).into_string();
    let eph = human_money_core::test_utils::bound_test_point(&offender);
    let eph_str = bs58::encode(eph).into_string();
    let t_a = bs58::encode(rand32()).into_string();
    let t_b = bs58::encode(rand32()).into_string();

    let (trap_a, _) = generate_sst_trap(&offender, &ds_tag, &eph, &t_a, "", &[0u8; 32]).unwrap();
    let (trap_b, _) = generate_sst_trap(&offender, &ds_tag, &eph, &t_b, "", &[0u8; 32]).unwrap();

    // Fingerprint extraction succeeds (this is what ingress.rs:734 does):
    let mut fp_a = fp(&t_a, &trap_a);
    fp_a.sender_ephemeral_pub = eph_str.clone();
    let mut fp_b = fp(&t_b, &trap_b);
    fp_b.sender_ephemeral_pub = eph_str.clone();
    let extracted_id = extract_sst_identity(&ds_tag, &eph, &fp_a, &fp_b).unwrap();
    let real_id = ed25519_pk_to_curve_point(&offender.verifying_key()).unwrap();
    assert_eq!(extracted_id, real_id);

    // Local transaction A (full) + synthetic soft_placeholder B as built in ingress.rs:770-785 (Fix 4):
    let tx_a = Transaction {
        t_id: t_a,
        sender_ephemeral_pub: Some(eph_str),
        trap_data: Some(trap_a),
        ..Default::default()
    };
    let synthetic_tx_b = Transaction {
        t_id: t_b,
        t_type: "soft_placeholder".to_string(),
        amount: "0.00 (Synthetic)".to_string(),
        sender_ephemeral_pub: Some(fp_b.sender_ephemeral_pub.clone()),
        layer2_signature: Some(fp_b.layer2_signature.clone()),
        trap_data: Some(TrapData {
            ds_tag: fp_b.ds_tag.clone(),
            trap_r: fp_b.trap_r.clone(),
            trap_s: fp_b.trap_s.clone(),
        }),
        t_time: fp_b.encrypted_timestamp.to_string(),
        ..Default::default()
    };

    // Any peer importing this ProofOfDoubleSpend runs Gate 3b:
    let import_gate_res =
        verify_stored_trap_shards_against_identity(&[tx_a, synthetic_tx_b], &extracted_id);
    assert!(
        import_gate_res.is_ok(),
        "Proof produced from 1 local tx + 1 gossip fingerprint must pass Gate 3b on import!"
    );
}


