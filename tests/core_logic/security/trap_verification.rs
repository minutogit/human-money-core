use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::SigningKey;
use human_money_core::services::crypto::{
    create_user_id, ed25519_pk_to_curve_point, get_hash_from_slices,
};
use human_money_core::services::trap_manager::{
    compute_tau, generate_sst_trap, verify_sst_witness, TrapWitness,
};
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::setup_voucher_with_one_tx;
use rand::rngs::OsRng;

/// Mirrors the production ds_tag derivation: H(prev_hash || revealed eph key).
/// Test fixture labels are Base58-encoded here so they match on-chain formats.
fn ds_tag_of(prev_fixture: &[u8], eph_b58: &str) -> String {
    let prev_b58 = bs58::encode(prev_fixture).into_string();
    get_hash_from_slices(&[
        &bs58::decode(prev_b58).into_vec().unwrap(),
        &bs58::decode(eph_b58).into_vec().unwrap(),
    ])
}

fn eph32_of(eph_b58: &str) -> [u8; 32] {
    bs58::decode(eph_b58)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn test_sst_generation_determinism() {
    // The SST engine replaces the old HKDF slope derivation with a fully
    // deterministic shared-signature construction. Equivalent guarantees:
    // 1. Generation MUST be deterministic (deterministic nonce + masking
    //    values derived exclusively from the long-term key and the input).
    // 2. Avalanche effect: changing one bit of the input context (here the
    //    prev_hash inside ds_tag) must change every shard byte.
    let sk = SigningKey::generate(&mut OsRng);
    let eph_b58 = bs58::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes())
        .into_string();
    let eph = eph32_of(&eph_b58);

    // 1. Run 100 times, must always be byte-identical
    let ds_tag = ds_tag_of(b"prev_hash_123456789", &eph_b58);
    let (first_trap, _) = generate_sst_trap(&sk, &ds_tag, &eph, "fixed_t_id").unwrap();

    for _ in 0..100 {
        let (trap, _) = generate_sst_trap(&sk, &ds_tag, &eph, "fixed_t_id").unwrap();
        assert_eq!(first_trap, trap, "SST generation must be deterministic!");
    }

    // 2. Avalanche Effect: Change one character of the fork point context
    let ds_tag_modified = ds_tag_of(b"prev_hash_123456788", &eph_b58);
    let (second_trap, _) = generate_sst_trap(&sk, &ds_tag_modified, &eph, "fixed_t_id").unwrap();

    assert_ne!(
        first_trap.trap_r, second_trap.trap_r,
        "Avalanche effect missing!"
    );
    assert_ne!(first_trap.trap_s, second_trap.trap_s);
}

#[test]
fn test_sst_collision_math_reconstruction() {
    // Mathematical core of the V3 Shared-Signature Trap: every fork publishes
    // a shard (R_i, s_i) = (R_sig + tau_i * M_R, s_sig + tau_i * m_s) of ONE
    // Schnorr signature. Two colliding shards determine the masking values by
    // linear interpolation:
    //   M_R = (R1 - R2) * (tau1 - tau2)^-1
    //   m_s = (s1 - s2) * (tau1 - tau2)^-1
    // We simulate the solver formula using raw scalars/points and verify the
    // reconstruction against the private witness (ground truth).
    let sk = SigningKey::generate(&mut OsRng);
    let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();

    let eph_b58 =
        bs58::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()).into_string();
    let eph = eph32_of(&eph_b58);
    let ds_tag = ds_tag_of(b"prev_hash_collision_math", &eph_b58);

    // Two forks of the same input => same ds_tag, distinct t_ids.
    let (trap_a, witness_a) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_A").unwrap();
    let (trap_b, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_B").unwrap();
    assert_eq!(trap_a.ds_tag, trap_b.ds_tag);

    // Decode the published shards.
    let parse_point = |s: &str| -> curve25519_dalek::edwards::EdwardsPoint {
        CompressedEdwardsY::from_slice(&bs58::decode(s).into_vec().unwrap())
            .unwrap()
            .decompress()
            .unwrap()
    };
    let parse_scalar = |s: &str| -> Scalar {
        let arr: [u8; 32] = bs58::decode(s)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        Scalar::from_canonical_bytes(arr)
            .into_option()
            .expect("canonical shard scalar")
    };

    let r1 = parse_point(&trap_a.trap_r);
    let r2 = parse_point(&trap_b.trap_r);
    let s1 = parse_scalar(&trap_a.trap_s);
    let s2 = parse_scalar(&trap_b.trap_s);
    let tau1 = compute_tau(&ds_tag, "tx_A");
    let tau2 = compute_tau(&ds_tag, "tx_B");
    assert_ne!(tau1, tau2, "distinct t_ids must yield distinct evaluation points");

    // Solver logic: polynomial interpolation of the masking values ...
    let delta_tau_inv = (tau1 - tau2).invert();
    let m_hat_r = (r1 - r2) * delta_tau_inv;
    let m_hat_s = (s1 - s2) * delta_tau_inv;

    // ... and reconstruction of the underlying signature.
    let r_hat = r1 - tau1 * m_hat_r;
    let s_hat = s1 - tau1 * m_hat_s;

    // Ground truth: the reconstruction must EXACTLY match the private witness
    // (R_sig, s_sig, M_R, m_s) that only the legitimate recipient holds.
    assert_eq!(m_hat_r, parse_point(&witness_a.m_r), "masking point mismatch");
    assert_eq!(m_hat_s, parse_scalar(&witness_a.m_s), "masking scalar mismatch");
    assert_eq!(r_hat, parse_point(&witness_a.r_sig), "commitment mismatch");
    assert_eq!(s_hat, parse_scalar(&witness_a.s_sig), "response mismatch");

    // Identity extraction (challenge-bound, EUF-CMA secure) recovers the signer.
    let fp_a = human_money_core::models::conflict::TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "tx_A".to_string(),
        trap_r: trap_a.trap_r.clone(),
        trap_s: trap_a.trap_s.clone(),
        ..Default::default()
    };
    let fp_b = human_money_core::models::conflict::TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "tx_B".to_string(),
        trap_r: trap_b.trap_r.clone(),
        trap_s: trap_b.trap_s.clone(),
        ..Default::default()
    };
    let recovered = human_money_core::services::trap_manager::extract_sst_identity(
        &ds_tag, &eph, &fp_a, &fp_b,
    )
    .unwrap();
    assert_eq!(
        recovered, id_point,
        "Identity extraction failed mathematically!"
    );
}

#[test]
fn test_sst_random_mask_substitution_is_futile() {
    // Security Test (V3 analogue of the old "random slope" attack):
    // In V2 an attacker could vary the blinded slope m per transaction. In
    // SST the masking values are derived deterministically from the long-term
    // key and the input — there is NO randomness left to substitute:
    //
    // 1. Regenerating a shard for the SAME (key, input, t_id) yields
    //    byte-identical TrapData (no nonce re-roll, no malleability).
    // 2. Distinct forks necessarily differ by t_id, which forces DISTINCT
    //    evaluation points tau(t_id) — hence distinct shards on a common
    //    line, which is precisely what makes collision extraction work.
    let sk = SigningKey::generate(&mut OsRng);
    let eph_b58 =
        bs58::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()).into_string();
    let eph = eph32_of(&eph_b58);
    let ds_tag = ds_tag_of(b"tag_1", &eph_b58);

    // Case 1: identical parameters => identical shard (nothing to vary).
    let (trap_real, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_id").unwrap();
    let (trap_regenerated, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_id").unwrap();
    assert_eq!(
        trap_real, trap_regenerated,
        "SST generation must not leave room for arbitrary mask substitution"
    );

    // Case 2: a fork (different t_id) keeps the ds_tag but MUST change shards.
    let (trap_fork, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_id_fork").unwrap();
    assert_eq!(trap_real.ds_tag, trap_fork.ds_tag);
    assert_ne!(trap_real.trap_r, trap_fork.trap_r);
    assert_ne!(trap_real.trap_s, trap_fork.trap_s);
    // The two shards lie on the line of ONE shared signature: colliding them
    // reconstructs the signer identity (verified extensively elsewhere).
}

#[test]
fn test_sst_ds_tag_manipulation_detected_with_bypass() {
    // Attack: Manipulate the trap context (ds_tag) to NOT match Hash(Input).
    // This requires bypassing signature verification because the layer2
    // digest covers the shards. The structural ds_tag check must STILL fire.
    human_money_core::set_signature_bypass(true);

    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // Manipulate the trap context in the transaction.
    // The original ds_tag is valid. We overwrite it with a different valid
    // hash so only the semantic input-binding check can detect the fraud.
    let wrong_ds_tag = get_hash_from_slices(&[b"totally_unrelated_context"]);
    voucher
        .transactions
        .last_mut()
        .unwrap()
        .trap_data
        .as_mut()
        .expect("Trap data missing")
        .ds_tag = wrong_ds_tag;

    // Now validate.
    // The signature check is bypassed. But the chain validation deep inside
    // `validate_voucher_against_standard` recomputes:
    //   expected_ds_tag = H(prev_hash || sender_ephemeral_pub)
    // and rejects any mismatch (context confusion / replay across inputs).
    let result = validate_voucher_against_standard(&voucher, standard);

    assert!(
        result.is_err(),
        "Manipulation of the trap ds_tag must be detected even with signature bypass!"
    );

    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.contains("DS-Tag"),
        "Error message should indicate trap ds_tag mismatch. Got: {}",
        err_msg
    );

    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_hash_to_curve_not_default() {
    // This test ensures that `hash_to_curve` does not simply return the
    // default value of the EdwardsPoint curve. A trivial point on the curve
    // completely undermines the security of Elliptic Curve Cryptography.
    let point = human_money_core::services::crypto::hash_to_curve(b"test_input");
    let default_point = curve25519_dalek::edwards::EdwardsPoint::default();
    assert_ne!(point, default_point, "hash_to_curve must not return the default identity point");
}

#[test]
fn test_sst_zero_challenge_forgery_rejected() {
    // This test mathematically proves that the SST witness verification
    // enforces a non-zero challenge. If the challenge c were erroneously 0,
    // the verification equation s*G == R + c*X collapses to s*G == R, which
    // an attacker can satisfy WITHOUT knowing the payer key by choosing
    // R = s*G. We actively construct this forgery and require the verifier
    // to reject it, hardening the system against zero-challenge regressions.
    let victim_sk = SigningKey::generate(&mut OsRng);
    let payer_did = create_user_id(&victim_sk.verifying_key(), None).unwrap();

    let eph_b58 =
        bs58::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()).into_string();
    let eph = eph32_of(&eph_b58);
    let ds_tag = ds_tag_of(b"zero_challenge_tag", &eph_b58);

    // ZKP FORGERY: choose s randomly (without knowing the payer secret) and
    // set R = s * G. This satisfies s*G == R + 0*X for ANY payer identity.
    let s_fake = Scalar::random(&mut OsRng);
    let commitment_r = s_fake * ED25519_BASEPOINT_POINT;

    let witness = TrapWitness {
        r_sig: bs58::encode(commitment_r.compress().as_bytes()).into_string(),
        s_sig: bs58::encode(s_fake.as_bytes()).into_string(),
        m_r: bs58::encode(ED25519_BASEPOINT_POINT.compress().as_bytes()).into_string(),
        m_s: bs58::encode(Scalar::ONE.as_bytes()).into_string(),
    };
    // The shard itself is irrelevant: the signature equation fires first.
    let trap_shard = human_money_core::models::voucher::TrapData {
        ds_tag: ds_tag.clone(),
        ..Default::default()
    };

    let verify_result = verify_sst_witness(&witness, &trap_shard, &payer_did, &ds_tag, &eph, "some_t_id");

    // Verification must NOT succeed: with a correctly computed non-zero
    // challenge, s*G == R but R + c*X != R, so the forgery fails. If
    // calculate_challenge() were to (erroneously) return 0, verification
    // would succeed — which is exactly the regression this test pins down.
    assert!(
        verify_result.is_err(),
        "The SST witness check must fail for a forged signature where s*G == R, \
         which means the challenge c must not be zero"
    );
    let err_msg = verify_result.err().unwrap().to_string();
    assert!(
        err_msg.contains("signature does not verify"),
        "Expected signature-equation rejection, got: {}",
        err_msg
    );
}
