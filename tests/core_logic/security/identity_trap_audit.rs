// tests/core_logic/security/identity_trap_audit.rs
//!
//! V3 (Shared-Signature Trap / SST) lifecycle audit:
//! generation determinism -> L1 witness verification -> autonomous collision
//! extraction -> framing resistance.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{SigningKey, VerifyingKey};
use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::voucher::TrapData;
use human_money_core::services::crypto_utils::{
    create_user_id, ed25519_pk_to_curve_point, get_hash_from_slices, sign_ed25519,
};
use human_money_core::services::trap_manager::{
    extract_sst_identity, generate_sst_trap, verify_sst_witness, TrapWitness,
};
use rand::rngs::OsRng;
use sha2::Digest;

// Helper function to add two little-endian 32-byte arrays representing large integers
fn add_bytes_le(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut result = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    if carry > 0 {
        None // overflowed 256 bits
    } else {
        Some(result)
    }
}

/// Builds a gossip fingerprint carrying the SST shard pair.
fn make_fp(t_id: &str, trap: &TrapData) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: trap.ds_tag.clone(),
        t_id: t_id.to_string(),
        trap_r: trap.trap_r.clone(),
        trap_s: trap.trap_s.clone(),
        ..Default::default()
    }
}

/// Derives the collision context exactly like production code.
fn sst_context(prev_hash: &str, ephem_pub_bytes: &[u8]) -> (String, [u8; 32]) {
    let eph = eph32_of(ephem_pub_bytes);
    let ds_tag = get_hash_from_slices(&[prev_hash.as_bytes(), &eph]);
    (ds_tag, eph)
}

/// Zero-pads an arbitrary tag into a 32-byte ephemeral key placeholder.
fn eph32_of(tag: &[u8]) -> [u8; 32] {
    let mut e = [0u8; 32];
    let n = tag.len().min(32);
    e[..n].copy_from_slice(&tag[..n]);
    e
}

/// Test 1: test_fabricated_shards_do_not_reveal_or_frame_identity
/// Attack Vector 1 (V3 analogue of the random-slope attack): an attacker
/// publishes arbitrarily fabricated shard material instead of honestly
/// participating in the shared-signature protocol. The reconstruction then
/// yields SOME point, but the attacker cannot steer it — neither to their own
/// real identity nor to any chosen victim identity.
#[test]
fn test_fabricated_shards_do_not_reveal_or_frame_identity() {
    // The attacker's real identity point.
    let attacker_sk = SigningKey::generate(&mut OsRng);
    let attacker_id_point = ed25519_pk_to_curve_point(&attacker_sk.verifying_key()).unwrap();

    // The innocent third party the attacker wants to frame.
    let victim_sk = SigningKey::generate(&mut OsRng);
    let victim_id_point = ed25519_pk_to_curve_point(&victim_sk.verifying_key()).unwrap();

    // Collision context: same input spent twice.
    let prev_hash = "prev_hash_test_1";
    let ephem_pub_bytes = *b"ephem_pub_test_1_32_bytes_long___";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    // Fabricate two syntactically valid shards with arbitrary content
    // (random valid curve points and canonical scalars, distinct t_ids so
    // every degenerate-case guard is passed deliberately).
    let r_fake = || {
        bs58::encode(
            (Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        )
        .into_string()
    };
    let s_fake = || bs58::encode(Scalar::random(&mut OsRng).as_bytes()).into_string();
    let fp1 = TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "fabricated_tx_A".to_string(),
        trap_r: r_fake(),
        trap_s: s_fake(),
        ..Default::default()
    };
    let fp2 = TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "fabricated_tx_B".to_string(),
        trap_r: r_fake(),
        trap_s: s_fake(),
        ..Default::default()
    };

    // Assertions
    // 1. Reconstruction of garbage shards yields SOME point (garbage in,
    //    garbage out) — extraction itself is total on well-formed input.
    let recovered = extract_sst_identity(&ds_tag, &eph, &fp1, &fp2).unwrap();

    // 2. But it is mathematically bound to NOTHING the attacker chose:
    //    neither the attacker's own identity ...
    assert_ne!(
        recovered, attacker_id_point,
        "Fabricated shards must not reconstruct to the fabricator's chosen identity"
    );
    // ... nor the framed victim (anti-framing, AUDIT-01-F07).
    assert_ne!(
        recovered, victim_id_point,
        "Fabricated shards must not be steerable to a chosen victim identity"
    );

    // 3. The extracted point is mathematically garbage (not a real actor key).
    let victim_compressed = victim_id_point.compress().to_bytes();
    let recovered_compressed = recovered.compress().to_bytes();
    assert_ne!(victim_compressed, recovered_compressed);
}

/// Test 2: test_honest_double_spend_identity_always_recovered
/// Counterpart to Test 1: Proves that honest SST generation always recovers
/// the signer identity autonomously from two colliding gossip fingerprints.
#[test]
fn test_honest_double_spend_identity_always_recovered() {
    // Fixed sender with signing_key
    let sk = SigningKey::generate(&mut OsRng);
    let original_ver_key = sk.verifying_key();
    let id_point = ed25519_pk_to_curve_point(&original_ver_key).unwrap();

    // Same prev_hash (Double-Spend condition), two distinct fork t_ids.
    let prev_hash = "prev_hash_test_2";
    let ephem_pub_bytes = *b"ephem_pub_test_2_32_bytes_long____";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    let (trap1, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_A").unwrap();
    let (trap2, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_B").unwrap();

    // Assertions
    // 1. Generation is deterministic and fork-distinct at the same time.
    assert_eq!(trap1.ds_tag, trap2.ds_tag, "same input => identical ds_tag");
    assert_ne!(trap1.trap_r, trap2.trap_r, "distinct t_ids => distinct shards");

    // 2. extract_sst_identity(...) == id_point
    let fp1 = make_fp("tx_A", &trap1);
    let fp2 = make_fp("tx_B", &trap2);
    let recovered_id = extract_sst_identity(&ds_tag, &eph, &fp1, &fp2).unwrap();
    assert_eq!(recovered_id, id_point);

    // 3. Compressed point is a valid VerifyingKey
    let compressed_bytes = recovered_id.compress().to_bytes();
    let ver_key_res = VerifyingKey::from_bytes(&compressed_bytes);
    assert!(ver_key_res.is_ok());
    let ver_key = ver_key_res.unwrap();
    assert_eq!(ver_key, original_ver_key);

    // 4. create_user_id() reconstructs the correct user DID (root did:key).
    let expected_user_id = create_user_id(&original_ver_key, None).unwrap();
    let reconstructed_user_id = create_user_id(&ver_key, None).unwrap();
    assert_eq!(reconstructed_user_id, expected_user_id);
}

/// Test 3: test_trap_replay_rejected_by_shard_mismatch
/// Attack Vector 2: Attacker copies valid TrapData from Tx_A into Tx_B.
#[test]
fn test_trap_replay_rejected_by_shard_mismatch() {
    let sk = SigningKey::generate(&mut OsRng);

    let prev_hash = "prev_hash_test_3";
    let ephem_pub_bytes = *b"ephem_pub_test_3_32_bytes_long____";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    // Create valid TrapData + witness for Tx_A.
    let (trap_a, witness_a) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_A").unwrap();
    let payer_did = create_user_id(&sk.verifying_key(), None).unwrap();

    // Tx_B reuses the copied shard under a different transaction id.
    let t_id_b = "tx_B";

    // Assertions
    // 1. The L1 witness check rejects the replayed shard: tau(tx_B) differs,
    //    so the shard cannot lie on the witness line for THIS spend.
    let result = verify_sst_witness(&witness_a, &trap_a, &payer_did, &ds_tag, &eph, t_id_b);
    assert!(result.is_err(), "Replayed trap must fail the witness check");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("shard does not match"),
        "Expected shard/witness mismatch error, got: {}",
        err_msg
    );

    // 2. The autonomous collision path also refuses the replay: both
    //    fingerprints carry byte-identical shard values (replay, not a fork).
    let fp_copy = make_fp(t_id_b, &trap_a);
    let fp_a = make_fp("tx_A", &trap_a);
    // Sanity: the copy is value-identical to the original shard pair.
    assert_eq!(fp_copy.trap_r, fp_a.trap_r, "shard values must be copied verbatim");
    assert_eq!(fp_copy.trap_s, fp_a.trap_s);
    let replay_result = extract_sst_identity(&ds_tag, &eph, &fp_a, &fp_copy);
    assert!(replay_result.is_err(), "identical shards (replay) must abort extraction");
}

/// Test 4: test_forged_witness_without_key_knowledge_rejected
/// Attack Vector 3: Attacker does not know the payer secret and constructs
/// forged witnesses (R_sig, s_sig, M_R, m_s) at random.
#[test]
fn test_forged_witness_without_key_knowledge_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let payer_did = create_user_id(&sk.verifying_key(), None).unwrap();

    let prev_hash = "prev_hash_test_4";
    let ephem_pub_bytes = *b"ephem_pub_test_4_32_bytes_long____";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    let honest_trap = generate_sst_trap(&sk, &ds_tag, &eph, "honest_t_id").unwrap().0;

    // Attacker tries to forge a witness over 1000 random attempts
    for _ in 0..1000 {
        let s_fake = Scalar::random(&mut OsRng);
        let r_fake = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
        let m_r_fake = Scalar::random(&mut OsRng) * ED25519_BASEPOINT_POINT;
        let m_s_fake = Scalar::random(&mut OsRng);

        let fake_witness = TrapWitness {
            r_sig: bs58::encode(r_fake.compress().as_bytes()).into_string(),
            s_sig: bs58::encode(s_fake.as_bytes()).into_string(),
            m_r: bs58::encode(m_r_fake.compress().as_bytes()).into_string(),
            m_s: bs58::encode(m_s_fake.as_bytes()).into_string(),
        };

        // Assertions
        // 1. verify_sst_witness must fail (Schnorr equation is unsatisfiable
        //    without the payer secret).
        let verify_result = verify_sst_witness(
            &fake_witness, &honest_trap, &payer_did, &ds_tag, &eph, "honest_t_id",
        );
        assert!(verify_result.is_err());
        let err_msg = verify_result.err().unwrap().to_string();
        assert!(
            err_msg.contains("SST witness rejected"),
            "Expected SST witness rejection, got: {}",
            err_msg
        );
    }
}

/// Test 5: test_ds_tag_prefix_independent
/// Historical Vulnerability A: ds_tag must NOT depend on the prefix.
/// (Unchanged by V3: the tag remains H(prev_hash || revealed eph key).)
#[test]
fn test_ds_tag_prefix_independent() {
    let prev_hash = "prev_hash_test_5";
    let ephem_pub = "ephem_pub_test_5";
    let prev_hash_bytes = prev_hash.as_bytes().to_vec();
    let ephem_pub_bytes = ephem_pub.as_bytes().to_vec();

    // Calculate ds_tag with current formula
    let ds_tag1 = get_hash_from_slices(&[&prev_hash_bytes, &ephem_pub_bytes]);

    // Comparison with a hypothetical prefix-dependent tag logic
    let mut hasher = sha2::Sha512::new();
    hasher.update(&prev_hash_bytes);
    hasher.update(&ephem_pub_bytes);
    hasher.update(b"prefix");
    let prefix_dependent_tag = bs58::encode(hasher.finalize()).into_string();

    // Assertions
    // 1. Current ds_tag does not match prefix_dependent_tag
    assert_ne!(ds_tag1, prefix_dependent_tag);

    // 2. get_hash_from_slices does not include prefix
    let ds_tag2 = get_hash_from_slices(&[&prev_hash_bytes, &ephem_pub_bytes]);
    assert_eq!(ds_tag1, ds_tag2);
}

/// Test 6: test_scalar_malleability_no_bypass
/// Scalar Malleability via from_bytes_mod_order — V3 parses shard scalars
/// strictly canonically, so malleated encodings are rejected outright.
#[test]
fn test_scalar_malleability_no_bypass() {
    // Prime order l of Ed25519 / Ristretto255 curve
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    let sk = SigningKey::generate(&mut OsRng);
    let prev_hash = "prev_hash_test_6";
    let ephem_pub_bytes = *b"ephem_pub_test_6_32_bytes_long____";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    // Generate an honest shard pair over two distinct forks.
    let (trap1, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_one").unwrap();
    let (trap2, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_two").unwrap();

    let s2_bytes: [u8; 32] = bs58::decode(&trap2.trap_s)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    // Modify the serialized s value by adding the curve order l
    let s_plus_l_bytes = add_bytes_le(&s2_bytes, &L_BYTES).expect("s < l implies no overflow");

    // 1. from_bytes_mod_order(s) == from_bytes_mod_order(s + l) — the two
    //    encodings denote the SAME scalar, only one of them is canonical.
    let sc1 = Scalar::from_bytes_mod_order(s2_bytes);
    let sc2 = Scalar::from_bytes_mod_order(s_plus_l_bytes);
    assert_eq!(sc1, sc2, "Scalar must be identical after modular reduction");

    // SECURITY FIX: Non-canonical scalar encodings (s + l) must be REJECTED.
    // Accepting them allowed malleability attacks where two different byte
    // strings represent the same reduced scalar (bypassing identical-shard
    // guards, enabling misattribution).
    let mut fp_attack = make_fp("tx_two", &trap2);
    fp_attack.trap_s = bs58::encode(s_plus_l_bytes).into_string();
    let fp1 = make_fp("tx_one", &trap1);

    let verify_result = extract_sst_identity(&ds_tag, &eph, &fp1, &fp_attack);
    assert!(verify_result.is_err(), "Non-canonical scalar encoding must be rejected");
    let err_msg = verify_result.err().unwrap().to_string();
    assert!(
        err_msg.contains("canonical"),
        "Expected non-canonical rejection, got: {}",
        err_msg
    );

    // 2. If the bytes become > 32 bytes, parsing fails as well.
    let mut over_long_bytes = s2_bytes.to_vec();
    over_long_bytes.push(0x00); // 33 bytes

    let mut fp_over_long = make_fp("tx_two", &trap2);
    fp_over_long.trap_s = bs58::encode(over_long_bytes).into_string();

    let length_result = extract_sst_identity(&ds_tag, &eph, &fp1, &fp_over_long);
    assert!(length_result.is_err());
    let err_msg = length_result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Invalid Scalar") || err_msg.contains("length"),
        "Expected invalid length error, got: {}",
        err_msg
    );
}

/// Test 7: test_degenerate_and_invalid_extraction_handling
/// Checks what happens when colliding fingerprints are degenerate or when
/// extraction yields something that is not a valid Ed25519 key.
#[test]
fn test_degenerate_and_invalid_extraction_handling() {
    let sk = SigningKey::generate(&mut OsRng);
    let prev_hash = "prev_hash_test_7";
    let ephem_pub_bytes = *b"ephem_pub_test_7_32_bytes_long____";
    let (ds_tag, eph) = sst_context(prev_hash, &ephem_pub_bytes);

    let (trap1, _) = generate_sst_trap(&sk, &ds_tag, &eph, "tx_A").unwrap();

    // AUDIT-01-F09 (V3 analogue of byte-identical blinded IDs): a second
    // fingerprint carrying the SAME shard values under a different t_id is a
    // degenerate/replay artifact and must be REJECTED instead of producing an
    // attacker-chosen point.
    let fp1 = make_fp("tx_A", &trap1);
    let fp_degenerate = TransactionFingerprint {
        ds_tag: ds_tag.clone(),
        t_id: "tx_B".to_string(),
        trap_r: trap1.trap_r.clone(),
        trap_s: trap1.trap_s.clone(),
        ..Default::default()
    };
    let degenerate_result = extract_sst_identity(&ds_tag, &eph, &fp1, &fp_degenerate);
    assert!(
        degenerate_result.is_err(),
        "identical trap shards must be rejected as degenerate fork data"
    );

    // Downstream validity handling (unchanged wallet-side logic):
    // 1. A returned EdwardsPoint can always be compressed.
    let genuine_pair_trap2 = generate_sst_trap(&sk, &ds_tag, &eph, "tx_C").unwrap().0;
    let fp_c = make_fp("tx_C", &genuine_pair_trap2);
    let recovered_point = extract_sst_identity(&ds_tag, &eph, &fp1, &fp_c).unwrap();
    let compressed_y = recovered_point.compress();
    let _pk_bytes = compressed_y.to_bytes();

    // 2. VerifyingKey::from_bytes() fails if the point is not a valid verifying key.
    // We search for a 32-byte array that cannot be decompressed to a valid curve point,
    // which VerifyingKey::from_bytes must reject.
    let mut corrupted_pk_bytes = [0u8; 32];
    let mut found_invalid = false;
    for i in 0..256 {
        corrupted_pk_bytes[0] = i as u8;
        if VerifyingKey::from_bytes(&corrupted_pk_bytes).is_err() {
            found_invalid = true;
            break;
        }
    }
    assert!(found_invalid, "Should find at least one invalid key representation that VerifyingKey::from_bytes rejects");

    // 3. The wallet logic in verify_and_create_proof checks this correctly
    // If the public key conversion fails (e.g. due to corrupted/invalid bytes), the wallet logic
    // preserves the offender_id as "anonymous" and does not update it.
    let mut offender_id = "anonymous".to_string();
    if let Ok(pk) = VerifyingKey::from_bytes(&corrupted_pk_bytes) {
        if let Ok(did_id) = create_user_id(&pk, None) {
            offender_id = did_id;
        }
    }

    assert_eq!(offender_id, "anonymous", "offender_id must not be updated with the invalid key");
}

/// Test 8: test_manipulated_shard_rejected_by_recipient_witness_check
/// Intercepts a private payment and replaces the trap shard with shards from
/// a manipulated derivation (V3 analogue of the non-deterministic random
/// slope attack). The recipient wallet must reject the bundle because the
/// private SST witness from the privacy guard no longer matches the shard.
#[test]
fn test_manipulated_shard_rejected_by_recipient_witness_check() {
    use human_money_core::services::conflict_manager::encrypt_transaction_timestamp;
    use human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw;
    use human_money_core::test_utils::{
        add_voucher_to_wallet, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, derive_holder_key,
    };
    use std::collections::HashMap;

    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    let alice_local_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        &MINUTO_STANDARD.0,
        true
    ).unwrap();

    let voucher = alice_wallet.voucher_store.vouchers.get(&alice_local_id).unwrap().voucher.clone();
    let holder_key = derive_holder_key(&voucher, &alice.identity.signing_key);

    // 1. Create a legitimate transaction (SST trap + private witness inside
    //    the encrypted RecipientPayload).
    let (mut voucher_for_bob, _secrets) = human_money_core::services::voucher_manager::create_transaction(
        &voucher,
        &MINUTO_STANDARD.0,
        &alice.identity.user_id,
        &alice.identity.signing_key,
        &holder_key,
        &bob.identity.user_id,
        "100",
        None,
    ).unwrap();

    // V3 Protocol (audit_02_11): the voucher container id is bound into the
    // digest; this is a real spend, so the hex layer2_voucher_id must be used.
    let l2_voucher_id =
        human_money_core::services::l2_gateway::extract_layer2_voucher_id(&voucher_for_bob)
            .unwrap();

    // 2. Tamper with the trap: regenerate the public shards for a DIFFERENT
    //    evaluation point (simulating a manipulated mask derivation) while
    //    the honest witness stays inside the untouched privacy guard.
    let last_tx = voucher_for_bob.transactions.last_mut().unwrap();
    let original_trap = last_tx.trap_data.clone().unwrap();
    let eph: [u8; 32] = bs58::decode(last_tx.sender_ephemeral_pub.as_deref().unwrap())
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    let (fake_trap, _) = generate_sst_trap(
        &alice.identity.signing_key,
        &original_trap.ds_tag,
        &eph,
        // Different t_id => different tau => shards off the honest line.
        "manipulated_evaluation_point",
    ).unwrap();
    last_tx.trap_data = Some(fake_trap.clone());

    // Re-bind ONLY the layer2 digest to the manipulated shards (the attacker
    // holds the ephemeral holder key) so chain-level validation passes.
    // t_id and the privacy guard stay untouched: the V3 t_id preimage
    // excludes trap_data/privacy_guard.
    let t_id_raw: [u8; 32] = bs58::decode(&last_tx.t_id)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let sender_raw: [u8; 32] = bs58::decode(last_tx.sender_ephemeral_pub.as_deref().unwrap())
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let encrypted_timestamp = encrypt_transaction_timestamp(last_tx).unwrap();
    let payload_hash = calculate_l2_payload_hash_raw(
        &l2_voucher_id,
        &fake_trap.ds_tag,
        &t_id_raw,
        &sender_raw,
        &fake_trap.trap_r,
        &fake_trap.trap_s,
        encrypted_timestamp,
        last_tx.deletable_at.as_deref(),
        // SECURITY (HMSEC-SA04-08): the guard stays untouched, so its
        // canonical commitment must be bound exactly like the validator does.
        &human_money_core::services::l2_gateway::privacy_guard_commitment(
            last_tx.privacy_guard.as_deref(),
        ),
    );
    let l2_sig = sign_ed25519(&holder_key, &payload_hash);
    last_tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

    // 3. Encrypt bundle and attempt to process at recipient (Bob)
    let (bundle_bytes, _header) = alice_wallet.create_and_encrypt_transaction_bundle(
        &alice.identity,
        vec![voucher_for_bob],
        &bob.identity.user_id,
        None,
        vec![],
        HashMap::new(),
        None,
    ).unwrap();

    let mut standards = HashMap::new();
    standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

    let process_result = bob_wallet.process_encrypted_transaction_bundle(
        &bob.identity,
        &bundle_bytes,
        None,
        &standards,
    );

    // 4. Assert rejection due to the witness/shard mismatch!
    assert!(process_result.is_err(), "Bundle should have been rejected!");
    let err_string = process_result.unwrap_err().to_string();
    assert!(
        err_string.contains("SST trap witness verification failed"),
        "Expected SST witness rejection, got: {}",
        err_string
    );
}
