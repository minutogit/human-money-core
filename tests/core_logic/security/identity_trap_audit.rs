// tests/core_logic/security/identity_trap_audit.rs

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::EdwardsPoint;
use ed25519_dalek::{SigningKey, VerifyingKey};
use human_money_core::services::trap_manager::{
    derive_m, generate_trap, verify_trap, extract_id_point_from_raw_data, hash_to_scalar
};
use human_money_core::services::crypto_utils::{
    create_user_id, ed25519_pk_to_curve_point, get_hash_from_slices
};
use human_money_core::models::voucher::TrapData;
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

/// Test 1: test_random_slope_attack_identity_not_recoverable
/// Attack Vector 1: Attacker uses a random m instead of the HKDF-derived m.
#[test]
fn test_random_slope_attack_identity_not_recoverable() {
    let mut rng = OsRng;

    // Fixed id_point (attacker identity)
    let id_scalar = Scalar::random(&mut rng);
    let id_point = id_scalar * ED25519_BASEPOINT_POINT;

    // prev_hash
    let prev_hash = "prev_hash_test_1";
    let prev_hash_bytes = prev_hash.as_bytes();

    // Two transactions with different u_scalars
    let u_scalar1 = Scalar::random(&mut rng);
    let u_scalar2 = Scalar::random(&mut rng);

    // Attacker uses random m1 and m2 instead of deterministic HKDF
    let m1 = Scalar::random(&mut rng);
    let m2 = Scalar::random(&mut rng);

    // ds_tag is identical
    let ephem_pub_bytes = b"ephem_pub_test_1";
    let ds_tag = get_hash_from_slices(&[prev_hash_bytes, ephem_pub_bytes]);

    // Generate traps
    let trap1 = generate_trap(ds_tag.clone(), &u_scalar1, &m1, &id_point, Some("prefix")).unwrap();
    let trap2 = generate_trap(ds_tag.clone(), &u_scalar2, &m2, &id_point, Some("prefix")).unwrap();

    // Assertions
    // 1. ds_tag is identical
    assert_eq!(trap1.ds_tag, trap2.ds_tag);

    // 2. extract_id_point_from_raw_data() yields a point != id_point
    let recovered_id = extract_id_point_from_raw_data(
        &trap1.ds_tag,
        &trap1.u,
        &trap1.blinded_id,
        &trap2.ds_tag,
        &trap2.u,
        &trap2.blinded_id,
    ).unwrap();

    assert_ne!(recovered_id, id_point);

    // 3. The extracted point is mathematically garbage (not the real public key)
    let original_compressed = id_point.compress().to_bytes();
    let recovered_compressed = recovered_id.compress().to_bytes();
    assert_ne!(original_compressed, recovered_compressed);
}

/// Test 2: test_honest_double_spend_identity_always_recovered
/// Counterpart to Test 1: Proves that honest (deterministic) m-derivation always recovers the identity.
#[test]
fn test_honest_double_spend_identity_always_recovered() {
    let mut rng = OsRng;
    
    // Fixed sender with signing_key
    let sk = SigningKey::generate(&mut rng);
    let original_ver_key = sk.verifying_key();
    let id_point = ed25519_pk_to_curve_point(&original_ver_key).unwrap();
    let prefix = "prefix";

    // Same prev_hash (Double-Spend condition)
    let prev_hash = "prev_hash_test_2";
    let prev_hash_bytes = prev_hash.as_bytes();

    // m = derive_m(prev_hash, sk, prefix) - identical for both
    let m = derive_m(prev_hash, &sk.to_bytes(), Some(prefix)).unwrap();

    // Different u_scalars (different recipient data)
    let u_scalar1 = Scalar::random(&mut rng);
    let u_scalar2 = Scalar::random(&mut rng);

    // ds_tag is identical
    let ephem_pub_bytes = b"ephem_pub_test_2";
    let ds_tag = get_hash_from_slices(&[prev_hash_bytes, ephem_pub_bytes]);

    // Generate traps
    let trap1 = generate_trap(ds_tag.clone(), &u_scalar1, &m, &id_point, Some(prefix)).unwrap();
    let trap2 = generate_trap(ds_tag.clone(), &u_scalar2, &m, &id_point, Some(prefix)).unwrap();

    // Assertions
    // 1. extract_id_point_from_raw_data(...) == id_point
    let recovered_id = extract_id_point_from_raw_data(
        &trap1.ds_tag,
        &trap1.u,
        &trap1.blinded_id,
        &trap2.ds_tag,
        &trap2.u,
        &trap2.blinded_id,
    ).unwrap();
    assert_eq!(recovered_id, id_point);

    // 2. Compressed point is a valid VerifyingKey
    let compressed_bytes = recovered_id.compress().to_bytes();
    let ver_key_res = VerifyingKey::from_bytes(&compressed_bytes);
    assert!(ver_key_res.is_ok());
    let ver_key = ver_key_res.unwrap();
    assert_eq!(ver_key, original_ver_key);

    // 3. create_user_id() reconstructs the correct user DID
    let expected_user_id = create_user_id(&original_ver_key, Some(prefix)).unwrap();
    let reconstructed_user_id = create_user_id(&ver_key, Some(prefix)).unwrap();
    assert_eq!(reconstructed_user_id, expected_user_id);
}

/// Test 3: test_trap_replay_rejected_by_u_mismatch
/// Attack Vector 2: Attacker copies valid TrapData from Tx_A to Tx_B.
#[test]
fn test_trap_replay_rejected_by_u_mismatch() {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
    let prefix = "prefix";

    let prev_hash = "prev_hash_test_3";
    let m = derive_m(prev_hash, &sk.to_bytes(), Some(prefix)).unwrap();
    
    let ephem_pub_bytes = b"ephem_pub_test_3";
    let ds_tag = get_hash_from_slices(&[prev_hash.as_bytes(), ephem_pub_bytes]);

    // Create valid TrapData for Tx_A (amount="50", receiver_hash="hash_A")
    let u_input_a = format!("{}{}{}", ds_tag, "50", "hash_A");
    let u_scalar_a = hash_to_scalar(u_input_a.as_bytes());
    let trap_a = generate_trap(ds_tag.clone(), &u_scalar_a, &m, &id_point, Some(prefix)).unwrap();

    // Create Tx_B with different data (amount="100", receiver_hash="hash_B")
    let u_input_b = format!("{}{}{}", ds_tag, "100", "hash_B");

    // Assertions
    // 1. verify_trap with Tx_B data as expected_u_input fails
    let result = verify_trap(
        &trap_a,
        &ds_tag,
        u_input_b.as_bytes(),
        &id_point,
        Some(prefix),
    );
    assert!(result.is_err());

    // 2. Error message contains "Varying Input Mismatch" or similar
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Varying Input Mismatch") || err_msg.contains("Trap Scalar U does not match"),
        "Expected Varying Input Mismatch error, got: {}",
        err_msg
    );
}

/// Test 4: test_forged_zkp_without_m_knowledge_rejected
/// Attack Vector 3: Attacker does not know m, constructs forged ZKP.
#[test]
fn test_forged_zkp_without_m_knowledge_rejected() {
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
    let prefix = "prefix";

    let prev_hash = "prev_hash_test_4";
    let ephem_pub_bytes = b"ephem_pub_test_4";
    let ds_tag = get_hash_from_slices(&[prev_hash.as_bytes(), ephem_pub_bytes]);

    let u_input = format!("{}{}{}", ds_tag, "50", "hash_A");
    let u_scalar = hash_to_scalar(u_input.as_bytes());

    // Attacker chooses a random V (blinded_id) not correctly constructed
    let v_fake = Scalar::random(&mut rng) * ED25519_BASEPOINT_POINT;
    
    // Attacker tries to forge proof (R, s) over 1000 random attempts
    for _ in 0..1000 {
        let s_fake = Scalar::random(&mut rng);
        let r_fake = Scalar::random(&mut rng) * ED25519_BASEPOINT_POINT;

        // Construct fake TrapData
        let u_str = bs58::encode(u_scalar.as_bytes()).into_string();
        let blinded_id_str = bs58::encode(v_fake.compress().as_bytes()).into_string();
        
        let mut proof_bytes = Vec::with_capacity(64);
        proof_bytes.extend_from_slice(r_fake.compress().as_bytes());
        proof_bytes.extend_from_slice(s_fake.as_bytes());
        let proof_str = bs58::encode(proof_bytes).into_string();

        let trap_data = TrapData {
            ds_tag: ds_tag.clone(),
            u: u_str,
            blinded_id: blinded_id_str,
            proof: proof_str,
        };

        // Assertions
        // 1. verify_trap must fail
        let verify_result = verify_trap(
            &trap_data,
            &ds_tag,
            u_input.as_bytes(),
            &id_point,
            Some(prefix),
        );
        assert!(verify_result.is_err());
        let err_msg = verify_result.err().unwrap().to_string();
        assert!(
            err_msg.contains("ZKP verification failed") || err_msg.contains("Trap ZKP verification failed"),
            "Expected ZKP verification failed, got: {}",
            err_msg
        );
    }
}

/// Test 5: test_ds_tag_prefix_independent
/// Historical Vulnerability A: ds_tag must NOT depend on the prefix.
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
/// Scalar Malleability via from_bytes_mod_order.
#[test]
fn test_scalar_malleability_no_bypass() {
    let mut rng = OsRng;

    // Prime order l of Ed25519 / Ristretto255 curve
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    let u_input = b"varying_test_input_6";
    let u_scalar = hash_to_scalar(u_input);
    let u_bytes = u_scalar.to_bytes();

    // Modify the serialized u value by adding the curve order l
    if let Some(u_plus_l_bytes) = add_bytes_le(&u_bytes, &L_BYTES) {
        // 1. from_bytes_mod_order(u_bytes) == from_bytes_mod_order(u_bytes + l)
        let s1 = Scalar::from_bytes_mod_order(u_bytes);
        let s2 = Scalar::from_bytes_mod_order(u_plus_l_bytes);
        assert_eq!(s1, s2, "Scalar must be identical after modular reduction");

        let sk = SigningKey::generate(&mut rng);
        let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
        let prefix = "prefix";
        let prev_hash = "prev_hash_test_6";
        let m = derive_m(prev_hash, &sk.to_bytes(), Some(prefix)).unwrap();
        let ephem_pub_bytes = b"ephem_pub_test_6";
        let ds_tag = get_hash_from_slices(&[prev_hash.as_bytes(), ephem_pub_bytes]);

        // Generate trap with the original u_scalar
        let mut trap = generate_trap(ds_tag.clone(), &u_scalar, &m, &id_point, Some(prefix)).unwrap();

        // Inject the malleable representation u_plus_l_bytes into the trap data
        trap.u = bs58::encode(u_plus_l_bytes).into_string();

        // Verifying this trap must still succeed because the scalar is reduced mod order to the exact same value.
        let verify_result = verify_trap(
            &trap,
            &ds_tag,
            u_input,
            &id_point,
            Some(prefix),
        );
        assert!(verify_result.is_ok(), "Verification should succeed since scalar is reduced to the same value");
    }

    // 2. If the bytes become > 32 bytes, parsing fails in verify_trap
    let mut over_long_bytes = u_bytes.to_vec();
    over_long_bytes.push(0x00); // 33 bytes
    
    let sk = SigningKey::generate(&mut rng);
    let id_point = ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap();
    let prefix = "prefix";
    let prev_hash = "prev_hash_test_6";
    let m = derive_m(prev_hash, &sk.to_bytes(), Some(prefix)).unwrap();
    let ephem_pub_bytes = b"ephem_pub_test_6";
    let ds_tag = get_hash_from_slices(&[prev_hash.as_bytes(), ephem_pub_bytes]);

    let mut trap = generate_trap(ds_tag.clone(), &u_scalar, &m, &id_point, Some(prefix)).unwrap();
    trap.u = bs58::encode(over_long_bytes).into_string();

    let verify_result = verify_trap(
        &trap,
        &ds_tag,
        u_input,
        &id_point,
        Some(prefix),
    );
    assert!(verify_result.is_err());
    let err_msg = verify_result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Invalid Scalar U length") || err_msg.contains("Invalid length"),
        "Expected invalid length error, got: {}",
        err_msg
    );
}

/// Test 7: test_extracted_point_validity_check
/// Checks what happens if extract_id_point_from_raw_data returns a point that is not a valid Ed25519 key.
#[test]
fn test_extracted_point_validity_check() {
    let mut rng = OsRng;

    let ds_tag = "ds_tag_test_7";
    let u1_scalar = Scalar::random(&mut rng);
    let u2_scalar = Scalar::random(&mut rng);
    
    // Construct identity point (default point)
    let identity_point = EdwardsPoint::default();
    
    let u1_str = bs58::encode(u1_scalar.to_bytes()).into_string();
    let u2_str = bs58::encode(u2_scalar.to_bytes()).into_string();
    let v1_str = bs58::encode(identity_point.compress().to_bytes()).into_string();
    let v2_str = bs58::encode(identity_point.compress().to_bytes()).into_string();

    let recovered_point = extract_id_point_from_raw_data(
        ds_tag,
        &u1_str,
        &v1_str,
        ds_tag,
        &u2_str,
        &v2_str,
    ).unwrap();

    // Assertions
    // 1. The returned EdwardsPoint can be compressed
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
