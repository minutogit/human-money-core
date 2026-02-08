use human_money_core::models::voucher::TrapData;
use human_money_core::services::trap_manager;
use human_money_core::services::crypto_utils;
use human_money_core::test_utils::{ACTORS, TestUser};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

// Helper to simulate a mathematical trap setup
fn setup_trap_data(
    prev_hash: &str,
    sender: &TestUser,
    t_id: &str,
) -> TrapData {
    // 1. Calculate Constant DS-Tag (Input based)
    let (_ephemeral_secret, ephemeral_pub) = crypto_utils::derive_ephemeral_key_pair(
        &sender.signing_key,
        prev_hash.as_bytes(),
        "test_ephemeral_gen",
        None,
    ).unwrap();
    let sender_ephemeral_pub_b58 = bs58::encode(ephemeral_pub.as_bytes()).into_string();

    let ds_tag_input = format!(
        "{}{}{}",
        prev_hash,
        sender_ephemeral_pub_b58,
        "prefix"
    );
    let ds_tag = crypto_utils::get_hash(ds_tag_input);

    // 2. Calculate Varying U (Output based) -> SCALAR now!
    let u_input_varying = format!("{}{}", ds_tag, t_id); 
    let u_scalar = trap_manager::hash_to_scalar(u_input_varying.as_bytes());
    
    // m derivation (Constant for same input)
    let m = trap_manager::derive_m(prev_hash, &sender.signing_key.to_bytes(), "prefix").unwrap();
    
    let my_id_point = crypto_utils::ed25519_pk_to_curve_point(&sender.public_key).unwrap();
    
    trap_manager::generate_trap(ds_tag, &u_scalar, &m, &my_id_point, "prefix").unwrap()
}

#[test]
fn test_identity_recovery_from_conflicting_fingerprints() {
    let alice = &ACTORS.alice;
    let prev_hash = "prev_hash_123";
    
    // 1. Transaction A (Alice -> Bob)
    let trap_a = setup_trap_data(prev_hash, alice, "tx_id_A");
    
    // 2. Transaction B (Alice -> Charlie)
    let trap_b = setup_trap_data(prev_hash, alice, "tx_id_B");
    
    // Verify Double Spend Condition
    assert_eq!(trap_a.ds_tag, trap_b.ds_tag, "DS Tags must match");
    assert_ne!(trap_a.u, trap_b.u, "U (Scalars) must differ");
    
    // --- IDENTITY RECOVERY LOGIC ---
    // The goal: Recover Alice's Public Key (ID) from just the two Traps.
    
    // 1. Decode Values
    let u_a_bytes = bs58::decode(&trap_a.u).into_vec().unwrap();
    let u_b_bytes = bs58::decode(&trap_b.u).into_vec().unwrap();
    let v_a_bytes = bs58::decode(&trap_a.blinded_id).into_vec().unwrap();
    let v_b_bytes = bs58::decode(&trap_b.blinded_id).into_vec().unwrap();
    
    let u_a = Scalar::from_bytes_mod_order(u_a_bytes.try_into().unwrap());
    let u_b = Scalar::from_bytes_mod_order(u_b_bytes.try_into().unwrap());
    
    let v_a = CompressedEdwardsY::from_slice(&v_a_bytes).unwrap().decompress().unwrap();
    let v_b = CompressedEdwardsY::from_slice(&v_b_bytes).unwrap().decompress().unwrap();
    
    // 2. Calculate Deltas
    // Delta V = V_a - V_b
    let delta_v = v_a - v_b;
    
    // Delta U = u_a - u_b
    let delta_u = u_a - u_b;
    
    // 3. Recover Slope Point M
    // V = u * M + ID
    // V_a - V_b = (u_a - u_b) * M
    // M = Delta V * (Delta U)^-1
    let delta_u_inv = delta_u.invert();
    let m_point = delta_v * delta_u_inv;
    
    // 4. Recover Identity ID
    // ID = V_a - u_a * M
    let recovered_id_point = v_a - (m_point * u_a);
    
    // 5. Verify against Alice's actual ID
    let alice_id_point = crypto_utils::ed25519_pk_to_curve_point(&alice.public_key).unwrap();
    
    assert_eq!(recovered_id_point, alice_id_point, "Recovered Identity Point must match Alice's Public Key Point!");
    
    println!("SUCCESS: Identity of Double Spender recovered mathematically!");
}
