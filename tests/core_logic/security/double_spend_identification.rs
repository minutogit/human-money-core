use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::voucher::TrapData;
use human_money_core::services::crypto_utils;
use human_money_core::services::trap_manager::{self, generate_sst_trap};
use human_money_core::test_utils::{ACTORS, TestUser};

// Helper to simulate a mathematical trap setup (V3 / Shared-Signature Trap).
// Returns the public shard pair plus the revealed ephemeral key bytes needed
// as collision context for autonomous identity extraction.
fn setup_trap_data(prev_hash: &str, sender: &TestUser, t_id: &str) -> (TrapData, [u8; 32]) {
    // 1. Calculate Constant DS-Tag (Input based)
    let (_ephemeral_secret, ephemeral_pub) = crypto_utils::derive_ephemeral_key_pair(
        &sender.signing_key,
        prev_hash.as_bytes(),
        "test_ephemeral_gen",
        None,
    )
    .unwrap();
    let eph32: [u8; 32] = *ephemeral_pub.as_bytes();

    let ds_tag = crypto_utils::get_hash_from_slices(&[prev_hash.as_bytes(), &eph32]);

    // 2. Generate the SST shard pair for this fork. The shards are bound to
    //    tau(t_id), so distinct forks of the same input yield distinct shards
    //    on one shared-signature line.
    let (trap, _) = generate_sst_trap(&sender.signing_key, &ds_tag, &eph32, t_id).unwrap();
    (trap, eph32)
}

#[test]
fn test_sst_identity_recovery_from_conflicting_fingerprints() {
    let alice = &ACTORS.alice;
    let prev_hash = "prev_hash_123";

    // 1. Transaction A (Alice -> Bob)
    let (trap_a, eph) = setup_trap_data(prev_hash, alice, "tx_id_A");

    // 2. Transaction B (Alice -> Charlie)
    let (trap_b, _) = setup_trap_data(prev_hash, alice, "tx_id_B");

    // Verify Double Spend Condition
    assert_eq!(trap_a.ds_tag, trap_b.ds_tag, "DS Tags must match");
    assert_ne!(trap_a.trap_r, trap_b.trap_r, "Shards must differ across forks");

    // --- IDENTITY RECOVERY LOGIC ---
    // The goal: Recover Alice's Public Key (ID) from just the two gossip
    // fingerprints (ds_tag, t_id, trap_r, trap_s).

    let fp_a = TransactionFingerprint {
        ds_tag: trap_a.ds_tag.clone(),
        t_id: "tx_id_A".to_string(),
        trap_r: trap_a.trap_r.clone(),
        trap_s: trap_a.trap_s.clone(),
        ..Default::default()
    };
    let fp_b = TransactionFingerprint {
        ds_tag: trap_b.ds_tag.clone(),
        t_id: "tx_id_B".to_string(),
        trap_r: trap_b.trap_r.clone(),
        trap_s: trap_b.trap_s.clone(),
        ..Default::default()
    };

    // Autonomous reconstruction: the two colliding shards determine the
    // masking values by linear interpolation and unmask the underlying
    // Schnorr signature, whose challenge binds it to exactly one key.
    let recovered_id_point =
        trap_manager::extract_sst_identity(&fp_a.ds_tag, &eph, &fp_a, &fp_b).unwrap();

    // Verify against Alice's actual ID
    let alice_id_point = crypto_utils::ed25519_pk_to_curve_point(&alice.public_key).unwrap();

    assert_eq!(
        recovered_id_point, alice_id_point,
        "Recovered Identity Point must match Alice's Public Key Point!"
    );

    println!("SUCCESS: Identity of Double Spender recovered mathematically!");
}
