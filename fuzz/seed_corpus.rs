use human_money_core::models::conflict::{ProofOfDoubleSpend, TransactionFingerprint};
use human_money_core::models::secure_container::{
    ContainerConfig, PayloadType, PrivacyMode, SecureContainer,
};
use human_money_core::services::bundle_processor::create_and_encrypt_bundle;
use human_money_core::test_utils::{setup_voucher_with_one_tx, ACTORS};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_dir = Path::new("fuzz/corpus");

    // 1. Corpus for fuzz_secure_container
    let c1_dir = base_dir.join("fuzz_secure_container");
    fs::create_dir_all(&c1_dir)?;

    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;

    // Asymmetric trial decryption
    let c_asym = SecureContainer::seal(
        alice,
        &ContainerConfig::TargetDid(bob.user_id.clone(), PrivacyMode::TrialDecryption),
        b"{\"test\": \"payload_data\"}",
        PayloadType::Generic("test".into()),
    )?;
    fs::write(c1_dir.join("seed_asym_trial.json"), serde_json::to_vec_pretty(&c_asym)?)?;

    // Asymmetric hashed routing
    let c_hashed = SecureContainer::seal(
        alice,
        &ContainerConfig::TargetDid(bob.user_id.clone(), PrivacyMode::HashedRouting),
        b"{\"test\": \"payload_hashed\"}",
        PayloadType::Generic("test".into()),
    )?;
    fs::write(c1_dir.join("seed_asym_hashed.json"), serde_json::to_vec_pretty(&c_hashed)?)?;

    // Symmetric password
    let c_sym = SecureContainer::seal(
        alice,
        &ContainerConfig::Password("correct_password".into()),
        b"{\"test\": \"payload_sym\"}",
        PayloadType::Generic("test".into()),
    )?;
    fs::write(c1_dir.join("seed_sym.json"), serde_json::to_vec_pretty(&c_sym)?)?;

    // Cleartext
    let c_clear = SecureContainer::seal(
        alice,
        &ContainerConfig::Cleartext,
        b"{\"test\": \"payload_clear\"}",
        PayloadType::Generic("test".into()),
    )?;
    fs::write(c1_dir.join("seed_clear.json"), serde_json::to_vec_pretty(&c_clear)?)?;

    // 2. Corpus for fuzz_bundle_ingress
    let c2_dir = base_dir.join("fuzz_bundle_ingress");
    fs::create_dir_all(&c2_dir)?;

    let (_, _, _, _, voucher, _) = setup_voucher_with_one_tx();
    let (bundle_bytes, bundle_obj) = create_and_encrypt_bundle(
        alice,
        vec![voucher.clone()],
        &bob.user_id,
        Some("fuzzing seed transaction note".into()),
        vec![],
        HashMap::new(),
        Some("Alice".into()),
    )?;
    fs::write(c2_dir.join("seed_sealed_bundle.bin"), &bundle_bytes)?;
    fs::write(c2_dir.join("seed_bundle_raw.json"), serde_json::to_vec_pretty(&bundle_obj)?)?;

    // 3. Corpus for fuzz_voucher_and_standard_parser
    let c3_dir = base_dir.join("fuzz_voucher_and_standard_parser");
    fs::create_dir_all(&c3_dir)?;

    // Standard TOMLs from disk
    if let Ok(freetaler) = fs::read_to_string("voucher_standards/freetaler_v1/standard.toml") {
        fs::write(c3_dir.join("seed_freetaler.toml"), freetaler)?;
    }
    if let Ok(minuto) = fs::read_to_string("voucher_standards/minuto_v1/standard.toml") {
        fs::write(c3_dir.join("seed_minuto.toml"), minuto)?;
    }
    if let Ok(tpl) = fs::read_to_string("voucher_standards/standard_template.toml") {
        fs::write(c3_dir.join("seed_template.toml"), tpl)?;
    }

    // Voucher JSON
    let voucher_json = serde_json::to_vec_pretty(&voucher)?;
    fs::write(c3_dir.join("seed_voucher.json"), &voucher_json)?;
    fs::write(c3_dir.join("seed_rfc3339.txt"), b"2026-09-19T19:00:00.000000Z")?;
    fs::write(c3_dir.join("seed_iso_duration.txt"), b"P3Y6M")?;

    // 4. Corpus for fuzz_conflict_proof_and_sst
    let c4_dir = base_dir.join("fuzz_conflict_proof_and_sst");
    fs::create_dir_all(&c4_dir)?;

    let proof = ProofOfDoubleSpend {
        proof_id: "test_proof_id_1234567890".into(),
        offender_id: alice.user_id.clone(),
        suspected_identity: Some(alice.user_id.clone()),
        fork_point_prev_hash: "00000000000000000000000000000000".into(),
        conflicting_transactions: voucher.transactions.clone(),
        deletable_at: "2030-01-01T00:00:00Z".into(),
        reporter_id: bob.user_id.clone(),
        report_timestamp: "2026-09-19T19:00:00Z".into(),
        reporter_signature: "placeholder_sig".into(),
        affected_voucher_name: Some("Test Voucher".into()),
        voucher_standard_uuid: Some(voucher.voucher_standard.uuid.clone()),
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
    };
    fs::write(c4_dir.join("seed_proof.json"), serde_json::to_vec_pretty(&proof)?)?;

    let fp = TransactionFingerprint {
        ds_tag: "tag123456".into(),
        t_id: "tx987654".into(),
        encrypted_timestamp: 123456789,
        layer2_signature: "sig123".into(),
        sender_ephemeral_pub: "ephem_pub_123".into(),
        deletable_at: "2030-01-01T00:00:00Z".into(),
        trap_r: "trap_r_sample".into(),
        trap_s: "trap_s_sample".into(),
        layer2_voucher_id: "v_id".into(),
        privacy_guard_hash: "guard_hash".into(),
    };
    fs::write(c4_dir.join("seed_fingerprint.json"), serde_json::to_vec_pretty(&fp)?)?;

    println!("Corpus successfully seeded across all 4 targets!");
    Ok(())
}
