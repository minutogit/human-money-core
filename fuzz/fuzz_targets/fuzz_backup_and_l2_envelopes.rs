#![no_main]

use human_money_core::app_service::AppService;
use human_money_core::models::backup::{
    BackupManifestPayload, BackupRestoreCredentials, EncryptedBackupManifest,
};
use human_money_core::models::layer2_api::{
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, QuorumCertificateDto,
    QuorumProof,
};
use human_money_core::services::l2_gateway;
use humoco_proto::causal::CausalOutputProof;
use humoco_proto::live::{
    live_state_digest, verify_live_state_proof, LiveStateContext, LiveStateProof,
};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

static APP_BASE: OnceLock<PathBuf> = OnceLock::new();

fn get_app() -> AppService {
    let path = APP_BASE.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("hmc_fuzz_backup_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&p);
        p
    });
    AppService::new(path).expect("AppService initialization")
}

fuzz_target!(|data: &[u8]| {
    let app = get_app();

    // =========================================================================
    // Part A: Differential Backup Inspection & Archive Parsing Entrypoints
    // =========================================================================

    // 1. Password-based backup inspection
    let _ = app.inspect_backup(data, &BackupRestoreCredentials::BackupPassword("fuzz_password"));
    let _ = app.inspect_backup(data, &BackupRestoreCredentials::BackupPassword(""));

    // 2. Mnemonic-based backup inspection
    let _ = app.inspect_backup(
        data,
        &BackupRestoreCredentials::Mnemonic {
            phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            passphrase: None,
            prefix: None,
            language: human_money_core::MnemonicLanguage::English,
        },
    );

    // 3. Direct EncryptedBackupManifest deserialization
    if let Ok(manifest) = serde_json::from_slice::<EncryptedBackupManifest>(data) {
        let _ = manifest.format.len();
        let _ = manifest.protection_mode.len();
    }

    // 4. Direct BackupManifestPayload deserialization & path validation
    if let Ok(payload) = serde_json::from_slice::<BackupManifestPayload>(data) {
        for (blob, path) in &payload.blob_map {
            let _ = blob.len();
            let _ = path.len();
            let _ = path.contains("..");
        }
    }

    // 5. Restore attempt with mock blob set
    if data.len() <= 64 * 1024 {
        let mut blobs = HashMap::new();
        blobs.insert("blob_test.enc".to_string(), data.to_vec());
        let mut app_restore = get_app();
        let _ = app_restore.restore_backup(
            data,
            &blobs,
            BackupRestoreCredentials::BackupPassword("fuzz_password"),
            "new_local_password",
            "fuzz_instance_id".into(),
        );
    }

    // =========================================================================
    // Part B: L2 Response / Quorum Proof / Checkout Envelope Entrypoints
    // =========================================================================

    // 1. Raw L2 verdict processor entrypoint
    let server_pubkey = [0x42u8; 32];
    let _ = l2_gateway::process_l2_verdict(
        data,
        &server_pubkey,
        "local_t_id_fuzz",
        "challenge_tag_fuzz",
        Some("ephem_pub_fuzz"),
        "voucher_id_fuzz",
    );

    // 2. L2ResponseEnvelope deserialization & quorum proof extraction
    if let Ok(env) = serde_json::from_slice::<L2ResponseEnvelope>(data) {
        if let Some(proof) = env.quorum_proof() {
            let dummy_digest = [0u8; 32];
            let _ = l2_gateway::verify_checkout_receipt(&proof, &dummy_digest, &[], 0);
            let _ = l2_gateway::verify_checkout_receipt(&proof, &dummy_digest, &[[1u8; 32]], 1);
            let _ = l2_gateway::verify_checkout_receipt(
                &proof,
                &dummy_digest,
                &[[1u8; 32], [2u8; 32]],
                14,
            );
        }
        if let Some(ref cert) = env.quorum_certificate {
            let _ = l2_gateway::verify_checkout_receipt_certificate(cert, &[0u8; 32], &[], 14);
            let _ = l2_gateway::verify_quorum_plausibility(cert, cert.shard_id);
            let _ = l2_gateway::verify_quorum_plausibility(cert, 0);
            let _ = QuorumProof::try_from(cert);
        }
    }

    // 3. QuorumCertificateDto deserialization & plausibility verification
    if let Ok(cert) = serde_json::from_slice::<QuorumCertificateDto>(data) {
        let _ = QuorumProof::try_from(&cert);
        let _ = l2_gateway::verify_quorum_plausibility(&cert, cert.shard_id);
        let _ = l2_gateway::verify_quorum_plausibility(&cert, 0);
        let _ = l2_gateway::verify_checkout_receipt_certificate(&cert, &[0u8; 32], &[], 14);
        let _ = l2_gateway::verify_checkout_receipt_certificate(&cert, &[1u8; 32], &[[1u8; 32]], 1);
    }

    // 4. QuorumProof deserialization & mathematical verification
    if let Ok(proof) = serde_json::from_slice::<QuorumProof>(data) {
        let digest = [0u8; 32];
        let _ = l2_gateway::verify_checkout_receipt(&proof, &digest, &[], 0);
        let _ = l2_gateway::verify_checkout_receipt(&proof, &digest, &[[1u8; 32]], 1);
        let _ = l2_gateway::verify_checkout_receipt(
            &proof,
            &digest,
            &[[1u8; 32], [2u8; 32]],
            14,
        );
        let _ = humoco_proto::verify::verify_quorum_proof(&proof, &digest, &[], 0);
        let _ = humoco_proto::verify::verify_quorum_proof(&proof, &digest, &[[1u8; 32]], 1);
    }

    // 5. L2LockEntry deserialization & proof of truth verification
    if let Ok(entry) = serde_json::from_slice::<L2LockEntry>(data) {
        let _ = l2_gateway::verify_lock_entry_proof(
            &entry,
            &entry.layer2_voucher_id,
            None,
            "challenge_tag_fuzz",
        );
        let _ = l2_gateway::verify_lock_entry_proof(
            &entry,
            "mismatch_voucher_id",
            Some("ephem_pub_fuzz"),
            "tag",
        );
    }

    // 6. L2LockRequest deserialization & payload hash calculation
    if let Ok(req) = serde_json::from_slice::<L2LockRequest>(data) {
        let _ = l2_gateway::calculate_l2_payload_hash(&req);
        let entry = L2LockEntry::from(&req);
        let _ = l2_gateway::verify_lock_entry_proof(
            &entry,
            &entry.layer2_voucher_id,
            None,
            "tag",
        );
    }

    // 7. LiveStateProof & LiveStateContext verification
    if let Ok(proof) = serde_json::from_slice::<LiveStateProof>(data) {
        let _ = verify_live_state_proof(&proof, &proof.context);
        let _ = l2_gateway::verify_current_checkout(&proof, &proof.context);
        let _ = app.verify_live_checkout_proof(&proof, &proof.context, false);
        let _ = app.verify_live_checkout_proof(&proof, &proof.context, true);
    }
    if let Ok(context) = serde_json::from_slice::<LiveStateContext>(data) {
        let _ = live_state_digest(&context);
    }

    // 8. CausalOutputProof wire format deserialization
    if let Ok(causal) = serde_json::from_slice::<CausalOutputProof>(data) {
        let _ = serde_json::to_vec(&causal);
    }

    // 9. L2StatusQuery deserialization
    if let Ok(query) = serde_json::from_slice::<L2StatusQuery>(data) {
        let _ = serde_json::to_vec(&query);
    }
});
