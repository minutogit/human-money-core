// tests/wallet_api/conflict_management.rs
// cargo test --test wallet_api_tests wallet_api::conflict_management
//!
//! Testet die Wallet-Methoden zur Verwaltung von Konfliktbeweisen
//! (List-Conflicts, Get-Proof, Add-Resolution, Cleanup).

use human_money_core::test_utils::ACTORS;
use human_money_core::models::voucher::Transaction;
use human_money_core::models::conflict::{ProofOfDoubleSpend, ResolutionEndorsement};
use human_money_core::services::crypto_utils;
use human_money_core::test_utils::setup_in_memory_wallet;
use chrono::{Utc, Duration};
use bs58;
use tempfile::tempdir;
use human_money_core::app_service::AppService;
use human_money_core::MnemonicLanguage;

fn create_mock_proof(offender_id: &str) -> ProofOfDoubleSpend {
    let reporter = &ACTORS.victim;
    let fork_point_prev_hash = "fork_hash_123".to_string();
    let proof_id = crypto_utils::get_hash(format!("{}{}", offender_id, fork_point_prev_hash));
    let signature = crypto_utils::sign_ed25519(&reporter.signing_key, proof_id.as_bytes());

    ProofOfDoubleSpend {
        proof_id,
        offender_id: offender_id.to_string(),
        fork_point_prev_hash,
        conflicting_transactions: vec![Transaction::default(), Transaction::default()],
        deletable_at: (Utc::now() + Duration::days(90)).to_rfc3339(),
        reporter_id: reporter.user_id.clone(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
    }
}

#[test]
fn test_wallet_list_and_get_conflicts() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let proof1 = create_mock_proof("offender1");
    let proof2 = create_mock_proof("offender2");

    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    wallet.proof_store.proofs.insert(proof1.proof_id.clone(), ProofStoreEntry { 
        proof: proof1.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
    });
    wallet.proof_store.proofs.insert(proof2.proof_id.clone(), ProofStoreEntry { 
        proof: proof2.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
    });

    let list = wallet.list_conflicts();
    assert_eq!(list.len(), 2);

    let fetched = wallet.get_proof_of_double_spend(&proof1.proof_id).unwrap();
    assert_eq!(fetched.offender_id, "offender1");
}

#[test]
fn test_wallet_add_resolution_endorsement() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);
    let proof = create_mock_proof("offender1");
    
    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry { 
        proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
    });

    let victim = &ACTORS.victim;
    let endorsement = ResolutionEndorsement {
        endorsement_id: "e123".to_string(),
        proof_id: proof.proof_id.clone(),
        victim_id: victim.user_id.clone(),
        resolution_timestamp: Utc::now().to_rfc3339(),
        notes: Some("Settled".to_string()),
        victim_signature: "sig".to_string(),
    };

    wallet.add_resolution_endorsement(endorsement).unwrap();

    let updated = wallet.get_proof_of_double_spend(&proof.proof_id).unwrap();
    assert_eq!(updated.resolutions.as_ref().unwrap().len(), 1);
}

#[test]
fn test_cleanup_proofs_removes_expired_only() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let mut proof_old = create_mock_proof("old");
    proof_old.deletable_at = (Utc::now() - Duration::days(1)).to_rfc3339();
    
    let mut proof_new = create_mock_proof("new");
    proof_new.deletable_at = (Utc::now() + Duration::days(1)).to_rfc3339();

    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    wallet.proof_store.proofs.insert(proof_old.proof_id.clone(), ProofStoreEntry { 
        proof: proof_old.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
    });
    wallet.proof_store.proofs.insert(proof_new.proof_id.clone(), ProofStoreEntry { 
        proof: proof_new.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness 
    });

    wallet.run_storage_cleanup(None, 0).unwrap();

    assert!(!wallet.proof_store.proofs.contains_key(&proof_old.proof_id));
    assert!(wallet.proof_store.proofs.contains_key(&proof_new.proof_id));
}

#[test]
fn test_conflict_override_persistence() {
    let dir = tempdir().unwrap();
    let mut service = AppService::new(dir.path()).unwrap();
    service.create_profile("PersistTest", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None, Some("al"), "pwd123", MnemonicLanguage::English).unwrap();

    // Import a proof directly
    let mut tx = Transaction::default();
    tx.t_id = "tx123".to_string();
    let proof = ProofOfDoubleSpend {
        proof_id: "persist-proof-id".to_string(),
        offender_id: "bad_guy".to_string(),
        conflicting_transactions: vec![tx.clone(), tx],
        reporter_id: "reporter_xyz".to_string(),
        resolutions: None,
        layer2_verdict: None,
        fork_point_prev_hash: "hash".to_string(),
        deletable_at: "2050-01-01T00:00:00Z".to_string(),
        report_timestamp: "2025-01-01T00:00:00Z".to_string(),
        reporter_signature: "sig".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
    };
    
    // Test import_proof saves it: Check that logging out and logging back in works.
    service.import_proof(proof, Some("pwd123")).unwrap();
    service.set_conflict_local_override("persist-proof-id", true, Some("Trust me".to_string()), Some("pwd123")).unwrap();
    
    service.logout();
    
    // Login and get details
    let profile_folder = service.list_profiles().unwrap()[0].folder_name.clone();
    service.login(&profile_folder, "pwd123", false).unwrap();
    
    let conflicts = service.list_conflicts().unwrap();
    let loaded_conflict = conflicts.iter().find(|c| c.proof_id == "persist-proof-id").expect("Proof should be persisted");
    
    assert!(loaded_conflict.local_override);
    assert_eq!(loaded_conflict.local_note, Some("Trust me".to_string()));
}
