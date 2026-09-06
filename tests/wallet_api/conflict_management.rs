// tests/wallet_api/conflict_management.rs
// cargo test --test wallet_api_tests wallet_api::conflict_management
//!
//! Tests wallet methods for managing conflict proofs
//! (List-Conflicts, Get-Proof, Add-Resolution, Cleanup).

use human_money_core::test_utils::ACTORS;
use human_money_core::models::conflict::ProofOfDoubleSpend;
use human_money_core::services::crypto;
use human_money_core::test_utils::setup_in_memory_wallet;
use chrono::{Utc, Duration};
use bs58;
use tempfile::tempdir;
use human_money_core::app_service::AppService;
use human_money_core::MnemonicLanguage;
use human_money_core::{
    Transaction,Voucher, Wallet, VoucherInstance, VoucherStatus};

fn create_mock_proof(offender_id: &str) -> ProofOfDoubleSpend {
    let reporter = &ACTORS.victim;
    let fork_point_prev_hash = "fork_hash_123".to_string();
    let proof_id = crypto::get_hash(format!("{}{}", offender_id, fork_point_prev_hash));
    let signature = crypto::sign_ed25519(&reporter.signing_key, proof_id.as_bytes());

    ProofOfDoubleSpend {
        proof_id,
        offender_id: offender_id.to_string(),
        suspected_identity: None,
        fork_point_prev_hash,
        conflicting_transactions: vec![human_money_core::models::voucher::Transaction::default(), human_money_core::models::voucher::Transaction::default()],
        deletable_at: (Utc::now() + Duration::days(90)).to_rfc3339(),
        reporter_id: reporter.user_id.clone(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
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

    // SECURITY (HMSEC-SA06-12): add_resolution_endorsement now verifies
    // victim_signature over endorsement_id against the claimed victim key.
    // The fixture therefore uses the canonical signer instead of a bogus
    // placeholder signature.
    let victim = &ACTORS.victim;
    let endorsement =
        human_money_core::services::conflict_manager::create_and_sign_resolution_endorsement(
            &proof.proof_id,
            victim,
            Some("Settled".to_string()),
        )
        .unwrap();

    wallet.add_resolution_endorsement(endorsement).unwrap();

    let updated = wallet.get_proof_of_double_spend(&proof.proof_id).unwrap();
    assert_eq!(updated.resolutions.as_ref().unwrap().len(), 1);
}

// SECURITY REGRESSION TEST (HMSEC-SA04 endorsement replay / cross-proof
// attachment): an endorsement minted for proof A must not be attachable,
// unmodified, to proof B. The content-hash gate in add_resolution_endorsement
// re-derives endorsement_id from the endorsement's own fields; mutating ONLY
// the proof_id breaks that binding deterministically before any signature or
// state mutation happens.
#[test]
fn test_endorsement_replay_onto_foreign_proof_is_rejected() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    // Two independent conflict proofs (different offenders).
    let proof_a = create_mock_proof("offenderA");
    let proof_b = create_mock_proof("offenderB");
    use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
    wallet.proof_store.proofs.insert(
        proof_a.proof_id.clone(),
        ProofStoreEntry {
            proof: proof_a.clone(),
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );
    wallet.proof_store.proofs.insert(
        proof_b.proof_id.clone(),
        ProofStoreEntry {
            proof: proof_b.clone(),
            local_override: false,
            local_note: None,
            conflict_role: ConflictRole::Witness,
        },
    );

    // The victim legitimately endorses proof A.
    let victim = &ACTORS.victim;
    let endorsement =
        human_money_core::services::conflict_manager::create_and_sign_resolution_endorsement(
            &proof_a.proof_id,
            victim,
            Some("Settled with A".to_string()),
        )
        .unwrap();

    // Positive control: the unmodified endorsement attaches to ITS proof.
    {
        let mut wallet_control = setup_in_memory_wallet(alice);
        wallet_control.proof_store.proofs.insert(
            proof_a.proof_id.clone(),
            ProofStoreEntry {
                proof: proof_a.clone(),
                local_override: false,
                local_note: None,
                conflict_role: ConflictRole::Witness,
            },
        );
        wallet_control
            .add_resolution_endorsement(endorsement.clone())
            .expect("legitimate endorsement must attach to its own proof");
    }

    // THE ATTACK: relabel the signed endorsement onto proof B WITHOUT
    // re-signing (the signature over endorsement_id stays untouched).
    let mut replayed = endorsement;
    replayed.proof_id = proof_b.proof_id.clone();

    let result = wallet.add_resolution_endorsement(replayed);
    assert!(
        result.is_err(),
        "SECURITY VIOLATION: a validly signed endorsement for proof A was \
         attached to foreign proof B (cross-proof replay)"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("does not match canonical hash of endorsement fields"));

    // Proof B remains UNRESOLVED: no resolutions recorded, reputation of its
    // offender stays KnownOffender.
    let b_state = wallet.get_proof_of_double_spend(&proof_b.proof_id).unwrap();
    assert!(
        b_state.resolutions.as_ref().is_none_or(|v| v.is_empty()),
        "replayed endorsement leaked into proof B's resolutions"
    );
    assert!(
        matches!(
            wallet.check_reputation(&proof_b.offender_id),
            human_money_core::models::conflict::TrustStatus::KnownOffender(_)
        ),
        "offender of proof B must remain KnownOffender after the rejected replay"
    );
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
    service.create_profile("PersistTest", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None, Some("al"), "pwd123", MnemonicLanguage::English, "test-id".to_string()).unwrap();

    // Import a proof directly. SECURITY: imports must be properly signed and
    // structurally valid (import_proof enforces the gates).
    let fork_point_prev_hash = bs58::encode([4u8; 32]).into_string();
    let ephemeral_pub = bs58::encode([9u8; 32]).into_string();
    let mk_tx = |id: &str| Transaction {
        t_id: id.to_string(),
        prev_hash: fork_point_prev_hash.clone(),
        sender_ephemeral_pub: Some(ephemeral_pub.clone()),
        ..Default::default()
    };
    let genuine_proof = human_money_core::services::conflict_manager::create_proof_of_double_spend(
        "bad_guy".to_string(),
        fork_point_prev_hash.clone(),
        vec![mk_tx("tx123"), mk_tx("tx456")],
        "2050-01-01T00:00:00Z".to_string(),
        &ACTORS.bob.identity,
        false,
    )
    .unwrap();
    let persist_proof_id = genuine_proof.proof_id.clone();

    // Test import_proof saves it: Check that logging out and logging back in works.
    service.import_proof(genuine_proof, Some("pwd123")).unwrap();
    service.set_conflict_local_override(&persist_proof_id, true, Some("Trust me".to_string()), Some("pwd123")).unwrap();
    
    service.logout();
    
    // Login and get details
    let profile_folder = service.list_profiles().unwrap()[0].folder_name.clone();
    service.login(&profile_folder, "pwd123", false, "test-id".to_string()).unwrap();
    
    let conflicts = service.list_conflicts().unwrap();
    let loaded_conflict = conflicts.iter().find(|c| c.proof_id == persist_proof_id).expect("Proof should be persisted");
    
    assert!(loaded_conflict.local_override);
    assert_eq!(loaded_conflict.local_note, Some("Trust me".to_string()));
}

#[test]
fn test_get_proof_id_for_voucher_all_heuristics() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);

    let local_id = "test_voucher_instance";

    // Helper to generate a base voucher
    let mut voucher = human_money_core::models::voucher::Voucher::default();
    voucher.voucher_id = "v123".to_string();
    voucher.transactions = vec![human_money_core::models::voucher::Transaction::default()];
    
    // Helper to clear proofs and voucher store
    let reset_wallet = |w: &mut Wallet, v: Voucher| {
        w.proof_store.proofs.clear();
        w.voucher_store.vouchers.clear();
        w.voucher_store.vouchers.insert(local_id.to_string(), VoucherInstance {
            voucher: v,
            status: VoucherStatus::Quarantined { reason: "test".to_string() },
            local_instance_id: local_id.to_string(),
        });
    };

    // Test Case 1: Match 1 (Direct t_id match)
    {
        let mut v = voucher.clone();
        v.transactions[0].t_id = "tx_match_1".to_string();
        reset_wallet(&mut wallet, v);

        let mut proof = create_mock_proof("offender1");
        proof.proof_id = "proof_case_1".to_string();
        proof.conflicting_transactions[0].t_id = "tx_match_1".to_string();

        use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
        wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry {
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness
        });

        assert_eq!(wallet.get_proof_id_for_voucher(local_id), Some("proof_case_1".to_string()));
    }

    // Test Case 2: Match 2 (DS-Tag match)
    {
        use human_money_core::models::voucher::TrapData;
        let mut v = voucher.clone();
        v.transactions[0].trap_data = Some(TrapData {
            ds_tag: "tag_match_2".to_string(),
            ..Default::default()
        });
        reset_wallet(&mut wallet, v);

        let mut proof = create_mock_proof("offender2");
        proof.proof_id = "proof_case_2".to_string();
        proof.conflicting_transactions[0].trap_data = Some(TrapData {
            ds_tag: "tag_match_2".to_string(),
            ..Default::default()
        });

        use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
        wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry {
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness
        });

        assert_eq!(wallet.get_proof_id_for_voucher(local_id), Some("proof_case_2".to_string()));
    }

    // Test Case 3: Match 3 (Deep Fork Point match)
    {
        let mut v = voucher.clone();
        v.transactions[0].prev_hash = "fork_hash_3".to_string();
        reset_wallet(&mut wallet, v);

        let mut proof = create_mock_proof("offender3");
        proof.proof_id = "proof_case_3".to_string();
        proof.fork_point_prev_hash = "fork_hash_3".to_string();

        use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
        wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry {
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness
        });

        assert_eq!(wallet.get_proof_id_for_voucher(local_id), Some("proof_case_3".to_string()));
    }

    // Test Case 4: Match 4 (Offender & Chain Link match)
    {
        let mut v = voucher.clone();
        v.transactions[0].sender_id = Some("offender4".to_string());
        reset_wallet(&mut wallet, v);

        let mut proof = create_mock_proof("offender4");
        proof.proof_id = "proof_case_4".to_string();

        use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
        wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry {
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness
        });

        assert_eq!(wallet.get_proof_id_for_voucher(local_id), Some("proof_case_4".to_string()));
    }

    // Test Case 5: Match 5 (Recipient match)
    {
        let mut v = voucher.clone();
        v.transactions[0].recipient_id = "victim5".to_string();
        reset_wallet(&mut wallet, v);

        let mut proof = create_mock_proof("offender5");
        proof.proof_id = "proof_case_5".to_string();
        proof.conflicting_transactions[0].recipient_id = "victim5".to_string();

        use human_money_core::models::conflict::{ProofStoreEntry, ConflictRole};
        wallet.proof_store.proofs.insert(proof.proof_id.clone(), ProofStoreEntry {
            proof: proof.clone(), local_override: false, local_note: None, conflict_role: ConflictRole::Witness
        });

        assert_eq!(wallet.get_proof_id_for_voucher(local_id), Some("proof_case_5".to_string()));
    }
}
