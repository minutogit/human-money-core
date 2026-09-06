//! # src/wallet/reputation_tests.rs
//! Unit tests for reputation management and ProofStore.

#[cfg(test)]
mod tests {
    use crate::test_utils::{ACTORS, setup_in_memory_wallet};
    use crate::models::conflict::{ProofOfDoubleSpend, ProofStoreEntry, ConflictRole, TransactionFingerprint, FingerprintMetadata};
    use crate::models::voucher::Transaction;
    use crate::VoucherStatus;
    use std::collections::HashMap;

    /// Builds a structurally valid, properly SIGNED proof.
    ///
    /// SECURITY NOTE: Since `import_proof` enforces reporter signature,
    /// proof-id consistency and structural collision checks, dummy proofs
    /// must satisfy the same gates as production proofs.
    fn create_signed_proof(offender_id: &str) -> ProofOfDoubleSpend {
        let fork_point_prev_hash = bs58::encode([1u8; 32]).into_string();
        let ephemeral_pub = bs58::encode([7u8; 32]).into_string();

        let mut tx1 = Transaction { t_id: "t1".to_string(), ..Default::default() };
        tx1.prev_hash = fork_point_prev_hash.clone();
        tx1.sender_ephemeral_pub = Some(ephemeral_pub.clone());
        let mut tx2 = Transaction { t_id: "t2".to_string(), ..Default::default() };
        tx2.prev_hash = fork_point_prev_hash.clone();
        tx2.sender_ephemeral_pub = Some(ephemeral_pub.clone());

        crate::services::conflict_manager::create_proof_of_double_spend(
            offender_id.to_string(),
            fork_point_prev_hash,
            vec![tx1, tx2],
            "2099-01-01T00:00:00Z".to_string(),
            &ACTORS.alice.identity,
            false,
        )
        .unwrap()
    }

    #[test]
    fn test_wrapper_serialization_and_hash_integrity() {
        let proof = create_signed_proof("offender");
        let entry = ProofStoreEntry {
            proof: proof.clone(),
            local_override: true,
            local_note: Some("Clear manual resolution".to_string()),
            conflict_role: ConflictRole::Victim,
        };

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: ProofStoreEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.proof.proof_id, proof.proof_id);
        assert_eq!(deserialized.local_override, true);
        assert_eq!(deserialized.conflict_role, ConflictRole::Victim);
        
        // Export simulation: just the inner proof
        let exported_json = serde_json::to_string(&deserialized.proof).unwrap();
        let original_json = serde_json::to_string(&proof).unwrap();
        assert_eq!(exported_json, original_json, "Exported proof must be identical to original");
    }

    #[test]
    fn test_import_protection_immunity() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let mut proof = create_signed_proof("offender");
        let proof_id = proof.proof_id.clone();
        
        // 1. Set manual override
        wallet.proof_store.proofs.insert(proof_id.to_string(), ProofStoreEntry {
            proof: proof.clone(),
            local_override: true,
            local_note: None,
            conflict_role: ConflictRole::Victim,
        });

        // 2. Re-import same proof (e.g. with different signature or metadata)
        proof.reporter_id = "malicious_reporter".to_string();
        wallet.import_proof(proof).unwrap();

        // 3. Verify that local state (override) was preserved
        let entry = wallet.proof_store.proofs.get(&proof_id).unwrap();
        assert_eq!(entry.local_override, true);
        assert_eq!(entry.proof.reporter_id, ACTORS.alice.identity.user_id, "Original reporter should not be overwritten");
    }

    #[test]
    fn test_vip_effective_head_start_and_eviction() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // 1. Two normal fingerprints (depth 0 and depth 5)
        wallet.fingerprint_metadata.insert("norm_0".to_string(), FingerprintMetadata { depth: 0, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "norm_0".to_string(), 
            vec![TransactionFingerprint { ds_tag: "norm_0".to_string(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
        );

        wallet.fingerprint_metadata.insert("norm_5".to_string(), FingerprintMetadata { depth: 5, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "norm_5".to_string(), 
            vec![TransactionFingerprint { ds_tag: "norm_5".to_string(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
        );

        // 2. A slightly aged VIP fingerprint (-3) -> Effective depth: abs(-3) - 2 = 1
        wallet.fingerprint_metadata.insert("vip_minus_3".to_string(), FingerprintMetadata { depth: -3, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "vip_minus_3".to_string(), 
            vec![TransactionFingerprint { ds_tag: "vip_minus_3".to_string(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
        );

        // 3. A heavily aged VIP fingerprint (-10) -> Effective depth: abs(-10) - 2 = 8
        wallet.fingerprint_metadata.insert("vip_minus_10".to_string(), FingerprintMetadata { depth: -10, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "vip_minus_10".to_string(), 
            vec![TransactionFingerprint { ds_tag: "vip_minus_10".to_string(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
        );

        // Selection for bundle
        let (selected, _) = wallet.select_fingerprints_for_bundle("recipient", &[]).unwrap();

        // Verification of sort order based on effective depth!
        // Rank 1: norm_0 (effective: 0)
        // Rank 2: vip_minus_3 (effective: 1)
        // Rank 3: norm_5 (effective: 5)
        // Rank 4: vip_minus_10 (effective: 8)
        
        assert_eq!(selected[0].ds_tag, "norm_0");
        assert_eq!(selected[1].ds_tag, "vip_minus_3", "VIP with -3 must be treated as depth 1!");
        assert_eq!(selected[2].ds_tag, "norm_5");
        assert_eq!(selected[3].ds_tag, "vip_minus_10", "Heavily aged VIP must land behind fresh normal fingerprint!");
    }

    #[test]
    fn test_vip_symmetry_check() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        // Case 1: Asymmetric VIP spam (only one fingerprint with -2)
        // V2: fingerprints must be self-authenticating to pass the ingress gate.
        let f1 = crate::test_utils::make_signed_fingerprint("f1", "", 0);
        let mut depths = HashMap::new();
        depths.insert("f1".to_string(), -2);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1], &depths).unwrap();
        
        // Must be normalized to positive (e.g. 1 + 1 = 2)
        assert!(wallet.fingerprint_metadata["f1"].depth > 0);

        // Case 2: Symmetric VIP (two partners with -2)
        let f2a = crate::test_utils::make_signed_fingerprint("fraud", "", 0);
        let f2b = crate::test_utils::make_signed_fingerprint("fraud", "", 0);
        let mut depths2 = HashMap::new();
        depths2.insert("fraud".to_string(), -2);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f2a, f2b], &depths2).unwrap();
        
        // Must remain VIP and age (-2 -> -3)
        assert_eq!(wallet.fingerprint_metadata["fraud"].depth, -3);
    }

    #[test]
    fn test_loop_protection_ignore_fresher_vip() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let ds_tag = "loop_tag".to_string();
        wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
            depth: -10, // Already aged
            ..Default::default()
        });
        wallet.known_fingerprints.foreign_fingerprints.insert(ds_tag.clone(), vec![
            crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0)
        ]);

        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        
        // Someone sends the fingerprint "fresh" with -1
        let f = crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0);
        let f2 = crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0);
        let mut depths = HashMap::new();
        depths.insert(ds_tag.clone(), -1);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f, f2], &depths).unwrap();
        
        // Must stay at -10 (-1 is "fresher" and is ignored)
        assert_eq!(wallet.fingerprint_metadata[&ds_tag].depth, -10);
    }

    #[test]
    fn test_saturating_sub_boundary() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        
        let f1 = crate::test_utils::make_signed_fingerprint("bound", "", 0);
        let f2 = crate::test_utils::make_signed_fingerprint("bound", "", 0);
        let mut depths = HashMap::new();
        depths.insert("bound".to_string(), -128);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1, f2], &depths).unwrap();
        
        assert_eq!(wallet.fingerprint_metadata["bound"].depth, -128); // Must not overflow/wrap
    }

    #[test]
    fn test_multi_proof_reputation_check() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let offender = "bad_guy";

        // Proof A: Resolved via override
        let proof_a = create_signed_proof(offender);
        wallet.import_proof(proof_a).unwrap();
        wallet.set_conflict_local_override(&wallet.list_conflicts()[0].proof_id.clone(), true, Some("Resolved A".to_string())).unwrap();

        // Proof B: Unresolved (different fork point => different proof_id)
        let proof_b = {
            let mut p = create_signed_proof(offender);
            // Re-derive with a different fork point so the proof ids differ.
            let fork2 = bs58::encode([2u8; 32]).into_string();
            for tx in p.conflicting_transactions.iter_mut() {
                tx.prev_hash = fork2.clone();
                tx.trap_data = None;
            }
            let rebuilt = crate::services::conflict_manager::create_proof_of_double_spend(
                offender.to_string(),
                fork2,
                p.conflicting_transactions.clone(),
                p.deletable_at.clone(),
                &ACTORS.alice.identity,
                false,
            )
            .unwrap();
            assert_ne!(rebuilt.proof_id, p.proof_id);
            rebuilt
        };
        wallet.import_proof(proof_b).unwrap();

        use crate::models::conflict::TrustStatus;
        let status = wallet.check_reputation(offender);
        
        let expected_unresolved = wallet
            .list_conflicts()
            .into_iter()
            .find(|c| c.offender_id == offender && !c.is_resolved && !c.local_override)
            .map(|c| c.proof_id)
            .expect("one unresolved proof must exist");

        if let TrustStatus::KnownOffender(pid) = status {
            assert_eq!(pid, expected_unresolved, "Must return the unsolved proof, even if the other one is resolved");
        } else {
            panic!("Should be KnownOffender(unresolved proof)");
        }
    }

    #[test]
    fn test_vip_overrides_existing_positive_fingerprint() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let ds_tag = "transition_tag".to_string();

        // 1. Setup: Fingerprint is already known locally as "normal" (positive)
        wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
            depth: 5, // Positive depth (harmless)
            ..Default::default()
        });
        wallet.known_fingerprints.foreign_fingerprints.insert(ds_tag.clone(), vec![
            crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0)
        ]);

        // 2. Action: A legitimate, symmetric VIP update (fraud detection) arrives
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        // Two fingerprints with the same ds_tag satisfy the symmetry rule
        let f1 = crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0);
        let f2 = crate::test_utils::make_signed_fingerprint(&ds_tag, "", 0);
        
        let mut depths = HashMap::new();
        depths.insert(ds_tag.clone(), -2); // Incoming VIP status

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1, f2], &depths).unwrap();

        // 3. Verification: The positive value (5) must have been overwritten by the negative value.
        // For received_depth = -2, aging via saturating_sub(1) applies, so the result must be -3.
        let updated_depth = wallet.fingerprint_metadata[&ds_tag].depth;
        assert_eq!(
            updated_depth, -3, 
            "The positive value (5) must be overwritten by the legitimate VIP update (-2 - 1 = -3)!"
        );
    }

    #[test]
    fn test_conflict_role_victim_identification() {
        // Tests detection logic: If one of the fraudulent transactions
        // affects a voucher that we own locally and is therefore quarantined,
        // our role MUST be "Victim".
        
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        // 1. Simulate a local voucher that fell victim to a double-spend
        let tx_id_victim = "tx_local_victim_123";
        let mut instance = crate::wallet::instance::VoucherInstance {
            local_instance_id: "inst_1".to_string(),
            // Status is Quarantined (moved there due to the conflict)
            status: VoucherStatus::Quarantined { reason: "Double Spend".to_string() },
            ..Default::default()
        };
        // History contains the affected transaction
        instance.voucher.transactions.push(Transaction { t_id: tx_id_victim.to_string(), ..Default::default() });
        wallet.voucher_store.vouchers.insert("inst_1".to_string(), instance);
        
        // 2. Create a simulated proof whose collision affects us
        // (role check operates on the transaction list only; the helper
        // provides valid signatures so the object matches production shape)
        let mut proof = create_signed_proof("offender");
        let fork_point_prev_hash = bs58::encode([3u8; 32]).into_string();
        proof.fork_point_prev_hash = fork_point_prev_hash.clone();
        proof.conflicting_transactions = vec![
            Transaction { t_id: tx_id_victim.to_string(), prev_hash: fork_point_prev_hash.clone(), ..Default::default() }, // Our path
            Transaction { t_id: "tx_foreign_456".to_string(), prev_hash: fork_point_prev_hash, ..Default::default() }, // Other path
        ];
        
        // 3. Execute exact role check logic from transaction_handler
        let mut conflict_role = ConflictRole::Witness;
        for tx in &proof.conflicting_transactions {
            if let Some(local_inst) = wallet.find_local_voucher_by_tx_id(&tx.t_id) {
                if matches!(local_inst.status, VoucherStatus::Quarantined { .. }) {
                    conflict_role = ConflictRole::Victim;
                    break;
                }
            }
        }
        
        // 4. Verification
        assert_eq!(
            conflict_role, 
            ConflictRole::Victim, 
            "The user must be identified as Victim since their local voucher is affected and quarantined."
        );
    }

    #[test]
    fn test_bundle_selection_priority_at_max_limit() {
        // Tests transmission priority: When the limit of 150 is reached,
        // VIP fingerprints (negative) must be sent. Normal, weak
        // fingerprints (high positive depth) are ignored for this bundle.
        
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // 1. Fill system with 150 regular fingerprints (all depth 10)
        for i in 1..=150 {
            let ds_tag = format!("norm_{:03}", i);
            wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
                depth: 10,
                ..Default::default()
            });
            wallet.own_fingerprints.history.insert(
                ds_tag.clone(), 
                vec![TransactionFingerprint { ds_tag: ds_tag.clone(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
            );
        }

        // 2. Add a VIP fingerprint (depth -1)
        let vip_tag = "vip_fraud".to_string();
        wallet.fingerprint_metadata.insert(vip_tag.clone(), FingerprintMetadata {
            depth: -1,
            ..Default::default()
        });
        wallet.own_fingerprints.history.insert(
            vip_tag.clone(), 
            vec![TransactionFingerprint { ds_tag: vip_tag.clone(), trap_r: "synthetic_shard".to_string(), trap_s: "synthetic_shard".to_string(), ..Default::default() }]
        );

        // We now have 151 fingerprints in memory.
        // 3. Trigger bundle selection (accesses MAX_FINGERPRINTS_TO_SEND = 150)
        let (selected, _depths) = wallet.select_fingerprints_for_bundle("recipient", &[]).unwrap();

        // 4. Verification
        assert_eq!(
            selected.len(), 
            150, 
            "The hard limit of exactly 150 fingerprints in the bundle must be strictly respected."
        );
        
        // The VIP fingerprint MUST have secured a spot
        assert!(
            selected.iter().any(|f| f.ds_tag == vip_tag), 
            "The VIP fingerprint was not prioritized! It must be in the bundle despite the limit."
        );
        
        // The weakest regular fingerprint (depth 150) was displaced / not selected in favor of the VIP
        assert!(
            !selected.iter().any(|f| f.ds_tag == "norm_150"), 
            "The weakest regular fingerprint should have been ignored in favor of the VIP fingerprint."
        );
    }
}

