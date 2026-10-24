//! # src/wallet/reputation_tests.rs
//! Unit tests for reputation management, ProofStore, and 30/70 KISS-Gossip protocol.

#[cfg(test)]
mod tests {
    use crate::test_utils::{ACTORS, setup_in_memory_wallet, make_signed_fingerprint};
    use crate::models::conflict::{
        ActiveGossipState, ConflictRole, DirectEntry, ProofOfDoubleSpend, ProofStoreEntry,
        QuarantineEntry, TransactionFingerprint,
    };
    use crate::models::profile::TransactionBundleHeader;
    use crate::models::voucher::{Transaction, Voucher};
    use crate::error::{ValidationError, VoucherCoreError};
    use crate::storage::{AuthMethod, FileStorage};
    use crate::VoucherStatus;
    use tempfile::tempdir;

    /// Builds a structurally valid, properly SIGNED proof.
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

    fn create_dummy_voucher_with_txs(tx_count: usize) -> Voucher {
        let mut voucher = Voucher {
            voucher_id: "v_test".to_string(),
            voucher_nonce: "nonce".to_string(),
            valid_until: "2099-01-01T00:00:00Z".to_string(),
            transactions: Vec::new(),
            ..Default::default()
        };
        for i in 0..tx_count {
            let eph = bs58::encode([i as u8 + 1; 32]).into_string();
            let prev = bs58::encode([i as u8; 32]).into_string();
            let tid = bs58::encode([i as u8 + 50; 32]).into_string();
            voucher.transactions.push(Transaction {
                t_id: tid,
                prev_hash: prev,
                t_type: if i == 0 { "init".to_string() } else { "transfer".to_string() },
                amount: "10.0".to_string(),
                sender_ephemeral_pub: Some(eph),
                t_time: "2026-01-01T00:00:00Z".to_string(),
                trap_data: if i == 0 {
                    None
                } else {
                    Some(crate::models::voucher::TrapData {
                        ds_tag: format!("ds_tag_{}", i),
                        ..Default::default()
                    })
                },
                ..Default::default()
            });
        }
        voucher
    }

    //==============================================================================
    // Section 1: ProofStore & Reputation Core Tests
    //==============================================================================

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
        assert!(deserialized.local_override);
        assert_eq!(deserialized.conflict_role, ConflictRole::Victim);
        
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
        
        wallet.proof_store.proofs.insert(proof_id.to_string(), ProofStoreEntry {
            proof: proof.clone(),
            local_override: true,
            local_note: None,
            conflict_role: ConflictRole::Victim,
        });

        proof.reporter_id = "malicious_reporter".to_string();
        wallet.import_proof(proof).unwrap();

        let entry = wallet.proof_store.proofs.get(&proof_id).unwrap();
        assert!(entry.local_override);
        assert_eq!(entry.proof.reporter_id, ACTORS.alice.identity.user_id, "Original reporter should not be overwritten");
    }

    #[test]
    fn test_multi_proof_reputation_check() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let offender = "bad_guy";

        let proof_a = create_signed_proof(offender);
        wallet.import_proof(proof_a).unwrap();
        wallet.set_conflict_local_override(&wallet.list_conflicts()[0].proof_id.clone(), true, Some("Resolved A".to_string())).unwrap();

        let proof_b = {
            let mut p = create_signed_proof(offender);
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
    fn test_conflict_role_victim_identification() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let tx_id_victim = "tx_local_victim_123";
        let mut instance = crate::wallet::instance::VoucherInstance {
            local_instance_id: "inst_1".to_string(),
            status: VoucherStatus::Quarantined { reason: "Double Spend".to_string() },
            ..Default::default()
        };
        instance.voucher.transactions.push(Transaction { t_id: tx_id_victim.to_string(), ..Default::default() });
        wallet.voucher_store.vouchers.insert("inst_1".to_string(), instance);
        
        let mut proof = create_signed_proof("offender");
        let fork_point_prev_hash = bs58::encode([3u8; 32]).into_string();
        proof.fork_point_prev_hash = fork_point_prev_hash.clone();
        proof.conflicting_transactions = vec![
            Transaction { t_id: tx_id_victim.to_string(), prev_hash: fork_point_prev_hash.clone(), ..Default::default() },
            Transaction { t_id: "tx_foreign_456".to_string(), prev_hash: fork_point_prev_hash, ..Default::default() },
        ];
        
        let mut conflict_role = ConflictRole::Witness;
        for tx in &proof.conflicting_transactions {
            if let Some(local_inst) = wallet.find_local_voucher_by_tx_id(&tx.t_id)
                && matches!(local_inst.status, VoucherStatus::Quarantined { .. }) {
                    conflict_role = ConflictRole::Victim;
                    break;
                }
        }
        
        assert_eq!(
            conflict_role, 
            ConflictRole::Victim, 
            "The user must be identified as Victim since their local voucher is affected and quarantined."
        );
    }

    //==============================================================================
    // Testsuite 1: Proportionale Protokoll- & Sicherheits-Invarianten
    //==============================================================================

    #[test]
    fn test_quarantine_egress_proportional_to_vouchers() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // Fill quarantine direct queue with 20 entries
        for i in 0..20 {
            let fp1 = make_signed_fingerprint(&format!("ds_q_{}", i), &format!("t1_{}", i), 0);
            let fp2 = make_signed_fingerprint(&format!("ds_q_{}", i), &format!("t2_{}", i), 0);
            wallet.active_gossip.quarantine_direct_queue.push(QuarantineEntry {
                pair: [fp1, fp2],
                sent_to: Vec::new(),
            });
        }

        // Case A: 1 voucher in bundle -> max 3 quarantine pairs
        let v1 = create_dummy_voucher_with_txs(2);
        let (_, q_pairs_1) = wallet.select_fingerprints_for_bundle("bob", std::slice::from_ref(&v1)).unwrap();
        assert_eq!(q_pairs_1.len(), 3, "1 voucher must yield exactly 3 quarantine pairs (V * 3)");

        // Reset wallet quarantine queue with fresh entries
        wallet.active_gossip.quarantine_direct_queue.clear();
        for i in 0..20 {
            let fp1 = make_signed_fingerprint(&format!("ds_q2_{}", i), &format!("t1_{}", i), 0);
            let fp2 = make_signed_fingerprint(&format!("ds_q2_{}", i), &format!("t2_{}", i), 0);
            wallet.active_gossip.quarantine_direct_queue.push(QuarantineEntry {
                pair: [fp1, fp2],
                sent_to: Vec::new(),
            });
        }

        // Case B: 5 vouchers in bundle -> max 15 quarantine pairs
        let vouchers_5: Vec<Voucher> = (0..5).map(|i| {
            let mut v = create_dummy_voucher_with_txs(2);
            v.voucher_id = format!("v_5_{}", i);
            v
        }).collect();
        let (_, q_pairs_5) = wallet.select_fingerprints_for_bundle("bob", &vouchers_5).unwrap();
        assert_eq!(q_pairs_5.len(), 15, "5 vouchers must yield exactly 15 quarantine pairs (5 * 3)");
    }

    #[test]
    fn test_quarantine_ingress_hard_rejection_proportional_excess() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let header = TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        // Bundle with 1 voucher and 4 quarantine pairs (> 1 * 3)
        let v1 = create_dummy_voucher_with_txs(2);
        let q_pairs: Vec<[TransactionFingerprint; 2]> = (0..4).map(|i| {
            let fp1 = make_signed_fingerprint(&format!("ds_spam_{}", i), &format!("t1_{}", i), 0);
            let fp2 = make_signed_fingerprint(&format!("ds_spam_{}", i), &format!("t2_{}", i), 0);
            [fp1, fp2]
        }).collect();

        let result = wallet.process_received_fingerprints(&header, &[v1], &[], &q_pairs);
        assert!(result.is_err(), "Must reject bundle with excessive quarantine pairs");
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::SecurityViolation(_))
        ));
    }

    #[test]
    fn test_bundle_own_fingerprints_bypass_lottery_and_preserved_for_subsequent_transfers() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        let v1 = create_dummy_voucher_with_txs(2);
        let bundle_tag = v1.transactions[1].trap_data.as_ref().map(|t| t.ds_tag.clone()).unwrap();

        // Put a fingerprint sharing bundle's ds_tag into fresh_gossip_pool
        let fp_bundle = make_signed_fingerprint(&bundle_tag, "tx_own_pool", 0);
        wallet.active_gossip.fresh_gossip_pool.push_back(fp_bundle.clone());

        // Put another foreign fingerprint into pool
        let fp_foreign = make_signed_fingerprint("foreign_ds_tag", "tx_foreign_pool", 0);
        wallet.active_gossip.fresh_gossip_pool.push_back(fp_foreign.clone());

        // Run selection for v1
        let (selected, _) = wallet.select_fingerprints_for_bundle("bob", &[v1]).unwrap();

        // fp_bundle must not be in selected gossip
        assert!(!selected.iter().any(|f| f.ds_tag == bundle_tag), "Bundle-own fingerprint must not be selected");

        // fp_bundle must be PRESERVED in fresh_gossip_pool for subsequent transfers
        assert!(
            wallet.active_gossip.fresh_gossip_pool.iter().any(|f| f.ds_tag == bundle_tag),
            "Bundle-own fingerprint must remain preserved in pool"
        );
    }

    //==============================================================================
    // Testsuite 2: Ingress-Reinheit, FIFO-Drain & Fließgleichgewicht
    //==============================================================================

    #[test]
    fn test_ingress_only_tip_to_direct_queue_predecessors_to_archive() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let header = TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        // Construct voucher with 5 transactions
        let voucher = create_dummy_voucher_with_txs(5);
        let tip_t_id = voucher.transactions[4].t_id.clone();

        wallet.process_received_fingerprints(&header, &[voucher], &[], &[]).unwrap();

        // Exactly 1 entry in direct_queue, which corresponds to the tip (Tx_5)
        assert_eq!(wallet.active_gossip.direct_queue.len(), 1);
        assert_eq!(wallet.active_gossip.direct_queue[0].fingerprint.t_id, tip_t_id);

        // fresh_gossip_pool must remain empty (no pollution)
        assert!(wallet.active_gossip.fresh_gossip_pool.is_empty());

        // Passive archive (local_history) must contain all transactions
        let total_archived: usize = wallet.known_fingerprints.local_history.values().map(|v| v.len()).sum();
        assert_eq!(total_archived, 5);
    }

    #[test]
    fn test_fifo_drain_preserves_untested_gossips() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // Fill fresh_gossip_pool with 30 fingerprints
        for i in 0..30 {
            let fp = make_signed_fingerprint(&format!("foreign_{}", i), &format!("tx_{}", i), 0);
            wallet.active_gossip.fresh_gossip_pool.push_back(fp);
        }

        let v1 = create_dummy_voucher_with_txs(2);
        // Budget M = 1 * 10 = 10 fingerprints
        let (selected, _) = wallet.select_fingerprints_for_bundle("bob", &[v1]).unwrap();

        assert!(selected.len() <= 10, "Selected fingerprints must not exceed proportional budget of 10");
        // Untested entries remain in pool
        assert!(!wallet.active_gossip.fresh_gossip_pool.is_empty(), "Untested entries must remain in fresh_gossip_pool");
    }

    #[test]
    fn test_redemption_transaction_enqueued_in_direct_queue() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let header = TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        let mut voucher = create_dummy_voucher_with_txs(3);
        voucher.transactions[2].t_type = "redeem".to_string();
        let redeem_t_id = voucher.transactions[2].t_id.clone();

        wallet.process_received_fingerprints(&header, &[voucher], &[], &[]).unwrap();

        assert_eq!(wallet.active_gossip.direct_queue.len(), 1);
        assert_eq!(wallet.active_gossip.direct_queue[0].fingerprint.t_id, redeem_t_id);
    }

    //==============================================================================
    // Testsuite 3: Unique Recipient & Persistenz
    //==============================================================================

    #[test]
    fn test_direct_queue_distinct_recipient_filter() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        let fp = make_signed_fingerprint("tip_ds_tag", "tip_tx_id", 0);
        let tip_tid = fp.t_id.clone();
        wallet.active_gossip.direct_queue.push_back(DirectEntry {
            fingerprint: fp.clone(),
            sent_to: Vec::new(),
        });

        let v1 = create_dummy_voucher_with_txs(2);

        // 1st payment to Bob: direct tip is selected
        let (sel1, _) = wallet.select_fingerprints_for_bundle("bob", std::slice::from_ref(&v1)).unwrap();
        assert!(sel1.iter().any(|f| f.t_id == tip_tid), "Tip must be sent to Bob on first transfer");

        // 2nd payment to Bob: direct tip is NOT selected (already known by Bob)
        let (sel2, _) = wallet.select_fingerprints_for_bundle("bob", std::slice::from_ref(&v1)).unwrap();
        assert!(!sel2.iter().any(|f| f.t_id == tip_tid), "Tip must NOT be sent to Bob again");

        // 1st payment to Charlie: direct tip IS selected
        let (sel3, _) = wallet.select_fingerprints_for_bundle("charlie", std::slice::from_ref(&v1)).unwrap();
        assert!(sel3.iter().any(|f| f.t_id == tip_tid), "Tip must be sent to Charlie on first transfer");

        // 1st payment to Dave: direct tip IS selected (3rd distinct recipient)
        let (sel4, _) = wallet.select_fingerprints_for_bundle("dave", std::slice::from_ref(&v1)).unwrap();
        assert!(sel4.iter().any(|f| f.t_id == tip_tid), "Tip must be sent to Dave on first transfer");

        // After reaching 3 distinct recipients (Bob, Charlie, Dave), entry must be evicted from direct_queue
        assert!(wallet.active_gossip.direct_queue.is_empty(), "Direct tip must be evicted after 3 distinct recipients");
    }

    #[test]
    fn test_active_gossip_state_persistence_roundtrip() {
        let dir = tempdir().unwrap();
        let user_id = ACTORS.alice.identity.user_id.clone();
        let mut storage = FileStorage::new(dir.path());
        let auth = AuthMethod::Password("test_pw_123");

        // Initialize wallet storage first
        let profile = crate::models::profile::UserProfile {
            user_id: user_id.clone(),
            ..Default::default()
        };
        let voucher_store = crate::models::profile::VoucherStore::default();
        storage.save_wallet(&profile, &voucher_store, &ACTORS.alice, &auth).unwrap();

        let mut gossip = ActiveGossipState::default();
        let fp1 = make_signed_fingerprint("tag_1", "tx_1", 0);
        let fp2 = make_signed_fingerprint("tag_2", "tx_2", 0);
        gossip.direct_queue.push_back(DirectEntry {
            fingerprint: fp1.clone(),
            sent_to: vec![[1, 2, 3, 4]],
        });
        gossip.fresh_gossip_pool.push_back(fp2.clone());

        storage.save_active_gossip(&auth, &gossip).unwrap();
        let loaded = storage.load_active_gossip(&auth).unwrap();

        assert_eq!(loaded.direct_queue.len(), 1);
        assert_eq!(loaded.direct_queue[0].fingerprint.t_id, fp1.t_id);
        assert_eq!(loaded.direct_queue[0].sent_to, vec![[1, 2, 3, 4]]);
        assert_eq!(loaded.fresh_gossip_pool.len(), 1);
        assert_eq!(loaded.fresh_gossip_pool[0].t_id, fp2.t_id);
    }

    #[test]
    fn test_bundle_scaling_32_vouchers_with_320_fingerprints() {
        use crate::services::bundle_processor::{
            create_and_encrypt_bundle, open_and_verify_bundle,
        };

        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;

        // Create 32 dummy vouchers
        let vouchers_32: Vec<Voucher> = (0..32).map(|i| {
            let mut v = create_dummy_voucher_with_txs(2);
            v.voucher_id = format!("voucher_{}", i);
            v
        }).collect();

        // 320 fingerprints (32 vouchers * 10 max per voucher)
        let fps_320: Vec<TransactionFingerprint> = (0..320).map(|i| {
            make_signed_fingerprint(&format!("ds_scale_{}", i), &format!("tx_scale_{}", i), 0)
        }).collect();

        // 96 quarantine pairs (32 vouchers * 3 max per voucher)
        let q_pairs_96: Vec<[TransactionFingerprint; 2]> = (0..96).map(|i| {
            let f1 = make_signed_fingerprint(&format!("ds_qscale_{}", i), &format!("tx_q1_{}", i), 0);
            let f2 = make_signed_fingerprint(&format!("ds_qscale_{}", i), &format!("tx_q2_{}", i), 0);
            [f1, f2]
        }).collect();

        // 1. Bundle creation with 32 vouchers, 320 fps and 96 q-pairs MUST succeed
        let (bundle_bytes, bundle) = create_and_encrypt_bundle(
            alice,
            vouchers_32.clone(),
            &bob.user_id,
            None,
            fps_320.clone(),
            q_pairs_96.clone(),
            None,
        ).expect("Bundle creation with 32 vouchers and 320 fingerprints must succeed");

        assert_eq!(bundle.vouchers.len(), 32);
        assert_eq!(bundle.forwarded_fingerprints.len(), 320);
        assert_eq!(bundle.quarantine_pairs.len(), 96);

        // 2. Open and verify on recipient side MUST succeed
        let received_bundle = open_and_verify_bundle(bob, &bundle_bytes)
            .expect("Bundle opening with 32 vouchers and 320 fingerprints must succeed");
        assert_eq!(received_bundle.vouchers.len(), 32);
        assert_eq!(received_bundle.forwarded_fingerprints.len(), 320);
        assert_eq!(received_bundle.quarantine_pairs.len(), 96);

        // 3. Exceeding 320 fingerprints (e.g. 321) MUST be rejected
        let mut fps_321 = fps_320.clone();
        fps_321.push(make_signed_fingerprint("ds_scale_extra", "tx_scale_extra", 0));
        let err = create_and_encrypt_bundle(
            alice,
            vouchers_32.clone(),
            &bob.user_id,
            None,
            fps_321,
            q_pairs_96,
            None,
        );
        assert!(err.is_err(), "Bundle with 321 fingerprints for 32 vouchers must be rejected");
    }

    #[test]
    fn test_active_gossip_queue_capacity_bounds() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let header = TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        // Send 3500 foreign gossip fingerprints (cap is 3000)
        let fps_3500: Vec<TransactionFingerprint> = (0..3500).map(|i| {
            make_signed_fingerprint(&format!("ds_bound_{}", i), &format!("tx_bound_{}", i), 0)
        }).collect();

        wallet.process_received_fingerprints(&header, &[], &fps_3500, &[]).unwrap();

        assert_eq!(
            wallet.active_gossip.fresh_gossip_pool.len(),
            3000,
            "Fresh gossip pool must be capped at 3000 entries (FIFO bounded)"
        );
    }

    #[test]
    fn test_storage_cleanup_phase_2_chronological_retention() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // Add 12 fingerprints in foreign_fingerprints with distinct deletable_at dates:
        // 2030, 2031, ..., 2041.
        for i in 0..12 {
            let year = 2030 + i;
            let tag = format!("ds_tag_{:02}", i);
            let mut fp = make_signed_fingerprint(&tag, &format!("tx_id_{:02}", i), 0);
            fp.deletable_at = format!("{}-06-01T00:00:00Z", year);
            wallet.known_fingerprints.foreign_fingerprints.insert(tag, vec![fp]);
        }

        assert_eq!(wallet.known_fingerprints.foreign_fingerprints.len(), 12);

        // Run cleanup with max_limit = 10 (target removal = ceil(12 * 0.15) = 2 entries)
        let report = wallet.run_storage_cleanup(Some(10), 50).unwrap();
        assert_eq!(report.limit_based_fingerprints_removed, 2);
        assert_eq!(wallet.known_fingerprints.foreign_fingerprints.len(), 10);

        // The oldest 2 entries (2030 and 2031: ds_tag_00 and ds_tag_01) MUST have been removed
        assert!(!wallet.known_fingerprints.foreign_fingerprints.contains_key("ds_tag_00"));
        assert!(!wallet.known_fingerprints.foreign_fingerprints.contains_key("ds_tag_01"));
        // Later entries (2032..2041) MUST still be present
        assert!(wallet.known_fingerprints.foreign_fingerprints.contains_key("ds_tag_02"));
        assert!(wallet.known_fingerprints.foreign_fingerprints.contains_key("ds_tag_11"));
    }

    #[test]
    fn test_reproduces_local_tag_invalid_prev_hash() {
        use crate::models::profile::VoucherStore;
        use crate::wallet::instance::{VoucherInstance, VoucherStatus};

        let mut store = VoucherStore::default();
        let mut voucher = create_dummy_voucher_with_txs(2);
        // Sabotage prev_hash with invalid base58
        voucher.transactions[1].prev_hash = "invalid-base58-garbage!!!".to_string();

        store.vouchers.insert(
            "inst_1".to_string(),
            VoucherInstance {
                voucher,
                status: VoucherStatus::Active,
                local_instance_id: "inst_1".to_string(),
            },
        );

        let fp = make_signed_fingerprint("ds_test", "tx_test", 0);

        // Calling resolve_conflict_offline must fail-closed safely without panicking on invalid prev_hash
        crate::wallet::conflicts::resolve_conflict_offline(&mut store, &[fp]);

        // Status must remain Active (not incorrectly quarantined by invalid base58 evaluation)
        assert!(matches!(store.vouchers["inst_1"].status, VoucherStatus::Active));
    }

    #[test]
    fn test_verify_fingerprint_signature_fuzz_malformed_fields() {
        let malformed_inputs = [
            "",
            "not-base-58!?",
            "0", // too short
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111", // too long
        ];

        for malformed in malformed_inputs {
            let mut fp = make_signed_fingerprint("ds", "tx", 0);
            fp.sender_ephemeral_pub = malformed.to_string();
            assert!(!crate::services::conflict_manager::verify_fingerprint_signature(&fp));

            let mut fp2 = make_signed_fingerprint("ds", "tx", 0);
            fp2.t_id = malformed.to_string();
            assert!(!crate::services::conflict_manager::verify_fingerprint_signature(&fp2));

            let mut fp3 = make_signed_fingerprint("ds", "tx", 0);
            fp3.layer2_signature = malformed.to_string();
            assert!(!crate::services::conflict_manager::verify_fingerprint_signature(&fp3));
        }
    }

    #[test]
    fn test_clock_drift_protection_skips_expiration_sweep() {
        let dir = tempdir().unwrap();
        let password = "correct_password";
        let (mut app, profile_info) =
            crate::test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", password);
        app.unlock_session(password, 60).unwrap();

        // Create a voucher that is technically expired relative to now
        let past_valid_until = "2020-01-01T00:00:00Z".to_string();
        let voucher = Voucher {
            voucher_id: "v_expired_test".to_string(),
            valid_until: past_valid_until,
            creation_date: "2019-01-01T00:00:00Z".to_string(),
            ..Default::default()
        };
        let mut storage = FileStorage::new(dir.path().join(&profile_info.folder_name));
        let auth = AuthMethod::Password(password);

        app.get_wallet_mut().unwrap().add_voucher_instance("inst_drift".to_string(), voucher, VoucherStatus::Active);
        app.get_wallet_mut().unwrap().save(&mut storage, &ACTORS.alice.identity, &auth).unwrap();

        // 1. With normal seal (timestamp = now), loading triggers expiration sweep:
        let (loaded_normal, _) =
            crate::wallet::Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();
        assert_eq!(
            loaded_normal.voucher_store.vouchers["inst_drift"].status,
            VoucherStatus::Expired
        );

        // Reset voucher to Active and persist to disk
        app.get_wallet_mut().unwrap().voucher_store.vouchers.get_mut("inst_drift").unwrap().status = VoucherStatus::Active;
        app.get_wallet_mut().unwrap().save(&mut storage, &ACTORS.alice.identity, &auth).unwrap();

        // 2. Simulate clock drift backward: seal timestamp in the future (2099)
        let future_seal = crate::models::seal::WalletSeal {
            payload: crate::models::seal::SealPayload {
                version: 1,
                user_id: ACTORS.alice.identity.user_id.clone(),
                epoch: 0,
                epoch_start_time: "2099-01-01T00:00:00Z".to_string(),
                tx_nonce: 0,
                prev_seal_hash: "none".to_string(),
                state_hash: "hash".to_string(),
                timestamp: "2099-01-01T00:00:00Z".to_string(),
                instance_id: "test-id".to_string(),
            },
            signature: "sig".to_string(),
        };
        let seal_record = crate::models::seal::LocalSealRecord {
            seal: future_seal,
            sync_status: crate::models::seal::SyncStatus::Synced,
            is_locked_due_to_fork: false,
        };
        storage.save_seal(&auth, &seal_record).unwrap();

        // Loading the wallet now detects clock drift backward -> skips expiration sweep!
        let (loaded_drift_back, _) =
            crate::wallet::Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();
        assert_eq!(
            loaded_drift_back.voucher_store.vouchers["inst_drift"].status,
            VoucherStatus::Active,
            "Expiration sweep must be skipped when clock went backward relative to seal"
        );

        // 3. Simulate clock drift forward by > 30 days: seal timestamp is 60 days in the past
        let sixty_days_ago = chrono::Utc::now() - chrono::Duration::days(60);
        let sixty_days_ago_str = sixty_days_ago.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let past_seal = crate::models::seal::WalletSeal {
            payload: crate::models::seal::SealPayload {
                version: 1,
                user_id: ACTORS.alice.identity.user_id.clone(),
                epoch: 0,
                epoch_start_time: sixty_days_ago_str.clone(),
                tx_nonce: 0,
                prev_seal_hash: "none".to_string(),
                state_hash: "hash".to_string(),
                timestamp: sixty_days_ago_str,
                instance_id: "test-id".to_string(),
            },
            signature: "sig".to_string(),
        };
        let seal_record_past = crate::models::seal::LocalSealRecord {
            seal: past_seal,
            sync_status: crate::models::seal::SyncStatus::Synced,
            is_locked_due_to_fork: false,
        };
        storage.save_seal(&auth, &seal_record_past).unwrap();

        // Loading the wallet now detects clock drift forward > 30 days -> skips expiration sweep!
        let (loaded_drift_fwd, _) =
            crate::wallet::Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();
        assert_eq!(
            loaded_drift_fwd.voucher_store.vouchers["inst_drift"].status,
            VoucherStatus::Active,
            "Expiration sweep must be skipped when system clock jumped forward by > 30 days"
        );
    }

    #[test]
    fn test_possession_priority_for_local_active_vouchers() {
        use crate::models::profile::VoucherStore;
        use crate::wallet::instance::VoucherInstance;

        let mut store = VoucherStore::default();
        let prev_hash = bs58::encode([2u8; 32]).into_string();
        let eph_bytes = [3u8; 32];
        let eph_pub = bs58::encode(eph_bytes).into_string();

        let local_t_id = bs58::encode([4u8; 32]).into_string();
        let local_tx = Transaction {
            t_id: local_t_id.clone(),
            prev_hash: prev_hash.clone(),
            sender_ephemeral_pub: Some(eph_pub.clone()),
            t_time: "2026-06-01T12:00:00Z".to_string(),
            ..Default::default()
        };
        let voucher = Voucher {
            voucher_id: "v_local_active".to_string(),
            transactions: vec![local_tx.clone()],
            ..Default::default()
        };
        store.vouchers.insert(
            "inst_local".to_string(),
            VoucherInstance {
                voucher,
                status: VoucherStatus::Active,
                local_instance_id: "inst_local".to_string(),
            },
        );

        // Construct a foreign gossip fingerprint with an earlier timestamp
        let foreign_t_id = bs58::encode([5u8; 32]).into_string();
        let ds_tag = crate::services::crypto::get_ds_tag(&prev_hash, &eph_pub).unwrap();

        let foreign_tx = Transaction {
            t_id: foreign_t_id.clone(),
            prev_hash: prev_hash.clone(),
            sender_ephemeral_pub: Some(eph_pub.clone()),
            t_time: "2026-06-01T10:00:00Z".to_string(), // 2 hours earlier!
            ..Default::default()
        };
        let foreign_enc_ts =
            crate::services::conflict_manager::encrypt_transaction_timestamp(&foreign_tx).unwrap();

        let foreign_fp = TransactionFingerprint {
            t_id: foreign_t_id.clone(),
            encrypted_timestamp: foreign_enc_ts,
            created_at_ms: 0,
            ds_tag,
            trap_r: "u".to_string(),
            trap_s: "b".to_string(),
            layer2_signature: "sig".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            sender_ephemeral_pub: eph_pub,
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
        };

        let local_enc_ts =
            crate::services::conflict_manager::encrypt_transaction_timestamp(&local_tx).unwrap();
        let local_fp = TransactionFingerprint {
            t_id: local_t_id,
            encrypted_timestamp: local_enc_ts,
            ..foreign_fp.clone()
        };

        // When both local and foreign fingerprints are passed to resolve_conflict_offline:
        // Even though foreign_fp is earlier, local Active voucher must NOT be quarantined!
        crate::wallet::conflicts::resolve_conflict_offline(&mut store, &[local_fp, foreign_fp]);

        assert_eq!(
            store.vouchers["inst_local"].status,
            VoucherStatus::Active,
            "Local active voucher must retain possession priority against foreign gossip winner"
        );
    }

    #[test]
    fn test_can_skip_l2_spend_lock_invariant() {
        use crate::services::l2_gateway::can_skip_l2_spend_lock;

        // Voucher with 0 transactions
        let empty_voucher = Voucher::default();
        assert!(can_skip_l2_spend_lock(&empty_voucher));

        // Voucher with 1 transaction (genesis/init)
        let init_voucher = Voucher {
            transactions: vec![Transaction {
                t_type: "init".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(can_skip_l2_spend_lock(&init_voucher));

        // Voucher with 2 transactions (circulated/spent) -> cannot skip!
        let spent_voucher = Voucher {
            transactions: vec![
                Transaction {
                    t_type: "init".to_string(),
                    ..Default::default()
                },
                Transaction {
                    t_type: "transfer".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(!can_skip_l2_spend_lock(&spent_voucher));
    }

    #[test]
    fn test_app_service_check_reputation() {
        let dir = tempdir().unwrap();
        let password = "correct_password";
        let (mut app, _) =
            crate::test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", password);
        app.unlock_session(password, 60).unwrap();

        let offender_id = "offender_123";
        // Initially clean
        assert_eq!(
            app.check_reputation(offender_id).unwrap(),
            crate::models::conflict::TrustStatus::Clean
        );

        // Add a signed proof for offender_123
        let proof = create_signed_proof(offender_id);
        let proof_id = proof.proof_id.clone();
        app.get_wallet_mut().unwrap().proof_store.proofs.insert(
            proof_id.clone(),
            ProofStoreEntry {
                proof,
                local_override: false,
                local_note: None,
                conflict_role: ConflictRole::Witness,
            },
        );

        // Now returns KnownOffender(proof_id)
        assert_eq!(
            app.check_reputation(offender_id).unwrap(),
            crate::models::conflict::TrustStatus::KnownOffender(proof_id)
        );
    }

    #[test]
    fn test_known_offender_transaction_blocked_unless_force_accepted() {
        use crate::services::bundle_processor::create_and_encrypt_bundle;
        use crate::services::voucher_validation::StandardRegistry;

        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;
        let mut bob_wallet = setup_in_memory_wallet(&ACTORS.bob);

        let voucher = create_dummy_voucher_with_txs(1);
        let (bundle_bytes, _) = create_and_encrypt_bundle(
            alice,
            vec![voucher],
            &bob.user_id,
            None,
            vec![],
            vec![],
            None,
        ).expect("Bundle creation should succeed");

        // Record a double-spend proof making Alice a known offender in Bob's wallet
        let proof = create_signed_proof(&alice.user_id);
        let proof_id = proof.proof_id.clone();
        bob_wallet.proof_store.proofs.insert(
            proof_id.clone(),
            ProofStoreEntry {
                proof,
                local_override: false,
                local_note: None,
                conflict_role: ConflictRole::Witness,
            },
        );

        let registry = StandardRegistry::new();

        // 1. Without force_accept: bundle from KnownOffender must be rejected with KnownOffenderTransactionBlocked
        let err = bob_wallet.process_bundle_with_registry_inner(
            bob,
            &bundle_bytes,
            None,
            &registry,
            None,
            0,
            false,
        ).unwrap_err();

        match err {
            VoucherCoreError::KnownOffenderTransactionBlocked { id, proof_id: p_id } => {
                assert_eq!(id, alice.user_id);
                assert_eq!(p_id, proof_id);
            }
            other => panic!("Expected KnownOffenderTransactionBlocked, got: {:?}", other),
        }

        // 2. With force_accept: true, KnownOffender check is bypassed
        let res = bob_wallet.process_bundle_with_registry_inner(
            bob,
            &bundle_bytes,
            None,
            &registry,
            None,
            0,
            true,
        );
        if let Err(VoucherCoreError::KnownOffenderTransactionBlocked { .. }) = res {
            panic!("force_accept = true should bypass KnownOffenderTransactionBlocked check");
        }
    }

    #[test]
    fn test_known_offender_voucher_creator_blocked_unless_force_accepted() {
        use crate::services::bundle_processor::create_and_encrypt_bundle;
        use crate::services::voucher_validation::StandardRegistry;

        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;
        let bad_creator_id = "bad_creator_456".to_string();
        let mut bob_wallet = setup_in_memory_wallet(&ACTORS.bob);

        let mut voucher = create_dummy_voucher_with_txs(1);
        voucher.creator_profile.id = Some(bad_creator_id.clone());

        let (bundle_bytes, _) = create_and_encrypt_bundle(
            alice,
            vec![voucher],
            &bob.user_id,
            None,
            vec![],
            vec![],
            None,
        ).expect("Bundle creation should succeed");

        // Record a double-spend proof making the voucher creator a known offender
        let proof = create_signed_proof(&bad_creator_id);
        let proof_id = proof.proof_id.clone();
        bob_wallet.proof_store.proofs.insert(
            proof_id.clone(),
            ProofStoreEntry {
                proof,
                local_override: false,
                local_note: None,
                conflict_role: ConflictRole::Witness,
            },
        );

        let registry = StandardRegistry::new();

        // 1. Without force_accept: bundle with KnownOffender creator must be rejected
        let err = bob_wallet.process_bundle_with_registry_inner(
            bob,
            &bundle_bytes,
            None,
            &registry,
            None,
            0,
            false,
        ).unwrap_err();

        match err {
            VoucherCoreError::KnownOffenderTransactionBlocked { id, proof_id: p_id } => {
                assert_eq!(id, bad_creator_id);
                assert_eq!(p_id, proof_id);
            }
            other => panic!("Expected KnownOffenderTransactionBlocked, got: {:?}", other),
        }

        // 2. With force_accept: true, KnownOffender check is bypassed
        let res = bob_wallet.process_bundle_with_registry_inner(
            bob,
            &bundle_bytes,
            None,
            &registry,
            None,
            0,
            true,
        );
        if let Err(VoucherCoreError::KnownOffenderTransactionBlocked { .. }) = res {
            panic!("force_accept = true should bypass KnownOffenderTransactionBlocked check for creator");
        }
    }
}


