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
        let (_, q_pairs_1) = wallet.select_fingerprints_for_bundle("bob", &[v1.clone()]).unwrap();
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
        let (sel1, _) = wallet.select_fingerprints_for_bundle("bob", &[v1.clone()]).unwrap();
        assert!(sel1.iter().any(|f| f.t_id == tip_tid), "Tip must be sent to Bob on first transfer");

        // 2nd payment to Bob: direct tip is NOT selected (already known by Bob)
        let (sel2, _) = wallet.select_fingerprints_for_bundle("bob", &[v1.clone()]).unwrap();
        assert!(!sel2.iter().any(|f| f.t_id == tip_tid), "Tip must NOT be sent to Bob again");

        // 1st payment to Charlie: direct tip IS selected
        let (sel3, _) = wallet.select_fingerprints_for_bundle("charlie", &[v1.clone()]).unwrap();
        assert!(sel3.iter().any(|f| f.t_id == tip_tid), "Tip must be sent to Charlie on first transfer");

        // 1st payment to Dave: direct tip IS selected (3rd distinct recipient)
        let (sel4, _) = wallet.select_fingerprints_for_bundle("dave", &[v1.clone()]).unwrap();
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
}

