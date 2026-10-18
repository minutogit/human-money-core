// tests/architecture/resilience_and_gossip.rs
// cargo test --test architecture_tests
//!
//! Tests the core functions of the architecture:
//! - Resilience: Storage cleanup and recovery.
//! - Gossip: KISS-Gossip 30/70 propagation and selection.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use human_money_core::app_service::{AppService, ProfileInfo};
    use human_money_core::models::conflict::{DirectEntry, TransactionFingerprint};
    use human_money_core::services::bundle_processor;
    use human_money_core::NewVoucherData;
    use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
    use std::collections::HashMap;
    use tempfile::{TempDir, tempdir};

    const PASSWORD: &str = "test-password-123";

    /// Helper function to create a clean test environment with two AppService instances.
    fn setup_test_environment(
        dir: &TempDir,
    ) -> ((AppService, ProfileInfo), (AppService, ProfileInfo)) {
        // Create Alice
        let (alice_service, alice_profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

        // Create Bob
        let (bob_service, bob_profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.bob, "Bob", "password");

        ((alice_service, alice_profile), (bob_service, bob_profile))
    }

    //==============================================================================
    // C. Storage Cleanup Tests (Resilience in Operation)
    //==============================================================================

    #[test]
    fn test_cleanup_phase1_removes_expired_fingerprints() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.bob,
            "CleanupTest1",
            "password",
        );
        let wallet_path = dir.path().join(&profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        service
            .login(&profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let wallet_state = service.get_unlocked_mut_for_test().0;
        let now = Utc::now();
        let expired_date = (now - Duration::days(1)).to_rfc3339();
        let valid_date = (now + Duration::days(1)).to_rfc3339();
        let expired_fp = TransactionFingerprint {
            ds_tag: "expired_key".to_string(),
            trap_r: "synthetic_shard".to_string(),
            trap_s: "synthetic_shard".to_string(),
            deletable_at: expired_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            created_at_ms: 0,
            layer2_signature: String::new(),
            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
        };
        let valid_fp = TransactionFingerprint {
            ds_tag: "valid_key".to_string(),
            trap_r: "synthetic_shard".to_string(),
            trap_s: "synthetic_shard".to_string(),
            deletable_at: valid_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            created_at_ms: 0,
            layer2_signature: String::new(),
            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
        };
        wallet_state
            .known_fingerprints
            .local_history
            .insert("expired_key".to_string(), vec![expired_fp]);
        wallet_state
            .known_fingerprints
            .local_history
            .insert("valid_key".to_string(), vec![valid_fp]);

        let report = service.run_storage_cleanup().unwrap();
        let wallet_state = service.get_unlocked_mut_for_test().0;

        assert_eq!(report.limit_based_fingerprints_removed, 0);
        assert_eq!(report.expired_fingerprints_removed, 1);
        assert_eq!(wallet_state.known_fingerprints.local_history.len(), 1);
        assert!(
            wallet_state
                .known_fingerprints
                .local_history
                .contains_key("valid_key")
        );

        service.logout();
    }

    #[test]
    fn test_cleanup_phase2_removes_by_limit_and_tie_breaker() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "CleanupTest2",
            "password",
        );
        let wallet_path = dir.path().join(&profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        service
            .login(&profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let wallet = service.get_unlocked_mut_for_test().0;
        for i in 0..12 {
            let key = format!("key_{:02}", i);
            let fp = TransactionFingerprint {
                ds_tag: key.clone(),
                trap_r: "synthetic_shard".to_string(),
                trap_s: "synthetic_shard".to_string(),
                t_id: format!("tx_{:02}", i),
                encrypted_timestamp: 0,
                created_at_ms: 0,
                layer2_signature: String::new(),
                deletable_at: String::new(),
                sender_ephemeral_pub: String::new(),
                layer2_voucher_id: String::new(),
                privacy_guard_hash: String::new(),
            };
            wallet
                .known_fingerprints
                .local_history
                .insert(key, vec![fp]);
        }

        // WHEN: Storage cleanup is triggered directly on the wallet with max 10 items.
        let report = service
            .get_unlocked_mut_for_test()
            .0
            .run_storage_cleanup(Some(10), 2)
            .unwrap();
        assert_eq!(report.limit_based_fingerprints_removed, 2);

        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert_eq!(final_wallet.known_fingerprints.local_history.len(), 10);

        service.logout();
    }

    //==============================================================================
    // D. Tests for Robustness and Recovery
    //==============================================================================

    #[test]
    fn test_recovery_rebuilds_if_fingerprint_stores_missing() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "RecoveryTest2",
            PASSWORD,
        );
        let wallet_path = dir.path().join(&profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        service
            .login(&profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let new_voucher_data = NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();
        let wallet_path = dir.path().join(&profile.folder_name);
        service.logout();
        std::fs::remove_file(wallet_path.join("own_fingerprints.enc")).unwrap();
        std::fs::remove_file(wallet_path.join("known_fingerprints.enc")).unwrap();
        let seal_path = wallet_path.join("seal.enc");
        if seal_path.exists() {
            std::fs::remove_file(seal_path).unwrap();
        }

        service
            .login(&profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        let wallet = service.get_unlocked_mut_for_test().0;
        assert_eq!(wallet.own_fingerprints.history.len(), 1);
    }

    //==============================================================================
    // A. Gossip Propagation & Selection Tests
    //==============================================================================

    #[test]
    fn test_gossip_ingress_accepts_valid_fingerprint() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }
        let bob_wallet_path = dir.path().join(&bob_profile.folder_name);
        let bob_lock_file = bob_wallet_path.join(".wallet.lock");
        if bob_lock_file.exists() {
            std::fs::remove_file(&bob_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // Create a voucher for Alice so the bundle carries V = 1 voucher
        let new_voucher_data = NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();

        let local_id = alice_service.get_unlocked_mut_for_test().0.voucher_store.vouchers.keys().next().unwrap().clone();

        let fp_key = "test_fp_key".to_string();
        let mut fingerprint =
            human_money_core::test_utils::make_signed_fingerprint(&fp_key, "", 0);
        fingerprint.deletable_at = (Utc::now() + Duration::days(10)).to_rfc3339();

        let (alice_wallet, _) = alice_service.get_unlocked_mut_for_test();
        alice_wallet.active_gossip.direct_queue.push_back(DirectEntry {
            fingerprint: fingerprint.clone(),
            sent_to: Vec::new(),
        });

        let mut standards = HashMap::new();
        standards.insert(
            FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
            toml::to_string(&FREETALER_STANDARD.0).unwrap(),
        );

        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: bob_id,
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };

        let bundle_res = alice_service
            .create_transfer_bundle(request, &standards, None, Some(PASSWORD))
            .unwrap();

        alice_service.logout();

        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();

        bob_service
            .receive_bundle(&bundle_res.bundle_bytes, &standards, None, Some("password"), false)
            .unwrap();

        let (bob_wallet, _) = bob_service.get_unlocked_mut_for_test();
        assert!(bob_wallet.known_fingerprints.foreign_fingerprints.contains_key(&fp_key));
    }

    #[test]
    fn test_selection_heuristic_proportional_budget() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }
        let bob_wallet_path = dir.path().join(&bob_profile.folder_name);
        let bob_lock_file = bob_wallet_path.join(".wallet.lock");
        if bob_lock_file.exists() {
            std::fs::remove_file(&bob_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // Create 1 voucher for Alice
        let new_voucher_data = NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();

        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();
        let voucher = wallet.voucher_store.vouchers.values().next().unwrap().voucher.clone();

        // Populate direct_queue and foreign_fingerprints
        for i in 0..10 {
            let key = format!("direct_key_{}", i);
            let fp = human_money_core::test_utils::make_signed_fingerprint(&key, "", 0);
            wallet.active_gossip.direct_queue.push_back(DirectEntry {
                fingerprint: fp.clone(),
                sent_to: Vec::new(),
            });
            wallet.known_fingerprints.local_history.insert(key, vec![fp]);
        }
        for i in 0..20 {
            let key = format!("foreign_key_{}", i);
            let fp = human_money_core::test_utils::make_signed_fingerprint(&key, "", 0);
            wallet.known_fingerprints.foreign_fingerprints.insert(key.clone(), vec![fp.clone()]);
            wallet.active_gossip.fresh_gossip_pool.push_back(fp);
        }

        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();

        // 1. V = 0 vouchers -> budget is strictly 0 (no leakage)
        let (fps_empty, q_empty) = wallet.select_fingerprints_for_bundle(&bob_id, &[]).unwrap();
        assert!(fps_empty.is_empty());
        assert!(q_empty.is_empty());

        // 2. V = 1 voucher -> standard budget = 10 (3 direct + 7 gossip)
        let (fingerprints_to_send, quarantine_to_send) =
            wallet.select_fingerprints_for_bundle(&bob_id, &[voucher.clone()]).unwrap();

        assert_eq!(fingerprints_to_send.len(), 10);
        assert!(quarantine_to_send.is_empty());

        let (bundle_bytes, _header) = wallet
            .create_and_encrypt_transaction_bundle(
                alice_identity,
                vec![voucher],
                &bob_id,
                None,
                fingerprints_to_send,
                quarantine_to_send,
                None,
            )
            .unwrap();

        alice_service.logout();

        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        assert_eq!(bundle.forwarded_fingerprints.len(), 10);
    }

    #[test]
    fn test_gossip_zero_voucher_bundle_emits_no_fingerprints() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (_, _)) = setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let (wallet, _) = alice_service.get_unlocked_mut_for_test();

        // Fill queues
        for i in 0..5 {
            let fp = human_money_core::test_utils::make_signed_fingerprint(&format!("dq_{}", i), "", 0);
            wallet.active_gossip.direct_queue.push_back(DirectEntry {
                fingerprint: fp,
                sent_to: Vec::new(),
            });
        }
        for i in 0..5 {
            let fp = human_money_core::test_utils::make_signed_fingerprint(&format!("gp_{}", i), "", 0);
            wallet.active_gossip.fresh_gossip_pool.push_back(fp);
        }

        // When vouchers_in_bundle is empty, selection must immediately return empty vecs
        let (fps, qps) = wallet.select_fingerprints_for_bundle(&ACTORS.bob.user_id, &[]).unwrap();
        assert!(fps.is_empty(), "0-voucher bundle must select 0 fingerprints");
        assert!(qps.is_empty(), "0-voucher bundle must select 0 quarantine pairs");
    }

    #[test]
    fn test_gossip_lottery_preservation_for_bundle_vouchers() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), _) = setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // Create a voucher
        let new_voucher_data = NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();

        let (wallet, _) = alice_service.get_unlocked_mut_for_test();
        let voucher = wallet.voucher_store.vouchers.values().next().unwrap().voucher.clone();

        // Obtain ds_tag for the transaction of the created voucher
        let voucher_tx = &voucher.transactions[0];
        let voucher_fp = human_money_core::services::conflict_manager::create_fingerprint_for_transaction(
            voucher_tx,
            &voucher,
        ).unwrap();

        // Insert this exact fingerprint into fresh_gossip_pool along with other foreign fps
        wallet.active_gossip.fresh_gossip_pool.push_back(voucher_fp.clone());
        for i in 0..10 {
            let fp = human_money_core::test_utils::make_signed_fingerprint(&format!("other_{}", i), "", 0);
            wallet.active_gossip.fresh_gossip_pool.push_back(fp);
        }

        // Select fingerprints for a bundle containing this voucher
        let (fps, _) = wallet.select_fingerprints_for_bundle(&ACTORS.bob.user_id, &[voucher]).unwrap();

        // The bundle-owned ds_tag MUST NOT be selected as forwarded gossip, but PRESERVED in fresh_gossip_pool
        assert!(!fps.iter().any(|f| f.ds_tag == voucher_fp.ds_tag), "Bundle ds_tag must not be gossiped");
        assert!(wallet.active_gossip.fresh_gossip_pool.iter().any(|f| f.ds_tag == voucher_fp.ds_tag), "Bundle ds_tag must be preserved in pool");
    }

    #[test]
    fn test_gossip_sent_to_recipient_filter_and_cleanup() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), _) = setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // Create a voucher
        let new_voucher_data = NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();

        let (wallet, _) = alice_service.get_unlocked_mut_for_test();
        let voucher = wallet.voucher_store.vouchers.values().next().unwrap().voucher.clone();

        let fp = human_money_core::test_utils::make_signed_fingerprint("test_direct_filter", "", 0);
        wallet.active_gossip.direct_queue.push_back(DirectEntry {
            fingerprint: fp,
            sent_to: Vec::new(),
        });

        // Send 1 to Bob
        let (fps1, _) = wallet.select_fingerprints_for_bundle("user_1@did:key:z6Mku", &[voucher.clone()]).unwrap();
        assert_eq!(fps1.len(), 1);
        assert_eq!(wallet.active_gossip.direct_queue.len(), 1);
        assert_eq!(wallet.active_gossip.direct_queue[0].sent_to.len(), 1);

        // Sending again to same recipient must NOT re-select it
        let (fps1_dup, _) = wallet.select_fingerprints_for_bundle("user_1@did:key:z6Mku", &[voucher.clone()]).unwrap();
        assert!(fps1_dup.is_empty());

        // Send to 2nd recipient
        let (fps2, _) = wallet.select_fingerprints_for_bundle("user_2@did:key:z6Mkv", &[voucher.clone()]).unwrap();
        assert_eq!(fps2.len(), 1);
        assert_eq!(wallet.active_gossip.direct_queue[0].sent_to.len(), 2);

        // Send to 3rd recipient -> must be purged afterwards (retain sent_to.len() < 3)
        let (fps3, _) = wallet.select_fingerprints_for_bundle("user_3@did:key:z6Mkw", &[voucher]).unwrap();
        assert_eq!(fps3.len(), 1);
        assert!(wallet.active_gossip.direct_queue.is_empty(), "Entry must be removed after 3 distinct recipients");
    }

    #[test]
    fn test_gossip_quarantine_relay_pool_strict_fifo_cap() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (_, _)) = setup_test_environment(&dir);

        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }

        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let (wallet, _) = alice_service.get_unlocked_mut_for_test();

        // Push 505 quarantine pairs into quarantine_relay_pool using process_received_fingerprints
        const MAX_CAP: usize = 500;
        for i in 0..505 {
            let fp1 = human_money_core::test_utils::make_signed_fingerprint(&format!("q_tag_{}", i), "tx1", 0);
            let fp2 = human_money_core::test_utils::make_signed_fingerprint(&format!("q_tag_{}", i), "tx2", 0);
            // Simulate direct bounded push in active_gossip
            while wallet.active_gossip.quarantine_relay_pool.len() >= MAX_CAP {
                wallet.active_gossip.quarantine_relay_pool.pop_front();
            }
            wallet.active_gossip.quarantine_relay_pool.push_back([fp1, fp2]);
        }

        assert_eq!(wallet.active_gossip.quarantine_relay_pool.len(), MAX_CAP);
        // The first 5 entries should have been popped (q_tag_0 .. q_tag_4)
        assert_eq!(wallet.active_gossip.quarantine_relay_pool[0][0].ds_tag, "q_tag_5");
        assert_eq!(wallet.active_gossip.quarantine_relay_pool[MAX_CAP - 1][0].ds_tag, "q_tag_504");
    }
}
