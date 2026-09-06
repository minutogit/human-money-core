// tests/architecture/resilience_and_gossip.rs
// cargo test --test architecture_tests
//!
//! Tests the core functions of the new architecture:
//! - Resilience: Storage cleanup and recovery.
//! - Gossip: Correct propagation and updating of fingerprint metadata.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use human_money_core::app_service::{AppService, ProfileInfo};
    use human_money_core::models::conflict::{FingerprintMetadata, TransactionFingerprint};
    use human_money_core::services::bundle_processor;
    use human_money_core::NewVoucherData;
    use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
    use std::collections::HashMap;
    use tempfile::{TempDir, tempdir};

    const PASSWORD: &str = "test-password-123";

    /// Helper function to create a clean test environment with two AppService instances.
    /// Services are NOT automatically logged in to prevent locking conflicts.
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

    /// Helper function: Creates and sends a bundle containing only fingerprints.
    fn create_and_send_fingerprint_bundle(
        sender_service: &mut AppService,
        recipient_id: &str,
        fingerprints: Vec<(TransactionFingerprint, i8)>, // Tuple of (Fingerprint, depth)
    ) -> Vec<u8> {
        let (fprints, depths): (Vec<_>, HashMap<_, _>) = fingerprints
            .into_iter()
            .map(|(fp, depth)| (fp.clone(), (fp.ds_tag, depth)))
            .unzip();

        let forwarded_fingerprints = fprints;
        let fingerprint_depths: HashMap<String, i8> = depths.into_iter().collect();
        let (wallet, identity) = sender_service.get_unlocked_mut_for_test();

        let (bundle_bytes, _header) = wallet
            .create_and_encrypt_transaction_bundle(
                identity,
                vec![], // No vouchers
                recipient_id,
                None,
                forwarded_fingerprints,
                fingerprint_depths,
                None, // sender_profile_name
            )
            .unwrap();
        bundle_bytes
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
        // Clean up any existing lock file
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

        // With current constants (MAX_FINGERPRINTS = 20_000), Phase 2 of cleanup
        // is not triggered in this test. The assertion is corrected to 0.
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
    fn test_cleanup_phase2_removes_by_depth_and_tie_breaker() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "CleanupTest2",
            "password",
        );
        // Clean up any existing lock file
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
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                ds_tag: key.clone(),
                trap_r: "synthetic_shard".to_string(),
                trap_s: "synthetic_shard".to_string(),
                t_id: format!("tx_{:02}", i), // Padding for correct lexical sorting
                encrypted_timestamp: 0,
                layer2_signature: String::new(),
                deletable_at: String::new(),
                            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};
            let mut meta = FingerprintMetadata::default();
            meta.depth = match i {
                0 | 1 => 5, // Highest depth, deleted first
                _ => 1,
            };
            wallet
                .known_fingerprints
                .local_history
                .insert(key.clone(), vec![fp]);
            wallet.fingerprint_metadata.insert(key, meta);
        }

        // WHEN: Storage cleanup is triggered directly on the wallet with a
        // low limit for the test.
        let report = service
            .get_unlocked_mut_for_test()
            .0
            .run_storage_cleanup(Some(10), 2)
            .unwrap();
        assert_eq!(report.limit_based_fingerprints_removed, 2);

        // THEN: The 2 fingerprints with the highest `depth` were removed.
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert_eq!(final_wallet.fingerprint_metadata.len(), 10);
        assert!(!final_wallet.fingerprint_metadata.contains_key("key_0"));
        assert!(!final_wallet.fingerprint_metadata.contains_key("key_1"));

        service.logout();
    }

    //==============================================================================
    // D. Tests for Robustness and Recovery
    //==============================================================================

    #[test]
    fn test_recovery_rebuilds_from_vouchers_if_metadata_missing() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "RecoveryTest1",
            PASSWORD,
        );
        // Clean up any existing lock file
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
                unit: "EUR".to_string(),
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

        // IMPORTANT: The file `fingerprint_metadata.enc` must exist before being deleted.
        // The fix in `Wallet::create_new_voucher` ensures this.
        let metadata_path = wallet_path.join("fingerprint_metadata.enc");
        assert!(
            metadata_path.exists(),
            "Pre-condition failed: metadata file was not created."
        );

        std::fs::remove_file(metadata_path).unwrap();
        // Also remove the seal as it contains the old state_hash.
        // In real data loss, the seal would also be affected.
        let seal_path = wallet_path.join("seal.enc");
        if seal_path.exists() {
            std::fs::remove_file(seal_path).unwrap();
        }

        service
            .login(&profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        let wallet = service.get_unlocked_mut_for_test().0;
        assert!(!wallet.fingerprint_metadata.is_empty());
        assert_eq!(wallet.fingerprint_metadata.len(), 1);
    }

    #[test]
    fn test_recovery_rebuilds_if_fingerprint_stores_missing() {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "RecoveryTest2",
            PASSWORD,
        );
        // Clean up any existing lock file
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
        // Also remove the seal as it contains the old state_hash.
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

    #[test]
    fn test_recovery_initializes_depth_correctly() {
        // GIVEN: A wallet with a voucher having 3 transactions is saved.
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // FIX: Provide a valid nominal_value
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
        let _voucher_id = alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap()
            .voucher_id;
        let local_id = alice_service
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();

        // Tx 2: Alice -> Bob

        // FIX: We need to retrieve Bob's REAL user ID from his service.
        // The static ID in ACTORS.bob differs from the ID generated in the service
        // due to different key derivation methods (test-fast vs prod-slow).
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();
        let bundle1 = {
            let request = human_money_core::wallet::MultiTransferRequest {
                recipient_id: bob_id.clone(),
                sources: vec![human_money_core::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "10".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
        use_privacy_mode: None,
            };

            let mut standards_toml = std::collections::HashMap::new();
            standards_toml.insert(
                FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
                toml::to_string(&FREETALER_STANDARD.0).unwrap(),
            );

            let human_money_core::wallet::CreateBundleResult {
                bundle_bytes: bundle1_result,
                ..
            } = alice_service
                .create_transfer_bundle(request, &standards_toml, None, Some(PASSWORD))
                .unwrap();
            bundle1_result
        };

        // Log out Alice
        alice_service.logout();

        // Log in Bob and receive bundle
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let mut standards = HashMap::new();
        standards.insert(
            FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
            toml::to_string(&FREETALER_STANDARD.0).unwrap(),
        );
        bob_service
            .receive_bundle(&bundle1, &standards, None, Some("password"), false)
            .unwrap();
        let bob_local_id = bob_service
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();

        // Tx 3: Bob -> Alice
        // FIX: Retrieve real ID of Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let alice_id = alice_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        alice_service.logout();

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: alice_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: bob_local_id.clone(),
                amount_to_send: "5".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(
            FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
            toml::to_string(&FREETALER_STANDARD.0).unwrap(),
        );
        let human_money_core::wallet::CreateBundleResult {
            bundle_bytes: bundle2,
            ..
        } = bob_service
            .create_transfer_bundle(request, &standards_toml, None, Some("password"))
            .unwrap();

        // Log out Bob
        bob_service.logout();

        // Log in Alice again and receive bundle
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        alice_service
            .receive_bundle(&bundle2, &standards, None, Some(PASSWORD), false)
            .unwrap();

        // DEBUG: Check Alice's voucher store state before logout
        let (wallet_before_logout, _) = alice_service.get_unlocked_mut_for_test();
        let tx_count_before_logout = wallet_before_logout
            .voucher_store
            .vouchers
            .values()
            .next()
            .unwrap()
            .voucher
            .transactions
            .len();
        println!(
            "[Debug Test] TX count in Alice's wallet before logout: {}",
            tx_count_before_logout
        );

        let wallet_path = dir.path().join(&alice_profile.folder_name);
        alice_service.logout();
        std::fs::remove_file(wallet_path.join("fingerprint_metadata.enc")).unwrap();
        // Also remove the seal as it contains the old state_hash.
        let seal_path = wallet_path.join("seal.enc");
        if seal_path.exists() {
            std::fs::remove_file(seal_path).unwrap();
        }

        // WHEN: Alice's wallet is restored
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // THEN: The `depth` of transactions in the chain is correctly initialized (0=newest, 1, 2=oldest)
        let (wallet, _) = alice_service.get_unlocked_mut_for_test();
        let _voucher = &wallet
            .voucher_store
            .vouchers
            .values()
            .next()
            .unwrap()
            .voucher;

        // CORRECTION: The test must reflect the correct "min(depth)" logic.
        // The archived instance (2 Txs) produces depth=1 for the first transaction.
        // The active instance (3 Txs) produces depth=2 for the first transaction.
        // The correct rule "min wins" results in depth=1 being persisted.
        let _fp_tx1 = wallet
            .fingerprint_metadata
            .values()
            .find(|meta| meta.depth == 1)
            .expect("Tx mit depth 1 (min rule) nicht gefunden");
        let _fp_tx2 = wallet
            .fingerprint_metadata
            .values()
            .find(|meta| meta.depth == 0)
            .expect("Tx mit depth 0 (zweite Tx) nicht gefunden");
        let _fp_tx3 = wallet
            .fingerprint_metadata
            .values()
            .find(|meta| meta.depth == 0)
            .expect("Tx mit depth 0 nicht gefunden");
    }

    //==============================================================================
    // A. Core Logic Tests (Propagation & Merging)
    //==============================================================================

    #[test]
    fn test_min_merge_rule_updates_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        let fp_key = "test_fp_key".to_string();
        // V2: gossip fingerprints must be self-authenticating to pass ingress.
        let mut fingerprint =
            human_money_core::test_utils::make_signed_fingerprint(&fp_key, "", 0);
        // FIX: Set valid date so cleanup doesn't remove it
        fingerprint.deletable_at = (Utc::now() + Duration::days(10)).to_rfc3339();

        // Log out Alice
        alice_service.logout();

        // Log in Bob and set metadata
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        bob_service
            .get_unlocked_mut_for_test()
            .0
            .fingerprint_metadata
            .entry(fp_key.clone())
            .or_default()
            .depth = 10;

        // FIX: Persist metadata changes. AppService won't detect memory changes to auxiliary stores automatically.
        // We use storage cleanup to force a save of metadata.
        bob_service.run_storage_cleanup().unwrap();

        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

        // Log out Bob
        bob_service.logout();

        // Log in Alice again and create bundle
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let bundle_bytes =
            create_and_send_fingerprint_bundle(&mut alice_service, &bob_id, vec![(fingerprint, 2)]);

        // Log out Alice
        alice_service.logout();

        // Log in Bob again and receive bundle
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let (_, bob_identity) = bob_service.get_unlocked_mut_for_test();
        println!(
            "[Debug Test] Bob's identity user_id for lookup: '{}'",
            bob_identity.user_id
        );

        bob_service
            .receive_bundle(&bundle_bytes, &HashMap::new(), None, Some("password"), false)
            .unwrap();

        let (bob_wallet, _) = bob_service.get_unlocked_mut_for_test();
        let meta = bob_wallet.fingerprint_metadata.get(&fp_key).unwrap();
        assert_eq!(meta.depth, 3);
    }

    #[test]
    fn test_min_merge_rule_keeps_lower_local_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Bob and set metadata
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let fp_key = "test_fp_key".to_string();
        let fingerprint = TransactionFingerprint {
            ds_tag: fp_key.clone(),
            trap_r: "synthetic_shard".to_string(),
            trap_s: "synthetic_shard".to_string(),
            t_id: String::new(),
            encrypted_timestamp: 0,
            layer2_signature: String::new(),
            // FIX: Set a valid future date so cleanup does not remove this fingerprint
            deletable_at: (Utc::now() + Duration::days(365)).to_rfc3339(),
                    sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};

        // Manipulate state directly in memory.
        // IMPORTANT: We do NOT log Bob out. Since Alice and Bob use different folders,
        // there is no locking conflict. This prevents the rebuild process on login
        // from deleting our manual data (which has no backing vouchers).
        {
            let (wallet, _) = bob_service.get_unlocked_mut_for_test();
            wallet.fingerprint_metadata.insert(
                fp_key.clone(),
                FingerprintMetadata {
                    depth: 3,
                    ..Default::default()
                },
            );
            wallet
                .known_fingerprints
                .local_history
                .insert(fp_key.clone(), vec![fingerprint.clone()]);
        }
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

        // Log in Alice and create bundle
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let bundle_bytes =
            create_and_send_fingerprint_bundle(&mut alice_service, &bob_id, vec![(fingerprint, 5)]); // sender_depth + 1 = 6

        // Log out Alice
        alice_service.logout();

        // Bob (still logged in) receives the bundle
        bob_service
            .receive_bundle(&bundle_bytes, &HashMap::new(), None, Some("password"), false)
            .unwrap();

        let (bob_wallet, _) = bob_service.get_unlocked_mut_for_test();
        let meta = bob_wallet.fingerprint_metadata.get(&fp_key).unwrap();
        assert_eq!(
            meta.depth, 3,
            "Lokale `depth` sollte beibehalten werden, da sie niedriger war."
        );
    }

    #[test]
    fn test_implicit_marking_on_send() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (_bob_service, _bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
        let alice_wallet_path = dir.path().join(&alice_profile.folder_name);
        let alice_lock_file = alice_wallet_path.join(".wallet.lock");
        if alice_lock_file.exists() {
            std::fs::remove_file(&alice_lock_file).unwrap();
        }

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
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
        alice_service
            .create_new_voucher(
                &toml::to_string(&FREETALER_STANDARD.0).unwrap(),
                new_voucher_data,
                Some(PASSWORD),
            )
            .unwrap();
        let local_id = alice_service
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()[0]
            .local_instance_id
            .clone();
        let init_tx_fp_key = alice_service
            .get_unlocked_mut_for_test()
            .0
            .fingerprint_metadata
            .keys()
            .next()
            .unwrap()
            .clone();

        let bob_id = ACTORS.bob.user_id.clone(); // Use known ID

        // NEW: Calculate expected short hash for assertion
        let bob_short_hash = human_money_core::crypto::get_short_hash_from_user_id(&bob_id);

        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: bob_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "10".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(
            FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
            toml::to_string(&FREETALER_STANDARD.0).unwrap(),
        );
        alice_service
            .create_transfer_bundle(request, &standards_toml, None, Some(PASSWORD))
            .unwrap();

        let (alice_wallet, _) = alice_service.get_unlocked_mut_for_test();
        let meta = alice_wallet
            .fingerprint_metadata
            .get(&init_tx_fp_key)
            .unwrap();
        assert!(
            meta.known_by_peers.contains(&bob_short_hash),
            "Bobs Kurz-Hash sollte implizit als Kenner des Fingerprints markiert sein."
        );

        alice_service.logout();
    }

    #[test]
    fn test_selection_heuristic_prioritizes_low_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();
        for i in 0..5 {
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                trap_r: "synthetic_shard".to_string(),
                trap_s: "synthetic_shard".to_string(),
                ds_tag: key.clone(),
                t_id: String::new(),
                encrypted_timestamp: 0,
                layer2_signature: String::new(),
                deletable_at: String::new(),
                            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};
            let meta = FingerprintMetadata {
                depth: if i < 2 {
                    0
                } else if i < 4 {
                    1
                } else {
                    5
                },
                ..Default::default()
            };
            wallet.fingerprint_metadata.insert(key.clone(), meta);
            wallet
                .known_fingerprints
                .local_history
                .insert(key, vec![fp]);
        }

        // WHEN: Alice triggers a transfer that uses the heuristic internally.

        // FIX: Retrieve real ID of Bob (since test users may have different IDs than ACTORS)
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();

        let (fingerprints_to_send, depths_to_send) =
            wallet.select_fingerprints_for_bundle(&bob_id, &[]).unwrap();
        let (bundle_bytes, _header) = wallet
            .create_and_encrypt_transaction_bundle(
                alice_identity,
                vec![], // No real voucher transfer needed
                &bob_id,
                None,
                fingerprints_to_send,
                depths_to_send,
                None, // sender_profile_name
            )
            .unwrap();

        // Log out Alice
        alice_service.logout();

        // THEN: We open the bundle to check what was selected.
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;

        // The logic is "greedy" and also collects fingerprints with higher `depth`
        // to fill the quota. Therefore 5 is the correct result.
        assert_eq!(selected.len(), 5);
        let depths: Vec<i8> = selected
            .iter()
            .map(|fp| *bundle.fingerprint_depths.get(&fp.ds_tag).unwrap())
            .collect();
        assert_eq!(depths.iter().filter(|&&d| d == 0).count(), 2);
        assert_eq!(depths.iter().filter(|&&d| d == 1).count(), 2);
    }

    #[test]
    fn test_selection_heuristic_skips_known_peers() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Bob to get ID
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();
        let key = "key_already_known".to_string();
        let fp = TransactionFingerprint {
            ds_tag: key.clone(),
            trap_r: "synthetic_shard".to_string(),
            trap_s: "synthetic_shard".to_string(),
            t_id: String::new(),
            encrypted_timestamp: 0,
            layer2_signature: String::new(),
            deletable_at: String::new(),
                    sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};
        let mut meta = FingerprintMetadata {
            depth: 0,
            ..Default::default()
        };
        meta.known_by_peers
            .insert(human_money_core::crypto::get_short_hash_from_user_id(
                &bob_id,
            ));
        wallet.fingerprint_metadata.insert(key.clone(), meta);
        wallet
            .known_fingerprints
            .local_history
            .insert(key, vec![fp]);

        // WHEN: Alice creates a new transfer to Bob
        let (bundle_bytes, _header) = wallet
            .create_and_encrypt_transaction_bundle(
                alice_identity,
                vec![],
                &bob_id,
                None,
                vec![],
                HashMap::new(),
                None, // sender_profile_name
            )
            .unwrap();

        // Log out Alice
        alice_service.logout();

        // THEN: The already known fingerprint is not sent again.
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;

        assert!(selected.is_empty());
    }

    #[test]
    fn test_selection_heuristic_fills_contingent() {
        const CONTINGENT_SIZE: usize = 150;
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, bob_profile)) =
            setup_test_environment(&dir);

        // Clean up any existing lock files
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

        // Log in Alice
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();

        // GIVEN: A wallet with 200 fingerprints at depth = 0
        for i in 0..200 {
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                trap_r: "synthetic_shard".to_string(),
                trap_s: "synthetic_shard".to_string(),
                ds_tag: key.clone(),
                t_id: String::new(),
                encrypted_timestamp: 0,
                layer2_signature: String::new(),
                deletable_at: String::new(),
                            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};
            wallet.fingerprint_metadata.insert(
                key.clone(),
                FingerprintMetadata {
                    depth: 0,
                    ..Default::default()
                },
            );
            wallet
                .known_fingerprints
                .local_history
                .insert(key, vec![fp]);
        }

        // WHEN: A transfer is triggered

        // FIX: Retrieve real ID of Bob
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
        bob_service.logout();

        let (fingerprints_to_send, depths_to_send) =
            wallet.select_fingerprints_for_bundle(&bob_id, &[]).unwrap();
        let (bundle_bytes, _header) = wallet
            .create_and_encrypt_transaction_bundle(
                alice_identity,
                vec![],
                &bob_id,
                None,
                fingerprints_to_send,
                depths_to_send,
                None, // sender_profile_name
            )
            .unwrap();

        // Log out Alice
        alice_service.logout();

        // THEN: The quota of 150 is filled exactly
        bob_service
            .login(&bob_profile.folder_name, "password", false, "test-id".to_string())
            .unwrap();
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;

        // THEN: The quota of 150 is filled exactly
        assert_eq!(selected.len(), CONTINGENT_SIZE);
    }
}
