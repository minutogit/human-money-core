// tests/architecture/hardening.rs
// cargo test --test architecture_tests
//!
//! Contains "hardening tests" that verify the robustness of the architecture in
//! edge cases and consistency checks.

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use human_money_core::models::conflict::TransactionFingerprint;
    use human_money_core::NewVoucherData;
    use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
    use tempfile::tempdir;

    const PASSWORD: &str = "test-password-123";

    #[test]
    fn test_cleanup_synchronizes_stores() {
        // GIVEN: A wallet with an expired fingerprint present in both stores.
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.bob,
            "HardeningTest1",
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

        let wallet = service.get_unlocked_mut_for_test().0;
        let expired_date = (Utc::now() - Duration::days(1)).to_rfc3339();
        let key = "expired_key".to_string();

        let expired_fp = TransactionFingerprint {
            ds_tag: key.clone(),
            trap_r: String::new(),
            trap_s: String::new(),
            deletable_at: expired_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            layer2_signature: String::new(),
                    sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
};

        // Add the fingerprint to both relevant stores
        wallet
            .known_fingerprints
            .local_history
            .insert(key.clone(), vec![expired_fp]);
        wallet.fingerprint_metadata.entry(key.clone()).or_default();

        assert!(
            wallet.known_fingerprints.local_history.contains_key(&key),
            "Pre-condition: Fingerprint must be in history"
        );
        assert!(
            wallet.fingerprint_metadata.contains_key(&key),
            "Pre-condition: Metadata must exist for fingerprint"
        );

        // WHEN: Storage cleanup is executed.
        service.run_storage_cleanup().unwrap();

        // THEN: The fingerprint was removed synchronously from BOTH stores.
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert!(
            !final_wallet
                .known_fingerprints
                .local_history
                .contains_key(&key),
            "Fingerprint should be removed from history"
        );
        assert!(
            !final_wallet.fingerprint_metadata.contains_key(&key),
            "Metadata should be removed simultaneously"
        );

        service.logout();
    }

    #[test]
    fn test_recovery_handles_split_transaction_chain() {
        // GIVEN: A wallet with a voucher that was split.
        let dir = tempdir().unwrap();
        let (mut alice_service, alice_profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "RecoveryTest3",
            PASSWORD,
        );
        // Clean up any existing lock file
        let wallet_path = dir.path().join(&alice_profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // Create a voucher with 100 units
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
        let voucher = alice_service
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

        let wallet_path = dir.path().join(&alice_profile.folder_name);
        alice_service.logout(); // Saves the state
        // Manually remove lock file
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }

        // Perform a split (send 40 to Bob, keep 60)
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();
        let request = human_money_core::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "40".to_string(),
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

        alice_service.logout(); // Saves state with 2 transactions
        // Manually remove lock file
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }

        // WHEN: Metadata is deleted and the wallet is restored.
        let metadata_path = wallet_path.join("fingerprint_metadata.enc");
        std::fs::remove_file(metadata_path).unwrap();
        // Also remove the seal as it contains the old state_hash.
        let seal_path = wallet_path.join("seal.enc");
        if seal_path.exists() {
            std::fs::remove_file(seal_path).unwrap();
        }
        alice_service
            .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
            .unwrap();

        // THEN: The `depth` values of the chain are correctly initialized.
        let wallet = alice_service.get_unlocked_mut_for_test().0;
        let voucher_instance = wallet
            .voucher_store
            .vouchers
            .values()
            .find(|v| v.voucher.voucher_id == voucher.voucher_id)
            .unwrap();
        assert_eq!(
            voucher_instance.voucher.transactions.len(),
            2,
            "Voucher should have two transactions"
        );

        // Find fingerprints for both transactions
        let init_tx_fp_key = voucher_instance.voucher.transactions[0].t_id.clone(); // This is not the key, we need to find it
        let split_tx_fp_key = voucher_instance.voucher.transactions[1].t_id.clone();

        let mut init_depth = None;
        let mut split_depth = None;

        // Find metadata by comparing t_id, since we don't have the key directly
        for (key, meta) in &wallet.fingerprint_metadata {
            if let Some(fp_vec) = wallet.own_fingerprints.history.get(key) {
                if fp_vec.iter().any(|fp| fp.t_id == init_tx_fp_key) {
                    init_depth = Some(meta.depth);
                } else if fp_vec.iter().any(|fp| fp.t_id == split_tx_fp_key) {
                    split_depth = Some(meta.depth);
                }
            }
        }

        assert_eq!(
            split_depth,
            Some(0),
            "Die letzte Transaktion (split) sollte depth 0 haben."
        );
        assert_eq!(
            init_depth,
            Some(1),
            "Die erste Transaktion (init) sollte depth 1 haben."
        );
    }

    #[test]
    fn test_operations_on_empty_wallet_do_not_panic() {
        // GIVEN: A brand new, empty wallet.
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "EmptyWalletTest",
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

        assert!(
            service
                .get_unlocked_mut_for_test()
                .0
                .voucher_store
                .vouchers
                .is_empty(),
            "Pre-condition: Wallet must be empty"
        );

        // WHEN: Maintenance operations are executed.
        // THEN: The operations run without errors or panics.
        let cleanup_report = service
            .run_storage_cleanup()
            .expect("Cleanup on empty wallet should not fail");
        assert_eq!(cleanup_report.expired_fingerprints_removed, 0);
        assert_eq!(cleanup_report.limit_based_fingerprints_removed, 0);

        // Calling rebuild_derived_stores is part of `login` and was already tested implicitly.
        // An explicit call confirms that it is also safe during ongoing operation.
        service
            .get_unlocked_mut_for_test()
            .0
            .rebuild_derived_stores()
            .expect("Rebuild on empty wallet should not fail");

        // Check state afterwards
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert!(final_wallet.fingerprint_metadata.is_empty());
        assert!(final_wallet.own_fingerprints.history.is_empty());

        service.logout();
    }

    #[test]
    fn test_security_trap_detects_bad_instance_id_storage() {
        use human_money_core::app_service::AppService;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let tauri_app_dir = dir.path(); 
        
        // We simulate that the Core works in a "wallets" subfolder
        let base_storage_path = tauri_app_dir.join("wallets");
        
        // The careless app developer writes the file to the Tauri app folder (one level above)
        std::fs::write(tauri_app_dir.join("instance_id"), "dummy-device-123").unwrap();
        
        let mut service = AppService::new(&base_storage_path).unwrap();
        
        // Attempting to create a profile should immediately trigger the trap!
        let result = service.create_profile(
            "Trap Test", 
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", 
            None, 
            None, 
            "password", 
            human_money_core::services::mnemonic::MnemonicLanguage::English, 
            "dummy-device-123".to_string()
        );
        
        assert!(result.is_err(), "Die Falle hat nicht zugeschnappt!");
        assert!(result.unwrap_err().to_string().contains("CRITICAL SECURITY VIOLATION"), "Falsche Fehlermeldung!");
    }
}
