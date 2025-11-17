// tests/architecture/hardening.rs
// cargo test --test architecture_tests
//!
//! Enthält "Härtungstests", die die Robustheit der Architektur in
//! Randfällen und bei Konsistenzprüfungen verifizieren.

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use voucher_lib::test_utils::{self, ACTORS, SILVER_STANDARD};
    use voucher_lib::models::conflict::TransactionFingerprint;
    use chrono::{Utc, Duration};
    use voucher_lib::services::voucher_manager::NewVoucherData;

    const PASSWORD: &str = "test-password-123";

    #[test]
    fn test_cleanup_synchronizes_stores() {
        // GIVEN: Ein Wallet mit einem abgelaufenen Fingerprint, der in beiden Stores vorhanden ist.
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.bob, "HardeningTest1", PASSWORD);
        // Clean up any existing lock file
        let wallet_path = dir.path().join(&profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        service.login(&profile.folder_name, PASSWORD, false).unwrap();

        let wallet = service.get_unlocked_mut_for_test().0;
        let expired_date = (Utc::now() - Duration::days(1)).to_rfc3339();
        let key = "expired_key".to_string();

        let expired_fp = TransactionFingerprint {
            prvhash_senderid_hash: key.clone(),
            valid_until: expired_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
        };

        // Füge den Fingerprint beiden relevanten Stores hinzu
        wallet.known_fingerprints.local_history.insert(key.clone(), vec![expired_fp]);
        wallet.fingerprint_metadata.entry(key.clone()).or_default();

        assert!(wallet.known_fingerprints.local_history.contains_key(&key), "Pre-condition: Fingerprint must be in history");
        assert!(wallet.fingerprint_metadata.contains_key(&key), "Pre-condition: Metadata must exist for fingerprint");

        // WHEN: Die Speicherbereinigung wird ausgeführt.
        service.run_storage_cleanup().unwrap();

        // THEN: Der Fingerprint wurde aus BEIDEN Stores synchron entfernt.
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert!(!final_wallet.known_fingerprints.local_history.contains_key(&key), "Fingerprint should be removed from history");
        assert!(!final_wallet.fingerprint_metadata.contains_key(&key), "Metadata should be removed simultaneously");

        service.logout();
    }

    #[test]
    fn test_recovery_handles_split_transaction_chain() {
        // GIVEN: Ein Wallet mit einem Gutschein, der geteilt (split) wurde.
        let dir = tempdir().unwrap();
        let (mut alice_service, alice_profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "RecoveryTest3", PASSWORD);
        // Clean up any existing lock file
        let wallet_path = dir.path().join(&alice_profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        alice_service.login(&alice_profile.folder_name, PASSWORD, false).unwrap();

        // Erstelle einen Gutschein mit 100 Einheiten
        let new_voucher_data = NewVoucherData {
            nominal_value: voucher_lib::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: voucher_lib::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            }, ..Default::default()
        };
        let voucher = alice_service.create_new_voucher(&toml::to_string(&SILVER_STANDARD.0).unwrap(), "de", new_voucher_data, Some(PASSWORD)).unwrap();
        let local_id = alice_service.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();

        let wallet_path = dir.path().join(&alice_profile.folder_name);
        alice_service.logout(); // Speichert den Zustand
        // Manually remove lock file
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }

        // Führe einen Split durch ( sende 40 an Bob, behalte 60)
        alice_service.login(&alice_profile.folder_name, PASSWORD, false).unwrap();
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(SILVER_STANDARD.0.metadata.uuid.clone(), toml::to_string(&SILVER_STANDARD.0).unwrap());
        alice_service.create_transfer_bundle(request, &standards_toml, None, Some(PASSWORD)).unwrap();

        alice_service.logout(); // Speichert den Zustand mit 2 Transaktionen
        // Manually remove lock file
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }

        // WHEN: Die Metadaten werden gelöscht und das Wallet wiederhergestellt.
        let metadata_path = wallet_path.join("fingerprint_metadata.enc");
        std::fs::remove_file(metadata_path).unwrap();
        alice_service.login(&alice_profile.folder_name, PASSWORD, false).unwrap();

        // THEN: Die `depth`-Werte der Kette sind korrekt initialisiert.
        let wallet = alice_service.get_unlocked_mut_for_test().0;
        let voucher_instance = wallet.voucher_store.vouchers.values().find(|v| v.voucher.voucher_id == voucher.voucher_id).unwrap();
        assert_eq!(voucher_instance.voucher.transactions.len(), 2, "Voucher should have two transactions");

        // Finde die Fingerprints für beide Transaktionen
        let init_tx_fp_key = voucher_instance.voucher.transactions[0].t_id.clone(); // Dies ist nicht der Key, wir müssen ihn finden
        let split_tx_fp_key = voucher_instance.voucher.transactions[1].t_id.clone();

        let mut init_depth = None;
        let mut split_depth = None;

        // Finde die Metadaten, indem wir die t_id vergleichen, da wir den Key nicht direkt haben
        for (key, meta) in &wallet.fingerprint_metadata {
            if let Some(fp_vec) = wallet.own_fingerprints.history.get(key) {
                if fp_vec.iter().any(|fp| fp.t_id == init_tx_fp_key) {
                    init_depth = Some(meta.depth);
                } else if fp_vec.iter().any(|fp| fp.t_id == split_tx_fp_key) {
                    split_depth = Some(meta.depth);
                }
            }
        }

        assert_eq!(split_depth, Some(0), "Die letzte Transaktion (split) sollte depth 0 haben.");
        assert_eq!(init_depth, Some(1), "Die erste Transaktion (init) sollte depth 1 haben.");
    }

    #[test]
    fn test_operations_on_empty_wallet_do_not_panic() {
        // GIVEN: Ein brandneues, leeres Wallet.
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "EmptyWalletTest", PASSWORD);
        // Clean up any existing lock file
        let wallet_path = dir.path().join(&profile.folder_name);
        let lock_file = wallet_path.join(".wallet.lock");
        if lock_file.exists() {
            std::fs::remove_file(&lock_file).unwrap();
        }
        service.login(&profile.folder_name, PASSWORD, false).unwrap();

        assert!(service.get_unlocked_mut_for_test().0.voucher_store.vouchers.is_empty(), "Pre-condition: Wallet must be empty");

        // WHEN: Wartungsoperationen werden ausgeführt.
        // THEN: Die Operationen laufen ohne Fehler oder Panics durch.
        let cleanup_report = service.run_storage_cleanup().expect("Cleanup on empty wallet should not fail");
        assert_eq!(cleanup_report.expired_fingerprints_removed, 0);
        assert_eq!(cleanup_report.limit_based_fingerprints_removed, 0);

        // Der Aufruf von rebuild_derived_stores ist Teil von `login` und wurde bereits implizit getestet.
        // Ein expliziter Aufruf bestätigt, dass es auch im laufenden Betrieb sicher ist.
        service.get_unlocked_mut_for_test().0.rebuild_derived_stores().expect("Rebuild on empty wallet should not fail");

        // Prüfe den Zustand danach
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert!(final_wallet.fingerprint_metadata.is_empty());
        assert!(final_wallet.own_fingerprints.history.is_empty());

        service.logout();
    }
}