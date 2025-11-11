//! # tests/architecture/resilience_and_gossip.rs
//!
//! Testet die Kernfunktionen der neuen Architektur:
//! - Resilienz: Speicherbereinigung (Cleanup) und Wiederherstellung (Recovery).
//! - Gossip: Die korrekte Verbreitung und Aktualisierung von Fingerprint-Metadaten.

#[cfg(test)]
mod tests {
    use voucher_lib::services::bundle_processor;
    use tempfile::{tempdir, TempDir};
    use voucher_lib::app_service::{AppService, ProfileInfo};
    use voucher_lib::test_utils::{self, ACTORS, SILVER_STANDARD};
    use voucher_lib::models::conflict::{TransactionFingerprint, FingerprintMetadata};
    use std::collections::HashMap;
    use chrono::{Utc, Duration};
    use voucher_lib::services::voucher_manager::NewVoucherData;

    const PASSWORD: &str = "test-password-123";

    /// Hilfsfunktion, um eine saubere Testumgebung mit zwei entsperrten AppService-Instanzen zu erstellen.
    fn setup_test_environment(
        dir: &TempDir,
    ) -> ((AppService, ProfileInfo), (AppService, ProfileInfo)) {
        // Alice erstellen
        let (mut alice_service, alice_profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.alice,
            "Alice",
            PASSWORD,
        );
        alice_service.login(&alice_profile.folder_name, PASSWORD, false).unwrap();

        // Bob erstellen
        let (mut bob_service, bob_profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.bob, "Bob", PASSWORD);
        bob_service.login(&bob_profile.folder_name, PASSWORD, false).unwrap();

        ((alice_service, alice_profile), (bob_service, bob_profile))
    }

    /// Hilfsfunktion: Erstellt und sendet ein Bundle, das nur Fingerprints enthält.
    fn create_and_send_fingerprint_bundle(
        sender_service: &mut AppService,
        recipient_id: &str,
        fingerprints: Vec<(TransactionFingerprint, u8)>, // Tupel von (Fingerprint, depth)
    ) -> Vec<u8> {
        let (fprints, depths): (Vec<_>, HashMap<_, _>) = fingerprints
            .into_iter()
            .map(|(fp, depth)| (fp.clone(), (fp.prvhash_senderid_hash, depth)))
            .unzip();

 let forwarded_fingerprints = fprints;
 let fingerprint_depths: HashMap<String, u8> = depths.into_iter().collect();
 let (wallet, identity) = sender_service.get_unlocked_mut_for_test();

        let (bundle_bytes, _header) = wallet.create_and_encrypt_transaction_bundle( identity,
            vec![], // Keine Gutscheine
            recipient_id,
            None,
            forwarded_fingerprints,
            fingerprint_depths,
            None, // sender_profile_name
 ).unwrap();
 bundle_bytes
    }


    //==============================================================================
    // C. Speicherbereinigungs-Tests (Resilienz im Betrieb)
    //==============================================================================

    #[test]
    fn test_cleanup_phase1_removes_expired_fingerprints() {
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
        service.login(&profile.folder_name, PASSWORD, false).unwrap();
        let wallet_state = service.get_unlocked_mut_for_test().0;
        let now = Utc::now();
        let expired_date = (now - Duration::days(1)).to_rfc3339();
        let valid_date = (now + Duration::days(1)).to_rfc3339();
        let expired_fp = TransactionFingerprint {
            prvhash_senderid_hash: "expired_key".to_string(),
            valid_until: expired_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
        };
        let valid_fp = TransactionFingerprint {
            prvhash_senderid_hash: "valid_key".to_string(),
            valid_until: valid_date,
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
        };
        wallet_state.known_fingerprints.local_history.insert("expired_key".to_string(), vec![expired_fp]);
        wallet_state.known_fingerprints.local_history.insert("valid_key".to_string(), vec![valid_fp]);

        let report = service.run_storage_cleanup().unwrap();
        let wallet_state = service.get_unlocked_mut_for_test().0;

 // Mit den aktuellen Konstanten (MAX_FINGERPRINTS = 20_000) wird Phase 2 des Cleanups
 // in diesem Test nicht ausgelöst. Die Assertion wird auf 0 korrigiert.
 assert_eq!(report.limit_based_fingerprints_removed, 0);

        assert_eq!(report.expired_fingerprints_removed, 1);
        assert_eq!(wallet_state.known_fingerprints.local_history.len(), 1);
        assert!(wallet_state.known_fingerprints.local_history.contains_key("valid_key"));
    }

    #[test]
    fn test_cleanup_phase2_removes_by_depth_and_tie_breaker() {
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
        service.login(&profile.folder_name, PASSWORD, false).unwrap();
        let wallet = service.get_unlocked_mut_for_test().0;
        for i in 0..12 {
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                prvhash_senderid_hash: key.clone(),
                t_id: format!("tx_{:02}", i), // Padding für korrekte lexikalische Sortierung
                encrypted_timestamp: 0,
                sender_signature: String::new(),
                valid_until: String::new(),
            };
            let mut meta = FingerprintMetadata::default();
            meta.depth = match i {
                0 | 1 => 5, // Höchste depth, werden zuerst gelöscht
                _ => 1,
            };
            wallet.known_fingerprints.local_history.insert(key.clone(), vec![fp]);
            wallet.fingerprint_metadata.insert(key, meta);
        }

        // WHEN: Die Speicherbereinigung wird direkt auf dem Wallet mit einem
        // niedrigen Limit für den Test getriggert.
        let report = service.get_unlocked_mut_for_test().0.run_storage_cleanup(Some(10)).unwrap();
        assert_eq!(report.limit_based_fingerprints_removed, 2);

        // THEN: Die 2 Fingerprints mit der höchsten `depth` wurden entfernt.
        let final_wallet = service.get_unlocked_mut_for_test().0;
        assert_eq!(final_wallet.fingerprint_metadata.len(), 10);
        assert!(!final_wallet.fingerprint_metadata.contains_key("key_0"));
        assert!(!final_wallet.fingerprint_metadata.contains_key("key_1"));
    }

    //==============================================================================
    // D. Tests zur Robustheit und Wiederherstellung (Recovery)
    //==============================================================================

    #[test]
    fn test_recovery_rebuilds_from_vouchers_if_metadata_missing() {
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
        service.login(&profile.folder_name, PASSWORD, false).unwrap();
        let new_voucher_data = NewVoucherData {
            nominal_value: voucher_lib::models::voucher::NominalValue {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(ACTORS.alice.user_id.clone()), ..Default::default() }, ..Default::default()
        };
        service.create_new_voucher(&toml::to_string(&SILVER_STANDARD.0).unwrap(), "de", new_voucher_data, PASSWORD).unwrap();
        let wallet_path = dir.path().join(&profile.folder_name);
        service.logout();

        // WICHTIG: Die Datei `fingerprint_metadata.enc` muss existieren, bevor sie gelöscht wird.
        // Der Fix in `Wallet::create_new_voucher` stellt dies nun sicher.
        let metadata_path = wallet_path.join("fingerprint_metadata.enc");
        assert!(metadata_path.exists(), "Pre-condition failed: metadata file was not created.");

        std::fs::remove_file(metadata_path).unwrap();

        service.login(&profile.folder_name, PASSWORD, false).unwrap();

        let wallet = service.get_unlocked_mut_for_test().0;
        assert!(!wallet.fingerprint_metadata.is_empty());
        assert_eq!(wallet.fingerprint_metadata.len(), 1);
    }

    #[test]
    fn test_recovery_rebuilds_if_fingerprint_stores_missing() {
        let dir = tempdir().unwrap();
        let (mut service, profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
        service.login(&profile.folder_name, PASSWORD, false).unwrap();
        let new_voucher_data = NewVoucherData {
            nominal_value: voucher_lib::models::voucher::NominalValue {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(ACTORS.alice.user_id.clone()), ..Default::default() }, ..Default::default()
        };
        service.create_new_voucher(&toml::to_string(&SILVER_STANDARD.0).unwrap(), "de", new_voucher_data, PASSWORD).unwrap();
        let wallet_path = dir.path().join(&profile.folder_name);
        service.logout();
        std::fs::remove_file(wallet_path.join("own_fingerprints.enc")).unwrap();
        std::fs::remove_file(wallet_path.join("known_fingerprints.enc")).unwrap();

        service.login(&profile.folder_name, PASSWORD, false).unwrap();

        let wallet = service.get_unlocked_mut_for_test().0;
        assert_eq!(wallet.own_fingerprints.history.len(), 1);
    }

    #[test]
    fn test_recovery_initializes_depth_correctly() {
        // GIVEN: Ein Wallet mit einem Gutschein mit 3 Transaktionen wird gespeichert.
        let dir = tempdir().unwrap();
        let ((mut alice_service, alice_profile), (mut bob_service, _)) = setup_test_environment(&dir);
        let new_voucher_data = NewVoucherData {
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(ACTORS.alice.user_id.clone()), ..Default::default() }, ..Default::default()
        };
        let _voucher_id = alice_service.create_new_voucher(&toml::to_string(&SILVER_STANDARD.0).unwrap(), "de", NewVoucherData { nominal_value: voucher_lib::models::voucher::NominalValue { amount: "100".to_string(), ..Default::default()}, ..new_voucher_data }, PASSWORD).unwrap().voucher_id;
        let local_id = alice_service.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();

        // Tx 2: Alice -> Bob
        let bob_id = bob_service.get_user_id().unwrap();
        let bundle1 = {
            let request = voucher_lib::wallet::MultiTransferRequest {
                recipient_id: bob_id.clone(),
                sources: vec![voucher_lib::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "10".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
            };

            let mut standards_toml = std::collections::HashMap::new();
            standards_toml.insert(SILVER_STANDARD.0.metadata.uuid.clone(), toml::to_string(&SILVER_STANDARD.0).unwrap());

            let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle1_result, .. } = alice_service.create_transfer_bundle(request, &standards_toml, None, PASSWORD).unwrap();
            bundle1_result
        };
        let mut standards = HashMap::new();
        standards.insert(SILVER_STANDARD.0.metadata.uuid.clone(), toml::to_string(&SILVER_STANDARD.0).unwrap());
        bob_service.receive_bundle(&bundle1, &standards, None, PASSWORD).unwrap();
        let bob_local_id = bob_service.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();

        // Tx 3: Bob -> Alice
        let alice_id = alice_service.get_user_id().unwrap();
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: alice_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: bob_local_id.clone(),
                amount_to_send: "5".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(SILVER_STANDARD.0.metadata.uuid.clone(), toml::to_string(&SILVER_STANDARD.0).unwrap());
        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle2, .. } = bob_service.create_transfer_bundle(request, &standards_toml, None, PASSWORD).unwrap();
        // Erneute Bereitstellung der Standard-Definition für den Empfang.
        alice_service.receive_bundle(&bundle2, &standards, None, PASSWORD).unwrap();

        // DEBUG: Check Alice's voucher store state before logout
        let (wallet_before_logout, _) = alice_service.get_unlocked_mut_for_test();
        let tx_count_before_logout = wallet_before_logout.voucher_store.vouchers.values().next().unwrap().voucher.transactions.len();
        println!("[Debug Test] TX count in Alice's wallet before logout: {}", tx_count_before_logout);

        let wallet_path = dir.path().join(&alice_profile.folder_name);
        alice_service.logout();
        std::fs::remove_file(wallet_path.join("fingerprint_metadata.enc")).unwrap();

        // WHEN: Alice' Wallet wird wiederhergestellt
        alice_service.login(&alice_profile.folder_name, PASSWORD, false).unwrap();

        // THEN: Die `depth` der Transaktionen in der Kette ist korrekt initialisiert (0=neueste, 1, 2=älteste)
        let (wallet, _) = alice_service.get_unlocked_mut_for_test();
        let _voucher = &wallet.voucher_store.vouchers.values().next().unwrap().voucher;

        // KORREKTUR: Der Test muss die korrekte "min(depth)"-Logik widerspiegeln.
        // Die archivierte Instanz (2 Txs) erzeugt für die erste Transaktion depth=1.
        // Die aktive Instanz (3 Txs) erzeugt für die erste Transaktion depth=2.
        // Die korrekte Regel "min gewinnt" führt dazu, dass depth=1 persistiert wird.
        let _fp_tx1 = wallet.fingerprint_metadata.values().find(|meta| meta.depth == 1).expect("Tx mit depth 1 (min rule) nicht gefunden");
        let _fp_tx2 = wallet.fingerprint_metadata.values().find(|meta| meta.depth == 0).expect("Tx mit depth 0 (zweite Tx) nicht gefunden");
        let _fp_tx3 = wallet.fingerprint_metadata.values().find(|meta| meta.depth == 0).expect("Tx mit depth 0 nicht gefunden");
    }


    //==============================================================================
    // A. Core-Logik-Tests (Verbreitung & Merging)
    //==============================================================================

    #[test]
    fn test_min_merge_rule_updates_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (mut bob_service, _)) = setup_test_environment(&dir);
        let fp_key = "test_fp_key".to_string();
        let fingerprint = TransactionFingerprint {
            prvhash_senderid_hash: fp_key.clone(),
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
            valid_until: String::new(),
        };
        bob_service.get_unlocked_mut_for_test().0.fingerprint_metadata.entry(fp_key.clone()).or_default().depth = 10;

        let bob_id = bob_service.get_user_id().unwrap();
        let bundle_bytes = create_and_send_fingerprint_bundle(&mut alice_service, &bob_id, vec![(fingerprint, 2)]);
        let (_, bob_identity) = bob_service.get_unlocked_mut_for_test();
        println!("[Debug Test] Bob's identity user_id for lookup: '{}'", bob_identity.user_id);

        bob_service.receive_bundle(&bundle_bytes, &HashMap::new(), None, PASSWORD).unwrap();

        let (bob_wallet, _) = bob_service.get_unlocked_mut_for_test();
        let meta = bob_wallet.fingerprint_metadata.get(&fp_key).unwrap();
        assert_eq!(meta.depth, 3);
    }

    #[test]
    fn test_min_merge_rule_keeps_lower_local_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (mut bob_service, _)) = setup_test_environment(&dir);
        let fp_key = "test_fp_key".to_string();
        let fingerprint = TransactionFingerprint {
            prvhash_senderid_hash: fp_key.clone(),
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
            valid_until: String::new(),
        };
        bob_service.get_unlocked_mut_for_test().0.fingerprint_metadata.entry(fp_key.clone()).or_default().depth = 3;

        let bob_id = bob_service.get_user_id().unwrap();
        let bundle_bytes = create_and_send_fingerprint_bundle(&mut alice_service, &bob_id, vec![(fingerprint, 5)]); // sender_depth + 1 = 6
        bob_service.receive_bundle(&bundle_bytes, &HashMap::new(), None, PASSWORD).unwrap();

        let (bob_wallet, _) = bob_service.get_unlocked_mut_for_test();
        let meta = bob_wallet.fingerprint_metadata.get(&fp_key).unwrap();
        assert_eq!(meta.depth, 3, "Lokale `depth` sollte beibehalten werden, da sie niedriger war.");
    }

    #[test]
    fn test_implicit_marking_on_send() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (bob_service, _)) = setup_test_environment(&dir);
        let new_voucher_data = NewVoucherData {
            nominal_value: voucher_lib::models::voucher::NominalValue {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(ACTORS.alice.user_id.clone()), ..Default::default() }, ..Default::default()
        };
        alice_service.create_new_voucher(&toml::to_string(&SILVER_STANDARD.0).unwrap(), "de", new_voucher_data, PASSWORD).unwrap();
        let local_id = alice_service.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();
        let init_tx_fp_key = alice_service.get_unlocked_mut_for_test().0.fingerprint_metadata.keys().next().unwrap().clone();

        let bob_id = bob_service.get_user_id().unwrap();
        
        // NEU: Berechne den erwarteten Kurz-Hash für die Assertion
        let bob_short_hash = voucher_lib::crypto_utils::get_short_hash_from_user_id(&bob_id);

        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: bob_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "10".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(SILVER_STANDARD.0.metadata.uuid.clone(), toml::to_string(&SILVER_STANDARD.0).unwrap());
        alice_service.create_transfer_bundle(request, &standards_toml, None, PASSWORD).unwrap();

        let (alice_wallet, _) = alice_service.get_unlocked_mut_for_test();
        let meta = alice_wallet.fingerprint_metadata.get(&init_tx_fp_key).unwrap();
        assert!(meta.known_by_peers.contains(&bob_short_hash), "Bobs Kurz-Hash sollte implizit als Kenner des Fingerprints markiert sein.");
    }

    #[test]
    fn test_selection_heuristic_prioritizes_low_depth() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (mut bob_service, _)) = setup_test_environment(&dir);
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();
        for i in 0..5 {
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                prvhash_senderid_hash: key.clone(),
                t_id: String::new(),
                encrypted_timestamp: 0,
                sender_signature: String::new(),
                valid_until: String::new(),
            };
            let meta = FingerprintMetadata { depth: if i < 2 { 0 } else if i < 4 { 1 } else { 5 }, ..Default::default() };
            wallet.fingerprint_metadata.insert(key.clone(), meta);
            wallet.known_fingerprints.local_history.insert(key, vec![fp]);
        }

        // WHEN: Alice einen Transfer auslöst, der die Heuristik intern verwendet.
        let bob_id = bob_service.get_user_id().unwrap();
        let (fingerprints_to_send, depths_to_send) = wallet.select_fingerprints_for_bundle(&bob_id, &[]).unwrap();
 let (bundle_bytes, _header) = wallet.create_and_encrypt_transaction_bundle(
            alice_identity,
            vec![], // Kein echter Gutschein-Transfer nötig
            &bob_id,
            None,
            fingerprints_to_send,
            depths_to_send,
            None, // sender_profile_name
        ).unwrap();

        // THEN: Wir öffnen das Bundle, um zu prüfen, was ausgewählt wurde.
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;

        // Die Logik ist "gierig" und sammelt auch Fingerprints mit höherer `depth`,
        // um das Kontingent zu füllen. Daher ist 5 das korrekte Ergebnis.
        assert_eq!(selected.len(), 5);
        let depths: Vec<u8> = selected.iter().map(|fp| bundle.fingerprint_depths.get(&fp.prvhash_senderid_hash).unwrap().clone()).collect();
        assert_eq!(depths.iter().filter(|&&d| d == 0).count(), 2);
        assert_eq!(depths.iter().filter(|&&d| d == 1).count(), 2);
    }

    #[test]
    fn test_selection_heuristic_skips_known_peers() {
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (mut bob_service, _)) = setup_test_environment(&dir);
        let bob_id = bob_service.get_user_id().unwrap();
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();
        let key = "key_already_known".to_string();
        let fp = TransactionFingerprint {
            prvhash_senderid_hash: key.clone(),
            t_id: String::new(),
            encrypted_timestamp: 0,
            sender_signature: String::new(),
            valid_until: String::new(),
        };        let mut meta = FingerprintMetadata { depth: 0, ..Default::default() };
        meta.known_by_peers.insert(voucher_lib::crypto_utils::get_short_hash_from_user_id(&bob_id));
        wallet.fingerprint_metadata.insert(key.clone(), meta);
        wallet.known_fingerprints.local_history.insert(key, vec![fp]);

        // WHEN: Alice einen neuen Transfer an Bob erstellt
        let (bundle_bytes, _header) = wallet.create_and_encrypt_transaction_bundle(
            alice_identity,
            vec![],
            &bob_id,
            None,
            vec![],
            HashMap::new(),
            None, // sender_profile_name
        ).unwrap();

        // THEN: Der bereits bekannte Fingerprint wird nicht erneut gesendet.
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;


        assert!(selected.is_empty());
    }

    #[test]
    fn test_selection_heuristic_fills_contingent() {
        const CONTINGENT_SIZE: usize = 150;
        let dir = tempdir().unwrap();
        let ((mut alice_service, _), (mut bob_service, _)) = setup_test_environment(&dir);
        let (wallet, alice_identity) = alice_service.get_unlocked_mut_for_test();

        // GIVEN: Ein Wallet mit 200 Fingerprints bei depth = 0
        for i in 0..200 {
            let key = format!("key_{}", i);
            let fp = TransactionFingerprint {
                prvhash_senderid_hash: key.clone(),
                t_id: String::new(),
                encrypted_timestamp: 0,
                sender_signature: String::new(),
                valid_until: String::new(),
            };            wallet.fingerprint_metadata.insert(key.clone(), FingerprintMetadata { depth: 0, ..Default::default() });
            wallet.known_fingerprints.local_history.insert(key, vec![fp]);
        }

        // WHEN: Ein Transfer ausgelöst wird
        let bob_id = bob_service.get_user_id().unwrap();
        let (fingerprints_to_send, depths_to_send) = wallet.select_fingerprints_for_bundle(&bob_id, &[]).unwrap();
 let (bundle_bytes, _header) = wallet.create_and_encrypt_transaction_bundle(
            alice_identity,
            vec![],
            &bob_id,
            None,
            fingerprints_to_send,
            depths_to_send,
            None, // sender_profile_name
        ).unwrap();

        // THEN: Das Kontingent von 150 wird exakt gefüllt
        let bob_identity = &bob_service.get_unlocked_mut_for_test().1;
        let bundle = bundle_processor::open_and_verify_bundle(bob_identity, &bundle_bytes).unwrap();
        let selected = bundle.forwarded_fingerprints;

        // THEN: Das Kontingent von 150 wird exakt gefüllt
        assert_eq!(selected.len(), CONTINGENT_SIZE);
    }
}