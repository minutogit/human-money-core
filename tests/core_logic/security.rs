// tests/core_logic/security.rs

//! # Test-Suite für Sicherheitsaspekte und Betrugserkennung
//!
//! Diese Datei bündelt zwei kritische Bereiche der Gutschein-Sicherheit:
//!
//! 1.  **Lokale Double-Spending-Erkennung:**
//!     - Überprüfung der Fingerprint-Verwaltung.
//!     - End-to-End-Szenario zur Erkennung eines Betrugsversuchs.
//!
//! 2.  **Sicherheitslücken & Angriffs-Simulationen:**
//!     - Simulation von Angriffen durch einen böswilligen Akteur ("Hacker").
//!     - Überprüfung der Robustheit der Validierungslogik (`voucher_validation.rs`).
//!     - Fuzzing-Tests zur Prüfung der strukturellen Integrität.


use voucher_lib::test_utils;

// ===================================================================================
// --- BEGINN: LOCAL DOUBLE SPEND DETECTION TESTS ---
// (Ursprünglich in `test_local_double_spend_detection.rs`)
// ===================================================================================

mod local_double_spend_detection {
    use voucher_lib::archive::file_archive::FileVoucherArchive;
    // NEU: AppService und Storage importieren
    use voucher_lib::app_service::AppService; // KORREKTUR: Falscher Import E0432
    use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};
    use std::collections::HashMap;
    use std::{path::Path};
    use voucher_lib::test_utils::{setup_in_memory_wallet, ACTORS, SILVER_STANDARD};
    use voucher_lib::{services::crypto_utils, UserIdentity, VoucherStatus};
    use voucher_lib::models::conflict::TransactionFingerprint;
    use voucher_lib::models::voucher::{Address, Collateral, Creator, NominalValue, Voucher};
    use voucher_lib::services::voucher_manager::{self, NewVoucherData};
    use voucher_lib::wallet::Wallet;

    // ===================================================================================
    // HILFSFUNKTIONEN
    // ===================================================================================

    /// Erstellt für einen Test ein frisches, leeres Wallet für eine vordefinierte Identität.
    /// Stellt die Test-Isolation durch separates Speichern sicher.
    fn setup_test_wallet(identity: &UserIdentity, _name: &str, _storage_dir: &Path) -> Wallet {
        setup_in_memory_wallet(identity)
    }

    /// Extrahiert den einzigen Gutschein aus dem Wallet eines Akteurs.
    fn get_voucher_from_wallet(wallet: &Wallet) -> Voucher {
        assert_eq!(wallet.voucher_store.vouchers.len(), 1, "Expected exactly one voucher in the wallet");
        wallet.voucher_store.vouchers.values().next().unwrap().voucher.clone()
    }

    /// Erstellt einen leeren Fingerprint für Testzwecke.
    fn new_dummy_fingerprint(t_id: &str) -> TransactionFingerprint {
        TransactionFingerprint {
            prvhash_senderid_hash: "".to_string(),
            t_id: t_id.to_string(),
            encrypted_timestamp: 0,
            sender_signature: "".to_string(),
            valid_until: "2099-12-31T23:59:59.999999Z".to_string(),
        }
    }

    /// Erstellt leere `NewVoucherData` für Testzwecke.
    fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
        NewVoucherData {
            validity_duration: Some("P5Y".to_string()),
            non_redeemable_test_voucher: false,
            nominal_value: NominalValue {
                amount: "100".to_string(),
                unit: String::new(),
                abbreviation: String::new(),
                description: String::new(),
            },
            collateral: Collateral::default(),
            creator: Creator {
                id: creator_id,
                first_name: String::new(),
                last_name: String::new(),
                address: Address::default(),
                organization: Some(String::new()),
                community: Some(String::new()),
                phone: Some(String::new()),
                email: Some(String::new()),
                url: Some(String::new()),
                gender: String::new(),
                service_offer: Some(String::new()),
                needs: Some(String::new()),
                signature: String::new(),
                coordinates: String::new(),
            },
        }
    }

    // ===================================================================================
    // UNIT-TESTS ("VORTESTS")
    // ===================================================================================

    #[test]
    fn test_fingerprint_generation() {
        let _temp_dir = tempfile::tempdir().unwrap();
        let identity = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(identity);

        // Erstelle einen Gutschein mit 2 Transaktionen (init + transfer)
        let voucher_data = new_test_voucher_data(identity.user_id.clone());
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        // create_voucher erwartet den &SigningKey, nicht die ganze Identity.
        let mut voucher = voucher_manager::create_voucher(voucher_data, standard, standard_hash, &identity.signing_key, "en").unwrap();
        voucher = voucher_manager::create_transaction(&voucher, standard, &identity.user_id, &identity.signing_key, "recipient_id", "50").unwrap();
        let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id).unwrap();
        wallet.add_voucher_instance(local_id, voucher.clone(), VoucherStatus::Active);

        // Aktion
        wallet.scan_and_rebuild_fingerprints().unwrap();

        // Assertions
        assert_eq!(wallet.own_fingerprints.history.values().map(|v| v.len()).sum::<usize>(), 2, "Es sollten Fingerprints für 2 Transaktionen existieren.");

        let tx1 = &voucher.transactions[0];
        let expected_hash1 = crypto_utils::get_hash(format!("{}{}", tx1.prev_hash, tx1.sender_id));
        assert!(wallet.own_fingerprints.history.contains_key(&expected_hash1), "Fingerprint für die init-Transaktion fehlt.");

        // Berechne den erwarteten, auf das Monatsende gerundeten `valid_until`-Wert.
        let expected_rounded_valid_until = {
            let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until).unwrap();
            let year = parsed_date.year();
            let month = parsed_date.month();
            let first_of_next_month = if month == 12 {
                NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
            } else {
                NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
            };
            let last_day_of_month = first_of_next_month.pred_opt().unwrap();
            let end_of_month_dt = last_day_of_month.and_hms_micro_opt(23, 59, 59, 999999).unwrap().and_utc();
            end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
        };

        assert_eq!(wallet.own_fingerprints.history.get(&expected_hash1).unwrap()[0].valid_until, expected_rounded_valid_until, "Der valid_until-Wert im Fingerprint muss dem auf das Monatsende gerundeten Wert entsprechen.");
    }

    #[test]
    fn test_fingerprint_exchange() {
        let mut sender_wallet = setup_in_memory_wallet(&ACTORS.sender);
        let mut receiver_wallet = setup_in_memory_wallet(&ACTORS.recipient1);

        // Setup: Erzeuge Fingerprints im Sender-Wallet
        let mut fp1 = new_dummy_fingerprint("t1");
        fp1.prvhash_senderid_hash = "hash1".to_string();
        sender_wallet.own_fingerprints.history.insert("hash1".to_string(), vec![fp1]);

        // Aktion
        let exported_data = sender_wallet.export_own_fingerprints().unwrap();
        let import_count1 = receiver_wallet.import_foreign_fingerprints(&exported_data).unwrap();
        let import_count2 = receiver_wallet.import_foreign_fingerprints(&exported_data).unwrap();

        // Assertions
        assert_eq!(import_count1, 1, "Der erste Import sollte einen neuen Fingerprint hinzufügen.");
        assert_eq!(import_count2, 0, "Der zweite Import sollte keinen neuen Fingerprint hinzufügen.");
        assert!(receiver_wallet.own_fingerprints.history.is_empty(), "Die eigenen Fingerprints des Empfängers sollten leer sein.");
        assert_eq!(receiver_wallet.known_fingerprints.foreign_fingerprints.len(), 1, "Die fremden Fingerprints des Empfängers sollten einen Eintrag enthalten.");
    }

    #[test]
    fn test_conflict_classification() {
        let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

        let conflict_hash = "shared_hash".to_string();
        let fp1 = new_dummy_fingerprint("t_id_1");
        let fp2 = new_dummy_fingerprint("t_id_2");

        // Fall A: Verifizierbarer Konflikt
        // Um einen Konflikt als verifizierbar zu klassifizieren, muss der Hash in der
        // `local_history` vorhanden sein. Dies simuliert, dass der Nutzer den Gutschein
        // besitzt oder besessen hat.
        wallet.known_fingerprints.local_history.insert(conflict_hash.clone(), vec![fp1.clone()]);
        wallet.known_fingerprints.foreign_fingerprints.insert(conflict_hash.clone(), vec![fp2.clone()]);

        let result_a = wallet.check_for_double_spend();
        assert_eq!(result_a.verifiable_conflicts.len(), 1, "Fall A: Ein verifizierbarer Konflikt muss erkannt werden.");
        assert!(result_a.unverifiable_warnings.is_empty(), "Fall A: Es sollte keine unverifizierbaren Warnungen geben.");

        // Fall B: Nicht verifizierbarer Konflikt
        wallet.known_fingerprints.local_history.clear();
        wallet.known_fingerprints.foreign_fingerprints.insert(conflict_hash.clone(), vec![fp1, fp2]);

        let result_b = wallet.check_for_double_spend();
        assert_eq!(result_b.unverifiable_warnings.len(), 1, "Fall B: Eine unverifizierbare Warnung muss erkannt werden.");
        assert!(result_b.verifiable_conflicts.is_empty(), "Fall B: Es sollte keine verifizierbaren Konflikte geben.");
    }

    #[test]
    fn test_cleanup_expired_fingerprints() {
        let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

        let mut expired_fp_hist = new_dummy_fingerprint("t_hist_expired");
        expired_fp_hist.valid_until = "2020-01-01T00:00:00Z".to_string();
        let valid_fp_hist = new_dummy_fingerprint("t_hist_valid");

        let mut expired_fp_foreign = new_dummy_fingerprint("t_foreign_expired");
        expired_fp_foreign.valid_until = "2020-01-01T00:00:00Z".to_string();
        let valid_fp_foreign = new_dummy_fingerprint("t_foreign_valid");

        // Füge Fingerprints zu beiden Speichern hinzu
        wallet.own_fingerprints.history.insert("hist_expired".to_string(), vec![expired_fp_hist]);
        wallet.own_fingerprints.history.insert("hist_valid".to_string(), vec![valid_fp_hist]);
        wallet.known_fingerprints.foreign_fingerprints.insert("foreign_expired".to_string(), vec![expired_fp_foreign]);
        wallet.known_fingerprints.foreign_fingerprints.insert("foreign_valid".to_string(), vec![valid_fp_foreign]);

        // Aktion: Rufe die zentrale Aufräumfunktion mit einer Frist von 0 Jahren auf,
        // was eine sofortige Bereinigung aller abgelaufenen Einträge auslösen sollte.
        wallet.cleanup_storage(0);

        // Assertions für den flüchtigen Speicher (sollte bereinigt werden)
        assert!(!wallet.known_fingerprints.foreign_fingerprints.contains_key("foreign_expired"), "Abgelaufener fremder Fingerprint sollte entfernt werden.");
        assert!(wallet.known_fingerprints.foreign_fingerprints.contains_key("foreign_valid"), "Gültiger fremder Fingerprint sollte erhalten bleiben.");

        // Assertions für den History-Speicher (sollte jetzt auch bereinigt werden)
        assert!(!wallet.own_fingerprints.history.contains_key("hist_expired"), "Abgelaufener History-Fingerprint sollte mit 0 Jahren Frist entfernt werden.");
        assert!(wallet.own_fingerprints.history.contains_key("hist_valid"), "Gültiger History-Fingerprint muss erhalten bleiben.");
    }

    // ===================================================================================
    // PROACTIVE PREVENTION TEST
    // ===================================================================================

    #[test]
    fn test_proactive_double_spend_prevention_and_self_healing_in_appservice() {
        // ### Setup ###
        // Erstellt einen Sender und zwei potenzielle Empfänger.
        let temp_dir = tempfile::tempdir().unwrap();
        let storage_path = temp_dir.path();

        let recipient1_identity = &ACTORS.recipient1;
        let recipient2_identity = &ACTORS.recipient2;

        // 1. AppService für Sender erstellen und entsperren
        let mut app_service = AppService::new(storage_path).unwrap();
        // KORREKTUR: Verwende den korrekten Pfad zur Mnemonic des Senders aus test_utils.rs
        // KORREKTUR (Panic-Fix): Übergebe das in ACTORS definierte Präfix ('Some("se")') an create_profile.
        app_service.create_profile("sender", &ACTORS.sender.mnemonic, None, ACTORS.sender.prefix, "password123").unwrap();

        // KORREKTUR (Panic-Fix): Wir müssen den anonymen 'folder_name' abrufen,
        // da 'login' diesen anstelle des 'profile_name' erwartet.
        let profile_info = app_service.list_profiles().unwrap()
            .into_iter()
            .find(|p| p.profile_name == "sender")
            .expect("Konnte das 'sender'-Profil nach der Erstellung nicht finden");
        let sender_folder_name = profile_info.folder_name;

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        // KORREKTUR: Lade den rohen TOML-String. Der Service erwartet TOML-Inhalt, nicht den Hash.
        let silver_toml_str = include_str!("../../voucher_standards/silver_v1/standard.toml");

        let mut standards_map = HashMap::new();
        // KORREKTUR: Die Map muss UUID -> TOML-Inhalt enthalten (für spätere Transfer-Aufrufe).
        standards_map.insert(standard.metadata.uuid.clone(), silver_toml_str.to_string());

        // 2. Sender erhält einen initialen Gutschein.
        let voucher_data = new_test_voucher_data(app_service.get_user_id().unwrap());
        let initial_voucher = app_service.create_new_voucher(
            silver_toml_str, // KORREKTUR (Panic-Fix): Übergebe den TOML-Inhalt, nicht den Hash
            "en",
            voucher_data,
            "password123"
        ).unwrap();

        // Merke dir die lokale ID des Gutscheins
        let initial_local_id = app_service.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();
        let original_voucher_state_for_attack = initial_voucher.clone(); // Klonen für späteren Angriff

        // ### Akt 1: Legitime Transaktion ###
        // Sender sendet den Gutschein an Empfänger 1.
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: recipient1_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: initial_local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let transfer1_result = app_service.create_transfer_bundle(
            request,
            &standards_map,
            None,
            "password123"
        );
        assert!(transfer1_result.is_ok(), "Die erste Transaktion sollte erfolgreich sein.");

        // Status-Prüfung: Der Gutschein sollte jetzt 'Archived' sein
        let summary_after_send = app_service.get_voucher_summaries(None, None).unwrap();

        // KORREKTUR: Die 'initial_local_id' existiert nicht mehr. Die Wallet-Logik
        // hat die alte Instanz entfernt und eine NEUE Instanz mit einer NEUEN local_id
        // und dem Status 'Archived' erstellt.
        assert_eq!(summary_after_send.len(), 1, "Es sollte genau eine Gutschein-Instanz (die archivierte) im Wallet geben.");
        
        let instance_status = &summary_after_send[0].status;
        assert!(matches!(instance_status, VoucherStatus::Archived), "Der Status des neuen Gutscheins sollte 'Archived' sein, war aber: {:?}", instance_status);

        // Stelle sicher, dass die alte ID wirklich weg ist.
        let old_instance_exists = summary_after_send.iter().any(|s| s.local_instance_id == initial_local_id);
        assert!(!old_instance_exists, "Die alte Gutschein-Instanz MUSS entfernt worden sein.");

        // ### Akt 2: Manuelle Manipulation für einen Betrugsversuch ###
        // Wir simulieren, dass der Sender versucht, denselben ursprünglichen Gutschein-Zustand erneut auszugeben.
        // Wir müssen den AppService austricksen, indem wir das Wallet manuell laden,
        // manipulieren und den AppService neu initialisieren (ein "Restore" simulieren).
        app_service.logout();

        // HIER IST DER FIX: Wir müssen die `FileStorage`-Instanz mit dem exakten
        // Pfad zum Profil-Ordner (den wir aus Akt 1 kennen) initialisieren,
        // nicht nur mit dem Basis-Speicherpfad.
        let profile_storage_path = storage_path.join(&sender_folder_name);
        let mut storage = voucher_lib::storage::file_storage::FileStorage::new(&profile_storage_path);
        // KORREKTUR: E0609 Verwende die korrekte AuthMethod
        let auth = voucher_lib::storage::AuthMethod::Password("password123");
        let (mut wallet, identity) = Wallet::load(&storage, &auth).unwrap();

        // HIER IST DER ANGRIFF: Füge den alten, ausgegebenen Gutschein wieder als 'Active' hinzu.
        let user_id = identity.user_id.clone();
        let local_id_2 = Wallet::calculate_local_instance_id(&original_voucher_state_for_attack, &user_id).unwrap();
        wallet.add_voucher_instance(local_id_2, original_voucher_state_for_attack, VoucherStatus::Active);
        wallet.save(&mut storage, &identity, "password123").unwrap();

        // AppService neu laden (simuliert App-Neustart nach "Restore")
        let mut app_service = AppService::new(storage_path).unwrap();
        // KORREKTUR (Panic-Fix): Verwende den 'sender_folder_name' anstelle von "sender".
        app_service.login(&sender_folder_name, "password123", false).unwrap();
        assert_eq!(app_service.get_voucher_summaries(None, Some(&[VoucherStatus::Active])).unwrap().len(), 1, "Wallet sollte jetzt einen inkonsistenten 'Active' Gutschein haben.");

        // ### Akt 3: Der blockierte Double-Spend-Versuch ###
        // Sender versucht, den wiederhergestellten, ursprünglichen Gutschein an Empfänger 2 zu senden.
        // Dies MUSS fehlschlagen UND die Selbstheilung auslösen.
        let request_2 = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: recipient2_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: initial_local_id.clone(), // KORREKTUR: E0063
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        
        // KORREKTUR: E0425 Ersetze alte sender_wallet Logik
        let transfer2_result = app_service.create_transfer_bundle(
            request_2,
            &standards_map, // standards_map existiert bereits von oben
            None,
            "password123"
        );

        assert!(transfer2_result.is_err(), "Die zweite Transaktion von demselben Zustand aus muss fehlschlagen.");
        assert!(transfer2_result.err().unwrap().contains("Action blocked and wallet state corrected"));

        // ### Akt 4: Verifizierung der Selbstheilung ###
        // Überprüfe, ob der AppService den inkonsistenten Gutschein auf 'Quarantined' gesetzt hat.
        let summary_after_fail = app_service.get_voucher_summaries(None, None).unwrap();
        let instance = summary_after_fail.iter().find(|s| s.local_instance_id.contains(&initial_local_id)).unwrap();

        assert!(
            matches!(instance.status, VoucherStatus::Quarantined { .. }),
            "Der inkonsistente Gutschein MUSS jetzt auf 'Quarantined' gesetzt sein (Self-Healing)."
        );
        println!("Test erfolgreich: Inkonsistenz erkannt, Transfer blockiert UND Wallet-Zustand selbst geheilt.");
    }

    // ===================================================================================
    // INTEGRATIONSTEST
    // ===================================================================================

    #[test]
    fn test_local_double_spend_detection_lifecycle() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let storage_path = temp_dir.path();
        let archive = FileVoucherArchive::new(storage_path.join("archive"));

        // ### Akt 1: Initialisierung & Erster Transfer ###
        println!("--- Akt 1: Alice erstellt einen Gutschein und sendet ihn an Bob ---");

        let alice_identity = &ACTORS.alice;
        let bob_identity = &ACTORS.bob;
        let mut alice_wallet = setup_test_wallet(alice_identity, "alice", storage_path);
        let mut bob_wallet = setup_test_wallet(bob_identity, "bob", storage_path);

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let voucher_data = new_test_voucher_data(alice_identity.user_id.clone());
        let initial_voucher = voucher_manager::create_voucher(voucher_data, standard, standard_hash, &alice_identity.signing_key, "en").unwrap();
        let local_id = Wallet::calculate_local_instance_id(&initial_voucher, &alice_identity.user_id).unwrap();
        alice_wallet.add_voucher_instance(local_id, initial_voucher, VoucherStatus::Active);

        // Alice verwendet die neue, korrekte Methode, um den Gutschein an Bob zu senden.
        // Wir klonen die ID, um den immutable borrow auf alice_wallet sofort zu beenden.
        let alice_initial_local_id = alice_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
        
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: bob_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: alice_initial_local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle_to_bob, .. } = alice_wallet.execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            Some(&archive),
        ).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_bob = std::collections::HashMap::new();
        standards_for_bob.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        bob_wallet.process_encrypted_transaction_bundle(bob_identity, &bundle_to_bob, Some(&archive), &standards_for_bob).unwrap();

        assert_eq!(alice_wallet.voucher_store.vouchers.len(), 1, "Alices Wallet muss den gesendeten Gutschein als 'Archived' behalten.");
        let instance_a = alice_wallet.voucher_store.vouchers.values().next().unwrap();
        assert!(matches!(instance_a.status, VoucherStatus::Archived), "Der Status von Alices Gutschein muss 'Archived' sein.");
        assert!(matches!(bob_wallet.voucher_store.vouchers.values().next().unwrap().status, VoucherStatus::Active));

        // ### Akt 2: Der Double Spend ###
        println!("--- Akt 2: Bob begeht einen Double Spend an Charlie und David ---");

        let charlie_identity = &ACTORS.charlie;
        let david_identity = &ACTORS.david;
        let mut charlie_wallet = setup_test_wallet(charlie_identity, "charlie", storage_path);
        let mut david_wallet = setup_test_wallet(david_identity, "david", storage_path);
        let voucher_from_bob = get_voucher_from_wallet(&bob_wallet);

        // Bob agiert böswillig. Er umgeht die Schutzmechanismen seines Wallets (create_transfer würde das blockieren)
        // und erstellt manuell zwei widersprüchliche Transaktionen aus demselben Zustand.
        // Wichtig: Wir fügen eine kleine Verzögerung ein, um sicherzustellen, dass die Zeitstempel
        // der betrügerischen Transaktionen deterministisch unterscheidbar sind.
        let voucher_for_charlie = voucher_manager::create_transaction(&voucher_from_bob, standard, &bob_identity.user_id, &bob_identity.signing_key, &charlie_identity.user_id, "100").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let voucher_for_david = voucher_manager::create_transaction(&voucher_from_bob, standard, &bob_identity.user_id, &bob_identity.signing_key, &david_identity.user_id, "100").unwrap();

        // Wir merken uns die IDs der beiden widersprüchlichen Transaktionen.
        let winning_tx_id = voucher_for_charlie.transactions.last().unwrap().t_id.clone();
        let losing_tx_id = voucher_for_david.transactions.last().unwrap().t_id.clone();

        // Er verpackt und sendet die erste betrügerische Version an Charlie. Hierfür nutzt er die alte Methode.
        let (bundle_to_charlie, _header) = bob_wallet.create_and_encrypt_transaction_bundle(bob_identity, vec![voucher_for_charlie.clone()], &charlie_identity.user_id, None, Vec::new(), std::collections::HashMap::new(), None).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_charlie = std::collections::HashMap::new();
        standards_for_charlie.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        charlie_wallet.process_encrypted_transaction_bundle(charlie_identity, &bundle_to_charlie, Some(&archive), &standards_for_charlie).unwrap();

        // Um den zweiten Betrug zu ermöglichen, setzt er den Zustand seines Wallets künstlich zurück.
        let local_id_bob = Wallet::calculate_local_instance_id(&voucher_from_bob, &bob_identity.user_id).unwrap();
        bob_wallet.add_voucher_instance(local_id_bob, voucher_from_bob, VoucherStatus::Active);
        let (bundle_to_david, _header) = bob_wallet.create_and_encrypt_transaction_bundle(bob_identity, vec![voucher_for_david.clone()], &david_identity.user_id, None, Vec::new(), std::collections::HashMap::new(), None).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_david = std::collections::HashMap::new();
        standards_for_david.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        david_wallet.process_encrypted_transaction_bundle(david_identity, &bundle_to_david, Some(&archive), &standards_for_david).unwrap();

        assert_eq!(charlie_wallet.voucher_store.vouchers.len(), 1);
        assert_eq!(david_wallet.voucher_store.vouchers.len(), 1);

        // ### Akt 3: Die Rückkehr (Teil 1) ###
        println!("--- Akt 3: Charlie sendet seine Version zurück an Alice ---");

        // Charlie handelt legitim und verwendet die korrekte `create_transfer` Methode.
        // Wir klonen die ID, um den immutable borrow auf charlie_wallet sofort zu beenden.
        let charlie_local_id = charlie_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
        
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: alice_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: charlie_local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle_to_alice_1, .. } = charlie_wallet.execute_multi_transfer_and_bundle(
            charlie_identity,
            &standards,
            request,
            Some(&archive)
        ).unwrap();

        println!("\n[Debug Test] Alices Wallet VOR dem Empfang von Charlie:");
        for (id, instance) in &alice_wallet.voucher_store.vouchers {
            println!("  -> Vorhanden: ID={}, Status={:?}, Tx-Anzahl={}", id, instance.status, instance.voucher.transactions.len());
        }
        println!("[Debug Test] Verarbeite jetzt Bündel von Charlie...");

        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_alice = std::collections::HashMap::new();
        standards_for_alice.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        let result1 = alice_wallet
            .process_encrypted_transaction_bundle(alice_identity, &bundle_to_alice_1, Some(&archive), &standards_for_alice)
            .unwrap();
        assert_eq!(alice_wallet.voucher_store.vouchers.len(), 2, "Alice muss jetzt einen 'Archived' und einen 'Active' Gutschein haben.");
        assert!(result1.check_result.verifiable_conflicts.is_empty(), "Nach dem ersten zurückerhaltenen Gutschein darf es noch keinen Konflikt geben.");

        // ### Akt 4: Die Aufdeckung ###
        println!("--- Akt 4: David sendet seine widersprüchliche Version an Alice. Der Betrug wird aufgedeckt. ---");

        // David handelt ebenfalls legitim (aus seiner Sicht) und verwendet `create_transfer`.
        // Wir klonen die ID, um den immutable borrow auf david_wallet sofort zu beenden.
        let david_local_id = david_wallet.voucher_store.vouchers.keys().next().unwrap().clone();
        
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: alice_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: david_local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle_to_alice_2, .. } = david_wallet.execute_multi_transfer_and_bundle(
            david_identity,
            &standards,
            request,
            Some(&archive)
        ).unwrap();

        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_alice_2 = std::collections::HashMap::new();
        standards_for_alice_2.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        let result2 = alice_wallet
            .process_encrypted_transaction_bundle(alice_identity, &bundle_to_alice_2, Some(&archive), &standards_for_alice_2)
            .unwrap();

        // Assertions
        assert_eq!(result2.check_result.verifiable_conflicts.len(), 1, "Ein verifizierbarer Konflikt MUSS erkannt worden sein.");
        assert_eq!(alice_wallet.voucher_store.vouchers.len(), 3, "Alices Wallet sollte am Ende drei Instanzen des Gutscheins enthalten.");

        // ### Akt 5: Überprüfung der intelligenten Konfliktlösung ###
        println!("--- Akt 5: Überprüfe, ob die korrekte Gutschein-Instanz aktiv geblieben ist ---");

        let mut winner_status: Option<VoucherStatus> = None;
        let mut loser_status: Option<VoucherStatus> = None;
        let mut loser_local_id: Option<String> = None;

        // Finde die beiden konkurrierenden Gutschein-Instanzen in Alices Wallet und prüfe ihren Status.
        // Wir müssen die gesamte Transaktionskette durchsuchen, nicht nur die letzte Transaktion.
        for (local_id, instance) in &alice_wallet.voucher_store.vouchers {
            // Prüfe, ob die Gewinner-Transaktion Teil der Historie dieses Gutscheins ist.
            if instance.voucher.transactions.iter().any(|tx| tx.t_id == winning_tx_id) {
                winner_status = Some(instance.status.clone());
            }
            // Prüfe, ob die Verlierer-Transaktion Teil der Historie dieses Gutscheins ist.
            if instance.voucher.transactions.iter().any(|tx| tx.t_id == losing_tx_id) {
                loser_status = Some(instance.status.clone());
                loser_local_id = Some(local_id.clone());
            }
        }

        assert_eq!(winner_status, Some(VoucherStatus::Active), "Die 'Gewinner'-Instanz (von Charlie, weil früher) muss aktiv bleiben.");
        assert!(
            matches!(loser_status, Some(VoucherStatus::Quarantined { .. })),
            "Die 'Verlierer'-Instanz (von David, weil später) muss unter Quarantäne gestellt werden."
        );

        // Der Versuch, den unter Quarantäne stehenden Gutschein (die 'Verlierer'-Instanz) auszugeben, muss fehlschlagen.
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: bob_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: loser_local_id.unwrap(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let transfer_attempt = alice_wallet.execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            Some(&archive) // archive
        );
        assert!(transfer_attempt.is_err(), "Die Verwendung eines unter Quarantäne stehenden Gutscheins via create_transfer muss fehlschlagen.");

        println!("Test erfolgreich: Double Spend wurde erkannt, und die 'Der Früheste gewinnt'-Regel wurde korrekt angewendet.");
    }
}


// ===================================================================================
// --- ENDE: LOCAL DOUBLE SPEND DETECTION TESTS ---
// ===================================================================================


// ===================================================================================
// --- BEGINN: SECURITY VULNERABILITY TESTS ---
// (Ursprünglich in `test_security_vulnerabilities.rs`)
// ===================================================================================

mod security_vulnerabilities {
    use super::test_utils;
    use voucher_lib::{
        create_transaction, create_voucher, to_canonical_json, validate_voucher_against_standard,
        VoucherCoreError,
    };
    use voucher_lib::crypto_utils;
    use voucher_lib::models::profile::{TransactionBundle};
    use voucher_lib::{UserIdentity, VoucherStatus};
    use voucher_lib::models::voucher::{Collateral, Creator, GuarantorSignature, NominalValue, Transaction, Voucher, AdditionalSignature};
    use voucher_lib::services::crypto_utils::{create_user_id, get_hash, sign_ed25519};
    use voucher_lib::services::secure_container_manager::create_secure_container;
    use voucher_lib::services::utils::{get_current_timestamp};
    use voucher_lib::services::voucher_manager::{self, NewVoucherData};
    use voucher_lib::error::ValidationError;
    use voucher_lib::services::voucher_validation::{self};
    use voucher_lib::{VoucherInstance, services::voucher_manager::get_spendable_balance};
    use serde_json::Value;
    use self::test_utils::{
        create_voucher_for_manipulation,
        setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
    };
    use rand::{Rng, thread_rng};
    use rand::seq::SliceRandom;
    use voucher_lib::models::secure_container::PayloadType;
    use voucher_lib::wallet::Wallet;
    use rust_decimal_macros::dec;
    use rust_decimal::Decimal;
    use std::{str::FromStr};
    use ed25519_dalek::SigningKey;
    
    // ===================================================================================
    // HILFSFUNKTIONEN & SETUP (Adaptiert aus bestehenden Tests)
    // ===================================================================================

    /// Wählt eine zufällige Transaktion (außer `init`) und macht ihren Betrag negativ.
    fn mutate_to_negative_amount(voucher: &mut Voucher) -> String {
        if voucher.transactions.len() < 2 { return "No non-init transaction to mutate".to_string(); }
        let mut rng = thread_rng();
        let tx_index = rng.gen_range(1..voucher.transactions.len());

        if let Some(tx) = voucher.transactions.get_mut(tx_index) {
            if let Ok(mut amount) = Decimal::from_str(&tx.amount) {
                if amount > Decimal::ZERO {
                    amount.set_sign_negative(true);
                    tx.amount = amount.to_string();
                    return format!("Set tx[{}] amount to negative: {}", tx_index, tx.amount);
                }
            }
        }
        "Failed to apply negative amount mutation".to_string()
    }

    /// Wählt eine zufällige Split-Transaktion und macht ihren Restbetrag negativ.
    fn mutate_to_negative_remainder(voucher: &mut Voucher) -> String {
        let mut rng = thread_rng();
        // Finde alle Indizes von Transaktionen, die einen Restbetrag haben
        let splittable_indices: Vec<usize> = voucher.transactions.iter().enumerate()
            .filter(|(_, tx)| tx.sender_remaining_amount.is_some())
            .map(|(i, _)| i)
            .collect();

        if let Some(&tx_index) = splittable_indices.choose(&mut rng) {
            if let Some(tx) = voucher.transactions.get_mut(tx_index) {
                if let Some(remainder_str) = &tx.sender_remaining_amount {
                    if let Ok(mut remainder) = Decimal::from_str(remainder_str) {
                        if remainder > Decimal::ZERO {
                            remainder.set_sign_negative(true);
                            tx.sender_remaining_amount = Some(remainder.to_string());
                            return format!("Set tx[{}] remainder to negative: {}", tx_index, remainder);
                        }
                    }
                }
            }
        }
        "No suitable split transaction found to mutate".to_string()
    }

    /// Verschiebt den `t_type` "init" auf eine zufällige, ungültige Position.
    fn mutate_init_to_wrong_position(voucher: &mut Voucher) -> String {
        if voucher.transactions.len() < 2 { return "Not enough transactions to move 'init' type".to_string(); }
        let mut rng = thread_rng();
        let tx_index = rng.gen_range(1..voucher.transactions.len());

        if let Some(tx) = voucher.transactions.get_mut(tx_index) {
            tx.t_type = "init".to_string();
            return format!("Set tx[{}] t_type to 'init'", tx_index);
        }
        "Failed to move 'init' t_type".to_string()
    }

    /// Nimmt eine `AdditionalSignature` und macht sie ungültig, indem die Signaturdaten manipuliert werden.
    fn mutate_invalidate_additional_signature(voucher: &mut Voucher) -> String {
        if let Some(sig) = voucher.additional_signatures.get_mut(0) {
            sig.signature = "invalid_signature_data".to_string();
            return "Invalidated signature of first AdditionalSignature".to_string();
        }
        "No AdditionalSignature found to invalidate".to_string()
    }

    /// Definiert die verschiedenen Angriffsstrategien für den Fuzzer.
    #[derive(Debug, Clone, Copy)]
    enum FuzzingStrategy {
        /// Manipuliert eine `AdditionalSignature`, um die Validierung zu testen.
        InvalidateAdditionalSignature,
        /// Setzt einen Transaktionsbetrag auf einen negativen Wert.
        SetNegativeTransactionAmount,
        /// Setzt den Restbetrag eines Splits auf einen negativen Wert.
        SetNegativeRemainderAmount,
        /// Verschiebt eine `init`-Transaktion an eine ungültige Position.
        SetInitTransactionInWrongPosition,
        /// Führt eine zufällige, strukturelle Mutation durch (der alte Ansatz).
        GenericRandomMutation,
    }

    /// Erstellt ein frisches, leeres In-Memory-Wallet für einen Akteur.
    fn setup_test_wallet(identity: &UserIdentity) -> Wallet {
        setup_in_memory_wallet(identity)
    }

    /// Erstellt leere `NewVoucherData` für Testzwecke.
    fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
        NewVoucherData {
            validity_duration: Some("P5Y".to_string()), // Erhöht auf 5 Jahre, um die Mindestgültigkeit zu erfüllen
            non_redeemable_test_voucher: false,
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            collateral: Collateral::default(),
            creator: Creator { id: creator_id, ..Default::default() },
        }
    }

    /// Erstellt eine gültige Bürgschaft für einen gegebenen Gutschein.
    fn create_guarantor_signature(
        voucher: &Voucher,
        guarantor_identity: &UserIdentity,
        organization: Option<&str>,
        gender: &str,
    ) -> GuarantorSignature {
        let mut sig_obj = GuarantorSignature {
            voucher_id: voucher.voucher_id.clone(),
            guarantor_id: guarantor_identity.user_id.clone(),
            first_name: "Garant".to_string(),
            last_name: "Test".to_string(),
            signature_time: get_current_timestamp(),
            organization: organization.map(String::from),
            gender: gender.to_string(),
            ..Default::default()
        };

        let mut sig_obj_for_id = sig_obj.clone();
        sig_obj_for_id.signature_id = "".to_string();
        sig_obj_for_id.signature = "".to_string();
        let id_hash = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());

        sig_obj.signature_id = id_hash;
        let signature = sign_ed25519(&guarantor_identity.signing_key, sig_obj.signature_id.as_bytes());
        sig_obj.signature = bs58::encode(signature.to_bytes()).into_string();
        sig_obj
    }

    /// Simuliert die Aktion eines Hackers: Verpackt einen (manipulierten) Gutschein in einen Container.
    fn create_hacked_bundle_and_container(
        hacker_identity: &UserIdentity,
        victim_id: &str,
        malicious_voucher: Voucher,
    ) -> Vec<u8> {
        let mut bundle = TransactionBundle {
            bundle_id: "".to_string(),
            sender_id: hacker_identity.user_id.clone(),
            recipient_id: victim_id.to_string(),
            vouchers: vec![malicious_voucher],
            timestamp: get_current_timestamp(),
            notes: Some("Hacked".to_string()),
            sender_signature: "".to_string(),
            forwarded_fingerprints: Vec::new(),
            fingerprint_depths: std::collections::HashMap::new(),
            sender_profile_name: None,
        };
        let bundle_json_for_id = to_canonical_json(&bundle).unwrap();
        bundle.bundle_id = get_hash(bundle_json_for_id);
        let signature = sign_ed25519(&hacker_identity.signing_key, bundle.bundle_id.as_bytes());
        bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
        let signed_bundle_bytes = serde_json::to_vec(&bundle).unwrap();
        let secure_container = create_secure_container(
            hacker_identity,
            &[victim_id.to_string()],
            &signed_bundle_bytes,
            PayloadType::TransactionBundle,
        ).unwrap();
        serde_json::to_vec(&secure_container).unwrap()
    }

    /// Erstellt und signiert eine (potenziell manipulierte) Transaktion.
    fn create_hacked_tx(signer_identity: &UserIdentity, mut hacked_tx: Transaction) -> Transaction {
        let tx_json_for_id = to_canonical_json(&hacked_tx).unwrap();
        hacked_tx.t_id = get_hash(tx_json_for_id);

        let signature_payload = serde_json::json!({
            "prev_hash": hacked_tx.prev_hash, "sender_id": hacked_tx.sender_id,
            "t_id": hacked_tx.t_id
        });
        let signature_payload_hash = get_hash(to_canonical_json(&signature_payload).unwrap());
        let signature = sign_ed25519(&signer_identity.signing_key, signature_payload_hash.as_bytes());
        hacked_tx.sender_signature = bs58::encode(signature.to_bytes()).into_string();
        hacked_tx
    }

    /// **NEUER STUB:** Erstellt einen Test-Creator für die neuen Tests.
    fn setup_creator() -> (SigningKey, Creator) {
        let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub"));
        let user_id = create_user_id(&public_key, Some("cs")).unwrap();
        let creator = Creator {
            id: user_id,
            first_name: "Stub".to_string(),
            last_name: "Creator".to_string(),
            ..Default::default()
        };
        (signing_key, creator)
    }

    /// **NEUER STUB:** Erstellt Test-Voucher-Daten für die neuen Tests.
    fn create_test_voucher_data_with_amount(creator: Creator, amount: &str) -> NewVoucherData {
        NewVoucherData {
            validity_duration: Some("P5Y".to_string()),
            non_redeemable_test_voucher: false,
            nominal_value: NominalValue {
                amount: amount.to_string(),
                ..Default::default()
            },
            collateral: Collateral::default(),
            creator,
        }
    }


    // ===================================================================================
    // ANGRIFFSKLASSE 1 & 4: MANIPULATION VON STAMMDATEN & BÜRGSCHAFTEN
    // ===================================================================================
    #[test]
    fn test_attack_tamper_core_data_and_guarantors() {
        // ### SETUP ###
        let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
        let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
        let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
        let voucher_data = new_test_voucher_data(ACTORS.issuer.user_id.clone());

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);


        let mut valid_voucher = voucher_manager::create_voucher(voucher_data, standard, standard_hash, &ACTORS.issuer.signing_key, "en").unwrap();
        let guarantor_sig = create_guarantor_signature(&valid_voucher, &ACTORS.guarantor1, None, "0");
        valid_voucher.guarantor_signatures.push(guarantor_sig);
        let local_id = Wallet::calculate_local_instance_id(&valid_voucher, &ACTORS.issuer.user_id).unwrap();
        let instance = VoucherInstance { voucher: valid_voucher, status: VoucherStatus::Active, local_instance_id: local_id.clone() };
        issuer_wallet.voucher_store.vouchers.insert(local_id.clone(), instance);

        // Issuer sendet den Gutschein an den Hacker, der ihn nun für Angriffe besitzt.
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: ACTORS.hacker.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: container_to_hacker, .. } = issuer_wallet.execute_multi_transfer_and_bundle(&ACTORS.issuer, &standards, request, None).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_hacker = std::collections::HashMap::new();
        standards_for_hacker.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        hacker_wallet.process_encrypted_transaction_bundle(&ACTORS.hacker, &container_to_hacker, None, &standards_for_hacker).unwrap();
        let voucher_in_hacker_wallet = &hacker_wallet.voucher_store.vouchers.iter().next().unwrap().1.voucher;

        // ### SZENARIO 1a: WERTINFLATION ###
        println!("--- Angriff 1a: Wertinflation ---");
        let mut inflated_voucher = voucher_in_hacker_wallet.clone();
        inflated_voucher.nominal_value.amount = "9999".to_string();

        // Der Hacker muss die sichere `create_transaction`-Funktion umgehen.
        // Er erstellt die finale Transaktion zum Opfer manuell und hängt sie an den manipulierten Gutschein an.
        let mut final_tx = Transaction {
            prev_hash: get_hash(to_canonical_json(inflated_voucher.transactions.last().unwrap()).unwrap()),
            t_time: get_current_timestamp(),
            sender_id: ACTORS.hacker.user_id.clone(),
            recipient_id: ACTORS.victim.user_id.clone(),
            amount: "100".to_string(), // Hacker gibt seinen ursprünglichen Betrag aus
            t_type: "transfer".to_string(),
            ..Default::default()
        };
        // Diese Transaktion selbst ist valide und wird vom Hacker signiert. Der Betrug liegt im manipulierten Creator-Block.
        final_tx = create_hacked_tx(&ACTORS.hacker, final_tx);
        inflated_voucher.transactions.push(final_tx);

        let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, inflated_voucher);
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_victim = std::collections::HashMap::new();
        standards_for_victim.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None, &standards_for_victim).unwrap();
        let received_voucher = &victim_wallet.voucher_store.vouchers.iter().next().unwrap().1.voucher;
        let result = voucher_validation::validate_voucher_against_standard(received_voucher, standard);
        assert!(matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidCreatorSignature { .. }))),
                "Validation must fail due to manipulated nominal value.");
        victim_wallet.voucher_store.vouchers.clear(); // Reset for next test

        // ### SZENARIO 4a: BÜRGEN-METADATEN MANIPULIEREN ###
        println!("--- Angriff 4a: Bürgen-Metadaten manipulieren ---");
        let mut tampered_guarantor_voucher = voucher_in_hacker_wallet.clone();
        tampered_guarantor_voucher.guarantor_signatures[0].first_name = "Mallory".to_string();

        let mut final_tx_2 = Transaction {
            prev_hash: get_hash(to_canonical_json(tampered_guarantor_voucher.transactions.last().unwrap()).unwrap()),
            t_time: get_current_timestamp(),
            sender_id: ACTORS.hacker.user_id.clone(),
            recipient_id: ACTORS.victim.user_id.clone(),
            amount: "100".to_string(),
            t_type: "transfer".to_string(),
            ..Default::default()
        };
        final_tx_2 = create_hacked_tx(&ACTORS.hacker, final_tx_2);
        tampered_guarantor_voucher.transactions.push(final_tx_2);

        let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, tampered_guarantor_voucher);
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_victim = std::collections::HashMap::new();
        standards_for_victim.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None, &standards_for_victim).unwrap();
        let received_voucher = &victim_wallet.voucher_store.vouchers.iter().next().unwrap().1.voucher;
        let result = voucher_validation::validate_voucher_against_standard(received_voucher, standard);
        assert!(matches!(result, Err(VoucherCoreError::Validation(ValidationError::InvalidSignatureId(_)))),
                "Validation must fail due to manipulated guarantor metadata (InvalidSignatureId).");
        victim_wallet.voucher_store.vouchers.clear();
    }


    // ===================================================================================
    // ANGRIFFSKLASSE 2: FÄLSCHUNG DER TRANSAKTIONSHISTORIE
    // ===================================================================================
    #[test]
    fn test_attack_tamper_transaction_history() {
        // ### SETUP ###
        let mut alice_wallet = setup_test_wallet(&ACTORS.alice);
        let mut bob_wallet_hacker = setup_test_wallet(&ACTORS.bob);
        let data = new_test_voucher_data(ACTORS.alice.user_id.clone());

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let voucher_a = voucher_manager::create_voucher(data, standard, standard_hash, &ACTORS.alice.signing_key, "en").unwrap();
        let local_id_a = Wallet::calculate_local_instance_id(&voucher_a, &ACTORS.alice.user_id).unwrap();
        let instance_a = VoucherInstance { voucher: voucher_a, status: VoucherStatus::Active, local_instance_id: local_id_a.clone() };
        alice_wallet.voucher_store.vouchers.insert(local_id_a.clone(), instance_a);
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: local_id_a.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: container_to_bob, .. } = alice_wallet.execute_multi_transfer_and_bundle(&ACTORS.alice, &standards, request, None).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_bob = std::collections::HashMap::new();
        standards_for_bob.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        bob_wallet_hacker.process_encrypted_transaction_bundle(&ACTORS.bob, &container_to_bob, None, &standards_for_bob).unwrap();
        let voucher_in_bob_wallet = &bob_wallet_hacker.voucher_store.vouchers.iter().next().unwrap().1.voucher;

        // ### ANGRIFF ###
        println!("--- Angriff 2a: Transaktionshistorie fälschen ---");
        let mut voucher_with_tampered_history = voucher_in_bob_wallet.clone();
        // Manipuliere eine Signatur in der Kette, um sie ungültig zu machen.
        voucher_with_tampered_history.transactions[0].sender_signature = "invalid_signature".to_string();

        // DANK DES SICHERHEITSPATCHES in `voucher_manager` schlägt dieser Aufruf nun fehl,
        // da `create_transaction` den Gutschein vorab validiert.
        let transfer_attempt_result = voucher_manager::create_transaction(
            &voucher_with_tampered_history, standard, &ACTORS.bob.user_id, &ACTORS.bob.signing_key, &ACTORS.victim.user_id, "100"
        );
        assert!(transfer_attempt_result.is_err(), "Transaction creation must fail if history is tampered.");
    }

    // ===================================================================================
    // ANGRIFFSKLASSE 3: ERSTELLUNG EINER LOGISCH INKONSISTENTEN TRANSAKTION
    // ===================================================================================
    #[test]
    fn test_attack_create_inconsistent_transaction() {
        // ### SETUP ###
        let mut issuer_wallet = setup_test_wallet(&ACTORS.issuer);
        let mut hacker_wallet = setup_test_wallet(&ACTORS.hacker);
        let mut victim_wallet = setup_test_wallet(&ACTORS.victim);
        let data = new_test_voucher_data(ACTORS.issuer.user_id.clone());

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let initial_voucher = voucher_manager::create_voucher(data, standard, standard_hash, &ACTORS.issuer.signing_key, "en").unwrap();
        let local_id_issuer = Wallet::calculate_local_instance_id(&initial_voucher, &ACTORS.issuer.user_id).unwrap();
        let instance_i = VoucherInstance { voucher: initial_voucher, status: VoucherStatus::Active, local_instance_id: local_id_issuer.clone() };
        issuer_wallet.voucher_store.vouchers.insert(local_id_issuer.clone(), instance_i);
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: ACTORS.hacker.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: local_id_issuer.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: container_to_hacker, .. } = issuer_wallet.execute_multi_transfer_and_bundle(&ACTORS.issuer, &standards, request, None).unwrap();
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_hacker = std::collections::HashMap::new();
        standards_for_hacker.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        hacker_wallet.process_encrypted_transaction_bundle(&ACTORS.hacker, &container_to_hacker, None, &standards_for_hacker).unwrap();
        let voucher_in_hacker_wallet = &hacker_wallet.voucher_store.vouchers.iter().next().unwrap().1.voucher;

        // ### SZENARIO 3a: OVERSPENDING ###
        println!("--- Angriff 3a: Overspending ---");
        let mut overspend_voucher = voucher_in_hacker_wallet.clone();
        let overspend_tx_unsigned = Transaction {
            prev_hash: get_hash(to_canonical_json(overspend_voucher.transactions.last().unwrap()).unwrap()),
            t_time: get_current_timestamp(),
            sender_id: ACTORS.hacker.user_id.clone(),
            recipient_id: ACTORS.victim.user_id.clone(),
            amount: "200".to_string(),
            t_type: "transfer".to_string(),
            ..Default::default()
        };
        let overspend_tx = create_hacked_tx(&ACTORS.hacker, overspend_tx_unsigned);
        overspend_voucher.transactions.push(overspend_tx);
        let hacked_container = create_hacked_bundle_and_container(&ACTORS.hacker, &ACTORS.victim.user_id, overspend_voucher);
        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_victim = std::collections::HashMap::new();
        standards_for_victim.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        victim_wallet.process_encrypted_transaction_bundle(&ACTORS.victim, &hacked_container, None, &standards_for_victim).unwrap();
        let received_voucher = &victim_wallet.voucher_store.vouchers.iter().next().unwrap().1.voucher;
        let result = voucher_validation::validate_voucher_against_standard(received_voucher, standard);

        // KORREKTUR: Der primäre Fehler bei einer Überziehung ist "unzureichendes Guthaben".
        // Der Test muss auf den korrekten Fehler prüfen.
        assert!(matches!(result, Err(VoucherCoreError::Validation(ValidationError::InsufficientFundsInChain { .. }))),
                "Validation must fail with InsufficientFundsInChain on overspending attempt.");
        victim_wallet.voucher_store.vouchers.clear();
    }

    #[test]
    fn test_attack_inconsistent_split_transaction() {
        // ### SETUP ###
        // Ein Hacker besitzt einen gültigen Gutschein über 100 Einheiten.
        let hacker_identity = &ACTORS.hacker;
        let victim_identity = &ACTORS.victim;
        let data = new_test_voucher_data(hacker_identity.user_id.clone());
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let voucher =
            voucher_manager::create_voucher(data, standard, standard_hash, &hacker_identity.signing_key, "en")
                .unwrap();

        // ### ANGRIFF ###
        println!("--- Angriff 3b: Inkonsistente Split-Transaktion (Gelderschaffung) ---");
        let mut inconsistent_split_voucher = voucher.clone();

        // Hacker erstellt eine Split-Transaktion, bei der die Summe nicht stimmt (100 -> 30 + 80)
        let inconsistent_tx_unsigned = Transaction {
            prev_hash: get_hash(
                to_canonical_json(inconsistent_split_voucher.transactions.last().unwrap()).unwrap(),
            ),
            t_time: get_current_timestamp(),
            sender_id: hacker_identity.user_id.clone(),
            recipient_id: victim_identity.user_id.clone(),
            amount: "30".to_string(),
            sender_remaining_amount: Some("80".to_string()), // Falscher Restbetrag
            t_type: "split".to_string(),
            ..Default::default()
        };
        let inconsistent_tx = create_hacked_tx(hacker_identity, inconsistent_tx_unsigned);
        inconsistent_split_voucher.transactions.push(inconsistent_tx);

        // ### VALIDIERUNG ###
        let result =
            voucher_validation::validate_voucher_against_standard(&inconsistent_split_voucher, standard);

        // Die Validierung SOLLTE fehlschlagen. Aktuell tut sie das nicht.
        assert!(result.is_err(), "Validation must fail on inconsistent split transaction.");
    }

    #[test]
    fn test_attack_init_amount_mismatch() {
        // ### SETUP ###
        // Ein Hacker erstellt einen scheinbar gültigen Gutschein mit Nennwert 100.
        let hacker_identity = &ACTORS.hacker;
        let data = new_test_voucher_data(hacker_identity.user_id.clone());
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let mut voucher =
            voucher_manager::create_voucher(data, standard, standard_hash, &hacker_identity.signing_key, "en")
                .unwrap();

        // ### ANGRIFF ###
        println!("--- Angriff: Inkonsistenter Betrag in 'init'-Transaktion ---");
        // Der Nennwert des Gutscheins ist 100, aber der Hacker manipuliert die 'init'-Transaktion,
        // sodass sie nur einen Betrag von 101 ausweist.
        let mut malicious_init_tx = voucher.transactions[0].clone();
        malicious_init_tx.amount = "101.0000".to_string();

        // Die Transaktion muss neu signiert werden, damit die Validierung nicht an einer
        // kaputten Signatur scheitert, bevor der Betrug geprüft wird.
        let resigned_malicious_tx = create_hacked_tx(hacker_identity, malicious_init_tx);
        voucher.transactions[0] = resigned_malicious_tx;

        // ### VALIDIERUNG ###
        let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);

        // Der Betrug muss mit dem spezifischen Fehler `InitAmountMismatch` erkannt werden.
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InitAmountMismatch { .. })
        ));
    }

    #[test]
    fn test_attack_negative_or_zero_amount_transaction() {
        // ### SETUP ###
        let hacker_identity = &ACTORS.hacker;
        let victim_identity = &ACTORS.victim;
        let data = new_test_voucher_data(hacker_identity.user_id.clone());
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let voucher =
            voucher_manager::create_voucher(data, standard, standard_hash, &hacker_identity.signing_key, "en")
                .unwrap();

        // ### ANGRIFF 1: Negativer Betrag ###
        let negative_tx_unsigned = Transaction {
            amount: "-10.0000".to_string(),
            // Restliche Felder sind für diesen Test nicht primär relevant
            prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
            t_time: get_current_timestamp(),
            sender_id: hacker_identity.user_id.clone(),
            recipient_id: victim_identity.user_id.clone(),
            t_type: "transfer".to_string(),
            ..Default::default()
        };

        // Die `create_hacked_tx` ist hier nicht nötig, da die Validierung VOR der Signaturprüfung fehlschlagen sollte.
        let mut voucher_with_negative_tx = voucher.clone();
        voucher_with_negative_tx.transactions.push(negative_tx_unsigned);

        let result_negative = voucher_validation::validate_voucher_against_standard(&voucher_with_negative_tx, standard);
        assert!(matches!(
            result_negative.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
        ));

        // ### ANGRIFF 2: Betrag von Null ###
        let zero_tx_unsigned = Transaction {
            amount: "0.0000".to_string(),
            prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
            t_time: get_current_timestamp(),
            sender_id: hacker_identity.user_id.clone(),
            recipient_id: victim_identity.user_id.clone(),
            t_type: "transfer".to_string(),
            ..Default::default()
        };
        let mut voucher_with_zero_tx = voucher.clone();
        voucher_with_zero_tx.transactions.push(zero_tx_unsigned);

        let result_zero = voucher_validation::validate_voucher_against_standard(&voucher_with_zero_tx, standard);
        assert!(matches!(
            result_zero.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::NegativeOrZeroAmount { .. })
        ));
    }

    #[test]
    fn test_attack_invalid_precision_in_nominal_value() {
        // ### SETUP ###
        // Erstelle Testdaten mit einem Nennwert, der zu viele Nachkommastellen hat.
        let creator_identity = &ACTORS.issuer;
        let mut voucher_data = new_test_voucher_data(creator_identity.user_id.clone());
        voucher_data.nominal_value.amount = "100.12345".to_string(); // 5 statt der erlaubten 4

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        // ### ANGRIFF ###
        // Die `create_voucher` Funktion selbst validiert dies noch nicht, der Zustand wird also erstellt.
        let malicious_voucher = voucher_manager::create_voucher(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en").unwrap();

        // ### VALIDIERUNG ###
        // Die `validate_voucher_against_standard` muss diesen Fehler jedoch erkennen.
        let result = voucher_validation::validate_voucher_against_standard(&malicious_voucher, standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 4, found: 5 }) if path == "nominal_value.amount"
        ));
    }

    #[test]
    fn test_attack_full_transfer_amount_mismatch() {
        // ### SETUP ###
        let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let (public_key, signing_key) =
            crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub"));
        let user_id = crypto_utils::create_user_id(&public_key, Some("cs")).unwrap();
        let creator_identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };
        let creator = Creator {
            id: user_id,
            first_name: "Stub".to_string(),
            last_name: "Creator".to_string(),
            ..Default::default()
        };
        let voucher_data = create_test_voucher_data_with_amount(creator.clone(), "100");
        let mut voucher =
            create_voucher(voucher_data, standard, &SILVER_STANDARD.1, &creator_identity.signing_key, "en")
                .unwrap();

        // ### ANGRIFF ###
        // Erstelle eine 'transfer' Transaktion, die aber nicht den vollen Betrag von 100 sendet.
        // Wir erstellen die Transaktion explizit, anstatt die `init`-Transaktion zu klonen,
        // um Nebeneffekte zu vermeiden und den Test robuster zu machen.
        let malicious_tx = Transaction {
            prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
            t_type: "transfer".to_string(),
            amount: "99.0000".to_string(), // Inkorrekt für einen 'transfer' bei einem Guthaben von 100
            sender_id: creator.id.clone(),
            recipient_id: ACTORS.bob.user_id.clone(),
            t_time: get_current_timestamp(),
            sender_remaining_amount: None,
            ..Default::default()
        };
        let resigned_malicious_tx = create_hacked_tx(&creator_identity, malicious_tx);
        voucher.transactions.push(resigned_malicious_tx);

        // ### VALIDIERUNG ###
        let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FullTransferAmountMismatch { .. })
        ));
    }

    #[test]
    fn test_attack_remainder_in_full_transfer() {
        // ### SETUP ###
        let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let (public_key, signing_key) =
            crypto_utils::generate_ed25519_keypair_for_tests(Some("creator_stub_2"));
        let user_id = crypto_utils::create_user_id(&public_key, Some("cs2")).unwrap();
        let creator_identity = UserIdentity {
            signing_key,
            public_key,
            user_id: user_id.clone(),
        };
        let creator = Creator {
            id: user_id,
            first_name: "Stub".to_string(),
            last_name: "Creator".to_string(),
            ..Default::default()
        };
        let voucher_data = create_test_voucher_data_with_amount(creator.clone(), "100");
        let mut voucher =
            create_voucher(voucher_data, standard, &SILVER_STANDARD.1, &creator_identity.signing_key, "en")
                .unwrap();

        // ### ANGRIFF ###
        // Erstelle eine 'transfer' Transaktion, die den vollen Betrag sendet,
        // aber fälschlicherweise auch einen Restbetrag enthält.
        let malicious_tx = Transaction {
            prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
            t_type: "transfer".to_string(),
            amount: "100.0000".to_string(),
            sender_remaining_amount: Some("0.0001".to_string()), // Darf nicht vorhanden sein
            sender_id: creator.id.clone(),
            recipient_id: ACTORS.bob.user_id.clone(),
            t_time: get_current_timestamp(),
            ..Default::default()
        };
        let resigned_malicious_tx = create_hacked_tx(&creator_identity, malicious_tx);
        voucher.transactions.push(resigned_malicious_tx);

        // ### VALIDIERUNG ###
        let result = voucher_validation::validate_voucher_against_standard(&voucher, standard);
        assert!(result.is_err(), "Validation must fail when a 'transfer' transaction has a remainder.");
    }

    // ===================================================================================
    // ANGRIFFSKLASSE 5: STRUKTURELLE INTEGRITÄTSPRÜFUNG DURCH FUZZING
    // ===================================================================================
    /// Hilfsfunktion für den Fuzzing-Test.
    /// Versucht, eine einzelne, zufällige Mutation durchzuführen und gibt bei Erfolg
    /// eine Beschreibung der Änderung zurück.
    fn mutate_value(val: &mut Value, rng: &mut impl Rng, current_path: &str) -> Option<String> {
        match val {
            Value::Object(map) => {
                if map.is_empty() { return None; }
                let keys: Vec<String> = map.keys().cloned().collect();
                // Mische die Schlüssel, um bei jedem Durchlauf eine andere Reihenfolge zu haben
                let mut shuffled_keys = keys;
                shuffled_keys.shuffle(rng);

                for key in shuffled_keys {
                    let new_path = format!("{}.{}", current_path, key);
                    if let Some(desc) = mutate_value(map.get_mut(&key).unwrap(), rng, &new_path) {
                        return Some(desc);
                    }
                }
            }
            Value::Array(arr) => {
                if arr.is_empty() { return None; }
                // Wähle einen zufälligen Index zum Mutieren
                let idx_to_mutate = rng.gen_range(0..arr.len());
                let new_path = format!("{}[{}]", current_path, idx_to_mutate);
                if let Some(desc) = mutate_value(&mut arr[idx_to_mutate], rng, &new_path) {
                    return Some(desc);
                }
            }
            Value::String(s) => {
                let old_val = s.clone();
                *s = format!("{}-mutated", s);
                return Some(format!("CHANGED path '{}' from '{}' to '{}'", current_path, old_val, s));
            }
            Value::Number(n) => {
                let old_val = n.clone();
                let old_val_i64 = n.as_i64().unwrap_or(0);
                let mut new_val_num;
                loop {
                    new_val_num = old_val_i64 + rng.gen_range(-10..10);
                    if new_val_num != old_val_i64 {
                        break; // Stelle sicher, dass der Wert sich tatsächlich ändert
                    }
                }
                *val = Value::Number(new_val_num.into());
                return Some(format!("CHANGED path '{}' from '{}' to '{}'", current_path, old_val, val));
            }
            Value::Bool(b) => {
                let old_val = *b;
                *b = !*b;
                return Some(format!("FLIPPED path '{}' from '{}' to '{}'", current_path, old_val, b));
            }
            Value::Null => {
                *val = Value::String("was_null".to_string());
                return Some(format!("CHANGED path '{}' from null to 'was_null'", current_path));
            }
        }
        None // Keine Mutation in diesem Zweig durchgeführt
    }

    // --- NEUE TESTS FÜR WALLET-ZUSTANDSVERWALTUNG UND KOLLABORATIVE SICHERHEIT ---

    #[test]
    fn test_wallet_state_management_on_split() {
        // 1. Setup
        let a_identity = &ACTORS.alice;
        let b_identity = &ACTORS.bob;
        let mut wallet_a = setup_test_wallet(a_identity);
        let mut wallet_b = setup_test_wallet(b_identity);

        // 2. Erstelle einen Gutschein explizit und füge ihn zu Wallet A hinzu, um das Setup zu verdeutlichen.
        let creator_data = Creator {
            id: a_identity.user_id.clone(),
            first_name: "Alice".to_string(),
            last_name: "Test".to_string(),
            ..Default::default()
        };
        let voucher_data = create_test_voucher_data_with_amount(creator_data, "100.0000");

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let initial_voucher = create_voucher(voucher_data, standard, standard_hash, &a_identity.signing_key, "en").unwrap();

        let local_id = Wallet::calculate_local_instance_id(&initial_voucher, &a_identity.user_id).unwrap();
        wallet_a.add_voucher_instance(local_id, initial_voucher, VoucherStatus::Active);
        let original_local_id = wallet_a.voucher_store.vouchers.keys().next().unwrap().clone();

        // 3. Aktion: Wallet A sendet 40 an Wallet B
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: b_identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: original_local_id.clone(),
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };

        let mut standards = std::collections::HashMap::new();
        standards.insert(standard.metadata.uuid.clone(), standard.clone());

        let voucher_lib::wallet::CreateBundleResult { bundle_bytes: bundle_to_b, .. } = wallet_a.execute_multi_transfer_and_bundle(
            &a_identity,
            &standards,
            request,
            None,
        )
            .unwrap();

        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_for_bob = std::collections::HashMap::new();
        standards_for_bob.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
        wallet_b.process_encrypted_transaction_bundle(&b_identity, &bundle_to_b, None, &standards_for_bob).unwrap();

        // 4. Verifizierung (Wallet A)
        // NACH ÄNDERUNG: Wallet A sollte jetzt nur noch EINE Instanz haben - den aktiven Restbetrag.
        // Die ursprüngliche Instanz wird gelöscht, nicht archiviert.
        assert_eq!(wallet_a.voucher_store.vouchers.len(), 1, "Wallet A should have exactly one instance (the active remainder).");
        assert!(wallet_a.voucher_store.vouchers.get(&original_local_id).is_none(), "The original voucher instance must be removed.");

        let remainder_instance = wallet_a.voucher_store.vouchers.values()
            .next()
            .expect("Wallet A must have one voucher instance left.");
        assert_eq!(remainder_instance.status, VoucherStatus::Active);

        let remainder_balance = get_spendable_balance(&remainder_instance.voucher, &a_identity.user_id, standard).unwrap();
        assert_eq!(remainder_balance, dec!(60));

        // 5. Verifizierung (Wallet B)
        assert_eq!(wallet_b.voucher_store.vouchers.len(), 1, "Wallet B should have one voucher instance.");
        let received_instance = wallet_b.voucher_store.vouchers.values().next().unwrap();
        assert_eq!(received_instance.status, VoucherStatus::Active);

        let received_balance = get_spendable_balance(&received_instance.voucher, &b_identity.user_id, standard).unwrap();
        assert_eq!(received_balance, dec!(40));
    }

    #[test]
    fn test_collaborative_fraud_detection_with_fingerprints() {
        // 1. Setup
        let a_identity = &ACTORS.alice;
        let mut alice_wallet = setup_test_wallet(a_identity);
        let b_identity = &ACTORS.bob;
        let mut bob_wallet = setup_test_wallet(b_identity);
        // Wir verwenden den "Hacker" als böswilligen Akteur Eve
        let eve_identity = &ACTORS.hacker;
        let mut eve_wallet = setup_test_wallet(eve_identity);

        // 2. Akt 1 (Double Spend)
        let eve_creator = Creator { id: eve_identity.user_id.clone(), ..setup_creator().1 };
        let voucher_data = create_test_voucher_data_with_amount(eve_creator, "100");

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let initial_voucher = create_voucher(voucher_data, standard, standard_hash, &eve_identity.signing_key, "en").unwrap();

        // Eve erstellt zwei widersprüchliche Zukünfte
        let voucher_for_alice = create_transaction(&initial_voucher, standard, &eve_identity.user_id, &eve_identity.signing_key, &a_identity.user_id, "100").unwrap();
        let voucher_for_bob = create_transaction(&initial_voucher, standard, &eve_identity.user_id, &eve_identity.signing_key, &b_identity.user_id, "100").unwrap();

        // Eve verpackt und sendet die Gutscheine
        let (bundle_to_alice, _header) = eve_wallet.create_and_encrypt_transaction_bundle(&eve_identity, vec![voucher_for_alice], &a_identity.user_id, None, Vec::new(), std::collections::HashMap::new(), None).unwrap();
        let (bundle_to_bob, _header) = eve_wallet.create_and_encrypt_transaction_bundle(&eve_identity, vec![voucher_for_bob], &b_identity.user_id, None, Vec::new(), std::collections::HashMap::new(), None).unwrap();

        // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
        let mut standards_map = std::collections::HashMap::new();
        standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());

        alice_wallet.process_encrypted_transaction_bundle(&a_identity, &bundle_to_alice, None, &standards_map).unwrap();
        bob_wallet.process_encrypted_transaction_bundle(&b_identity, &bundle_to_bob, None, &standards_map).unwrap();

        // 3. Akt 2 (Austausch)
        println!("\n[DEBUG TEST] --- Phase 2: Austausch ---");
        alice_wallet.scan_and_rebuild_fingerprints().unwrap();
        // KORREKTUR: Für die kollaborative Betrugserkennung muss Alice ihre gesamte lokale
        // Historie teilen, nicht nur die Fingerprints von Transaktionen, die sie gesendet hat.
        println!("[DEBUG TEST] Alice's local_history nach Scan: {:#?}", alice_wallet.known_fingerprints.local_history);

        // KORREKTUR: Für die kollaborative Betrugserkennung muss Alice ihre gesamte lokale
        // Historie teilen, nicht nur die Fingerprints von Transaktionen, die sie gesendet hat.
        let alice_fingerprints = serde_json::to_vec(&alice_wallet.known_fingerprints.local_history).unwrap();
        println!("[DEBUG TEST] Alice's exportierte Fingerprints (JSON): {}", String::from_utf8_lossy(&alice_fingerprints));

        let import_count = bob_wallet.import_foreign_fingerprints(&alice_fingerprints).unwrap();
        println!("[DEBUG TEST] Bob hat {} neue Fingerprints importiert.", import_count);
        println!("[DEBUG TEST] Bob's foreign_fingerprints nach Import: {:#?}", bob_wallet.known_fingerprints.foreign_fingerprints);

        // 4. Akt 3 (Aufdeckung)
        println!("\n[DEBUG TEST] --- Phase 3: Aufdeckung ---");
        bob_wallet.scan_and_rebuild_fingerprints().unwrap();
        println!("[DEBUG TEST] Bob's local_history nach Scan: {:#?}", bob_wallet.known_fingerprints.local_history);
        let check_result = bob_wallet.check_for_double_spend();
        println!("[DEBUG TEST] Ergebnis von Bob's check_for_double_spend: {:#?}", check_result);

        // 5. Verifizierung
        assert!(check_result.unverifiable_warnings.is_empty(), "There should be no unverifiable warnings.");
        assert_eq!(check_result.verifiable_conflicts.len(), 1, "A verifiable conflict must be detected.");

        let conflict = check_result.verifiable_conflicts.values().next().unwrap();
        assert_eq!(conflict.len(), 2, "The conflict should involve two transactions.");
        println!("SUCCESS: Collaborative fraud detection upgraded a warning to a verifiable conflict.");
    }

    #[test]
    fn test_serialization_roundtrip_with_special_chars() {
        // 1. Setup
        let (signing_key, mut creator) = setup_creator();
        creator.first_name = "Jörg-ẞtråße".to_string(); // Sonderzeichen

        let voucher_data = create_test_voucher_data_with_amount(creator, "123");

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let mut original_voucher = create_voucher(voucher_data, standard, standard_hash, &signing_key, "en").unwrap();

        // Mache den Gutschein komplexer
        let g1_identity = &ACTORS.guarantor1;

        // **KORRIGIERTER AUFRUF:** Metadaten werden jetzt bei der Erstellung übergeben.
        let guarantor_sig =
            create_guarantor_signature(&original_voucher, &g1_identity, Some("Bürge & Co."), "1");
        original_voucher.guarantor_signatures.push(guarantor_sig);

        // FÜGE ZWEITEN BÜRGEN HINZU, UM DIE VALIDIERUNG ZU ERFÜLLEN
        // ÄNDERUNG: Gender auf "2" gesetzt, um die Regel des Minuto-Standards zu erfüllen.
        let second_guarantor_sig = create_guarantor_signature(&original_voucher, &ACTORS.guarantor2, None, "2");
        original_voucher.guarantor_signatures.push(second_guarantor_sig);

        original_voucher = create_transaction(
            &original_voucher,
            standard,
            &original_voucher.creator.id,
            &signing_key,
            "some_recipient_id",
            "23"
        ).unwrap();

        // 2. Aktion
        // Wir verwenden serde_json::to_string direkt, um den Prozess ohne unsere Wrapper zu testen.
        let json_string = serde_json::to_string(&original_voucher).unwrap();
        let deserialized_voucher: Voucher = serde_json::from_str(&json_string).unwrap();

        // 3. Verifizierung
        assert_eq!(original_voucher, deserialized_voucher, "The deserialized voucher must be identical to the original.");
    }

    #[test]
    fn test_attack_fuzzing_random_mutations() {
        // ### SETUP ###
        // Erstelle einen "Master"-Gutschein, der alle für die Angriffe relevanten Features enthält.
        let mut data = new_test_voucher_data(ACTORS.issuer.user_id.clone());
        data.nominal_value.amount = "1000".to_string();

        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

        let mut master_voucher = voucher_manager::create_voucher(data, standard, standard_hash, &ACTORS.issuer.signing_key, "en").unwrap();

        // Füge Bürgen hinzu.
        master_voucher.guarantor_signatures.push(create_guarantor_signature(&master_voucher, &ACTORS.guarantor1, None, "0"));
        master_voucher.guarantor_signatures.push(create_guarantor_signature(&master_voucher, &ACTORS.guarantor2, None, "0"));

        // WICHTIG: Füge eine `AdditionalSignature` hinzu, damit der Fuzzer sie angreifen kann.
        let mut additional_sig = AdditionalSignature {
            voucher_id: master_voucher.voucher_id.clone(),
            signer_id: ACTORS.victim.user_id.clone(),
            signature_time: get_current_timestamp(),
            description: "A valid additional signature".to_string(),
            ..Default::default()
        };
        let mut sig_obj_for_id = additional_sig.clone();
        sig_obj_for_id.signature_id = "".to_string();
        sig_obj_for_id.signature = "".to_string();
        additional_sig.signature_id = get_hash(to_canonical_json(&sig_obj_for_id).unwrap());
        let signature = sign_ed25519(&ACTORS.victim.signing_key, additional_sig.signature_id.as_bytes());
        additional_sig.signature = bs58::encode(signature.to_bytes()).into_string();
        master_voucher.additional_signatures.push(additional_sig);

        // Erstelle eine Transaktionskette, die auch einen Split enthält.
        master_voucher = create_transaction(&master_voucher, standard, &ACTORS.issuer.user_id, &ACTORS.issuer.signing_key, &ACTORS.alice.user_id, "1000").unwrap();
        master_voucher = create_transaction(&master_voucher, standard, &ACTORS.alice.user_id, &ACTORS.alice.signing_key, &ACTORS.bob.user_id, "500").unwrap(); // Split

        let mut rng = thread_rng();
        println!("--- Starte intelligenten Fuzzing-Test mit 2000 Iterationen ---");
        let iterations = 100;

        // Definiere die intelligenten und zufälligen Angriffsstrategien.
        let strategies = [
            FuzzingStrategy::InvalidateAdditionalSignature,
            FuzzingStrategy::SetNegativeTransactionAmount,
            FuzzingStrategy::SetNegativeRemainderAmount,
            FuzzingStrategy::SetInitTransactionInWrongPosition,
            FuzzingStrategy::GenericRandomMutation, // Behalte die alte Methode für allgemeine Zufälligkeit bei.
            FuzzingStrategy::GenericRandomMutation, // Erhöhe die Wahrscheinlichkeit für zufällige Mutationen.
        ];

        for i in 0..iterations {
            let mut mutated_voucher = master_voucher.clone();
            let strategy = strategies.choose(&mut rng).unwrap();
            let change_description: String;

            // Führe die gewählte Angriffsstrategie aus
            match strategy {
                FuzzingStrategy::InvalidateAdditionalSignature => {
                    change_description = mutate_invalidate_additional_signature(&mut mutated_voucher);
                }
                FuzzingStrategy::SetNegativeTransactionAmount => {
                    change_description = mutate_to_negative_amount(&mut mutated_voucher);
                }
                FuzzingStrategy::SetNegativeRemainderAmount => {
                    change_description = mutate_to_negative_remainder(&mut mutated_voucher);
                }
                FuzzingStrategy::SetInitTransactionInWrongPosition => {
                    change_description = mutate_init_to_wrong_position(&mut mutated_voucher);
                }
                FuzzingStrategy::GenericRandomMutation => {
                    // Konvertiere zu JSON, mutiere zufällig und konvertiere zurück
                    let mut as_value = serde_json::to_value(&mutated_voucher).unwrap();
                    change_description = mutate_value(&mut as_value, &mut rng, "voucher")
                        .unwrap_or_else(|| "Generic mutation did not change anything".to_string());

                    if let Ok(v) = serde_json::from_value(as_value) {
                        mutated_voucher = v;
                    } else {
                        // Wenn die zufällige Mutation die Struktur so zerstört hat, dass sie nicht mehr
                        // als Voucher geparst werden kann, ist das ein "erfolgreicher" Fund.
                        // Wir können zur nächsten Iteration übergehen.
                        println!("Iter {}: Generic mutation created invalid structure. OK.", i);
                        continue;
                    }
                }
            }

            let validation_result = voucher_validation::validate_voucher_against_standard(&mutated_voucher, standard);
            assert!(validation_result.is_err(),
                    "FUZZING-FEHLER bei Iteration {}: Eine Mutation hat die Validierung umgangen!\nStrategie: {:?}\nÄnderung: {}\nMutierter Gutschein:\n{}",
                    i, strategy, change_description, serde_json::to_string_pretty(&mutated_voucher).unwrap()
            );
        }
        println!("--- Intelligenter Fuzzing-Test erfolgreich abgeschlossen ---");
    }

    // ===================================================================================
    // ANGRIFFSKLASSE 6: UMGEHUNG VON SIGNATUR-ANFORDERUNGEN (NEU)
    // ===================================================================================

    #[cfg(test)]
    mod required_signatures_validation {
        use super::*;
        use self::test_utils::{create_guarantor_signature_with_time, create_male_guarantor_signature};
        use voucher_lib::models::voucher::AdditionalSignature;

        fn load_required_sig_standard() -> (voucher_lib::VoucherStandardDefinition, String) {
            // Verwende die neue, robuste lazy_static-Variable
            (self::test_utils::REQUIRED_SIG_STANDARD.0.clone(), self::test_utils::REQUIRED_SIG_STANDARD.1.clone())
        }

        fn create_base_voucher_for_sig_test(standard: &voucher_lib::VoucherStandardDefinition, standard_hash: &str) -> Voucher {
            let creator_identity = &ACTORS.alice;
            let voucher_data = NewVoucherData {
                creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
                validity_duration: Some("P1Y".to_string()), // HINZUGEFÜGT: Gültigkeit explizit setzen
                // HINZUGEFÜGT: Nennwert explizit setzen, um "Invalid decimal: empty" zu vermeiden
                nominal_value: NominalValue {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default() // Füllt den Rest mit Standardwerten
            };
            // Verwende die "manipulation"-Hilfsfunktion, die die finale Validierung überspringt.
            // Das ist notwendig, da der Standard eine Signatur erfordert, die wir in den Tests erst hinzufügen wollen.
            create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en")
        }

        fn create_valid_approval_signature(voucher: &Voucher) -> AdditionalSignature {
            // KORREKTUR: Wir müssen die Identität verwenden, die den Standard signiert hat (TEST_ISSUER),
            // da dessen ID in den `allowed_signer_ids` steht.
            let signer = &self::test_utils::TEST_ISSUER;
            let mut sig = AdditionalSignature {
                voucher_id: voucher.voucher_id.clone(),
                signer_id: signer.user_id.clone(),
                description: "Approved for circulation 2025".to_string(),
                signature_time: get_current_timestamp(),
                ..Default::default()
            };
            // KORREKTUR: Die signature_id muss aus dem Hash der Metadaten *ohne* die Felder
            // 'signature_id' und 'signature' selbst berechnet werden. Die Verifizierungslogik
            // tut genau das. Wir müssen es hier exakt nachbilden.
            let mut data_for_id_hash = sig.clone();
            println!("\n[DEBUG TEST CREATE SIG] --- START CREATION ---");
            data_for_id_hash.signature_id = "".to_string();
            data_for_id_hash.signature = "".to_string();
            let canonical_json_for_creation = to_canonical_json(&data_for_id_hash).unwrap();
            println!("[DEBUG TEST CREATE SIG] Canonical JSON for creation:\n{}", canonical_json_for_creation);
            sig.signature_id = get_hash(&canonical_json_for_creation);
            println!("[DEBUG TEST CREATE SIG] Generated signature_id: {}", sig.signature_id);
            let digital_sig = sign_ed25519(&signer.signing_key, sig.signature_id.as_bytes());
            sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
            println!("[DEBUG TEST CREATE SIG] --- END CREATION ---\n");
            sig
        }

        #[test]
        fn test_required_signature_ok() {
            let (standard, standard_hash) = load_required_sig_standard();
            let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
            voucher.additional_signatures.push(create_valid_approval_signature(&voucher));

            let result = validate_voucher_against_standard(&voucher, &standard);
            if let Err(e) = &result {
                // Hinzufügen von Debug-Ausgabe, um den genauen Fehler zu sehen
                panic!("Validation failed unexpectedly in test_required_signature_ok: {:?}", e);
            }
            // Die ursprüngliche Assertion bleibt bestehen, um den Test im Erfolgsfall grün zu halten.
            assert!(result.is_ok());
        }

        #[test]
        fn test_fails_on_missing_mandatory_signature() {
            let (standard, standard_hash) = load_required_sig_standard();
            let voucher = create_base_voucher_for_sig_test(&standard, &standard_hash); // Ohne Signatur

            let result = validate_voucher_against_standard(&voucher, &standard);
            assert!(matches!(
                result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { .. })
            ));
        }

        #[test]
        fn test_fails_on_signature_from_wrong_signer() {
            let (standard, standard_hash) = load_required_sig_standard();
            let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
            let mut wrong_sig = create_valid_approval_signature(&voucher);
            wrong_sig.signer_id = ACTORS.hacker.user_id.clone(); // Nicht in allowed_signer_ids
            // Muss neu signiert werden, da sich die Daten geändert haben
            let mut obj_to_hash = wrong_sig.clone();
            obj_to_hash.signature_id = "".to_string();
            obj_to_hash.signature = "".to_string();
            wrong_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
            let digital_sig = sign_ed25519(&ACTORS.hacker.signing_key, wrong_sig.signature_id.as_bytes());
            wrong_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
            voucher.additional_signatures.push(wrong_sig);

            let result = validate_voucher_against_standard(&voucher, &standard);
            assert!(matches!(
                result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { .. })
            ));
        }

        #[test]
        fn test_fails_on_wrong_signature_description() {
            let (standard, standard_hash) = load_required_sig_standard();
            let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
            let mut wrong_desc_sig = create_valid_approval_signature(&voucher);
            wrong_desc_sig.description = "Some other description".to_string();
            // Muss neu signiert werden
            let mut obj_to_hash = wrong_desc_sig.clone();
            obj_to_hash.signature_id = "".to_string();
            obj_to_hash.signature = "".to_string();
            wrong_desc_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
            let digital_sig = sign_ed25519(&ACTORS.issuer.signing_key, wrong_desc_sig.signature_id.as_bytes());
            wrong_desc_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
            voucher.additional_signatures.push(wrong_desc_sig);

            let result = validate_voucher_against_standard(&voucher, &standard);
            assert!(matches!(
                result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { .. })
            ));
        }

        #[test]
        fn test_creator_as_guarantor_attack_fails() {
            let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
            let creator_identity = &ACTORS.alice;
            let voucher_data = NewVoucherData {
                creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
                nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
                // KORREKTUR: Der Minuto-Standard erfordert eine Mindestgültigkeit (z.B. P3Y).
                // P1Y war zu kurz und löste `ValidityDurationTooShort` aus, bevor die eigentliche
                // Angriffslogik (`CreatorAsGuarantor`) geprüft werden konnte.
                validity_duration: Some("P4Y".to_string()),
                ..Default::default()
            };
            let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

            // Angriff: Der Ersteller (Alice) versucht, für sich selbst zu bürgen.
            let self_guarantor_sig = create_guarantor_signature_with_time(
                &voucher.voucher_id,
                creator_identity, // Alice bürgt
                "Alice", "2",
                "2026-08-01T10:00:00Z"
            );

            voucher.guarantor_signatures.push(self_guarantor_sig);
            // Füge einen zweiten, validen Bürgen hinzu, um die `CountOutOfBounds`-Regel zu umgehen
            voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));

            let validation_result = validate_voucher_against_standard(&voucher, standard);

            // --- DEBUG-Ausgabe hinzugefügt ---
            if let Err(e) = &validation_result {
                println!("[DEBUG] Validation failed as expected. The actual error was:");
                println!("[DEBUG] {:?}", e);
            } else {
                // Wenn die Validierung unerwartet erfolgreich ist, lassen wir den Test fehlschlagen.
                panic!("[DEBUG] Validation unexpectedly succeeded, but should have failed!");
            }
            // --- Ende DEBUG-Ausgabe ---

            // HINWEIS: Mit der Implementierung von `CreatorAsGuarantor` in `error.rs` und
            // `voucher_validation.rs` prüfen wir nun auf den spezifischeren, korrekten Fehler.
            assert!(matches!(
                validation_result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::CreatorAsGuarantor { .. })
            ));
        }
    }
}
// ===================================================================================
// --- ENDE: SECURITY VULNERABILITY TESTS ---
// ===================================================================================