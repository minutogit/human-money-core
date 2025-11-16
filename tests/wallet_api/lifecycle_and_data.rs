//! # tests/wallet_api/lifecycle_and_data.rs
//!
//! Enthält Robustheitstests für die kritischen `AppService`-Funktionen
//! in den Bereichen Lebenszyklus (Erstellung, Login, Wiederherstellung) und
//! generische Datenverschlüsselung.

#[cfg(test)]
mod tests {

    use voucher_lib::services::voucher_manager::{NewVoucherData};
    use voucher_lib::app_service::AppService;
    use voucher_lib::test_utils;
    use voucher_lib::app_service::ProfileInfo;
    use voucher_lib::test_utils::{generate_signed_standard_toml, ACTORS};
    use tempfile::tempdir;
    // HINZUGEFÜGT: Imports für den neuen Testplan
    use std::collections::HashMap;
    use voucher_lib::wallet::MultiTransferRequest;

    const PASSWORD: &str = "correct-password-123";
    const WRONG_PASSWORD: &str = "wrong-password-!@#";

    // --- Interne Test-Hilfsfunktionen ---

    /// Erstellt eine Dummy-Transferanfrage für Tests.
    /// Benötigt einen Service, der bereits einen Gutschein hat.
    fn create_dummy_transfer_request(service: &mut AppService) -> MultiTransferRequest {
        let summary = service.get_voucher_summaries(None, None).unwrap().pop().expect("Service has no vouchers to transfer");
        MultiTransferRequest {
            recipient_id: "did:key:z6MkhXrm1Rvwj3veuaDtiN2o22uVQdWKkXEkK84vEgJtB7Ti".to_string(),
            sources: vec![
                voucher_lib::wallet::SourceTransfer {
                    local_instance_id: summary.local_instance_id,
                    amount_to_send: "1.0".to_string(),
                }
            ],
            notes: None,
            sender_profile_name: None,
        }
    }

    /// Hilfsfunktion, die einen Service erstellt UND einen Gutschein darin anlegt.
    /// Notwendig für alle Tests, die `create_transfer_bundle` aufrufen wollen.
    /// Gibt auch das TempDir zurück, um sicherzustellen, dass es während des Tests existiert.
    fn setup_service_with_voucher(password: &str) -> (AppService, ProfileInfo, String, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Voucher User", password);


        let voucher_data = NewVoucherData {
            creator_profile: voucher_lib::models::profile::PublicProfile {
                id: Some(service.get_user_id().unwrap()),
                ..Default::default()
            },
            nominal_value: voucher_lib::models::voucher::ValueDefinition {
                amount: "100.0000".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");

        // HINWEIS: Dieser Aufruf MUSS Some(password) (Modus A) verwenden, da setup_service_with_profile
        // (und der darin enthaltene Anker-Fix) KEINE Modus B-Session startet.
        let _voucher = service.create_new_voucher(&signed_standard, "de", voucher_data, Some(password))
            .expect("Voucher creation in setup_service_with_voucher failed");
        let local_id = service.get_voucher_summaries(None, None).unwrap().pop().unwrap().local_instance_id;

        (service, profile, local_id, dir)
    }


    // --- Teil 1: Absicherung des Gelben Bereichs (data_encryption.rs) ---

    /// **Test 1: test_data_encryption_workflow()** (Angepasst für Modus B)
    ///
    /// Überprüft den kompletten "Happy Path" des generischen Datenspeichers
    /// im "Passwort merken"-Modus (Modus B).
    #[test]
    fn test_data_encryption_workflow() {
        // 1. Profil erstellen und entsperren
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Data User", PASSWORD);

        // 2. Daten speichern (mit Modus B)
        let data_name = "user_settings";
        let original_data = b"some secret application data".to_vec();
        service
            .save_encrypted_data(data_name, &original_data, Some(PASSWORD))
            .expect("Saving data should succeed");

        // 3. Daten laden (mit Modus B)
        let loaded_data = service
            .load_encrypted_data(data_name, Some(PASSWORD))
            .expect("Loading data should succeed");

        // 4. Assert: Geladene Daten müssen den Originaldaten entsprechen
        assert_eq!(original_data, loaded_data);
    }

    /// **Test 2: test_data_encryption_fails_when_locked()**
    ///
    /// Stellt sicher, dass im `Locked`-Zustand kein Zugriff auf sensible Daten möglich ist.
    #[test]
    fn test_data_encryption_fails_when_locked() {
        let dir = tempdir().unwrap();
        // 1. Profil erstellen (Service ist danach entsperrt)
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Lock User", PASSWORD);
        // 2. Service sperren
        service.logout();

        // 3. Versuche zu speichern und zu laden (mit Modus A oder B - beides muss fehlschlagen)
        let save_result = service.save_encrypted_data("any_data", &[1, 2, 3], None);
        let load_result = service.load_encrypted_data("any_data", None);
        let save_result_pw = service.save_encrypted_data("any_data", &[1, 2, 3], Some(PASSWORD));
        let load_result_pw = service.load_encrypted_data("any_data", Some(PASSWORD));

        // 4. Assert: Alle Aufrufe müssen fehlschlagen
        assert!(save_result.is_err());
        assert!(save_result.unwrap_err().contains("Wallet is locked"));
        assert!(load_result.is_err());
        assert!(load_result.unwrap_err().contains("Wallet is locked"));
        assert!(save_result_pw.is_err());
        assert!(save_result_pw.unwrap_err().contains("Wallet is locked"));
        assert!(load_result_pw.is_err());
        assert!(load_result_pw.unwrap_err().contains("Wallet is locked"));
    }

    /// **Test 3: test_data_encryption_fails_with_wrong_password()** (Angepasst für Modus A)
    ///
    /// Verifiziert die Passwort-Prüfung für den Datenspeicher im "Immer fragen"-Modus (Modus A).
    #[test]
    fn test_data_encryption_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        // 1. Profil erstellen
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Wrong Pass User", PASSWORD);

        let data_name = "user_settings";
        let original_data = b"some config".to_vec();
        // Speichere mit Modus A (Some(PASSWORD))
        service
            .save_encrypted_data(data_name, &original_data, Some(PASSWORD))
            .expect("Saving data with correct password should work");

        // 2. Assert: Versuch, mit falschem Passwort zu laden (Modus A), schlägt fehl
        let load_err = service
            .load_encrypted_data(data_name, Some(WRONG_PASSWORD))
            .unwrap_err();
        assert!(load_err.contains("Authentication failed")); // Oder "Password verification failed"

        // 3. Assert: Versuch, mit falschem Passwort zu schreiben (Modus A), schlägt fehl
        let save_err = service
            .save_encrypted_data("other_data", &[0], Some(WRONG_PASSWORD))
            .unwrap_err();
        assert!(save_err.contains("Authentication failed")); // Oder "Password verification failed"
    }

    // --- Teil 2: Absicherung des Roten Bereichs (lifecycle.rs) ---

    /// **Test 4: test_create_profile_fails_with_invalid_mnemonic()**
    /// (Unverändert, da `create_profile` keine Session-Logik verwendet)
    #[test]
    fn test_create_profile_fails_with_invalid_mnemonic() {
        let dir = tempdir().unwrap();
        let mut service = AppService::new(dir.path()).unwrap();
        let invalid_mnemonic = "this is not a valid bip39 phrase";
        let result = service.create_profile("Invalid Mnemonic Profile", invalid_mnemonic, None, Some("test"), PASSWORD);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to create new wallet"));
        assert!(service.get_user_id().is_err());
    }

    /// **Test 5: test_login_fails_with_wrong_password()**
    /// (Unverändert, da `login` keine Session-Logik verwendet)
    #[test]
    fn test_login_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        let (mut service, profile_info) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Login Test", PASSWORD);
        service.logout();
        let result = service.login(&profile_info.folder_name, WRONG_PASSWORD, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Login failed (check password)"));
        assert!(service.get_user_id().is_err(), "Should not be able to get user ID while locked.");
    }

    /// **Test 6: test_recovery_preserves_wallet_data()** (Angepasst für Modus B)
    ///
    /// Stellt sicher, dass die Passwort-Wiederherstellung bestehende Wallet-Inhalte erhält.
    #[test]
    fn test_recovery_preserves_wallet_data() {
        let dir = tempdir().unwrap();
        let test_user = &ACTORS.test_user;
        // 1. Profil erstellen
        let (mut service, profile_info) = test_utils::setup_service_with_profile(dir.path(), test_user, "Recovery Test", PASSWORD);

        // 2. Einen Test-Gutschein erstellen (benötigt Modus B)
        let user_id = service.get_user_id().unwrap();

        let voucher_data = NewVoucherData {
            creator_profile: voucher_lib::models::profile::PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: voucher_lib::models::voucher::ValueDefinition {
                amount: "100.0000".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };

        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let created_voucher = service
            // KORREKTUR: Der Login (via setup_service_with_profile) startet keine Session.
            // Wir MÜSSEN Modus A (Some(PASSWORD)) verwenden.
            .create_new_voucher(&signed_standard, "de", voucher_data, Some(PASSWORD))
            .expect("Voucher creation should succeed");

        // 3. Prüfen, ob der Gutschein vorhanden ist
        let summaries_before = service.get_voucher_summaries(None, None).unwrap();
        assert_eq!(summaries_before.len(), 1);
        let local_id = summaries_before[0].local_instance_id.clone();

        // 4. Service sperren
        service.logout();

        // 5. Wallet wiederherstellen und neues Passwort setzen
        service
            .recover_wallet_and_set_new_password(&profile_info.folder_name, &test_user.mnemonic, test_user.passphrase, "new_password")
            .expect("Recovery should succeed");

        // 6. Assert: Der Gutschein muss nach der Wiederherstellung noch vorhanden sein
        let details_after = service.get_voucher_details(&local_id).unwrap();
        assert_eq!(details_after.local_instance_id, local_id);
        assert_eq!(details_after.voucher.voucher_id, created_voucher.voucher_id);
    }

    /* * ANFANG: Neuer Testabschnitt (aus Testplan 5)
     * HINWEIS: Die Tests 1-3 sind bereits oben abgedeckt (test_data_encryption_...).
     * Wir fügen hier die neuen Tests für Session-Management hinzu.
     */

    /// # 5. Tests für Session-Management und Flexible Authentifizierung
    ///
    /// Diese Tests verifizieren die "Sicheres Passwort merken"-Funktion (Plan B),
    /// die beide Modi abdeckt: "Immer fragen" (Modus A) und "Passwort merken" (Modus B).

    /// --- 5.1 Grundlegende Session-Verwaltung ---

    #[test]
    fn test_session_unlock_session_success() {
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        // HINWEIS: setup_service_with_profile verlässt den Service im Unlocked-Zustand.
        // Dieser Test prüft, ob unlock_session mit dem korrekten PW im Unlocked-Zustand funktioniert.
        let result = service.unlock_session(PASSWORD, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_unlock_session_fail() {
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        let result = service.unlock_session(WRONG_PASSWORD, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Password verification failed"));
    }

    /// --- 5.2 Modus A: "Immer fragen" (Argument `Some(password)`) ---

    #[test]
    fn test_session_mode_a_action_succeeds_with_password_only() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // setup_service_with_voucher hinterlässt den Service im Unlocked-Zustand,
        // aber OHNE aktive Session (da lock_session() entfernt wurde).
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, Some(PASSWORD));
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_mode_a_action_fails_with_wrong_password() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, Some(WRONG_PASSWORD));
        assert!(result.is_err());
        // Der Fehler kommt von derive_key_for_session -> get_file_key -> AuthenticationFailed
        assert!(result.unwrap_err().contains("Authentication failed"));
    }

    /// --- 5.3 Modus B: "Passwort merken" (Argument `None` + Aktive Session) ---

    #[test]
    fn test_session_mode_b_action_fails_without_session() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Service ist Unlocked, aber Session ist Locked (da setup_service_with_voucher lock_session() entfernt hat)
        // Der Aufruf mit `None` muss fehlschlagen.
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Password required.")); // KORREKTUR: Die Fehlermeldung ist kürzer.
    }

    #[test]
    fn test_session_mode_b_action_succeeds_with_session() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 60).unwrap();
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_mode_b_timeout() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 1).unwrap(); // 1 Sekunde Timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Session timed out."));
    }

    #[test]
    fn test_session_mode_b_refresh_activity_sliding_window() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 3).unwrap(); // 3 Sekunden Timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        service.refresh_session_activity(); // Timer zurücksetzen
        std::thread::sleep(std::time::Duration::from_secs(2)); // Gesamt 4s vergangen
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_ok(), "Session should have been refreshed by refresh_session_activity");
    }

    #[test]
    fn test_session_mode_b_action_refreshes_session() {
        let dir = tempdir().unwrap();
        let (mut service, _profile) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 3).unwrap(); // 3 Sekunden Timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        service.save_encrypted_data("test1", b"data", None).unwrap(); // Aktion setzt Timer zurück
        std::thread::sleep(std::time::Duration::from_secs(2)); // Gesamt 4s vergangen
        let result = service.load_encrypted_data("test1", None);
        assert!(result.is_ok(), "Session should have been refreshed by save_encrypted_data");
    }

    #[test]
    fn test_session_mode_b_lock_session_works() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 60).unwrap();
        service.lock_session(); // Session manuell sperren
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Password required."));
    }

    /// --- 5.4 Edge Cases: Überschreiben der Session ---

    #[test]
    fn test_session_mode_a_overrides_mode_b_succeeds() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 60).unwrap(); // Modus B ist aktiv
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, Some(PASSWORD));
        assert!(result.is_ok(), "Modus A (Some(pass)) sollte Vorrang vor Modus B (Session) haben.");
    }

    #[test]
    fn test_session_mode_a_wrong_password_fails_even_if_mode_b_is_active() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Session explizit für diesen Test entsperren
        service.unlock_session(PASSWORD, 60).unwrap(); // Modus B ist aktiv
        let request = create_dummy_transfer_request(&mut service);
        
        // Load the standard definition for SILVER-PAYMENT-V1-2025-09
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("SILVER-PAYMENT-V1-2025-09".to_string(), signed_standard);
        
        let result = service.create_transfer_bundle(request, &standard_definitions, None, Some(WRONG_PASSWORD));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Authentication failed"));
    }

    /* ENDE: Neuer Testabschnitt */
}