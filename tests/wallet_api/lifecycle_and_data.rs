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
    use voucher_lib::test_utils::{generate_signed_standard_toml, ACTORS};
    use tempfile::tempdir;

    const PASSWORD: &str = "correct-password-123";
    const WRONG_PASSWORD: &str = "wrong-password-!@#";

    // --- Teil 1: Absicherung des Gelben Bereichs (data_encryption.rs) ---

    /// **Test 1: test_data_encryption_workflow()**
    ///
    /// Überprüft den kompletten "Happy Path" des generischen Datenspeichers.
    #[test]
    fn test_data_encryption_workflow() {
        // 1. Profil erstellen und entsperren
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Data User", PASSWORD);

        // 2. Daten speichern
        let data_name = "user_settings";
        let original_data = b"some secret application data".to_vec();
        service
            .save_encrypted_data(data_name, &original_data, PASSWORD)
            .expect("Saving data should succeed");

        // 3. Daten laden
        let loaded_data = service
            .load_encrypted_data(data_name, PASSWORD)
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

        // 3. Versuche zu speichern und zu laden
        let save_result = service.save_encrypted_data("any_data", &[1, 2, 3], PASSWORD);
        let load_result = service.load_encrypted_data("any_data", PASSWORD);

        // 4. Assert: Beide Aufrufe müssen fehlschlagen
        assert!(save_result.is_err());
        assert!(save_result
            .unwrap_err()
            .contains("Wallet is locked"));

        assert!(load_result.is_err());
        assert!(load_result
            .unwrap_err()
            .contains("Cannot load data while wallet is locked"));
    }

    /// **Test 3: test_data_encryption_fails_with_wrong_password()**
    ///
    /// Verifiziert die Passwort-Prüfung für den Datenspeicher.
    #[test]
    fn test_data_encryption_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        // 1. Profil erstellen und Daten mit korrektem Passwort speichern
        let (mut service, _) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Wrong Pass User", PASSWORD);

        let data_name = "user_settings";
        let original_data = b"some config".to_vec();
        service
            .save_encrypted_data(data_name, &original_data, PASSWORD)
            .expect("Saving data with correct password should work");

        // 2. Assert: Versuch, mit falschem Passwort zu laden, schlägt fehl
        let load_err = service
            .load_encrypted_data(data_name, WRONG_PASSWORD)
            .unwrap_err();
        assert!(load_err.contains("uthentication failed"));

        // 3. Assert: Versuch, mit falschem Passwort zu schreiben, schlägt fehl
        let save_err = service
            .save_encrypted_data("other_data", &[0], WRONG_PASSWORD)
            .unwrap_err();
        assert!(save_err.contains("uthentication failed"));
    }

    // --- Teil 2: Absicherung des Roten Bereichs (lifecycle.rs) ---

    /// **Test 4: test_create_profile_fails_with_invalid_mnemonic()**
    ///
    /// Stellt sicher, dass die Eingabevalidierung bei der Profilerstellung greift.
    #[test]
    fn test_create_profile_fails_with_invalid_mnemonic() {
        let dir = tempdir().unwrap();
        let mut service = AppService::new(dir.path()).unwrap();

        // 1. Ungültige Mnemonic vorbereiten
        let invalid_mnemonic = "this is not a valid bip39 phrase";

        // 2. Profilerstellung versuchen
        let result = service.create_profile("Invalid Mnemonic Profile", invalid_mnemonic, None, Some("test"), PASSWORD);

        // 3. Assert: Funktion muss einen Fehler zurückgeben
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Failed to create new wallet"));

        // 4. Assert: Der Service muss im `Locked`-Zustand bleiben.
        // Indirekte Prüfung: Ein Aufruf, der einen entsperrten Zustand erfordert, muss fehlschlagen.
        assert!(service.get_user_id().is_err());
    }

    /// **Test 5: test_login_fails_with_wrong_password()**
    ///
    /// Testet den häufigsten Fehlerfall beim Login.
    #[test]
    fn test_login_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        // 1. Profil erstellen und wieder sperren
        let (mut service, profile_info) = test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Login Test", PASSWORD);
        service.logout();

        // 2. Login mit falschem Passwort versuchen
        let result = service.login(&profile_info.folder_name, WRONG_PASSWORD, false);

        // 3. Assert: Login muss fehlschlagen
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Login failed (check password)"));

        // 4. Assert: Der Service muss im `Locked`-Zustand bleiben.
        assert!(service.get_user_id().is_err(), "Should not be able to get user ID while locked.");
    }

    /// **Test 6: test_recovery_preserves_wallet_data()**
    ///
    /// Stellt sicher, dass die Passwort-Wiederherstellung bestehende Wallet-Inhalte erhält.
    #[test]
    fn test_recovery_preserves_wallet_data() {
        let dir = tempdir().unwrap();
        let test_user = &ACTORS.test_user;
        // 1. Profil erstellen
        let (mut service, profile_info) = test_utils::setup_service_with_profile(dir.path(), test_user, "Recovery Test", PASSWORD);

        // 2. Einen Test-Gutschein erstellen und dem Wallet hinzufügen
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
            // KORREKTUR: Fehlende Gültigkeitsdauer für die Gutschein-Erstellung hinzufügen.
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };

        // KORREKTUR: Einen korrekt signierten Standard verwenden, anstatt des rohen TOML-Strings.
        let signed_standard = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
        let created_voucher = service
            .create_new_voucher(&signed_standard, "de", voucher_data, PASSWORD)
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
        // Wir verwenden get_voucher_details, um das volle Voucher-Objekt zu prüfen.
        let details_after = service.get_voucher_details(&local_id).unwrap();
        assert_eq!(details_after.local_instance_id, local_id);
        assert_eq!(details_after.voucher.voucher_id, created_voucher.voucher_id);
    }
}