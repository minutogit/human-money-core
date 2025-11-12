//! # tests/wallet_api/general_workflows.rs
//!
//! Enthält Integrationstests für die primären, nicht-signaturbezogenen
//! End-to-End-Workflows, die über die `AppService`- und `Wallet`-Fassaden
//! abgewickelt werden.

// Binde das `test_utils` Modul explizit über seinen Dateipfad ein.


use voucher_lib::test_utils::{
    add_voucher_to_wallet, create_voucher_for_manipulation, generate_signed_standard_toml,
    generate_valid_mnemonic, setup_in_memory_wallet, setup_service_with_profile, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
};
use rust_decimal::Decimal;
use std::str::FromStr;
use tempfile::tempdir;
use voucher_lib::{
    app_service::AppService,
    models::{
        voucher::{ValueDefinition},
        voucher_standard_definition::VoucherStandardDefinition, profile::PublicProfile,
    },
    services::voucher_manager::NewVoucherData,
    storage::{AuthMethod},
    wallet::Wallet,
    VoucherCoreError, VoucherStatus,
};

// --- 1. AppService Workflows ---

/// Simuliert den gesamten Lebenszyklus eines Benutzers über den `AppService`.
///
/// ### Szenario:
/// 1.  Zwei temporäre Verzeichnisse für Alice und Bob werden erstellt.
/// 2.  Zwei `AppService`-Instanzen werden initialisiert.
/// 3.  Alice und Bob erstellen ihre Profile mit Mnemonic und Passwort.
/// 4.  Alice loggt sich aus und wieder ein, um die Authentifizierung zu testen.
/// 5.  Alice erstellt einen neuen Gutschein in ihrem Wallet.
/// 6.  Alice transferiert den gesamten Gutschein an Bob.
/// 7.  Der alte Gutschein-Zustand bei Alice wird als archiviert verifiziert.
/// 8.  Bob empfängt das Bundle und verifiziert seinen neuen Kontostand.
#[test]
fn api_app_service_full_lifecycle() {
    // --- 1. Setup ---
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let dir_bob = tempdir().expect("Failed to create temp dir for Bob");
    let actor_alice = &ACTORS.alice;
    let actor_bob = &ACTORS.bob;
    let password = "password123";

    // --- 2. Profile erstellen ---
    let (mut service_alice, profile_info_alice) =
        setup_service_with_profile(dir_alice.path(), actor_alice, "Alice", password);
    let (mut service_bob, _) =
        setup_service_with_profile(dir_bob.path(), actor_bob, "Bob", password);

    let id_alice = service_alice.get_user_id().unwrap();
    let id_bob = service_bob.get_user_id().unwrap();

    // --- 3. Logout und Login für Alice ---
    service_alice.logout();
    assert!(service_alice.get_user_id().is_err(), "Service should be locked after logout");
    service_alice
        .login(&profile_info_alice.folder_name, password, false)
        .expect("Login with correct password should succeed");
    assert_eq!(service_alice.get_user_id().unwrap(), id_alice);

    // --- 4. Alice erstellt einen Gutschein ---
    service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            password,
        )
        .expect("Voucher creation failed");
    let summaries_alice = service_alice.get_voucher_summaries(None, None).unwrap();
    let local_id_alice = summaries_alice[0].local_instance_id.clone();

    // --- 5. Alice sendet den Gutschein an Bob ---
    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: id_bob.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: local_id_alice.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(standard.metadata.uuid.clone(), silver_standard_toml.clone());
    let voucher_lib::wallet::CreateBundleResult { bundle_bytes: transfer_bundle, .. } = service_alice
        .create_transfer_bundle(
            request,
            &standards_toml,
            None,
            password,
        )
        .expect("Transfer failed");
    let summary = service_alice
        .get_voucher_details(&local_id_alice)
        .expect_err("Old voucher ID should not resolve to an active voucher anymore");
    assert!(summary.to_lowercase().contains("not found"));

    // --- 6. Bob empfängt den Gutschein ---
    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), silver_standard_toml);
    service_bob
        .receive_bundle(&transfer_bundle, &standards, None, password)
        .expect("Receive failed");
    let balance_bob = service_bob.get_total_balance_by_currency().unwrap();
    // KORREKTUR: Die Bilanz wird jetzt nach der Abkürzung der Währung gruppiert, nicht nach der Einheit.
    let silver_abbreviation = "Oz"; // Korrigierte, statische Abkürzung für den Silber-Standard.
    let bob_silver_balance = balance_bob
        .iter()
        .find(|b| &b.unit == silver_abbreviation)
        .map(|b| b.total_amount.as_str())
        .expect("Bob should have a silver balance");
    assert_eq!(bob_silver_balance, "100.0000");
}

/// Testet den `AppService` Lebenszyklus, wenn eine BIP39-Passphrase verwendet wird.
///
/// ### Szenario:
/// 1.  Ein Profil wird mit Mnemonic UND Passphrase erstellt.
/// 2.  Die resultierende User-ID wird gespeichert.
/// 3.  Ein Wiederherstellungsversuch NUR mit der Mnemonic (ohne Passphrase) schlägt fehl,
///     da die abgeleiteten Schlüssel nicht übereinstimmen.
#[test]
fn api_app_service_lifecycle_with_passphrase() {
    // --- 1. Setup ---
    let actor_with_passphrase = &ACTORS.test_user; // Dieser Aktor ist mit einer Passphrase konfiguriert.
    let dir = tempdir().expect("Failed to create temp dir");
    let password = "password123";

    // --- 2. Profil mit Passphrase erstellen und Service entsperren ---
    let (mut service, profile_info) = setup_service_with_profile(dir.path(), actor_with_passphrase, "Test User", password);
    let original_user_id = service.get_user_id().unwrap();
    assert!(original_user_id.starts_with(actor_with_passphrase.prefix.unwrap()));
    service.logout();

    // --- 3. Wiederherstellung ohne Passphrase (muss fehlschlagen) ---
    let recovery_result = service.recover_wallet_and_set_new_password(
        &profile_info.folder_name,
        &actor_with_passphrase.mnemonic,
        None, // <- Fehlende Passphrase
        "any-new-password",
    );

    assert!(
        recovery_result.is_err(),
        "Recovery with mnemonic only (when passphrase was used for creation) should fail."
    );
    assert!(recovery_result
        .unwrap_err()
        .to_lowercase()
        .contains("recovery failed"));

    assert!(
        service.get_user_id().is_err(),
        "Service should remain locked after failed recovery"
    );
}

/// Testet die statischen Mnemonic-Hilfsfunktionen des `AppService`.
///
/// ### Szenario:
/// 1.  Generiert eine gültige 12-Wort-Phrase und prüft deren Korrektheit.
/// 2.  Versucht, eine Phrase mit ungültiger Wortanzahl zu generieren (soll fehlschlagen).
/// 3.  Validiert eine frisch generierte Phrase (soll erfolgreich sein).
/// 4.  Validiert Phrasen mit ungültigen Wörtern oder schlechter Prüfsumme (sollen fehlschlagen).
#[test]
fn api_app_service_mnemonic_helpers() {
    let mnemonic = AppService::generate_mnemonic(12).unwrap();
    assert_eq!(
        mnemonic.split_whitespace().count(),
        12,
        "Mnemonic should have 12 words"
    );
    assert!(
        AppService::generate_mnemonic(11).is_err(),
        "Should fail with invalid word count"
    );
    assert!(
        AppService::validate_mnemonic(&mnemonic).is_ok(),
        "A freshly generated mnemonic should be valid"
    );
    let invalid_word_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    assert!(
        AppService::validate_mnemonic(invalid_word_mnemonic).is_err(),
        "Should fail with an invalid word"
    );
    let bad_checksum_mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(
        AppService::validate_mnemonic(bad_checksum_mnemonic).is_err(),
        "Should fail with a bad checksum"
    );
}

/// Testet die Passwort-Wiederherstellungsfunktion des `AppService`.
///
/// ### Szenario:
/// 1.  Ein Profil wird erstellt und sofort wieder gesperrt.
/// 2.  Ein Wiederherstellungsversuch mit einer falschen Mnemonic schlägt fehl.
/// 3.  Ein Wiederherstellungsversuch mit der korrekten Mnemonic ist erfolgreich.
/// 4.  Das Wallet ist nach der Wiederherstellung entsperrt.
/// 5.  Nach erneutem Sperren schlägt der Login mit dem alten Passwort fehl,
///     während der Login mit dem neuen Passwort funktioniert.
#[test]
fn api_app_service_password_recovery() {
    // --- 1. Setup ---
    let dir = tempdir().expect("Failed to create temp dir");
    let actor = &ACTORS.alice; // Alice hat keine Passphrase.
    let initial_password = "password-123";
    let new_password = "password-ABC";

    // --- 2. Profil erstellen und wieder sperren ---
    let (mut service, profile_info) = setup_service_with_profile(dir.path(), actor, "Alice Recovery", initial_password);
    service.logout();

    // --- 3. Wiederherstellung mit falscher Mnemonic (muss fehlschlagen) ---
    let wrong_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // Schlechte Prüfsumme
    assert!(
        service
            .recover_wallet_and_set_new_password(&profile_info.folder_name, wrong_mnemonic, None, new_password)
            .is_err()
    );
    assert!( service.get_user_id().is_err(), "Service should remain locked after failed recovery" );

    // --- 4. Wiederherstellung mit korrekter Mnemonic (muss erfolgreich sein) ---
    service.recover_wallet_and_set_new_password(&profile_info.folder_name, &actor.mnemonic, None, new_password).expect("Recovery with correct mnemonic should succeed");
    assert!(
        service.get_user_id().is_ok(),
        "Service should be unlocked after successful recovery"
    );

    service.logout();
    assert!(
        service.login(&profile_info.folder_name, initial_password, false).is_err(),
        "Login with old password should fail after recovery"
    );
    assert!(
        service.login(&profile_info.folder_name, new_password, false).is_ok(),
        "Login with new password should succeed after recovery"
    );
}

/// Testet die Passwort-Wiederherstellung explizit für ein Wallet, das mit einer Passphrase erstellt wurde.
///
/// ### Szenario:
/// 1.  Ein Profil wird mit Mnemonic, Passphrase und Passwort erstellt.
/// 2.  Ein Wiederherstellungsversuch mit der korrekten Mnemonic, aber OHNE Passphrase, schlägt fehl.
/// 3.  Ein Wiederherstellungsversuch mit der korrekten Mnemonic UND der korrekten Passphrase ist erfolgreich.
/// 4.  Der Login mit dem neu gesetzten Passwort funktioniert.
#[test]
fn api_app_service_password_recovery_with_passphrase() {
    let dir = tempdir().expect("Failed to create temp dir");
    let actor = &ACTORS.test_user; // Dieser Aktor verwendet eine Passphrase.
    let initial_password = "password-123";
    let new_password = "password-ABC";

    // 1. Profil mit Passphrase erstellen
    let (mut service, profile_info) = setup_service_with_profile(dir.path(), actor, "Passphrase User", initial_password);
    service.logout();

    // 2. Wiederherstellung OHNE Passphrase (muss fehlschlagen)
    let recovery_fail =
        service.recover_wallet_and_set_new_password(&profile_info.folder_name, &actor.mnemonic, None, new_password);
    assert!(
        recovery_fail.is_err(),
        "Recovery without the correct passphrase should fail"
    );

    // 3. Wiederherstellung MIT korrekter Passphrase (muss erfolgreich sein)
    service .recover_wallet_and_set_new_password(&profile_info.folder_name, &actor.mnemonic, actor.passphrase, new_password)
        .expect("Recovery with correct passphrase should succeed");

    // 4. Verifizierung
    service.logout();
    // Erneutes Login nach der Wiederherstellung, false für cleanup
    let login_result = service.login(&profile_info.folder_name, new_password, false);
    assert!(
        login_result.is_ok(),
        "Login with new password should succeed. Error: {:?}", login_result.err()
    );
}

// --- 2. Wallet Workflows ---

/// Testet den grundlegenden Lebenszyklus des Wallets: Erstellen, Speichern, Laden.
///
/// ### Szenario:
/// 1.  Ein neues Wallet wird aus einer Mnemonic-Phrase erstellt.
/// 2.  Der Zustand des Wallets wird mit einem Passwort verschlüsselt gespeichert.
/// 3.  Das Wallet wird aus dem Speicher geladen.
/// 4.  Es wird verifiziert, dass die geladene User ID mit der ursprünglichen übereinstimmt.
#[test]
fn api_wallet_lifecycle() {
    let dir = tempdir().unwrap();
    let test_user = &ACTORS.alice; // Nehmen wir Alice als Testperson
    let (wallet_a, identity_a) =
        Wallet::new_from_mnemonic(&test_user.mnemonic, test_user.passphrase, test_user.prefix).expect("Wallet creation failed");
    let original_user_id = wallet_a.profile.user_id.clone();
    let folder_name = {
        let secret_string = format!("{}{}{}", &test_user.mnemonic, test_user.passphrase.unwrap_or(""), test_user.prefix.unwrap_or(""));
        voucher_lib::services::crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = dir.path().join(folder_name);
    let mut storage = voucher_lib::storage::file_storage::FileStorage::new(user_storage_path);


    wallet_a
        .save(&mut storage, &identity_a, "password123")
        .expect("Saving wallet failed");

    let auth = AuthMethod::Password("password123");
    let (wallet_b, _) = Wallet::load(&storage, &auth).expect("Loading wallet failed");

    assert_eq!(
        wallet_b.profile.user_id, original_user_id,
        "Loaded user ID should match the original"
    );
}

/// Testet eine vollständige Überweisung des gesamten Gutscheinbetrags.
///
/// ### Szenario:
/// 1.  Alice hat einen Gutschein über 100m.
/// 2.  Sie erstellt einen Transfer von 100m an Bob.
/// 3.  Ihr ursprünglicher Gutschein wird archiviert.
/// 4.  Bob empfängt das Bundle und hat danach einen aktiven Gutschein über 100m.
#[test]
fn api_wallet_transfer_full_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let voucher_lib::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(
            &alice.identity,
            &standards,
            request,
            None,
        )
        .unwrap();

    let summary = alice_wallet
        .list_vouchers(None, None)
        .into_iter()
        .find(|s| s.status == VoucherStatus::Archived)
        .unwrap();
    assert_eq!(summary.status, VoucherStatus::Archived);

    // KORREKTUR: Die Map muss den Minuto-Standard enthalten.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());
    bob_wallet
        .process_encrypted_transaction_bundle(&bob.identity, &bundle_bytes, None, &standards_for_bob)
        .unwrap();

    let summary = bob_wallet.list_vouchers(None, None).pop().unwrap();
    assert_eq!(summary.current_amount, "100");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Testet eine Teilüberweisung, bei der der Restbetrag beim Sender verbleibt.
///
/// ### Szenario:
/// 1.  Alice hat einen Gutschein über 100m.
/// 2.  Sie sendet 30m an Bob.
/// 3.  Ihr alter Gutschein wird archiviert und ein neuer, aktiver Gutschein
///     über 70m wird für sie erstellt.
/// 4.  Bob empfängt das Bundle und hat danach einen aktiven Gutschein über 30m.
#[test]
fn api_wallet_transfer_split_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "30".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let voucher_lib::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(
            &alice.identity,
            &standards,
            request,
            None,
        )
        .unwrap();

    let active_summary = alice_wallet
        .list_vouchers(None, None)
        .into_iter()
        .find(|s| s.status == VoucherStatus::Active)
        .unwrap();
    assert_eq!(active_summary.current_amount, "70");

    // KORREKTUR: Die Map muss den Minuto-Standard enthalten.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());
    bob_wallet
        .process_encrypted_transaction_bundle(&bob.identity, &bundle_bytes, None, &standards_for_bob)
        .unwrap();
    let bob_summary = bob_wallet.list_vouchers(None, None).pop().unwrap();
    assert_eq!(bob_summary.current_amount, "30");
}

/// Stellt sicher, dass Transfers mit ungültigen Beträgen fehlschlagen.
///
/// ### Szenario:
/// 1.  Ein Transfer mit einem negativen Betrag wird versucht und schlägt fehl.
/// 2.  Ein Transfer mit für den Standard unzulässiger Genauigkeit (Dezimalstellen)
///     wird versucht und schlägt fehl.
#[test]
fn api_wallet_transfer_invalid_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let bob = &ACTORS.bob;

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "-50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let result_negative = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request,
        None,
    );
    assert!(matches!(
        result_negative,
        Err(VoucherCoreError::Manager(_))
    ));

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "50.5".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let result_decimal = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request,
        None,
    );
    assert!(matches!(
        result_decimal,
        Err(VoucherCoreError::Manager(_))
    ));
}

/// Stellt sicher, dass Transfers nur mit `Active` Gutscheinen möglich sind.
///
/// ### Szenario:
/// 1.  Ein Gutschein wird manuell auf den Status `Quarantined` gesetzt.
/// 2.  Ein Transferversuch mit diesem Gutschein schlägt mit einem `VoucherNotActive`
///     Fehler fehl.
#[test]
fn api_wallet_transfer_inactive_voucher() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let bob = &ACTORS.bob;

    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    instance.status = VoucherStatus::Quarantined { reason: "test".to_string() };

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let result = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request,
        None,
    );
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined{..}))
    ));
}

/// Testet die proaktive Double-Spend-Verhinderung im `Wallet`.
///
/// ### Szenario:
/// 1.  Alice transferiert einen Gutschein an Bob. Der `create_transfer` Aufruf
///     ist erfolgreich und entfernt den alten Gutschein-Zustand aus dem aktiven Speicher.
/// 2.  Alice versucht, denselben alten Gutschein-Zustand ein zweites Mal an Charlie
///     zu senden.
/// 3.  Der Aufruf schlägt mit `VoucherNotFound` fehl, da der Zustand bereits
///     verbraucht und archiviert wurde. Dies ist der eingebaute Schutz.
#[test]
fn api_wallet_proactive_double_spend_prevention() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let bob = &ACTORS.bob;

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    alice_wallet
        .execute_multi_transfer_and_bundle(
            &alice.identity,
            &standards,
            request,
            None,
        )
        .expect("First transfer should succeed");

    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: ACTORS.charlie.identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let result = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request,
        None,
    );
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotFound(_))
    ));
}

/// Testet das Erstellen eines neuen Gutscheins direkt im Wallet.
///
/// ### Szenario:
/// 1.  Ein neues Wallet wird für einen Aussteller (`issuer`) erstellt.
/// 2.  Die Methode `get_user_id` gibt die korrekte ID zurück.
/// 3.  Ein neuer Gutschein wird mit `create_new_voucher` erstellt.
/// 4.  Der Gutschein ist danach im Wallet vorhanden, hat den Status `Active`
///     und den korrekten Betrag.
#[test]
fn api_wallet_create_voucher_and_get_id() {
    let issuer = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(&issuer.identity);
    assert_eq!(wallet.get_user_id(), issuer.identity.user_id);

    let new_voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(issuer.identity.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "500".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };
    let (silver_standard, silver_standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    wallet
        .create_new_voucher(
            &issuer.identity,
            silver_standard,
            silver_standard_hash,
            "en",
            new_voucher_data,
        )
        .unwrap();

    let summary = wallet
        .list_vouchers(None, None)
        .pop()
        .expect("Wallet should contain one voucher");
    assert_eq!(summary.current_amount, "500.0000");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Testet die korrekte Saldoberechnung über mehrere Währungen hinweg.
///
/// ### Szenario:
/// 1.  Ein Wallet wird mit mehreren aktiven Gutscheinen für "Minuto" und "Unzen"
///     sowie einem nicht-aktiven Gutschein gefüllt.
/// 2.  Die Methode `get_total_balance_by_currency` wird aufgerufen.
/// 3.  Das Ergebnis enthält korrekte, summierte Salden für die beiden Währungen,
///     wobei nur die aktiven Gutscheine berücksichtigt wurden.
#[test]
fn api_wallet_query_total_balance() {
    let issuer = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(&issuer.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let mut add_voucher =
        |amount: &str, status: VoucherStatus, standard: &VoucherStandardDefinition| {
            let new_voucher_data = NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(issuer.identity.user_id.clone()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: amount.to_string(),
                    ..Default::default()
                },
                validity_duration: Some("P4Y".to_string()),
                ..Default::default()
            };
            let mut standard_to_hash = standard.clone();
            standard_to_hash.signature = None;
            let correct_hash = voucher_lib::services::crypto_utils::get_hash(
                voucher_lib::services::utils::to_canonical_json(&standard_to_hash).unwrap(),
            );
            let voucher = create_voucher_for_manipulation(
                new_voucher_data,
                standard,
                &correct_hash,
                &issuer.identity.signing_key,
                "en",
            );
            let local_id = Wallet::calculate_local_instance_id(&voucher, &issuer.identity.user_id).unwrap();
            wallet
                .add_voucher_instance(local_id, voucher, status);
        };

    add_voucher("100", VoucherStatus::Active, minuto_standard);
    add_voucher("50", VoucherStatus::Active, minuto_standard);
    add_voucher("200", VoucherStatus::Quarantined { reason: "test".to_string() }, minuto_standard); // Ignored
    add_voucher("1.25", VoucherStatus::Active, silver_standard);
    add_voucher("0.75", VoucherStatus::Active, silver_standard);

    let balances = wallet.get_total_balance_by_currency();

    assert_eq!(balances.len(), 2, "Two currencies should be present");
    // KORREKTUR: Die Tests müssen die korrekten Währungs-Abkürzungen aus den Standards verwenden.
    let minuto_abbreviation = "Minuto"; // Korrigierte, statische Abkürzung für den Minuto-Standard.
    let expected_minuto_balance = Decimal::from_str("150").unwrap();
    let actual_minuto_balance = Decimal::from_str(
        balances
            .iter()
            .find(|b| &b.unit == minuto_abbreviation)
            .map(|b| b.total_amount.as_str())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual_minuto_balance, expected_minuto_balance);

    let silver_abbreviation = "Oz"; // Korrigierte, statische Abkürzung für den Silber-Standard.
    let expected_silver_balance = Decimal::from_str("2.00").unwrap();
    let actual_silver_balance = Decimal::from_str(
        balances.iter().find(|b| &b.unit == silver_abbreviation).map(|b| b.total_amount.as_str()).unwrap(),
    )
    .unwrap();
    assert_eq!(actual_silver_balance, expected_silver_balance);
}

/// Stellt sicher, dass das Wallet ein Bundle mit einem ungültigen Gutschein abweist.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein, der gegen eine Inhaltsregel seines Standards verstößt.
/// 2.  Sie verpackt diesen ungültigen Gutschein in ein Bundle für Bob.
/// 3.  Eine externe Logik (die den Client simuliert) öffnet das Bundle,
///     validiert den Gutschein und stellt fest, dass er ungültig ist.
/// 4.  Da die Validierung fehlschlägt, wird der Gutschein **nicht** an Bobs Wallet
///     übergeben. Bobs Wallet bleibt leer.
#[test]
fn api_wallet_rejects_invalid_bundle() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(&bob.identity);

    let toml_str = include_str!("../test_data/standards/standard_content_rules.toml");
    let mut standard: VoucherStandardDefinition = toml::from_str(toml_str).unwrap();
    standard.template.fixed.nominal_value.unit = "EUR".to_string();
    standard.template.fixed.description = vec![
        voucher_lib::models::voucher_standard_definition::LocalizedText {
            lang: "en".to_string(),
            text: "INV-123456".to_string(),
        },
    ];

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(alice.identity.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "50.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = voucher_lib::services::crypto_utils::get_hash(
        voucher_lib::services::utils::to_canonical_json(&standard_to_hash).unwrap(),
    );
    let mut voucher = voucher_lib::services::voucher_manager::create_voucher(
        voucher_data,
        &standard,
        &standard_hash,
        &alice.identity.signing_key,
        "en",
    )
        .unwrap();

    voucher.voucher_standard.template.description = "BAD-FORMAT".to_string(); // Verstößt gegen Regex

    let (bundle_bytes, _header) = alice_wallet
        .create_and_encrypt_transaction_bundle(
            &alice.identity,
            vec![voucher.clone()],
            &bob.identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None, // sender_profile_name
        )
        .unwrap();

    let decrypted_bundle =
        voucher_lib::services::bundle_processor::open_and_verify_bundle(&bob.identity, &bundle_bytes)
            .unwrap();
    let received_voucher = decrypted_bundle.vouchers.first().unwrap();

    let validation_result = voucher_lib::services::voucher_validation::validate_voucher_against_standard(
        received_voucher,
        &standard,
    );
    assert!(
        validation_result.is_err(),
        "Validation of the manipulated voucher should fail"
    );

    assert!(
        bob_wallet.voucher_store.vouchers.is_empty(),
        "Bob's wallet should remain empty"
    );
}

/// Testet, dass get_voucher_details die korrekten Details eines Gutscheins zurückgibt.
///
/// ### Szenario:
/// 1.  Es wird ein AppService erstellt und ein Profil angelegt.
/// 2.  Ein Gutschein wird erstellt.
/// 3.  Die lokale ID des Gutscheins wird über get_voucher_summaries ermittelt.
/// 4.  get_voucher_details wird aufgerufen, um die vollständigen Details zu erhalten.
/// 5.  Es wird verifiziert, dass die zurückgegebenen Details korrekt sind:
///     - Der Status ist 'Active'
///     - Der Gutscheininhalt stimmt mit den Erwartungen überein
///     - Der Nominalwert ist korrekt
///     - Die Transaktionen sind vorhanden
#[test]
fn api_app_service_get_voucher_details_returns_correct_data() {
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let password = "password123";
    let mut service_alice =
        AppService::new(dir_alice.path()).expect("Failed to create service for Alice");
    let mnemonic = generate_valid_mnemonic();

    // 1. Profile erstellen
    service_alice
        .create_profile("Alice Details", &mnemonic, None, Some("alice"), password)
        .expect("Alice profile creation failed");

    let id_alice = service_alice.get_user_id().unwrap();

    // 2. Alice erstellt einen Gutschein
    let created_voucher = service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            password,
        )
        .expect("Voucher creation failed");

    // 3. Die lokale ID des Gutscheins ermitteln
    let summaries_alice = service_alice.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_alice.len(), 1, "Should have one voucher");
    let local_id = &summaries_alice[0].local_instance_id;

    // 4. Details des Gutscheins abrufen
    let details = service_alice
        .get_voucher_details(local_id)
        .expect("Should be able to get voucher details");

    // 5. Überprüfen, dass die Details korrekt sind
    assert_eq!(details.status, VoucherStatus::Active, "Voucher should be active");
    assert_eq!(details.voucher.voucher_id, created_voucher.voucher_id, "Voucher ID should match");
    assert_eq!(details.voucher.nominal_value.amount, "100", "Nominal value should match");
    assert_eq!(details.voucher.creator_profile.id.as_ref().unwrap(), &id_alice, "Creator ID should match");
    assert!(!details.voucher.transactions.is_empty(), "Voucher should have at least one transaction");
    assert_eq!(details.voucher.transactions[0].t_type, "init", "First transaction should be init");
}

/// Testet einen Multi-Transfer, bei dem Guthaben von mehreren Quellen gebündelt wird.
///
/// ### Szenario:
/// 1.  Alice hat zwei Gutscheine (100m und 50m).
/// 2.  Sie sendet 20m vom ersten und 30m vom zweiten Gutschein in einer einzigen Transaktion an Bob.
/// 3.  Ihre alten Gutscheine werden archiviert und zwei neue, aktive Gutscheine
///     mit den Restbeträgen (80m und 20m) werden für sie erstellt.
/// 4.  Bob empfängt das Bundle und hat danach zwei neue, aktive Gutscheine (20m und 30m),
///     was einem Gesamtguthaben von 50m entspricht.
#[test]
fn api_wallet_transfer_multi_source() {
    // 1. SETUP
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Füge zwei Gutscheine zu Alices Wallet hinzu
    let voucher_id_1 =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, true)
            .unwrap();
    let voucher_id_2 =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "50", minuto_standard, true)
            .unwrap();

    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    // 2. AKTION: Erstelle eine Anfrage, die 20 vom ersten und 30 vom zweiten Gutschein sendet.
    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![
            voucher_lib::wallet::SourceTransfer {
                local_instance_id: voucher_id_1.clone(),
                amount_to_send: "20".to_string(),
            },
            voucher_lib::wallet::SourceTransfer {
                local_instance_id: voucher_id_2.clone(),
                amount_to_send: "30".to_string(),
            },
        ],
        notes: Some("Zahlung aus zwei Quellen".to_string()),
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());

    let voucher_lib::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None)
        .unwrap();

    // 3. VERIFIZIERUNG (Alice)
    let alice_summaries = alice_wallet.list_vouchers(None, None);
    let mut remaining_amounts_alice: Vec<_> = alice_summaries
        .iter()
        .filter(|s| s.status == VoucherStatus::Active)
        .map(|s| Decimal::from_str(&s.current_amount).unwrap())
        .collect();
    remaining_amounts_alice.sort(); // Sortieren für deterministischen Vergleich

    assert_eq!(remaining_amounts_alice.len(), 2, "Alice sollte zwei aktive Rest-Gutscheine haben");
    assert_eq!(remaining_amounts_alice, vec![Decimal::from(20), Decimal::from(80)]);

    // 4. VERIFIZIERUNG (Bob)
    // KORREKTUR: Die Map muss den Minuto-Standard enthalten.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(minuto_standard.metadata.uuid.clone(), minuto_standard.clone());
    bob_wallet
        .process_encrypted_transaction_bundle(&bob.identity, &bundle_bytes, None, &standards_for_bob)
        .unwrap();
    let balances = bob_wallet.get_total_balance_by_currency();
    let minuto_balance = balances.iter().find(|b| b.unit == "Minuto").unwrap();
    assert_eq!(minuto_balance.total_amount, "50", "Bobs Gesamtguthaben sollte 50 sein");
    assert_eq!(bob_wallet.list_vouchers(None, None).len(), 2, "Bob sollte zwei neue Gutscheine erhalten haben");
}
