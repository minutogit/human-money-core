// tests/persistence/file_storage.rs
// cargo test --test persistence_tests
//!
//! Enthält Integrationstests für das refaktorierte Profil- und VoucherStore-Management,
//! inklusive der Passwort-Wiederherstellungslogik und Randbedingungen.
//! Ursprünglich in `tests/test_file_storage.rs`.

use human_money_core::UserIdentity;
use human_money_core::VoucherStatus;
use human_money_core::error::VoucherCoreError;
use human_money_core::models::voucher::{ValueDefinition, Voucher};
use human_money_core::services::crypto_utils;
use human_money_core::services::voucher_manager;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::storage::AuthMethod;
use human_money_core::{FileStorage, Storage, StorageError, Wallet};
use std::fs;
use tempfile::tempdir;

// Lade die Test-Hilfsfunktionen aus dem übergeordneten Verzeichnis.

use human_money_core::test_utils::{
    ACTORS, SILVER_STANDARD, add_voucher_to_wallet, setup_in_memory_wallet,
};

// --- Hilfsfunktionen ---
fn create_test_voucher(identity: &UserIdentity) -> Voucher {
    let new_voucher_data = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            address: Some(Default::default()),
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: Some("9".to_string()),
            coordinates: Some("0,0".to_string()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    // KORREKTUR: Passe den Aufruf an die neue 5-parametrige Signatur an.
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    voucher_manager::create_voucher(
        new_voucher_data,
        standard,
        standard_hash,
        &identity.signing_key,
        "en",
    )
    .expect("Voucher creation failed")
}

// --- Tests ---

#[test]
fn test_wallet_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";
    let identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let wallet = setup_in_memory_wallet(identity);

    // 2. Speichern
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .expect("Failed to save wallet");

    // 3. Laden und Verifizieren
    let (loaded_wallet, loaded_identity) =
        Wallet::load(&storage, &AuthMethod::Password(password)).expect("Failed to load wallet");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert_eq!(identity.user_id, loaded_identity.user_id);
    assert!(loaded_wallet.voucher_store.vouchers.is_empty());

    // 4. Fehlerfall: Falsches Passwort
    let result = Wallet::load(&storage, &AuthMethod::Password("wrongpassword"));
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_password_recovery_and_reset_with_data() {
    // 1. Setup: Erstelle ein Profil mit einem Gutschein.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let initial_password = "my-secret-password";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);
    let voucher = create_test_voucher(identity);
    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id).unwrap();

    wallet.add_voucher_instance(local_id.clone(), voucher, VoucherStatus::Active);
    assert_eq!(wallet.voucher_store.vouchers.len(), 1);

    wallet
        .save(
            &mut storage,
            &identity,
            &AuthMethod::Password(initial_password),
        )
        .expect("Initial save failed");

    // 2. Wiederherstellung mit der Mnemonic-Phrase (Identität).
    // Erzeuge eine Identität für die Referenz (borrow) und eine zweite für die Wertübergabe (move).
    let (recovered_wallet, recovered_identity) =
        Wallet::load(&storage, &AuthMethod::RecoveryIdentity(identity))
            .expect("Recovery with correct identity should succeed");

    // Überprüfe, ob die wiederhergestellten Daten (inkl. Gutschein) korrekt sind.
    assert_eq!(wallet.profile.user_id, recovered_wallet.profile.user_id);
    assert_eq!(identity.user_id, recovered_identity.user_id);
    assert_eq!(
        recovered_wallet.voucher_store.vouchers.len(),
        1,
        "Voucher should be present after recovery"
    );
    assert!(
        recovered_wallet
            .voucher_store
            .vouchers
            .contains_key(&local_id)
    );

    // 3. Passwort zurücksetzen.
    let new_password = "my-new-strong-password-456";
    storage
        .reset_password(identity, new_password)
        .expect("Password reset should succeed");

    // 4. Verifizierung nach dem Reset.
    // Login mit altem Passwort muss fehlschlagen.
    let result = Wallet::load(&storage, &AuthMethod::Password(initial_password));
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));

    // Login mit neuem Passwort muss erfolgreich sein und die Daten müssen intakt sein.
    let (final_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(new_password))
        .expect("Login with new password should succeed");

    assert_eq!(wallet.profile.user_id, final_wallet.profile.user_id);
    assert_eq!(
        final_wallet.voucher_store.vouchers.len(),
        1,
        "Voucher should still be present after reset"
    );
    assert!(final_wallet.voucher_store.vouchers.contains_key(&local_id));

    // 5. Fehlerfall: Wiederherstellung mit der falschen Identität.
    let imposter_identity = &ACTORS.hacker;
    let result = Wallet::load(&storage, &AuthMethod::RecoveryIdentity(imposter_identity));
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_load_with_missing_voucher_store() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .unwrap();

    // Lösche die Gutschein-Datei
    fs::remove_file(storage.user_storage_path.join("vouchers.enc")).unwrap();

    // Das Laden sollte trotzdem erfolgreich sein und einen leeren Store zurückgeben
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(password))
        .expect("Loading with missing voucher store should succeed");

    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert!(
        loaded_wallet.voucher_store.vouchers.is_empty(),
        "Voucher store should be empty by default"
    );
}

#[test]
fn test_load_from_corrupted_profile_file() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let identity = &ACTORS.victim;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .unwrap();

    // Beschädige die Profil-Datei
    // KORREKTUR: Pfad muss auf den User-Unterordner zeigen
    let profile_path = storage.user_storage_path.join("profile.enc");
    let mut contents = fs::read(&profile_path).unwrap();
    contents.truncate(contents.len() / 2); // Schneide die Hälfte ab
    fs::write(&profile_path, contents).unwrap();

    // Das Laden sollte mit einem Deserialisierungs- oder Formatfehler fehlschlagen
    let result = Wallet::load(&storage, &AuthMethod::Password(password));
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(StorageError::InvalidFormat(_)))
    ));
}

#[test]
fn test_empty_password_handling() {
    let temp_dir = tempdir().unwrap();
    let empty_password = "";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let wallet = setup_in_memory_wallet(identity);

    // Speichern mit leerem Passwort sollte funktionieren
    wallet
        .save(
            &mut storage,
            &identity,
            &AuthMethod::Password(empty_password),
        )
        .expect("Saving with empty password should succeed");

    // Laden mit leerem Passwort sollte funktionieren
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(empty_password))
        .expect("Loading with empty password should succeed");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);

    // Laden mit einem falschen, nicht-leeren Passwort sollte fehlschlagen
    let result = Wallet::load(&storage, &AuthMethod::Password("a-real-password"));
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_save_and_load_with_bundle_history() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";

    // Erstelle Sender (Alice) und Empfänger (Bob)
    let alice_identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &alice_identity.mnemonic,
            alice_identity.passphrase.unwrap_or(""),
            alice_identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);

    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    // Alice erstellt einen Gutschein und fügt ihn ihrem Wallet hinzu
    let local_id = add_voucher_to_wallet(
        &mut alice_wallet,
        alice_identity,
        "100",
        silver_standard,
        false,
    )
    .unwrap();

    // 2. Aktion: Führe eine Transaktion durch, um Bundle-Metadaten zu erzeugen.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "100".to_string(), // Sende den vollen Betrag
        }],
        notes: Some("Test transfer".to_string()),
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        silver_standard.metadata.uuid.clone(),
        silver_standard.clone(),
    );

    let _ = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            None::<&dyn human_money_core::archive::VoucherArchive>,
        )
        .expect("Transfer failed");

    // Überprüfe den Zustand vor dem Speichern
    assert_eq!(alice_wallet.bundle_meta_store.history.len(), 1);
    let original_bundle_id = alice_wallet
        .bundle_meta_store
        .history
        .keys()
        .next()
        .unwrap()
        .clone();

    // 3. Speichern
    alice_wallet
        .save(
            &mut storage,
            &alice_identity,
            &AuthMethod::Password(password),
        )
        .expect("Failed to save wallet with history");

    // Überprüfe, ob die neue Metadaten-Datei erstellt wurde
    assert!(storage.user_storage_path.join("bundles.meta.enc").exists());

    // 4. Laden und Verifizieren
    let (loaded_wallet, _) =
        Wallet::load(&storage, &AuthMethod::Password(password)).expect("Failed to load wallet");

    // **Die entscheidende Prüfung:** Wurde die Historie korrekt geladen?
    assert_eq!(
        loaded_wallet.bundle_meta_store.history.len(),
        1,
        "Bundle history should have been loaded from bundles.meta.enc"
    );
    assert!(
        loaded_wallet
            .bundle_meta_store
            .history
            .contains_key(&original_bundle_id)
    );
    assert_eq!(loaded_wallet.profile.user_id, alice_wallet.profile.user_id);
}

/// Ein Hilfs-Struct, um das Speichern von serialisierten Daten zu testen.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct AppSettings {
    theme: String,
    notifications_enabled: bool,
    user_level: u32,
}

#[test]
fn test_save_and_load_arbitrary_data() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "arbitrary-data-password";
    let identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    println!(
        "--> Test storage created in: {:?}",
        storage.user_storage_path
    );
    let wallet = setup_in_memory_wallet(identity);

    // WICHTIG: Zuerst das Wallet speichern, damit die Schlüssel-Infrastruktur
    // (master_key.enc, recovery_key.enc) für die Verschlüsselung initialisiert wird.
    wallet
        .save(&mut storage, identity, &AuthMethod::Password(password))
        .expect("Initial wallet save failed");

    // 2. Erstelle Testdaten (einfach und komplex)
    let blob_name1 = "simple_blob";
    let simple_data = b"this is some raw byte data".to_vec();

    let blob_name2 = "app_settings";
    let complex_data = AppSettings {
        theme: "dark".to_string(),
        notifications_enabled: true,
        user_level: 5,
    };
    let complex_data_bytes = bincode::serialize(&complex_data).unwrap();

    // 3. Speichern der Daten
    println!("--> Saving blobs to storage...");
    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
            &simple_data,
        )
        .expect("Saving simple blob should succeed");

    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name2,
            &complex_data_bytes,
        )
        .expect("Saving complex blob should succeed");

    println!("--> Blobs saved successfully.");

    // Überprüfe, ob die Dateien mit dem korrekten, benutzerspezifischen Namen erstellt wurden
    let user_hash = crypto_utils::get_hash(identity.user_id.as_bytes());
    let expected_path1 = storage
        .user_storage_path
        .join(format!("generic_{}.{}.enc", blob_name1, user_hash));
    let expected_path2 = storage
        .user_storage_path
        .join(format!("generic_{}.{}.enc", blob_name2, user_hash));

    println!("--> Verifying existence of file: {:?}", expected_path1);
    assert!(
        expected_path1.exists(),
        "File for simple blob was not created at the expected path!"
    );
    println!("--> Verifying existence of file: {:?}", expected_path2);
    assert!(
        expected_path2.exists(),
        "File for complex blob was not created at the expected path!"
    );

    // 4. Laden und Verifizieren
    let loaded_simple_data = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
        )
        .expect("Loading simple blob should succeed");
    assert_eq!(simple_data, loaded_simple_data);

    let loaded_complex_data_bytes = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name2,
        )
        .expect("Loading complex blob should succeed");
    let loaded_complex_data: AppSettings =
        bincode::deserialize(&loaded_complex_data_bytes).unwrap();
    assert_eq!(complex_data, loaded_complex_data);

    // 5. Fehlerfälle
    // Falsches Passwort
    let res = storage.load_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password("wrong-pass"),
        blob_name1,
    );
    assert!(matches!(res, Err(StorageError::AuthenticationFailed)));

    // Nicht existierende Daten
    let res = storage.load_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password(password),
        "non-existent-blob",
    );
    assert!(matches!(res, Err(StorageError::NotFound)));

    // 6. Überschreiben testen
    let new_simple_data = b"this is updated data".to_vec();
    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
            &new_simple_data,
        )
        .expect("Overwriting blob should succeed");

    let reloaded_data = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
        )
        .expect("Loading overwritten blob should succeed");
    assert_eq!(new_simple_data, reloaded_data);
    assert_ne!(simple_data, reloaded_data);
}

/// Testet den "Re-entrancy"-Schutz (Wiedereintrittsschutz).
/// Szenario: Ein Prozess (PID X) hält bereits eine Sperre (simuliert durch manuelles Erstellen der .lock Datei).
/// Derselbe Prozess versucht über eine zweite Storage-Instanz erneut zu schreiben.
/// Erwartung: Der Lock-Mechanismus erkennt, dass die PID in der Datei die eigene ist, und erlaubt den Zugriff.
#[test]
fn test_storage_reentrancy_same_process() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "reentrancy_check";
    let identity = &ACTORS.alice;

    // Pfad-Berechnung analog zu anderen Tests
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        crypto_utils::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = temp_dir.path().join(folder_name);

    // Instanz 1: Initialisieren, um Keys anzulegen (damit save_arbitrary_data später nicht an Auth scheitert)
    let mut storage1 = FileStorage::new(user_storage_path.clone());
    let wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage1, identity, &AuthMethod::Password(password))
        .expect("Initial setup save failed");

    // 2. SIMULATION: Wir injizieren manuell eine Lock-Datei mit UNSERER aktuellen PID.
    // Das simuliert, dass wir (oder ein anderer Thread in diesem Prozess) den Lock halten.
    let lock_path = user_storage_path.join(".wallet.lock");
    let current_pid = std::process::id();
    fs::write(&lock_path, current_pid.to_string()).expect("Failed to inject fake lock file");

    // 3. Instanz 2: Zugriff auf denselben Pfad
    let mut storage2 = FileStorage::new(user_storage_path);

    // 4. ACT: Versuch, Daten zu speichern.
    // Dies ruft intern lock() auf. Wenn der Re-entrancy-Fix fehlt, würde er die Lock-Datei sehen,
    // die PID lesen und einen LockFailed werfen, weil er "denkt", er sei blockiert.
    let res = storage2.save_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password(password),
        "reentrancy_blob",
        b"data",
    );

    // 5. ASSERT
    assert!(
        res.is_ok(),
        "Re-entrancy Check failed! Prozess hat sich selbst ausgesperrt. Error: {:?}",
        res.err()
    );
}
