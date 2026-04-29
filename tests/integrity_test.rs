use human_money_core::app_service::AppService;
use human_money_core::models::storage_integrity::IntegrityReport;
use human_money_core::services::mnemonic::MnemonicLanguage;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_wallet_integrity_missing_item() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    // Profil erstellen - das sollte auch den initialen Digest schreiben
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Initialer Check - sollte Valid sein
    let report = app.check_integrity(Some(password)).expect("Integrity check failed");
    assert_eq!(report, IntegrityReport::Valid);
    
    // 2. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 3. Eine wichtige Datei löschen (z.B. vouchers.enc)
    let vouchers_file = wallet_path.join("vouchers.enc");
    assert!(vouchers_file.exists(), "vouchers.enc should exist");
    fs::remove_file(vouchers_file).unwrap();
    
    // 4. Check erneut - sollte MissingItems melden
    let report = app.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::MissingItems(items) => {
            println!("Detected missing items: {:?}", items);
            assert!(items.contains(&"vouchers.enc".to_string()));
        }
        other => panic!("Expected MissingItems, got {:?}", other),
    }
}

#[test]
fn test_wallet_integrity_manipulated_item() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 2. Eine Datei manipulieren
    let vouchers_file = wallet_path.join("vouchers.enc");
    fs::write(vouchers_file, b"corrupted data").unwrap();
    
    // 3. Check - sollte ManipulatedItems melden
    let report = app.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::ManipulatedItems(items) => {
            println!("Detected manipulated items: {:?}", items);
            assert!(items.contains(&"vouchers.enc".to_string()));
        }
        other => panic!("Expected ManipulatedItems, got {:?}", other),
    }
}

#[test]
fn test_wallet_integrity_unknown_item() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 2. Eine unbekannte Datei erstellen
    let unknown_file = wallet_path.join("unknown_attacker_file.txt");
    fs::write(unknown_file, b"evil").unwrap();
    
    // 3. Check - sollte UnknownItems melden
    let report = app.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::UnknownItems(items) => {
            println!("Detected unknown items: {:?}", items);
            assert!(items.contains(&"unknown_attacker_file.txt".to_string()));
        }
        other => panic!("Expected UnknownItems, got {:?}", other),
    }
}

#[test]
fn test_wallet_integrity_missing_digest() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 2. Integrity Record löschen
    let integrity_file = wallet_path.join("storage_integrity.json");
    fs::remove_file(integrity_file).unwrap();
    
    // 3. Check - sollte MissingIntegrityRecord melden
    let report = app.check_integrity(Some(password)).unwrap();
    assert_eq!(report, IntegrityReport::MissingIntegrityRecord);
}

#[test]
fn test_wallet_integrity_invalid_signature() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 2. Integrity Record manipulieren (Signatur-Bruch)
    let integrity_file = wallet_path.join("storage_integrity.json");
    let content = fs::read_to_string(&integrity_file).unwrap();
    println!("Integrity Record content: {}", content);
    
    // Wir manipulieren den payload, damit die Signatur bricht.
    let manipulated = content.replace("\"version\": 1", "\"version\": 2")
                             .replace("\"version\":1", "\"version\":2");
    
    assert_ne!(content, manipulated, "Integrity Record manipulation failed - string matching issue?");
    fs::write(integrity_file, manipulated).unwrap();
    
    // 3. Check - sollte InvalidSignature melden
    let report = app.check_integrity(Some(password)).unwrap();
    assert_eq!(report, IntegrityReport::InvalidSignature);
}

#[test]
fn test_wallet_integrity_repair() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    app.create_profile("Repair Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 1. Eine Datei manipulieren
    let vouchers_file = wallet_path.join("vouchers.enc");
    fs::write(vouchers_file, b"legitimate manual change").unwrap();
    
    // 2. Check - sollte ManipulatedItems melden
    let report = app.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::ManipulatedItems(_) => (),
        other => panic!("Expected ManipulatedItems, got {:?}", other),
    }
    
    // 3. Reparatur ausführen (Nutzer sagt "OK")
    app.repair_integrity(Some(password)).expect("Repair failed");
    
    // 4. Check erneut - sollte jetzt Valid sein
    let report = app.check_integrity(Some(password)).unwrap();
    assert_eq!(report, IntegrityReport::Valid);
}

#[test]
fn test_wallet_integrity_missing_bundles_meta_after_restart() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    // Profil erstellen
    app.create_profile("Bundles Test", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 1. Initialer Check - sollte Valid sein
    let report = app.check_integrity(Some(password)).expect("Integrity check failed");
    assert_eq!(report, IntegrityReport::Valid);
    
    // 2. Info holen um den Pfad zu finden
    let profiles = app.list_profiles().unwrap();
    let folder_name = &profiles[0].folder_name;
    let wallet_path = base_path.join(folder_name);
    
    // 3. bundles.meta.enc löschen
    let bundles_meta_file = wallet_path.join("bundles.meta.enc");
    if bundles_meta_file.exists() {
        fs::remove_file(bundles_meta_file).unwrap();
    }
    
    // 4. Check - sollte MissingItems mit bundles.meta.enc melden
    let report = app.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::MissingItems(items) => {
            println!("Detected missing items: {:?}", items);
            assert!(items.contains(&"bundles.meta.enc".to_string()), 
                    "bundles.meta.enc should be in missing items");
        }
        other => panic!("Expected MissingItems, got {:?}", other),
    }
    
    // 5. Wallet logout und login simulieren (Neustart)
    app.logout();
    
    let mut app2 = AppService::new(base_path).unwrap();
    let profiles2 = app2.list_profiles().unwrap();
    let folder_name2 = &profiles2[0].folder_name;
    app2.login(folder_name2, password, false, "test-id".to_string()).expect("Login failed");
    
    // 6. Nach dem Neustart sollte die Datei noch fehlen (wird nicht automatisch recreated)
    let bundles_meta_file_after = wallet_path.join("bundles.meta.enc");
    assert!(!bundles_meta_file_after.exists(), "bundles.meta.enc should still be missing after restart");
    
    // 7. Check erneut - sollte immer noch MissingItems melden, da login() den Zustand NICHT mehr blind versiegelt
    let report = app2.check_integrity(Some(password)).unwrap();
    match report {
        IntegrityReport::MissingItems(items) => {
            assert!(items.contains(&"bundles.meta.enc".to_string()), 
                    "bundles.meta.enc should still be detected as missing after login");
        }
        other => panic!("Expected MissingItems after login, got {:?}", other),
    }
    
    // 8. Reparatur ausführen - erst jetzt sollte es Valid sein
    app2.repair_integrity(Some(password)).expect("Repair failed");
    let report = app2.check_integrity(Some(password)).unwrap();
    assert_eq!(report, IntegrityReport::Valid, "Integrity should be Valid ONLY after explicit repair");
}

#[test]
fn test_storage_integrity_after_save_encrypted_data() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    // 1. Create Profile (this should be valid and sealed)
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    let report = app.check_integrity(Some(password)).expect("Initial integrity check failed");
    assert_eq!(report, IntegrityReport::Valid, "Initially, integrity should be valid");
    
    // 2. Save some arbitrary data (e.g., settings)
    app.save_encrypted_data("settings", b"{\"theme\": \"dark\"}", Some(password)).unwrap();
    
    // 3. Check integrity again
    let report = app.check_integrity(Some(password)).expect("Integrity check after save failed");
    assert_eq!(report, IntegrityReport::Valid, "Integrity should remain valid after save_encrypted_data");
}

#[test]
fn test_storage_integrity_after_login_anchor_write() {
    let dir = tempdir().unwrap();
    let base_path = dir.path();
    let mut app = AppService::new(base_path).unwrap();
    
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    let password = "test-password";
    
    // 1. Create Profile
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English, "test-id".to_string()).unwrap();
    
    // 2. Logout
    let profiles = app.list_profiles().unwrap();
    let folder_name = profiles[0].folder_name.clone();
    app.logout();
    
    // 3. Login
    let mut app2 = AppService::new(base_path).unwrap();
    app2.login(&folder_name, password, false, "test-id".to_string()).unwrap();
    
    // 4. Check integrity
    let report = app2.check_integrity(Some(password)).expect("Integrity check after login failed");
    assert_eq!(report, IntegrityReport::Valid, "Integrity should remain valid after login (session anchor write)");
}
