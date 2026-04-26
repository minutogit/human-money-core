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
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
    
    app.create_profile("Test Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
    
    app.create_profile("Repair Profil", &mnemonic, None, Some("test"), password, MnemonicLanguage::English).unwrap();
    
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
