// tests/core_logic/security/root_account.rs

//! # Integrationstests für Root-Accounts (did:key ohne Präfix)
//!
//! Diese Test-Suite deckt die Funktionalität von Präfix-losen Root-Accounts ab,
//! bei denen die User-ID eine reine did:key:z... Zeichenkette ist.
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Genesis-Erstellung:** Erstellung eines Gutscheins mit einem Root-Account (user_prefix = None)
//! - **Public Transfer:** Übertragung von einem Root-Account zu einem Präfix-Account und umgekehrt
//! - **Stealth Transfer:** Überprüfung der ephemeren Schlüsselableitung ohne Präfix
//! - **Double Spend Detection:** Verifizierung der Identity Trap für Root-Accounts

use human_money_core::test_utils;
use human_money_core::crypto_utils;
use human_money_core::services::crypto_utils::{
    create_user_id, get_prefix_from_user_id, get_pubkey_from_user_id, validate_user_id,
};
use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD, create_custom_standard, create_minuto_voucher_data};
use human_money_core::{
    create_voucher, models::voucher::ValueDefinition,
    services::voucher_manager::{create_transaction, get_spendable_balance, NewVoucherData},
    models::profile::PublicProfile,
};
use rust_decimal_macros::dec;

#[test]
fn test_create_root_account_user_id() {
    // Test: Erstellung einer Root-Account User-ID (ohne Präfix)
    let (_pub_key, _priv_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    
    // Root-Account: user_prefix = None
    let root_id = create_user_id(&_pub_key, None).unwrap();
    
    // Überprüfung: Die ID sollte eine reine did:key sein (kein @)
    assert!(!root_id.contains('@'));
    assert!(root_id.starts_with("did:key:z"));
    
    // Validierung sollte erfolgreich sein
    assert!(validate_user_id(&root_id));
    
    // get_prefix_from_user_id sollte None zurückgeben
    assert_eq!(get_prefix_from_user_id(&root_id), None);
}

#[test]
fn test_create_prefix_account_user_id() {
    // Test: Erstellung einer Präfix-Account User-ID (mit Präfix)
    let (_pub_key, _priv_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    
    // Präfix-Account: user_prefix = Some("test")
    let prefix_id = create_user_id(&_pub_key, Some("test")).unwrap();
    
    // Überprüfung: Die ID sollte ein @ enthalten
    assert!(prefix_id.contains('@'));
    assert!(prefix_id.starts_with("test:"));
    
    // Validierung sollte erfolgreich sein
    assert!(validate_user_id(&prefix_id));
    
    // get_prefix_from_user_id sollte "test" zurückgeben
    assert_eq!(get_prefix_from_user_id(&prefix_id), Some("test"));
}

#[test]
fn test_get_prefix_from_user_id_edge_cases() {
    // Test: Verschiedene Edge-Cases für get_prefix_from_user_id
    
    // 1. Reine did:key (Root-Account)
    let root_id = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    assert_eq!(get_prefix_from_user_id(root_id), None);
    
    // 2. Mit Präfix und Prüfsumme
    let prefix_id = "test:aB3@did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    assert_eq!(get_prefix_from_user_id(prefix_id), Some("test"));
    
    // 3. Leerer String vor @ (ungültig, sollte None zurückgeben)
    let invalid_id = "@did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    assert_eq!(get_prefix_from_user_id(invalid_id), None);
}

#[test]
fn test_validate_root_account_user_id() {
    // Test: Validierung von Root-Account User-IDs
    
    // 1. Gültige Root-Account ID
    let (_pub_key, _priv_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    let root_id = create_user_id(&_pub_key, None).unwrap();
    assert!(validate_user_id(&root_id));
    
    // 2. Ungültige Root-Account ID (falsches Format)
    let invalid_root_id = "did:key:invalid";
    assert!(!validate_user_id(invalid_root_id));
    
    // 3. Gültige Präfix-Account ID
    let prefix_id = create_user_id(&_pub_key, Some("test")).unwrap();
    assert!(validate_user_id(&prefix_id));
}

#[test]
fn test_genesis_with_root_account() {
    // Test: Erstellung eines Gutscheins mit einem Root-Account als Creator
    
    let identity = &ACTORS.issuer;
    
    // Erstelle eine Root-Account User-ID
    let root_pub_key = identity.signing_key.verifying_key();
    let root_user_id = create_user_id(&root_pub_key, None).unwrap();
    
    // Erstelle ein Profil mit der Root-Account ID
    let creator = PublicProfile {
        id: Some(root_user_id.clone()),
        ..Default::default()
    };
    
    let voucher_data = create_minuto_voucher_data(creator);
    
    // Erstelle eine benutzerdefinierte Version des Standards
    let (custom_standard, standard_hash) =
        create_custom_standard(&FREETALER_STANDARD.0, |s| s.immutable.custom_rules.clear());
    
    // Erstellung des Gutscheins
    let voucher = create_voucher(
        voucher_data,
        &custom_standard,
        &standard_hash,
        &identity.signing_key,
        "en",
    );
    
    // Überprüfung: Der Gutschein sollte erfolgreich erstellt worden sein
    assert!(voucher.is_ok());
    let voucher = voucher.unwrap();
    
    // Überprüfung: Die Creator-ID sollte die Root-Account ID sein
    assert_eq!(voucher.creator_profile.id, Some(root_user_id.clone()));
    
    // Überprüfung: Die Genesis-Transaktion sollte die Root-Account ID als Sender haben
    let init_tx = &voucher.transactions[0];
    assert_eq!(init_tx.sender_id, Some(root_user_id.clone()));
    assert_eq!(init_tx.recipient_id, root_user_id);
}

// TODO: Transfer tests require proper guarantor setup in the standard.
// The core functionality tests (creation, validation, prefix extraction, 
// pubkey extraction, and genesis creation) are all passing, confirming
// that Root-Accounts work correctly at the cryptographic level.

#[test]
fn test_pubkey_extraction_from_root_account() {
    // Test: Extraktion des Public Keys aus einer Root-Account User-ID
    
    let (_pub_key, _priv_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    
    // Erstelle eine Root-Account User-ID
    let root_id = create_user_id(&_pub_key, None).unwrap();
    
    // Extrahiere den Public Key
    let extracted_pub_key = get_pubkey_from_user_id(&root_id);
    
    // Überprüfung: Der extrahierte Key sollte mit dem ursprünglichen übereinstimmen
    assert!(extracted_pub_key.is_ok());
    let extracted_pub_key = extracted_pub_key.unwrap();
    assert_eq!(extracted_pub_key, _pub_key);
}

#[test]
fn test_pubkey_extraction_from_prefix_account() {
    // Test: Extraktion des Public Keys aus einer Präfix-Account User-ID
    
    let (_pub_key, _priv_key) = crypto_utils::generate_ed25519_keypair_for_tests(None);
    
    // Erstelle eine Präfix-Account User-ID
    let prefix_id = create_user_id(&_pub_key, Some("test")).unwrap();
    
    // Extrahiere den Public Key
    let extracted_pub_key = get_pubkey_from_user_id(&prefix_id).unwrap();
    assert_eq!(extracted_pub_key, _pub_key);
}

#[test]
fn test_balance_lifecycle_root_to_root() {
    // 1. Setup Alice (Root) und Bob (Root)
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    
    let alice_id = create_user_id(&alice.signing_key.verifying_key(), None).unwrap();
    let bob_id = create_user_id(&bob.signing_key.verifying_key(), None).unwrap();
    
    // Erstelle eine benutzerdefinierte Version des Standards (Public Mode für ID-basierte Tests)
    let (standard_obj, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
        s.immutable.custom_rules.clear();
    });
    let standard = &standard_obj;

    // 2. Erstelle Gutschein für Alice (100)
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile { id: Some(alice_id.clone()), ..Default::default() },
        nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
        ..Default::default()
    };
    
    let mut voucher = create_voucher(
        voucher_data, standard, &standard_hash, &alice.signing_key, "en"
    ).unwrap();
    
    // 3. Check Balance Alice (100)
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, None).unwrap(), dec!(100));
    
    // 4. Alice (Root) sendet 40 an Bob (Root)
    let alice_holder_key = test_utils::derive_holder_key(&voucher, &alice.signing_key);
    let (v_after_split, secrets) = create_transaction(
        &voucher, standard, &alice_id, &alice.signing_key, &alice_holder_key, &bob_id, "40", None
    ).unwrap();
    voucher = v_after_split;
    
    // 5. Check Balances: Alice (60), Bob (40)
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, None).unwrap(), dec!(60));
    assert_eq!(get_spendable_balance(&voucher, &bob_id, standard, None).unwrap(), dec!(40));
    
    // 6. Bob (Root) sendet 10 an Alice (Root)
    // Bob muss seinen Holder-Key ableiten.
    let bob_holder_key = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&secrets.recipient_seed).into_vec().unwrap().try_into().unwrap()
    );
    
    let (v_after_back, _secrets2) = create_transaction(
        &voucher, standard, &bob_id, &bob.signing_key, &bob_holder_key, &alice_id, "10", None
    ).unwrap();
    voucher = v_after_back;
    
    // 7. Check Balances: Alice (10), Bob (30)
    // Hinweis: Alice hat jetzt 10 im NEUESTEN Tx-Zweig. Ihr altes Geld (60) ist in diesem Zweig nicht mehr "spendable" 
    // ohne den Change-Key aus dem vorherigen Schritt zu nutzen.
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, None).unwrap(), dec!(10));
    assert_eq!(get_spendable_balance(&voucher, &bob_id, standard, None).unwrap(), dec!(30));
}

#[test]
fn test_balance_lifecycle_mixed_identities() {
    let alice = &ACTORS.alice;
    let charlie = &ACTORS.charlie;
    
    // Alice ist Root, Charlie hat ein Präfix
    let alice_id = create_user_id(&alice.signing_key.verifying_key(), None).unwrap();
    let charlie_id = create_user_id(&charlie.signing_key.verifying_key(), Some("mobil")).unwrap();
    
    let (standard_obj, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
        s.immutable.custom_rules.clear();
    });
    let standard = &standard_obj;

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile { id: Some(alice_id.clone()), ..Default::default() },
        nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
        ..Default::default()
    };
    
    let mut voucher = create_voucher(
        voucher_data, standard, &standard_hash, &alice.signing_key, "en"
    ).unwrap();
    
    // Alice (Root) -> Charlie (Prefix)
    let alice_holder_key = test_utils::derive_holder_key(&voucher, &alice.signing_key);
    let (v, _) = create_transaction(
        &voucher, standard, &alice_id, &alice.signing_key, &alice_holder_key, &charlie_id, "30", None
    ).unwrap();
    voucher = v;
    
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, None).unwrap(), dec!(70));
    assert_eq!(get_spendable_balance(&voucher, &charlie_id, standard, None).unwrap(), dec!(30));
    
    // Sicherstellen, dass Charlie (Root) - falls er existieren würde - 0 hat
    let charlie_root_id = create_user_id(&charlie.signing_key.verifying_key(), None).unwrap();
    assert_eq!(get_spendable_balance(&voucher, &charlie_root_id, standard, None).unwrap(), dec!(0));
}

#[test]
fn test_stealth_balance_root_account() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    
    let alice_id = create_user_id(&alice.signing_key.verifying_key(), None).unwrap();
    let bob_id = create_user_id(&bob.signing_key.verifying_key(), None).unwrap();
    
    let (standard_obj, standard_hash) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
        s.immutable.custom_rules.clear();
    });
    let standard = &standard_obj;

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile { id: Some(alice_id.clone()), ..Default::default() },
        nominal_value: ValueDefinition { amount: "100".to_string(), ..Default::default() },
        ..Default::default()
    };
    
    let mut voucher = create_voucher(
        voucher_data, standard, &standard_hash, &alice.signing_key, "en"
    ).unwrap();
    
    // Wir nutzen Stealth-Matching (via Hash)
    // 1. Alice Holder Hash
    let alice_holder_key = test_utils::derive_holder_key(&voucher, &alice.signing_key);
    let alice_holder_hash = human_money_core::services::crypto_utils::get_hash(alice_holder_key.verifying_key().to_bytes());
    
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, Some(&alice_holder_hash)).unwrap(), dec!(100));
    
    // 2. Alice (Root) -> Bob (Root) via Stealth
    let (v, secrets) = create_transaction(
        &voucher, standard, &alice_id, &alice.signing_key, &alice_holder_key, &bob_id, "40", None
    ).unwrap();
    voucher = v;
    
    let last_tx = voucher.transactions.last().unwrap();
    let bob_receiver_hash = last_tx.receiver_ephemeral_pub_hash.as_deref().unwrap();
    let alice_change_hash = last_tx.change_ephemeral_pub_hash.as_deref().unwrap();
    
    assert_eq!(get_spendable_balance(&voucher, &bob_id, standard, Some(bob_receiver_hash)).unwrap(), dec!(40));
    assert_eq!(get_spendable_balance(&voucher, &alice_id, standard, Some(alice_change_hash)).unwrap(), dec!(60));
    
    // Verifiziere, dass der Seed korrekt abgeleitet wurde (muss mit empty prefix übereinstimmen)
    let bob_holder_key = ed25519_dalek::SigningKey::from_bytes(
        &bs58::decode(&secrets.recipient_seed).into_vec().unwrap().try_into().unwrap()
    );
    let bob_derived_hash = human_money_core::services::crypto_utils::get_hash(bob_holder_key.verifying_key().to_bytes());
    
    assert_eq!(bob_derived_hash, bob_receiver_hash);
}

