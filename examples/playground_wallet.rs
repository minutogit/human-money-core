// examples/playground_wallet.rs
// run with: cargo run --example playground_wallet
//! # examples/playground_wallet.rs
//!
//! Ein kurzer Playground für die Wallet-Fassade.
//! 1. Erstellt zwei Identitäten (Alice als Senderin, Bob als Empfänger).
//! 2. Initialisiert Alices Wallet und fügt einen neuen Gutschein hinzu.
//! 3. Alice sendet den Gutschein über `wallet.execute_multi_transfer_and_bundle` an Bob.
//! 4. Gibt den finalen Gutschein-Zustand und den dabei erzeugten
//!    anonymen Transaktions-Fingerprint im Terminal aus.

use human_money_core::models::conflict::CanonicalMetadataStore;
use human_money_core::models::profile::UserIdentity;
use human_money_core::models::voucher::{Address, Collateral, ValueDefinition};
use human_money_core::services::crypto_utils;
use human_money_core::wallet::Wallet;
use human_money_core::{NewVoucherData, VoucherStatus, verify_and_parse_standard};

/// Hilfsfunktion, um eine deterministische UserIdentity für Tests zu erstellen.
fn create_test_identity(seed: &str, prefix: &str) -> UserIdentity {
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some(seed));
    let user_id = crypto_utils::create_user_id(&public_key, Some(prefix)).unwrap();
    UserIdentity {
        signing_key,
        public_key,
        user_id,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- WALLET TRANSACTION PLAYGROUND ---");

    // --- SCHRITT 1: Setup ---
    println!("\n--- SCHRITT 1: Erstelle Identitäten, Wallet und einen initialen Gutschein ---");

    // Erstelle Identitäten für Alice (Senderin) und Bob (Empfänger)
    let alice_identity = create_test_identity("alice", "al");
    let bob_identity = create_test_identity("bob", "bo");
    println!(
        "✅ Identitäten für Alice ({}) und Bob ({}) erstellt.",
        alice_identity.user_id, bob_identity.user_id
    );

    // Lade den für den Gutschein gültigen Standard
    let standard_toml = std::fs::read_to_string("voucher_standards/silver_v1/standard.toml")?;
    let (standard, standard_hash) = verify_and_parse_standard(&standard_toml)?;
    println!(
        "✅ Standard '{}' verifiziert und geladen.",
        standard.immutable.identity.name
    );

    // Erstelle eine neue, leere Wallet für Alice
    let mut alice_wallet = Wallet {
        profile: human_money_core::models::profile::UserProfile {
            user_id: alice_identity.user_id.clone(),
            first_name: None,
            last_name: None,
            organization: None,
            community: None,
            address: None,
            gender: None,
            email: None,
            phone: None,
            coordinates: None,
            url: None,
            service_offer: None,
            needs: None,
            picture_url: None,
            l2_server_pubkey: None,
        },
        voucher_store: Default::default(),
        bundle_meta_store: Default::default(),
        known_fingerprints: Default::default(),
        own_fingerprints: Default::default(),
        proof_store: Default::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
    };
    println!("✅ Leeres Wallet für Alice erstellt.");

    // Erstelle einen neuen Gutschein und füge ihn Alices Wallet hinzu
    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // 5 Jahre, entspricht dem Standard-Default
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: "1.5".to_string(),
            ..Default::default()
        }, // 1.5 Unzen
        collateral: Some(Collateral::default()),
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(alice_identity.user_id.clone()),
            first_name: Some("Alice".into()),
            last_name: Some("Silversmith".into()),
            address: Some(Address::default()),
            gender: Some("2".into()),
            ..Default::default()
        },
    };
    let initial_voucher = human_money_core::create_voucher(
        voucher_data,
        &standard,
        &standard_hash,
        &alice_identity.signing_key,
        "en",
    )?;
    let local_id = Wallet::calculate_local_instance_id(&initial_voucher, &alice_identity.user_id)?;
    alice_wallet.add_voucher_instance(local_id, initial_voucher, VoucherStatus::Active);
    println!("✅ Initialen Gutschein erstellt und zu Alices Wallet hinzugefügt.");

    // --- SCHRITT 2: Transaktion durchführen ---
    println!("\n--- SCHRITT 2: Alice sendet 0.5 Unzen an Bob ---");

    // Die lokale ID des Gutscheins in Alices Wallet holen
    let local_instance_id = alice_wallet
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    // Erstelle eine MultiTransferRequest und rufe die neue Methode auf
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_instance_id.clone(),
            amount_to_send: "0.5".to_string(),
        }],
        notes: Some("Payment for services".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards_map = std::collections::HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    // For this example, we need to create a new method to execute transfer and get result vouchers
    // Let's call the same method but process the resulting bundle to get the vouchers
    let _container_bytes = alice_wallet.execute_multi_transfer_and_bundle(
        &alice_identity,
        &standards_map,
        request,
        None::<&dyn human_money_core::archive::VoucherArchive>, // Kein Archiv
    )?;

    println!("✅ Transaktion erfolgreich durchgeführt. Wallet-Zustand wurde aktualisiert.");

    // --- AUSGABE 1: Hinweis auf den Transfer-Erfolg ---
    println!("\n--- AUSGABE 1: Transfer erfolgreich durchgeführt ---");
    println!(
        "Der Transfer-Bundle wurde erfolgreich erstellt und kann an den Empfänger gesendet werden."
    );

    // --- AUSGABE 2: Anonymer Fingerprint der Transaktion (Rohdaten) ---
    println!("\n--- AUSGABE 2: Anonymer Fingerprint der Transaktion (Rohdaten) ---");
    println!(
        "Dieser Fingerprint wurde automatisch von `execute_multi_transfer_and_bundle` erzeugt und in Alices Wallet gespeichert, um Double-Spending proaktiv zu verhindern."
    );

    // Den erzeugten Fingerprint aus dem Store des Wallets auslesen
    let fingerprint = alice_wallet
        .own_fingerprints
        .history
        .values()
        .next() // Nimm den ersten (und einzigen) Vektor von Fingerprints
        .and_then(|fps| fps.first()) // Nimm den ersten (und einzigen) Fingerprint aus dem Vektor
        .expect("Fingerprint sollte im Wallet-Store vorhanden sein.");

    // Gib die "Rohdaten" des Fingerprints aus
    println!("{:#?}", fingerprint);

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}
