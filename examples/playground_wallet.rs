//! # Wallet Facade Playground
//!
//! Demonstrates the high-level `Wallet` facade.
//! - Creates deterministic user identities (Alice and Bob)
//! - Initializes a wallet instance and registers active vouchers
//! - Executes a multi-transfer and bundles the resulting transaction data
//! - Inspects and prints the generated transaction fingerprint
//!
//! Run with: `cargo run --example playground_wallet`

use human_money_core::models::profile::UserIdentity;
use human_money_core::models::voucher::{Address, Collateral, ValueDefinition};
use human_money_core::services::crypto_utils;
use human_money_core::wallet::Wallet;
use human_money_core::{NewVoucherData, VoucherStatus, verify_and_parse_standard};

/// Helper function to create a deterministic UserIdentity for tests.
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

    // --- STEP 1: Setup ---
    println!("\n--- SCHRITT 1: Erstelle Identitäten, Wallet und einen initialen Gutschein ---");

    // Create identities for Alice (sender) and Bob (recipient)
    let alice_identity = create_test_identity("alice", "al");
    let bob_identity = create_test_identity("bob", "bo");
    println!(
        "✅ Identitäten für Alice ({}) und Bob ({}) erstellt.",
        alice_identity.user_id, bob_identity.user_id
    );

    // Load valid standard for the voucher
    let standard_toml = std::fs::read_to_string("voucher_standards/freetaler_v1/standard.toml")?;
    let (standard, standard_hash) = verify_and_parse_standard(&standard_toml)?;
    println!(
        "✅ Standard '{}' verifiziert und geladen.",
        standard.immutable.identity.name
    );

    // Create a new empty wallet for Alice
    let mut alice_wallet = human_money_core::test_utils::setup_in_memory_wallet(&alice_identity);

    // Create a new voucher and add it to Alice's wallet
    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()), // 5 years, corresponds to standard default
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: "1.5".to_string(),
            ..Default::default()
        }, // 1.5 Taler
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
        &alice_identity.signing_key)?;
    let local_id = Wallet::calculate_local_instance_id(&initial_voucher, &alice_identity.user_id)?;
    alice_wallet.add_voucher_instance(local_id, initial_voucher, VoucherStatus::Active);
    println!("✅ Initialen Gutschein erstellt und zu Alices Wallet hinzugefügt.");

    // --- STEP 2: Execute transaction ---
    println!("\n--- SCHRITT 2: Alice sendet 0.5 Taler an Bob ---");

    // Get local ID of voucher in Alice's wallet
    let local_instance_id = alice_wallet
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    // Create a MultiTransferRequest and invoke method
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
        None::<&dyn human_money_core::archive::VoucherArchive>, // No archive
    )?;

    println!("✅ Transaktion erfolgreich durchgeführt. Wallet-Zustand wurde aktualisiert.");

    // --- OUTPUT 1: Transfer success notice ---
    println!("\n--- AUSGABE 1: Transfer erfolgreich durchgeführt ---");
    println!(
        "Der Transfer-Bundle wurde erfolgreich erstellt und kann an den Empfänger gesendet werden."
    );

    // --- OUTPUT 2: Anonymous transaction fingerprint (raw data) ---
    println!("\n--- AUSGABE 2: Anonymer Fingerprint der Transaktion (Rohdaten) ---");
    println!(
        "Dieser Fingerprint wurde automatisch von `execute_multi_transfer_and_bundle` erzeugt und in Alices Wallet gespeichert, um Double-Spending proaktiv zu verhindern."
    );

    // Read generated fingerprint from wallet store
    let fingerprint = alice_wallet
        .own_fingerprints
        .history
        .values()
        .next() // Take first (and only) vector of fingerprints
        .and_then(|fps| fps.first()) // Take first (and only) fingerprint from vector
        .expect("Fingerprint sollte im Wallet-Store vorhanden sein.");

    // Print raw data of fingerprint
    println!("{:#?}", fingerprint);

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}
