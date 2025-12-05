// tests/persistence/archive.rs
// cargo test --test persistence_tests
//!
//! Testet die Funktionalität des `VoucherArchive`-Traits und der `FileVoucherArchive`-Implementierung.
//! Ursprünglich in `tests/test_archive.rs`.

use human_money_core::{
    archive::file_archive::FileVoucherArchive,
    models::{
        conflict::{CanonicalMetadataStore},
        profile::UserProfile,
    },
    models::voucher::{ValueDefinition}, services::voucher_manager, wallet::Wallet, VoucherStatus
};
use std::fs;
use tempfile::tempdir;

// Lade die Test-Hilfsfunktionen aus dem übergeordneten Verzeichnis.

use human_money_core::test_utils::{ACTORS, SILVER_STANDARD};

// --- Haupttest ---

#[test]
fn test_voucher_archiving_on_full_spend() {
    // 1. SETUP
    // Verwende die vordefinierten Test-Akteure aus `test_utils`.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;

    let mut alice_wallet = Wallet {
        profile: UserProfile { 
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
        },
        voucher_store: Default::default(),
        bundle_meta_store: Default::default(),
        known_fingerprints: Default::default(),
        own_fingerprints: Default::default(),
        proof_store: Default::default(),
        fingerprint_metadata: CanonicalMetadataStore::default(),
    };

    // Erstelle Alices Archiv im temporären Verzeichnis.
    let temp_dir = tempdir().unwrap();
    let archive = FileVoucherArchive::new(temp_dir.path());
    // Verwende den vordefinierten, zur Laufzeit signierten Standard.
    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    // Alice erstellt einen Gutschein und fügt ihn ihrem Wallet hinzu.
    let voucher = {
        let nominal_value = ValueDefinition {
            amount: "100.0000".to_string(), // KORREKTUR: Vier Dezimalstellen für den Silber-Standard
            unit: "".to_string(),
            abbreviation: Some("".to_string()),
            description: Some("".to_string()),
        };
        let voucher_data = voucher_manager::NewVoucherData {
            nominal_value,
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(alice_identity.user_id.clone()),
                // Fülle nur die nötigsten Felder für diesen Test.
                ..Default::default()
            },
            ..Default::default()
        };

        voucher_manager::create_voucher(voucher_data, standard, standard_hash, &alice_identity.signing_key, "en")
            .unwrap()
    };

    let voucher_id = voucher.voucher_id.clone();
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .add_voucher_instance(local_id.clone(), voucher.clone(), VoucherStatus::Active);

    // 2. AKTION
    // Alice sendet ihr GESAMTES Guthaben ("100") an Bob und übergibt dabei ihr Archiv.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "100.0000".to_string(), // KORREKTUR: Betrag muss ebenfalls das korrekte Format haben.
        }],
        notes: None,
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.metadata.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(
            &alice_identity,
            &standards,
            request,
            Some(&archive), // Das Archiv-Backend wird übergeben.
        )
        .expect("Transfer with archive should succeed.");
    
    // The new method returns only bundle bytes, not the voucher state, so we need to reconstruct
    // it from the bundle to maintain the test functionality
    let transferred_voucher_state = {
        // To get the transferred voucher state, we need to open the bundle
        let bundle_result = human_money_core::services::bundle_processor::open_and_verify_bundle(&bob_identity, &bundle_bytes).unwrap();
        bundle_result.vouchers.into_iter().next().unwrap()
    };

    // 3. VERIFIZIERUNG
    // Prüfe, ob das Archiv-System die korrekte Datei im korrekten Unterverzeichnis angelegt hat.
    let last_tx = transferred_voucher_state.transactions.last().unwrap();
    let expected_file_path = temp_dir
        .path()
        .join(&voucher_id)
        .join(format!("{}.json", &last_tx.t_id));

    assert!(expected_file_path.exists(), "Archive file was not created.");

    // Lade den Inhalt der archivierten Datei und vergleiche ihn.
    let archived_content = fs::read(expected_file_path).unwrap();
    let archived_voucher: human_money_core::models::voucher::Voucher =
        serde_json::from_slice(&archived_content).unwrap();

    // Der archivierte Gutschein muss exakt dem Zustand entsprechen, den die `create_transfer`-Funktion zurückgegeben hat.
    assert_eq!(archived_voucher, transferred_voucher_state);
}