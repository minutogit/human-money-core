// examples/playground_voucher_lifecycle.rs
// run with: cargo run --example playground_voucher_lifecycle
//!
//!
//! Demonstriert den gesamten Lebenszyklus eines Gutscheins unter Verwendung der
//! High-Level `AppService`-Fassade, so wie es eine echte Client-Anwendung tun würde.
//!
//! ### Simulierte Schritte:
//! 1.  **Setup:** Erstellt separate `AppService`-Instanzen für alle Teilnehmer (Ersteller, 2 Bürgen, Empfänger).
//! 2.  **Gutschein-Erstellung:** Der Ersteller legt einen neuen Gutschein an, der initial unvollständig ist.
//! 3.  **Bürgen-Workflow (asynchron):**
//!     - Ersteller sendet eine Signaturanfrage an Bürge 1.
//!     - Bürge 1 signiert und sendet die Signatur zurück.
//!     - Ersteller fügt die Signatur an. Der Gutschein ist immer noch unvollständig.
//!     - Der Prozess wird für Bürge 2 wiederholt.
//! 4.  **Aktivierung:** Nach Erhalt der zweiten Signatur wird der Gutschein automatisch `Active`.
//! 5.  **Transfer:** Der Ersteller sendet einen Teilbetrag an einen Empfänger.
//! 6.  **Verifizierung:** Die neuen Kontostände werden bei beiden Teilnehmern geprüft.
//! 7.  **Rohdaten-Ausgabe:** Der finale Zustand des Gutscheins wird als JSON ausgegeben.

use human_money_core::app_service::AppService;
use human_money_core::models::secure_container::{ContainerConfig, PrivacyMode};
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::{NewVoucherData, VoucherStatus, verify_and_parse_standard};
use human_money_core::MnemonicLanguage;
use std::collections::HashMap;
use tempfile::tempdir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- VOUCHER LIFECYCLE PLAYGROUND (AppService API) ---");

    // --- 1. SETUP: Erstelle Services für alle Teilnehmer ---
    let dir_creator = tempdir()?;
    let dir_g1 = tempdir()?;
    let dir_g2 = tempdir()?;
    let dir_recipient = tempdir()?;
    let dir_charlie = tempdir()?;
    let password = "password123";

    let mut service_creator = AppService::new(dir_creator.path())?;
    let mut service_g1 = AppService::new(dir_g1.path())?;
    let mut service_g2 = AppService::new(dir_g2.path())?;
    let mut service_recipient = AppService::new(dir_recipient.path())?;
    let mut service_charlie = AppService::new(dir_charlie.path())?;

    // Erstelle Profile für alle Teilnehmer
    service_creator.create_profile(
        "Creator",
        &AppService::generate_mnemonic(12, MnemonicLanguage::English)?,
        Some("Test".into()),
        Some("creator"),
        password,
        MnemonicLanguage::English,
        "example-id".to_string(),
    )?;
    service_g1.create_profile(
        "Guarantor 1",
        &AppService::generate_mnemonic(12, MnemonicLanguage::English)?,
        Some("Test".into()),
        Some("g1"),
        password,
        MnemonicLanguage::English,
        "example-id".to_string(),
    )?;
    service_g2.create_profile(
        "Guarantor 2",
        &AppService::generate_mnemonic(12, MnemonicLanguage::English)?,
        Some("Test".into()),
        Some("g2"),
        password,
        MnemonicLanguage::English,
        "example-id".to_string(),
    )?;
    service_recipient.create_profile(
        "Recipient",
        &AppService::generate_mnemonic(12, MnemonicLanguage::English)?,
        Some("Test".into()),
        Some("rcp"),
        password,
        MnemonicLanguage::English,
        "example-id".to_string(),
    )?;
    service_charlie.create_profile(
        "Charlie",
        &AppService::generate_mnemonic(12, MnemonicLanguage::English)?,
        Some("Test".into()),
        Some("charlie"),
        password,
        MnemonicLanguage::English,
        "example-id".to_string(),
    )?;

    let g1_id = service_g1.get_user_id()?;
    let g2_id = service_g2.get_user_id()?;

    // Erstellen einer vollständigen Address-Struktur für Bürge 1
    let g1_address = human_money_core::models::voucher::Address {
        street: "Bürgenstraße".to_string(),
        house_number: "789".to_string(),
        zip_code: "98765".to_string(),
        city: "Bürgenstadt".to_string(),
        country: "Deutschland".to_string(),
        full_address: "Bürgenstraße 789, 98765 Bürgenstadt, Deutschland".to_string(),
    };

    // Erstellen eines vollständigen PublicProfile für Bürge 1 mit Beispielwerten
    let g1_profile = human_money_core::models::profile::PublicProfile {
        protocol_version: Some("v1".to_string()),
        id: Some(g1_id.clone()),
        first_name: Some("Max".to_string()),
        last_name: Some("Bürger".to_string()),
        organization: Some("Bürgschaft GmbH".to_string()),
        community: Some("Bürgergemeinschaft Musterstadt".to_string()),
        address: Some(g1_address),
        gender: Some("1".to_string()), // ISO 5218: 1 = male
        email: Some("max@buergen.de".to_string()),
        phone: Some("+49 123 987654".to_string()),
        coordinates: Some("50.1109, 8.6821".to_string()), // Frankfurt
        url: Some("https://www.buergen.de".to_string()),
        service_offer: None,
        needs: None,
        picture_url: None,
    };

    // Aktualisieren des Profils für Bürge 1
    {
        let (wallet, _identity) = service_g1.get_unlocked_mut_for_test();
        wallet.profile.first_name = g1_profile.first_name.clone();
        wallet.profile.last_name = g1_profile.last_name.clone();
        wallet.profile.organization = g1_profile.organization.clone();
        wallet.profile.community = g1_profile.community.clone();
        wallet.profile.address = g1_profile.address.clone();
        wallet.profile.gender = g1_profile.gender.clone();
        wallet.profile.email = g1_profile.email.clone();
        wallet.profile.phone = g1_profile.phone.clone();
        wallet.profile.coordinates = g1_profile.coordinates.clone();
        wallet.profile.url = g1_profile.url.clone();
    }

    // Erstellen einer vollständigen Address-Struktur für Bürge 2
    let g2_address = human_money_core::models::voucher::Address {
        street: "Bürgenstraße".to_string(),
        house_number: "456".to_string(),
        zip_code: "54321".to_string(),
        city: "Bürgenstadt".to_string(),
        country: "Deutschland".to_string(),
        full_address: "Bürgenstraße 456, 54321 Bürgenstadt, Deutschland".to_string(),
    };

    // Erstellen eines vollständigen PublicProfile für Bürge 2 mit Beispielwerten
    let g2_profile = human_money_core::models::profile::PublicProfile {
        protocol_version: Some("v1".to_string()),
        id: Some(g2_id.clone()),
        first_name: Some("Erika".to_string()),
        last_name: Some("Bürgin".to_string()),
        organization: Some("Bürgschaft GmbH".to_string()),
        community: Some("Bürgergemeinschaft Musterstadt".to_string()),
        address: Some(g2_address),
        gender: Some("2".to_string()), // ISO 5218: 2 = female
        email: Some("erika@buergin.de".to_string()),
        phone: Some("+49 987 654321".to_string()),
        coordinates: Some("48.1351, 11.5820".to_string()), // München
        url: Some("https://www.buergin.de".to_string()),
        service_offer: None,
        needs: None,
        picture_url: None,
    };

    // Aktualisieren des Profils für Bürge 2
    {
        let (wallet, _identity) = service_g2.get_unlocked_mut_for_test();
        wallet.profile.first_name = g2_profile.first_name.clone();
        wallet.profile.last_name = g2_profile.last_name.clone();
        wallet.profile.organization = g2_profile.organization.clone();
        wallet.profile.community = g2_profile.community.clone();
        wallet.profile.address = g2_profile.address.clone();
        wallet.profile.gender = g2_profile.gender.clone();
        wallet.profile.email = g2_profile.email.clone();
        wallet.profile.phone = g2_profile.phone.clone();
        wallet.profile.coordinates = g2_profile.coordinates.clone();
        wallet.profile.url = g2_profile.url.clone();
    }

    let creator_id = service_creator.get_user_id()?;
    let g1_id = service_g1.get_user_id()?;
    let g2_id = service_g2.get_user_id()?;
    let recipient_id = service_recipient.get_user_id()?;
    let charlie_id = service_charlie.get_user_id()?;
    println!("\n✅ Profile für Ersteller, 2 Bürgen und Empfänger erstellt.");

    // Lade den Minuto-Standard
    let standard_toml = std::fs::read_to_string("voucher_standards/minuto_v1/standard.toml")?;
    let (standard, _) = verify_and_parse_standard(&standard_toml)?;

    // --- 2. Gutschein-Erstellung durch den Ersteller ---
    println!("\n--- SCHRITT 2: Ersteller legt einen neuen (unvollständigen) Gutschein an ---");

    // Erstellen einer vollständigen Address-Struktur mit Beispielwerten
    let address = human_money_core::models::voucher::Address {
        street: "Musterstraße".to_string(),
        house_number: "123".to_string(),
        zip_code: "12345".to_string(),
        city: "Musterstadt".to_string(),
        country: "Deutschland".to_string(),
        full_address: "Musterstraße 123, 12345 Musterstadt, Deutschland".to_string(),
    };

    // Erstellen eines vollständigen PublicProfile mit Beispielwerten
    let complete_creator_profile = human_money_core::models::profile::PublicProfile {
        protocol_version: Some("v1".to_string()),
        id: Some(creator_id.clone()),
        first_name: Some("Max".to_string()),
        last_name: Some("Mustermann".to_string()),
        organization: Some("Musterfirma GmbH".to_string()),
        community: Some("Bürgergemeinschaft Musterstadt".to_string()),
        address: Some(address),
        gender: Some("2".to_string()), // ISO 5218: 2 = female
        email: Some("max@mustermann.de".to_string()),
        phone: Some("+49 123 456789".to_string()),
        coordinates: Some("52.5200, 13.4050".to_string()), // Berlin
        url: Some("https://www.mustermann.de".to_string()),
        service_offer: Some("Biete Webdesign und Beratung".to_string()),
        needs: Some("Suche Minuto-Gutscheine".to_string()),
        picture_url: None,
    };

    let voucher_data = NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        nominal_value: ValueDefinition {
            unit: "Minuto".to_string(),
            amount: "60".to_string(),
            abbreviation: Some("m".to_string()),
            description: Some("Objektive Zeit".to_string()),
        },
        creator_profile: complete_creator_profile,
        ..Default::default()
    };
    service_creator.unlock_session(password, 60).unwrap();
    let created_voucher =
        service_creator.create_new_voucher(&standard_toml, "de", voucher_data, None)?;

    let summary = service_creator
        .get_voucher_summaries(None, None)?
        .pop()
        .unwrap();
    let local_id = summary.local_instance_id;
    println!(
        "✅ Gutschein '{}' erstellt. Status: {:?}",
        created_voucher.voucher_id, summary.status
    );
    assert!(matches!(summary.status, VoucherStatus::Incomplete { .. }));

    // --- 3. Bürgen-Workflow ---
    println!("\n--- SCHRITT 3: Asynchroner Bürgen-Workflow ---");

    // **Teil A: Bürge 1**
    println!("\n  -> Ersteller sendet Signaturanfrage an Bürge 1...");
    let _request_bundle_to_g1 = service_creator.create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(g1_id.clone(), PrivacyMode::TrialDecryption))?;
    // In einer echten App würde `request_bundle_to_g1` nun z.B. via QR-Code übertragen.

    println!("  -> Bürge 1 empfängt die Anfrage, signiert und sendet die Signatur zurück...");
    // Der Bürge muss den Gutschein aus dem Bundle extrahieren, um ihn zu signieren.
    // In einer echten App würde die App des Bürgen das Bundle öffnen. Hier simulieren wir das.
    let response_bundle_from_g1 = service_g1.create_detached_signature_response_bundle(
        &created_voucher,
        "guarantor",
        true,
        ContainerConfig::TargetDid(creator_id.clone(), PrivacyMode::TrialDecryption),
        Some(password),
    )?;

    println!("  -> Ersteller empfängt die Signatur von Bürge 1 und fügt sie an...");
    service_creator.process_and_attach_signature(
        &response_bundle_from_g1,
        &standard_toml,
        None,
        Some(password),
    )?;
    let details_after_g1 = service_creator.get_voucher_details(&local_id)?;
    println!(
        "     -> Status nach 1. Signatur: {:?}",
        details_after_g1.status
    );
    assert!(matches!(
        details_after_g1.status,
        VoucherStatus::Incomplete { .. }
    ));

    // **Teil B: Bürge 2**
    println!("\n  -> Ersteller sendet Signaturanfrage an Bürge 2...");
    let _request_bundle_to_g2 = service_creator.create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(g2_id.clone(), PrivacyMode::TrialDecryption))?;

    println!("  -> Bürge 2 empfängt, signiert und sendet zurück...");
    let response_bundle_from_g2 = service_g2.create_detached_signature_response_bundle(
        &created_voucher,
        "guarantor",
        true,
        ContainerConfig::TargetDid(creator_id.clone(), PrivacyMode::TrialDecryption),
        Some(password),
    )?;

    println!("  -> Ersteller empfängt die Signatur von Bürge 2 und fügt sie an...");
    service_creator.process_and_attach_signature(
        &response_bundle_from_g2,
        &standard_toml,
        None,
        Some(password),
    )?;

    // --- 4. Aktivierung des Gutscheins ---
    println!("\n--- SCHRITT 4: Gutschein wird automatisch aktiviert ---");
    let final_details = service_creator.get_voucher_details(&local_id)?;
    println!(
        "✅ Gutschein ist nach Erhalt der 2. Signatur vollständig und wurde automatisch aktiviert."
    );
    println!("   -> Finaler Status: {:?}", final_details.status);
    assert!(matches!(final_details.status, VoucherStatus::Active));

    // --- 5. Transfer eines Teilbetrags ---
    println!("\n--- SCHRITT 5: Ersteller sendet 25 Minuto an den Empfänger ---");
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), standard_toml.clone());

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: recipient_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "25".to_string(),
        }],
        notes: Some("Viel Spaß!".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(standard.immutable.identity.uuid.clone(), standard_toml.clone());
    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: transfer_bundle,
        ..
    } = service_creator.create_transfer_bundle(request, &standards_toml, None, Some(password))?;

    // --- 6. Verifizierung der Kontostände ---
    println!("\n--- SCHRITT 6: Empfänger erhält das Bundle und Kontostände werden geprüft ---");
    service_recipient.receive_bundle(&transfer_bundle, &standards_map, None, Some(password), false)?;

    let balance_creator = service_creator.get_total_balance_by_currency()?;
    let balance_recipient = service_recipient.get_total_balance_by_currency()?;

    println!("   -> Kontostand Ersteller: {:?}", balance_creator);
    println!("   -> Kontostand Empfänger: {:?}", balance_recipient);

    // KORREKTUR: Suchen Sie den Saldo im Vec<AggregatedBalance> anhand der Einheit.
    let creator_balance_str = balance_creator
        .iter()
        .find(|b| b.unit == "m") // Suchen nach Abkürzung 'm', nicht 'Minuto'
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    let recipient_balance_str = balance_recipient
        .iter()
        .find(|b| b.unit == "m") // Suchen nach Abkürzung 'm', nicht 'Minuto'
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    assert_eq!(creator_balance_str, "35");
    assert_eq!(recipient_balance_str, "25");

    // --- SCHRITT 7: Zweiter Transfer in der Kette ---
    println!("\n--- SCHRITT 7: Empfänger sendet 10 Minuto an einen neuen Teilnehmer (Charlie) ---");

    // Finde die local_id des Gutscheins im Wallet des ersten Empfängers
    let recipient_summary = service_recipient
        .get_voucher_summaries(None, None)?
        .pop()
        .unwrap();
    let recipient_local_id = recipient_summary.local_instance_id;

    // Der erste Empfänger erstellt jetzt das Transfer-Bundle für Charlie
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: charlie_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: recipient_local_id.clone(),
            amount_to_send: "25".to_string(), // (ÄNDERUNG) Sende den vollen Restbetrag
        }],
        notes: Some("Weitergereicht!".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(standard.immutable.identity.uuid.clone(), standard_toml.clone());
    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: transfer_bundle_to_charlie,
        ..
    } = service_recipient.create_transfer_bundle(request, &standards_toml, None, Some(password))?;

    // Charlie empfängt das Bundle
    service_charlie.receive_bundle(
        &transfer_bundle_to_charlie,
        &standards_map,
        None,
        Some(password),
        false,
    )?;

    // Überprüfe die finalen Kontostände
    let balance_recipient_after_send = service_recipient.get_total_balance_by_currency()?;
    let balance_charlie = service_charlie.get_total_balance_by_currency()?;
    println!(
        "   -> Kontostand Empfänger (jetzt Sender): {:?}",
        balance_recipient_after_send
    );
    println!(
        "   -> Kontostand Charlie (neuer Empfänger): {:?}",
        balance_charlie
    );

    // KORREKTUR: Suchen Sie den Saldo im Vec<AggregatedBalance> anhand der Einheit.
    let recipient_has_balance = balance_recipient_after_send.iter().any(|b| b.unit == "m");
    let charlie_balance_str = balance_charlie
        .iter()
        .find(|b| b.unit == "m") // Suchen nach Abkürzung 'm', nicht 'Minuto'
        .map(|b| b.total_amount.as_str())
        .unwrap_or("0");
    assert!(
        !recipient_has_balance,
        "Nach einem vollen Transfer sollte der Sender keinen Minuto-Saldo mehr haben."
    );
    assert_eq!(charlie_balance_str, "25");

    // --- 8. Finale Rohdaten-Ausgabe ---
    println!("\n--- SCHRITT 8: Finale Rohdaten-Ausgabe des Gutscheins bei Charlie ---");
    let charlie_summary = service_charlie
        .get_voucher_summaries(None, None)?
        .pop()
        .unwrap();
    let charlie_voucher_details =
        service_charlie.get_voucher_details(&charlie_summary.local_instance_id)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&charlie_voucher_details.voucher)?
    );

    println!("\n--- PLAYGROUND BEENDET ---");
    Ok(())
}
