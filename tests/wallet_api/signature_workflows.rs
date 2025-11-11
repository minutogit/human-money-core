//! # tests/wallet_api/signature_workflows.rs
//!
//! Enthält Integrationstests speziell für die Signatur-Workflows,
//! die über die `AppService`- und `Wallet`-Fassaden gesteuert werden.
//! Dies umfasst das Anfordern, Erstellen und Anhängen von Signaturen.

// Binde das `test_utils` Modul explizit über seinen Dateipfad ein.

use std::{fs, path::PathBuf};
use tempfile::tempdir;
use voucher_lib::{
    error::ValidationError, models::{
        secure_container::SecureContainer, signature::DetachedSignature, voucher::{
            Creator, VoucherSignature, NominalValue, Voucher
        }
    },
    services::{
        secure_container_manager::{self, ContainerManagerError}, voucher_manager::NewVoucherData, voucher_validation
    },
    test_utils::{
        self, add_voucher_to_wallet, create_additional_signature_data,
        create_voucher_for_manipulation, debug_open_container, generate_signed_standard_toml,
        setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD,
    },
    UserIdentity, VoucherCoreError, VoucherInstance, VoucherStatus, Wallet,
};

/// Hilfsfunktion, um einen Standard-Gutschein für Tests zu erstellen und
/// direkt in das Wallet einer Testperson zu legen.
fn setup_voucher_for_alice(
    alice_wallet: &mut Wallet,
    alice_identity: &UserIdentity,
) -> (Voucher, String) {
    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        creator: Creator {
            id: alice_identity.user_id.clone(),
            ..Default::default()
        },
        // KORREKTUR: Fehlender Betrag (verursachte InvalidAmountFormat)
        nominal_value: NominalValue {
            amount: "60".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher = create_voucher_for_manipulation(
        voucher_data,
        standard,
        standard_hash,
        &alice_identity.signing_key,
        "en",
    );
    let local_id =
        Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet
        .voucher_store
        .vouchers
        .insert(local_id.clone(), VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        });
    (voucher, local_id)
}

// --- 1. Wallet Signature Workflows ---

/// Testet den vollständigen Signatur-Workflow über die `Wallet`-Fassade.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein, der laut Standard Bürgen benötigt.
///     Die initiale Validierung schlägt daher fehl.
/// 2.  Alice erstellt eine Signaturanfrage (`SecureContainer`) und sendet sie an Bob.
/// 3.  Bob empfängt die Anfrage, öffnet den Container, extrahiert den Gutschein,
///     erstellt seine Bürgen-Signatur und sendet diese in einer Antwort zurück.
/// 4.  Alice empfängt Bobs Antwort, verarbeitet sie und fügt die Signatur
///     an ihren Gutschein an.
/// 5.  Die finale Verifizierung zeigt, dass der Gutschein nun eine Signatur hat,
///     aber die Validierung immer noch fehlschlägt, weil die *Anzahl* der
///     benötigten Bürgen nicht erfüllt ist.
#[test]
fn api_wallet_full_signature_workflow() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let temp_dir = tempdir().expect("Failed to create temporary directory");

    let (voucher, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    assert!(voucher_validation::validate_voucher_against_standard(&voucher, minuto_standard)
        .is_err());

    let request_container_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, &bob.identity.user_id)
        .unwrap();
    let request_file_path: PathBuf = temp_dir.path().join("request.secure");
    fs::write(&request_file_path, request_container_bytes).unwrap();

    let received_request_bytes = fs::read(&request_file_path).unwrap();
    let container: SecureContainer = serde_json::from_slice(&received_request_bytes).unwrap();
    let decrypted_payload = secure_container_manager::open_secure_container(&container, &bob.identity).unwrap();
    let voucher_from_alice: Voucher = serde_json::from_slice(&decrypted_payload).unwrap();

    let guarantor_metadata = VoucherSignature {
        voucher_id: voucher_from_alice.voucher_id.clone(),
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_container_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_from_alice,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            &alice.identity.user_id,
        )
        .unwrap();
    let response_file_path: PathBuf = temp_dir.path().join("response.secure");
    fs::write(&response_file_path, response_container_bytes).unwrap();

    let received_response_bytes = fs::read(&response_file_path).unwrap();
    alice_wallet
        .process_and_attach_signature(&alice.identity, &received_response_bytes)
        .unwrap();

    let instance = alice_wallet.voucher_store.vouchers.get(&local_id).unwrap();
    assert_eq!(instance.voucher.signatures.len(), 1);
    assert_eq!(instance.voucher.signatures[0].signer_id, bob.user_id);
    // Prüfe, ob die verschachtelten Details (via `include_details: true`) vorhanden sind
    // (Das Wallet-Profil von Bob ist leer, daher sind die Felder None)
    assert!(instance.voucher.signatures[0].details.is_some());

    let validation_result = voucher_validation::validate_voucher_against_standard(&instance.voucher, minuto_standard);
    dbg!(&validation_result);

    assert!(matches!(
        voucher_validation::validate_voucher_against_standard(&instance.voucher, minuto_standard).unwrap_err(),
        // KORREKTUR: Die Assertion war veraltet. Der Minuto-Standard validiert
        // basierend auf `gender`, nicht `role`.
        // Bob hat eine Signatur mit `gender: None` (via Default) hinzugefügt.
        // Die erste Regel (`gender="1"`) schlägt fehl (erwartet 1, gefunden 0).
        VoucherCoreError::Validation(ValidationError::FieldValueCountOutOfBounds { path, field, value, min: 1, max: 1, found: 0 })
        if path == "signatures" && field == "details.gender" && value == "1"
    ));
}

/// Stellt sicher, dass ein `SecureContainer` nicht von einem falschen Empfänger geöffnet werden kann.
///
/// ### Szenario:
/// 1.  Alice erstellt eine Signaturanfrage, die explizit an Bob adressiert ist.
/// 2.  Eve (eine dritte Partei) fängt die Anfrage ab und versucht, sie zu öffnen.
/// 3.  Der Versuch schlägt mit `NotAnIntendedRecipient` fehl.
#[test]
fn api_wallet_signature_fail_wrong_recipient() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let eve = &ACTORS.hacker;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, &bob.identity.user_id)
        .unwrap();

    let container: SecureContainer = serde_json::from_slice(&request_bytes).unwrap();
    let result = secure_container_manager::open_secure_container(&container, &eve.identity);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)
    ));
}

/// Stellt sicher, dass ein manipulierter `SecureContainer` abgewiesen wird.
///
/// ### Szenario:
/// 1.  Bob erstellt eine gültige Signatur-Antwort für Alice.
/// 2.  Ein Angreifer manipuliert ein Byte im verschlüsselten Payload des Containers.
/// 3.  Alice versucht, die manipulierte Antwort zu verarbeiten.
/// 4.  Der Prozess schlägt fehl, weil die Entschlüsselung aufgrund des
///     Authentifizierungsfehlers (AEAD) fehlschlägt.
#[test]
fn api_wallet_signature_fail_tampered_container() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (voucher, _) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let guarantor_metadata = VoucherSignature {
        voucher_id: voucher.voucher_id.clone(),
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            &alice.identity.user_id,
        )
        .unwrap();

    let mut container: SecureContainer = serde_json::from_slice(&response_bytes).unwrap();

    // Manipuliere den Base64-String des Payloads, um einen AEAD-Fehler zu provozieren.
    let mut chars: Vec<char> = container.p.chars().collect();
    if chars.len() > 10 {
        // Tausche ein Zeichen aus, um die Signatur ungültig zu machen.
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    }
    container.p = chars.into_iter().collect();
    let tampered_bytes = serde_json::to_vec(&container).unwrap();

    let result = alice_wallet.process_and_attach_signature(&alice.identity, &tampered_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::SymmetricEncryption(_)
    ));
}

/// Stellt sicher, dass eine Signatur für einen unbekannten Gutschein abgewiesen wird.
///
/// ### Szenario:
/// 1.  Alice hat Gutschein A in ihrem Wallet. Sie hat auch Gutschein B erstellt,
///     ihn aber nicht in ihr Wallet gelegt.
/// 2.  Bob soll Gutschein A signieren, erstellt aber fälschlicherweise eine Signatur,
///     die sich auf die ID von Gutschein B bezieht.
/// 3.  Alice versucht, diese Signatur zu verarbeiten.
/// 4.  Der Prozess schlägt mit `VoucherNotFound` fehl, da ihr Wallet den Gutschein
///     mit der ID von B nicht kennt, an den die Signatur angehängt werden soll.
#[test]
fn api_wallet_signature_fail_mismatched_voucher_id() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (_voucher_a, _) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let voucher_data_b = NewVoucherData {
        creator: Creator {
            id: alice.user_id.clone(),
            ..Default::default()
        },
        nominal_value: NominalValue {
            amount: "120".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P3Y".to_string()),
        ..Default::default()
    };
    let (minuto_standard, minuto_standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_b = create_voucher_for_manipulation(
        voucher_data_b,
        minuto_standard,
        minuto_standard_hash,
        &alice.identity.signing_key,
        "en",
    );

    let guarantor_metadata = VoucherSignature {
        voucher_id: voucher_b.voucher_id.clone(), // Falsche ID!
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_b,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            &alice.identity.user_id,
        )
        .unwrap();

    let result = alice_wallet.process_and_attach_signature(&alice.identity, &response_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherNotFound(_)
    ));
}

/// Stellt sicher, dass die Verarbeitung fehlschlägt, wenn der Payload-Typ nicht erwartet wird.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Container vom Typ `VoucherForSigning`.
/// 2.  Sie versucht, diesen Container mit der Funktion `process_and_attach_signature`
///     zu verarbeiten, die einen Payload vom Typ `DetachedSignature` erwartet.
/// 3.  Der Prozess schlägt mit `InvalidPayloadType` fehl.
#[test]
fn api_wallet_signature_fail_wrong_payload_type() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let request_container_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, &alice.identity.user_id)
        .unwrap();

    let result =
        alice_wallet.process_and_attach_signature(&alice.identity, &request_container_bytes);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::InvalidPayloadType
    ));
}

// --- 2. AppService Signature Workflows ---

/// Testet den vollständigen Signatur-Workflow über die `AppService`-Fassade.
///
/// ### Szenario:
/// 1.  Zwei `AppService`-Instanzen für einen Ersteller und einen Bürgen werden eingerichtet.
/// 2.  Der Ersteller legt einen Gutschein an.
/// 3.  Der Ersteller fordert eine Signatur vom Bürgen an.
/// 4.  Der Bürge empfängt die Anfrage, erstellt eine `AdditionalSignature`
///     (passend zum Silber-Standard) und sendet sie zurück.
/// 5.  Der Ersteller empfängt die Antwort und fügt die Signatur erfolgreich an.
/// 6.  Die Details des Gutscheins zeigen die neue Signatur an.
#[test]
fn api_app_service_full_signature_workflow() {
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let dir_creator = tempdir().unwrap();
    let dir_guarantor = tempdir().unwrap();
    let password = "sig-password";

    let creator = &ACTORS.alice;
    let guarantor = &ACTORS.guarantor1;
    let (mut service_creator, _) = test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", password);
    let (mut service_guarantor, profile_guarantor) = test_utils::setup_service_with_profile(dir_guarantor.path(), guarantor, "Guarantor", password);
    let id_guarantor = service_guarantor.get_user_id().unwrap();

    let _voucher = service_creator.create_new_voucher(
        &silver_standard_toml,
        "en",
        NewVoucherData {
            creator: Creator {
                id: service_creator.get_user_id().unwrap(),
                ..Default::default()
            },
            nominal_value: NominalValue {
                amount: "50".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        password,
    )
        .unwrap();
    let local_id = service_creator.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();

    let request_bytes = service_creator
        .create_signing_request_bundle(&local_id, &id_guarantor)
        .unwrap();

    let voucher_to_sign = {
        service_guarantor.login(&profile_guarantor.folder_name, password, false).unwrap();
        let guarantor_identity = service_guarantor.get_unlocked_mut_for_test().1;
        // Der Sender (creator) ist bekannt, wir brauchen ihn nicht aus dem Container.
        debug_open_container(&request_bytes, guarantor_identity).unwrap()
    };
    let _signature_data = create_additional_signature_data(
        service_guarantor.get_unlocked_mut_for_test().1,
        &voucher_to_sign.voucher_id,
        "Verified by external party.",
    );

    let response_bytes = service_guarantor
        .create_detached_signature_response_bundle(
            &voucher_to_sign,
            "notary", // Role (basierend auf `create_additional_signature_data`)
            true,     // include_details
            &service_creator.get_user_id().unwrap()
        )
        .unwrap();

    service_creator
        .process_and_attach_signature(&response_bytes, &silver_standard_toml, password)
        .unwrap();

    let details = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(details.voucher.signatures.len(), 1);
    assert_eq!(
        details.voucher.signatures.iter().find(|s| s.role != "guarantor").unwrap().signer_id,
        id_guarantor,
    );
}

/// Testet den Signatur-Roundtrip für einen Standard, der Signaturen erfordert (Minuto).
///
/// ### Szenario:
/// 1.  Alice erstellt einen Minuto-Gutschein, der ohne Bürgen ungültig ist.
/// 2.  Sie fordert eine Signatur von Bob an.
/// 3.  Bob empfängt die Anfrage, erstellt eine `GuarantorSignature` und sendet
///     diese in einer verschlüsselten Antwort zurück.
/// 4.  Alice empfängt die Antwort und fügt die Signatur an ihren Gutschein an.
/// 5.  Der Gutschein hat danach eine Signatur von Bob.
#[test]
fn api_wallet_signature_roundtrip_minuto_required() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity); // Bobs Wallet für die Antwort
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Erstelle einen Minuto-Gutschein, der noch Bürgen braucht. `false` = nicht valide erstellen.
    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", minuto_standard, false)
            .unwrap();

    // Alice erstellt eine Signaturanfrage für Bob
    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &voucher_id, &bob.identity.user_id)
        .unwrap();

    // Bob verarbeitet die Anfrage und erstellt eine Antwort
    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    // Bob erstellt seine Signatur-Daten (als Enum)
    let mut signature_data_enum =
        test_utils::create_guarantor_signature_data(&bob.identity, "1", &voucher_for_signing.voucher_id);
    // Wir modifizieren die innere Struktur via Pattern Matching
    let DetachedSignature::Signature(guarantor_struct) = &mut signature_data_enum;
    assert_eq!(guarantor_struct.role, "guarantor");
    // Das Setzen von `first_name` etc. ist nicht mehr nötig, da `create_detached_signature_response`
    // die `details` (PublicProfile) aus dem Wallet (hier Bob) automatisch einfügt.
    // Wir müssen Bobs Wallet-Profil füllen, damit die Details ankommen.
    bob_wallet.profile.first_name = Some("Bob".to_string());
    bob_wallet.profile.last_name = Some("Builder".to_string());

    // Bob erstellt die verschlüsselte Antwort mit der Signatur
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity, &voucher_for_signing, signature_data_enum, true, &alice.identity.user_id
        )
        .unwrap();

    // Alice verarbeitet die Signatur-Antwort
    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes)
        .unwrap();

    // Assert: Der Gutschein hat jetzt genau eine Signatur von Bob
    let final_instance = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_instance.voucher.signatures.len(), 1);
    assert_eq!(
        final_instance.voucher.signatures[0].signer_id, bob.identity.user_id
    );
    // Prüfe die verschachtelten Details
    let details = final_instance.voucher.signatures[0].details.as_ref().unwrap();
    assert_eq!(details.first_name.as_deref(), Some("Bob"));
    assert_eq!(details.last_name.as_deref(), Some("Builder"));
}

/// Testet den vollständigen Bürgen-Workflow über die `AppService`-Fassade,
/// insbesondere den Statusübergang von `Incomplete` zu `Active`.
///
/// ### Szenario:
/// 1.  Ein Ersteller und zwei Bürgen werden als separate `AppService`-Instanzen initialisiert.
/// 2.  Der Ersteller erstellt einen neuen Gutschein nach dem Minuto-Standard, der
///     zwei Bürgen erfordert.
/// 3.  **Assertion 1:** Der Gutschein hat initial den Status `Incomplete`.
/// 4.  Der Ersteller fordert Signaturen von beiden Bürgen an und fügt diese nacheinander an.
/// 5.  **Assertion 2:** Nach dem Anfügen der ersten Signatur ist der Status immer
///     noch `Incomplete`, aber mit einer aktualisierten Begründung.
/// 6.  **Assertion 3:** Nach dem Anfügen der zweiten (und letzten benötigten) Signatur
///     wechselt der Status des Gutscheins zu `Active`.
#[test]
fn test_full_guarantor_workflow_via_app_service() {
    // --- 1. Setup: Drei separate Benutzer simulieren ---
    let dir_creator = tempdir().expect("Failed to create temp dir for creator");
    let dir_g1 = tempdir().expect("Failed to create temp dir for guarantor1");
    let dir_g2 = tempdir().expect("Failed to create temp dir for guarantor2");
    let password = "password123";

    let minuto_standard_toml =
        generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");

    // Creator Service
    let creator = &ACTORS.alice;
    let (mut service_creator, _) = test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", password);
    let creator_id = service_creator.get_user_id().unwrap();
    let (service_g1, _) = test_utils::setup_service_with_profile(dir_g1.path(), &ACTORS.male_guarantor, "Male Guarantor", password);
    let g1_id = service_g1.get_user_id().unwrap();
    let (service_g2, _) = test_utils::setup_service_with_profile(dir_g2.path(), &ACTORS.female_guarantor, "Female Guarantor", password);
    let g2_id = service_g2.get_user_id().unwrap();

    // --- 2. Schritt 1: Erstellung des unvollständigen Gutscheins ---
    // RUFE NUN DIE KORRIGIERTE API-FUNKTION AUF
    let voucher_data = NewVoucherData {
        creator: Creator {
            id: creator_id.clone(),
            ..Default::default()
        },
        nominal_value: NominalValue {
            amount: "60".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P3Y".to_string()),
        ..Default::default()
    };

    // Diese Funktion sollte dank des Patches in `command_handler.rs` jetzt
    // einen `Incomplete` Gutschein korrekt erstellen, anstatt zu paniken.
    let _created_voucher = service_creator.create_new_voucher(
        &minuto_standard_toml,
        "en",
        voucher_data,
        password
    ).expect("create_new_voucher should now succeed for incomplete vouchers");

    let summary = service_creator.get_voucher_summaries(None, None).expect("Failed to get summaries").pop().expect("Wallet should contain one voucher");
    let local_id = summary.local_instance_id;

    // --- 3. Assertion 1: Status ist `Incomplete` ---
    let details_before = service_creator
        .get_voucher_details(&local_id)
        .expect("Should find voucher details");
    assert!(matches!(details_before.status, VoucherStatus::Incomplete { .. }));

    // --- 4. Schritt 2: Simulieren des Signaturprozesses ---

    // --- Signatur von Bürge 1 ---
    let _request_bundle_1 = service_creator
        .create_signing_request_bundle(&local_id, &g1_id)
        .expect("Failed to create signing request for G1");
    // Hinweis: In der neuen Struktur setzt create_detached_signature_response_bundle
    // die Details nur, wenn include_details=true und der AppService das unterstützt.
    // Hier müssen wir direkt eine Signatur mit Details erstellen.
    let response_bundle_1 = service_g1
        .create_detached_signature_response_bundle(
            &details_before.voucher,
            "guarantor",
            true, // include_details
            &service_creator.get_user_id().unwrap(),
        )
        .expect("Failed to create signature response from G1");
    service_creator
        .process_and_attach_signature(&response_bundle_1, &minuto_standard_toml, password)
        .expect("Failed to attach G1's signature");
    let details_mid = service_creator.get_voucher_details(&local_id).unwrap();
    assert!(matches!(details_mid.status, VoucherStatus::Incomplete { .. }));

    // --- Signatur von Bürge 2 ---
    let _request_bundle_2 = service_creator
        .create_signing_request_bundle(&local_id, &g2_id)
        .expect("Failed to create signing request for G2");
    // Hinweis: In der neuen Struktur setzt create_detached_signature_response_bundle
    // die Details nur, wenn include_details=true und der AppService das unterstützt.
    let response_bundle_2 = service_g2
        .create_detached_signature_response_bundle(
            &details_mid.voucher,
            "guarantor",
            true, // include_details
            &service_creator.get_user_id().unwrap(),
        )
        .expect("Failed to create signature response from G2");
    service_creator
        .process_and_attach_signature(&response_bundle_2, &minuto_standard_toml, password)
        .expect("Failed to attach G2's signature");

    // --- 5. Assertion 3: Überprüfung des finalen `Active`-Zustands ---
    let details_after = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_after.status,
        VoucherStatus::Active,
        "Final voucher status should be Active"
    );
    // Überprüfe die verschachtelten Gender-Daten
    assert_eq!(
        details_after.voucher.signatures[0].details.as_ref().unwrap().gender.as_deref(),
        Some("1")
    );
}

/// Testet den Signatur-Roundtrip für einen Standard mit optionalen Signaturen (Silber).
///
/// ### Szenario:
/// 1.  Alice erstellt einen Silber-Gutschein, der initial gültig ist, da `needed_guarantors = 0`.
/// 2.  Sie fordert trotzdem eine optionale Signatur von Bob an.
/// 3.  Bob empfängt und beantwortet die Anfrage.
/// 4.  Alice fügt die optionale Signatur erfolgreich an.
/// 5.  Der Gutschein hat danach eine Signatur, obwohl sie nicht erforderlich war.
#[test]
fn api_wallet_signature_roundtrip_silver_optional() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let voucher_id =
        add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "10", silver_standard, false)
            .unwrap();

    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &voucher_id, &bob.identity.user_id)
        .unwrap();

    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    let mut signature_data_enum =
        test_utils::create_guarantor_signature_data(&bob.identity, "1" , &voucher_for_signing.voucher_id);
    let DetachedSignature::Signature(guarantor_struct) = &mut signature_data_enum;
    assert_eq!(guarantor_struct.role, "guarantor");
    // Das Setzen von `first_name` etc. ist nicht mehr nötig, da `create_detached_signature_response`
    // die `details` (PublicProfile) aus dem Wallet (hier Bob) automatisch einfügt.

    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_for_signing,
            signature_data_enum,
            false, // include_details
            &alice.identity.user_id,
        )
        .unwrap();

    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes)
        .unwrap();

    let final_instance = alice_wallet.voucher_store.vouchers.get(&voucher_id).unwrap();
    assert_eq!(final_instance.voucher.signatures.len(), 1);
    // Details sollten `None` sein, da `include_details: false`
    assert!(final_instance.voucher.signatures[0].details.is_none());
}