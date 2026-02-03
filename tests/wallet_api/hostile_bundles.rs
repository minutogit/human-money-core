// tests/wallet_api/hostile_bundles.rs
// cargo test --test wallet_api_tests
//!
// HINWEIS: Tests 2.1 und 2.2 wurden auf die öffentliche `AppService::create_new_voucher` API umgestellt.
//! Enthält Tests, die den `AppService` gegen den Empfang von feindseligen,
//! intern inkonsistenten Gutscheinen härten.

use human_money_core::{
    UserIdentity,
    app_service::AppService,
    models::{profile::PublicProfile, voucher::ValueDefinition},
    services::voucher_manager::NewVoucherData,
    test_utils::{
        ACTORS, SILVER_STANDARD, create_test_bundle, generate_signed_standard_toml,
        resign_transaction, setup_service_with_profile,
    },
    wallet::{MultiTransferRequest, SourceTransfer, instance::VoucherStatus},
};
use std::collections::HashMap;
use tempfile::tempdir;

const PASSWORD: &str = "test-password-123";

fn setup_test_environment(
    dir: &tempfile::TempDir,
) -> ((AppService, UserIdentity), (AppService, String)) {
    // Alice erstellen
    let (mut alice_service, alice_profile) =
        setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
    alice_service
        .login(&alice_profile.folder_name, PASSWORD, false)
        .unwrap();
    alice_service.unlock_session(PASSWORD, 60).unwrap();
    let alice_identity = alice_service.get_unlocked_mut_for_test().1.clone();

    // Bob erstellen
    let (mut bob_service, bob_profile) =
        setup_service_with_profile(dir.path(), &ACTORS.bob, "Bob", PASSWORD);
    bob_service
        .login(&bob_profile.folder_name, PASSWORD, false)
        .unwrap();
    bob_service.unlock_session(PASSWORD, 60).unwrap();
    let bob_id = bob_service.get_user_id().unwrap();

    ((alice_service, alice_identity), (bob_service, bob_id))
}

/// Erstellt eine Sender- und Empfänger-Instanz für die Tests.
fn setup_sender_recipient() -> (AppService, UserIdentity, AppService, String) {
    let dir_sender = tempdir().unwrap();
    // HINWEIS: Wir MÜSSEN einen "slow" crypto-Akteur (wie alice) verwenden,
    // damit die 'identity_sender' mit der von AppService abgeleiteten Identität übereinstimmt.
    // `ACTORS.sender` verwendet 'fast' crypto und ist hierfür ungeeignet.
    let sender = &ACTORS.alice;
    let (mut service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    service_sender.unlock_session("pwd", 60).unwrap();
    let identity_sender = sender.identity.clone();

    let dir_recipient = tempdir().unwrap();
    let recipient = &ACTORS.recipient1;
    let (mut service_recipient, _) =
        setup_service_with_profile(dir_recipient.path(), recipient, "Recipient", "pwd");
    service_recipient.unlock_session("pwd", 60).unwrap();
    let id_recipient = service_recipient.get_user_id().unwrap();

    (
        service_sender,
        identity_sender,
        service_recipient,
        id_recipient,
    )
}

/// Test 2.1: Ein empfangenes Bundle mit einem Gutschein, dessen Transaktionskette
/// gebrochen ist (`prev_hash` ist falsch), muss abgewiesen werden.
#[test]
fn test_rejection_of_broken_transaction_chain() {
    let dir = tempdir().unwrap();
    let ((mut service_sender, identity_sender), (mut service_recipient, id_recipient)) =
        setup_test_environment(&dir);
    let silver_toml = toml::to_string(&SILVER_STANDARD.0).unwrap(); // Ist bereits signiert aus lazy_static
    let mut voucher = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(PASSWORD),
        )
        .unwrap();

    // --- Test-Modifikation ---
    // 1. Erstelle eine gültige Transfer-Transaktion von Alice an Bob.
    //    Wir müssen das `VoucherStandardDefinition`-Objekt (nicht den TOML-String) verwenden.
    let valid_tx = human_money_core::services::voucher_manager::create_transaction(
        &voucher,
        &SILVER_STANDARD.0, // Das Objekt aus test_utils
        &identity_sender.user_id,
        &identity_sender.signing_key,
        &human_money_core::test_utils::derive_holder_key(&voucher, &identity_sender.signing_key), // Init -> Tx1
        &id_recipient,
        "50.0000",
    )
    .unwrap()
    .0
    .transactions
    .pop()
    .unwrap(); // Nimm die neue, gültige Transaktion

    // 2. Breche die Kette, indem der prev_hash der GÜLTIGEN Transaktion manipuliert wird.
    let mut broken_tx = valid_tx;
    broken_tx.prev_hash = "garbage_hash_value_that_breaks_the_chain".to_string();

    // 3. WICHTIG: Transaktion neu signieren (resign).
    //    Dies ist notwendig, damit die Transaktion die *erste* Validierungsprüfung
    //    (t_id == hash(inhalt)) besteht.
    //    Die `resign_transaction` berechnet die t_id und Signatur basierend auf dem
    //    *neuen* (kaputten) prev_hash.
    let resigned_broken_tx = resign_transaction(broken_tx, &identity_sender.signing_key);

    // Füge die kaputte, aber kryptographisch konsistente Transaktion hinzu
    voucher.transactions.push(resigned_broken_tx);

    let bundle = create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, Some(PASSWORD));

    // 3. ASSERT
    assert!(result.is_err());
    let err_str = result.unwrap_err();
    assert!(
        err_str.contains("Invalid signature for signer Layer2-Anchor"),
        "Error should complain about broken L2 signature due to tampered prev_hash. Got: {}",
        err_str
    );
    assert!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .is_empty()
    );
}

/// Test 2.2: Ein Bundle mit einer "split"-Transaktion, deren Beträge sich nicht korrekt
/// zum vorherigen Saldo aufsummieren, muss abgewiesen werden.
#[test]
fn test_rejection_of_inconsistent_split_math() {
    // 1. ARRANGE
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient();
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Erstelle einen Gutschein mit 100 (über die öffentliche API)
    let mut voucher = service_sender
        .create_new_voucher(
            &silver_toml,
            "en", // Erstelle einen Gutschein mit 100
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    let prev_tx_hash = human_money_core::services::crypto_utils::get_hash(
        human_money_core::services::utils::to_canonical_json(voucher.transactions.last().unwrap())
            .unwrap(),
    );

    // Erstelle eine Split-Transaktion: Sende 30, behalte 80. (30 + 80 != 100 -> FEHLER)
    let mut tx2 = voucher.transactions[0].clone();
    tx2.prev_hash = prev_tx_hash;
    tx2.t_type = "split".to_string();
    tx2.recipient_id = id_recipient.clone();
    tx2.amount = "30.0000".to_string();
    tx2.sender_remaining_amount = Some("80.0000".to_string()); // Falscher Restbetrag
    tx2 = resign_transaction(tx2, &identity_sender.signing_key);
    voucher.transactions.push(tx2);

    let bundle = create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, Some("pwd"));

    // 3. ASSERT
    // HINWEIS: Dies deckt eine Lücke in der aktuellen Validierungslogik auf.
    // `voucher_validation.rs` prüft nur `InsufficientFunds`, aber nicht, ob die Summe
    // eines Splits korrekt ist. Der Test wird daher aktuell fälschlicherweise PASSIEREN.
    // Ein idealer Fehler wäre `InvalidSplitBalance`. Wir prüfen auf einen generischen Fehler.
    assert!(
        result.is_err(),
        "Receive bundle should have failed due to bad math. This might indicate a validation logic gap if it passes."
    );

    // Sobald die Validierung gehärtet ist, kann die spezifische Fehlermeldung geprüft werden.
    // assert!(result.unwrap_err().contains("InvalidSplitBalance"));
}

/// Test 2.3: Ein Bundle, das für einen anderen Empfänger (Bob) erstellt wurde,
/// darf nicht vom Sender (Alice) selbst eingelesen werden können.
#[test]
fn test_rejection_of_self_received_bundle() {
    // 1. ARRANGE
    let (mut service_sender, _, mut service_recipient, id_recipient) = setup_sender_recipient();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Sender erstellt einen neuen Gutschein
    let _ = service_sender // Das zurückgegebene Voucher-Objekt wird nicht direkt benötigt
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    // KORREKTUR für E0609: Die local_instance_id muss aus den Summaries geholt werden.
    let summaries = service_sender.get_voucher_summaries(None, None).unwrap();
    let local_id = summaries
        .first()
        .expect("Wallet should have one voucher summary after creation")
        .local_instance_id
        .clone();

    // Sender erstellt ein Bundle für den Empfänger (id_recipient)
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id,
            amount_to_send: "50".to_string(),
        }],
        notes: Some("Für Bob".to_string()),
        sender_profile_name: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes_for_bob = bundle_result.bundle_bytes;

    // 2. ACT
    // Der SENDER versucht nun, das Bundle, das für Bob bestimmt ist, SELBST einzulesen.
    let result_self_receive =
        service_sender.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, Some("pwd"));

    // 3. ASSERT
    assert!(result_self_receive.is_err());
    let err_str = result_self_receive.unwrap_err();
    assert!(
        // HINWEIS: Dieser Test hat sich durch die Einführung des Layer-1-Replay-Schutzes (Bundle-ID-Prüfung) geändert.
        // Da der Sender das Bundle erstellt, ist die Bundle-ID in seinem `bundle_meta_store` bekannt.
        // Der Versuch, dasselbe Bundle erneut zu empfangen, wird nun von der Layer-1-Prüfung
        // (BundleAlreadyProcessed) abgefangen, *bevor* die Layer-3-Prüfung (BundleRecipientMismatch) erreicht wird.
        // Dies ist das neue, korrekte Verhalten.
        err_str.contains("Bundle has already been processed"),
        "Error should be 'BundleAlreadyProcessed' (L1 check). Got: {}",
        err_str
    );

    // Stelle sicher, dass der ursprüngliche Gutschein (jetzt mit Restbetrag)
    // im 'Active'-Status verblieben ist und kein neuer Gutschein erstellt wurde.
    let summaries = service_sender.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status, VoucherStatus::Active);
    assert_eq!(summaries[0].current_amount, "50.0000"); // Der Restbetrag nach dem Split

    // Der Empfänger (Bob) kann es problemlos empfangen
    let result_recipient =
        service_recipient.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, Some("pwd"));
    assert!(result_recipient.is_ok());
    assert_eq!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.4: (Layer 1) Ein identisches Bundle, das erneut empfangen wird,
/// muss anhand seiner Bundle-ID abgewiesen werden.
#[test]
fn test_rejection_of_identical_bundle_replay() {
    // 1. ARRANGE
    let (mut service_sender, _, mut service_recipient, id_recipient) = setup_sender_recipient();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Sender erstellt einen neuen Gutschein
    let _ = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    let summaries = service_sender.get_voucher_summaries(None, None).unwrap();
    let local_id = summaries.first().unwrap().local_instance_id.clone();

    // Sender erstellt ein Bundle für den Empfänger
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id,
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes = bundle_result.bundle_bytes;

    // 2. ACT (First Receive)
    let result_first =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, Some("pwd"));

    // 3. ASSERT (First Receive)
    assert!(result_first.is_ok());
    assert_eq!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );

    // 4. ACT (Second Receive - Replay)
    let result_second =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, Some("pwd"));

    // 5. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err();
    assert!(
        err_str.contains("Bundle has already been processed"),
        "Error should be BundleAlreadyProcessed. Got: {}",
        err_str
    );
    // Der Zustand des Wallets darf sich nicht geändert haben
    assert_eq!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.5: (Layer 2) Ein Gutschein, der bereits empfangen wurde, darf nicht
/// in einem *neuen* Bundle erneut empfangen werden (Fingerprint-Prüfung).
#[test]
fn test_rejection_of_voucher_replay_in_new_bundle() {
    // 1. ARRANGE
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Manuelles Erstellen von voucher_A (wie in Test 2.1)
    let voucher_a = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();
    let (voucher_a_sent, _) = human_money_core::services::voucher_manager::create_transaction(
        &voucher_a,
        &SILVER_STANDARD.0,
        &identity_sender.user_id,
        &identity_sender.signing_key,
        &human_money_core::test_utils::derive_holder_key(&voucher_a, &identity_sender.signing_key), // Init -> Tx 1
        &id_recipient,
        "50.0000",
    )
    .unwrap();

    // Bundle 1 (Das legitime Bundle)
    let bundle_1_bytes = create_test_bundle(
        &identity_sender,
        vec![voucher_a_sent.clone()],
        &id_recipient,
        Some("Bundle 1"),
    )
    .unwrap();
    // Bundle 2 (Das bösartige Replay-Bundle mit neuer Bundle-ID, aber identischem Inhalt)
    let bundle_2_bytes = create_test_bundle(
        &identity_sender,
        vec![voucher_a_sent],
        &id_recipient,
        Some("Bundle 2"),
    )
    .unwrap();

    // 2. ACT (First Receive)
    let result_first =
        service_recipient.receive_bundle(&bundle_1_bytes, &standards_map, None, Some("pwd"));
    assert!(result_first.is_ok());
    assert_eq!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );

    // 3. ACT (Second Receive - Replay)
    let result_second =
        service_recipient.receive_bundle(&bundle_2_bytes, &standards_map, None, Some("pwd"));

    // 4. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err();
    assert!(
        err_str.contains("Transaction fingerprint is already known"),
        "Error should be TransactionFingerprintAlreadyKnown. Got: {}",
        err_str
    );
    assert_eq!(
        service_recipient
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.6: (Layer 3) Ein Bundle, das an ein anderes Präfix (mobil) derselben
/// Identität gesendet wird, muss vom Wallet mit dem "pc"-Präfix abgewiesen werden.
/// Dies ist der Kerntest für das "Separated Account Identity (SAI)".
#[test]
fn test_rejection_of_bundle_for_different_prefix_same_identity() {
    // 1. ARRANGE
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // --- Sender (Alice) ---
    let dir_sender = tempdir().unwrap();
    let sender = &ACTORS.alice;
    let (mut service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    service_sender.unlock_session("pwd", 60).unwrap();

    // --- Empfänger-Wallets (Beide "Bob", aber unterschiedliche Präfixe) ---
    // WICHTIG: Wir verwenden ACTORS.bob und ACTORS.issuer. Beide nutzen
    // dieselbe Mnemonic (mnemonics::BOB), aber unterschiedliche Präfixe ("bo", "is").
    // Dies simuliert denselben User auf zwei Geräten.
    let recipient_user_pc = &ACTORS.bob; // prefix "bo"
    let recipient_user_mobil = &ACTORS.issuer; // prefix "is"

    // Wallet 1: PC
    let dir_recipient_pc = tempdir().unwrap();
    let (mut service_recipient_pc, _) = setup_service_with_profile(
        dir_recipient_pc.path(),
        recipient_user_pc,
        "Bob_PC",
        "pwd_bob",
    );
    service_recipient_pc.unlock_session("pwd_bob", 60).unwrap();
    let id_recipient_pc = service_recipient_pc.get_user_id().unwrap();

    // Wallet 2: Mobil
    let dir_recipient_mobil = tempdir().unwrap();
    let (mut service_recipient_mobil, _) = setup_service_with_profile(
        dir_recipient_mobil.path(),
        recipient_user_mobil,
        "Bob_Mobil",
        "pwd_bob",
    );
    service_recipient_mobil
        .unlock_session("pwd_bob", 60)
        .unwrap();
    let id_recipient_mobil = service_recipient_mobil.get_user_id().unwrap();

    // Sanity Check: Sicherstellen, dass die Public Keys gleich sind,
    // aber die vollen User-IDs (Adressen) unterschiedlich.
    let pk_pc = human_money_core::services::crypto_utils::get_pubkey_from_user_id(&id_recipient_pc)
        .unwrap();
    let pk_mobil =
        human_money_core::services::crypto_utils::get_pubkey_from_user_id(&id_recipient_mobil)
            .unwrap();
    assert_eq!(
        pk_pc, pk_mobil,
        "Public keys must be identical for this test."
    );
    assert_ne!(
        id_recipient_pc, id_recipient_mobil,
        "Full User IDs (addresses) must be different."
    );
    assert!(id_recipient_pc.starts_with("bo:")); // Präfix von ACTORS.bob
    assert!(id_recipient_mobil.starts_with("is:")); // Präfix von ACTORS.issuer

    // --- Sender erstellt Gutschein und Bundle für "Mobil" ---
    let _ = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();
    let local_id_sender = service_sender
        .get_voucher_summaries(None, None)
        .unwrap()
        .first()
        .unwrap()
        .local_instance_id
        .clone();

    // Bundle wird explizit an die "Mobil"-Adresse gesendet
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient_mobil.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id_sender,
            amount_to_send: "50".to_string(),
        }],
        notes: Some("Für Bobs Handy".to_string()),
        sender_profile_name: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes_for_mobil = bundle_result.bundle_bytes;

    // 2. ACT
    // Das "PC"-Wallet versucht, das für "Mobil" bestimmte Bundle einzulesen.
    let result_pc_receive = service_recipient_pc.receive_bundle(
        &bundle_bytes_for_mobil,
        &standards_map,
        None,
        Some("pwd_bob"),
    );

    // 3. ASSERT (PC Wallet)
    assert!(result_pc_receive.is_err());
    let err_str = result_pc_receive.unwrap_err();
    assert!(
        // KORREKTUR: Der Fehler tritt korrekterweise bereits auf Layer 1
        // (Secure Container) auf, da die User-ID "bo-..." nicht in der
        // Empfängerliste des Containers ("is-...") enthalten ist.
        err_str.contains("The current user is not in the list of recipients for this container"),
        "Error must be 'Not in recipient list' (L1 check). Got: {}",
        err_str
    );
    // Das PC-Wallet muss leer bleiben
    assert!(
        service_recipient_pc
            .get_voucher_summaries(None, None)
            .unwrap()
            .is_empty()
    );

    // 4. ASSERT (Mobil Wallet - Sanity Check)
    // Das "Mobil"-Wallet (der korrekte Empfänger) kann es problemlos annehmen.
    let result_mobil_receive = service_recipient_mobil.receive_bundle(
        &bundle_bytes_for_mobil,
        &standards_map,
        None,
        Some("pwd_bob"),
    );
    assert!(result_mobil_receive.is_ok());
    assert_eq!(
        service_recipient_mobil
            .get_voucher_summaries(None, None)
            .unwrap()
            .len(),
        1
    );
}
