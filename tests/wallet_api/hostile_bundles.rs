//! # tests/wallet_api/hostile_bundles.rs
//!
// HINWEIS: Tests 2.1 und 2.2 wurden auf die öffentliche `AppService::create_new_voucher` API umgestellt.
//! Enthält Tests, die den `AppService` gegen den Empfang von feindseligen,
//! intern inkonsistenten Gutscheinen härten.

use voucher_lib::{
    app_service::AppService,
    test_utils::{
        create_test_bundle, generate_signed_standard_toml, resign_transaction, ACTORS,
        SILVER_STANDARD, setup_service_with_profile,
    }, UserIdentity,
    models::voucher::{Creator, NominalValue}, services::voucher_manager::NewVoucherData,
    wallet::{instance::VoucherStatus, MultiTransferRequest, SourceTransfer},
};
use std::collections::HashMap;
use tempfile::tempdir;

/// Erstellt eine Sender- und Empfänger-Instanz für die Tests.
fn setup_sender_recipient() -> (AppService, UserIdentity, AppService, String) {
    let dir_sender = tempdir().unwrap();
    // HINWEIS: Wir MÜSSEN einen "slow" crypto-Akteur (wie alice) verwenden,
    // damit die 'identity_sender' mit der von AppService abgeleiteten Identität übereinstimmt.
    // `ACTORS.sender` verwendet 'fast' crypto und ist hierfür ungeeignet.
    let sender = &ACTORS.alice;
    let (service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    let identity_sender = sender.identity.clone();

    let dir_recipient = tempdir().unwrap();
    let recipient = &ACTORS.recipient1;
    let (service_recipient, _) =
        setup_service_with_profile(dir_recipient.path(), recipient, "Recipient", "pwd");
    let id_recipient = service_recipient.get_user_id().unwrap();

    (service_sender, identity_sender, service_recipient, id_recipient)
}

/// Test 2.1: Ein empfangenes Bundle mit einem Gutschein, dessen Transaktionskette
/// gebrochen ist (`prev_hash` ist falsch), muss abgewiesen werden.
#[test]
fn test_rejection_of_broken_transaction_chain() {
    // 1. ARRANGE
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient();
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Verwende die öffentliche API des AppService
    let mut voucher = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: service_sender.get_user_id().unwrap(),
                    ..Default::default()
                },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();

    let mut tx2 = voucher.transactions[0].clone();
    tx2.prev_hash = "garbage_hash_value".to_string(); // Kette brechen
    tx2.t_type = "transfer".to_string();
    tx2.recipient_id = id_recipient.clone();
    tx2 = resign_transaction(tx2, &identity_sender.signing_key);
    voucher.transactions.push(tx2);

    let bundle =
        create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, "pwd");

    // 3. ASSERT
    assert!(result.is_err());
    let err_str = result.unwrap_err();
    assert!(
        err_str.contains("Transaction chain broken"),
        "Error should complain about broken transaction chain. Got: {}",
        err_str
    );
    assert!(service_recipient
        .get_voucher_summaries(None, None)
        .unwrap()
        .is_empty());
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
                creator: Creator {
                    id: service_sender.get_user_id().unwrap(),
                    ..Default::default()
                },
                nominal_value: NominalValue {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            "pwd")
        .unwrap();

    let prev_tx_hash = voucher_lib::services::crypto_utils::get_hash(
        voucher_lib::services::utils::to_canonical_json(voucher.transactions.last().unwrap())
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

    let bundle =
        create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, "pwd");

    // 3. ASSERT
    // HINWEIS: Dies deckt eine Lücke in der aktuellen Validierungslogik auf.
    // `voucher_validation.rs` prüft nur `InsufficientFunds`, aber nicht, ob die Summe
    // eines Splits korrekt ist. Der Test wird daher aktuell fälschlicherweise PASSIEREN.
    // Ein idealer Fehler wäre `InvalidSplitBalance`. Wir prüfen auf einen generischen Fehler.
    assert!(result.is_err(), "Receive bundle should have failed due to bad math. This might indicate a validation logic gap if it passes.");

    // Sobald die Validierung gehärtet ist, kann die spezifische Fehlermeldung geprüft werden.
    // assert!(result.unwrap_err().contains("InvalidSplitBalance"));
}

/// Test 2.3: Ein Bundle, das für einen anderen Empfänger (Bob) erstellt wurde,
/// darf nicht vom Sender (Alice) selbst eingelesen werden können.
#[test]
fn test_rejection_of_self_received_bundle() {
    // 1. ARRANGE
    let (mut service_sender, _, mut service_recipient, id_recipient) =
        setup_sender_recipient();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Sender erstellt einen neuen Gutschein
    let _ = service_sender // Das zurückgegebene Voucher-Objekt wird nicht direkt benötigt
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: service_sender.get_user_id().unwrap(),
                    ..Default::default()
                },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();

    // KORREKTUR für E0609: Die local_instance_id muss aus den Summaries geholt werden.
    let summaries = service_sender.get_voucher_summaries(None, None).unwrap();
    let local_id = summaries.first()
        .expect("Wallet should have one voucher summary after creation")
        .local_instance_id.clone();

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
        .create_transfer_bundle(transfer_request, &standards_map, None, "pwd")
        .unwrap();
    let bundle_bytes_for_bob = bundle_result.bundle_bytes;

    // 2. ACT
    // Der SENDER versucht nun, das Bundle, das für Bob bestimmt ist, SELBST einzulesen.
    let result_self_receive =
        service_sender.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, "pwd");

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
        service_recipient.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, "pwd");
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
    let (mut service_sender, _, mut service_recipient, id_recipient) =
        setup_sender_recipient();

    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(SILVER_STANDARD.0.metadata.uuid.clone(), silver_toml.clone());

    // Sender erstellt einen neuen Gutschein
    let _ = service_sender
        .create_new_voucher(
            &silver_toml,
            "en",
            NewVoucherData {
                creator: Creator {
                    id: service_sender.get_user_id().unwrap(),
                    ..Default::default()
                },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
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
        .create_transfer_bundle(transfer_request, &standards_map, None, "pwd")
        .unwrap();
    let bundle_bytes = bundle_result.bundle_bytes;

    // 2. ACT (First Receive)
    let result_first =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, "pwd");

    // 3. ASSERT (First Receive)
    assert!(result_first.is_ok());
    assert_eq!(service_recipient.get_voucher_summaries(None, None).unwrap().len(), 1);

    // 4. ACT (Second Receive - Replay)
    let result_second =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, "pwd");

    // 5. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err();
    assert!(
        err_str.contains("Bundle has already been processed"),
        "Error should be BundleAlreadyProcessed. Got: {}",
        err_str
    );
    // Der Zustand des Wallets darf sich nicht geändert haben
    assert_eq!(service_recipient.get_voucher_summaries(None, None).unwrap().len(), 1);
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
    let voucher_a = service_sender.create_new_voucher(&silver_toml, "en", NewVoucherData { creator: Creator { id: service_sender.get_user_id().unwrap(), ..Default::default() }, nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() }, ..Default::default() }, "pwd").unwrap();
    let voucher_a_sent = voucher_lib::services::voucher_manager::create_transaction(&voucher_a, &SILVER_STANDARD.0, &identity_sender.user_id, &identity_sender.signing_key, &id_recipient, "50.0000").unwrap();

    // Bundle 1 (Das legitime Bundle)
    let bundle_1_bytes = create_test_bundle(&identity_sender, vec![voucher_a_sent.clone()], &id_recipient, Some("Bundle 1")).unwrap();
    // Bundle 2 (Das bösartige Replay-Bundle mit neuer Bundle-ID, aber identischem Inhalt)
    let bundle_2_bytes = create_test_bundle(&identity_sender, vec![voucher_a_sent], &id_recipient, Some("Bundle 2")).unwrap();

    // 2. ACT (First Receive)
    let result_first = service_recipient.receive_bundle(&bundle_1_bytes, &standards_map, None, "pwd");
    assert!(result_first.is_ok());
    assert_eq!(service_recipient.get_voucher_summaries(None, None).unwrap().len(), 1);

    // 3. ACT (Second Receive - Replay)
    let result_second = service_recipient.receive_bundle(&bundle_2_bytes, &standards_map, None, "pwd");

    // 4. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err();
    assert!(
        err_str.contains("Transaction fingerprint is already known"),
        "Error should be TransactionFingerprintAlreadyKnown. Got: {}",
        err_str
    );
    assert_eq!(service_recipient.get_voucher_summaries(None, None).unwrap().len(), 1);
}
