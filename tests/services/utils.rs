// tests/services/utils.rs
// cargo test --test services_tests
//!
//! Bündelt Tests für verschiedene Hilfsfunktionen und Low-Level-Services,
//! wie Datumsberechnungen und die Generierung von lokalen Instanz-IDs.

// Explizite Pfadangabe für das `test_utils`-Modul, um Unklarheiten zu vermeiden.

// --- Tests from test_date_utils.rs ---

use chrono::{DateTime, Utc};
use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD};
use human_money_core::{
    NewVoucherData, VoucherCoreError,
    error::ValidationError,
    services::{
        crypto_utils,
        utils::to_canonical_json,
        voucher_manager::{self, create_voucher},
        voucher_validation::validate_voucher_against_standard,
    },
};

#[test]
fn test_iso8601_duration_date_math_correctness() {
    // Diese Testfälle wurden speziell entwickelt, um die Schwächen
    // der alten, vereinfachten Datumsberechnung aufzudecken.

    let test_cases = vec![
        // 1. Kritischer Fall: Monats-Überlauf
        // 31. Januar + 1 Monat sollte der 28. Februar sein, nicht der 2. März.
        ("2025-01-31T10:00:00Z", "P1M", "2025-02-28T10:00:00Z"),
        // 2. Kritischer Fall: Schaltjahr-Logik
        // 15. Feb 2024 (Schaltjahr) + 1 Jahr sollte der 15. Feb 2025 sein.
        // Die alte Logik (+365 Tage) würde auf den 14. Feb 2025 kommen.
        ("2024-02-15T10:00:00Z", "P1Y", "2025-02-15T10:00:00Z"),
        // 3. Kritischer Fall: Start am Schalttag
        // 29. Feb 2024 + 1 Jahr sollte auf den 28. Feb 2025 ausweichen.
        ("2024-02-29T10:00:00Z", "P1Y", "2025-02-28T10:00:00Z"),
        // 4. Standardfall Monat (zur Absicherung)
        ("2025-04-15T10:00:00Z", "P2M", "2025-06-15T10:00:00Z"),
        // 5. Standardfall Tag (zur Absicherung)
        ("2025-01-01T10:00:00Z", "P10D", "2025-01-11T10:00:00Z"),
    ];

    for (start_str, duration_str, expected_str) in test_cases {
        let start_date = DateTime::parse_from_rfc3339(start_str)
            .unwrap()
            .with_timezone(&Utc);

        let expected_date = DateTime::parse_from_rfc3339(expected_str)
            .unwrap()
            .with_timezone(&Utc);

        // Annahme: `add_iso8601_duration` ist für den Test aufrufbar.
        let result_date = voucher_manager::add_iso8601_duration(start_date, duration_str)
            .expect("Date calculation should not fail");

        // Wir vergleichen nur die Datums- und Zeit-Komponenten bis zur Sekunde,
        // um mögliche minimale Abweichungen in Nanosekunden zu ignorieren.
        assert_eq!(
            result_date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            expected_date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "Failed on test case: {} + {}",
            start_str,
            duration_str
        );
    }
}

#[test]
fn test_round_up_date_logic() {
    let test_cases = vec![
        // 1. Aufrunden auf das Ende des Tages
        (
            "2025-08-26T10:20:30Z",
            "P1D",
            "2025-08-26T23:59:59.999999999Z",
        ),
        // 2. Aufrunden auf das Ende des Monats (31 Tage)
        (
            "2025-01-15T12:00:00Z",
            "P1M",
            "2025-01-31T23:59:59.999999999Z",
        ),
        // 3. Aufrunden auf das Ende des Monats (Februar, kein Schaltjahr)
        (
            "2025-02-10T00:00:00Z",
            "P1M",
            "2025-02-28T23:59:59.999999999Z",
        ),
        // 4. Randfall: Aufrunden am letzten Tag des Monats (Schaltjahr)
        (
            "2024-02-29T18:00:00Z",
            "P1M",
            "2024-02-29T23:59:59.999999999Z",
        ),
        // 5. Aufrunden auf das Ende des Jahres
        (
            "2025-03-01T01:00:00Z",
            "P1Y",
            "2025-12-31T23:59:59.999999999Z",
        ),
        // 6. Randfall: Aufrunden am letzten Tag des Jahres
        (
            "2025-12-31T23:00:00Z",
            "P1Y",
            "2025-12-31T23:59:59.999999999Z",
        ),
    ];

    for (start_str, rounding_str, expected_str) in test_cases {
        let start_date = DateTime::parse_from_rfc3339(start_str)
            .unwrap()
            .with_timezone(&Utc);
        let expected_date = DateTime::parse_from_rfc3339(expected_str)
            .unwrap()
            .with_timezone(&Utc);

        // Annahme: `round_up_date` ist für den Test aufrufbar.
        let result_date = voucher_manager::round_up_date(start_date, rounding_str)
            .expect("Rounding calculation should not fail");

        assert_eq!(
            result_date, expected_date,
            "Failed on rounding case: {} with rule {}",
            start_str, rounding_str
        );
    }
}

#[test]
fn test_chronological_validation_with_timezones() {
    // 1. Setup
    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let test_user = &ACTORS.test_user;

    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(test_user.user_id.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    // KORREKTUR: Übergebe den korrekten `signing_key` vom Typ &SigningKey.
    let mut voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &test_user.signing_key,
        "en",
    )
    .unwrap();

    // 2. Manipuliere den Zeitstempel der `init`-Transaktion so, dass er VOR dem Erstellungsdatum des Gutscheins liegt.
    // Die Validierung sollte dies als Fehler erkennen.
    voucher.transactions[0].t_time = "2020-01-01T00:00:00Z".to_string(); // Eindeutig in der Vergangenheit

    // Damit der Fehler isoliert wird, müssen wir die Transaktion neu hashen und signieren.
    let mut tx = voucher.transactions[0].clone();
    tx.t_id = "".to_string(); // Hash-relevante Felder zurücksetzen
    tx.layer2_signature = None;
    tx.sender_identity_signature = None;
    tx.t_id = crypto_utils::get_hash(to_canonical_json(&tx).unwrap());

    // KORREKTUR: Signiere t_id raw für L2 (technisch)
    let t_id_raw = bs58::decode(&tx.t_id).into_vec().unwrap();
    let l2_sig = crypto_utils::sign_ed25519(&test_user.signing_key, &t_id_raw);
    tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());

    // KORREKTUR: Signiere t_id raw für Identität (sozial)
    let identity_sig = crypto_utils::sign_ed25519(&test_user.signing_key, &t_id_raw);
    tx.sender_identity_signature = Some(bs58::encode(identity_sig.to_bytes()).into_string());

    voucher.transactions[0] = tx;

    // 3. Validierung: Die Transaktionszeit (`2020`) liegt nun vor dem Erstellungsdatum (`~2025`).
    // Die Validierung muss dies als `InvalidTimeOrder` erkennen.
    let result = validate_voucher_against_standard(&voucher, standard);

    // Verbessere die Fehlerausgabe wie gewünscht.
    let err = result.expect_err("Validation should have failed but returned Ok");
    assert!(
        matches!(
            err, // Der Compiler schlägt die korrekte Syntax für ein struct variant vor.
            VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
        ),
        "Expected InvalidTimeOrder, but got a different error: {:?}",
        err
    );
}

// --- Tests from test_local_instance_id.rs ---

use human_money_core::models::voucher::{
    Address, Collateral, Transaction, ValueDefinition, Voucher, VoucherStandard,
    VoucherTemplateData,
};

// -------------------------------------------------------------------------
// Additional edge-case tests for ISO 8601 duration parsing, date rounding,
// and the issuance circulation firewall.
// -------------------------------------------------------------------------

/// Verifies that `add_iso8601_duration` rejects strings that violate the ISO 8601 duration
/// format independently:
/// - A string with the wrong leading character but correct length must be rejected.
/// - A string with the correct 'P' prefix but insufficient length must be rejected.
/// - A well-formed string ('P1Y') must be accepted.
///
/// Each condition of the format guard is exercised in isolation so that both
/// halves of the combined check are confirmed to be necessary.
#[test]
fn test_iso8601_duration_rejects_each_format_violation_independently() {
    let now = chrono::Utc::now();

    // Wrong leading character, but length ≥ 3 – violates the prefix rule only.
    let result = voucher_manager::add_iso8601_duration(now, "ABC");
    assert!(
        result.is_err(),
        "Expected Err for 'ABC' (wrong prefix, correct length), but got Ok"
    );

    // Correct 'P' prefix, but length < 3 – violates the length rule only.
    let result2 = voucher_manager::add_iso8601_duration(now, "P");
    assert!(
        result2.is_err(),
        "Expected Err for 'P' (correct prefix, too short), but got Ok"
    );

    // Valid format must succeed.
    let result3 = voucher_manager::add_iso8601_duration(now, "P1Y");
    assert!(result3.is_ok(), "Expected Ok for valid 'P1Y', got Err");
}

/// Verifies that `add_iso8601_duration` correctly handles month additions that cross
/// a year boundary, i.e. when the source date is in the last months of the year.
///
/// The month arithmetic in this function determines the number of days in the target
/// month by looking ahead to the first day of the *following* month. When the target
/// month is December this look-ahead must reference January of the *next* year.
/// The following cases confirm this year-rollover path:
///   - November start → December target (no year change, sanity check)
///   - December start → January target (year increments)
///   - December 31st  → January 31st   (year increments, full-month clamp)
#[test]
fn test_iso8601_duration_month_addition_across_year_boundary() {
    let test_cases = vec![
        // Sanity: November + 1 month → December (no year change)
        ("2025-11-15T12:00:00Z", "P1M", "2025-12-15T12:00:00Z"),
        // Core case: December + 1 month → January of the following year
        ("2025-12-15T12:00:00Z", "P1M", "2026-01-15T12:00:00Z"),
        // Edge case: last day of December + 1 month → last day of January (year rollover)
        ("2025-12-31T12:00:00Z", "P1M", "2026-01-31T12:00:00Z"),
    ];

    for (start_str, duration_str, expected_str) in test_cases {
        let start = chrono::DateTime::parse_from_rfc3339(start_str)
            .unwrap()
            .with_timezone(&chrono::Utc);
        let expected = chrono::DateTime::parse_from_rfc3339(expected_str)
            .unwrap()
            .with_timezone(&chrono::Utc);

        let result = voucher_manager::add_iso8601_duration(start, duration_str)
            .unwrap_or_else(|e| panic!("Unexpected error for '{}': {:?}", start_str, e));

        assert_eq!(
            result.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            expected.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "Failed for: {} + {}",
            start_str,
            duration_str
        );
    }
}

/// Verifies that `round_up_date` with rule `P1M` correctly rounds a December date to
/// the last moment of December (i.e. `2025-12-31T23:59:59.999999999Z`).
///
/// The function works by computing `first_of_next_month - 1ns`. For a December input
/// the "next month" is January of the *following* year, so the year must be incremented
/// when building this reference date. This test confirms that the year-rollover path
/// produces the correct end-of-December timestamp.
#[test]
fn test_round_up_date_p1m_correctly_handles_december() {
    // A December date rounded to P1M must yield the last nanosecond of December.
    let start = chrono::DateTime::parse_from_rfc3339("2025-12-15T10:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let expected = chrono::DateTime::parse_from_rfc3339("2025-12-31T23:59:59.999999999Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let result = voucher_manager::round_up_date(start, "P1M")
        .expect("round_up_date should not fail for December with P1M");

    assert_eq!(
        result, expected,
        "round_up_date for December + P1M should yield 2025-12-31T23:59:59.999999999Z"
    );
}

/// Verifies the issuance circulation firewall: when a standard defines
/// `issuance_minimum_validity_duration`, the creator may only forward a voucher to a
/// third party while the remaining validity exceeds that minimum.
///
/// Two cases are checked:
/// - A voucher with P2Y validity (well above the P1Y minimum) must be allowed through.
/// - A voucher with only P1D validity (well below the P1Y minimum) must be rejected.
///
/// Note: the voucher with insufficient validity is intentionally created against a
/// no-minimum standard so that `create_voucher` itself does not block it; only the
/// subsequent `create_transaction` call enforces the firewall rule.
#[test]
fn test_issuance_firewall_blocks_creator_when_validity_below_minimum() {
    let (base_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    // Build a standard that requires at least P1Y of remaining validity for the creator.
    let (standard_with_p1y, standard_hash) =
        human_money_core::test_utils::create_custom_standard(base_standard, |s| {
            s.immutable.issuance.issuance_minimum_validity_duration = "P1Y".to_string();
        });

    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;

    // --- Case 1: validity P2Y (well above minimum P1Y) -- must be allowed ---
    let voucher_data_allowed = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P2Y".to_string()),
        ..Default::default()
    };

    let voucher_allowed = create_voucher(
        voucher_data_allowed,
        &standard_with_p1y,
        &standard_hash,
        &creator.signing_key,
        "en",
    )
    .expect("create_voucher with P2Y should succeed");

    let holder_key_allowed =
        human_money_core::test_utils::derive_holder_key(&voucher_allowed, &creator.signing_key);

    let result_allowed = human_money_core::services::voucher_manager::create_transaction(
        &voucher_allowed,
        &standard_with_p1y,
        &creator.user_id,
        &creator.signing_key,
        &holder_key_allowed,
        &recipient.user_id,
        "10",
        None,
    );

    assert!(
        result_allowed.is_ok(),
        "Voucher with P2Y validity (above P1Y minimum) should be allowed through the firewall, got: {:?}",
        result_allowed.err()
    );

    // --- Case 2: validity P1D (well below minimum P1Y) -- must be blocked ---
    // Create with a no-minimum standard so that create_voucher itself does not reject it.
    let (standard_no_min, hash_no_min) =
        human_money_core::test_utils::create_custom_standard(base_standard, |s| {
            s.immutable.issuance.issuance_minimum_validity_duration = "P0Y".to_string();
        });

    let voucher_data_short = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1D".to_string()), // Only 1 day – well below P1Y
        ..Default::default()
    };

    let voucher_short = create_voucher(
        voucher_data_short,
        &standard_no_min,
        &hash_no_min,
        &creator.signing_key,
        "en",
    )
    .expect("create_voucher with P1D on no-min standard should succeed");

    let holder_key_short =
        human_money_core::test_utils::derive_holder_key(&voucher_short, &creator.signing_key);

    // Attempt the transaction against the stricter P1Y standard -- firewall must block it.
    let result_short = human_money_core::services::voucher_manager::create_transaction(
        &voucher_short,
        &standard_with_p1y,
        &creator.user_id,
        &creator.signing_key,
        &holder_key_short,
        &recipient.user_id,
        "10",
        None,
    );

    assert!(
        result_short.is_err(),
        "Voucher with only P1D validity must be blocked by the P1Y issuance firewall"
    );
}
use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::wallet::Wallet;

/// Hilfsfunktion, um einen einfachen Test-Gutschein zu erstellen.
/// Initialisiert alle Felder manuell, um die fehlende `Default`-Implementierung zu umgehen.
fn create_base_voucher(creator_id: &str, amount: &str) -> Voucher {
    let voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: "Test Standard".to_string(),
            uuid: "uuid-test".to_string(),
            standard_definition_hash: "dummy-hash-for-test".to_string(),
            template: VoucherTemplateData {
                description: "A test voucher".to_string(),
                primary_redemption_type: "SERVICE".to_string(),
                allow_partial_transfers: true,
                issuance_minimum_validity_duration: "P1Y".to_string(),
                footnote: "".to_string(),
            },
        },
        voucher_id: "voucher-123".to_string(),
        voucher_nonce: "test-nonce".to_string(),
        creation_date: get_current_timestamp(),
        valid_until: get_current_timestamp(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "Minutes".to_string(),
            amount: amount.to_string(),
            abbreviation: Some("m".to_string()),
            description: Some("Test".to_string()),
        },
        collateral: Some(Collateral {
            value: ValueDefinition {
                unit: "".to_string(),
                amount: "".to_string(),
                abbreviation: Some("".to_string()),
                description: Some("".to_string()),
            },
            collateral_type: Some("".to_string()),
            redeem_condition: Some("".to_string()),
        }),
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator_id.to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("Creator".to_string()),
            address: Some(Address::default()), // Address leitet Default ab und kann so verwendet werden
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: Some("9".to_string()),
            coordinates: Some("0,0".to_string()),
            ..Default::default()
        },
        transactions: vec![], // Wird im nächsten Schritt gefüllt
        signatures: vec![],
    };

    let mut voucher = voucher;
    let init_transaction = Transaction {
        sender_identity_signature: None,
        t_id: "t-init-abc".to_string(),
        prev_hash: get_hash(format!("{}{}", &voucher.voucher_id, &voucher.voucher_nonce)),
        t_type: "init".to_string(),
        t_time: get_current_timestamp(),
        sender_id: Some(creator_id.to_string()),
        recipient_id: creator_id.to_string(),
        amount: amount.to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash: None,
    };
    voucher.transactions.push(init_transaction);
    voucher
}

/// Testet, ob die `local_instance_id` für den ursprünglichen Ersteller
/// korrekt auf Basis der `init`-Transaktion berechnet wird.
#[test]
fn test_local_id_for_initial_creator() {
    let creator = &ACTORS.alice;
    let voucher = create_base_voucher(&creator.user_id, "100");

    let result = Wallet::calculate_local_instance_id(&voucher, &creator.user_id);
    assert!(result.is_ok());
    let local_id = result.unwrap();

    let expected_combined_string =
        format!("{}{}{}", voucher.voucher_id, "t-init-abc", &creator.user_id);
    let expected_hash = get_hash(expected_combined_string);

    assert_eq!(local_id, expected_hash);
}

/// Testet, ob die `local_instance_id` für einen Empfänger nach einem
/// vollständigen Transfer korrekt auf Basis der Transfer-Transaktion berechnet wird.
#[test]
fn test_local_id_after_full_transfer() {
    let creator = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let mut voucher = create_base_voucher(&creator.user_id, "100");

    let transfer_tx = Transaction {
        sender_identity_signature: None,
        t_id: "t-transfer-def".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(), // Voller Transfer
        t_time: get_current_timestamp(),
        sender_id: Some(creator.user_id.clone()),
        recipient_id: recipient.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None, // Kein Restbetrag
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash: None,
    };
    voucher.transactions.push(transfer_tx);

    // ID für den neuen Besitzer (Empfänger)
    let result_recipient = Wallet::calculate_local_instance_id(&voucher, &recipient.user_id);
    assert!(result_recipient.is_ok());
    let local_id_recipient = result_recipient.unwrap();

    let expected_combined_string = format!(
        "{}{}{}",
        voucher.voucher_id, "t-transfer-def", &recipient.user_id
    );
    let expected_hash = get_hash(expected_combined_string);

    assert_eq!(local_id_recipient, expected_hash);

    // ID für den ursprünglichen Besitzer (jetzt archiviert)
    // NACH ÄNDERUNG: Die ID muss nun auf der Transfer-Transaktion basieren, da der Creator dort der Sender war.
    let result_creator = Wallet::calculate_local_instance_id(&voucher, &creator.user_id);
    assert!(result_creator.is_ok());
    let creators_archived_id = result_creator.unwrap();
    let expected_archived_string = format!(
        "{}{}{}",
        voucher.voucher_id, "t-transfer-def", &creator.user_id
    );
    assert_eq!(
        creators_archived_id,
        get_hash(expected_archived_string),
        "Die archivierte ID des Erstellers sollte auf der Transfer-Transaktion basieren."
    );
}

/// Testet die `local_instance_id` für Sender und Empfänger nach einer Teilung (Split).
/// Beide IDs müssen auf der Split-Transaktion basieren.
#[test]
fn test_local_id_after_split() {
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;
    let mut voucher = create_base_voucher(&sender.user_id, "100");

    let split_tx = Transaction {
        sender_identity_signature: None,
        t_id: "t-split-ghi".to_string(),
        prev_hash: get_hash("..."),
        t_type: "split".to_string(),
        t_time: get_current_timestamp(),
        sender_id: Some(sender.user_id.clone()),
        recipient_id: recipient.user_id.clone(),
        amount: "40".to_string(),
        sender_remaining_amount: Some("60".to_string()),
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash: None,
    };
    voucher.transactions.push(split_tx);

    // ID für den Sender (hat noch Restguthaben)
    let result_sender = Wallet::calculate_local_instance_id(&voucher, &sender.user_id);
    assert!(result_sender.is_ok());
    let local_id_sender = result_sender.unwrap();
    let expected_combined_sender =
        format!("{}{}{}", voucher.voucher_id, "t-split-ghi", &sender.user_id);
    assert_eq!(local_id_sender, get_hash(expected_combined_sender));

    // ID für den Empfänger des Teilbetrags
    let result_recipient = Wallet::calculate_local_instance_id(&voucher, &recipient.user_id);
    assert!(result_recipient.is_ok());
    let local_id_recipient = result_recipient.unwrap();
    let expected_combined_recipient = format!(
        "{}{}{}",
        voucher.voucher_id, "t-split-ghi", &recipient.user_id
    );
    assert_eq!(local_id_recipient, get_hash(expected_combined_recipient));
}

/// Testet, ob die Funktion korrekt einen Fehler zurückgibt, wenn der
/// angegebene Nutzer den Gutschein nie besessen hat.
#[test]
fn test_local_id_for_non_owner() {
    let creator = &ACTORS.alice;
    let non_owner = &ACTORS.hacker;
    let voucher = create_base_voucher(&creator.user_id, "100");

    let result = Wallet::calculate_local_instance_id(&voucher, &non_owner.user_id);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherOwnershipNotFound(_)
    ));
}

/// Stellt sicher, dass sich die `local_instance_id` ändert, wenn ein Gutschein
/// erst weggeschickt und dann wieder zurückempfangen wird.
#[test]
fn test_local_id_changes_on_round_trip() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut voucher = create_base_voucher(&alice.user_id, "100");

    // 1. Alice's initialer Zustand
    let initial_alice_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("Alice should own the voucher initially");
    assert!(!initial_alice_id.is_empty());

    // 2. Alice sendet den Gutschein an Bob
    let tx_to_bob = Transaction {
        sender_identity_signature: None,
        t_id: "t-alice-to-bob".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(),
        t_time: get_current_timestamp(),
        sender_id: Some(alice.user_id.clone()),
        recipient_id: bob.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash: None,
    };
    voucher.transactions.push(tx_to_bob);

    // 3. Überprüfen: Bob besitzt ihn jetzt, Alice nicht mehr
    let _bobs_id = Wallet::calculate_local_instance_id(&voucher, &bob.user_id)
        .expect("Bob should now own the voucher");
    let alice_result_after_send = Wallet::calculate_local_instance_id(&voucher, &alice.user_id);
    // NACH ÄNDERUNG: Alice's Aufruf muss erfolgreich sein und eine NEUE ID zurückgeben, die
    // auf der Transaktion basiert, bei der sie die Senderin war.
    assert!(alice_result_after_send.is_ok());
    let alice_archived_id = alice_result_after_send.unwrap();
    assert_ne!(
        initial_alice_id, alice_archived_id,
        "Alice's archived ID should NOT be her initial ID."
    );
    let expected_archived_string = format!(
        "{}{}{}",
        voucher.voucher_id, "t-alice-to-bob", &alice.user_id
    );
    assert_eq!(
        alice_archived_id,
        get_hash(expected_archived_string),
        "Alice's archived ID should be based on the transaction to Bob."
    );

    // 4. Bob sendet den Gutschein zurück an Alice
    let tx_to_alice = Transaction {
        sender_identity_signature: None,
        t_id: "t-bob-to-alice".to_string(),
        prev_hash: get_hash("..."),
        t_type: "".to_string(),
        t_time: get_current_timestamp(),
        sender_id: Some(bob.user_id.clone()),
        recipient_id: alice.user_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash: None,
    };
    voucher.transactions.push(tx_to_alice);

    // 5. Finale Überprüfung: Alice besitzt ihn wieder, aber mit einer NEUEN ID. Bob besitzt ihn nicht mehr.
    let final_alice_id = Wallet::calculate_local_instance_id(&voucher, &alice.user_id)
        .expect("Alice should own the voucher again");
    let bob_result_after_send = Wallet::calculate_local_instance_id(&voucher, &bob.user_id);
    // NACH ÄNDERUNG: Bob's Aufruf muss erfolgreich sein und seine ID aus der Transaktion zu ihm zurückgeben.
    assert!(bob_result_after_send.is_ok());

    // Die wichtigste Prüfung: Die neue ID von Alice muss sich von ihrer ursprünglichen ID unterscheiden.
    assert_ne!(
        initial_alice_id, final_alice_id,
        "Alice's local instance ID should be different after receiving the voucher back."
    );

    // Die neue ID muss auf der letzten Transaktion basieren.
    let expected_final_string = format!(
        "{}{}{}",
        voucher.voucher_id, "t-bob-to-alice", &alice.user_id
    );
    assert_eq!(final_alice_id, get_hash(expected_final_string));
}
