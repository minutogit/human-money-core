// tests/core_logic/lifecycle.rs

// cargo test --test test_voucher_lifecycle
//! # Integrationstests für den Gutschein-Lebenszyklus und die Sicherheit
//!
//! Diese Test-Suite deckt den gesamten Lebenszyklus eines `Voucher`-Objekts ab,
//! von der Erstellung bis zur vollständigen Validierung, und prüft kritische
//! Sicherheitsaspekte.
//!
//! #![feature(test-utils)]
//!
//! ## Abgedeckte Szenarien:
//!
//! - **Vollständiger Lebenszyklus:**
//!   - Erstellung eines Gutscheins.
//!   - Validierung im initialen Zustand (erwarteter Fehlschlag wegen fehlender Bürgen).
//!   - Erstellung und Hinzufügen von korrekten, entkoppelten Bürgen-Signaturen.
//!   - Finale, erfolgreiche Validierung des vollständigen Gutscheins.
//! - **Serialisierung:**
//!   - Korrekte Umwandlung zwischen `Voucher`-Struct und JSON-String.
//! - **Validierungs-Fehlerfälle:**
//!   - Ungültige oder manipulierte Creator-Signatur.
//!   - Fehlende, im Standard definierte Felder.
//!   - Inkonsistente Daten (z.B. falsche Nennwert-Einheit).
//!   - Nichterfüllung von Bürgen-Anforderungen (Anzahl, Geschlecht).
//! - **Sicherheitsprüfungen:**
//!   - **Replay-Angriff:** Verhindert, dass eine Bürgen-Signatur von einem Gutschein
//!     für einen anderen wiederverwendet wird.
//!   - **Daten-Manipulation:** Stellt sicher, dass eine nachträgliche Änderung
//!     an den Metadaten einer Signatur erkannt wird.
//! - **Kanonische Serialisierung:**
//!   - Überprüfung der deterministischen und sortierten JSON-Ausgabe.
//!   - Toleranz gegenüber unbekannten Feldern für Vorwärtskompatibilität.

// Wir importieren die öffentlichen Typen, die in lib.rs re-exportiert wurden.

use voucher_lib::test_utils;

use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, from_json, get_spendable_balance,
    to_canonical_json, to_json, validate_voucher_against_standard, Collateral, Creator,
    NewVoucherData, NominalValue, Transaction, Voucher, VoucherCoreError, VoucherStatus, VoucherInstance,
};
use voucher_lib::services::crypto_utils::get_hash;
use voucher_lib::error::ValidationError;
use voucher_lib::services::voucher_manager::VoucherManagerError;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use voucher_lib::test_utils::{create_custom_standard, setup_in_memory_wallet, ACTORS, MINUTO_STANDARD, SILVER_STANDARD};

// --- HELPER-FUNKTIONEN UND TESTDATEN ---

#[test]
fn test_full_creation_and_validation_cycle() {
    // 1. Setup: Lade Standard und erstelle Creator
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    // KORREKTUR: Erstelle eine benutzerdefinierte Version des Standards, um sicherzustellen,
    // dass die Aufrundungsregel für diesen Test aktiv ist. Dies macht den Test
    // unabhängig vom Zustand der globalen MINUTO_STANDARD-Variable.
    let (minuto_standard_with_rounding, standard_hash) = create_custom_standard(&MINUTO_STANDARD.0, |s| {
        s.template.fixed.round_up_validity_to = Some("end_of_year".to_string());
    });



    // 2. Erstellung
    let mut voucher = voucher_lib::test_utils::create_voucher_for_manipulation(voucher_data, &minuto_standard_with_rounding, &standard_hash, &identity.signing_key, "en");
    assert!(!voucher.voucher_id.is_empty());
    assert!(!voucher.creator.signature.is_empty());
    // Prüfe die neuen Werte, die aus dem geänderten Standard kommen.
    assert_eq!(voucher.standard_minimum_issuance_validity, "P3Y");

    // --- DEBUG-Ausgabe hinzugefügt ---
    println!("[DEBUG] Erwartetes Ende: -12-31T23:59:59");
    println!("[DEBUG] Tatsächliches valid_until: {}", voucher.valid_until);
    // --- Ende DEBUG-Ausgabe ---

    // Prüfe, ob das Gültigkeitsdatum korrekt auf das Jahresende gerundet wurde.
    assert!(voucher.valid_until.contains("-12-31T23:59:59"));
    let expected_description = "A voucher for goods or services worth 60 minutes of quality performance.";
    assert_eq!(voucher.description.trim(), expected_description.trim());

    // 3. Erste Validierung: Muss fehlschlagen, da Bürgen fehlen.
    let initial_validation_result = validate_voucher_against_standard(&voucher, &minuto_standard_with_rounding);
    assert!(matches!(
        initial_validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, .. }) if field == "guarantor_signatures"
    ));

    // 4. Simulation des Bürgenprozesses nach neuer Logik
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = voucher_lib::test_utils::create_guarantor_signature(&voucher, g1, "Hans", "1");
    let guarantor_sig_2 = voucher_lib::test_utils::create_guarantor_signature(&voucher, g2, "Gabi", "2");

    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);

    // 5. Finale Validierung (Positivfall mit Bürgen)
    let final_validation_result = validate_voucher_against_standard(&voucher, &minuto_standard_with_rounding);
    assert!(
        final_validation_result.is_ok(),
        "Final validation failed unexpectedly: {:?}",
        final_validation_result.err()
    );
}

#[test]
fn test_serialization_deserialization() {
    // 1. Erstelle einen Gutschein
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = voucher_lib::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let original_voucher = voucher_lib::test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // 2. Serialisiere zu JSON
    let json_string = to_json(&original_voucher).unwrap();

    // 3. Deserialisiere zurück
    let deserialized_voucher: Voucher = from_json(&json_string).unwrap();

    // 4. Vergleiche die Objekte
    assert_eq!(original_voucher, deserialized_voucher);
}

#[test]
fn test_validation_fails_on_invalid_signature() {
    // 1. Erstelle einen gültigen Gutschein
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = voucher_lib::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = voucher_lib::test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Füge die benötigten Bürgen hinzu, um den Gutschein valide zu machen, BEVOR wir ihn manipulieren.
    // Ansonsten würde die Validierung bereits an den fehlenden Bürgen scheitern.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    let guarantor_sig_1 = voucher_lib::test_utils::create_guarantor_signature(&voucher, g1, "Guarantor1", "1");
    let guarantor_sig_2 = voucher_lib::test_utils::create_guarantor_signature(&voucher, g2, "Guarantor2", "2");
    voucher.guarantor_signatures.push(guarantor_sig_1);
    voucher.guarantor_signatures.push(guarantor_sig_2);
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // 2. Manipuliere die Signatur
    voucher.creator.signature = "invalid_signature_string_12345".to_string();

    // 3. Validierung sollte fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(validation_result.is_err());
    // Wir erwarten einen Fehler beim Dekodieren der Signatur, da sie kein gültiges Base58 ist.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(_))
    ));
}

#[test]
fn test_validation_fails_on_missing_required_field() {
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = voucher_lib::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, _standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // 2. Manipuliere den Standard zur Laufzeit, um eine content_rule hinzuzufügen,
    // die das Vorhandensein des optionalen Feldes `creator.phone` erzwingt.
    let mut standard = minuto_standard.clone();
    let validation = standard.validation.get_or_insert_with(Default::default);
    let content_rules = validation.content_rules.get_or_insert_with(Default::default);
    // Um die Existenz eines Feldes zu erzwingen, verwenden wir eine Regex-Regel.
    let regex_patterns = content_rules.regex_patterns.get_or_insert_with(Default::default);
    regex_patterns.insert("creator.phone".to_string(), ".+".to_string()); // Muss mind. 1 Zeichen enthalten

    // 3. Der Hash des modifizierten Standards muss neu berechnet und für die
    // Gutscheinerstellung verwendet werden, um einen `StandardHashMismatch` zu vermeiden.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());

    let mut voucher = voucher_lib::test_utils::create_voucher_for_manipulation(voucher_data, &standard, &new_hash, &identity.signing_key, "en");

    // Füge gültige Bürgen hinzu, damit die Validierung nicht an der Anzahl scheitert,
    // bevor die Inhaltsregel überhaupt geprüft wird.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher.guarantor_signatures.push(voucher_lib::test_utils::create_guarantor_signature(&voucher, g1, "G1", "1"));
    voucher.guarantor_signatures.push(voucher_lib::test_utils::create_guarantor_signature(&voucher, g2, "G2", "2"));

    // 4. Validierung sollte mit `PathNotFound` fehlschlagen, da das Feld im Gutschein `None` ist.
    let validation_result = validate_voucher_against_standard(&voucher, &standard);
    assert!(validation_result.is_err());
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::PathNotFound { path, .. }) if path == "creator.phone"
    ));
}

#[test]
fn test_validation_fails_on_inconsistent_unit() {
    // Erstelle einen initial gültigen Gutschein nach dem Silber-Standard.
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = voucher_lib::test_utils::create_minuto_voucher_data(creator);

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    // KORREKTUR: Der Test muss den Standard VOR der Gutscheinerstellung modifizieren,
    // um Hash-Fehler zu vermeiden.
    let mut standard_with_rule = silver_standard.clone();
    let validation = standard_with_rule.validation.get_or_insert_with(Default::default);
    let content_rules = validation.content_rules.get_or_insert_with(Default::default);
    let fixed_fields = content_rules.fixed_fields.get_or_insert_with(Default::default);
    fixed_fields.insert("nominal_value.unit".to_string(), serde_json::json!(silver_standard.template.fixed.nominal_value.unit));

    // Hash des modifizierten Standards berechnen.
    let mut standard_to_hash = standard_with_rule.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());

    // Erstelle den Gutschein mit dem ORIGINALEN Standard, der eine korrekte Einheit setzt.
    let mut voucher = create_voucher(voucher_data, silver_standard, standard_hash, &identity.signing_key, "en").unwrap();

    // Manipuliere die Einheit NACH der Erstellung, um einen inkonsistenten Zustand zu erzeugen.
    voucher.nominal_value.unit = "EUR".to_string();
    // WICHTIG: Aktualisiere den Hash im Gutschein, damit die Validierung nicht am Hash-Mismatch scheitert.
    voucher.voucher_standard.standard_definition_hash = new_hash;

    // Damit die Validierung gegen den modifizierten Standard nicht am Hash scheitert,
    // müssen wir den Gutschein neu signieren.
    let mut voucher_to_sign = voucher.clone();
    voucher_to_sign.creator.signature = "".to_string();
    voucher_to_sign.voucher_id = "".to_string();
    voucher_to_sign.transactions.clear();
    let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
    let new_sig = crypto_utils::sign_ed25519(&identity.signing_key, hash.as_bytes());
    voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

    // Validierung sollte wegen der Einheit fehlschlagen
    let validation_result = validate_voucher_against_standard(&voucher, &standard_with_rule);
    assert!(validation_result.is_err());
    // This is now covered by the generic `content_rules` validation.
    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::FieldValueMismatch { field, .. }) if field == "nominal_value.unit"
    ));
}

#[test]
fn test_validation_fails_on_guarantor_count() {
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = self::test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Der erstellte Gutschein hat 0 Bürgen, der Standard erfordert aber 2
    voucher.guarantor_signatures.clear();

    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        // Die neue, präzisere Fehlermeldung wird erwartet.
        VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min: _, max: _, found: _ }) => {
            // Korrekter Fehlertyp
            assert_eq!(field, "guarantor_signatures");
        }
        e => panic!("Expected CountOutOfBounds error, but got {:?}", e),
    }
}

// --- NEUE TESTS FÜR KANONISCHE SERIALISIERUNG ---

#[test]
fn test_canonical_json_is_deterministic_and_sorted() {
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let data1 = self::test_utils::create_minuto_voucher_data(creator.clone());
    let data2 = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Wir fügen eine winzige Pause ein, um sicherzustellen, dass die Zeitstempel
    // und somit die Hashes sich auf jeden Fall unterscheiden.
    let voucher1 = self::test_utils::create_voucher_for_manipulation(data1, minuto_standard, standard_hash, &identity.signing_key, "en");
    std::thread::sleep(std::time::Duration::from_micros(10));
    let voucher2 = self::test_utils::create_voucher_for_manipulation(data2, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Verifiziere, dass die Gutscheine NICHT identisch sind, da ihre Zeitstempel
    // und die daraus abgeleiteten Felder (IDs, Signaturen) sich unterscheiden müssen.
    assert_ne!(
        voucher1, voucher2,
        "Vouchers should be different due to unique timestamps"
    );

    // Teste die kanonische Serialisierung an einem statischen Teil des Gutscheins.
    // Das Ergebnis muss immer alphabetisch sortierte Schlüssel haben,
    // z.B. "abbreviation" vor "amount".
    let canonical_json = to_canonical_json(&voucher1.nominal_value).unwrap();

    // Erzeuge den Erwartungswert dynamisch aus dem geladenen Standard,
    // anstatt einen hartkodierten String zu verwenden.
    let expected_json = format!(
        r#"{{"abbreviation":"{}","amount":"60","description":"Qualitative Leistung","unit":"{}"}}"#,
        minuto_standard.metadata.abbreviation, minuto_standard.template.fixed.nominal_value.unit
    );
    assert_eq!(canonical_json, expected_json);
}

#[test]
fn test_validation_succeeds_with_extra_fields_in_json() {
    // 1. Erstelle einen VOLLSTÄNDIG gültigen Gutschein, inklusive der benötigten Bürgen.
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let voucher_data = self::test_utils::create_minuto_voucher_data(creator);

    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut valid_voucher = self::test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Füge die für den Minuto-Standard erforderlichen Bürgen hinzu.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let guarantor_sig_1 = self::test_utils::create_guarantor_signature(&valid_voucher, g1, "Guarantor1", "1");
    let guarantor_sig_2 = self::test_utils::create_guarantor_signature(&valid_voucher, g2, "Guarantor2", "2");
    valid_voucher.guarantor_signatures.push(guarantor_sig_1);
    valid_voucher.guarantor_signatures.push(guarantor_sig_2);

    // Stelle sicher, dass der Gutschein jetzt gültig ist, bevor wir ihn modifizieren.
    assert!(validate_voucher_against_standard(&valid_voucher, minuto_standard).is_ok());

    let mut voucher_as_value: serde_json::Value = serde_json::to_value(&valid_voucher).unwrap();

    // 2. Füge ein unbekanntes Feld zum JSON-Objekt hinzu.
    // Dies simuliert einen Gutschein, der von einer neueren Software-Version erstellt wurde.
    voucher_as_value
        .as_object_mut()
        .unwrap()
        .insert("unknown_future_field".to_string(), serde_json::json!("some_data"));

    // Füge auch ein unbekanntes Feld in ein verschachteltes Objekt ein.
    voucher_as_value
        .get_mut("creator")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "creator_metadata".to_string(),
            serde_json::json!({"rating": 5}),
        );

    let json_with_extra_fields = serde_json::to_string(&voucher_as_value).unwrap();

    // 3. Deserialisiere diesen JSON-String. `serde` sollte die unbekannten Felder ignorieren.
    let deserialized_voucher: Voucher = from_json(&json_with_extra_fields).unwrap();

    // 4. Der deserialisierte Gutschein sollte exakt dem Original entsprechen, da die
    // zusätzlichen Felder verworfen wurden.
    assert_eq!(valid_voucher, deserialized_voucher);

    // 5. Die Validierung muss erfolgreich sein. Die `verify_creator_signature`-Funktion
    // wird intern die kanonische Form des `deserialized_voucher` (ohne die extra Felder)
    // berechnen, und diese muss mit der ursprünglichen Signatur übereinstimmen.
    let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);

    assert!(
        validation_result.is_ok(),
        "Validation failed unexpectedly with extra fields: {:?}",
        validation_result.err()
    );
}

// --- NEUE TESTS FÜR SPLIT-TRANSAKTIONEN ---

#[test]
fn test_split_transaction_cycle_and_balance_check() {
    // 1. Setup: Silber-Standard, da er teilbar ist und keine Bürgen benötigt.
    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    assert!(silver_standard.template.fixed.is_divisible);

    // 2. Erstelle Sender und Empfänger
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    // 3. Erstelle einen Gutschein mit dem Wert 100.0000 - wir passen die Daten von `create_minuto_voucher_data` an.
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "100.0000".to_string();

    let initial_voucher = create_voucher(voucher_data, silver_standard, standard_hash, &sender.signing_key, "en").unwrap();

    // 4. Überprüfe den initialen Zustand und das Guthaben
    assert!(validate_voucher_against_standard(&initial_voucher, silver_standard).is_ok());
    let initial_balance = get_spendable_balance(&initial_voucher, &sender.user_id, silver_standard).unwrap();
    assert_eq!(initial_balance, dec!(100.0000));

    // 5. Führe eine Split-Transaktion durch: Sende 30.5000 an den Empfänger
    let split_amount = "30.5000";
    let voucher_after_split = create_transaction(
        &initial_voucher,
        &SILVER_STANDARD.0,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        split_amount,
    )
        .unwrap();

    // 6. Validiere den Gutschein nach dem Split
    let validation_result = validate_voucher_against_standard(&voucher_after_split, silver_standard);
    assert!(
        validation_result.is_ok(),
        "Validation after split failed: {:?}",
        validation_result.err()
    );
    assert_eq!(voucher_after_split.transactions.len(), 2);
    assert_eq!(
        voucher_after_split.transactions.last().unwrap().t_type,
        "split"
    );

    // 7. Überprüfe die Guthaben beider Parteien
    let sender_balance_after_split =
        get_spendable_balance(&voucher_after_split, &sender.user_id, silver_standard).unwrap();
    let recipient_balance_after_split =
        get_spendable_balance(&voucher_after_split, &recipient.user_id, silver_standard).unwrap();

    assert_eq!(sender_balance_after_split, dec!(69.5000)); // 100.0000 - 30.5000
    assert_eq!(recipient_balance_after_split, dec!(30.5000));
}

#[test]
fn test_split_fails_on_insufficient_funds() {
    // Setup wie oben
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "50.0".to_string(); // Initialwert 50

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = create_voucher(voucher_data, silver_standard, standard_hash, &sender.signing_key, "en").unwrap();

    // Versuche, 50.1 zu senden (mehr als vorhanden)
    let split_result = create_transaction(
        &initial_voucher,
        silver_standard,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        "50.1",
    );

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::InsufficientFunds { .. })
    ));
}


// --- NEUER TEST FÜR DATENGESTEUERTE VALIDIERUNG (PHASE 4) ---

#[test]
fn test_fails_to_create_forbidden_transaction_type() {
    // 1. Setup: Lade den neuen Test-Standard, der "split" verbietet.
    let toml_str = include_str!("../../tests/test_data/standards/standard_no_split.toml");
    let standard: voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition =
        toml::from_str(toml_str).unwrap();

    // Da der Standard zur Laufzeit geladen wird, müssen wir den Hash für die Erstellung manuell berechnen.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let standard_hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());

    // 2. Erstelle einen Gutschein, der nach diesem Standard gültig ist.
    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let creator = Creator { id: sender.user_id.clone(), ..Default::default() };
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(creator);
    voucher_data.nominal_value.amount = "100".to_string();

    let initial_voucher = create_voucher(voucher_data, &standard, &standard_hash, &sender.signing_key, "en").unwrap();
    assert!(validate_voucher_against_standard(&initial_voucher, &standard).is_ok());

    // 3. Versuche, eine "split"-Transaktion zu erstellen, obwohl sie verboten ist.
    let split_result = create_transaction(
        &initial_voucher,
        &standard,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        "50", // Teilbetrag, der einen "split" erzwingt
    );

    // 4. Assert: Die Erstellung muss mit einem `TransactionTypeNotAllowed`-Fehler fehlschlagen.
    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::TransactionTypeNotAllowed { t_type, .. }) if t_type == "split"
    ));
}

#[test]
fn test_split_fails_on_non_divisible_voucher() {
    // Manipuliere den Standard, um ihn nicht-teilbar zu machen
    let (mut standard, _) = (SILVER_STANDARD.0.clone(), SILVER_STANDARD.1.clone());
    standard.template.fixed.is_divisible = false;
    assert!(!standard.template.fixed.is_divisible);

    // Da der Standard manipuliert wurde, muss der Konsistenz-Hash neu berechnet werden.
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let new_hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());

    let sender = &ACTORS.alice;
    let recipient = &ACTORS.bob;
    let sender_creator = Creator { id: sender.user_id.clone(), ..Default::default() };

    let mut voucher_data = self::test_utils::create_minuto_voucher_data(sender_creator);
    voucher_data.nominal_value.amount = "60.0000".to_string();

    let initial_voucher = create_voucher(voucher_data, &standard, &new_hash, &sender.signing_key, "en").unwrap();

    let split_result = create_transaction(
        &initial_voucher,
        &standard,
        &sender.user_id,
        &sender.signing_key,
        &recipient.user_id,
        "10.0",
    );

    assert!(matches!(
        split_result.unwrap_err(),
        VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)
    ));
}

#[test]
fn test_validity_duration_rules() {
    // 1. Setup
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    // 2. Testfall: Versuch, einen Gutschein mit zu kurzer Gültigkeit zu erstellen.
    // Der Minuto-Standard erfordert P3Y. Wir versuchen es mit P2Y.
    let mut short_duration_data = self::test_utils::create_minuto_voucher_data(creator.clone());
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    short_duration_data.validity_duration = Some("P2Y".to_string());
    let creation_result = create_voucher(short_duration_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    assert!(
        matches!(
            creation_result.unwrap_err(),
            VoucherCoreError::Manager(VoucherManagerError::InvalidValidityDuration(_))
        ),
        "Creation should fail with InvalidValidityDuration error"
    );

    // 3. Testfall: Erstelle einen gültigen Gutschein und manipuliere dann sein Gültigkeitsdatum.
    let valid_data = self::test_utils::create_minuto_voucher_data(creator.clone());
    let mut voucher = self::test_utils::create_voucher_for_manipulation(valid_data, minuto_standard, standard_hash, &identity.signing_key, "en");

    // Mache ihn mit Bürgen vollständig gültig, um die Datumsprüfung zu isolieren.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher.guarantor_signatures.push(self::test_utils::create_guarantor_signature(&voucher, g1, "G1", "1"));
    voucher.guarantor_signatures.push(self::test_utils::create_guarantor_signature(&voucher, g2, "G2", "2"));
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // Manipuliere das Datum
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
    let tampered_until_dt = creation_dt + chrono::Duration::days(10); // weniger als 90
    voucher.valid_until = tampered_until_dt.to_rfc3339();

    // KORREKTUR: Jede Änderung an den Gutscheindaten nach der Erstellung macht die Signatur
    // des Erstellers ungültig. Um gezielt die Gültigkeitsdauer-Regel zu testen, müssen wir
    // den Gutschein neu signieren, damit die Validierung nicht vorzeitig an einer ungültigen
    // Signatur scheitert. Die Logik hier spiegelt die in `verify_creator_signature`.
    let mut voucher_to_sign = voucher.clone();
    voucher_to_sign.creator.signature = "".to_string();
    voucher_to_sign.voucher_id = "".to_string();
    voucher_to_sign.transactions.clear();
    voucher_to_sign.guarantor_signatures.clear();
    voucher_to_sign.additional_signatures.clear();
    let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
    let new_sig = crypto_utils::sign_ed25519(&identity.signing_key, hash.as_bytes());
    voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(matches!(validation_result.unwrap_err(), VoucherCoreError::Validation(ValidationError::ValidityDurationTooShort)));

    // 4. Testfall: Nicht übereinstimmende Mindestgültigkeitsregel zwischen Gutschein und Standard
    let mut voucher2 = self::test_utils::create_voucher_for_manipulation(self::test_utils::create_minuto_voucher_data(creator.clone()), minuto_standard, standard_hash, &identity.signing_key, "en");

    // Füge gültige Bürgen hinzu, damit die Validierung nicht an der Anzahl scheitert.
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher2.guarantor_signatures.push(self::test_utils::create_guarantor_signature(&voucher2, g1, "G1", "1"));
    voucher2.guarantor_signatures.push(self::test_utils::create_guarantor_signature(&voucher2, g2, "G2", "2"));

    // Manipuliere die im Gutschein gespeicherte Regel
    voucher2.standard_minimum_issuance_validity = "P1Y".to_string(); // Standard erwartet P3Y

    // KORREKTUR: Wie im Fall davor, muss der Gutschein nach der Manipulation neu signiert werden,
    // um einen vorzeitigen Abbruch der Validierung wegen Signaturfehlers zu verhindern.
    let mut voucher_to_sign2 = voucher2.clone();
    voucher_to_sign2.creator.signature = "".to_string();
    voucher_to_sign2.voucher_id = "".to_string();
    voucher_to_sign2.transactions.clear();
    voucher_to_sign2.guarantor_signatures.clear();
    voucher_to_sign2.additional_signatures.clear();
    let hash2 = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign2).unwrap());
    let new_sig2 = crypto_utils::sign_ed25519(&identity.signing_key, hash2.as_bytes());
    voucher2.creator.signature = bs58::encode(new_sig2.to_bytes()).into_string();

    let validation_result2 = validate_voucher_against_standard(&voucher2, minuto_standard);
    assert!(matches!(
        validation_result2.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::MismatchedMinimumValidity { .. })
    ));
}

// --- NEUE SICHERHEITSTESTS ---

#[test]
fn test_validation_fails_on_replayed_guarantor_signature() {
    // 1. Erstelle zwei verschiedene Gutscheine
    let creator1_identity = &ACTORS.alice;
    let creator1 = Creator { id: creator1_identity.user_id.clone(), ..Default::default() };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_a = self::test_utils::create_voucher_for_manipulation(
        self::test_utils::create_minuto_voucher_data(creator1), minuto_standard, standard_hash, &creator1_identity.signing_key, "en"
    );

    let creator2 = Creator { id: ACTORS.bob.user_id.clone(), ..Default::default() };
    let mut voucher_b = self::test_utils::create_voucher_for_manipulation(self::test_utils::create_minuto_voucher_data(creator2), minuto_standard, standard_hash, &ACTORS.bob.signing_key, "en");
    assert_ne!(voucher_a.voucher_id, voucher_b.voucher_id);

    // 2. Erstelle eine gültige Bürgschaft für Gutschein A
    let g1 = &ACTORS.guarantor1;
    let valid_signature_for_a = self::test_utils::create_guarantor_signature(&voucher_a, g1, "Replay", "1");

    // 3. Versuche, die Signatur von A an B anzuhängen (Replay-Angriff)
    // (Wir benötigen eine zweite "Dummy"-Signatur, um die Anforderung von 2 Bürgen zu erfüllen)
    let g2 = &ACTORS.guarantor2;
    let dummy_signature_for_b = self::test_utils::create_guarantor_signature(&voucher_b, g2, "Dummy", "2");

    voucher_b.guarantor_signatures.push(valid_signature_for_a); // Falsche Signatur
    voucher_b.guarantor_signatures.push(dummy_signature_for_b); // Korrekte Signatur

    // 4. Validierung von B muss fehlschlagen, weil die erste Signatur die falsche voucher_id referenziert.
    let validation_result = validate_voucher_against_standard(&voucher_b, minuto_standard);
    assert!(validation_result.is_err());
    match validation_result.unwrap_err() {
        VoucherCoreError::Validation(ValidationError::MismatchedVoucherIdInSignature { expected, found }) => {
            assert_eq!(expected, voucher_b.voucher_id);
            assert_eq!(found, voucher_a.voucher_id);
        }
        e => panic!("Expected MismatchedVoucherIdInSignature error, but got {:?}", e),
    }
}

#[test]
fn test_validation_fails_on_tampered_guarantor_signature() {
    // 1. Erstelle einen vollständig gültigen Gutschein
    let identity = &ACTORS.issuer;
    let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
    let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let mut voucher = self::test_utils::create_voucher_for_manipulation(
        self::test_utils::create_minuto_voucher_data(creator), minuto_standard, standard_hash, &identity.signing_key, "en"
    );

    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;

    let sig1 = self::test_utils::create_guarantor_signature(&voucher, g1, "Original", "1");
    let sig2 = self::test_utils::create_guarantor_signature(&voucher, g2, "Untampered", "2");
    voucher.guarantor_signatures.push(sig1);
    voucher.guarantor_signatures.push(sig2);
    assert!(validate_voucher_against_standard(&voucher, minuto_standard).is_ok());

    // 2. Manipuliere die Metadaten der ersten Signatur, NACHDEM sie erstellt wurde.
    let original_signature_id = voucher.guarantor_signatures[0].signature_id.clone();
    voucher.guarantor_signatures[0].first_name = "Tampered".to_string();

    // 3. Die Validierung muss nun fehlschlagen, da der Hash der Daten nicht mehr zur signature_id passt.
    let validation_result = validate_voucher_against_standard(&voucher, minuto_standard);
    assert!(matches!(validation_result.unwrap_err(), VoucherCoreError::Validation(ValidationError::InvalidSignatureId(id)) if id == original_signature_id));
}

#[test]
fn test_double_spend_detection_logic() {
    // 1. Setup: Silber-Standard, ein Ersteller (Alice) und zwei Empfänger (Bob, Frank).
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let frank = &ACTORS.charlie; // Use charlie as Frank
    let alice_creator = Creator { id: alice.user_id.clone(), ..Default::default() };

    // 2. Alice erstellt einen SILBER-Gutschein mit dem Wert 100, da dieser teilbar ist.
    let mut voucher_data = self::test_utils::create_minuto_voucher_data(alice_creator);
    voucher_data.nominal_value.amount = "100".to_string();

    // Wir verwenden hier einen Silber-Gutschein, da dieser teilbar ist und die Logik
    // des Double Spends demonstrieren soll.
    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let initial_voucher = self::test_utils::create_voucher_for_manipulation(voucher_data, silver_standard, standard_hash, &alice.signing_key, "en");
    assert!(validate_voucher_against_standard(&initial_voucher, silver_standard).is_ok());

    // 3. Alice führt eine erste, legitime Transaktion durch: Sie sendet 40 an Bob.
    let voucher_after_split = create_transaction(
        &initial_voucher, silver_standard, &alice.user_id, &alice.signing_key, &bob.user_id, "40"
    ).unwrap();
    let validation_result_1 = validate_voucher_against_standard(&voucher_after_split, silver_standard);
    assert!(
        validation_result_1.is_ok(),
        "Validation of the first legitimate transaction failed unexpectedly: {:?}",
        validation_result_1.err()
    );
    // 4. Alice betrügt: Sie nimmt den Zustand VOR der Transaktion an Bob (`initial_voucher`)
    //    und versucht, ihr ursprüngliches Guthaben von 100 erneut auszugeben, indem sie 60 an Frank sendet.
    let fraudulent_voucher = create_transaction( &initial_voucher, silver_standard, &alice.user_id, &alice.signing_key, &frank.user_id, "60").unwrap();
    let validation_result_2 = validate_voucher_against_standard(&fraudulent_voucher, silver_standard);
    assert!(validation_result_2.is_ok(), "Validation of the fraudulent (but individually valid) transaction failed unexpectedly: {:?}", validation_result_2.err());

    // 5. Verifizierung des Double Spends:
    //    Beide Gutscheine sind für sich genommen gültig, aber die zweite Transaktion in beiden
    //    basiert auf demselben Vorgänger (der `init`-Transaktion).
    let tx_to_bob = &voucher_after_split.transactions[1];
    let fraudulent_tx_to_frank = &fraudulent_voucher.transactions[1];

    // Der Beweis: Gleicher `prev_hash` und `sender_id`, aber unterschiedliche `t_id`.
    // Dies ist der Fingerabdruck, den ein Layer-2-System erkennen würde.
    assert_eq!(tx_to_bob.prev_hash, fraudulent_tx_to_frank.prev_hash, "prev_hash values must be identical to prove the double spend");
    assert_eq!(tx_to_bob.sender_id, fraudulent_tx_to_frank.sender_id, "Sender IDs must be identical");
    assert_ne!(tx_to_bob.t_id, fraudulent_tx_to_frank.t_id, "Transaction IDs must be different");

    println!("Double Spend Test: OK. prev_hash für beide Transaktionen ist: {}", tx_to_bob.prev_hash);
}

// --- Hilfsfunktionen für den Transfer-Test, um private Logik der Wallet-Fassade zu simulieren ---

/// Berechnet das Guthaben eines bestimmten Nutzers nach einer spezifischen Transaktionshistorie.
fn get_balance_at_transaction(
    history: &[Transaction],
    user_id: &str,
    initial_amount: &str,
) -> Decimal {
    let mut current_balance = Decimal::ZERO;
    let total_amount = Decimal::from_str_exact(initial_amount).unwrap_or_default();

    for tx in history {
        let tx_amount = Decimal::from_str_exact(&tx.amount).unwrap_or_default();
        if tx.recipient_id == user_id {
            if tx.t_type == "init" {
                current_balance = total_amount;
            } else {
                current_balance += tx_amount;
            }
        } else if tx.sender_id == user_id {
            if let Some(remaining_str) = &tx.sender_remaining_amount {
                if let Ok(remaining_amount) = Decimal::from_str_exact(remaining_str) {
                    current_balance = remaining_amount;
                } else {
                    current_balance = Decimal::ZERO;
                }
            } else {
                current_balance = Decimal::ZERO;
            }
        }
    }
    current_balance
}

/// Berechnet eine deterministische, lokale ID für eine Gutschein-Instanz.
fn calculate_local_instance_id(voucher: &Voucher, profile_owner_id: &str) -> String {
    let mut defining_transaction_id: Option<String> = None;

    for i in (0..voucher.transactions.len()).rev() {
        let history_slice = &voucher.transactions[..=i];
        let balance =
            get_balance_at_transaction(history_slice, profile_owner_id, &voucher.nominal_value.amount);

        if balance > Decimal::ZERO {
            defining_transaction_id = Some(voucher.transactions[i].t_id.clone());
            break;
        }
    }

    let t_id = defining_transaction_id.expect("Voucher must be owned by the user.");
    let combined_string = format!("{}{}{}", voucher.voucher_id, t_id, profile_owner_id);
    get_hash(combined_string)
}


#[test]
fn test_secure_voucher_transfer_via_encrypted_bundle() {
    // --- 1. SETUP ---
    let alice_identity = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);
    let bob_identity = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(bob_identity);

    // --- 2. VOUCHER CREATION by Alice ---
    let alice_creator = Creator {
        id: alice_identity.user_id.clone(),
        first_name: "Alice".to_string(),
        // Restliche Felder für den Test gekürzt
        ..Default::default()
    };

    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: NominalValue { amount: "500".to_string(), ..self::test_utils::create_minuto_voucher_data(alice_creator.clone()).nominal_value },
        collateral: Collateral::default(),
        creator: alice_creator,
    };

    let (silver_standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let voucher = self::test_utils::create_voucher_for_manipulation(voucher_data, silver_standard, standard_hash, &alice_identity.signing_key, "en");
    let local_id = calculate_local_instance_id(&voucher, &alice_identity.user_id);

    // Alice adds the new voucher to her wallet's store
    alice_wallet.voucher_store.vouchers.insert(local_id.clone(), VoucherInstance {
        voucher,
        status: VoucherStatus::Active,
        local_instance_id: local_id.clone(),
    });
    assert!(alice_wallet.voucher_store.vouchers.contains_key(&local_id));

    // --- 3. SECURE TRANSFER from Alice to Bob ---
    // Anstatt die Transaktion manuell zu erstellen und zu bündeln, verwenden wir die
    // öffentliche `create_transfer`-Methode, die die Zustandsverwaltung (Archivierung) korrekt durchführt.
    let request = voucher_lib::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![voucher_lib::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "500".to_string(), // Sende den vollen Betrag
        }],
        notes: Some("Here is the voucher I promised!".to_string()),
        sender_profile_name: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());

    let voucher_lib::wallet::CreateBundleResult { bundle_bytes: encrypted_bundle_for_bob, .. } = alice_wallet.execute_multi_transfer_and_bundle(
        &alice_identity,
        &standards,
        request,
        None::<&dyn voucher_lib::archive::VoucherArchive>,
    ).unwrap();

    // NACH ÄNDERUNG: Die alte Instanz wird gelöscht. Es sollte nur noch eine neue, archivierte Instanz im Wallet sein.
    assert_eq!(alice_wallet.voucher_store.vouchers.len(), 1, "Alice's wallet should contain exactly one (archived) voucher instance.");
    let instance = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert!(matches!(instance.status, VoucherStatus::Archived), "The remaining voucher's status should be Archived after sending.");
    assert_eq!(
        alice_wallet.bundle_meta_store.history.len(),
        1,
        "Alice's bundle history should contain one entry."
    );

    // --- 4. RECEIPT AND PROCESSING by Bob ---
    // KORREKTUR: Die Map muss den Standard enthalten, der verarbeitet wird.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(SILVER_STANDARD.0.metadata.uuid.clone(), SILVER_STANDARD.0.clone());
    bob_wallet
        .process_encrypted_transaction_bundle(&bob_identity, &encrypted_bundle_for_bob, None::<&dyn voucher_lib::archive::VoucherArchive>, &standards_for_bob)
        .unwrap();

    // --- 5. VERIFICATION ---
    assert_eq!(bob_wallet.voucher_store.vouchers.len(), 1, "Bob's wallet should now have one voucher.");
    assert_eq!(
        bob_wallet.bundle_meta_store.history.len(),
        1,
        "Bob's bundle history should contain one entry."
    );

    // Berechne die lokale ID für Bobs Instanz des Gutscheins.
    let received_voucher = &bob_wallet.voucher_store.vouchers.values().next().unwrap().voucher;
    let bob_local_id = calculate_local_instance_id(received_voucher, &bob_identity.user_id);
    assert!(bob_wallet.voucher_store.vouchers.contains_key(&bob_local_id), "Voucher with correct local ID should be in Bob's wallet.");

    // Füge die finale Überprüfung hinzu, ob der empfangene Gutschein auch wirklich gültig ist.
    // KORREKTUR: Verwende ein assert!, das im Fehlerfall die genaue ValidationError ausgibt.
    let final_validation_result = validate_voucher_against_standard(received_voucher, silver_standard);
    assert!(
        final_validation_result.is_ok(),
        "Validation of the received voucher failed: {:?}",
        final_validation_result.err()
    );
    println!("SUCCESS: Voucher was securely transferred from Alice to Bob via an encrypted bundle.");
}