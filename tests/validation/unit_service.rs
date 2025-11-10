//! # tests/validation/unit_service.rs
//!
//! Unit-Tests für die einzelnen, datengesteuerten Funktionen
//! der Validierungs-Engine im `voucher_validation`-Service.

use voucher_lib::error::ValidationError;
use voucher_lib::models::voucher::{
    NominalValue, Transaction, Voucher, VoucherSignature,
};
use voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition;
use voucher_lib::services::voucher_validation;
use std::fs;

// --- Test-Hilfsfunktionen ---

/// Lädt einen Test-Standard aus dem `test_data`-Verzeichnis.
fn load_test_standard(file_name: &str) -> VoucherStandardDefinition {
    let path = format!("tests/test_data/standards/{}", file_name);
    let toml_str = fs::read_to_string(path).expect("Failed to read test standard file");
    toml::from_str(&toml_str).expect("Failed to parse test standard TOML")
}

/// Erstellt einen minimalen, leeren Gutschein für Testzwecke.
fn create_base_voucher() -> Voucher {
    let mut voucher = Voucher::default();
    voucher.nominal_value = NominalValue {
        unit: "EUR".to_string(),
        amount: "50.00".to_string(),
        ..Default::default()
    };
    voucher.description = "INV-123456".to_string();
    voucher.transactions.push(Transaction::default());
    voucher
}

// --- Test-Module ---
/// Prüft die `validate_transaction_count`-Logik.
#[cfg(test)]
mod transaction_count_validation {
    use super::*;

    #[test]
    fn test_validate_transaction_count_when_valid_then_succeeds() {
        let standard = load_test_standard("standard_strict_counts.toml");
        let mut voucher = create_base_voucher();
        // standard_strict_counts.toml [validation.counts] transactions = { min = 1, max = 2 }
        // create_base_voucher() fügt 1 Transaktion hinzu.

        let count_rules = standard.validation.as_ref().unwrap().counts.as_ref().unwrap();
        let result = voucher_validation::validate_transaction_count(&voucher, count_rules);

        assert!(result.is_ok());

        // Füge eine zweite Transaktion hinzu (max = 2)
        voucher.transactions.push(Transaction::default());
        let result_at_max = voucher_validation::validate_transaction_count(&voucher, count_rules);
        assert!(result_at_max.is_ok());

        // Füge eine dritte Transaktion hinzu (verletzt max = 2)
        voucher.transactions.push(Transaction::default());
        let result_above_max = voucher_validation::validate_transaction_count(&voucher, count_rules);
        assert!(matches!(
            result_above_max.err().unwrap(),
            ValidationError::CountOutOfBounds { field, min, max, found }
            if field == "transactions" && min == 1 && max == 2 && found == 3
        ));
    }
}

/// Prüft die `validate_content_rules`-Logik.
#[cfg(test)]
mod content_rules_validation {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_content_rules_when_content_is_valid_then_succeeds() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        // Werte entsprechen den Regeln in der TOML
        voucher.divisible = false;
        voucher.nominal_value.unit = "EUR".to_string();
        voucher.nominal_value.amount = "50.00".to_string();
        voucher.description = "INV-999888".to_string();

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_content_rules_when_fixed_field_is_wrong_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.unit = "USD".to_string(); // Falsch, Standard erfordert EUR

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldValueMismatch { field, expected, found }
            if field == "nominal_value.unit" && expected == json!("EUR") && found == json!("USD")
        ));
    }

    #[test]
    fn test_validate_content_rules_when_value_is_disallowed_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.nominal_value.amount = "75.00".to_string(); // Nicht in der erlaubten Liste

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldValueNotAllowed { field, found, .. }
            if field == "nominal_value.amount" && found == json!("75.00")
        ));
    }

    #[test]
    fn test_validate_content_rules_when_regex_mismatches_then_fails() {
        let standard = load_test_standard("standard_content_rules.toml");
        let mut voucher = create_base_voucher();
        voucher.description = "INVALID-123".to_string(); // Passt nicht zum Regex-Muster

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let content_rules = standard.validation.as_ref().unwrap().content_rules.as_ref().unwrap();
        let result = voucher_validation::validate_content_rules(&voucher_json, content_rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::FieldRegexMismatch { field, pattern: _, found }
            if field == "description" && found == "INVALID-123"
        ));
    }
}

/// Prüft die `validate_field_group_rules`-Logik.
#[cfg(test)]
mod field_group_rules_validation {
    use super::*;
    use serde_json::json;

    /// Erstellt eine Test-Signatur mit einem Geschlecht (für Gender-Tests).
    fn create_test_signature_with_gender(gender: &str) -> VoucherSignature {
        let sig = VoucherSignature {
            gender: Some(gender.to_string()),
            role: "other_role".to_string(), // Rolle ist für diesen Test irrelevant
            ..Default::default()
        };
        sig
    }

    #[test]
    fn test_validate_field_group_rules_when_counts_are_correct_then_succeeds() {
        // Dieser Test prüft `gender`-Regeln
        let standard = load_test_standard("standard_field_group_rules.toml");
        let mut voucher = create_base_voucher();
        // Regel: 1x "A", 2x "B"
        voucher.signatures = vec![
            create_test_signature_with_gender("A"),
            create_test_signature_with_gender("B"),
            create_test_signature_with_gender("B"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(result.is_ok(), "Validation failed unexpectedly: {:?}", result.err());
    }

    #[test]
    fn test_validate_field_group_rules_when_value_count_is_wrong_then_fails() {
        // Dieser Test prüft `gender`-Regeln
        let standard = load_test_standard("standard_field_group_rules.toml");
        let mut voucher = create_base_voucher();
        // Regel: 1x "A", 2x "B".
        // Setup: 2x "A", 1x "B". (Beide Regeln sind verletzt)
        voucher.signatures = vec![
            create_test_signature_with_gender("A"),
            create_test_signature_with_gender("A"),
            create_test_signature_with_gender("B"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        let err = result.err().unwrap();
        assert!(matches!(
            err,
            // HÄRTUNG: Die erste Regel, die fehlschlägt, ist `value = "A"` (erwartet 1, gefunden 2).
            ValidationError::FieldValueCountOutOfBounds { path, field, value, min, max, found }
            if path == "signatures" && field == "gender" && value == "A" && min == 1 && max == 1 && found == 2
        ));
    }

    /// Erstellt eine Test-Signatur mit einer bestimmten Rolle.
    fn create_test_signature_with_role(role: &str) -> VoucherSignature {
        let sig = VoucherSignature {
            role: role.to_string(),
            gender: Some("0".to_string()), // Geschlecht ist für diesen Test irrelevant
            ..Default::default()
        };
        sig
    }

    #[test]
    fn test_validate_field_group_rules_when_other_values_exist_but_required_are_met_then_succeeds() {
        // Lade den Standard, der `field="role"` prüft.
        let standard = load_test_standard("standard_conflicting_rules.toml");
        let mut voucher = create_base_voucher();
        // Regeln: "guarantor": { min = 3, max = 3 }, "A": { min = 2, max = 2 }, "B": { min = 2, max = 2 }
        // Dieses Setup erfüllt alle Regeln.
        voucher.signatures = vec![
            create_test_signature_with_role("A"),
            create_test_signature_with_role("A"),
            create_test_signature_with_role("B"),
            create_test_signature_with_role("B"),
            create_test_signature_with_role("guarantor"),
            create_test_signature_with_role("guarantor"),
            create_test_signature_with_role("guarantor"),
        ];

        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(result.is_ok(), "Validation failed unexpectedly: {:?}", result.err());
    }

    #[test]
    fn test_validate_field_group_rules_when_path_is_not_found_then_fails() {
        let standard = load_test_standard("standard_path_not_found.toml");
        let voucher = create_base_voucher(); // Hat kein "non_existent_field"
        let voucher_json = serde_json::to_value(&voucher).unwrap();
        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::PathNotFound { path } if path == "non_existent_field"
        ));
    }

    #[test]
    fn test_validate_field_group_rules_when_path_is_not_an_array_then_fails() {
        // Lade einen beliebigen Standard, der 'signatures' prüft.
        let standard = load_test_standard("standard_conflicting_rules.toml");
        let voucher_json = json!({
            "signatures": "this should be an array"
        });

        let rules = standard.validation.as_ref().unwrap().field_group_rules.as_ref().unwrap();
        let result = voucher_validation::validate_field_group_rules(&voucher_json, rules);

        assert!(matches!(
            result.err().unwrap(),
            ValidationError::InvalidDataType { path, expected }
            if path == "signatures" && expected == "Array"
        ));
    }
}