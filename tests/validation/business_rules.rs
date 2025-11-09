//! # tests/validation/business_rules.rs
//!
//! Integrationstests, die die korrekte Anwendung von komplexen Geschäftsregeln
//! und die logische Konsistenz eines `Voucher`-Objekts verifizieren.

// Wir importieren die oeffentlichen Typen, die in lib.rs re-exportiert wurden.
use voucher_lib::{
    create_transaction, create_voucher, crypto_utils, to_canonical_json, validate_voucher_against_standard, Creator, NewVoucherData, NominalValue,
    Transaction, VoucherCoreError,
};
use voucher_lib::error::ValidationError;
use voucher_lib::test_utils;

use voucher_lib::test_utils::{
    create_female_guarantor_signature,
    create_male_guarantor_signature, create_voucher_for_manipulation, resign_transaction, ACTORS,
    MINUTO_STANDARD, SILVER_STANDARD,
};

/// Prüft grundlegende strukturelle und logische Regeln.
#[cfg(test)]
mod structural_integrity {
    use super::*;

    #[test]
    fn test_validate_voucher_when_standard_uuid_mismatches_then_fails() {
        let (minuto_standard, minuto_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let silver_standard = &SILVER_STANDARD.0;

        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };

        let mut voucher = create_voucher_for_manipulation(voucher_data, minuto_standard, minuto_hash, &creator_identity.signing_key, "en");
        voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
        voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

        let validation_result = validate_voucher_against_standard(&voucher, silver_standard);

        assert!(matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::StandardUuidMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_voucher_when_date_logic_is_invalid_then_fails() {
        let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };

        let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");
        voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
        voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

        voucher.valid_until = "2020-01-01T00:00:00Z".to_string();

        let mut voucher_to_sign = voucher.clone();
        voucher_to_sign.creator.signature = "".to_string();
        voucher_to_sign.voucher_id = "".to_string();
        voucher_to_sign.transactions.clear();
        voucher_to_sign.guarantor_signatures.clear();
        voucher_to_sign.additional_signatures.clear();
        let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
        let new_sig = crypto_utils::sign_ed25519(&creator_identity.signing_key, hash.as_bytes());
        voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

        let validation_result = validate_voucher_against_standard(&voucher, standard);

        assert!(
            matches!(
                validation_result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::InvalidDateLogic { .. })
            ),
        );
    }

    #[test]
    fn test_validate_voucher_when_amount_string_is_malformed_then_fails() {
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "60".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let mut voucher = create_voucher(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en").unwrap();
        voucher.transactions[0].amount = "not-a-number".to_string();
        let tx = voucher.transactions[0].clone();
        voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);
        let validation_result = validate_voucher_against_standard(&voucher, standard);
        assert!(
            matches!(
                validation_result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::InvalidAmountFormat { .. })
            ),
            "Validation should fail with a DecimalConversionError."
        );
    }

    #[test]
    fn test_validate_voucher_when_transaction_time_order_is_invalid_then_fails() {
        let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
        let sender = &ACTORS.sender;
        let recipient = &ACTORS.recipient1;
        let voucher_data = NewVoucherData {
            creator: Creator { id: sender.user_id.clone(), ..Default::default() },
            nominal_value: NominalValue { amount: "60.0000".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let initial_voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &sender.signing_key, "en");
        let mut voucher_after_split = create_transaction(&initial_voucher, standard, &sender.user_id, &sender.signing_key, &recipient.user_id, "10.0000").unwrap();

        let invalid_second_time = "2020-01-01T00:00:00Z";
        voucher_after_split.transactions[1].t_time = invalid_second_time.to_string();
        let tx = voucher_after_split.transactions[1].clone();
        voucher_after_split.transactions[1] = resign_transaction(tx, &sender.signing_key);

        let validation_result = validate_voucher_against_standard(&voucher_after_split, standard);
        assert!(
            matches!(
                validation_result.unwrap_err(),
                VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })
            )
        );
    }
}

/// Prüft Regeln bezüglich der Anzahl von Elementen (Bürgen, Transaktionen etc.).
#[cfg(test)]
mod counts_and_group_rules {
    use super::*;
    use test_utils::{generate_signed_standard_toml, create_guarantor_signature_with_time};
    use voucher_lib::services::standard_manager::verify_and_parse_standard;

    fn load_toml_standard(path: &str) -> (voucher_lib::VoucherStandardDefinition, String) {
        let toml_str = generate_signed_standard_toml(path);
        verify_and_parse_standard(&toml_str).unwrap()
    }

    #[test]
    fn test_validate_voucher_when_transaction_count_exceeds_max_then_fails() {
        // Dieser Standard erlaubt maximal 2 Transaktionen.
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_strict_counts.toml");
        let creator_identity = &ACTORS.alice;
        let recipient = &ACTORS.bob;

        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };

        let mut voucher = create_voucher_for_manipulation(
            voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en",
        );
        voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));

        let mut voucher_after_tx1 = create_transaction(&voucher, &standard, &creator_identity.user_id, &creator_identity.signing_key, &recipient.user_id, "100").unwrap();
        voucher_after_tx1.transactions.push(Transaction::default());

        let result = validate_voucher_against_standard(&voucher_after_tx1, &standard);

        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min: 1, max: 2, found: 3 })
            if field == "transactions"
        ));
    }

    #[test]
    fn test_validate_voucher_when_count_and_group_rules_conflict_then_fails_correctly() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_conflicting_rules.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };
        let base_voucher = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");

        // Fall 1: Erfülle die `field_group_rules` (4 Bürgen), verletze aber die `counts`-Regel (max 3)
        let mut voucher1 = base_voucher.clone();
        voucher1.guarantor_signatures = vec![
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.guarantor1, "G1", "A", "2026-01-01T12:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.guarantor2, "G2", "A", "2026-01-01T13:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.male_guarantor, "G3", "B", "2026-01-01T14:00:00Z"),
            create_guarantor_signature_with_time(&voucher1.voucher_id, &ACTORS.female_guarantor, "G4", "B", "2026-01-01T15:00:00Z"),
        ];

        let result1 = validate_voucher_against_standard(&voucher1, &standard);
        assert!(matches!(
            result1.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::CountOutOfBounds { field, min: 3, max: 3, found: 4 }) if field == "guarantor_signatures"
        ));

        // Fall 2: Erfülle die `counts`-Regel (3 Bürgen), verletze aber die `field_group_rules` (braucht 2x "B")
        let mut voucher2 = base_voucher.clone();
        voucher2.guarantor_signatures = vec![
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.guarantor1, "G1", "A", "2026-01-01T12:00:00Z"),
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.guarantor2, "G2", "A", "2026-01-01T13:00:00Z"),
            create_guarantor_signature_with_time(&voucher2.voucher_id, &ACTORS.male_guarantor, "G3", "B", "2026-01-01T14:00:00Z"),
        ];

        let result2 = validate_voucher_against_standard(&voucher2, &standard);
        assert!(matches!(
            result2.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FieldValueCountOutOfBounds { value, min: 2, max: 2, found: 1, .. }) if value == "B"
        ));
    }
}

/// Prüft Regeln bezüglich erforderlicher Signaturen.
#[cfg(test)]
mod signature_requirements {
    use super::*;
    use test_utils::generate_signed_standard_toml;
    use voucher_lib::services::standard_manager::verify_and_parse_standard;
    use voucher_lib::error::ValidationError;

    fn load_toml_standard(path: &str) -> (voucher_lib::VoucherStandardDefinition, String) {
        let toml_str = generate_signed_standard_toml(path);        verify_and_parse_standard(&toml_str).unwrap()
    }
    fn create_additional_signature(
        voucher: &voucher_lib::Voucher, signer: &voucher_lib::UserIdentity, description: &str,
    ) -> voucher_lib::models::voucher::AdditionalSignature {
        use ed25519_dalek::Signer;
        use voucher_lib::services::{crypto_utils, utils};
        let mut signature_obj = voucher_lib::models::voucher::AdditionalSignature {
            voucher_id: voucher.voucher_id.clone(), signer_id: signer.user_id.clone(),
            signature_time: utils::get_current_timestamp(), description: description.to_string(),
            ..Default::default()
        };
        let mut obj_to_hash = signature_obj.clone();
        obj_to_hash.signature_id = "".to_string();
        let signature_id = crypto_utils::get_hash(utils::to_canonical_json(&obj_to_hash).unwrap());
        let signature = signer.signing_key.sign(signature_id.as_bytes());
        let signature_b58 = bs58::encode(signature.to_bytes()).into_string();
        signature_obj.signature_id = signature_id;
        signature_obj.signature = signature_b58;
        signature_obj
    }

    #[test]
    fn test_validate_voucher_when_mandatory_signature_is_missing_then_fails() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_required_signatures.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };
        // KORREKTUR: Nach dem Refactoring validiert `create_voucher` nicht mehr selbst.
        // 1. Wir erwarten, dass die Erstellung des (unvollständigen) Gutscheins erfolgreich ist.
        let voucher = create_voucher(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en").unwrap();

        // 2. Wir validieren den Gutschein in einem separaten Schritt und erwarten hier den Fehler.
        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { .. })
        ));
    }

    #[test]
    fn test_validate_voucher_when_signature_description_mismatches_then_fails() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_strict_sig_description.toml");
        let creator_identity = &ACTORS.alice;
        let approver = &ACTORS.bob;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };
        let mut voucher = create_voucher_for_manipulation(
            voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en",
        );
        let signature_with_wrong_desc = create_additional_signature(&voucher, approver, "Some other description");
        voucher.additional_signatures.push(signature_with_wrong_desc);
        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { role })
            if role == "Official Approval by Bob"
        ));
    }

    #[test]
    fn test_validate_voucher_when_signature_description_is_correct_then_succeeds() {
        // SETUP: Lade den Basis-Standard
        let (base_standard, _) = load_toml_standard("tests/test_data/standards/standard_strict_sig_description.toml");
        let creator = &ACTORS.alice;
        let approver = &ACTORS.bob;

        // KORREKTUR: Erstelle einen neuen, angepassten Standard zur Laufzeit,
        // der explizit `ACTORS.bob` als erlaubten Unterzeichner definiert.
        let (custom_standard, custom_hash) = test_utils::create_custom_standard(&base_standard, |s| {
            s.validation.as_mut().unwrap()
                .required_signatures.as_mut().unwrap()
                .iter_mut()
                .find(|rule| rule.role_description == "Official Approval by Bob")
                .unwrap().allowed_signer_ids = vec![approver.user_id.clone()];
        });

        let voucher_data = NewVoucherData {
            creator: Creator { id: creator.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        };
        let mut voucher = create_voucher_for_manipulation(voucher_data, &custom_standard, &custom_hash, &creator.signing_key, "en");
        let correct_signature = create_additional_signature(&voucher, approver, "Official Approval 2025");
        voucher.additional_signatures.push(correct_signature);
        assert!(validate_voucher_against_standard(&voucher, &custom_standard).is_ok());
    }
}

/// Prüft verhaltensbasierte Geschäftsregeln aus dem Standard.
#[cfg(test)]
mod behavioral_rules {
    use super::*;
    use test_utils::generate_signed_standard_toml;
    use voucher_lib::services::standard_manager::verify_and_parse_standard;
    use voucher_lib::services::voucher_manager::VoucherManagerError;

    fn load_toml_standard(path: &str) -> (voucher_lib::VoucherStandardDefinition, String) {
        let toml_str = generate_signed_standard_toml(path);
        verify_and_parse_standard(&toml_str).unwrap()
    }

    #[test]
    fn test_validate_voucher_when_validity_is_too_short_then_fails() {
        // TEST ENTFERNT (OBSOLET):
        // Diese statische Prüfung (ValidityDurationTooShort) wurde aus `validate_voucher_against_standard`
        // entfernt und durch den "Gatekeeper" (in `create_voucher`) und die "Firewall" (in `create_transaction`)
        // ersetzt.
        // Der Test `core_logic::lifecycle::test_validity_duration_rules` (Testfall 1)
        // deckt den "Gatekeeper"-Teil bereits ab.
    }

    #[test]
    fn test_validate_voucher_when_validity_is_too_long_then_fails() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_behavior_rules.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100.00".to_string(), ..Default::default() },
            ..Default::default()
        };
        let mut voucher = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date).unwrap();
        let long_validity_dt = creation_dt + chrono::Duration::days(365 * 6);
        voucher.valid_until = long_validity_dt.to_rfc3339();

        let mut voucher_to_sign = voucher.clone();
        voucher_to_sign.creator.signature = "".to_string();
        voucher_to_sign.voucher_id = "".to_string();
        voucher_to_sign.transactions.clear();
        voucher_to_sign.guarantor_signatures.clear();
        voucher_to_sign.additional_signatures.clear();
        let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
        let new_sig = crypto_utils::sign_ed25519(&creator_identity.signing_key, hash.as_bytes());
        voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();

        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::ValidityDurationTooLong { max_allowed, .. })
            if max_allowed == "P5Y"
        ));
    }

    #[test]
    fn test_validate_voucher_when_decimal_places_are_invalid_then_fails() {
        let (standard, standard_hash) = load_toml_standard("tests/test_data/standards/standard_behavior_rules.toml");
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100.123".to_string(), ..Default::default() },
            ..Default::default()
        };
        let voucher_bad_nominal = create_voucher_for_manipulation(voucher_data, &standard, &standard_hash, &creator_identity.signing_key, "en");
        let result1 = validate_voucher_against_standard(&voucher_bad_nominal, &standard);
        assert!(matches!(
            result1.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 2, found: 3 }) if path == "nominal_value.amount"
        ));

        let mut voucher = create_voucher(NewVoucherData {
            creator: Creator { id: creator_identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            nominal_value: NominalValue { amount: "100.00".to_string(), ..Default::default() },
            ..Default::default()
        }, &standard, &standard_hash, &creator_identity.signing_key, "en").unwrap();
        voucher.transactions[0].amount = "100.123".to_string();
        let tx = voucher.transactions[0].clone();
        voucher.transactions[0] = resign_transaction(tx, &creator_identity.signing_key);

        let result2 = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result2.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { path, max_places: 2, found: 3 }) if path == "transactions[0].amount"
        ));
    }

    #[test]
    fn test_validate_voucher_when_full_transfer_amount_mismatches_then_fails() {
        let (standard, _, _, recipient, mut voucher) = test_utils::setup_voucher_with_one_tx();
        let last_valid_tx = voucher.transactions.last().unwrap();
        let prev_hash = crypto_utils::get_hash(to_canonical_json(last_valid_tx).unwrap());
        let invalid_transfer_tx = Transaction {
            t_id: "".to_string(), prev_hash, t_type: "transfer".to_string(),
            t_time: voucher_lib::services::utils::get_current_timestamp(),
            sender_id: recipient.user_id.clone(), recipient_id: ACTORS.charlie.user_id.clone(),
            amount: "10.0000".to_string(), sender_remaining_amount: None, sender_signature: "".to_string(),
        };
        let signed_tx = resign_transaction(invalid_transfer_tx, &recipient.signing_key);
        voucher.transactions.push(signed_tx);

        let result = validate_voucher_against_standard(&voucher, &standard);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::FullTransferAmountMismatch { .. })
        ));
    }

    #[test]
    fn test_create_transaction_when_voucher_is_not_divisible_then_fails_on_split() {
        let (non_divisible_standard, hash) = test_utils::create_custom_standard(&SILVER_STANDARD.0, |s| {
            s.template.fixed.is_divisible = false;
        });
        let identity = &ACTORS.alice;
        let voucher = create_voucher(NewVoucherData {
            creator: Creator { id: identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P3Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        }, &non_divisible_standard, &hash, &identity.signing_key, "en").unwrap();

        let result = create_transaction(&voucher, &non_divisible_standard, &identity.user_id, &identity.signing_key, &ACTORS.bob.user_id, "40");
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Manager(VoucherManagerError::VoucherNotDivisible)));
    }

    #[test]
    fn test_create_transaction_when_type_is_not_allowed_then_fails() {
        let (restricted_standard, hash) = test_utils::create_custom_standard(&MINUTO_STANDARD.0, |s| {
            // KORREKTUR: Verwende `get_or_insert_with` statt `unwrap()`, um robust
            // gegen `None`-Werte in der Standard-Definition zu sein.
            let validation = s.validation.get_or_insert_with(Default::default);

            // 1. Setze die Regel, die wir testen wollen (nur 'init' erlaubt)
            let b_rules = validation.behavior_rules.get_or_insert_with(Default::default);
            b_rules.allowed_t_types = Some(vec!["init".to_string()]);
            // 3. (FIX) Deaktiviere die Issuance-Firewall, damit der Test nicht daran scheitert.
            b_rules.issuance_minimum_validity_duration = None;

            // 2. Entschärfe die 'max=1' Transaktions-Regel des Minuto-Standards
            let count_rules = validation.counts.get_or_insert_with(Default::default);
            count_rules.transactions = Some(voucher_lib::models::voucher_standard_definition::MinMax { min: 1, max: 2 });
        });
        let identity = &ACTORS.alice;
        
        // Erstelle einen Basis-Gutschein, der manipuliert werden kann.
        let mut voucher = create_voucher_for_manipulation(NewVoucherData {
            creator: Creator { id: identity.user_id.clone(), ..Default::default() },
            validity_duration: Some("P3Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            ..Default::default()
        }, &restricted_standard, &hash, &identity.signing_key, "en");

        // Füge die zwei für den Standard erforderlichen Bürgen hinzu, damit das Setup valide ist.
        voucher.guarantor_signatures.push(create_male_guarantor_signature(&voucher));
        voucher.guarantor_signatures.push(create_female_guarantor_signature(&voucher));

        let result = create_transaction(&voucher, &restricted_standard, &identity.user_id, &identity.signing_key, &ACTORS.bob.user_id, "100");

        // KORREKTUR: Verwende `matches!` für eine robuste Fehlerprüfung statt String-Vergleich.
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::TransactionTypeNotAllowed { t_type, .. }) if t_type == "transfer"
        ));
    }


    /// Testet die "Issuance Firewall" (issuance_minimum_validity_duration).
    /// Diese Tests validieren die "Gatekeeper"-Funktion (bei Erstellung) und
    // die "Firewall"-Funktion (bei Transaktion).
    #[cfg(test)]
    mod issuance_firewall {
        use super::*;
        use voucher_lib::test_utils::{create_custom_standard, SILVER_STANDARD};
        use voucher_lib::services::voucher_manager::VoucherManagerError;

        /// Erstellt eine Testumgebung mit den benötigten Akteuren und Standards.
        struct TestSetup {
            creator_pc: &'static test_utils::TestUser,
            creator_mobil: test_utils::TestUser,
            user_b: &'static test_utils::TestUser,
            user_c: &'static test_utils::TestUser,
            standard_a: (voucher_lib::VoucherStandardDefinition, String), // P1Y Firewall
            standard_b: (&'static voucher_lib::VoucherStandardDefinition, &'static String), // Keine Firewall
        }

        fn setup() -> TestSetup {
            let creator_pc = &ACTORS.alice;
            let user_b = &ACTORS.bob;
            let user_c = &ACTORS.charlie;

            // Erstellt einen "Mobil"-Akteur mit derselben Mnemonic (gleiche PK), aber anderem Präfix.
            let creator_mobil = test_utils::user_from_mnemonic_slow(
                &creator_pc.mnemonic,
                creator_pc.passphrase,
                Some("am"), // "alice mobile"
            );

            // Standard A: Mit 1-Jahres-Firewall
            let (standard_a, hash_a) = create_custom_standard(&SILVER_STANDARD.0, |s| {
                let validation = s.validation.get_or_insert_with(Default::default);
                let behavior = validation.behavior_rules.get_or_insert_with(Default::default);
                behavior.issuance_minimum_validity_duration = Some("P1Y".to_string());
            });

            TestSetup {
                creator_pc,
                creator_mobil,
                user_b,
                user_c,
                standard_a: (standard_a, hash_a),
                standard_b: (&SILVER_STANDARD.0, &SILVER_STANDARD.1),
            }
        }

        /// Hilfsfunktion zum Erstellen von Test-Voucher-Daten.
        fn create_voucher_data(creator: &test_utils::TestUser, duration: &str) -> NewVoucherData {
            NewVoucherData {
                creator: Creator { id: creator.user_id.clone(), ..Default::default() },
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                validity_duration: Some(duration.to_string()),
                ..Default::default()
            }
        }

        /// Hilfsfunktion, um einen Gutschein nach Manipulation neu zu signieren (Creator-Signatur).
        fn resign_voucher_creator_signature(mut voucher: voucher_lib::Voucher, signer_key: &ed25519_dalek::SigningKey) -> voucher_lib::Voucher {
            let mut voucher_to_sign = voucher.clone();
            voucher_to_sign.creator.signature = "".to_string();
            voucher_to_sign.voucher_id = "".to_string();
            voucher_to_sign.transactions.clear();
            voucher_to_sign.guarantor_signatures.clear();
            voucher_to_sign.additional_signatures.clear();
            let hash = crypto_utils::get_hash(to_canonical_json(&voucher_to_sign).unwrap());
            let new_sig = crypto_utils::sign_ed25519(signer_key, hash.as_bytes());
            voucher.creator.signature = bs58::encode(new_sig.to_bytes()).into_string();
            voucher
        }

        #[test]
        /// Testet Fall 1 (Gatekeeper): Erstellung schlägt fehl, wenn Gültigkeit < Regel.
        fn test_gatekeeper_blocks_creation_of_too_short_voucher() {
            let setup = setup();
            let (standard_a, hash_a) = (&setup.standard_a.0, &setup.standard_a.1);

            // Szenario: Erstelle Gutschein mit P6M Gültigkeit (Regel = P1Y)
            let voucher_data = create_voucher_data(setup.creator_pc, "P6M");

            let result = create_voucher(
                voucher_data,
                standard_a,
                hash_a,
                &setup.creator_pc.signing_key,
                "en"
            );

            // Erwartung: Die Erstellung (Gatekeeper) schlägt fehl.
            assert!(matches!(
                result.unwrap_err(),
                VoucherCoreError::Manager(VoucherManagerError::InvalidValidityDuration(_))
            ));
        }

        #[test]
        /// Testet Fall 1 (Firewall): Transaktion schlägt fehl, wenn Restgültigkeit < Regel.
        fn test_firewall_blocks_expired_issuance_to_third_party() {
            let setup = setup();
            let (standard_a, hash_a) = (&setup.standard_a.0, &setup.standard_a.1);

            // 1. Erstelle GÜLTIGEN Gutschein (P2Y > P1Y)
            let voucher_data = create_voucher_data(setup.creator_pc, "P2Y");
            let mut voucher = create_voucher(voucher_data, standard_a, hash_a, &setup.creator_pc.signing_key, "en").unwrap();

            // 2. Simuliere Zeitablauf: Manipuliere valid_until auf 6 Monate in der Zukunft
            let now = chrono::Utc::now();
            let six_months_from_now = voucher_lib::services::voucher_manager::add_iso8601_duration(now, "P6M").unwrap();
            voucher.valid_until = six_months_from_now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            voucher = resign_voucher_creator_signature(voucher, &setup.creator_pc.signing_key);

            // 3. Aktion: Versuche zu senden (Creator -> Dritter)
            let result = create_transaction(
                &voucher, standard_a, &setup.creator_pc.user_id, &setup.creator_pc.signing_key, &setup.user_b.user_id, "100"
            );

            // 4. Erwartung: Firewall schlägt fehl
            assert!(matches!(
                result.unwrap_err(),
                VoucherCoreError::Manager(VoucherManagerError::InvalidValidityDuration(msg))
                if msg.contains("less than the required minimum remaining duration")
            ));
        }

        #[test]
        /// Testet Fall 2: Transaktion (Creator -> Creator) ist trotz abgelaufener Frist erfolgreich (SAI-Ausnahme).
        fn test_firewall_allows_internal_creator_transfer_when_expired() {
            let setup = setup();
            let (standard_a, hash_a) = (&setup.standard_a.0, &setup.standard_a.1);
            let voucher_data = create_voucher_data(setup.creator_pc, "P2Y");
            let mut voucher = create_voucher(voucher_data, standard_a, hash_a, &setup.creator_pc.signing_key, "en").unwrap();

            // Simuliere Zeitablauf
            let now = chrono::Utc::now();
            let six_months_from_now = voucher_lib::services::voucher_manager::add_iso8601_duration(now, "P6M").unwrap();
            voucher.valid_until = six_months_from_now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            voucher = resign_voucher_creator_signature(voucher, &setup.creator_pc.signing_key);

            // Aktion: Sende an Creator_Mobil (gleiche PK, anderer Prefix)
            let result = create_transaction(
                &voucher, standard_a, &setup.creator_pc.user_id, &setup.creator_pc.signing_key, &setup.creator_mobil.user_id, "100"
            );
            assert!(result.is_ok());
        }

        #[test]
        /// Testet Fall 3: Transaktion (Nicht-Ersteller -> Dritter) ist trotz abgelaufener Frist erfolgreich.
        fn test_firewall_allows_non_creator_transfer_when_expired() {
            let setup = setup();
            let (standard_a, hash_a) = (&setup.standard_a.0, &setup.standard_a.1);
            let voucher_data = create_voucher_data(setup.creator_pc, "P2Y");
            let voucher = create_voucher(voucher_data, standard_a, hash_a, &setup.creator_pc.signing_key, "en").unwrap();

            // Sende an User_B (erfolgreich)
            let voucher_at_b = create_transaction(&voucher, standard_a, &setup.creator_pc.user_id, &setup.creator_pc.signing_key, &setup.user_b.user_id, "100").unwrap();

            // Simuliere Zeitablauf
            let mut voucher_at_b_expired = voucher_at_b.clone();
            let now = chrono::Utc::now();
            let six_months_from_now = voucher_lib::services::voucher_manager::add_iso8601_duration(now, "P6M").unwrap();
            voucher_at_b_expired.valid_until = six_months_from_now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            voucher_at_b_expired = resign_voucher_creator_signature(voucher_at_b_expired, &setup.creator_pc.signing_key);

            // Aktion: User_B (Nicht-Ersteller) sendet an User_C
            let result = create_transaction(
                &voucher_at_b_expired, standard_a, &setup.user_b.user_id, &setup.user_b.signing_key, &setup.user_c.user_id, "100"
            );
            assert!(result.is_ok());
        }

        #[test]
        /// Testet Fall 4: Transaktion (Creator -> Dritter) ist erfolgreich, wenn Gültigkeit ausreicht.
        fn test_firewall_allows_valid_issuance_to_third_party() {
            let setup = setup();
            let (standard_a, hash_a) = (&setup.standard_a.0, &setup.standard_a.1);
            let voucher_data = create_voucher_data(setup.creator_pc, "P2Y"); // P2Y > P1Y
            let voucher = create_voucher(voucher_data, standard_a, hash_a, &setup.creator_pc.signing_key, "en").unwrap();

            let result = create_transaction(&voucher, standard_a, &setup.creator_pc.user_id, &setup.creator_pc.signing_key, &setup.user_b.user_id, "100");
            assert!(result.is_ok());
        }

        #[test]
        /// Testet Fall 5: Transaktion (Creator -> Dritter) ist erfolgreich, wenn Regel nicht definiert ist.
        fn test_firewall_allows_transfer_if_rule_is_undefined() {
            let setup = setup();
            let (standard_b, hash_b) = (setup.standard_b.0, setup.standard_b.1); // Standard B (keine Regel)

            // Erstelle Gutschein mit P6M (wäre bei Standard A ungültig)
            let voucher_data = create_voucher_data(setup.creator_pc, "P6M");
            let voucher = create_voucher(voucher_data, standard_b, hash_b, &setup.creator_pc.signing_key, "en").unwrap();

            // Aktion: Sende an User_B
            let result = create_transaction(&voucher, standard_b, &setup.creator_pc.user_id, &setup.creator_pc.signing_key, &setup.user_b.user_id, "100");
            assert!(result.is_ok());
        }
    }
}