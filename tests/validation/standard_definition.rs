// tests/validation/standard_definition.rs
// cargo test --test validation_tests
//!
//! Enthält alle Tests zur Verifizierung der Gutschein-Standard-Definitionen (TOML),
//! deren korrekte Integration in den Gutschein und Härtungstests.

use ed25519_dalek::Signer;
use human_money_core::VoucherCoreError;
use human_money_core::error::StandardDefinitionError;
use human_money_core::models::voucher_standard_definition::LocalizedText;
use human_money_core::services::standard_manager::{get_localized_text, verify_and_parse_standard};
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::services::{crypto_utils, utils, voucher_manager};
use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD, SILVER_STANDARD, TEST_ISSUER, add_voucher_to_wallet,
    generate_signed_standard_toml, setup_in_memory_wallet,
};

/// Prüft das Parsen und die kryptographische Verifizierung von Standard-Dateien.
#[cfg(test)]
mod parsing_and_verification {
    use super::*;

    #[test]
    fn test_verify_standard_when_toml_is_valid_then_succeeds() {
        let valid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let result = verify_and_parse_standard(&valid_toml_str);
        assert!(result.is_ok());
        let (_standard, hash) = result.unwrap();
        assert_eq!(hash, MINUTO_STANDARD.1);
    }

    #[test]
    fn test_verify_standard_when_content_is_tampered_then_fails() {
        let mut tampered_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        tampered_toml_str =
            tampered_toml_str.replace("amount_decimal_places = 0", "amount_decimal_places = 8");
        let result = verify_and_parse_standard(&tampered_toml_str);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_standard_when_signature_block_is_missing_then_fails() {
        let mut toml_without_signature =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let signature_block_start = toml_without_signature.find("[signature]").unwrap();
        toml_without_signature.truncate(signature_block_start);
        let result = verify_and_parse_standard(&toml_without_signature);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)
        ));
    }

    #[test]
    fn test_verify_standard_when_signature_is_from_wrong_issuer_then_fails() {
        let mut standard = SILVER_STANDARD.0.clone();
        standard.signature = None;
        let hash_to_sign = crypto_utils::get_hash(utils::to_canonical_json(&standard).unwrap());
        let hacker_signature = ACTORS.hacker.signing_key.sign(hash_to_sign.as_bytes());

        standard.signature = Some(
            human_money_core::models::voucher_standard_definition::SignatureBlock {
                issuer_id: TEST_ISSUER.user_id.clone(),
                signature: bs58::encode(hacker_signature.to_bytes()).into_string(),
            },
        );

        let manipulated_toml = toml::to_string(&standard).unwrap();
        let result = verify_and_parse_standard(&manipulated_toml);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)
        ));
    }

    #[test]
    fn test_verify_standard_when_issuer_id_is_malformed_then_fails() {
        let mut invalid_toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        invalid_toml_str =
            invalid_toml_str.replace(&TEST_ISSUER.user_id, "did:key:invalid-format-123");
        let result = verify_and_parse_standard(&invalid_toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_localized_text_when_direct_match_exists_then_returns_it() {
        let texts = vec![
            LocalizedText {
                lang: "de".to_string(),
                text: "Hallo".to_string(),
            },
            LocalizedText {
                lang: "en".to_string(),
                text: "Hello".to_string(),
            },
        ];
        assert_eq!(get_localized_text(&texts, "de"), Some("Hallo"));
    }

    #[test]
    fn test_get_localized_text_when_no_match_then_falls_back_to_english() {
        let texts = vec![
            LocalizedText {
                lang: "de".to_string(),
                text: "Hallo".to_string(),
            },
            LocalizedText {
                lang: "en".to_string(),
                text: "Hello".to_string(),
            },
        ];
        assert_eq!(get_localized_text(&texts, "fr"), Some("Hello"));
    }

    #[test]
    fn test_get_localized_text_when_no_english_then_falls_back_to_first() {
        let texts = vec![
            LocalizedText {
                lang: "de".to_string(),
                text: "Hallo".to_string(),
            },
            LocalizedText {
                lang: "es".to_string(),
                text: "Hola".to_string(),
            },
        ];
        assert_eq!(get_localized_text(&texts, "fr"), Some("Hallo"));
    }
}

/// Prüft das korrekte Zusammenspiel zwischen einem Gutschein und seinem Standard.
#[cfg(test)]
mod integration_with_voucher {
    use super::*;

    use human_money_core::services::voucher_manager::NewVoucherData;

    #[test]
    fn test_validate_voucher_when_standard_hash_mismatches_then_fails() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(&mut wallet, identity, "100", &MINUTO_STANDARD.0, false).unwrap();
        let instance = wallet
            .voucher_store
            .vouchers
            .values()
            .next()
            .unwrap()
            .clone();
        let mut voucher = instance.voucher;
        voucher.voucher_standard.standard_definition_hash = "invalid_hash_string_123".to_string();
        let validation_result = validate_voucher_against_standard(&voucher, &MINUTO_STANDARD.0);
        assert!(matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::StandardHashMismatch)
        ));
    }

    #[test]
    fn test_create_voucher_when_lang_preference_is_set_then_uses_correct_localized_text() {
        let new_voucher_data_de = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "888".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let voucher_de = human_money_core::test_utils::create_voucher_for_manipulation(
            new_voucher_data_de,
            &MINUTO_STANDARD.0,
            &MINUTO_STANDARD.1,
            &ACTORS.alice.signing_key,
            "de",
        );

        let new_voucher_data_fr = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "888".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let voucher_fr = human_money_core::test_utils::create_voucher_for_manipulation(
            new_voucher_data_fr,
            &MINUTO_STANDARD.0,
            &MINUTO_STANDARD.1,
            &ACTORS.alice.signing_key,
            "fr",
        );

        assert!(
            voucher_de
                .voucher_standard
                .template
                .description
                .contains("Minuten qualitativer Leistung")
        );
        assert!(
            voucher_fr
                .voucher_standard
                .template
                .description
                .contains("minutes of quality performance")
        );
    }

    #[test]
    fn test_create_transaction_when_standard_is_wrong_then_fails() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        add_voucher_to_wallet(
            &mut wallet,
            identity,
            "5",
            &human_money_core::test_utils::SILVER_STANDARD.0,
            false,
        )
        .unwrap();
        let instance = wallet
            .voucher_store
            .vouchers
            .values()
            .next()
            .unwrap()
            .clone();
        let silver_voucher = instance.voucher;

        let result = voucher_manager::create_transaction(
            &silver_voucher,
            &MINUTO_STANDARD.0,
            &identity.user_id,
            &identity.signing_key,
            &ACTORS.bob.user_id,
            "1",
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Voucher standard UUID mismatch")
        );
    }
}

/// Prüft die Robustheit gegen manipulierte oder ungültige Standard-Definitionen.
#[cfg(test)]
mod security_hardening {
    use super::*;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::services::voucher_manager::NewVoucherData;

    #[test]
    fn test_verify_standard_when_signature_string_is_invalid_base58_then_fails() {
        let mut toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let original_sig_line = format!(
            "signature = \"{}\"",
            MINUTO_STANDARD.0.signature.as_ref().unwrap().signature
        );
        let placeholder_sig_line = "signature = \"This-is-an-invalid-placeholder-signature\"";
        toml_str = toml_str.replace(&original_sig_line, placeholder_sig_line);
        let result = verify_and_parse_standard(&toml_str);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(_))
        ));
    }

    #[test]
    fn test_verify_standard_when_signature_string_is_empty_then_fails() {
        let mut toml_str =
            generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");
        let original_sig_line = format!(
            "signature = \"{}\"",
            MINUTO_STANDARD.0.signature.as_ref().unwrap().signature
        );
        toml_str = toml_str.replace(&original_sig_line, "signature = \"\"");
        let result = verify_and_parse_standard(&toml_str);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(_))
        ));
    }

    #[test]
    fn test_parse_standard_when_field_types_are_mismatched_then_fails() {
        let raw_toml_str = include_str!("../../voucher_standards/minuto_v1/standard.toml");
        let manipulated_toml = raw_toml_str
            .replace(
                &format!("uuid = \"{}\"", MINUTO_STANDARD.0.metadata.uuid),
                "uuid = 12345",
            )
            .replace(
                "amount_decimal_places = 0",
                "amount_decimal_places = \"zero\"",
            );
        let result = verify_and_parse_standard(&manipulated_toml);
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Toml(_)));
    }

    #[test]
    fn test_create_voucher_when_standard_template_is_incomplete_then_fails() {
        let (incomplete_standard, hash) =
            human_money_core::test_utils::create_custom_standard(&MINUTO_STANDARD.0, |s| {
                s.template.fixed.nominal_value.unit = "".to_string();
            });
        let new_voucher_data = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "50".to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = voucher_manager::create_voucher(
            new_voucher_data,
            &incomplete_standard,
            &hash,
            &ACTORS.alice.signing_key,
            "en",
        );
        assert!(matches!(result.unwrap_err(), VoucherCoreError::Manager(_)));
    }
}
