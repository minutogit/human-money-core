//! # tests/validation/forward_compatibility.rs
//!
//! Stellt sicher, dass die Bibliothek robust gegenüber zukünftigen Änderungen
//! an den Datenstrukturen ist (Vorwärtskompatibilität).



use serde_json::json;
use voucher_lib::test_utils::{ACTORS, MINUTO_STANDARD};
use voucher_lib::{
    from_json, validate_voucher_against_standard, Creator, NewVoucherData, Voucher,
    VoucherCoreError, NominalValue,
};
use voucher_lib::error::ValidationError;
use voucher_lib::error::StandardDefinitionError;
use voucher_lib::services::standard_manager;
use voucher_lib::services::utils::to_canonical_json;

/// Prüft Szenarien zur Vorwärtskompatibilität.
#[cfg(test)]
mod compatibility_scenarios {
    use super::*;

    #[test]
    fn test_validate_voucher_with_unknown_fields_in_json_then_succeeds() {
        let identity = &ACTORS.issuer;
        let creator = Creator { id: identity.user_id.clone(), ..Default::default() };
        let voucher_data = NewVoucherData {
            validity_duration: Some("P3Y".to_string()),
            nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
            creator, ..Default::default()
        };
        let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let mut valid_voucher = voucher_lib::test_utils::create_voucher_for_manipulation(voucher_data, minuto_standard, standard_hash, &identity.signing_key, "en");

        let g1 = &ACTORS.guarantor1;
        let g2 = &ACTORS.guarantor2;
        let sig_data1 = voucher_lib::test_utils::create_guarantor_signature_data(g1, "1", &valid_voucher.voucher_id);
        let sig_data2 = voucher_lib::test_utils::create_guarantor_signature_data(g2, "2", &valid_voucher.voucher_id);
        let signed_sig1 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data1, &valid_voucher.voucher_id, g1).unwrap();
        let signed_sig2 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data2, &valid_voucher.voucher_id, g2).unwrap();
        let voucher_lib::models::signature::DetachedSignature::Signature(s1) = signed_sig1; valid_voucher.signatures.push(s1);
        let voucher_lib::models::signature::DetachedSignature::Signature(s2) = signed_sig2; valid_voucher.signatures.push(s2);
        assert!(validate_voucher_against_standard(&valid_voucher, minuto_standard).is_ok());

        let mut voucher_as_value: serde_json::Value = serde_json::to_value(&valid_voucher).unwrap();
        voucher_as_value.as_object_mut().unwrap().insert("new_root_field_from_v2".to_string(), json!("some future data"));
        voucher_as_value.get_mut("transactions").unwrap()[0].as_object_mut().unwrap().insert("transaction_memo".to_string(), json!("a memo for the init transaction"));
        let json_with_extra_fields = serde_json::to_string(&voucher_as_value).unwrap();

        let deserialized_voucher: Voucher = from_json(&json_with_extra_fields).unwrap();
        assert_eq!(valid_voucher, deserialized_voucher);

        let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);
        assert!(validation_result.is_ok(), "Validation failed unexpectedly with extra fields: {:?}", validation_result.err());
    }

    #[test]
    fn test_validate_voucher_when_t_type_is_unknown_then_fails() {
        let identity = &ACTORS.issuer;
        let (minuto_standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let mut voucher = voucher_lib::test_utils::create_voucher_for_manipulation(
            NewVoucherData {
                creator: Creator { id: identity.user_id.clone(), ..Default::default() },
                validity_duration: Some("P3Y".to_string()),
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                ..Default::default()
            },
            minuto_standard, standard_hash, &identity.signing_key, "en",
        );

        let g1 = &ACTORS.guarantor1;
        let g2 = &ACTORS.guarantor2;
        let sig_data1 = voucher_lib::test_utils::create_guarantor_signature_data(g1, "1", &voucher.voucher_id);
        let sig_data2 = voucher_lib::test_utils::create_guarantor_signature_data(g2, "2", &voucher.voucher_id);
        let signed_sig1 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data1, &voucher.voucher_id, g1).unwrap();
        let signed_sig2 = voucher_lib::services::signature_manager::complete_and_sign_detached_signature(sig_data2, &voucher.voucher_id, g2).unwrap();
        let voucher_lib::models::signature::DetachedSignature::Signature(s1) = signed_sig1; voucher.signatures.push(s1);
        let voucher_lib::models::signature::DetachedSignature::Signature(s2) = signed_sig2; voucher.signatures.push(s2);

        let mut voucher_as_value: serde_json::Value = serde_json::to_value(&voucher).unwrap();
        let transactions = voucher_as_value.get_mut("transactions").unwrap().as_array_mut().unwrap();
        let init_transaction = transactions[0].as_object_mut().unwrap();
        init_transaction.insert("t_type".to_string(), json!("merge"));

        let mut temp_tx: voucher_lib::models::voucher::Transaction = serde_json::from_value(serde_json::Value::Object(init_transaction.clone())).unwrap();
        temp_tx.t_id = "".to_string();
        temp_tx.sender_signature = "".to_string();
        let new_tid = voucher_lib::services::crypto_utils::get_hash(to_canonical_json(&temp_tx).unwrap());
        init_transaction.insert("t_id".to_string(), json!(new_tid));

        let signature_payload = json!({ "prev_hash": &temp_tx.prev_hash, "sender_id": &temp_tx.sender_id, "t_id": new_tid });
        let signature_payload_hash = voucher_lib::services::crypto_utils::get_hash(to_canonical_json(&signature_payload).unwrap());
        let new_signature = voucher_lib::services::crypto_utils::sign_ed25519(&identity.signing_key, signature_payload_hash.as_bytes());
        init_transaction.insert("sender_signature".to_string(), json!(bs58::encode(new_signature.to_bytes()).into_string()));

        let manipulated_json = serde_json::to_string(&voucher_as_value).unwrap();
        let deserialized_voucher: Voucher = from_json(&manipulated_json).unwrap();

        let validation_result = validate_voucher_against_standard(&deserialized_voucher, minuto_standard);
        assert!(matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::TransactionTypeNotAllowed { t_type, .. }) if t_type == "merge"
        ));
    }

    #[test]
    fn test_parse_standard_with_unknown_fields_in_toml_then_succeeds() {
        // 1. Nimm einen zur Laufzeit gültig signierten Standard.
        let (mut standard_struct, _) = MINUTO_STANDARD.clone();

        // 2. Modifiziere ein EXISTIERENDES Feld. Dies ändert den Hash-Wert der Struktur,
        // aber die Signatur bleibt die alte. Dadurch wird die Signatur ungültig.
        standard_struct.metadata.keywords.push("modified-for-test".to_string());

        // 3. Serialisiere die modifizierte Struktur mit der nun veralteten Signatur in einen String.
        let toml_str_with_invalid_sig = toml::to_string(&standard_struct).unwrap();

        // 4. Die Verifizierung muss jetzt wegen der ungültigen Signatur fehlschlagen.
        let result = standard_manager::verify_and_parse_standard(&toml_str_with_invalid_sig);
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Standard(StandardDefinitionError::InvalidSignature)
        ));

        // 5. Um die Vorwärtskompatibilität des Parsers selbst zu testen, fügen wir jetzt
        //    unbekannte Felder hinzu und parsen ohne Signaturprüfung.
        let mut toml_with_unknown_fields = toml_str_with_invalid_sig;
        toml_with_unknown_fields.push_str("\n[metadata.new_future_field]\ninfo = 'some data'\n");
        let parse_only_result: Result<voucher_lib::models::voucher_standard_definition::VoucherStandardDefinition, _> = toml::from_str(&toml_with_unknown_fields);
        assert!(parse_only_result.is_ok(), "Raw TOML parsing should succeed even with unknown fields.");
    }
}