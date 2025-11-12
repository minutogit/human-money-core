// tests/core_logic/security/standard_validation.rs

//! Tests für die Einhaltung und Umgehung der im Standard definierten Validierungsregeln.

use super::test_utils;
use voucher_lib::{
    to_canonical_json, validate_voucher_against_standard,
    VoucherCoreError,
};
use voucher_lib::models::voucher::{ValueDefinition, Voucher, VoucherSignature};
use voucher_lib::services::crypto_utils::{get_hash, sign_ed25519};
use voucher_lib::services::utils::get_current_timestamp;
use voucher_lib::services::voucher_manager::NewVoucherData;
use voucher_lib::error::ValidationError;
use self::test_utils::{
    create_voucher_for_manipulation, ACTORS, MINUTO_STANDARD,
};

#[cfg(test)]
mod required_signatures_validation {
    use super::*;
    use self::test_utils::{create_guarantor_signature_with_time, create_male_guarantor_signature};

    fn load_required_sig_standard() -> (voucher_lib::VoucherStandardDefinition, String) {
        // Verwende die neue, robuste lazy_static-Variable
        (test_utils::REQUIRED_SIG_STANDARD.0.clone(), test_utils::REQUIRED_SIG_STANDARD.1.clone())
    }

    fn create_base_voucher_for_sig_test(standard: &voucher_lib::VoucherStandardDefinition, standard_hash: &str) -> Voucher {
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(creator_identity.user_id.clone()), ..Default::default() },
            validity_duration: Some("P1Y".to_string()), // HINZUGEFÜGT: Gültigkeit explizit setzen
            // HINZUGEFÜGT: Nennwert explizit setzen, um "Invalid decimal: empty" zu vermeiden
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default() // Füllt den Rest mit Standardwerten
        };
        // Verwende die "manipulation"-Hilfsfunktion, die die finale Validierung überspringt.
        // Das ist notwendig, da der Standard eine Signatur erfordert, die wir in den Tests erst hinzufügen wollen.
        create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en")
    }

    fn create_valid_approval_signature(voucher: &Voucher) -> VoucherSignature {
        // KORREKTUR: Wir verwenden ACTORS.charlie, da die ID von ACTORS.issuer
        // im Test-Setup nicht mit der in standard_required_signatures.toml übereinstimmt.
        let signer = &ACTORS.charlie;
        let mut sig = VoucherSignature {
            voucher_id: voucher.voucher_id.clone(), // KORREKTUR: Setze die voucher_id vom Gutschein
            signer_id: signer.user_id.clone(),
            role: "Official Approver".to_string(), // KORREKTUR: Semantisch bessere Rolle (muss mit TOML übereinstimmen)
            signature_time: get_current_timestamp(),
            ..Default::default()
        };
        // KORREKTUR: Die signature_id muss aus dem Hash der Metadaten *ohne* die Felder
        // 'signature_id' und 'signature' selbst berechnet werden. Die Verifizierungslogik
        // tut genau das. Wir müssen es hier exakt nachbilden.
        let mut data_for_id_hash = sig.clone();
        println!("\n[DEBUG TEST CREATE SIG] --- START CREATION ---");
        data_for_id_hash.signature_id = "".to_string();
        data_for_id_hash.signature = "".to_string();
        let canonical_json_for_creation = to_canonical_json(&data_for_id_hash).unwrap();
        println!("[DEBUG TEST CREATE SIG] Canonical JSON for creation:\n{}", canonical_json_for_creation);
        sig.signature_id = get_hash(&canonical_json_for_creation);
        println!("[DEBUG TEST CREATE SIG] Generated signature_id: {}", sig.signature_id);
        let digital_sig = sign_ed25519(&signer.signing_key, sig.signature_id.as_bytes());
        sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        println!("[DEBUG TEST CREATE SIG] --- END CREATION ---\n");
        sig
    }

    #[test]
    fn test_required_signature_ok() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        voucher.signatures.push(create_valid_approval_signature(&voucher));

        let result = validate_voucher_against_standard(&voucher, &standard);
        if let Err(e) = &result {
            // Hinzufügen von Debug-Ausgabe, um den genauen Fehler zu sehen
            panic!("Validation failed unexpectedly in test_required_signature_ok: {:?}", e);
        }
        // Die ursprüngliche Assertion bleibt bestehen, um den Test im Erfolgsfall grün zu halten.
        assert!(result.is_ok());
    }

    #[test]
    fn test_fails_on_missing_mandatory_signature() {
        let (standard, standard_hash) = load_required_sig_standard();
        let voucher = create_base_voucher_for_sig_test(&standard, &standard_hash); // Ohne Signatur

        let result = validate_voucher_against_standard(&voucher, &standard);

        // Aussagekräftigere Assertion für Debugging
        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { role, .. }) => {
                assert_eq!(role, "Official Approver", "The role in the error did not match 'Official Approver'");
            }
            _ => panic!("Expected MissingRequiredSignature, but got {:?}", err),
        }
    }

    #[test]
    fn test_fails_on_signature_from_wrong_signer() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        let mut wrong_sig = create_valid_approval_signature(&voucher);
        let hacker_identity = &ACTORS.hacker;
        wrong_sig.signer_id = hacker_identity.user_id.clone(); // Nicht in allowed_signer_ids
        // Muss neu signiert werden, da sich die Daten geändert haben
        let mut obj_to_hash = wrong_sig.clone();
        obj_to_hash.signature_id = "".to_string();
        obj_to_hash.signature = "".to_string();
        wrong_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
        let digital_sig = sign_ed25519(&hacker_identity.signing_key, wrong_sig.signature_id.as_bytes());
        wrong_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        voucher.signatures.push(wrong_sig);

        let result = validate_voucher_against_standard(&voucher, &standard);

        // Aussagekräftigere Assertion für Debugging
        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { role, .. }) => {
                assert_eq!(role, "Official Approver", "The role in the error did not match 'Official Approver'");
            }
            _ => panic!("Expected MissingRequiredSignature, but got {:?}", err),
        }
    }

    #[test]
    fn test_fails_on_wrong_signature_description() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        let mut wrong_desc_sig = create_valid_approval_signature(&voucher);
        wrong_desc_sig.role = "Some other description".to_string();
        // Muss neu signiert werden
        let signer = &ACTORS.charlie; // Muss derselbe korrekte Signer sein
        let mut obj_to_hash = wrong_desc_sig.clone();
        obj_to_hash.signature_id = "".to_string();
        obj_to_hash.signature = "".to_string();
        wrong_desc_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
        let digital_sig = sign_ed25519(&signer.signing_key, wrong_desc_sig.signature_id.as_bytes());
        wrong_desc_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        voucher.signatures.push(wrong_desc_sig);

        let result = validate_voucher_against_standard(&voucher, &standard);

        // Aussagekräftigere Assertion für Debugging
        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::MissingRequiredSignature { role, .. }) => {
                assert_eq!(role, "Official Approver", "The role in the error did not match 'Official Approver'");
            }
            _ => panic!("Expected MissingRequiredSignature, but got {:?}", err),
        }
    }

    #[test]
    fn test_creator_as_guarantor_attack_fails() {
        let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator_profile: voucher_lib::models::profile::PublicProfile { id: Some(creator_identity.user_id.clone()), ..Default::default() },
            nominal_value: ValueDefinition { amount: "60".to_string(), ..Default::default() },
            // KORREKTUR: Der Minuto-Standard erfordert eine Mindestgültigkeit (z.B. P3Y).
            // P1Y war zu kurz und löste `ValidityDurationTooShort` aus, bevor die eigentliche
            // Angriffslogik (`CreatorAsGuarantor`) geprüft werden konnte.
            validity_duration: Some("P4Y".to_string()),
            ..Default::default()
        };
        let mut voucher = create_voucher_for_manipulation(voucher_data, standard, standard_hash, &creator_identity.signing_key, "en");

        // Angriff: Der Ersteller (Alice) versucht, für sich selbst zu bürgen.
        let self_guarantor_sig = create_guarantor_signature_with_time(
            creator_identity, // Alice bürgt
            "Alice", "guarantor", "2",
            "2026-08-01T10:00:00Z"
        );

        voucher.signatures.push(self_guarantor_sig);
        // Füge einen zweiten, validen Bürgen hinzu, um die `CountOutOfBounds`-Regel zu umgehen
        voucher.signatures.push(create_male_guarantor_signature(&voucher));

        let validation_result = validate_voucher_against_standard(&voucher, standard);

        // --- DEBUG-Ausgabe hinzugefügt ---
        if let Err(e) = &validation_result {
            println!("[DEBUG] Validation failed as expected. The actual error was:");
            println!("[DEBUG] {:?}", e);
        } else {
            // Wenn die Validierung unerwartet erfolgreich ist, lassen wir den Test fehlschlagen.
            panic!("[DEBUG] Validation unexpectedly succeeded, but should have failed!");
        }
        // --- Ende DEBUG-Ausgabe ---

        // HINWEIS: Mit der Implementierung von `CreatorAsGuarantor` in `error.rs` und
        // `voucher_validation.rs` prüfen wir nun auf den spezifischeren, korrekten Fehler.
        assert!(matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::CreatorAsGuarantor { .. })
        ));
    }
}