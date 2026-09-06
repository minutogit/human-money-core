// tests/core_logic/security/standard_validation.rs
// cargo test --test core_logic_tests

//! Tests for compliance and bypass of validation rules defined in the standard.

use self::test_utils::{ACTORS, MINUTO_STANDARD, create_voucher_for_manipulation};
use super::test_utils;
use human_money_core::error::ValidationError;
use human_money_core::models::voucher::{ValueDefinition, Voucher, VoucherSignature};
use human_money_core::services::crypto_utils::{get_hash, get_hash_from_slices, sign_ed25519};
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::{VoucherCoreError, to_canonical_json, validate_voucher_against_standard};

#[cfg(test)]
mod required_signatures_validation {
    use self::test_utils::{create_guarantor_signature_with_time, create_male_guarantor_signature};
    use super::*;

    fn load_required_sig_standard() -> (human_money_core::VoucherStandardDefinition, String) {
        // Use the robust lazy_static variable and add the CEL rule.
        // Re-sign the mutated clone via create_custom_standard so it stays
        // self-consistent at validation time (AUDIT-M03-010 enforces signature
        // validity when the standard enters validation).
        test_utils::create_custom_standard(&test_utils::REQUIRED_SIG_STANDARD.0, |standard| {
            standard.immutable.custom_rules.insert(
                "test_rule".to_string(),
                human_money_core::models::voucher_standard_definition::DynamicRule {
                    message: "Official Approver".to_string(),
                    expression: format!("Voucher.signatures.filter(s, s.signer_id == '{}' && s.role == 'Official Approver').size() == 1", ACTORS.charlie.user_id),
                }
            );
        })
    }

    fn create_base_voucher_for_sig_test(
        standard: &human_money_core::VoucherStandardDefinition,
        standard_hash: &str,
    ) -> Voucher {
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(creator_identity.user_id.clone()),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()), // ADDED: Explicitly set validity
            // ADDED: Explicitly set nominal value to avoid "Invalid decimal: empty"
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default() // Fills the rest with default values
        };
        // Use the "manipulation" helper function which skips final validation.
        // This is necessary because the standard requires a signature that we want to add in the tests.
        create_voucher_for_manipulation(
            voucher_data,
            standard,
            standard_hash,
            &creator_identity.signing_key)
    }

    fn create_valid_approval_signature(voucher: &Voucher) -> VoucherSignature {
        // CORRECTION: We use ACTORS.charlie, as ACTORS.issuer ID
        // in the test setup does not match the one in standard_required_signatures.toml.
        let signer = &ACTORS.charlie;
        let mut sig = VoucherSignature {
            voucher_id: voucher.voucher_id.clone(), // CORRECTION: Set voucher_id from the voucher
            signer_id: signer.user_id.clone(),
            role: "Official Approver".to_string(), // CORRECTION: Semantically better role (must match TOML)
            signature_time: get_current_timestamp(),
            ..Default::default()
        };
        // CORRECTION: signature_id must be calculated from the hash of metadata *without*
        // the fields 'signature_id' and 'signature' itself. The verification logic
        // does exactly that. We need to replicate it precisely here.
        let mut data_for_id_hash = sig.clone();
        println!("\n[DEBUG TEST CREATE SIG] --- START CREATION ---");
        data_for_id_hash.signature_id = "".to_string();
        data_for_id_hash.signature = "".to_string();
        let init_t_id = &voucher.transactions[0].t_id;
        sig.signature_id = get_hash_from_slices(&[
            to_canonical_json(&data_for_id_hash).unwrap().as_bytes(),
            init_t_id.as_bytes(),
        ]);
        println!(
            "[DEBUG TEST CREATE SIG] Generated signature_id: {}",
            sig.signature_id
        );
        let digital_sig = sign_ed25519(&signer.signing_key, sig.signature_id.as_bytes());
        sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        println!("[DEBUG TEST CREATE SIG] --- END CREATION ---\n");
        sig
    }

    #[test]
    fn test_required_signature_ok() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        voucher
            .signatures
            .push(create_valid_approval_signature(&voucher));

        let result = validate_voucher_against_standard(&voucher, &standard);
        if let Err(e) = &result {
            // Add debug output to see the exact error
            panic!(
                "Validation failed unexpectedly in test_required_signature_ok: {:?}",
                e
            );
        }
        // The original assertion remains to keep the test passing on success.
        assert!(result.is_ok());
    }

    #[test]
    fn test_fails_on_missing_mandatory_signature() {
        let (standard, standard_hash) = load_required_sig_standard();
        let voucher = create_base_voucher_for_sig_test(&standard, &standard_hash); // Without signature

        let result = validate_voucher_against_standard(&voucher, &standard);

        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
                if msg == "Official Approver" => {} // Success
            _ => panic!(
                "Expected BusinessRuleViolated('Official Approver'), but got {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_fails_on_signature_from_wrong_signer() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        let mut wrong_sig = create_valid_approval_signature(&voucher);
        let hacker_identity = &ACTORS.hacker;
        wrong_sig.signer_id = hacker_identity.user_id.clone(); // Not in allowed_signer_ids
        // Must be resigned because data changed
        let mut obj_to_hash = wrong_sig.clone();
        obj_to_hash.signature_id = "".to_string();
        obj_to_hash.signature = "".to_string();
        wrong_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
        let digital_sig = sign_ed25519(
            &hacker_identity.signing_key,
            wrong_sig.signature_id.as_bytes(),
        );
        wrong_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        voucher.signatures.push(wrong_sig);

        let result = validate_voucher_against_standard(&voucher, &standard);

        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
                if msg == "Official Approver" => {} // Success
            _ => panic!(
                "Expected BusinessRuleViolated('Official Approver'), but got {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_fails_on_wrong_signature_description() {
        let (standard, standard_hash) = load_required_sig_standard();
        let mut voucher = create_base_voucher_for_sig_test(&standard, &standard_hash);
        let mut wrong_desc_sig = create_valid_approval_signature(&voucher);
        wrong_desc_sig.role = "Some other description".to_string();
        // Must be resigned
        let signer = &ACTORS.charlie; // Must be the same correct signer
        let mut obj_to_hash = wrong_desc_sig.clone();
        obj_to_hash.signature_id = "".to_string();
        obj_to_hash.signature = "".to_string();
        wrong_desc_sig.signature_id = get_hash(to_canonical_json(&obj_to_hash).unwrap());
        let digital_sig = sign_ed25519(&signer.signing_key, wrong_desc_sig.signature_id.as_bytes());
        wrong_desc_sig.signature = bs58::encode(digital_sig.to_bytes()).into_string();
        voucher.signatures.push(wrong_desc_sig);

        let result = validate_voucher_against_standard(&voucher, &standard);

        let err = result.unwrap_err();
        match err {
            VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
                if msg == "Official Approver" => {} // Success
            _ => panic!(
                "Expected BusinessRuleViolated('Official Approver'), but got {:?}",
                err
            ),
        }
    }

    #[test]
    fn test_creator_as_guarantor_attack_fails() {
        let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let creator_identity = &ACTORS.alice;
        let voucher_data = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(creator_identity.user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "60".to_string(),
                ..Default::default()
            },
            // CORRECTION: The Minuto standard requires a minimum validity (e.g. P3Y).
            // P1Y was too short and triggered `ValidityDurationTooShort` before the actual
            // attack logic (`CreatorAsGuarantor`) could be checked.
            validity_duration: Some("P4Y".to_string()),
            ..Default::default()
        };
        let mut voucher = create_voucher_for_manipulation(
            voucher_data,
            standard,
            standard_hash,
            &creator_identity.signing_key);

        // Attack: The creator (Alice) attempts to act as guarantor for herself.
        let self_guarantor_sig = create_guarantor_signature_with_time(
            &voucher,
            creator_identity, // Alice guarantees
            "Alice",
            "guarantor",
            "2",
            "2026-08-01T10:00:00Z",
        );

        voucher.signatures.push(self_guarantor_sig);
        // Add a second valid guarantor to satisfy the `CountOutOfBounds` rule
        voucher
            .signatures
            .push(create_male_guarantor_signature(&voucher));

        let validation_result = validate_voucher_against_standard(&voucher, standard);

        // --- DEBUG output added ---
        if let Err(e) = &validation_result {
            println!("[DEBUG] Validation failed as expected. The actual error was:");
            println!("[DEBUG] {:?}", e);
        } else {
            // If validation unexpectedly succeeds, fail the test.
            panic!("[DEBUG] Validation unexpectedly succeeded, but should have failed!");
        }
        // --- End DEBUG output ---

        // NOTE: With the implementation of the "Anti-Signature-Reuse-Firewall"
        // in `voucher_validation.rs` we now check the cryptographic 
        // key, which triggers the `DuplicateIdentityDetected` error.
        assert!(matches!(
            validation_result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::DuplicateIdentityDetected { .. })
        ));
    }
}
