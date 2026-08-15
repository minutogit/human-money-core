use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::setup_voucher_with_one_tx;

#[test]
fn test_signature_bypass_mechanism() {
    // 1. SETUP: Create a valid voucher
    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // We invalidate the signature by overwriting it with garbage.
    // Normally, this would IMMEDIATELY cause a validation error.
    if let Some(sig) = voucher.signatures.get_mut(0) {
        sig.signature = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789".to_string();
    }

    // ---------------------------------------------------------
    // STEP 1: Without bypass (Expected: ERROR)
    // ---------------------------------------------------------
    println!("Step 1: Testing validation without bypass (should fail)...");

    // Ensure bypass is off (default)
    human_money_core::set_signature_bypass(false);

    let result_fail = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result_fail.is_err(),
        "Validierung sollte fehlschlagen, da Signatur defekt ist!"
    );
    println!("-> Success: Validation failed as expected.");

    // ---------------------------------------------------------
    // STEP 2: With bypass (Expected: SUCCESS)
    // ---------------------------------------------------------
    println!("Step 2: Testing validation WITH bypass (should succeed)...");

    // Enable bypass
    human_money_core::set_signature_bypass(true);

    // The exact same validation should now succeed
    let result_ok = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result_ok.is_ok(),
        "Validierung sollte trotz defekter Signatur erfolgreich sein, da Bypass aktiv ist! Fehler war: {:?}",
        result_ok.err()
    );
    println!("-> Success: Validation passed with bypass.");

    // ---------------------------------------------------------
    // STEP 3: Disable bypass (Expected: ERROR)
    // ---------------------------------------------------------
    println!("Step 3: Testing validation after disabling bypass (should fail again)...");

    // Turn bypass back off
    human_money_core::set_signature_bypass(false);

    let result_fail_again = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result_fail_again.is_err(),
        "Bypass sollte wieder inaktiv sein!"
    );
    println!("-> Success: Validation failed again as expected.");
}

#[test]
fn test_logic_modification_with_bypass() {
    // This test demonstrates the actual purpose:
    // We manipulate data (logic), which invalidates the signature,
    // but want to test whether the logic (e.g. invalid amount) is still checked?
    // NO: Here we only test that we can pass structurally valid but signature-invalid
    // objects through.

    human_money_core::set_signature_bypass(true);

    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // We change content (e.g. Transaction Amount) without re-signing.
    // This invalidates the hash -> signature no longer matches the content.
    // With bypass, this should be ignored.
    voucher.transactions[0].amount = "999999.0".to_string();

    let result = validate_voucher_against_standard(&voucher, standard);

    // NOTE: Whether this is OK or ERR depends on whether validate_voucher
    // also checks business rules (e.g. does amount fit history?).
    // But it must NOT fail with "SignatureInvalid".
    if let Err(e) = &result {
        let err_msg = format!("{:?}", e);
        assert!(
            !err_msg.contains("Signature"),
            "Fehler darf kein Signaturfehler sein! Erhalten: {}",
            err_msg
        );
    }
}

