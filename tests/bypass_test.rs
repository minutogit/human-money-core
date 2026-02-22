use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::setup_voucher_with_one_tx;

#[test]
fn test_signature_bypass_mechanism() {
    // 1. SETUP: Einen validen Voucher erstellen
    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // Wir machen die Signatur ungültig, indem wir sie mit Müll überschreiben.
    // Normalerweise würde dies SOFORT zu einem Validierungsfehler führen.
    if let Some(sig) = voucher.signatures.get_mut(0) {
        sig.signature = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789".to_string();
    }

    // ---------------------------------------------------------
    // SCHRITT 1: Ohne Bypass (Erwartung: FEHLER)
    // ---------------------------------------------------------
    println!("Step 1: Testing validation without bypass (should fail)...");

    // Sicherstellen, dass Bypass aus ist (Default)
    human_money_core::set_signature_bypass(false);

    let result_fail = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result_fail.is_err(),
        "Validierung sollte fehlschlagen, da Signatur defekt ist!"
    );
    println!("-> Success: Validation failed as expected.");

    // ---------------------------------------------------------
    // SCHRITT 2: Mit Bypass (Erwartung: ERFOLG)
    // ---------------------------------------------------------
    println!("Step 2: Testing validation WITH bypass (should succeed)...");

    // Bypass aktivieren
    human_money_core::set_signature_bypass(true);

    // Die exakt gleiche Validierung sollte jetzt durchgehen
    let result_ok = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result_ok.is_ok(),
        "Validierung sollte trotz defekter Signatur erfolgreich sein, da Bypass aktiv ist! Fehler war: {:?}",
        result_ok.err()
    );
    println!("-> Success: Validation passed with bypass.");

    // ---------------------------------------------------------
    // SCHRITT 3: Bypass deaktivieren (Erwartung: FEHLER)
    // ---------------------------------------------------------
    println!("Step 3: Testing validation after disabling bypass (should fail again)...");

    // Bypass wieder ausschalten
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
    // Dieser Test demonstriert den eigentlichen Nutzen:
    // Wir manipulieren Daten (Logik), was die Signatur ungültig macht,
    // wollen aber testen, ob die Logik (z.B. falscher Betrag) trotzdem geprüft wird?
    // NEIN: Hier testen wir nur, dass wir strukturell valide aber signatur-ungültige
    // Objekte durchschleusen können.

    human_money_core::set_signature_bypass(true);

    let (standard, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();

    // Wir ändern den Inhalt (z.B. Transaction Amount), ohne neu zu signieren.
    // Das macht den Hash ungültig -> Signatur passt nicht mehr zum Inhalt.
    // Mit Bypass sollte das ignoriert werden.
    voucher.transactions[0].amount = "999999.0".to_string();

    let result = validate_voucher_against_standard(&voucher, standard);

    // HINWEIS: Ob das hier OK oder ERR ist, hängt davon ab, ob validate_voucher
    // auch Business-Regeln prüft (z.B. passt Betrag zur History?).
    // Aber es darf NICHT an "SignatureInvalid" scheitern.
    if let Err(e) = &result {
        let err_msg = format!("{:?}", e);
        assert!(
            !err_msg.contains("Signature"),
            "Fehler darf kein Signaturfehler sein! Erhalten: {}",
            err_msg
        );
    }
}
