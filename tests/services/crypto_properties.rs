// tests/services/crypto_properties.rs
// cargo test --test services_tests
//!
//! Eigenschafts- und Grenztests für `src/services/crypto_utils.rs`.
//!
//! Diese Tests sichern die grundlegenden Invarianten (Korrektheit, Determinismus,
//! Eingabevalidierung) der kryptographischen Hilfsfunktionen ab. Sie ergänzen die
//! allgemeinen Integrationstests in `crypto.rs` mit präziseren Randfall-Szenarien:
//!
//! - **Vollständigkeit**: Werden alle gültigen Eingaben korrekt verarbeitet?
//! - **Ablehnung**: Werden ungültige Eingaben zuverlässig zurückgewiesen?
//! - **Determinismus**: Liefern Funktionen für gleiche Eingaben immer dasselbe Ergebnis?
//! - **Kommutiativität**: Ist die Reihenfolge von Argumenten irrelevant wo erwartet?
//! - **Fehlermeldungen**: Enthalten Fehlertypen aussagekräftige Texte für Endnutzer/Logging?
//!
//! Ausführen: `cargo test --test services_tests services::crypto_properties`

use bip39::Language;
use human_money_core::services::crypto_utils::{
    UserIdError, create_user_id, decrypt_data, generate_ed25519_keypair_for_tests,
    generate_mnemonic, validate_user_id,
};

// =============================================================================
// Mnemonic-Generierung
// =============================================================================

/// Alle fünf vom BIP-39-Standard unterstützten Wortanzahlen (12, 15, 18, 21, 24)
/// müssen eine Phrase mit exakt dieser Wortzahl erzeugen.
///
/// Hintergrund: BIP-39 definiert Entropielängen von 128–256 Bit in 32-Bit-Schritten,
/// was den Wortanzahlen 12, 15, 18, 21 und 24 entspricht. Jede davon ist ein
/// eigenständiger, unterstützter Anwendungsfall.
#[test]
fn test_mnemonic_generation_covers_all_bip39_sizes() -> Result<(), Box<dyn std::error::Error>> {
    let valid_counts = [12usize, 15, 18, 21, 24];
    for &count in &valid_counts {
        let mnemonic = generate_mnemonic(count, Language::English)
            .unwrap_or_else(|_| panic!("generate_mnemonic({count}) should succeed"));
        let word_count_actual = mnemonic.split_whitespace().count();
        assert_eq!(
            word_count_actual, count,
            "generate_mnemonic({count}) produced {word_count_actual} words, expected {count}"
        );
    }
    Ok(())
}

/// Wortanzahlen, die kein BIP-39-Entropie-Vielfaches ergeben (z. B. 11, 13, 0),
/// müssen mit einem Fehler abgelehnt werden.
#[test]
fn test_mnemonic_generation_rejects_unsupported_sizes() {
    assert!(generate_mnemonic(11, Language::English).is_err(), "11 words is not a BIP-39 size");
    assert!(generate_mnemonic(13, Language::English).is_err(), "13 words is not a BIP-39 size");
    assert!(generate_mnemonic(0,  Language::English).is_err(), "0 words makes no sense");
}

// =============================================================================
// Kurzform-Hash von User-IDs
// =============================================================================

/// `get_short_hash_from_user_id` dient als kompaktes Heuristik-Merkmal für bekannte Peers.
/// Diese Invarianten müssen gelten:
/// - Deterministisch (gleiche ID → gleicher Hash)
/// - Einzigartig (verschiedene IDs → verschiedene Hashes, statistisch)
/// - Feste 4-Byte-Ausgabe (kein leerer, trivialer oder variabler Rückgabewert)
#[test]
fn test_short_hash_is_deterministic_unique_and_fixed_size() {
    use human_money_core::services::crypto_utils::get_short_hash_from_user_id;

    let hash_alice = get_short_hash_from_user_id("alice@did:key:z6MkTest1");
    let hash_bob   = get_short_hash_from_user_id("bob@did:key:z6MkTest2");

    // Verschiedene IDs → verschiedene Hashes (kein konstanterRückgabewert)
    assert_ne!(hash_alice, hash_bob, "Different user IDs must produce different short hashes");

    // Deterministisch: gleiche Eingabe → gleicher Hash
    let hash_alice_again = get_short_hash_from_user_id("alice@did:key:z6MkTest1");
    assert_eq!(hash_alice, hash_alice_again, "Short hash must be deterministic");

    // Keine trivialen Konstanten als Rückgabewert
    assert_ne!(hash_alice, [0u8; 4], "Short hash must not be all-zero");
    assert_ne!(hash_alice, [1u8; 4], "Short hash must not be all-one");

    // Ausgabelänge immer genau 4 Bytes, unabhängig von der Eingabelänge
    let hash_single_char = get_short_hash_from_user_id("x");
    assert_eq!(hash_single_char.len(), 4, "Short hash must always be exactly 4 bytes");
}

// =============================================================================
// HKDF-Info-Vektor (build_hkdf_info)
// =============================================================================

/// Der HKDF-Info-Vektor muss beide Schlüssel-Bytes und das Label enthalten.
/// Er darf nicht leer sein und muss sich bei verschiedenen Schlüsselpaaren unterscheiden.
///
/// Hintergrund: `build_hkdf_info` kodiert beide Public Keys in einen deterministischen,
/// reihenfolgeunabhängigen Kontext-String für den HKDF-Expand-Schritt beim DH-Austausch.
#[test]
fn test_hkdf_info_contains_key_material_and_differs_per_keypair() {
    use human_money_core::services::crypto_utils::{build_hkdf_info, generate_ephemeral_x25519_keypair};

    let (pk1, _) = generate_ephemeral_x25519_keypair();
    let (pk2, _) = generate_ephemeral_x25519_keypair();

    let info = build_hkdf_info(&pk1, &pk2);

    // Kein leerer Vektor
    assert!(!info.is_empty(), "HKDF info must not be empty");
    // Muss das Label (32 Bytes) plus mindestens einen Schlüssel (32 Bytes) enthalten
    assert!(info.len() > 32, "HKDF info must include label + key material (> 32 bytes)");

    // Andere Schlüssel → anderer Info-Vektor
    let (pk3, _) = generate_ephemeral_x25519_keypair();
    let info_different = build_hkdf_info(&pk1, &pk3);
    assert_ne!(info, info_different, "Different key pairs must produce different HKDF info");
}

/// Der Info-Vektor muss unabhängig von der Argumentreihenfolge identisch sein
/// (Kommutativität). Das ist notwendig, damit Sender und Empfänger denselben
/// symmetrischen Schlüssel ableiten, ohne die Reihenfolge vorab abstimmen zu müssen.
#[test]
fn test_hkdf_info_is_independent_of_argument_order() {
    use human_money_core::services::crypto_utils::{
        build_hkdf_info, ed25519_pub_to_x25519, generate_ed25519_keypair_for_tests,
    };

    let (ed_a, _) = generate_ed25519_keypair_for_tests(Some("hkdf-key-aaaaa"));
    let (ed_b, _) = generate_ed25519_keypair_for_tests(Some("hkdf-key-zzzzz"));
    let pk_a = ed25519_pub_to_x25519(&ed_a);
    let pk_b = ed25519_pub_to_x25519(&ed_b);

    let info_ab = build_hkdf_info(&pk_a, &pk_b);
    let info_ba = build_hkdf_info(&pk_b, &pk_a);

    assert_eq!(
        info_ab, info_ba,
        "build_hkdf_info must produce the same result regardless of argument order"
    );

    // Mindestens einer der Schlüssel muss als Byte-Sequenz im Ergebnis auffindbar sein
    let contains_a = info_ab.windows(32).any(|w| w == pk_a.as_bytes());
    let contains_b = info_ab.windows(32).any(|w| w == pk_b.as_bytes());
    assert!(
        contains_a || contains_b,
        "HKDF info must contain actual key bytes, not placeholder data"
    );
}

// =============================================================================
// Mindestlänge für verschlüsselte Empfänger-Payloads
// =============================================================================

/// Ein verschlüsseltes Privacy-Guard-Paket besteht aus einem ephemeren Public Key
/// (32 Bytes) gefolgt von Nonce + Ciphertext (min. 12 Bytes). Eingaben unter diesem
/// Schwellwert von 44 Bytes müssen sofort mit einem Fehler abgelehnt werden,
/// bevor eine Entschlüsselung versucht wird.
///
/// Grenzfälle mit unterschiedlichen Unterschreitungen decken ab, dass die Prüfung
/// korrekt implementiert ist (z. B. nicht mit Subtraktion statt Addition).
#[test]
fn test_recipient_payload_decryption_requires_minimum_byte_length() {
    use base64::Engine as _;
    use human_money_core::services::crypto_utils::{decrypt_recipient_payload, generate_ed25519_keypair_for_tests};
    let engine = base64::engine::general_purpose::STANDARD;

    let (_, sk) = generate_ed25519_keypair_for_tests(Some("min-length-test"));

    // 43 Bytes = 32 + 11 → fehlt 1 Byte für den Nonce
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 43]), &sk).is_err(),
        "43 bytes (one short) must be rejected"
    );

    // 20 Bytes → weit unterhalb der Grenze
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 20]), &sk).is_err(),
        "20 bytes must be rejected"
    );

    // 21 Bytes → immer noch zu kurz
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 21]), &sk).is_err(),
        "21 bytes must be rejected"
    );

    // 0 Bytes → leere Eingabe muss abgelehnt werden
    assert!(
        decrypt_recipient_payload(&engine.encode([0u8; 0]), &sk).is_err(),
        "empty input must be rejected"
    );
}

// =============================================================================
// Nonce-Präfix bei symmetrischer Entschlüsselung
// =============================================================================

/// `decrypt_data` erwartet ein vorangestelltes 12-Byte-Nonce (ChaCha20-Poly1305).
/// Eingaben unter 12 Bytes müssen mit `InvalidLength` abgelehnt werden.
/// Eingaben ab 12 Bytes passieren die Längenprüfung und scheitern erst bei der
/// AEAD-Verifikation (anderer Fehlertyp: `DecryptionFailed`).
///
/// Das unterschiedliche Fehlerverhalten für 11 vs. 12 Bytes ist die relevante Invariante:
/// Es zeigt, dass die Längenprüfung einen exakten, korrekten Schwellwert verwendet.
#[test]
fn test_symmetric_decryption_distinguishes_length_error_from_decryption_error() {
    use chacha20poly1305::aead::{OsRng, rand_core::RngCore};

    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    // 11 Bytes → zu kurz für einen Nonce → InvalidLength
    let err_11 = decrypt_data(&key, &[0u8; 11]).unwrap_err();
    let err_str_11 = format!("{err_11:?}");
    assert!(
        err_str_11.contains("InvalidLength") || err_str_11.contains("nonce") || err_str_11.contains("12"),
        "Input shorter than NONCE_SIZE must produce an InvalidLength error, got: {err_str_11}"
    );

    // 12 Bytes → Nonce OK, aber kein Ciphertext → DecryptionFailed (kein InvalidLength)
    let err_12 = decrypt_data(&key, &[0u8; 12]).unwrap_err();
    let err_str_12 = format!("{err_12:?}");
    assert!(
        !err_str_12.contains("InvalidLength"),
        "Exactly 12 bytes must pass length check and fail with DecryptionFailed, not InvalidLength. \
         Got: {err_str_12}"
    );

    // Leere Eingabe → muss ebenfalls fehlschlagen
    assert!(decrypt_data(&key, &[]).is_err(), "Empty input must fail");
}

// =============================================================================
// Präfix-Validierung bei User-ID-Erstellung
// =============================================================================

/// Das Präfix einer User-ID darf maximal 63 Zeichen lang sein.
/// Exakt 63 Zeichen sind erlaubt; ab 64 Zeichen wird `PrefixTooLong` zurückgegeben.
#[test]
fn test_user_id_prefix_length_is_enforced_at_63_chars() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("length-boundary"));

    let result_63 = create_user_id(&pub_key, Some(&"a".repeat(63)));
    assert!(result_63.is_ok(), "63-char prefix must be accepted, got: {:?}", result_63.err());

    let result_64 = create_user_id(&pub_key, Some(&"a".repeat(64)));
    assert!(
        matches!(result_64, Err(UserIdError::PrefixTooLong(_))),
        "64-char prefix must be rejected as PrefixTooLong, got: {:?}", result_64
    );
}

/// Das Präfix darf nur Kleinbuchstaben (a–z), Ziffern (0–9) und Bindestriche (-) enthalten.
/// Großbuchstaben werden automatisch in Kleinbuchstaben umgewandelt.
/// Leerzeichen, '@', Sonderzeichen u. ä. sind nicht erlaubt.
#[test]
fn test_user_id_prefix_only_allows_lowercase_digits_and_hyphens() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("charset-test"));

    // Großbuchstaben werden via to_lowercase normalisiert → gültig
    let result_upper = create_user_id(&pub_key, Some("ABC"));
    assert!(result_upper.is_ok(), "Uppercase 'ABC' is normalized to 'abc' and must be accepted");

    // Leerzeichen → ungültig
    let result_space = create_user_id(&pub_key, Some("my prefix"));
    assert!(
        matches!(result_space, Err(UserIdError::InvalidPrefixChars)),
        "Space in prefix must be rejected as InvalidPrefixChars, got: {:?}", result_space
    );

    // '@'-Zeichen → ungültig (kollidiert mit dem ID-Format-Trennzeichen)
    let result_at = create_user_id(&pub_key, Some("pre@fix"));
    assert!(
        matches!(result_at, Err(UserIdError::InvalidPrefixChars)),
        "'@' in prefix must be rejected as InvalidPrefixChars, got: {:?}", result_at
    );
}

/// Bindestriche am Anfang oder Ende des Präfixes sind nicht erlaubt,
/// da sie zu konfusen oder schwer lesbaren IDs führen würden ("–account:…").
/// Jede dieser Positionen muss unabhängig abgelehnt werden.
#[test]
fn test_user_id_prefix_cannot_start_or_end_with_hyphen() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("hyphen-position"));

    let r_leading = create_user_id(&pub_key, Some("-prefix"));
    assert!(
        matches!(r_leading, Err(UserIdError::InvalidPrefixStartEnd)),
        "Leading hyphen must be rejected, got: {:?}", r_leading
    );

    let r_trailing = create_user_id(&pub_key, Some("prefix-"));
    assert!(
        matches!(r_trailing, Err(UserIdError::InvalidPrefixStartEnd)),
        "Trailing hyphen must be rejected, got: {:?}", r_trailing
    );

    // Bindestrich in der Mitte ist erlaubt (üblicher Trennstrich in Kontextnamen)
    let r_middle = create_user_id(&pub_key, Some("my-prefix"));
    assert!(r_middle.is_ok(), "Hyphen in the middle must be accepted, got: {:?}", r_middle.err());
}

/// Doppelte Trenner (`--`) sind nicht erlaubt, da sie kein sinnvolles Namensmuster darstellen
/// und zu Parsing-Ambiguitäten führen könnten.
#[test]
fn test_user_id_prefix_cannot_contain_consecutive_hyphens() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("consec-hyphens"));

    let r_double = create_user_id(&pub_key, Some("my--prefix"));
    assert!(
        matches!(r_double, Err(UserIdError::PrefixHasConsecutiveSeparators)),
        "Double hyphen '--' must be rejected, got: {:?}", r_double
    );

    // Doppelpunkte sind als Zeichen ebenfalls unzulässig
    assert!(create_user_id(&pub_key, Some(":prefix")).is_err(),  "Leading ':' must fail");
    assert!(create_user_id(&pub_key, Some("ab::cd")).is_err(),   "'::' must fail");
    assert!(create_user_id(&pub_key, Some("prefix:")).is_err(),  "Trailing ':' must fail");

    // Einzelner Bindestrich bleibt erlaubt
    let r_single = create_user_id(&pub_key, Some("my-prefix"));
    assert!(r_single.is_ok(), "Single hyphen must still be accepted");
}

// =============================================================================
// Validierung bestehender User-IDs
// =============================================================================

/// `validate_user_id` muss klar strukturell ungültige Strings ablehnen
/// und eine gültige ID akzeptieren. Außerdem muss eine nachträglich manipulierte
/// Prüfsumme erkannt werden (Integritätsschutz).
#[test]
fn test_user_id_validation_rejects_malformed_input_and_detects_tampering() {
    // Strukturell ungültig
    assert!(!validate_user_id(""),              "Empty string must fail");
    assert!(!validate_user_id("not-a-user-id"), "Plain string must fail");
    assert!(!validate_user_id("only@one"),      "Missing DID part must fail");
    assert!(!validate_user_id("a@@did:key:z"), "Double '@' must fail");
    assert!(!validate_user_id("x@NOTADID"),    "Non-DID suffix must fail");

    // Korrekte ID muss akzeptiert werden
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("validate-ok"));
    let valid_id = create_user_id(&pub_key, Some("test")).unwrap();
    assert!(validate_user_id(&valid_id), "Correctly generated ID must be valid");

    // Nachträgliche Manipulation der Prüfsumme muss erkannt werden
    let mut tampered = valid_id.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(!validate_user_id(&tampered), "Tampered checksum must be detected and rejected");
}

/// Ein Präfix mit mehr als 63 Zeichen in einer manuell konstruierten ID
/// (die nie durch `create_user_id` erzeugt werden kann) muss von
/// `validate_user_id` ebenfalls abgelehnt werden.
///
/// Dies stellt sicher, dass die Längenbeschränkung nicht nur bei der Erstellung,
/// sondern auch bei der Validierung eingehender IDs greift.
#[test]
fn test_user_id_validation_enforces_prefix_length_limit() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("pfx-len-validate"));

    // Valide ID mit maximalem 63-Zeichen-Präfix muss akzeptiert werden
    let valid_id = create_user_id(&pub_key, Some(&"a".repeat(63))).unwrap();
    assert!(validate_user_id(&valid_id), "Max-length (63-char) prefix must be valid");

    // Manuell konstruierte ID mit 64-Zeichen-Präfix muss abgelehnt werden
    let at_pos     = valid_id.find('@').unwrap();
    let did_part   = &valid_id[at_pos..];
    let last_colon = valid_id[..at_pos].rfind(':').unwrap();
    let checksum   = &valid_id[last_colon + 1..at_pos];
    let oversized  = format!("{}:{}{}", "a".repeat(64), checksum, did_part);
    assert!(!validate_user_id(&oversized), "Over-length prefix ID must be rejected by validator");
}

/// Jede einzelne Präfix-Formatregel muss unabhängig zur Ablehnung führen.
/// Insbesondere: führender Bindestrich, abschließender Bindestrich und
/// doppelte Bindestriche müssen jeweils allein ausreichen.
///
/// Hintergrund: Die Regeln sind mit OR verknüpft. Würden sie mit AND verknüpft,
/// müssten mehrere Fehler gleichzeitig auftreten — was in der Praxis seltener vorkommt
/// und Fehler verbergen würde.
#[test]
fn test_user_id_validation_each_prefix_rule_independently_triggers_rejection() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("indep-rules"));
    let valid_id   = create_user_id(&pub_key, Some("valid")).unwrap();
    let at_pos     = valid_id.find('@').unwrap();
    let did_part   = &valid_id[at_pos..];
    let last_colon = valid_id[..at_pos].rfind(':').unwrap();
    let checksum   = &valid_id[last_colon + 1..at_pos];

    // Nur führender Bindestrich → muss ablehnen
    assert!(
        !validate_user_id(&format!("-valid:{checksum}{did_part}")),
        "Leading hyphen alone must trigger rejection"
    );

    // Nur abschließender Bindestrich → muss ablehnen
    assert!(
        !validate_user_id(&format!("valid-:{checksum}{did_part}")),
        "Trailing hyphen alone must trigger rejection"
    );

    // Nur doppelter Bindestrich → muss ablehnen
    assert!(
        !validate_user_id(&format!("val--id:{checksum}{did_part}")),
        "Double hyphen alone must trigger rejection"
    );

    // Original-ID bleibt weiterhin gültig (Positiv-Kontrolle)
    assert!(validate_user_id(&valid_id), "Original valid ID must still pass");
}

/// Im Präfix sind Bindestriche und Ziffern explizit erlaubt.
/// Dies prüft, dass diese erlaubten Zeichen nicht fälschlich gesperrt werden.
#[test]
fn test_user_id_validation_accepts_hyphens_and_digits_in_prefix() {
    let (pub_key, _) = generate_ed25519_keypair_for_tests(Some("allowed-charset"));

    // Ziffern im Präfix → erlaubt
    let id_digit = create_user_id(&pub_key, Some("pre1fix")).unwrap();
    assert!(validate_user_id(&id_digit), "Prefix containing a digit must be valid");

    // Bindestrich in der Mitte → erlaubt
    let id_hyphen = create_user_id(&pub_key, Some("my-account")).unwrap();
    assert!(
        validate_user_id(&id_hyphen),
        "Prefix 'my-account' with a middle hyphen must be valid"
    );

    // Mehrere Bindestriche (nicht aufeinanderfolgend) → erlaubt
    let id_multi = create_user_id(&pub_key, Some("my-long-id")).unwrap();
    assert!(validate_user_id(&id_multi), "Prefix 'my-long-id' with multiple hyphens must be valid");

    // Ungültige Zeichen in konstruierten IDs → muss abgelehnt werden
    assert!(!validate_user_id("pre@fix:abc@did:key:zabc"), "Prefix with '@' must be rejected");
    assert!(!validate_user_id("pre fix:abc@did:key:zabc"), "Prefix with space must be rejected");
}

// =============================================================================
// Fehlermeldungen (Display & Error::source)
// =============================================================================

/// Alle Varianten von `UserIdError` müssen eine nicht-leere, lesbare Fehlermeldung liefern.
/// Das ist wichtig für aussagekräftige Rückmeldungen an Nutzer und Entwickler.
#[test]
fn test_user_id_error_variants_have_descriptive_messages() {
    let errors = [
        UserIdError::PrefixEmpty,
        UserIdError::PrefixTooLong(100),
        UserIdError::InvalidPrefixChars,
        UserIdError::InvalidPrefixStartEnd,
        UserIdError::PrefixHasConsecutiveSeparators,
    ];
    for e in &errors {
        let msg = format!("{e}");
        assert!(
            !msg.is_empty(),
            "Display for {e:?} must not be an empty string"
        );
    }
}

/// `GetPubkeyError` muss für alle Varianten eine lesbare Fehlermeldung liefern.
/// Bei Varianten, die eine Ursache wrappen (`DecodingFailed`, `ConversionFailed`),
/// muss `Error::source()` `Some` zurückgeben, damit die Ursachenkette nachvollziehbar ist.
/// Alle anderen Varianten sollten `None` zurückgeben.
#[test]
fn test_get_pubkey_error_has_readable_messages_and_correct_cause_chain() {
    use human_money_core::services::crypto_utils::GetPubkeyError;
    use std::error::Error;

    // Display muss für alle terminalen Varianten eine nicht-leere Meldung liefern
    for e in [
        GetPubkeyError::InvalidPrefix,
        GetPubkeyError::InvalidDidFormat,
        GetPubkeyError::InvalidMulticodec,
        GetPubkeyError::InvalidLength(10),
    ] {
        assert!(!format!("{e}").is_empty(), "Display for {e:?} must not be empty");
    }

    // Varianten ohne Ursache → source() == None
    assert!(GetPubkeyError::InvalidPrefix.source().is_none(),    "No source for InvalidPrefix");
    assert!(GetPubkeyError::InvalidDidFormat.source().is_none(), "No source for InvalidDidFormat");
    assert!(GetPubkeyError::InvalidMulticodec.source().is_none(),"No source for InvalidMulticodec");
    assert!(GetPubkeyError::InvalidLength(0).source().is_none(), "No source for InvalidLength");

    // DecodingFailed wraps a bs58 error → source() muss die Ursache durchreichen
    let decode_err = bs58::decode("!invalid!").into_vec().unwrap_err();
    let e_decode = GetPubkeyError::DecodingFailed(decode_err);
    assert!(
        e_decode.source().is_some(),
        "DecodingFailed must expose its wrapped error via source()"
    );
}

// =============================================================================
// Kurvenableitungen (ed25519_pk_to_curve_point)
// =============================================================================

/// `ed25519_pk_to_curve_point` konvertiert einen Ed25519-Verifikationsschlüssel
/// in einen Punkt auf der Edwards25519-Kurve. Diese Funktion wird u. a. für
/// kryptographische Trap-Berechnungen verwendet.
///
/// Invarianten:
/// - Verschiedene Schlüssel → verschiedene Kurvenpunkte (keine Kollision)
/// - Gleicher Schlüssel → immer derselbe Punkt (Determinismus)
#[test]
fn test_curve_point_derivation_is_injective_and_deterministic() {
    use human_money_core::services::crypto_utils::{
        ed25519_pk_to_curve_point, generate_ed25519_keypair_for_tests,
    };

    let (pub_key_a, _) = generate_ed25519_keypair_for_tests(Some("curve-key-a"));
    let (pub_key_b, _) = generate_ed25519_keypair_for_tests(Some("curve-key-b"));

    let point_a = ed25519_pk_to_curve_point(&pub_key_a).unwrap();
    let point_b = ed25519_pk_to_curve_point(&pub_key_b).unwrap();

    // Verschiedene Schlüssel → verschiedene Punkte (Injektivität)
    assert_ne!(
        point_a, point_b,
        "Different public keys must map to different Edwards curve points"
    );

    // Deterministisch: gleicher Schlüssel → immer gleicher Punkt
    let point_a_again = ed25519_pk_to_curve_point(&pub_key_a).unwrap();
    assert_eq!(
        point_a, point_a_again,
        "Same public key must always produce the same curve point"
    );
}
