//! tests/services/crypto.rs
//!
//! Bündelt alle kryptographischen Tests, inklusive der Logik für
//! den Secure Container und allgemeine Krypto-Hilfsfunktionen.

// Explizite Pfadangabe für das `test_utils`-Modul, um Unklarheiten zu vermeiden.


// --- Tests from test_secure_container.rs ---
use voucher_lib::test_utils::ACTORS;
use voucher_lib::models::secure_container::PayloadType;
use voucher_lib::services::secure_container_manager::{
    create_secure_container, open_secure_container, ContainerManagerError,
};
use voucher_lib::VoucherCoreError;

#[test]
fn test_multi_recipient_secure_container() {
    // --- 1. SETUP ---
    // Erstelle einen Sender (Alice) und drei weitere Personen.
    // Bob und Carol werden die legitimen Empfänger sein.
    // Dave ist ein unbefugter Dritter.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let carol_identity = &ACTORS.charlie; // Charlie represents Carol
    let david_identity = &ACTORS.david;

    // --- 2. CONTAINER CREATION ---
    // Alice erstellt eine geheime Nachricht für Bob und Carol.
    let secret_payload = b"This is a secret message for Bob and Carol!";
    let recipient_ids = vec![bob_identity.user_id.clone(), carol_identity.user_id.clone()];

    let container = create_secure_container(
        &alice_identity,
        &recipient_ids,
        secret_payload,
        PayloadType::Generic("test_message".to_string()),
    )
        .unwrap();

    // --- 3. VERIFICATION BY RECIPIENTS ---

    // Bob versucht, den Container zu öffnen.
    let bob_payload = open_secure_container(&container, &bob_identity).unwrap();
    assert_eq!(bob_payload, secret_payload);
    assert_eq!(container.c, PayloadType::Generic("test_message".to_string()));
    println!("SUCCESS: Bob successfully opened the container.");

    // Carol versucht, denselben Container zu öffnen.
    let carol_payload = open_secure_container(&container, &carol_identity).unwrap();
    assert_eq!(carol_payload, secret_payload);
    assert_eq!(container.c, PayloadType::Generic("test_message".to_string()));
    println!("SUCCESS: Carol successfully opened the container.");

    // --- 4. VERIFICATION FAILURE BY UNAUTHORIZED USER ---

    // David versucht, den Container zu öffnen. Dies muss fehlschlagen.
    let david_result = open_secure_container(&container, david_identity);
    assert!(david_result.is_err());

    // Überprüfe, ob der Fehler der richtige ist.
    match david_result.unwrap_err() {
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient) => {
            // Korrekter Fehlertyp
            println!("SUCCESS: Dave was correctly denied access.");
        }
        e => panic!("Dave's access should be denied with NotAnIntendedRecipient error, but got {:?}", e),
    }
}

/// Testet, ob der Sender einen von ihm erstellten Container später wieder öffnen kann.
/// Dies ist der kritische Testfall für das "Double Key Wrapping".
#[test]
fn test_sender_can_reopen_container() {
    // --- 1. SETUP ---
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;
    let payload = b"message for recipient that sender must be able to read later";

    // --- 2. CONTAINER CREATION ---
    // Sender erstellt einen Container für den Empfänger.
    let container = create_secure_container(
        sender,
        &[recipient.user_id.clone()],
        payload,
        PayloadType::TransactionBundle,
    )
    .unwrap();

    // --- 3. VERIFICATION BY RECIPIENT (Standardfall) ---
    // Der Empfänger kann den Container öffnen.
    let recipient_payload = open_secure_container(&container, recipient).unwrap();
    assert_eq!(
        recipient_payload,
        payload,
        "Recipient should be able to open the container"
    );

    // --- 4. VERIFICATION BY SENDER (Wichtiger Testfall) ---
    // Der Sender muss denselben Container ebenfalls öffnen können.
    let sender_payload = open_secure_container(&container, sender).unwrap();
    assert_eq!(
        sender_payload,
        payload,
        "Sender should be able to re-open their own container"
    );
    println!("SUCCESS: Sender was able to re-open the container, Double Key Wrapping works.");
}

// --- Tests from test_crypto_utils.rs ---

use bip39::Language;
use voucher_lib::services::crypto_utils::{
    create_user_id, decrypt_data, derive_ed25519_keypair, ed25519_pub_to_x25519,
    ed25519_sk_to_x25519_sk, encrypt_data, generate_ed25519_keypair_for_tests, UserIdError,
    generate_ephemeral_x25519_keypair, generate_mnemonic, get_pubkey_from_user_id,
    perform_diffie_hellman, sign_ed25519, validate_mnemonic_phrase, validate_user_id,
    verify_ed25519,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;


#[test]
fn test_generate_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    assert!(!mnemonic.is_empty());
    println!("Generated mnemonic: {}", mnemonic);
    Ok(())
}

#[test]
fn test_derive_ed25519_keypair() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic, None)?;
    assert_eq!(ed_pub.as_bytes().len(), 32);
    assert_eq!(ed_priv.as_bytes().len(), 32);
    println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
    println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));
    Ok(())
}

#[test]
fn test_validate_mnemonic() {
    // 1. Test mit einer bekanntermaßen gültigen Phrase
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let result = validate_mnemonic_phrase(valid_mnemonic);
    assert!(result.is_ok(), "Validation of a correct mnemonic failed. Error: {:?}", result.err());
    println!("SUCCESS: Correctly validated a valid mnemonic.");

    // 2. Test mit einem ungültigen Wort
    let invalid_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    let result = validate_mnemonic_phrase(invalid_word_mnemonic);
    assert!(result.is_err(), "Validation should have failed for an invalid word.");
    println!("SUCCESS: Correctly identified a mnemonic with an invalid word.");

    // 3. Test mit einer ungültigen Prüfsumme
    // "about" wurde durch "abandon" ersetzt, was die Prüfsumme ungültig macht.
    let bad_checksum_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let result = validate_mnemonic_phrase(bad_checksum_mnemonic);
    assert!(result.is_err(), "Validation should have failed for a bad checksum.");
    println!("SUCCESS: Correctly identified a mnemonic with a bad checksum.");
}

/// Testet die Erstellung von User-IDs und stellt sicher, dass ein Präfix obligatorisch ist.
///
/// HINWEIS: Das Präfix ist obligatorisch (darf nicht `None` oder leer sein).
///
/// Diese Anforderung ist eine fundamentale Sicherheitsentscheidung, um die
/// Integrität der Kontentrennung im "Separated Account Identity (SAI)" zu gewährleisten.
///
/// **Begründung (Verhinderung von Double Spends):**
/// Ein Benutzer kann dieselbe Mnemonic (und damit denselben Public Key,
/// z.B. `...did:key:zABC`) auf mehreren Geräten (z.B. PC und Mobiltelefon) verwenden.
///
/// Damit ein an `pc-123@did:key:zABC` gesendeter Gutschein nicht versehentlich
/// auch vom Mobiltelefon (z.B. `mobil-456@did:key:zABC`) angenommen werden kann,
/// muss die Wallet-Logik die *gesamte User-ID* strikt prüfen.
///
/// Indem wir ein Präfix erzwingen, vereinfachen wir das mentale Modell für den
/// Benutzer drastisch: "Jedes Gerät/Konto benötigt einen eigenen, eindeutigen
/// Namen (Präfix)."
///
/// Ein leeres Präfix würde zu einer "Standard-Adresse" (z.B. `789@did:key:zABC`)
/// führen, was die Anweisungen für Benutzer verkompliziert und das Risiko von
/// Zustands-Inkonsistenzen erhöht.
#[test]
fn test_user_id_creation_requires_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None)?;

    // 1. Test: `None` als Präfix muss fehlschlagen
    let result_none = create_user_id(&ed_pub, None);
    assert!(matches!(result_none, Err(UserIdError::PrefixEmpty)));
    println!("SUCCESS: create_user_id correctly failed for None prefix.");

    // 2. Test: Ein leeres String-Präfix muss fehlschlagen
    let result_empty = create_user_id(&ed_pub, Some(""));
    assert!(matches!(result_empty, Err(UserIdError::PrefixEmpty)));
    println!("SUCCESS: create_user_id correctly failed for empty string prefix.");

    // 3. Test: Ein gültiges Präfix muss erfolgreich sein
    let prefix = "pc";
    let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix))?;
    assert!(!user_id_with_prefix.is_empty());
    println!("User ID (prefix '{}'): {}", prefix, user_id_with_prefix);

    let is_valid = validate_user_id(&user_id_with_prefix);
    assert!(is_valid);
    println!("Checksum validation for user_id: {}", is_valid);
    Ok(())
}

#[test]
fn test_ed25519_to_x25519_conversion() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None)?;
    let x25519_pub = ed25519_pub_to_x25519(&ed_pub);
    assert_eq!(x25519_pub.as_bytes().len(), 32);
    println!("X25519 Public Key: {}", hex::encode(x25519_pub.to_bytes()));
    Ok(())
}

#[test]
fn test_ephemeral_dh_key_generation() {
    let (alice_dh_pub, alice_dh_priv) = generate_ephemeral_x25519_keypair();
    let (bob_dh_pub, bob_dh_priv) = generate_ephemeral_x25519_keypair();
    assert_eq!(alice_dh_pub.as_bytes().len(), 32);
    assert_eq!(bob_dh_pub.as_bytes().len(), 32);
    println!("Alice's ephemeral public key: {}", hex::encode(alice_dh_pub.to_bytes()));
    println!("Bob's ephemeral public key: {}", hex::encode(bob_dh_pub.to_bytes()));

    let alice_shared = perform_diffie_hellman(alice_dh_priv, &bob_dh_pub);
    let bob_shared = perform_diffie_hellman(bob_dh_priv, &alice_dh_pub);
    assert_eq!(alice_shared.len(), 32);
    assert_eq!(bob_shared.len(), 32);
    println!("Alice's shared secret: {}", hex::encode(alice_shared));
    println!("Bob's shared secret: {}", hex::encode(bob_shared));

    assert_eq!(alice_shared, bob_shared);
    println!("Success! Shared secrets match.");
}

#[test]
fn test_ed25519_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    let (_, ed_priv) = derive_ed25519_keypair(&mnemonic, None)?;
    let message = b"Voucher system test message";

    let signature = sign_ed25519(&ed_priv, message);
    let ed_pub = ed_priv.verifying_key();
    let is_valid = verify_ed25519(&ed_pub, message, &signature);
    assert!(is_valid);
    println!("Signature valid? {}", is_valid);

    let tampered_message = b"Voucher system test messagE";
    let is_valid_tampered = verify_ed25519(&ed_pub, tampered_message, &signature);
    assert!(!is_valid_tampered);
    println!("Tampered message valid? {}", is_valid_tampered);
    Ok(())
}

#[test]
fn test_get_pubkey_from_user_id() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, Language::English)?;
    let (ed_pub, ed_sk) = derive_ed25519_keypair(&mnemonic, None)?;
    let prefix = "ID";
    let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();

    let recovered_ed_pub = get_pubkey_from_user_id(&user_id_with_prefix)?;
    assert_eq!(ed_pub.to_bytes(), recovered_ed_pub.to_bytes());
    println!("Recovered key matches original key.");

    let message = b"Voucher system test message";
    let signature = sign_ed25519(&ed_sk, message);
    let is_valid_recovered = verify_ed25519(&recovered_ed_pub, message, &signature);
    assert!(is_valid_recovered);
    println!("Signature valid (using RECOVERED key)? {}", is_valid_recovered);
    Ok(())
}

#[test]
fn test_static_encryption_flow() {
    // 1. Erzeuge zwei deterministische Identitäten für einen wiederholbaren Test.
    let (alice_ed_pub, alice_ed_sk) = generate_ed25519_keypair_for_tests(Some("alice"));
    let (bob_ed_pub, bob_ed_sk) = generate_ed25519_keypair_for_tests(Some("bob"));

    // 2. Teste die Konvertierung des geheimen Schlüssels.
    // Die Konvertierung muss konsistent sein: Der aus dem konvertierten geheimen Schlüssel
    // abgeleitete öffentliche Schlüssel muss mit dem direkt konvertierten öffentlichen
    // Schlüssel übereinstimmen.
    let alice_x_sk_static = ed25519_sk_to_x25519_sk(&alice_ed_sk);
    let alice_x_pub_from_sk = X25519PublicKey::from(&alice_x_sk_static);
    let alice_x_pub_from_pub = ed25519_pub_to_x25519(&alice_ed_pub);
    assert_eq!(alice_x_pub_from_sk.as_bytes(), alice_x_pub_from_pub.as_bytes());
    println!("SUCCESS: Private key conversion (Ed25519 -> X25519) is consistent.");

    // 3. Führe einen statischen Diffie-Hellman-Austausch durch.
    // Alice verwendet ihren statischen geheimen Schlüssel und Bobs öffentlichen Schlüssel.
    let bob_x_pub = ed25519_pub_to_x25519(&bob_ed_pub);
    let shared_secret_alice = alice_x_sk_static.diffie_hellman(&bob_x_pub);

    // Bob macht dasselbe mit seinem statischen geheimen Schlüssel und Alice' öffentlichem Schlüssel.
    let bob_x_sk_static = ed25519_sk_to_x25519_sk(&bob_ed_sk);
    let shared_secret_bob = bob_x_sk_static.diffie_hellman(&alice_x_pub_from_pub);

    // Beide müssen zum selben Ergebnis kommen.
    assert_eq!(shared_secret_alice.as_bytes(), shared_secret_bob.as_bytes());
    println!("SUCCESS: Static Diffie-Hellman resulted in a matching shared secret.");

    // 4. Leite einen sicheren Verschlüsselungsschlüssel aus dem gemeinsamen Geheimnis ab (Best Practice).
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret_alice.as_bytes());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(b"voucher-p2p-encryption", &mut encryption_key).unwrap();

    // 5. Teste die Ver- und Entschlüsselung.
    let plaintext = b"This is a secret message for Bob.";
    println!("Plaintext: '{}'", std::str::from_utf8(plaintext).unwrap());

    let encrypted_data = encrypt_data(&encryption_key, plaintext).unwrap();
    println!("Encrypted (hex, nonce prefixed): {}", hex::encode(&encrypted_data));
    assert_ne!(plaintext, &encrypted_data[..]); // Sicherstellen, dass es kein Klartext ist.

    let decrypted_data = decrypt_data(&encryption_key, &encrypted_data).unwrap();
    println!("Decrypted: '{}'", std::str::from_utf8(&decrypted_data).unwrap());
    assert_eq!(plaintext.to_vec(), decrypted_data);
    println!("SUCCESS: Message was encrypted and decrypted correctly.");

    // 6. Negativtest: Entschlüsselung mit falschem Schlüssel muss fehlschlagen.
    let mut wrong_key = encryption_key;
    wrong_key[0] ^= 0xff; // Einen Bit im Schlüssel ändern.
    let result = decrypt_data(&wrong_key, &encrypted_data);
    assert!(result.is_err(), "Decryption should fail with a wrong key");
    println!("SUCCESS: Decryption correctly failed with the wrong key.");
}