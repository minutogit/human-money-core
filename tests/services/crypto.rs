// tests/services/crypto.rs
// cargo test --test services_tests
//!
//! Bundles all cryptographic tests, including logic for
//! the Secure Container and general crypto utilities.

// Explicit path specification for the `test_utils` module to avoid ambiguities.

// --- Tests from test_secure_container.rs ---
use human_money_core::VoucherCoreError;
use human_money_core::models::secure_container::{ContainerConfig, PayloadType, PrivacyMode, SecureContainer};
use human_money_core::test_utils::ACTORS;

#[test]
fn test_multi_recipient_secure_container() {
    // --- 1. SETUP ---
    // Create a sender (Alice) and three other individuals.
    // Bob and Carol will be the legitimate recipients.
    // Dave is an unauthorized third party.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let carol_identity = &ACTORS.charlie; // Charlie represents Carol
    let david_identity = &ACTORS.david;

    // --- 2. CONTAINER CREATION ---
    // Alice creates a secret message for Bob and Carol.
    let secret_payload = b"This is a secret message for Bob and Carol!";
    let recipient_ids = vec![bob_identity.user_id.clone(), carol_identity.user_id.clone()];

    let container = SecureContainer::seal(
        alice_identity,
        &ContainerConfig::TargetDids(recipient_ids, PrivacyMode::TrialDecryption),
        secret_payload,
        PayloadType::Generic("test_message".to_string()),
    )
    .unwrap();

    // --- 3. VERIFICATION BY RECIPIENTS ---

    // Bob attempts to open the container.
    let bob_payload = container.open(bob_identity, None).unwrap();
    assert_eq!(bob_payload, secret_payload);
    assert_eq!(
        container.c,
        PayloadType::Generic("test_message".to_string())
    );
    println!("SUCCESS: Bob successfully opened the container.");

    // Carol attempts to open the same container.
    let carol_payload = container.open(carol_identity, None).unwrap();
    assert_eq!(carol_payload, secret_payload);
    assert_eq!(
        container.c,
        PayloadType::Generic("test_message".to_string())
    );
    println!("SUCCESS: Carol successfully opened the container.");

    // --- 4. VERIFICATION BY UNAUTHORIZED THIRD PARTY ---

    // Dave attempts to open the container. This MUST fail.
    let david_result = container.open(david_identity, None);
    assert!(david_result.is_err());
    assert!(matches!(
        david_result.unwrap_err(),
        VoucherCoreError::NotAnIntendedRecipient
    ));
    println!("SUCCESS: Dave could not open the container, as expected.");
}

/// Tests whether the sender can re-open a container they created.
/// This is the critical test case for "Double Key Wrapping".
#[test]
fn test_sender_can_reopen_container() {
    // --- 1. SETUP ---
    let sender = &ACTORS.sender;
    let recipient = &ACTORS.recipient1;
    let payload = b"message for recipient that sender must be able to read later";

    // --- 2. CONTAINER CREATION ---
    // Sender creates a container for the recipient.
    let container = SecureContainer::seal(
        sender,
        &ContainerConfig::TargetDids(vec![recipient.user_id.clone()], PrivacyMode::TrialDecryption),
        payload,
        PayloadType::TransactionBundle,
    )
    .unwrap();

    // --- 3. VERIFICATION BY RECIPIENT (Standard Case) ---
    // The recipient can open the container.
    let recipient_payload = container.open(recipient, None).unwrap();
    assert_eq!(
        recipient_payload, payload,
        "Recipient should be able to open the container"
    );

    // --- 4. VERIFICATION BY SENDER (Critical Test Case) ---
    // The sender must also be able to open the same container.
    let sender_payload = container.open(sender, None).unwrap();
    assert_eq!(
        sender_payload, payload,
        "Sender should be able to re-open their own container"
    );
    println!("SUCCESS: Sender was able to re-open the container, Double Key Wrapping works.");
}

// --- Tests from test_crypto_utils.rs ---

use human_money_core::MnemonicLanguage;
use hkdf::Hkdf;
use human_money_core::services::crypto::{
    create_user_id, decrypt_data, derive_ed25519_keypair, ed25519_pub_to_x25519,
    ed25519_sk_to_x25519_sk, encrypt_data, generate_ed25519_keypair_for_tests,
    generate_ephemeral_x25519_keypair, generate_mnemonic, get_pubkey_from_user_id,
    perform_diffie_hellman, sign_ed25519, validate_mnemonic_phrase, validate_user_id,
    verify_ed25519,
};
use sha2::Sha256;
use x25519_dalek::PublicKey as X25519PublicKey;

#[test]
fn test_generate_mnemonic() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    assert!(!mnemonic.is_empty());
    println!("Generated mnemonic: {}", mnemonic);
    Ok(())
}

#[test]
fn test_derive_ed25519_keypair() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;
    assert_eq!(ed_pub.as_bytes().len(), 32);
    assert_eq!(ed_priv.as_bytes().len(), 32);
    println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
    println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));
    Ok(())
}

#[test]
fn test_validate_mnemonic() {
    // 1. Test with a known valid phrase
    let valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let result = validate_mnemonic_phrase(valid_mnemonic, MnemonicLanguage::English);
    assert!(
        result.is_ok(),
        "Validation of a correct mnemonic failed. Error: {:?}",
        result.err()
    );
    println!("SUCCESS: Correctly validated a valid mnemonic.");

    // 2. Test with an invalid word
    let invalid_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    let result = validate_mnemonic_phrase(invalid_word_mnemonic, MnemonicLanguage::English);
    assert!(
        result.is_err(),
        "Validation should have failed for an invalid word."
    );
    println!("SUCCESS: Correctly identified a mnemonic with an invalid word.");

    // 3. Test with an invalid checksum
    // "about" was replaced by "abandon", making the checksum invalid.
    let bad_checksum_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    let result = validate_mnemonic_phrase(bad_checksum_mnemonic, MnemonicLanguage::English);
    assert!(
        result.is_err(),
        "Validation should have failed for a bad checksum."
    );
    println!("SUCCESS: Correctly identified a mnemonic with a bad checksum.");
}

/// Tests user ID creation for root accounts and prefix accounts.
///
/// A root account is defined by a missing (`None`) or empty (`Some("")`)
/// prefix. In this case, the pure `did:key` is returned.
/// This enables simple interoperability and a flat account model
/// for users who do not require SAI separation.
#[test]
fn test_user_id_creation_supports_root_and_prefix() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;

    // 1. Test: `None` as prefix creates a root account (pure did:key)
    let root_id_none = create_user_id(&ed_pub, None).unwrap();
    assert!(!root_id_none.contains('@'));
    assert!(root_id_none.starts_with("did:key:z"));
    println!("Root ID (None): {}", root_id_none);

    // 2. Test: An empty string prefix also creates a root account
    let root_id_empty = create_user_id(&ed_pub, Some("")).unwrap();
    assert_eq!(root_id_none, root_id_empty);
    println!("Root ID (empty string): {}", root_id_empty);

    // 3. Test: A valid prefix creates a SAI ID with checksum
    let prefix = "pc";
    let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix))?;
    assert!(user_id_with_prefix.contains('@'));
    assert!(user_id_with_prefix.starts_with("pc:"));
    println!("User ID (prefix '{}'): {}", prefix, user_id_with_prefix);

    // Validation for all formats
    assert!(validate_user_id(&root_id_none));
    assert!(validate_user_id(&user_id_with_prefix));
    
    Ok(())
}

#[test]
fn test_ed25519_to_x25519_conversion() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    let (ed_pub, _) = derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;
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
    println!(
        "Alice's ephemeral public key: {}",
        hex::encode(alice_dh_pub.to_bytes())
    );
    println!(
        "Bob's ephemeral public key: {}",
        hex::encode(bob_dh_pub.to_bytes())
    );

    let alice_shared = perform_diffie_hellman(alice_dh_priv, &bob_dh_pub, "test-recipient").unwrap();
    let bob_shared = perform_diffie_hellman(bob_dh_priv, &alice_dh_pub, "test-recipient").unwrap();
    assert_eq!(alice_shared.len(), 32);
    assert_eq!(bob_shared.len(), 32);
    println!("Alice's shared secret: {}", hex::encode(alice_shared));
    println!("Bob's shared secret: {}", hex::encode(bob_shared));

    assert_eq!(alice_shared, bob_shared);
    println!("Success! Shared secrets match.");
}

#[test]
fn test_ed25519_signature() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    let (_, ed_priv) = derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;
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
    let mnemonic = generate_mnemonic(24, MnemonicLanguage::English)?;
    let (ed_pub, ed_sk) = derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;
    let prefix = "ID";
    let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();

    let recovered_ed_pub = get_pubkey_from_user_id(&user_id_with_prefix)?;
    assert_eq!(ed_pub.to_bytes(), recovered_ed_pub.to_bytes());
    println!("Recovered key matches original key.");

    let message = b"Voucher system test message";
    let signature = sign_ed25519(&ed_sk, message);
    let is_valid_recovered = verify_ed25519(&recovered_ed_pub, message, &signature);
    assert!(is_valid_recovered);
    println!(
        "Signature valid (using RECOVERED key)? {}",
        is_valid_recovered
    );
    Ok(())
}

#[test]
fn test_static_encryption_flow() {
    // 1. Generate two deterministic identities for a repeatable test.
    let (alice_ed_pub, alice_ed_sk) = generate_ed25519_keypair_for_tests(Some("alice"));
    let (bob_ed_pub, bob_ed_sk) = generate_ed25519_keypair_for_tests(Some("bob"));

    // 2. Test private key conversion.
    // The conversion must be consistent: The public key derived from the converted
    // private key must match the directly converted public key.
    let alice_x_sk_static = ed25519_sk_to_x25519_sk(&alice_ed_sk);
    let alice_x_pub_from_sk = X25519PublicKey::from(&alice_x_sk_static);
    let alice_x_pub_from_pub = ed25519_pub_to_x25519(&alice_ed_pub);
    assert_eq!(
        alice_x_pub_from_sk.as_bytes(),
        alice_x_pub_from_pub.as_bytes()
    );
    println!("SUCCESS: Private key conversion (Ed25519 -> X25519) is consistent.");

    // 3. Perform a static Diffie-Hellman exchange.
    // Alice uses her static private key and Bob's public key.
    let bob_x_pub = ed25519_pub_to_x25519(&bob_ed_pub);
    let shared_secret_alice = alice_x_sk_static.diffie_hellman(&bob_x_pub);

    // Bob does the same with his static private key and Alice's public key.
    let bob_x_sk_static = ed25519_sk_to_x25519_sk(&bob_ed_sk);
    let shared_secret_bob = bob_x_sk_static.diffie_hellman(&alice_x_pub_from_pub);

    // Both must arrive at the same result.
    assert_eq!(shared_secret_alice.as_bytes(), shared_secret_bob.as_bytes());
    println!("SUCCESS: Static Diffie-Hellman resulted in a matching shared secret.");

    // 4. Derive a secure encryption key from the shared secret (Best Practice).
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret_alice.as_bytes());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(b"voucher-p2p-encryption", &mut encryption_key)
        .unwrap();

    // 5. Test encryption and decryption.
    let plaintext = b"This is a secret message for Bob.";
    println!("Plaintext: '{}'", std::str::from_utf8(plaintext).unwrap());

    let encrypted_data = encrypt_data(&encryption_key, plaintext).unwrap();
    println!(
        "Encrypted (hex, nonce prefixed): {}",
        hex::encode(&encrypted_data)
    );
    assert_ne!(plaintext, &encrypted_data[..]); // Ensure it is not plaintext.

    let decrypted_data = decrypt_data(&encryption_key, &encrypted_data).unwrap();
    println!(
        "Decrypted: '{}'",
        std::str::from_utf8(&decrypted_data).unwrap()
    );
    assert_eq!(plaintext.to_vec(), decrypted_data);
    println!("SUCCESS: Message was encrypted and decrypted correctly.");

    // 6. Negative test: Decryption with wrong key must fail.
    let mut wrong_key = encryption_key;
    wrong_key[0] ^= 0xff; // Flip one bit in the key.
    let result = decrypt_data(&wrong_key, &encrypted_data);
    assert!(result.is_err(), "Decryption should fail with a wrong key");
    println!("SUCCESS: Decryption correctly failed with the wrong key.");
}


