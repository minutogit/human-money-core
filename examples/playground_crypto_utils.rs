// examples/playground_crypto_utils.rs
// run with: cargo run --example playground_crypto_utils
// more playgrounds 

use voucher_lib::services::crypto_utils::{
    generate_mnemonic, 
    derive_ed25519_keypair,
    generate_ephemeral_x25519_keypair,
    perform_diffie_hellman,
    ed25519_pub_to_x25519,
    sign_ed25519,
    verify_ed25519,
    create_user_id,
    validate_user_id,
    get_pubkey_from_user_id,
    get_hash
};
use bip39::Language;
use hex;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting program...");
    
    let input = "text for hashtest";
    let hash = get_hash(input);
    println!("Base58 hash: {}", hash);

    // Mnemonic generieren
    println!("\nGenerating mnemonic...");
    let mnemonic = generate_mnemonic(24, Language::English)?;
    println!("Mnemonic phrase: {}", mnemonic);

    // Ed25519-Schlüsselpaar ableiten
    println!("\nDeriving Ed25519 keys...");
    let (ed_pub, ed_priv) = derive_ed25519_keypair(&mnemonic, None)?; 
    println!("Ed25519 Public Key: {}", hex::encode(ed_pub.to_bytes()));
    println!("Ed25519 Private Key: {}", hex::encode(ed_priv.to_bytes()));

    // User ID generieren und ausgeben
    println!("\nGenerating User IDs...");

    // 1. Mit Präfix "main" (da Präfix jetzt obligatorisch ist)
    let prefix = "main";
    let user_id_with_prefix = create_user_id(&ed_pub, Some(prefix)).unwrap();
    println!("User ID (prefix '{}'): {}", prefix, user_id_with_prefix);

    // 2. Mit Präfix "work" 
    let prefix2 = "work";
    let user_id_with_prefix2 = create_user_id(&ed_pub, Some(prefix2)).unwrap();
    println!("User ID (prefix '{}'): {}", prefix2, user_id_with_prefix2);

    // Prüfe die Checksumme der generierten user_id
    let is_valid = validate_user_id(&user_id_with_prefix);
    println!("Checksum validation for user_id: {}", is_valid);

    // Ed25519 zu X25519 konvertieren
    println!("\nConverting to X25519...");
    let x25519_pub = ed25519_pub_to_x25519(&ed_pub);
    println!("X25519 Public Key: {}", hex::encode(x25519_pub.to_bytes()));

    // Ephemere DH-Schlüssel generieren
    println!("\nGenerating ephemeral DH keys...");
    let (alice_dh_pub, alice_dh_priv) = generate_ephemeral_x25519_keypair();
    let (bob_dh_pub, bob_dh_priv) = generate_ephemeral_x25519_keypair();
    
    println!("Alice's ephemeral public key: {}", hex::encode(alice_dh_pub.to_bytes()));
    println!("Bob's ephemeral public key: {}", hex::encode(bob_dh_pub.to_bytes()));

    // Schlüsselaustausch durchführen
    println!("\nPerforming Diffie-Hellman...");
    let alice_shared = perform_diffie_hellman(alice_dh_priv, &bob_dh_pub);
    let bob_shared = perform_diffie_hellman(bob_dh_priv, &alice_dh_pub);
    
    println!("Alice's shared secret: {}", hex::encode(alice_shared));
    println!("Bob's shared secret: {}", hex::encode(bob_shared));
    
    // Verifizieren dass die Secrets übereinstimmen
    assert_eq!(alice_shared, bob_shared);
    println!("\nSuccess! Shared secrets match.");

    // Ed25519 Signatur-Beispiel
    println!("\nTesting Ed25519 signatures...");
    let message = b"Voucher system test message";
    
    // Nachricht signieren
    let signature = sign_ed25519(&ed_priv, message);
    println!("\nMessage: {}", String::from_utf8_lossy(message));
    println!("Signature: {}", hex::encode(signature.to_bytes()));
    println!("Public key: {}", hex::encode(ed_pub.to_bytes()));
    
    // Signatur verifizieren
    let is_valid = verify_ed25519(&ed_pub, message, &signature);
    println!("Signature valid? {}", is_valid);
    
    // Test mit manipulierter Nachricht
    let tampered_message = b"Voucher system test messagE";
    let is_valid_tampered = verify_ed25519(&ed_pub, tampered_message, &signature);
    println!("Tampered message valid? {}", is_valid_tampered);

    // Signaturprüfung mit wiederhergestelltem Schlüssel von der user_id
    println!("\nTesting signature verification with key recovered from User ID...");
    println!("Using User ID: {}", user_id_with_prefix);

    // Konvertiere User ID zurück in Public Key
    let recovered_ed_pub = get_pubkey_from_user_id(&user_id_with_prefix)?;

    println!("Recovered public key: {}", hex::encode(recovered_ed_pub.to_bytes()));

    // Vergleiche wiederhergestellten Schlüssel mit Original (Bytes)
    assert_eq!(ed_pub.to_bytes(), recovered_ed_pub.to_bytes(), "Original and recovered keys DO NOT match!");
    println!("Recovered key matches original key.");

    // Signatur mit dem *wiederhergestellten* Public Key verifizieren
    let is_valid_recovered = verify_ed25519(&recovered_ed_pub, message, &signature);
    println!("Signature valid (using RECOVERED key)? {}", is_valid_recovered);
    assert!(is_valid_recovered);

    Ok(())
}
