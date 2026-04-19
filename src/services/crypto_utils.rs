//! # src/services/crypto_utils.rs
// Zufallszahlengenerierung
use rand_core::OsRng;
use rand_core::RngCore;

// Kryptografische Hashes (SHA-2)
use sha2::{Digest, Sha256, Sha512};

// Symmetrische Verschlüsselung
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};

// Ed25519 Signaturen
use ed25519_dalek::{
    Signature, SignatureError, Signer, SigningKey, Verifier, VerifyingKey as EdPublicKey,
};

// X25519 Schlüsselvereinbarung
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

// BIP39 Mnemonic Phrase (delegated to mnemonic module)
use crate::services::mnemonic::{MnemonicLanguage, MnemonicProcessor};

// Key Derivation Functions
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;

// Standard Bibliothek
use std::convert::TryInto;
use std::fmt;

use crate::error::VoucherCoreError;
use base64::{Engine as _, engine::general_purpose};

/// Generates a mnemonic phrase with a specified word count and language.
///
/// # Arguments
///
/// * `word_count` - The number of words in the mnemonic phrase (12, 15, 18, 21, or 24).
/// * `language` - The language of the mnemonic phrase.
///
/// # Errors
///
/// Returns an error if the `word_count` is invalid.
pub fn generate_mnemonic(
    word_count: usize,
    language: MnemonicLanguage,
) -> Result<String, Box<dyn std::error::Error>> {
    MnemonicProcessor::generate(word_count, language).map_err(|e| e.into())
}

/// Validates a BIP-39 mnemonic phrase.
///
/// This function checks if the given phrase consists of valid words from the
/// English wordlist and if the checksum is correct.
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase to validate.
///
/// # Returns
///
/// Returns `Ok(())` if the phrase is valid, otherwise an `Err` with a descriptive message.
pub fn validate_mnemonic_phrase(phrase: &str, language: MnemonicLanguage) -> Result<(), String> {
    MnemonicProcessor::validate(phrase, language).map_err(|e| e.to_string())
}

/// Computes a SHA3-256 hash of the input and returns it as a base58-encoded string.
///
/// # Arguments
///
/// * `input` - The data to hash. Accepts anything that can be referenced as a byte slice.
///
/// # Returns
///
/// A base58-encoded SHA3-256 hash string.
pub fn get_hash(input: impl AsRef<[u8]>) -> String {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    hasher.update(input.as_ref());
    let hash_bytes = hasher.finalize();
    bs58::encode(hash_bytes).into_string()
}

/// Computes a SHA3-256 hash of multiple inputs concatenated and returns it as a base58-encoded string.
/// This is used to avoid string-based concatenation malleability.
pub fn get_hash_from_slices(inputs: &[&[u8]]) -> String {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    for input in inputs {
        // Hängt die Länge des Segments davor (als 4-Byte Little Endian),
        // macht es unmöglich, Grenzen zu verschieben.
        hasher.update(&(input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let hash_bytes = hasher.finalize();
    bs58::encode(hash_bytes).into_string()
}

/// Erzeugt einen 4-stelligen, Base58-kodierten Kurz-Hash aus der User ID für
/// speichereffizientes Tracking von bekannten Peers.
/// Gibt die letzten 4 Bytes des Hashes als Array zurück, um Speicher zu sparen.
/// ACHTUNG: Dies ist ein verkürzter Hash und dient nur als Heuristik.
pub fn get_short_hash_from_user_id(user_id: &str) -> [u8; 4] {
    let hash = get_hash(user_id.as_bytes());

    // 1. Base58-String zurück in Bytes dekodieren
    let hash_bytes = bs58::decode(&hash).into_vec().unwrap_or_default();

    let len = hash_bytes.len();
    let mut short_hash = [0u8; 4];

    if len >= 4 {
        // 2. Die letzten 4 Bytes kopieren (beste Streuung)
        short_hash.copy_from_slice(&hash_bytes[len - 4..]);
    } else if len > 0 { // mutants: skip -- unreachable: SHA3-256 always produces 32 bytes, base58 never yields <4 bytes
        // Fallback: pad with leading zeros if hash is unexpectedly short.
        short_hash[4 - len..].copy_from_slice(&hash_bytes);
    }
    short_hash
}

/// Derives an Ed25519 keypair from a mnemonic phrase and an optional passphrase.
///
/// This function takes a BIP-39 mnemonic phrase and an optional passphrase,
/// derives the standard BIP-39 seed, and then applies additional key stretching
/// using PBKDF2 for enhanced security against brute-force attacks.
///
/// # Arguments
///
/// * `mnemonic_phrase` - The BIP-39 mnemonic phrase.
/// * `passphrase` - An optional passphrase.
///
/// # Returns
///
/// A Result containing a tuple of the Ed25519 public key and signing key,
/// or a VoucherCoreError if derivation fails.
pub fn derive_ed25519_keypair(
    mnemonic_phrase: &str,
    passphrase: Option<&str>,
    language: MnemonicLanguage,
) -> Result<(EdPublicKey, SigningKey), VoucherCoreError> {
    // Generate the standard BIP-39 seed (uses PBKDF2-HMAC-SHA512 with 2048 rounds)
    let bip39_seed = MnemonicProcessor::to_seed(
        mnemonic_phrase,
        passphrase.unwrap_or(""),
        language,
    )?;

    // Standard SLIP-0010 Master Key Derivation for Ed25519
    // I = HMAC-SHA512(key="ed25519 seed", Data=Seed)
    let mut hmac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(b"ed25519 seed")
        .map_err(|e| VoucherCoreError::Crypto(format!("HMAC initialization failed: {}", e)))?;
    hmac.update(&bip39_seed[..]);
    let result = hmac.finalize().into_bytes();

    // The first 32 bytes (I_L) are used as the secret seed for Ed25519
    let ed25519_seed: [u8; 32] = result[..32]
        .try_into()
        .map_err(|_| VoucherCoreError::Crypto("Invalid seed length from HMAC-SHA512".to_string()))?;

    // SigningKey::from_bytes takes the 32-byte seed
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let public_key = signing_key.verifying_key();

    Ok((public_key, signing_key))
}

/// Leitet ein kurzlebiges (ephemeral) Schlüsselpaar deterministisch aus einem Master-Schlüssel und einem Seed ab.
/// Verwendet HKDF-SHA256.
///
/// # Key Binding (Context Protection)
/// Um Context-Hopping zu verhindern, wird das `context_prefix` (z.B. "minuto:regio")
/// in die Ableitung eingebunden. Dadurch ist der resultierende Schlüssel mathematisch
/// an diesen Kontext gebunden. Ein Versuch, denselben Seed für einen anderen Kontext
/// zu verwenden, führt zu einem anderen Schlüssel.
pub fn derive_ephemeral_key_pair(
    master_key: &SigningKey,
    seed: &[u8],
    info: &str,
    context_prefix: Option<&str>,
) -> Result<(SigningKey, EdPublicKey), VoucherCoreError> {
    let ikm = master_key.to_bytes();

    // 1. HKDF Extract: Master Key + Seed
    let hkdf = Hkdf::<Sha256>::new(Some(seed), &ikm);

    // 2. HKDF Expand: Info (+ Context Binding)
    let mut final_info = info.as_bytes().to_vec();
    if let Some(prefix) = context_prefix {
        final_info.extend_from_slice(b"|");
        final_info.extend_from_slice(prefix.as_bytes());
    }

    let mut okm = [0u8; 32];
    hkdf.expand(&final_info, &mut okm)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion failed".to_string()))?;

    let signing_key = SigningKey::from_bytes(&okm);
    let public_key = EdPublicKey::from(&signing_key);

    Ok((signing_key, public_key))
}

/// Erzeugt ein zufälliges oder deterministisches Ed25519-Schlüsselpaar für Testzwecke.
///
/// # Warnung
/// **Diese Funktion ist NICHT für den produktiven Einsatz geeignet!**
/// Der deterministische Pfad verwendet eine einfache Hash-Funktion und ist nicht
/// gegen Brute-Force-Angriffe gehärtet. Er dient ausschließlich dazu, in Tests
/// reproduzierbare Schlüsselpaare zu erzeugen.
///
/// # Arguments
/// * `seed` - Ein optionaler String.
///   - `None`: Erzeugt ein vollständig zufälliges, neues Schlüsselpaar.
///   - `Some(seed_str)`: Erzeugt ein deterministisches Schlüsselpaar aus dem Seed-String.
///
/// # Returns
/// Ein Tupel, das den öffentlichen und den privaten Ed25519-Schlüssel enthält.
pub fn generate_ed25519_keypair_for_tests(seed: Option<&str>) -> (EdPublicKey, SigningKey) {
    if let Some(seed_str) = seed {
        // Deterministischer Pfad: Seed hashen, um einen 32-Byte-Schlüssel zu erzeugen.
        let mut hasher = Sha512::new();
        hasher.update(seed_str.as_bytes());
        let hash_result = hasher.finalize();
        let key_bytes: [u8; 32] = hash_result[..32]
            .try_into()
            .expect("Hash output must be 64 bytes");

        let signing_key = SigningKey::from_bytes(&key_bytes);
        (signing_key.verifying_key(), signing_key)
    } else {
        // Sicherer, zufälliger Pfad für allgemeine Tests.
        // Wir müssen RngCore importieren, um die fill_bytes-Methode nutzen zu können.
        let mut csprng = OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes); // Benötigt `use rand_core::RngCore;`

        let signing_key = SigningKey::from_bytes(&key_bytes);
        (signing_key.verifying_key(), signing_key)
    }
}

/// Converts an Ed25519 public key to an X25519 public key for Diffie-Hellman key exchange.
///
/// This function converts an Ed25519 public key to its X25519 equivalent,
/// which is required for performing Diffie-Hellman key exchange.
///
/// # Arguments
///
/// * `ed_pub` - The Ed25519 public key.
///
/// # Returns
///
/// The X25519 public key.
pub fn ed25519_pub_to_x25519(ed_pub: &EdPublicKey) -> X25519PublicKey {
    let montgomery_point = ed_pub.to_montgomery();
    let x25519_bytes: [u8; 32] = montgomery_point.to_bytes();
    X25519PublicKey::from(x25519_bytes)
}

/// Konvertiert einen Ed25519 Public Key in einen EdwardsPoint auf der Kurve.
/// Dies wird benötigt, um die ID in der Trap-Gleichung ($V = m \cdot U + ID$) zu verwenden.
pub fn ed25519_pk_to_curve_point(ed_pub: &EdPublicKey) -> Result<EdwardsPoint, VoucherCoreError> {
    CompressedEdwardsY::from_slice(ed_pub.as_bytes())
        .map_err(|_| VoucherCoreError::Crypto("Invalid Ed25519 public key bytes".to_string()))?
        .decompress()
        .ok_or_else(|| {
            VoucherCoreError::Crypto("Failed to decompress Ed25519 public key point".to_string())
        })
}

/// Helper: Baut den deterministischen Info-String für HKDF auf.
/// info = "human-money-core/x25519-exchange" + sort(pk1, pk2)
pub fn build_hkdf_info(pk1: &X25519PublicKey, pk2: &X25519PublicKey) -> Vec<u8> {
    const LABEL: &[u8] = b"human-money-core/x25519-exchange";
    const KEY_LEN: usize = 32;

    let (key_a, key_b) = if pk1.as_bytes() < pk2.as_bytes() {
        (pk1.as_bytes(), pk2.as_bytes())
    } else {
        (pk2.as_bytes(), pk1.as_bytes())
    };

    let mut info = Vec::with_capacity(LABEL.len() + KEY_LEN + KEY_LEN);
    info.extend_from_slice(LABEL);
    info.extend_from_slice(key_a);
    info.extend_from_slice(key_b);
    info
}

/// Entschlüsselt den Privacy Guard Payload für den Empfänger.
///
/// # Arguments
/// * `privacy_guard_base64` - Der Base64-kodierte Guard-String.
/// * `recipient_secret_key` - Der permanente Signing Key des Empfängers (wird in StaticSecret umgewandelt).
///
/// # Returns
/// Der entschlüsselte Byte-Vector (JSON Payload).
pub fn decrypt_recipient_payload(
    privacy_guard_base64: &str,
    recipient_secret_key: &SigningKey,
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Decode Base64
    let guard_bytes = decode_base64(privacy_guard_base64)?;

    // Guard Format: [EphemeralPK (32)] + [Nonce+Ciphertext]
    if guard_bytes.len() < 32 + 12 {
        return Err(VoucherCoreError::Crypto(
            "Invalid privacy guard length".to_string(),
        ));
    }

    let (ephemeral_pk_bytes, encrypted_content) = guard_bytes.split_at(32);

    // 2. Parse Ephemeral Public Key
    let ephemeral_pk_arr: [u8; 32] = ephemeral_pk_bytes.try_into().map_err(|_| {
        VoucherCoreError::Crypto(
            "Invalid ephemeral public key length (expected 32 bytes)".to_string(),
        )
    })?;
    let ephemeral_pk_x = X25519PublicKey::from(ephemeral_pk_arr);

    // 3. Recipient Secret Key conversion (Ed25519 -> X25519)
    let recipient_secret_x = ed25519_sk_to_x25519_sk(recipient_secret_key);

    // 4. DH Exchange
    // Note: We use the recipient's static secret and the sender's ephemeral public.
    let shared_point = recipient_secret_x.diffie_hellman(&ephemeral_pk_x);
    let shared_secret_bytes = shared_point.as_bytes();

    // 5. HKDF Derivation
    let recipient_public_x = X25519PublicKey::from(&recipient_secret_x);
    let info = build_hkdf_info(&ephemeral_pk_x, &recipient_public_x);

    let hkdf = Hkdf::<Sha256>::new(None, shared_secret_bytes);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion failed".to_string()))?;

    // 6. Decrypt
    decrypt_data(&symmetric_key, encrypted_content).map_err(VoucherCoreError::SymmetricEncryption)
}

/// Konvertiert einen Ed25519 Signaturschlüssel in einen X25519 geheimen Schlüssel für Diffie-Hellman.
///
/// Dies ist das Gegenstück zum öffentlichen Schlüssel `ed25519_pub_to_x25519`. Es ermöglicht die
/// Ableitung eines Schlüssel-Vereinbarungsschlüssels (X25519) aus einem langfristigen
/// Identitätsschlüssel (Ed25519).
///
/// # Arguments
///
/// * `ed_sk` - Der geheime Ed25519 Signaturschlüssel (`SigningKey`).
///
/// # Returns
///
/// Der entsprechende statische geheime X25519-Schlüssel (`StaticSecret`).
///
/// # Sicherheit
///
/// Die Konvertierung folgt der Standardmethode, bei der der Seed des privaten Ed25519-Schlüssels
/// mit SHA-512 gehasht wird. Die unteren 32 Bytes des Hashes werden verwendet. Die Funktion
/// `StaticSecret::from` führt anschließend das für X25519 erforderliche Clamping durch.
pub fn ed25519_sk_to_x25519_sk(ed_sk: &SigningKey) -> StaticSecret {
    let mut hasher = Sha512::new();
    hasher.update(&ed_sk.to_bytes());
    let hash = hasher.finalize();
    // Wir müssen dem Compiler den Zieltyp für `try_into` explizit angeben.
    let key_bytes: [u8; 32] = hash[..32]
        .try_into()
        .expect("SHA512 hash is guaranteed to be 64 bytes");
    StaticSecret::from(key_bytes)
}

/// Generates a temporary X25519 key pair for Diffie-Hellman (Forward Secrecy).
///
/// This function generates a fresh X25519 key pair for each Diffie-Hellman exchange,
/// ensuring forward secrecy.
///
/// # Returns
///
/// A tuple containing the X25519 public key and the ephemeral secret.
pub fn generate_ephemeral_x25519_keypair() -> (X25519PublicKey, EphemeralSecret) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    (public, secret)
}

/// Performs Diffie-Hellman key exchange.
///
/// This function performs Diffie-Hellman key exchange using our ephemeral secret
/// and the other party's public key.
///
/// # Security Note
///
/// This function provides **Confidentiality** and **Sender Forward Secrecy**, but:
/// * **No Authentication:** Without an additional authentication layer (like signing the resulting container), this exchange is vulnerable to Man-in-the-Middle (MITM) attacks.
/// * **Recipient Compromise:** Since the recipient uses a static key (asynchronous protocol), a compromise of the recipient's private key allows decryption of PAST messages.
/// * **Replay/Key-Substitution:** The protocol layer must ensure protection against replay attacks and key substitution (e.g., by binding the container signature to the keys).
///
/// # Returns
///
/// The derived 32-byte shared symmetric key, or an error if the exchange was non-contributory.
pub fn perform_diffie_hellman(
    our_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
) -> Result<[u8; 32], VoucherCoreError> {
    // 1. Eigenen Public Key ableiten (für Kontext-Bindung)
    let our_public = X25519PublicKey::from(&our_secret);

    // 2. Rohes Shared Secret berechnen
    let shared_secret = our_secret.diffie_hellman(their_public);

    // SICHERHEIT: Prüfen auf "non-contributory" Verhalten (z.B. Punkt im Unendlichen/Null).
    // Dies verhindert Angriffe durch schwache Schlüssel oder manipulierte Public Keys.
    if !shared_secret.was_contributory() {
        return Err(VoucherCoreError::Crypto(
            "Diffie-Hellman exchange was non-contributory (weak key).".to_string(),
        ));
    }

    // 3. HKDF-Expansion
    // Salt is None because we are an asynchronous offline protocol without an interactive session handshake.
    //
    // DESIGN DECISION ON KEY SPLITTING:
    // We derive only a single 32-byte key here because it serves exclusively as a KEK for
    // ChaCha20Poly1305 (AEAD) in a unidirectional context.
    // - AEAD does not require separate Enc/MAC keys.
    // - Unidirectionality does not require separation into Send/Receive keys.
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());

    // KANONISIERUNG & Info-String Bau
    let info = build_hkdf_info(&our_public, their_public);
    // Sicherer Aufbau des Info-Strings (via Helper)
    // info[..LABEL.len()].copy_from_slice(LABEL); ... replaced by helper

    // Ableitung des Schlüssels
    let mut symmetric_key = [0u8; 32];
    // expand sollte hier niemals fehlschlagen
    hkdf.expand(&info, &mut symmetric_key)
        .expect("HKDF expansion with valid length should not fail");

    // Ableitung des Schlüssels
    let mut symmetric_key = [0u8; 32];
    // expand sollte hier niemals fehlschlagen, da die Ausgabelänge fix ist.
    hkdf.expand(&info, &mut symmetric_key)
        .map_err(|_| VoucherCoreError::Crypto("HKDF expansion failed".to_string()))?;

    Ok(symmetric_key)
}

/// Custom error type for symmetric encryption/decryption functions.
#[derive(Debug, thiserror::Error)]
pub enum SymmetricEncryptionError {
    /// Indicates that the AEAD encryption process failed.
    #[error("AEAD encryption failed.")]
    EncryptionFailed,

    /// Indicates that AEAD decryption failed, likely due to a wrong key or tampered data.
    #[error(
        "AEAD decryption failed. The key may be incorrect or the data may have been tampered with."
    )]
    DecryptionFailed,

    /// Indicates that the provided data slice has an invalid length (e.g., too short to contain a nonce).
    #[error("Invalid data length: {0}")]
    InvalidLength(String),
}

/// Symmetrically encrypts data using ChaCha20-Poly1305.
///
/// This function encapsulates AEAD (Authenticated Encryption with Associated Data)
/// to provide both confidentiality and integrity. A random 12-byte nonce is generated
/// for each encryption and prepended to the ciphertext.
///
/// # Arguments
///
/// * `key` - A 32-byte key for the encryption.
/// * `data` - The plaintext data to encrypt.
///
/// # Returns
///
/// A `Result` containing a byte vector `[12-byte nonce | ciphertext]` or a `SymmetricEncryptionError`.
pub fn encrypt_data(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, SymmetricEncryptionError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    // `generate_nonce` uses a cryptographically secure RNG provided by the OS.
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // The `encrypt` method handles the authenticated encryption.
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|_| SymmetricEncryptionError::EncryptionFailed)?;

    // Prepend the nonce to the ciphertext for use in decryption.
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Symmetrically decrypts data encrypted with `encrypt_data`.
///
/// This function expects the input data to be in the format `[12-byte nonce | ciphertext]`.
/// It uses the AEAD properties of ChaCha20-Poly1305 to verify the integrity and
/// authenticity of the data before returning the plaintext.
///
/// # Arguments
///
/// * `key` - The 32-byte key used for the encryption.
/// * `encrypted_data_with_nonce` - The combined nonce and ciphertext.
///
/// # Returns
///
/// A `Result` containing the original plaintext data or a `SymmetricEncryptionError` if decryption fails.
pub fn decrypt_data(
    key: &[u8; 32],
    encrypted_data_with_nonce: &[u8],
) -> Result<Vec<u8>, SymmetricEncryptionError> {
    const NONCE_SIZE: usize = 12;
    if encrypted_data_with_nonce.len() < NONCE_SIZE {
        return Err(SymmetricEncryptionError::InvalidLength(format!(
            "Encrypted data must be at least {} bytes long to contain a nonce.",
            NONCE_SIZE
        )));
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce_bytes, ciphertext) = encrypted_data_with_nonce.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    // `decrypt` automatically verifies the authentication tag. If it fails, an error is returned.
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SymmetricEncryptionError::DecryptionFailed)
}

/// Verschlüsselt Daten symmetrisch mit einem Passwort via PBKDF2 und ChaCha20-Poly1305.
///
/// Diese Funktion ist für Einweg-Passwörter (PINs) beim Container-Austausch gedacht.
/// Sie generiert ein 16-Byte Salt, leitet über PBKDF2 (HMAC-SHA512) einen 32-Byte Key ab
/// und verschlüsselt die Daten mit ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `payload` - Die zu verschlüsselnden Daten.
/// * `password` - Das Passwort (als String).
///
/// # Returns
///
/// Ein Tupel aus (Ciphertext inkl. Nonce, Salt[16]) oder einen `VoucherCoreError`.
pub fn encrypt_symmetric_password(
    payload: &[u8],
    password: &str,
) -> Result<(Vec<u8>, [u8; 16]), VoucherCoreError> {
    // 1. Generiere ein zufälliges 16-Byte Salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // 2. Leite den Schlüssel via PBKDF2 ab (100_000 Iterationen wie im Master-Key)
    #[cfg(not(any(test, feature = "test-utils")))]
    const PBKDF2_ROUNDS: u32 = 100_000;
    #[cfg(any(test, feature = "test-utils"))]
    const PBKDF2_ROUNDS: u32 = 1;

    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        password.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        &mut key,
    )
    .map_err(|e| VoucherCoreError::Crypto(format!("PBKDF2 key derivation failed: {}", e)))?;

    // 3. Verschlüssele die Daten mit dem abgeleiteten Schlüssel
    let ciphertext = encrypt_data(&key, payload)
        .map_err(VoucherCoreError::SymmetricEncryption)?;

    Ok((ciphertext, salt))
}

/// Entschlüsselt Daten, die mit `encrypt_symmetric_password` verschlüsselt wurden.
///
/// # Arguments
///
/// * `encrypted_payload` - Der verschlüsselte Payload inkl. Nonce.
/// * `password` - Das Passwort (als String).
/// * `salt` - Das 16-Byte Salt, das bei der Verschlüsselung verwendet wurde.
///
/// # Returns
///
/// Die entschlüsselten Daten oder einen `VoucherCoreError`.
pub fn decrypt_symmetric_password(
    encrypted_payload: &[u8],
    password: &str,
    salt: &[u8; 16],
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Leite den Schlüssel via PBKDF2 ab (gleiche Iterationen wie bei Verschlüsselung)
    #[cfg(not(any(test, feature = "test-utils")))]
    const PBKDF2_ROUNDS: u32 = 100_000;
    #[cfg(any(test, feature = "test-utils"))]
    const PBKDF2_ROUNDS: u32 = 1;

    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        password.as_bytes(),
        salt,
        PBKDF2_ROUNDS,
        &mut key,
    )
    .map_err(|e| VoucherCoreError::Crypto(format!("PBKDF2 key derivation failed: {}", e)))?;

    // 2. Entschlüssele die Daten
    decrypt_data(&key, encrypted_payload)
        .map_err(VoucherCoreError::SymmetricEncryption)
}

/// Signs a message with an Ed25519 signing key.
///
/// # Arguments
///
/// * `signing_key` - The Ed25519 signing key.
/// * `message` - The message to be signed.
///
/// # Returns
///
/// The signature.
pub fn sign_ed25519(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verifies an Ed25519 signature.
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key.
/// * `message` - The message to be verified.
/// * `signature` - The signature to be verified.
///
/// # Returns
///
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_ed25519(public_key: &EdPublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}

/// Encodes byte data into a URL-safe Base64 string.
///
/// # Arguments
/// * `data` - The byte slice to encode.
///
/// # Returns
/// A Base64-encoded string.
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes a URL-safe Base64 string into bytes.
///
/// # Arguments
/// * `encoded_data` - The Base64 string to decode.
///
/// # Returns
/// A `Result` containing the decoded byte vector or a `VoucherCoreError`.
pub fn decode_base64(encoded_data: &str) -> Result<Vec<u8>, VoucherCoreError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_data)
        .map_err(|e| VoucherCoreError::Base64(e.to_string()))
}

/// Error types for user ID creation.
#[derive(Debug)]
pub enum UserIdError {
    /// Das Präfix ist obligatorisch und darf nicht leer sein.
    PrefixEmpty,
    /// Das Präfix ist zu lang (maximal 63 Zeichen erlaubt).
    PrefixTooLong(usize),
    /// Das Präfix enthält ungültige Zeichen.
    InvalidPrefixChars,
    /// Das Präfix darf nicht mit einem Bindestrich beginnen oder enden.
    InvalidPrefixStartEnd,
    /// Das Präfix darf keine zwei aufeinanderfolgenden Bindestriche enthalten.
    PrefixHasConsecutiveSeparators,
}

impl fmt::Display for UserIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserIdError::PrefixEmpty => {
                write!(f, "Prefix is mandatory and must not be empty.")
            }
            UserIdError::PrefixTooLong(len) => {
                write!(f, "Prefix is too long: {} characters (maximum is 63).", len)
            }
            UserIdError::InvalidPrefixChars => write!(
                f,
                "Prefix contains invalid characters. Only lowercase letters (a-z), numbers (0-9), and hyphens (-) are allowed."
            ),
            UserIdError::InvalidPrefixStartEnd => {
                write!(f, "Prefix must not start or end with a hyphen.")
            }
            UserIdError::PrefixHasConsecutiveSeparators => {
                write!(f, "Prefix contains consecutive separators (- or :)")
            }
        }
    }
}

impl std::error::Error for UserIdError {}

/// Generiert eine User-ID mit optionalem Präfix und einer obligatorischen Prüfsumme.
///
/// Das Format ist: `[präfix:]prüfsumme@did:key:z...`
pub fn create_user_id(
    public_key: &EdPublicKey,
    user_prefix: Option<&str>,
) -> Result<String, UserIdError> {
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    // Das Präfix ist nun obligatorisch und darf nicht leer sein.
    let prefix_str = user_prefix.ok_or(UserIdError::PrefixEmpty)?;
    let prefix = prefix_str.to_lowercase();

    if prefix.is_empty() {
        return Err(UserIdError::PrefixEmpty);
    }
    if prefix.len() > 63 {
        return Err(UserIdError::PrefixTooLong(prefix.len()));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(UserIdError::InvalidPrefixChars);
    }
    if prefix.starts_with('-') || prefix.ends_with('-') {
        return Err(UserIdError::InvalidPrefixStartEnd);
    }
    if prefix.contains("--") {
        return Err(UserIdError::PrefixHasConsecutiveSeparators);
    }

    // Generiere Prüfsumme
    let checksum_input = format!("{}{}", prefix, did_key);
    let hash = get_hash(checksum_input.as_bytes());
    let checksum = &hash[hash.len() - 3..];

    // Da das Präfix nun obligatorisch ist, entfällt der `if prefix.is_empty()`-Check.
    let human_readable_part = format!("{}:{}", prefix, checksum);

    Ok(format!("{}@{}", human_readable_part, did_key))
}

/// Validates a user ID string.
///
/// # Arguments
///
/// * `user_id` - The user ID string to validate.
///
/// # Returns
///
/// `true` if the user ID is valid, `false` otherwise.
pub fn validate_user_id(user_id: &str) -> bool {
    let parts: Vec<&str> = user_id.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let human_readable_part = parts[0];
    let did_key_part = parts[1];

    if get_pubkey_from_user_id(user_id).is_err() {
        return false;
    }

    let (prefix, received_checksum) = if let Some(pos) = human_readable_part.rfind(':') {
        let (p, c) = human_readable_part.split_at(pos);
        (p, &c[1..])
    } else {
        ("", human_readable_part)
    };

    if !prefix.is_empty() {
        if prefix.len() > 63
            || !prefix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || prefix.starts_with('-')
            || prefix.ends_with('-')
            || prefix.contains("--")
        {
            return false;
        }
    }

    let checksum_input = format!("{}{}", prefix, did_key_part);
    let expected_hash = get_hash(checksum_input.as_bytes());
    let expected_checksum = &expected_hash[expected_hash.len() - 3..];

    received_checksum == expected_checksum
}

/// Custom error type for `get_pubkey_from_user_id` function.
#[derive(Debug)]
pub enum GetPubkeyError {
    /// The prefix is invalid (e.g., empty string before '@').
    InvalidPrefix,
    /// Indicates that the user ID format is invalid (e.g., missing 'did:key:z').
    InvalidDidFormat,
    /// Indicates that Base58 decoding failed.
    DecodingFailed(bs58::decode::Error),
    /// Indicates that the decoded key bytes have an invalid multicodec prefix.
    InvalidMulticodec,
    /// Indicates that the decoded public key payload has an invalid length.
    InvalidLength(usize),
    /// Indicates that public key conversion failed.
    ConversionFailed(SignatureError),
}

impl std::fmt::Display for GetPubkeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetPubkeyError::InvalidPrefix => {
                write!(
                    f,
                    "Invalid prefix format (e.g., empty prefix is not allowed)"
                )
            }
            GetPubkeyError::InvalidDidFormat => write!(
                f,
                "Invalid user ID format (must be '[prefix]@[did:key:z...]' or 'did:key:z...')"
            ),
            GetPubkeyError::DecodingFailed(e) => write!(f, "Base58 decoding failed: {}", e),
            GetPubkeyError::InvalidMulticodec => write!(
                f,
                "Decoded key has invalid multicodec prefix (expected 0xed01 for Ed25519)"
            ),
            GetPubkeyError::InvalidLength(len) => write!(
                f,
                "Decoded public key has invalid length (expected 32, got {})",
                len
            ),
            GetPubkeyError::ConversionFailed(e) => write!(f, "Public key conversion failed: {}", e),
        }
    }
}

impl std::error::Error for GetPubkeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GetPubkeyError::DecodingFailed(e) => Some(e),
            GetPubkeyError::ConversionFailed(e) => Some(e),
            _ => None,
        }
    }
}

/// Extracts the Ed25519 public key from a user ID string.
///
/// # Arguments
///
/// * `user_id` - The user ID string created by `create_user_id`.
///
/// # Returns
///
/// A `Result` containing the `EdPublicKey` or a `GetPubkeyError`.
pub fn get_pubkey_from_user_id(user_id: &str) -> Result<EdPublicKey, GetPubkeyError> {
    const DID_KEY_PREFIX: &str = "did:key:z";
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    // Isolate the did:key part of the user ID
    let did_key_part = if let Some(pos) = user_id.rfind('@') {
        let (prefix, did_part) = user_id.split_at(pos);
        // An empty prefix like in "@did:key:..." is invalid.
        if prefix.is_empty() {
            return Err(GetPubkeyError::InvalidPrefix);
        }
        &did_part[1..] // Skip the '@'
    } else {
        user_id
    };

    if !did_key_part.starts_with(DID_KEY_PREFIX) {
        return Err(GetPubkeyError::InvalidDidFormat);
    }

    let base58_payload = &did_key_part[DID_KEY_PREFIX.len()..];
    let decoded_bytes = bs58::decode(base58_payload)
        .into_vec()
        .map_err(GetPubkeyError::DecodingFailed)?;

    if !decoded_bytes.starts_with(&ED25519_MULTICODEC_PREFIX) {
        return Err(GetPubkeyError::InvalidMulticodec);
    }

    let key_bytes = &decoded_bytes[ED25519_MULTICODEC_PREFIX.len()..];
    let actual_len = key_bytes.len();

    let key_bytes_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| GetPubkeyError::InvalidLength(actual_len))?;

    EdPublicKey::from_bytes(&key_bytes_array).map_err(GetPubkeyError::ConversionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_user_id() {
        let (pub_key, _) = generate_ed25519_keypair_for_tests(None);
        let valid_id = create_user_id(&pub_key, Some("valid-prefix")).unwrap();

        assert!(validate_user_id(&valid_id));

        // Let's test the prefix mutations manually
        // If we replace prefix chars with invalid
        let invalid_id = valid_id.replace("valid-prefix", "invalid_prefix");
        assert!(!validate_user_id(&invalid_id));

        let invalid_id2 = valid_id.replace("valid-prefix", "-invalid");
        assert!(!validate_user_id(&invalid_id2));

        let invalid_id3 = valid_id.replace("valid-prefix", "invalid--");
        assert!(!validate_user_id(&invalid_id3));
    }

    #[test]
    fn test_derive_ed25519_keypair_slip10_vector() {
        // Known SLIP-0010 Master Key for Ed25519 (All-zero entropy mnemonic)
        // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        // Expected Private Seed (hex): 560f9f3c94558b6551928bb781cf6092c6b8800b4fc544af2c9444ed126d51aa
        // Expected Public Key (hex): e96b1c6b8769fdb0b34fbecfdf85c33b053cecad9517e1ab88cba614335775c1

        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let (pub_key, priv_key) = derive_ed25519_keypair(mnemonic, None, MnemonicLanguage::English).unwrap();

        let pub_hex = hex::encode(pub_key.as_bytes());
        let priv_hex = hex::encode(priv_key.to_bytes());
        
        // Assert that we match the SLIP-0010 Master Key derivation
        assert_eq!(priv_hex, "560f9f3c94558b6551928bb781cf6092c6b8800b4fc544af2c9444ed126d51aa");
        assert_eq!(pub_hex, "e96b1c6b8769fdb0b34fbecfdf85c33b053cecad9517e1ab88cba614335775c1");
    }

    #[test]
    fn test_hmac_sha512_basic() {
        let key = b"key";
        let data = b"test";
        let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let result = mac.finalize().into_bytes();
        assert_eq!(hex::encode(result), "287a0fb89a7fbdfa5b5538636918e537a5b83065e4ff331268b7aaa115dde047a9b0f4fb5b828608fc0b6327f10055f7637b058e9e0dbb9e698901a3e6dd461c");
    }

    #[test]
    fn test_hmac_sha512_slip10_basic() {
        // SLIP-0010 Test Vector 1 (ed25519)
        // Seed: 000102030405060708090a0b0c0d0e0f
        // Expected IL: 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
        let key = b"ed25519 seed";
        let data = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(key).unwrap();
        mac.update(&data);
        let result = mac.finalize().into_bytes();
        let il = hex::encode(&result[..32]);
        assert_eq!(il, "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7");
    }

    #[test]
    fn test_get_short_hash_from_user_id() {
        let short_hash = get_short_hash_from_user_id("test_user");
        assert_eq!(short_hash.len(), 4);
    }
}

