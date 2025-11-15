//! # src/services/crypto_utils.rs
// Zufallszahlengenerierung
use rand::Rng;
use rand_core::RngCore;
use rand_core::OsRng;

// Kryptografische Hashes (SHA-2)
use sha2::{Sha256, Sha512, Digest};

// Symmetrische Verschlüsselung
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};

// Ed25519 Signaturen
use ed25519_dalek::{
    SigningKey,
    Signature,
    VerifyingKey as EdPublicKey,
    Signer,
    Verifier,
    SignatureError,
};

// X25519 Schlüsselvereinbarung
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

// BIP39 Mnemonic Phrase
use bip39::{Mnemonic, Language};

// Key Derivation Functions
use hmac::Hmac;
use pbkdf2::pbkdf2;
use hkdf::Hkdf;

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
pub fn generate_mnemonic(word_count: usize, language: Language) -> Result<String, Box<dyn std::error::Error>> {
    let entropy_length = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _  => return Err("Invalid entropy length".into()),
    };
    let mut rng = rand::thread_rng();
    let entropy: Vec<u8> = (0..entropy_length).map(|_| rng.gen()).collect();
    let mnemonic = Mnemonic::from_entropy_in(language, &entropy)?;
    Ok(mnemonic.to_string())
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
pub fn validate_mnemonic_phrase(phrase: &str) -> Result<(), String> {
    Mnemonic::parse_in_normalized(Language::English, phrase)
        .map(|_| ()) // We only care about success, not the Mnemonic object itself.
        .map_err(|e| e.to_string())
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
    } else if len > 0 {
        // Notfall: Falls der Hash kürzer ist, mit Nullen auffüllen.
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
) -> Result<(EdPublicKey, SigningKey), VoucherCoreError> {
    // Parse the mnemonic phrase according to BIP-39 standard
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic_phrase)
        .map_err(|e| VoucherCoreError::Crypto(format!("Mnemonic parsing failed: {}", e)))?;

    // Generate the standard BIP-39 seed (uses PBKDF2 with 2048 rounds)
    let bip39_seed = mnemonic.to_seed(passphrase.unwrap_or(""));

    // Apply additional key stretching using PBKDF2 with 100,000 rounds
    // This provides enhanced protection against brute-force attacks
    // while maintaining BIP-39 compatibility for the initial seed generation
    let mut stretched_key = [0u8; 32];
    pbkdf2::<Hmac<Sha512>>(
        &bip39_seed,
        b"voucher-core-stretch-v1",
        100_000,
        &mut stretched_key,
    ).map_err(|e| VoucherCoreError::Crypto(
        format!("PBKDF2 stretching failed: {}", e)
    ))?;

    // Use HKDF to derive an application-specific key from the stretched seed
    // This is a cryptographic best practice to separate keys for different purposes
    let hkdf = Hkdf::<Sha256>::new(None, &stretched_key);
    let mut ed_signing_key_seed = [0u8; 32];
    hkdf.expand(b"voucher-core/ed25519", &mut ed_signing_key_seed)
        .map_err(|_| VoucherCoreError::Crypto(
            "HKDF expansion failed".to_string()
        ))?;

    // SigningKey::from_seed_bytes takes a 32-byte seed and uses it to derive the
    // Ed25519 keypair in a secure and standardized way (internally uses SHA512)
    let signing_key = SigningKey::from_bytes(&ed_signing_key_seed);

    let public_key = signing_key.verifying_key();
    Ok((public_key, signing_key))
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
        let key_bytes: [u8; 32] = hash_result[..32].try_into().expect("Hash output must be 64 bytes");

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
    let key_bytes: [u8; 32] = hash[..32].try_into().expect("SHA512 hash must be 64 bytes");
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
/// # Arguments
///
/// * `our_secret` - Our ephemeral secret.
/// * `their_public` - The other party's public key.
///
/// # Returns
///
/// The shared secret.
pub fn perform_diffie_hellman(
    our_secret: EphemeralSecret,
    their_public: &X25519PublicKey,
) -> [u8; 32] {
    // X25519 liefert bereits ein sicheres, 32-Byte Shared Secret.
    // Eine zusätzliche HKDF-Expansion ist in diesem Fall unnötig.
    our_secret.diffie_hellman(their_public).to_bytes()
}

/// Custom error type for symmetric encryption/decryption functions.
#[derive(Debug, thiserror::Error)]
pub enum SymmetricEncryptionError {
    /// Indicates that the AEAD encryption process failed.
    #[error("AEAD encryption failed.")]
    EncryptionFailed,

    /// Indicates that AEAD decryption failed, likely due to a wrong key or tampered data.
    #[error("AEAD decryption failed. The key may be incorrect or the data may have been tampered with.")]
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
    let ciphertext = cipher.encrypt(&nonce, data)
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
pub fn decrypt_data(key: &[u8; 32], encrypted_data_with_nonce: &[u8]) -> Result<Vec<u8>, SymmetricEncryptionError> {
    const NONCE_SIZE: usize = 12;
    if encrypted_data_with_nonce.len() < NONCE_SIZE {
        return Err(SymmetricEncryptionError::InvalidLength(format!(
            "Encrypted data must be at least {} bytes long to contain a nonce.", NONCE_SIZE
        )));
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let (nonce_bytes, ciphertext) = encrypted_data_with_nonce.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    // `decrypt` automatically verifies the authentication tag. If it fails, an error is returned.
    cipher.decrypt(nonce, ciphertext).map_err(|_| SymmetricEncryptionError::DecryptionFailed)
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
    general_purpose::URL_SAFE_NO_PAD.decode(encoded_data).map_err(|e| VoucherCoreError::Base64(e.to_string()))
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
    PrefixHasDoubleHyphen,
}

impl fmt::Display for UserIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserIdError::PrefixEmpty => {
                write!(f, "Prefix is mandatory and must not be empty.")
            }
            UserIdError::PrefixTooLong(len) => write!(
                f,
                "Prefix is too long: {} characters (maximum is 63).",
                len
            ),
            UserIdError::InvalidPrefixChars => write!(
                f,
                "Prefix contains invalid characters. Only lowercase letters (a-z), numbers (0-9), and hyphens (-) are allowed."
            ),
            UserIdError::InvalidPrefixStartEnd => {
                write!(f, "Prefix must not start or end with a hyphen.")
            }
            UserIdError::PrefixHasDoubleHyphen => {
                write!(f, "Prefix must not contain consecutive hyphens.")
            }
        }
    }
}

impl std::error::Error for UserIdError {}

/// Generiert eine User-ID mit optionalem Präfix und einer obligatorischen Prüfsumme.
///
/// Das Format ist: `[präfix-]prüfsumme@did:key:z...`
pub fn create_user_id(public_key: &EdPublicKey, user_prefix: Option<&str>) -> Result<String, UserIdError> {
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
            return Err(UserIdError::PrefixHasDoubleHyphen);
        }

    // Generiere Prüfsumme
    let checksum_input = format!("{}{}", prefix, did_key);
    let hash = get_hash(checksum_input.as_bytes());
    let checksum = &hash[hash.len() - 3..];

    // Da das Präfix nun obligatorisch ist, entfällt der `if prefix.is_empty()`-Check.
    let human_readable_part = format!("{}-{}", prefix, checksum);

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

    let (prefix, received_checksum) =
        if let Some(pos) = human_readable_part.rfind('-') {
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
                write!(f, "Invalid prefix format (e.g., empty prefix is not allowed)")
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

    let key_bytes_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| GetPubkeyError::InvalidLength(actual_len))?;

    EdPublicKey::from_bytes(&key_bytes_array).map_err(GetPubkeyError::ConversionFailed)
}
