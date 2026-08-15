//! # src/services/crypto_symmetric.rs
//!
//! Contains symmetric encryption/decryption logic (ChaCha20-Poly1305 and PBKDF2).

use rand_core::{OsRng, RngCore};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use sha2::Sha512;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use crate::error::VoucherCoreError;

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

/// Symmetrically encrypts data using ChaCha20-Poly1305 with Additional Authenticated Data (AAD).
///
/// This function is used for JWE (JSON Web Encryption) compliance, where the protected header
/// must be included as AAD in the encryption process. Returns separate nonce, ciphertext, and tag.
///
/// # Arguments
///
/// * `key` - A 32-byte key for the encryption.
/// * `data` - The plaintext data to encrypt.
/// * `aad` - Additional Authenticated Data (e.g., the JWE protected header).
///
/// # Returns
///
/// A `Result` containing a tuple of (nonce, ciphertext, tag) or a `SymmetricEncryptionError`.
pub fn encrypt_data_with_aad(
    key: &[u8; 32],
    data: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), SymmetricEncryptionError> {
    use chacha20poly1305::aead::AeadInPlace;

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Prepare buffer with plaintext
    let mut buffer = data.to_vec();

    // Encrypt in-place with AAD - returns the tag separately
    let tag = cipher
        .encrypt_in_place_detached(&nonce, aad, &mut buffer)
        .map_err(|_| SymmetricEncryptionError::EncryptionFailed)?;

    Ok((nonce.to_vec(), buffer, tag.to_vec()))
}

/// Symmetrically decrypts data encrypted with `encrypt_data_with_aad`.
///
/// This function expects separate nonce, ciphertext, and tag, along with AAD.
/// It uses the AEAD properties of ChaCha20-Poly1305 to verify the integrity and
/// authenticity of the data before returning the plaintext.
///
/// # Arguments
///
/// * `key` - The 32-byte key used for the encryption.
/// * `nonce` - The 12-byte nonce.
/// * `ciphertext` - The ciphertext data.
/// * `tag` - The 16-byte authentication tag.
/// * `aad` - Additional Authenticated Data (e.g., the JWE protected header).
///
/// # Returns
///
/// A `Result` containing the original plaintext data or a `SymmetricEncryptionError` if decryption fails.
pub fn decrypt_data_with_aad(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SymmetricEncryptionError> {
    use chacha20poly1305::aead::AeadInPlace;

    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    if nonce.len() != NONCE_SIZE {
        return Err(SymmetricEncryptionError::InvalidLength(format!(
            "Nonce must be exactly {} bytes.",
            NONCE_SIZE
        )));
    }

    if tag.len() != TAG_SIZE {
        return Err(SymmetricEncryptionError::InvalidLength(format!(
            "Tag must be exactly {} bytes.",
            TAG_SIZE
        )));
    }

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce_obj = Nonce::from_slice(nonce);
    let tag_array = chacha20poly1305::Tag::from_slice(tag);

    // Decrypt in-place with AAD - ciphertext must be mutable for in-place decryption
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place_detached(nonce_obj, aad, &mut buffer, tag_array)
        .map_err(|_| SymmetricEncryptionError::DecryptionFailed)?;

    Ok(buffer)
}

/// Symmetrically encrypts data with a password using PBKDF2 and ChaCha20-Poly1305.
///
/// This function is intended for single-use passwords (PINs) during container exchange.
/// It generates a 16-byte salt, derives a 32-byte key via PBKDF2 (HMAC-SHA512),
/// and encrypts the data using ChaCha20-Poly1305.
///
/// # Arguments
///
/// * `payload` - The data to be encrypted.
/// * `password` - The password (as a string).
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The encrypted data (including nonce, `salt[16]`) or a `VoucherCoreError`.
pub fn encrypt_symmetric_password(
    payload: &[u8],
    password: &str,
) -> Result<(Vec<u8>, [u8; 16]), VoucherCoreError> {
    // 1. Generate a random 16-byte salt
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // 2. Derive the key via PBKDF2 (100,000 iterations like in the master key)
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

    // 3. Encrypt the data with the derived key
    let ciphertext = encrypt_data(&key, payload)
        .map_err(VoucherCoreError::SymmetricEncryption)?;

    Ok((ciphertext, salt))
}

/// Decrypts data that was encrypted with `encrypt_symmetric_password`.
///
/// # Arguments
///
/// * `encrypted_payload` - The encrypted payload including the nonce.
/// * `password` - The password (as a string).
/// * `salt` - The 16-byte salt used during encryption.
///
/// # Returns
///
/// The decrypted data or a `VoucherCoreError`.
pub fn decrypt_symmetric_password(
    encrypted_payload: &[u8],
    password: &str,
    salt: &[u8; 16],
) -> Result<Vec<u8>, VoucherCoreError> {
    // 1. Derive the key via PBKDF2 (same iterations as encryption)
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

    // 2. Decrypt the data
    decrypt_data(&key, encrypted_payload)
        .map_err(VoucherCoreError::SymmetricEncryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = [0u8; 32];
        let plaintext = b"Test plaintext";
        let aad = b"Additional Authenticated Data";

        let (nonce, ciphertext, tag) = encrypt_data_with_aad(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_data_with_aad(&key, &nonce, &ciphertext, &tag, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
