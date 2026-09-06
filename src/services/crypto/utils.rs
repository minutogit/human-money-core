//! # src/services/crypto/utils.rs
//!
//! Cryptographic utilities: core mathematical, hashing, signature,
//! and trap derivation logic.

// BIP39 Mnemonic Phrase (delegated to mnemonic module)
use crate::services::mnemonic::{MnemonicLanguage, MnemonicProcessor};

// Symmetric encryption and hashes
use sha2::{Digest as _, Sha512};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey as EdPublicKey,
};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose};

use crate::error::VoucherCoreError;

// Re-export for canonical change-key derivation (allows `super::utils::get_prefix_from_user_id` in keys.rs)
pub use super::identity::get_prefix_from_user_id;

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

/// Derives a cryptographically strong, memory-hard identifier using Argon2id.
///
/// Optimized for Mobile and WASM environments (19 MiB RAM, 3 iterations).
/// Uses a reduced configuration during tests for performance.
pub fn derive_argon2_id(password: &[u8], salt: &[u8]) -> Result<String, VoucherCoreError> {
    // Parameters tuned for Mobile/WASM (approx. 19MB RAM usage)
    #[cfg(not(any(test, feature = "test-utils")))]
    let (m_cost, t_cost, p_cost) = (19456, 3, 1);

    // Fast configuration for tests
    #[cfg(any(test, feature = "test-utils"))]
    let (m_cost, t_cost, p_cost) = (1024, 1, 1);

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Argon2 parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];

    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| VoucherCoreError::Crypto(format!("Argon2 derivation failed: {}", e)))?;

    Ok(bs58::encode(output).into_string())
}

/// Computes a SHA3-256 hash of multiple inputs concatenated and returns it as a base58-encoded string.
/// This is used to avoid string-based concatenation malleability.
pub fn get_hash_from_slices(inputs: &[&[u8]]) -> String {
    bs58::encode(get_raw_hash_from_slices(inputs)).into_string()
}

/// Raw-byte variant of [`get_hash_from_slices`].
///
/// Computes the identical length-prefixed SHA3-256 digest but returns the
/// 32 raw bytes instead of the base58 string. Used by protocol layers that
/// sign/verify over raw digests (e.g. the `HMC_TX_AUTH_V2` payload digest).
pub fn get_raw_hash_from_slices(inputs: &[&[u8]]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    for input in inputs {
        // Prepends the segment length (as 4-byte Little Endian),
        // making it impossible to shift boundaries.
        hasher.update((input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let hash_bytes = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash_bytes);
    out
}

/// Generates a 4-byte short hash from the user ID for memory-efficient tracking of known peers.
/// Returns the last 4 bytes of the SHA3-256 hash.
/// WARNING: This is a truncated hash and serves only as a heuristic.
pub fn get_short_hash_from_user_id(user_id: &str) -> [u8; 4] {
    use sha3::Digest;
    let digest = sha3::Sha3_256::digest(user_id.as_bytes());
    let mut short_hash = [0u8; 4];
    short_hash.copy_from_slice(&digest[28..32]);
    short_hash
}

/// Converts an Ed25519 public key into an EdwardsPoint on the curve.
/// This is required to use the ID in the trap equation ($V = m \cdot U + ID$).
pub fn ed25519_pk_to_curve_point(ed_pub: &EdPublicKey) -> Result<EdwardsPoint, VoucherCoreError> {
    CompressedEdwardsY::from_slice(ed_pub.as_bytes())
        .map_err(|_| VoucherCoreError::Crypto("Invalid Ed25519 public key bytes".to_string()))?
        .decompress()
        .ok_or_else(|| {
            VoucherCoreError::Crypto("Failed to decompress Ed25519 public key point".to_string())
        })
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

/// Derives the secret scalar corresponding to the public key point from an Ed25519 `SigningKey`.
pub fn get_secret_scalar(signing_key: &SigningKey) -> curve25519_dalek::scalar::Scalar {
    let mut hasher = Sha512::new();
    hasher.update(signing_key.to_bytes());
    let hash = hasher.finalize();
    let mut scalar_bytes: [u8; 32] = hash[..32].try_into().unwrap();
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(scalar_bytes)
}

/// Computes the double-spend tag `ds_tag = H(prev_hash || sender_ephemeral_pub)`.
///
/// Both inputs are Base58-encoded; decoding errors are mapped to
/// `VoucherCoreError::Crypto` (fail-closed). The digest uses
/// length-prefixed SHA3-256 via [`get_hash_from_slices`] (second-
/// preimage resistance).
///
/// # Errors
/// Returns `VoucherCoreError::Crypto` if either input is not valid Base58.
pub fn get_ds_tag(prev_hash: &str, sender_ephemeral_pub: &str) -> Result<String, VoucherCoreError> {
    let prev_hash_bytes = bs58::decode(prev_hash)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for prev_hash: {}", e)))?;
    let ephem_pub_bytes = bs58::decode(sender_ephemeral_pub)
        .into_vec()
        .map_err(|e| VoucherCoreError::Crypto(format!("Invalid Base58 for sender_ephemeral_pub: {}", e)))?;
    Ok(get_hash_from_slices(&[&prev_hash_bytes, &ephem_pub_bytes]))
}

/// A secure, deterministic mapping of a byte array (e.g. prev_hash) to an Ed25519 curve point.
#[allow(deprecated)]
pub fn hash_to_curve(data: &[u8]) -> EdwardsPoint {
    EdwardsPoint::nonspec_map_to_curve::<Sha512>(data)
}

/// Decodes a Base58 string into a fixed-size byte array with a DoS guard.
///
/// Rejects inputs whose Base58 length exceeds `N*2+10` before allocating,
/// then validates that the decoded payload is exactly `N` bytes.
/// Errors preserve the `InvalidHashFormat` taxonomy (no flattening).
pub fn decode_bs58_fixed<const N: usize>(s: &str, field_name: &str) -> Result<[u8; N], VoucherCoreError> {
    if s.len() > N * 2 + 10 {
        return Err(VoucherCoreError::InvalidHashFormat(format!(
            "{field_name} string exceeds maximum Base58 length for {N} bytes"
        )));
    }
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| VoucherCoreError::InvalidHashFormat(format!("Invalid base58 for {field_name}: {e}")))?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| {
        VoucherCoreError::InvalidHashFormat(format!("{field_name} must be {N} bytes, got {len}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_short_hash_from_user_id() {
        let short_hash = get_short_hash_from_user_id("test_user");
        assert_eq!(short_hash.len(), 4);
    }

    #[test]
    fn test_decode_bs58_fixed_32_bytes_ok() {
        let raw = [7u8; 32];
        let encoded = bs58::encode(&raw).into_string();
        let decoded = decode_bs58_fixed::<32>(&encoded, "t_id").expect("valid 32 bytes");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_decode_bs58_fixed_64_bytes_ok() {
        let raw = [9u8; 64];
        let encoded = bs58::encode(&raw).into_string();
        let decoded = decode_bs58_fixed::<64>(&encoded, "layer2_signature").expect("valid 64 bytes");
        assert_eq!(decoded, raw);
    }

    #[test]
    fn test_decode_bs58_fixed_invalid_chars() {
        // '0', 'O', 'I', 'l' are not in the Bitcoin Base58 alphabet
        let err = decode_bs58_fixed::<32>("0OIl", "t_id").unwrap_err();
        match err {
            VoucherCoreError::InvalidHashFormat(msg) => assert!(msg.contains("Invalid base58 for t_id")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_decode_bs58_fixed_wrong_length() {
        // 32 bytes expected, but we encode only 16 bytes
        let raw = [1u8; 16];
        let encoded = bs58::encode(&raw).into_string();
        let err = decode_bs58_fixed::<32>(&encoded, "t_id").unwrap_err();
        match err {
            VoucherCoreError::InvalidHashFormat(msg) => assert!(msg.contains("must be 32 bytes, got 16")),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn test_decode_bs58_fixed_dos_length_guard() {
        // N=32 => max is 32*2+10=74; input exceeding that must be rejected before decode
        let long = "A".repeat(75);
        let err = decode_bs58_fixed::<32>(&long, "t_id").unwrap_err();
        match err {
            VoucherCoreError::InvalidHashFormat(msg) => {
                assert!(msg.contains("exceeds maximum Base58 length for 32 bytes"))
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
        // Boundary: exactly N*2+10 must NOT trip the DoS guard (should fail on base58/length instead)
        // Using a string of valid alphabet chars but wrong decoded length
        let boundary = "A".repeat(74);
        let err2 = decode_bs58_fixed::<32>(&boundary, "t_id").unwrap_err();
        match err2 {
            VoucherCoreError::InvalidHashFormat(msg) => {
                assert!(!msg.contains("exceeds maximum Base58 length"))
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
