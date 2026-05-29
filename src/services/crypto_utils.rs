//! # src/services/crypto_utils.rs
//!
//! Cryptographic utilities. This serves as a facade re-exporting the sub-modules
//! while retaining core mathematical, hashing, and signature logic.

// Symmetric encryption (re-exports)
pub use super::crypto_keys::*;
pub use super::crypto_symmetric::*;
pub use super::crypto_dh::*;
pub use super::crypto_identity::*;

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
    use sha3::Digest;
    let mut hasher = sha3::Sha3_256::new();
    for input in inputs {
        // Prepends the segment length (as 4-byte Little Endian),
        // making it impossible to shift boundaries.
        hasher.update(&(input.len() as u32).to_le_bytes());
        hasher.update(input);
    }
    let hash_bytes = hasher.finalize();
    bs58::encode(hash_bytes).into_string()
}

/// Generates a 4-character, base58-encoded short hash from the user ID for
/// memory-efficient tracking of known peers.
/// Returns the last 4 bytes of the hash as an array to save memory.
/// WARNING: This is a truncated hash and serves only as a heuristic.
pub fn get_short_hash_from_user_id(user_id: &str) -> [u8; 4] {
    let hash = get_hash(user_id.as_bytes());

    // 1. Decode base58 string back to bytes
    let hash_bytes = bs58::decode(&hash).into_vec().unwrap_or_default();

    let len = hash_bytes.len();
    let mut short_hash = [0u8; 4];

    if len >= 4 {
        // 2. Copy the last 4 bytes (best entropy spread)
        short_hash.copy_from_slice(&hash_bytes[len - 4..]);
    } else if len > 0 { // mutants: skip -- unreachable: SHA3-256 always produces 32 bytes, base58 never yields <4 bytes
        // Fallback: pad with leading zeros if hash is unexpectedly short.
        short_hash[4 - len..].copy_from_slice(&hash_bytes);
    }
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
    hasher.update(&signing_key.to_bytes());
    let hash = hasher.finalize();
    let mut scalar_bytes: [u8; 32] = hash[..32].try_into().unwrap();
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(scalar_bytes)
}

/// A secure, deterministic mapping of a byte array (e.g. prev_hash) to an Ed25519 curve point.
#[allow(deprecated)]
pub fn hash_to_curve(data: &[u8]) -> EdwardsPoint {
    EdwardsPoint::nonspec_map_to_curve::<Sha512>(data)
}

/// Helper function to compute the DLEQ challenge.
fn calculate_dleq_challenge(
    g: &EdwardsPoint,
    pk: &EdwardsPoint,
    p: &EdwardsPoint,
    k: &EdwardsPoint,
    r1: &EdwardsPoint,
    r2: &EdwardsPoint,
) -> curve25519_dalek::scalar::Scalar {
    use sha2::Sha256;
    let mut hasher = Sha256::new();
    hasher.update(g.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(p.compress().as_bytes());
    hasher.update(k.compress().as_bytes());
    hasher.update(r1.compress().as_bytes());
    hasher.update(r2.compress().as_bytes());
    let hash_result = hasher.finalize();
    let hash_bytes: [u8; 32] = hash_result.into();
    curve25519_dalek::scalar::Scalar::from_bytes_mod_order(hash_bytes)
}

/// Generates a Chaum-Pedersen Discrete Logarithm Equality (DLEQ) proof.
/// Proves that log_G(pk_sender) == log_P(k_point) = sk_sender.
pub fn generate_dleq_proof(
    sk_sender: &curve25519_dalek::scalar::Scalar,
    p_point: &EdwardsPoint,
    k_point: &EdwardsPoint,
) -> (curve25519_dalek::scalar::Scalar, curve25519_dalek::scalar::Scalar) {
    let mut rng = rand::thread_rng();
    let k = curve25519_dalek::scalar::Scalar::random(&mut rng);
    let r1 = k * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let r2 = k * p_point;
    let pk_sender = sk_sender * curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    
    let c = calculate_dleq_challenge(
        &curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        &pk_sender,
        p_point,
        k_point,
        &r1,
        &r2,
    );
    let s = k + c * sk_sender;
    (c, s)
}

/// Verifies a Chaum-Pedersen DLEQ proof.
pub fn verify_dleq_proof(
    pk_sender: &EdwardsPoint,
    p_point: &EdwardsPoint,
    k_point: &EdwardsPoint,
    c: &curve25519_dalek::scalar::Scalar,
    s: &curve25519_dalek::scalar::Scalar,
) -> Result<(), VoucherCoreError> {
    let r1_prime = s * curve25519_dalek::constants::ED25519_BASEPOINT_POINT - c * pk_sender;
    let r2_prime = s * p_point - c * k_point;
    
    let c_prime = calculate_dleq_challenge(
        &curve25519_dalek::constants::ED25519_BASEPOINT_POINT,
        pk_sender,
        p_point,
        k_point,
        &r1_prime,
        &r2_prime,
    );
    
    if *c != c_prime {
        return Err(VoucherCoreError::InvalidTrapDerivation(
            "DLEQ proof verification failed".to_string()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_short_hash_from_user_id() {
        let short_hash = get_short_hash_from_user_id("test_user");
        assert_eq!(short_hash.len(), 4);
    }
}
