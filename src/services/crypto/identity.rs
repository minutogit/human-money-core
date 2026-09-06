//! # src/services/crypto/identity.rs
//!
//! Contains User Identity (DID Key) parsing, validation, and prefix extraction.

use std::convert::TryInto;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use ed25519_dalek::{VerifyingKey as EdPublicKey, SignatureError};
use thiserror::Error;
use crate::error::ValidationError;
use super::utils::get_hash;

/// Sanitizes a user ID string by removing all whitespace characters.
/// DID keys never contain spaces, tabs, or newlines, so this is always safe.
fn sanitize_user_id(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Extracts the prefix from a user ID string.
/// Returns None for Root-Accounts (pure did:key without @).
pub fn get_prefix_from_user_id(user_id: &str) -> Option<&str> {
    let user_id = user_id.trim();
    if let Some(pos) = user_id.rfind('@') {
        let prefix_part = &user_id[..pos];
        // Extract only the prefix part before the checksum (e.g., "prefix" from "prefix:checksum")
        if let Some(colon_pos) = prefix_part.rfind(':') {
            let prefix = &prefix_part[..colon_pos];
            if prefix.is_empty() { None } else { Some(prefix) }
        } else {
            // No checksum format, just return the whole prefix part
            if prefix_part.is_empty() { None } else { Some(prefix_part) }
        }
    } else {
        None // Root-Account (pure did:key)
    }
}

/// Generates a user ID with an optional prefix and a mandatory checksum.
///
/// The format is:
/// - With prefix: `[prefix:]checksum@did:key:z...`
/// - Without prefix (Root account): `did:key:z...`
pub fn create_user_id(
    public_key: &EdPublicKey,
    user_prefix: Option<&str>,
) -> Result<String, ValidationError> {
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    // Root account: No prefix, returns the pure did:key
    if user_prefix.is_none() {
        return Ok(did_key);
    }

    // With prefix: Validation and checksum logic
    let prefix_str = user_prefix.unwrap();
    let prefix = prefix_str.to_lowercase();

    if prefix.is_empty() {
        return Ok(did_key); // Empty string is treated as a Root account
    }
    if prefix.len() > 63 {
        return Err(ValidationError::PrefixTooLong(prefix.len()));
    }
    if !prefix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(ValidationError::InvalidPrefixChars);
    }
    if prefix.starts_with('-') || prefix.ends_with('-') {
        return Err(ValidationError::InvalidPrefixStartEnd);
    }
    if prefix.contains("--") {
        return Err(ValidationError::PrefixHasConsecutiveSeparators);
    }

    // Generate checksum
    let checksum_input = format!("{}{}", prefix, did_key);
    let hash = get_hash(checksum_input.as_bytes());
    let checksum = &hash[hash.len() - 3..];

    let human_readable_part = format!("{}:{}", prefix, checksum);

    Ok(format!("{}@{}", human_readable_part, did_key))
}

/// Validates a user ID string.
///
/// Supports both formats:
/// - With prefix: `[prefix:]checksum@did:key:z...`
/// - Without prefix (Root account): `did:key:z...`
///
/// # Arguments
///
/// * `user_id` - The user ID string to validate.
///
/// # Returns
///
/// `true` if the user ID is valid, `false` otherwise.
pub fn validate_user_id(user_id: &str) -> bool {
    let sanitized = sanitize_user_id(user_id);
    let user_id = &sanitized;
    // Root account: Pure did:key without @
    if !user_id.contains('@') {
        // Check if it starts with did:key:z and is a valid Ed25519 key
        if !user_id.starts_with("did:key:z") {
            return false;
        }
        return get_pubkey_from_user_id(user_id).is_ok();
    }

    // With prefix: Validation of the checksum
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
        // SECURITY (HMC-SEC-02-06): The empty-prefix form ":checksum@did..."
        // is not producible by `create_user_id` (an empty prefix maps to the
        // bare root did:key). It skips every prefix grammar check and its
        // checksum binds to "" + did_key (publicly computable), while
        // `get_prefix_from_user_id` resolves it as None — a non-canonical
        // ALIAS of the root identity that tears string comparisons and
        // prefix-based key derivation apart.
        if p.is_empty() {
            return false;
        }
        (p, &c[1..])
    } else {
        // SECURITY (HMC-SEC-02-06): A '@' form without a ':<checksum>'
        // separator is equally unproducible by `create_user_id` and lets an
        // attacker claim an arbitrary prefix name under a checksum derived
        // from the empty prefix.
        return false;
    };

    if !prefix.is_empty()
        && (prefix.len() > 63
            || !prefix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            || prefix.starts_with('-')
            || prefix.ends_with('-')
            || prefix.contains("--"))
        {
            return false;
        }

    let checksum_input = format!("{}{}", prefix, did_key_part);
    let expected_hash = get_hash(checksum_input.as_bytes());
    let expected_checksum = &expected_hash[expected_hash.len() - 3..];

    received_checksum == expected_checksum
}

/// Custom error type for `get_pubkey_from_user_id` function.
#[derive(Debug, Error)]
pub enum GetPubkeyError {
    /// The prefix is invalid (e.g., empty string before '@').
    #[error("Invalid prefix format (e.g., empty prefix is not allowed)")]
    InvalidPrefix,
    /// Indicates that the user ID format is invalid (e.g., missing 'did:key:z').
    #[error("Invalid user ID format (must be '[prefix]@[did:key:z...]' or 'did:key:z...')")]
    InvalidDidFormat,
    /// Indicates that Base58 decoding failed.
    #[error("Base58 decoding failed: {0}")]
    DecodingFailed(#[source] bs58::decode::Error),
    /// Indicates that the decoded key bytes have an invalid multicodec prefix.
    #[error("Decoded key has invalid multicodec prefix (expected 0xed01 for Ed25519)")]
    InvalidMulticodec,
    /// Indicates that the decoded public key payload has an invalid length.
    #[error("Decoded public key has invalid length (expected 32, got {0})")]
    InvalidLength(usize),
    /// Indicates that public key conversion failed.
    #[error("Public key conversion failed: {0}")]
    ConversionFailed(#[source] SignatureError),
    /// The encoded point is not a valid Ed25519 actor key (small-order or
    /// torsion-carrying). DH exchanges against such keys collapse to
    /// attacker-computable constants, so they must never enter key
    /// derivation (HMC-SEC-02-10 / SA02-01 invariant).
    #[error("Identity key is not a prime-order group element (small-order or torsion-carrying point rejected)")]
    NonPrimeOrderKey,
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
    let sanitized = sanitize_user_id(user_id);
    let user_id = &sanitized;
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

    let verifying_key =
        EdPublicKey::from_bytes(&key_bytes_array).map_err(GetPubkeyError::ConversionFailed)?;

    // HMC-SEC-02-10 (Public-Key-Firewall, SA02-01 invariant): a did:key MUST
    // denote a cryptographically usable group element. Honestly generated
    // Ed25519 keys are clamped scalars times the basepoint and therefore
    // torsion-free; small-order or mixed-torsion points make every DH
    // exchange non-contributory (outcome collapses to attacker-computable
    // constants) and are rejected fail-closed here.
    let point = CompressedEdwardsY::from_slice(verifying_key.as_bytes())
        .map_err(|_| GetPubkeyError::NonPrimeOrderKey)?
        .decompress()
        .ok_or(GetPubkeyError::NonPrimeOrderKey)?;
    // The neutral element is technically inside the prime-order subgroup,
    // but its Montgomery image is the all-zero u-coordinate (order-1 DH
    // collapse), so it must be rejected explicitly.
    if point.is_identity() || !point.is_torsion_free() {
        return Err(GetPubkeyError::NonPrimeOrderKey);
    }

    Ok(verifying_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::keys::generate_ed25519_keypair_for_tests;

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
    fn test_whitespace_handling_in_user_id() {
        let (pub_key, _) = generate_ed25519_keypair_for_tests(None);
        let valid_id = create_user_id(&pub_key, None).unwrap(); // Root-Account

        // Trailing space
        assert!(validate_user_id(&format!("{} ", valid_id)));
        // Leading tab
        assert!(validate_user_id(&format!("\t{}", valid_id)));
        // Trailing newline
        assert!(validate_user_id(&format!("{}\n", valid_id)));
        // Newline in the middle (e.g. from email line-wrap)
        let mid = valid_id.len() / 2;
        let wrapped = format!("{}\n{}", &valid_id[..mid], &valid_id[mid..]);
        assert!(validate_user_id(&wrapped));
        // get_pubkey should also work with whitespace
        assert!(get_pubkey_from_user_id(&format!("{} \t\n", valid_id)).is_ok());
    }

    #[test]
    fn test_whitespace_handling_with_prefix() {
        let (pub_key, _) = generate_ed25519_keypair_for_tests(None);
        let valid_id = create_user_id(&pub_key, Some("test-prefix")).unwrap();

        assert!(validate_user_id(&format!("  {} ", valid_id)));
        assert!(get_pubkey_from_user_id(&format!("{}\t", valid_id)).is_ok());
    }
}
