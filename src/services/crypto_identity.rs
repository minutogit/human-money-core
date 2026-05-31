//! # src/services/crypto_identity.rs
//!
//! Contains User Identity (DID Key) parsing, validation, and prefix extraction.

use std::fmt;
use std::convert::TryInto;
use ed25519_dalek::{VerifyingKey as EdPublicKey, SignatureError};
use crate::services::crypto_utils::get_hash;

/// Extracts the prefix from a user ID string.
/// Returns None for Root-Accounts (pure did:key without @).
pub fn get_prefix_from_user_id(user_id: &str) -> Option<&str> {
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
        None // Root-Account (reine did:key)
    }
}

/// Error types for user ID creation.
#[derive(Debug)]
pub enum UserIdError {
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
/// Das Format ist:
/// - Mit Präfix: `[präfix:]prüfsumme@did:key:z...`
/// - Ohne Präfix (Root-Account): `did:key:z...`
pub fn create_user_id(
    public_key: &EdPublicKey,
    user_prefix: Option<&str>,
) -> Result<String, UserIdError> {
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];

    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    // Root-Account: Kein Präfix, Rückgabe der reinen did:key
    if user_prefix.is_none() {
        return Ok(did_key);
    }

    // Mit Präfix: Validierung und Prüfsummen-Logik
    let prefix_str = user_prefix.unwrap();
    let prefix = prefix_str.to_lowercase();

    if prefix.is_empty() {
        return Ok(did_key); // Leerer String wird als Root-Account behandelt
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

    let human_readable_part = format!("{}:{}", prefix, checksum);

    Ok(format!("{}@{}", human_readable_part, did_key))
}

/// Validates a user ID string.
///
/// Supports both formats:
/// - Mit Präfix: `[präfix:]prüfsumme@did:key:z...`
/// - Ohne Präfix (Root-Account): `did:key:z...`
///
/// # Arguments
///
/// * `user_id` - The user ID string to validate.
///
/// # Returns
///
/// `true` if the user ID is valid, `false` otherwise.
pub fn validate_user_id(user_id: &str) -> bool {
    // Root-Account: Reine did:key ohne @
    if !user_id.contains('@') {
        // Prüfe, ob es mit did:key:z beginnt und ein gültiger Ed25519-Schlüssel ist
        if !user_id.starts_with("did:key:z") {
            return false;
        }
        return get_pubkey_from_user_id(user_id).is_ok();
    }

    // Mit Präfix: Validierung der Prüfsumme
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
    use crate::services::crypto_keys::generate_ed25519_keypair_for_tests;

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
}
