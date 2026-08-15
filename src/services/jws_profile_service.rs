//! # src/services/jws_profile_service.rs
//!
//! Implements JWS (JSON Web Signature) Compact Serialization (RFC 7515)
//! for profiles. This enables standards-compliant signing and verification
//! of profiles for QR codes and other exchange formats.

use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::services::crypto_utils::{decode_base64, encode_base64, sign_ed25519, verify_ed25519};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey as EdPublicKey};
use serde::{Deserialize, Serialize};

/// JWS Protected Header for profile signatures.
///
/// Follows RFC 7515 with standard algorithms for Ed25519.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JwsHeader {
    /// Algorithm: EdDSA with Ed25519
    pub alg: String,
    /// Content-Type: application/json
    pub cty: String,
    /// Type: JWT or JWS
    pub typ: String,
}

impl Default for JwsHeader {
    fn default() -> Self {
        Self {
            alg: "EdDSA".to_string(),
            cty: "application/json".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

/// Exports a profile as a JWS Compact Serialization string.
///
/// Format follows RFC 7515: base64url(header).base64url(payload).base64url(signature)
///
/// # Arguments
/// * `identity` - The SigningKey containing the private signing key.
/// * `profile` - The PublicProfile to sign.
///
/// # Returns
/// A JWS compact string or an error.
pub fn export_profile_as_jws(
    identity: &SigningKey,
    profile: &PublicProfile,
) -> Result<String, VoucherCoreError> {
    // 1. Create and serialize header
    let header = JwsHeader::default();
    let header_json = serde_json::to_string(&header)
        .map_err(VoucherCoreError::Json)?;
    let header_b64 = encode_base64(header_json.as_bytes());

    // 2. Serialize payload (the profile)
    let payload_json = serde_json::to_string(profile)
        .map_err(VoucherCoreError::Json)?;
    let payload_b64 = encode_base64(payload_json.as_bytes());

    // 3. Create message to sign: header.payload
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // 4. Sign the message
    let signature = sign_ed25519(identity, signing_input.as_bytes());
    let signature_b64 = encode_base64(signature.to_bytes().as_slice());

    // 5. Combine into JWS Compact: header.payload.signature
    Ok(format!(
        "{}.{}.{}",
        header_b64, payload_b64, signature_b64
    ))
}

/// Verifies and imports a JWS-encoded profile.
///
/// # Arguments
/// * `jws_compact` - The JWS Compact string.
///
/// # Returns
/// A tuple of (PublicProfile, did:key) on success, or an error.
pub fn verify_and_import_jws_profile(
    jws_compact: &str,
) -> Result<(PublicProfile, String), VoucherCoreError> {
    // 1. Split into three parts
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() != 3 {
        return Err(VoucherCoreError::Generic(
            "JWS must have exactly 3 parts separated by dots".to_string(),
        ));
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // 2. Decode header
    let header_bytes = decode_base64(header_b64)?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(VoucherCoreError::Json)?;

    // Validate algorithm
    if header.alg != "EdDSA" {
        return Err(VoucherCoreError::Crypto(format!(
            "Unsupported algorithm: {} (expected EdDSA)",
            header.alg
        )));
    }

    // 3. Decode payload (profile)
    let payload_bytes = decode_base64(payload_b64)?;
    let profile: PublicProfile = serde_json::from_slice(&payload_bytes)
        .map_err(VoucherCoreError::Json)?;

    // 4. Extract did:key from profile (if present) or from signature verification
    let did_key = profile.id.clone().ok_or_else(|| {
        VoucherCoreError::Generic("Profile must contain an 'id' field (did:key)".to_string())
    })?;

    // 5. Decode signature
    let signature_bytes = decode_base64(signature_b64)?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VoucherCoreError::Crypto("Invalid signature length".to_string()))?,
    );

    // 6. Extract public key from did:key
    let public_key = extract_pubkey_from_did_key(&did_key)?;

    // 7. Verify signature
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    if !verify_ed25519(&public_key, signing_input.as_bytes(), &signature) {
        return Err(VoucherCoreError::Crypto("Signature verification failed".to_string()));
    }

    Ok((profile, did_key))
}

/// Extracts an Ed25519 public key from a did:key URI.
///
/// # Arguments
/// * `did_key` - The did:key URI (e.g. "did:key:z6Mk...").
///
/// # Returns
/// The EdPublicKey or an error.
fn extract_pubkey_from_did_key(did_key: &str) -> Result<EdPublicKey, VoucherCoreError> {
    // did:key Format: did:key:<multibase-encoded-multicodec>
    if !did_key.starts_with("did:key:z") {
        return Err(VoucherCoreError::InvalidHashFormat(
            "Invalid did:key format (must start with 'did:key:z')".to_string(),
        ));
    }

    // Remove prefix
    let multibase = &did_key[9..]; // "did:key:z" is 9 characters

    // Decode Base58
    let decoded = bs58::decode(multibase)
        .into_vec()?;

    // Check for multicodec prefix for Ed25519 (0xed01)
    if decoded.len() < 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(VoucherCoreError::InvalidHashFormat(
            "Invalid multicodec prefix (expected 0xed01 for Ed25519)".to_string(),
        ));
    }

    // Extract 32 bytes of public key
    let key_bytes: [u8; 32] = decoded[2..34]
        .try_into()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid public key length".to_string()))?;

    EdPublicKey::from_bytes(&key_bytes)
        .map_err(|e| VoucherCoreError::Crypto(format!("Public key conversion failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto_keys::generate_ed25519_keypair_for_tests;

    #[test]
    fn test_jws_roundtrip() {
        // Generate test keypair
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("test_seed"));

        // Create a did:key
        const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
        let mut bytes_to_encode = Vec::with_capacity(34);
        bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
        bytes_to_encode.extend_from_slice(&public_key.to_bytes());
        let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

        // Create test profile
        let mut profile = PublicProfile::default();
        profile.id = Some(did_key.clone());
        profile.first_name = Some("Max".to_string());
        profile.last_name = Some("Mustermann".to_string());
        profile.protocol_version = Some("v1".to_string());

        // Export as JWS
        let jws = export_profile_as_jws(&signing_key, &profile).expect("JWS export failed");
        println!("JWS: {}", jws);

        // Import and verify
        let (imported_profile, imported_did) =
            verify_and_import_jws_profile(&jws).expect("JWS import failed");

        // Compare
        assert_eq!(imported_profile, profile);
        assert_eq!(imported_did, did_key);
    }

    #[test]
    fn test_jws_invalid_signature() {
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("test_seed2"));

        let mut bytes_to_encode = Vec::with_capacity(34);
        bytes_to_encode.extend_from_slice(&[0xed, 0x01]);
        bytes_to_encode.extend_from_slice(&public_key.to_bytes());
        let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

        let mut profile = PublicProfile::default();
        profile.id = Some(did_key);
        profile.first_name = Some("Test".to_string());

        let mut jws = export_profile_as_jws(&signing_key, &profile).expect("JWS export failed");

        // Manipulate signature (replace last character)
        let last_char = jws.pop().unwrap();
        jws.push(if last_char == 'A' { 'B' } else { 'A' });

        let result = verify_and_import_jws_profile(&jws);
        assert!(result.is_err());
    }

    #[test]
    fn test_jws_missing_parts() {
        let result = verify_and_import_jws_profile("invalid.jws");
        assert!(result.is_err());
    }
}
