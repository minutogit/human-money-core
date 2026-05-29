//! # src/services/bundle_processor.rs
//!
//! Encapsulates the logic for creating, encrypting, opening, and verifying
//! transaction bundles (`TransactionBundle`) and their `SecureContainer`.
//! This module is stateless and only operates on the data passed to it.

use ed25519_dalek::Signature;

use crate::error::ValidationError;
use crate::error::VoucherCoreError;
use crate::models::conflict::TransactionFingerprint;
use crate::models::profile::{TransactionBundle, UserIdentity};
use crate::models::secure_container::{PayloadType, PrivacyMode, SecureContainer};
use crate::models::voucher::Voucher;
use crate::services::crypto_identity::get_pubkey_from_user_id;
use crate::services::crypto_utils::{
    decode_base64, get_hash, sign_ed25519, verify_ed25519,
};
use crate::services::secure_container_manager::{create_secure_container, open_secure_container};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use std::collections::HashMap;

/// Creates a `TransactionBundle`, wraps it in a `SecureContainer` and serializes it.
/// This function is stateless and does not modify any wallet.
///
/// # Returns
/// A tuple containing the serialized bytes of the `SecureContainer` and the fully
/// created `TransactionBundle` (including ID and signature).
pub fn create_and_encrypt_bundle(
    identity: &UserIdentity,
    vouchers: Vec<Voucher>,
    recipient_id: &str,
    notes: Option<String>,
    forwarded_fingerprints: Vec<TransactionFingerprint>,
    fingerprint_depths: HashMap<String, i8>,
    sender_profile_name: Option<String>,
) -> Result<(Vec<u8>, TransactionBundle), VoucherCoreError> {
    let mut bundle = TransactionBundle {
        bundle_id: "".to_string(),
        sender_id: identity.user_id.clone(),
        recipient_id: recipient_id.to_string(),
        vouchers,
        timestamp: get_current_timestamp(),
        notes,
        sender_signature: "".to_string(),
        forwarded_fingerprints,
        fingerprint_depths,
        sender_profile_name,
    };

    let bundle_json_for_id = to_canonical_json(&bundle)?;
    bundle.bundle_id = get_hash(bundle_json_for_id);

    let signature = sign_ed25519(&identity.signing_key, bundle.bundle_id.as_bytes());
    bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();
    let signed_bundle_bytes = serde_json::to_vec(&bundle)?;

    let secure_container = create_secure_container(
        identity,
        crate::models::secure_container::ContainerConfig::TargetDid(recipient_id.to_string(), PrivacyMode::TrialDecryption),
        &signed_bundle_bytes,
        PayloadType::TransactionBundle, // content type
    )?;

    let container_bytes = serde_json::to_vec(&secure_container)?;

    Ok((container_bytes, bundle))
}

/// Opens a `SecureContainer`, validates the content as `TransactionBundle` and
/// verifies its digital signature.
/// This function is stateless and does not modify any wallet.
///
/// # Returns
/// The validated `TransactionBundle`.
pub fn open_and_verify_bundle(
    identity: &UserIdentity,
    container_bytes: &[u8],
) -> Result<TransactionBundle, VoucherCoreError> {
    let mut container: SecureContainer = serde_json::from_slice(container_bytes)?;

    if container.c != PayloadType::TransactionBundle {
        return Err(VoucherCoreError::InvalidPayloadType);
    }

    let decrypted_bundle_bytes = open_secure_container(&container, identity, None)?;
    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;

    // Cascaded verification:
    // 1. First verify the signature of the *container*.
    //    For this, we need the sender_id from the decrypted bundle.
    verify_container_signature(&mut container, &bundle.sender_id)?;

    // 2. Then verify the internal signature of the *bundle*.
    verify_bundle_signature(&bundle)?;

    Ok(bundle)
}

/// Verifies the digital signature of the SecureContainer.
fn verify_container_signature(
    container: &mut SecureContainer,
    sender_id: &str,
) -> Result<(), VoucherCoreError> {
    let sender_pubkey_ed = get_pubkey_from_user_id(sender_id)?;
    let signature_bytes = decode_base64(&container.signature)?;
    let signature = Signature::from_slice(&signature_bytes)?;

    if !verify_ed25519(&sender_pubkey_ed, container.i.as_bytes(), &signature) {
        return Err(ValidationError::InvalidContainerSignature.into());
    }

    Ok(())
}

/// Verifies the digital signature of a `TransactionBundle`.
fn verify_bundle_signature(bundle: &TransactionBundle) -> Result<(), VoucherCoreError> {
    let sender_pubkey_ed = get_pubkey_from_user_id(&bundle.sender_id)?;
    let signature_bytes = bs58::decode(&bundle.sender_signature)
        .into_vec()
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

    if !verify_ed25519(&sender_pubkey_ed, bundle.bundle_id.as_bytes(), &signature) {
        return Err(ValidationError::InvalidBundleSignature.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::secure_container::ContainerConfig;
    use crate::services::crypto_utils::generate_ed25519_keypair_for_tests;

    #[test]
    fn test_verify_container_signature_invalid() {
        let (pub_key1, sign_key1) = generate_ed25519_keypair_for_tests(None);
        let id1 = crate::models::profile::UserIdentity {
            user_id: crate::services::crypto_utils::create_user_id(&pub_key1, Some("test")).unwrap(),
            signing_key: sign_key1,
            public_key: pub_key1,
        };

        let (pub_key2, _sign_key2) = generate_ed25519_keypair_for_tests(None);
        let id2_str = crate::services::crypto_utils::create_user_id(&pub_key2, Some("test2")).unwrap();

        let mut container = create_secure_container(
            &id1,
            ContainerConfig::TargetDid(id2_str, PrivacyMode::TrialDecryption),
            b"test_payload",
            PayloadType::TransactionBundle,
        )
        .unwrap();

        // Mutate signature
        let mut sig_bytes = decode_base64(&container.signature).unwrap();
        sig_bytes[0] ^= 0xFF; // Flip bits
        container.signature = crate::services::crypto_utils::encode_base64(&sig_bytes);

        let result = verify_container_signature(&mut container, &id1.user_id);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidContainerSignature)
        ));
    }

    #[test]
    fn test_verify_bundle_signature_invalid() {
        let (pub_key, sign_key) = generate_ed25519_keypair_for_tests(None);
        let user_id = crate::services::crypto_utils::create_user_id(&pub_key, Some("test")).unwrap();

        let mut bundle = TransactionBundle {
            bundle_id: "test".to_string(),
            sender_id: user_id,
            recipient_id: "test2".to_string(),
            vouchers: vec![],
            timestamp: "0".to_string(),
            notes: None,
            sender_signature: "".to_string(),
            forwarded_fingerprints: vec![],
            fingerprint_depths: std::collections::HashMap::new(),
            sender_profile_name: None,
        };

        let signature = sign_ed25519(&sign_key, b"different_data");
        bundle.sender_signature = bs58::encode(signature.to_bytes()).into_string();

        let result = verify_bundle_signature(&bundle);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::Validation(ValidationError::InvalidBundleSignature)
        ));
    }
}
