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
use crate::models::secure_container::{
    ContainerConfig, EncryptionType, PayloadType, PrivacyMode, SecureContainer,
};
use crate::models::voucher::Voucher;
use crate::services::crypto::{
    decode_base64, get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
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

    let mut secure_container = SecureContainer::seal(
        identity,
        &ContainerConfig::TargetDid(recipient_id.to_string(), PrivacyMode::TrialDecryption),
        &signed_bundle_bytes,
        PayloadType::TransactionBundle, // content type
    )?;

    // HMC-SEC-06-02 (Privacy): If the transferred transaction chain is fully
    // anonymous, the envelope must not carry a plaintext Ed25519 signature
    // made with the sender's PERMANENT identity key. Such a signature is
    // publicly verifiable against `container.i` and turns every "anonymous"
    // transfer into a de-anonymization oracle for anyone holding a candidate
    // public key. `i` remains verifiable: it is hashed over the
    // empty-signature form. Post-decryption authenticity is unaffected, as
    // the inner bundle signature stays authoritative.
    //
    // HMSEC-SA06-08: The gate uses ANY semantics. A single anonymous chain is
    // sufficient to establish the privacy context of the whole container:
    // with ALL semantics, a mixed multi-standard transfer (e.g. one Public
    // chain plus one Stealth chain) kept the permanent-key signature alive,
    // publicly linking the co-transferred stealth sub-chain to the sender's
    // identity (SA06-01 oracle regression).
    if bundle_contains_anonymous_chain(&bundle) {
        secure_container.signature = String::new();
    }

    let container_bytes = serde_json::to_vec(&secure_container)?;

    Ok((container_bytes, bundle))
}

/// Determines whether a bundle contains at least one anonymous
/// (privacy mode / stealth) transaction chain. HMSEC-SA06-08: ANY semantics —
/// a single anonymous chain forces suppression of the permanent-key envelope
/// signature, because a publicly verifiable signature over the container
/// would de-anonymize every co-transferred stealth chain. A chain counts as
/// anonymous when its latest transaction has no plaintext sender
/// (`sender_id` absent) or an anonymous recipient.
fn bundle_contains_anonymous_chain(bundle: &TransactionBundle) -> bool {
    !bundle.vouchers.is_empty()
        && bundle.vouchers.iter().any(|v| {
            v.transactions.last().is_some_and(|tx| {
                tx.sender_id.is_none() || tx.recipient_id == crate::models::voucher::ANONYMOUS_ID
            })
        })
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

    // HMC-SEC-06-03: Enforce the "no plaintext financial payloads" fuse on
    // the RECEIVE side as well. The creation-side check
    // (`PlaintextNotAllowedForFinancialPayload`) only binds honest senders;
    // without this gate a hand-crafted `EncryptionType::None` container is
    // processed end-to-end by the wallet (CWE-311).
    if container.et == EncryptionType::None {
        return Err(VoucherCoreError::PlaintextNotAllowedForFinancialPayload);
    }

    // HMC-SEC-06-01: Recompute the container integrity ID from the received
    // bytes and require an exact match BEFORE any signature verification.
    // Both `i` and `signature` are excluded exactly as during creation.
    // Without this rebinding, any observer of a legitimate
    // `(i, signature)` pair can graft it onto different container content.
    container.verify_integrity()?;

    let decrypted_bundle_bytes = container.open(identity, None)?;
    let bundle: TransactionBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;

    // HMC-SEC-06-01 (bundle level): Recompute `bundle_id` from the received
    // content and require an exact match. `bundle_id` and `sender_signature`
    // are excluded exactly as during creation. This enforces the documented
    // contract that the sender signature makes the ENTIRE bundle
    // tamper-proof; a stolen `(bundle_id, sender_signature)` pair can no
    // longer be re-attached to manipulated content (CWE-347).
    let mut bundle_for_hash = bundle.clone();
    bundle_for_hash.bundle_id = String::new();
    bundle_for_hash.sender_signature = String::new();
    let expected_bundle_id = get_hash(to_canonical_json(&bundle_for_hash)?);
    if bundle.bundle_id != expected_bundle_id {
        return Err(ValidationError::InvalidBundleSignature.into());
    }

    // Cascaded verification:
    // 1. First verify the signature of the *container*.
    //    For this, we need the sender_id from the decrypted bundle.
    //    HMC-SEC-06-02: Privacy-mode containers intentionally carry NO
    //    envelope signature (de-anonymization oracle); authenticity is then
    //    guaranteed exclusively by the inner bundle signature below. A
    //    present signature is always verified against the claimed sender.
    if !container.signature.is_empty() {
        verify_container_signature(&mut container, &bundle.sender_id)?;
    }

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
    let signature_bytes = crate::services::crypto::decode_bs58_fixed::<64>(
        &bundle.sender_signature,
        "sender_signature",
    )
    .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    if !verify_ed25519(&sender_pubkey_ed, bundle.bundle_id.as_bytes(), &signature) {
        return Err(ValidationError::InvalidBundleSignature.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::secure_container::ContainerConfig;
    use crate::services::crypto::{create_user_id, encode_base64, generate_ed25519_keypair_for_tests};

    #[test]
    fn test_verify_container_signature_invalid() {
        let (pub_key1, sign_key1) = generate_ed25519_keypair_for_tests(None);
        let id1 = crate::models::profile::UserIdentity {
            user_id: create_user_id(&pub_key1, Some("test")).unwrap(),
            signing_key: sign_key1,
            public_key: pub_key1,
        };

        let (pub_key2, _sign_key2) = generate_ed25519_keypair_for_tests(None);
        let id2_str = create_user_id(&pub_key2, Some("test2")).unwrap();

        let mut container = SecureContainer::seal(
            &id1,
            &ContainerConfig::TargetDid(id2_str, PrivacyMode::TrialDecryption),
            b"test_payload",
            PayloadType::TransactionBundle,
        )
        .unwrap();

        // Mutate signature
        let mut sig_bytes = decode_base64(&container.signature).unwrap();
        sig_bytes[0] ^= 0xFF; // Flip bits
        container.signature = encode_base64(&sig_bytes);

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
        let user_id = create_user_id(&pub_key, Some("test")).unwrap();

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
