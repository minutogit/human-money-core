//! # src/services/secure_container_manager.rs
//!
//! Contains core logic for creating, encrypting, decrypting, and verifying
//! the anonymized `SecureContainer`. Implements Forward Secrecy and Double-Key-Wrapping.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, EncryptionType, JweRecipient, PayloadType, PrivacyMode, SecureContainer};
use crate::services::crypto_symmetric::{
    decrypt_data, decrypt_data_with_aad, decrypt_symmetric_password, encrypt_data,
    encrypt_data_with_aad, encrypt_symmetric_password,
};
use crate::services::crypto_dh::{ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk};
use crate::services::crypto_identity::get_pubkey_from_user_id;
use crate::services::crypto_utils::{
    self, decode_base64, encode_base64, get_hash,
};
use crate::services::utils::to_canonical_json;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroize;

/// Defines errors that can occur in the `secure_container_manager` module.
#[derive(Debug, thiserror::Error)]
pub enum ContainerManagerError {
    #[error("The current user is not in the list of recipients for this container.")]
    NotAnIntendedRecipient,
    #[error("The digital signature of the secure container is invalid.")]
    InvalidContainerSignature,
    #[error("Failed to derive key for key encryption: {0}")]
    KeyDerivationError(String),
    #[error("Security violation: Plaintext encryption is not allowed for financial payloads (TransactionBundle).")]
    PlaintextNotAllowedForFinancialPayload,
    #[error("Password required for symmetric encryption.")]
    PasswordRequired,
    #[error("Invalid encryption configuration.")]
    InvalidEncryptionConfig,
}

/// Creates, encrypts, and signs a JWE-compatible `SecureContainer` with configurable encryption.
///
/// This function implements RFC 7516 JSON Web Encryption (JWE) General Serialization.
/// For asymmetric encryption, a Protected Header with alg, enc, typ, and epk is created,
/// and the payload is encrypted using the Protected Header as AAD.
///
/// # Arguments
/// * `sender_identity` - The sender's identity, including keys.
/// * `config` - The encryption configuration (TargetDid, Password, or Cleartext).
/// * `payload` - The raw payload data to encrypt (e.g. a serialized JSON object).
/// * `content_type` - The payload type.
///
/// # Returns
/// A `Result` containing the fully configured `SecureContainer` or a `VoucherCoreError`.
pub fn create_secure_container(
    sender_identity: &UserIdentity,
    config: ContainerConfig,
    payload: &[u8],
    content_type: PayloadType,
) -> Result<SecureContainer, VoucherCoreError> {
    // Security check: Plaintext must not be used for financial payloads
    if config == ContainerConfig::Cleartext && content_type == PayloadType::TransactionBundle {
        return Err(ContainerManagerError::PlaintextNotAllowedForFinancialPayload.into());
    }

    let (recipient_ids, privacy_mode) = match &config {
        ContainerConfig::TargetDid(id, mode) => (vec![id.clone()], mode.clone()),
        ContainerConfig::TargetDids(ids, mode) => (ids.clone(), mode.clone()),
        _ => (Vec::new(), PrivacyMode::TrialDecryption),
    };

    let (encryption_type, protected, recipients, iv, ciphertext, tag, salt) = match config {
        ContainerConfig::TargetDid(_, _) | ContainerConfig::TargetDids(_, _) => {
            // Asymmetric encryption (JWE format)
            let esk_priv_static = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let esk_pub = x25519_dalek::PublicKey::from(&esk_priv_static);

            // Ephemeral public key as Base64url for protected header
            let epk_b64 = encode_base64(esk_pub.as_bytes());

            // Build protected header (RFC 7516)
            let protected_header = json!({
                "alg": "ECDH-ES+A256KW",
                "enc": "C20P", // ChaCha20-Poly1305
                "typ": content_type.to_didcomm_uri(),
                "epk": epk_b64
            });
            let protected_json = serde_json::to_string(&protected_header)
                .map_err(|e| VoucherCoreError::Crypto(format!("Failed to serialize protected header: {}", e)))?;
            let protected_b64 = encode_base64(protected_json.as_bytes());

            // Generate and encrypt payload key
            let (recipients_vec, mut payload_key) = {
                let mut payload_key = [0u8; 32];
                OsRng.fill_bytes(&mut payload_key);

                let mut recipients = Vec::new();

                // Key wrapping for all recipients
                for recipient_id in recipient_ids {
                    let recipient_pubkey_ed = get_pubkey_from_user_id(&recipient_id)?;
                    let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);

                    let shared_secret = esk_priv_static.diffie_hellman(&recipient_pubkey_x);
                    if !shared_secret.was_contributory() {
                        return Err(VoucherCoreError::Crypto(
                            "Non-contributory X25519 key exchange rejected (low-order point)".to_string(),
                        ));
                    }
                    let kek = derive_kek(shared_secret.as_bytes())?;
                    let encrypted_payload_key = encrypt_data(&kek, &payload_key)?;

                    // Set header based on PrivacyMode
                    let header = match privacy_mode {
                        PrivacyMode::TrialDecryption => None,
                        PrivacyMode::HashedRouting => Some(json!({"kid": get_hash(&recipient_id)})),
                        PrivacyMode::CleartextRouting => Some(json!({"kid": recipient_id})),
                    };

                    recipients.push(JweRecipient {
                        header,
                        encrypted_key: encode_base64(&encrypted_payload_key),
                    });
                }

                // Double-Key-Wrapping for the sender
                let sender_static_sk_x = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);
                let shared_secret_sender = sender_static_sk_x.diffie_hellman(&esk_pub);
                if !shared_secret_sender.was_contributory() {
                    return Err(VoucherCoreError::Crypto(
                        "Non-contributory X25519 key exchange rejected (low-order point)".to_string(),
                    ));
                }
                let kek_sender = derive_kek(shared_secret_sender.as_bytes())?;
                let encrypted_payload_key_sender = encrypt_data(&kek_sender, &payload_key)?;

                // Set header for sender based on PrivacyMode
                let sender_header = match privacy_mode {
                    PrivacyMode::TrialDecryption => None,
                    PrivacyMode::HashedRouting => Some(json!({"kid": get_hash(&sender_identity.user_id), "sender": true})),
                    PrivacyMode::CleartextRouting => Some(json!({"kid": sender_identity.user_id.clone(), "sender": true})),
                };

                recipients.push(JweRecipient {
                    header: sender_header,
                    encrypted_key: encode_base64(&encrypted_payload_key_sender),
                });

                (recipients, payload_key)
            };

            // Encrypt payload with AAD (protected header)
            // In JWE, AAD is the base64url-encoded protected header string (ASCII)
            let (nonce_bytes, ciphertext_bytes, tag_bytes) = encrypt_data_with_aad(
                &payload_key,
                payload,
                protected_b64.as_bytes(),
            ).map_err(VoucherCoreError::SymmetricEncryption)?;

            payload_key.zeroize();

            let iv_b64 = encode_base64(&nonce_bytes);
            let ciphertext_b64 = encode_base64(&ciphertext_bytes);
            let tag_b64 = encode_base64(&tag_bytes);

            (
                EncryptionType::Asymmetric,
                protected_b64,
                recipients_vec,
                iv_b64,
                ciphertext_b64,
                tag_b64,
                None,
            )
        }
        ContainerConfig::Password(password) => {
            // Symmetric encryption with password
            let (ciphertext, salt) = encrypt_symmetric_password(payload, &password)?;
            let encrypted_payload_b64 = encode_base64(&ciphertext);
            let salt_b64 = encode_base64(&salt);

            // Empty protected header for symmetric encryption
            let protected_b64 = String::new();
            let recipients = Vec::new();
            let iv_b64 = String::new();
            let tag_b64 = String::new();

            (
                EncryptionType::Symmetric,
                protected_b64,
                recipients,
                iv_b64,
                encrypted_payload_b64,
                tag_b64,
                Some(salt_b64),
            )
        }
        ContainerConfig::Cleartext => {
            // No encryption (Base64-encoded cleartext)
            let encrypted_payload_b64 = encode_base64(payload);

            let protected_b64 = String::new();
            let recipients = Vec::new();
            let iv_b64 = String::new();
            let tag_b64 = String::new();

            (
                EncryptionType::None,
                protected_b64,
                recipients,
                iv_b64,
                encrypted_payload_b64,
                tag_b64,
                None,
            )
        }
    };

    // Assemble container (JWE format)
    let mut container = SecureContainer {
        protected,
        unprotected: None,
        recipients,
        iv,
        ciphertext,
        tag,
        signature: String::new(),
        et: encryption_type,
        salt,
        i: String::new(),
        c: content_type.clone(),
    };

    // Generate container_id from hash of canonical content
    let container_json_for_id = to_canonical_json(&container)?;
    container.i = get_hash(container_json_for_id);

    // Sign the container_id
    let signature = crypto_utils::sign_ed25519(&sender_identity.signing_key, container.i.as_bytes());
    container.signature = encode_base64(&signature.to_bytes());

    Ok(container)
}

/// HMSEC-SA06-09: Verifies the wrapper-vs-payload binding of a
/// `SecureContainer` by recomputing the integrity id from the received
/// bytes. `i` and `signature` are excluded exactly as during creation
/// ([`create_secure_container`]), so the check covers ALL AEAD-exempt
/// envelope fields (`unprotected`, `salt`, `et`, `c`, recipients, ...).
///
/// Without this rebinding, a stolen-but-genuinely-signed `(i, signature)`
/// pair can be grafted onto manipulated container content and arbitrary
/// unauthenticated header metadata can be injected undetected
/// (CWE-347; same attack class as the bundle-level fix in
/// `bundle_processor::open_and_verify_bundle`). Every protocol receive path
/// MUST call this before acting on payload or envelope metadata.
pub fn verify_container_integrity_binding(container: &SecureContainer) -> Result<(), VoucherCoreError> {
    let mut container_for_hash = container.clone();
    container_for_hash.i = String::new();
    container_for_hash.signature = String::new();
    let expected_i = get_hash(to_canonical_json(&container_for_hash)?);
    if container.i != expected_i {
        return Err(crate::error::ValidationError::InvalidContainerSignature.into());
    }
    Ok(())
}

/// Decrypts the payload of a JWE-compatible `SecureContainer` with configurable encryption.
/// **Note:** This function does NOT verify the container's signature, as
/// the `sender_id` from the (still encrypted) payload is required for that.
/// Signature verification is the caller's responsibility (e.g. `bundle_processor`).
///
/// # Arguments
/// * `container` - The `SecureContainer` to open.
/// * `recipient_identity` - The identity of the recipient (the current user).
/// * `password` - Optional password for symmetric encryption.
///
/// # Returns
/// A `Result` containing the decrypted payload data or a `VoucherCoreError`.
pub fn open_secure_container(
    container: &SecureContainer,
    recipient_identity: &UserIdentity,
    password: Option<&str>,
) -> Result<Vec<u8>, VoucherCoreError> {
    match container.et {
        EncryptionType::Asymmetric => {
            // JWE format for asymmetric encryption
            let recipient_x25519_sk = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);

            // Decode protected header and extract epk
            if container.protected.is_empty() {
                return Err(VoucherCoreError::Crypto("Protected header is required for asymmetric encryption".to_string()));
            }

            let protected_bytes = decode_base64(&container.protected)?;
            let protected_header_json = serde_json::from_slice::<serde_json::Value>(&protected_bytes)
                .map_err(|e| VoucherCoreError::Crypto(format!("Failed to parse protected header: {}", e)))?;

            let epk_b64 = protected_header_json["epk"]
                .as_str()
                .ok_or_else(|| VoucherCoreError::Crypto("Missing epk in protected header".to_string()))?;
            let esk_pub_bytes = decode_base64(epk_b64)?;
            let esk_pub = x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(esk_pub_bytes)
                    .map_err(|_| VoucherCoreError::Crypto("Invalid ephemeral key length".to_string()))?,
            );

            // Search for matching recipient in recipients array
            let mut decrypted_payload_key: Option<[u8; 32]> = None;

            // Compute hash of own ID once for HashedRouting
            let my_hash = get_hash(&recipient_identity.user_id);

            for recipient in &container.recipients {
                let should_try_decrypt = match recipient.header.as_ref().and_then(|h| h.get("kid")).and_then(|v| v.as_str()) {
                    // If kid is present, check whether it is my plaintext ID or my hash
                    Some(kid) => kid == recipient_identity.user_id || kid == my_hash,
                    // If no header/kid is present, we MUST try (Trial Decryption Fallback)
                    None => true,
                };

                if should_try_decrypt {
                    let encrypted_payload_key = decode_base64(&recipient.encrypted_key)?;
                    let shared_secret = recipient_x25519_sk.diffie_hellman(&esk_pub);
                    if !shared_secret.was_contributory() {
                        // Fail closed for this entry only: skip like a failed
                        // decrypt attempt so trial decryption over mixed
                        // recipient lists still works.
                        log::warn!("Skipping non-contributory X25519 key exchange (low-order point) for one recipient entry");
                        continue;
                    }
                    let kek = derive_kek(shared_secret.as_bytes())?;

                    if let Ok(payload_key_bytes) = decrypt_data(&kek, &encrypted_payload_key) {
                        if let Ok(key_array) = payload_key_bytes.try_into() {
                            decrypted_payload_key = Some(key_array);
                            break;
                        }
                    }
                }
            }

            let mut payload_key = decrypted_payload_key
                .ok_or(ContainerManagerError::NotAnIntendedRecipient)?;

            // Decode ciphertext and tag
            let iv = decode_base64(&container.iv)?;
            let ciphertext = decode_base64(&container.ciphertext)?;
            let tag = decode_base64(&container.tag)?;

            // Use protected header as AAD
            let aad = container.protected.as_bytes();

            // Decrypt payload with AAD
            let plaintext = decrypt_data_with_aad(
                &payload_key,
                &iv,
                &ciphertext,
                &tag,
                aad,
            ).map_err(VoucherCoreError::SymmetricEncryption)?;

            payload_key.zeroize();
            Ok(plaintext)
        }
        EncryptionType::Symmetric => {
            // Symmetric encryption with password
            let password = password.ok_or(ContainerManagerError::PasswordRequired)?;
            let salt_b64 = container.salt.as_ref().ok_or_else(|| {
                VoucherCoreError::Crypto("Salt missing for symmetric encryption".to_string())
            })?;
            let salt = decode_base64(salt_b64)?;
            let salt_array: [u8; 16] = salt.try_into().map_err(|_| {
                VoucherCoreError::Crypto("Invalid salt length (expected 16 bytes)".to_string())
            })?;

            let encrypted_payload = decode_base64(&container.ciphertext)?;
            decrypt_symmetric_password(&encrypted_payload, password, &salt_array)
        }
        EncryptionType::None => {
            // No encryption (simply base64-decode)
            decode_base64(&container.ciphertext)
        }
    }
}

/// Derives a Key-Encryption-Key (KEK) from a shared secret via HKDF.
fn derive_kek(shared_secret: &[u8]) -> Result<[u8; 32], ContainerManagerError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut kek = [0u8; 32];
    hkdf.expand(b"secure-container-kek", &mut kek)
        .map_err(|e| ContainerManagerError::KeyDerivationError(e.to_string()))?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::UserIdentity;
    use crate::models::secure_container::PrivacyMode;
    use crate::services::crypto_identity::create_user_id;
    use crate::services::crypto_keys::generate_ed25519_keypair_for_tests;

    #[test]
    fn test_jwe_container_creation_and_opening() {
        // Create sender and recipient identities
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id.clone(),
            signing_key: sender_sk,
            public_key: sender_pub,
        };

        let (recipient_pub, recipient_sk) = generate_ed25519_keypair_for_tests(Some("recipient_seed"));
        let recipient_id = create_user_id(&recipient_pub, Some("recipient")).unwrap();
        let recipient_identity = UserIdentity {
            user_id: recipient_id.clone(),
            signing_key: recipient_sk,
            public_key: recipient_pub,
        };

        // Create a container in JWE format
        let payload = b"Test payload data";
        let config = ContainerConfig::TargetDid(recipient_id.clone(), PrivacyMode::TrialDecryption);
        let content_type = PayloadType::TransactionBundle;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        // Verify JWE structure
        assert!(!container.protected.is_empty(), "Protected header should not be empty");
        assert!(!container.recipients.is_empty(), "Recipients should not be empty");
        assert!(!container.iv.is_empty(), "IV should not be empty");
        assert!(!container.ciphertext.is_empty(), "Ciphertext should not be empty");
        assert!(!container.tag.is_empty(), "Tag should not be empty");
        assert!(!container.signature.is_empty(), "Signature should not be empty");

        // Open container as recipient
        let decrypted_payload = open_secure_container(&container, &recipient_identity, None)
            .expect("Failed to open container");

        assert_eq!(decrypted_payload, payload, "Decrypted payload should match original");
    }

    #[test]
    fn test_jwe_container_sender_can_open() {
        // Create sender identity
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id.clone(),
            signing_key: sender_sk.clone(),
            public_key: sender_pub,
        };

        let (recipient_pub, _) = generate_ed25519_keypair_for_tests(Some("recipient_seed"));
        let recipient_id = create_user_id(&recipient_pub, Some("recipient")).unwrap();

        // Create a container
        let payload = b"Test payload for sender";
        let config = ContainerConfig::TargetDid(recipient_id, PrivacyMode::TrialDecryption);
        let content_type = PayloadType::VoucherForSigning;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        // Open container as sender (should work thanks to Double-Key-Wrapping)
        let decrypted_payload = open_secure_container(&container, &sender_identity, None)
            .expect("Failed to open container as sender");

        assert_eq!(decrypted_payload, payload, "Decrypted payload should match original");
    }

    #[test]
    fn test_jwe_container_multiple_recipients() {
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id.clone(),
            signing_key: sender_sk,
            public_key: sender_pub,
        };

        let (recipient1_pub, recipient1_sk) = generate_ed25519_keypair_for_tests(Some("recipient1_seed"));
        let recipient1_id = create_user_id(&recipient1_pub, Some("recipient1")).unwrap();
        let recipient1_identity = UserIdentity {
            user_id: recipient1_id.clone(),
            signing_key: recipient1_sk,
            public_key: recipient1_pub,
        };

        let (recipient2_pub, recipient2_sk) = generate_ed25519_keypair_for_tests(Some("recipient2_seed"));
        let recipient2_id = create_user_id(&recipient2_pub, Some("recipient2")).unwrap();
        let recipient2_identity = UserIdentity {
            user_id: recipient2_id.clone(),
            signing_key: recipient2_sk,
            public_key: recipient2_pub,
        };

        let payload = b"Payload for multiple recipients";
        let config = ContainerConfig::TargetDids(vec![recipient1_id.clone(), recipient2_id.clone()], PrivacyMode::TrialDecryption);
        let content_type = PayloadType::TransactionBundle;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        // Both recipients should be able to open the container
        let decrypted1 = open_secure_container(&container, &recipient1_identity, None)
            .expect("Recipient 1 failed to open container");
        assert_eq!(decrypted1, payload);

        let decrypted2 = open_secure_container(&container, &recipient2_identity, None)
            .expect("Recipient 2 failed to open container");
        assert_eq!(decrypted2, payload);
    }

    #[test]
    fn test_plaintext_not_allowed_for_financial_payload() {
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id,
            signing_key: sender_sk,
            public_key: sender_pub,
        };

        let payload = b"Financial payload";
        let config = ContainerConfig::Cleartext;
        let content_type = PayloadType::TransactionBundle;

        let result = create_secure_container(&sender_identity, config, payload, content_type);
        assert!(result.is_err(), "Should fail for financial payload with cleartext");
    }

    #[test]
    fn test_cleartext_allowed_for_non_financial_payload() {
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id.clone(),
            signing_key: sender_sk,
            public_key: sender_pub,
        };

        let (recipient_pub, recipient_sk) = generate_ed25519_keypair_for_tests(Some("recipient_seed"));
        let recipient_id = create_user_id(&recipient_pub, Some("recipient")).unwrap();
        let recipient_identity = UserIdentity {
            user_id: recipient_id.clone(),
            signing_key: recipient_sk,
            public_key: recipient_pub,
        };

        let payload = b"Non-financial payload";
        let config = ContainerConfig::TargetDid(recipient_id, PrivacyMode::TrialDecryption);
        let content_type = PayloadType::DetachedSignature;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Should succeed for non-financial payload");

        let decrypted = open_secure_container(&container, &recipient_identity, None)
            .expect("Should open container");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_not_intended_recipient_fails() {
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id,
            signing_key: sender_sk,
            public_key: sender_pub,
        };

        let (recipient_pub, _) = generate_ed25519_keypair_for_tests(Some("recipient_seed"));
        let recipient_id = create_user_id(&recipient_pub, Some("recipient")).unwrap();

        let (other_pub, other_sk) = generate_ed25519_keypair_for_tests(Some("other_seed"));
        let other_id = create_user_id(&other_pub, Some("other")).unwrap();
        let other_identity = UserIdentity {
            user_id: other_id,
            signing_key: other_sk,
            public_key: other_pub,
        };

        let payload = b"Secret payload";
        let config = ContainerConfig::TargetDid(recipient_id, PrivacyMode::TrialDecryption);
        let content_type = PayloadType::TransactionBundle;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        let result = open_secure_container(&container, &other_identity, None);
        assert!(result.is_err(), "Non-recipient should not be able to open container");
    }
}
