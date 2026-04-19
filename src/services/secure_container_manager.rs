//! # src/services/secure_container_manager.rs
//!
//! Enthält die Kernlogik zur Erstellung, Verschlüsselung, Entschlüsselung und Verifizierung
//! des anonymisierten `SecureContainer`. Implementiert Forward Secrecy und Double-Key-Wrapping.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, EncryptionType, JweRecipient, PayloadType, PrivacyMode, SecureContainer};
use crate::services::crypto_utils::{
    self, decode_base64, decrypt_data_with_aad, decrypt_symmetric_password, ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk, encode_base64, encrypt_data_with_aad, encrypt_symmetric_password, get_hash,
    get_pubkey_from_user_id,
};
use crate::services::utils::to_canonical_json;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroize;

/// Definiert die Fehler, die im `secure_container_manager`-Modul auftreten können.
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

/// Erstellt, verschlüsselt und signiert einen JWE-kompatiblen `SecureContainer` mit konfigurierbarer Verschlüsselung.
///
/// Diese Funktion implementiert RFC 7516 JSON Web Encryption (JWE) General Serialization.
/// Für asymmetrische Verschlüsselung wird ein Protected Header mit alg, enc, typ und epk erstellt,
/// und die Payload mit dem Protected Header als AAD verschlüsselt.
///
/// # Arguments
/// * `sender_identity` - Die Identität des Senders, inklusive seiner Schlüssel.
/// * `config` - Die Verschlüsselungskonfiguration (TargetDid, Password, oder Cleartext).
/// * `payload` - Die zu verschlüsselnden Rohdaten (z.B. ein serialisiertes JSON-Objekt).
/// * `content_type` - Die Art des Payloads.
///
/// # Returns
/// Ein `Result`, das den vollständig konfigurierten `SecureContainer` oder einen `VoucherCoreError` enthält.
pub fn create_secure_container(
    sender_identity: &UserIdentity,
    config: ContainerConfig,
    payload: &[u8],
    content_type: PayloadType,
) -> Result<SecureContainer, VoucherCoreError> {
    // Sicherheits-Check: Plaintext darf nicht für finanzielle Payloads verwendet werden
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
            // Asymmetrische Verschlüsselung (JWE-Format)
            let esk_priv_static = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let esk_pub = x25519_dalek::PublicKey::from(&esk_priv_static);

            // Ephemeral Public Key als Base64url für den Protected Header
            let epk_b64 = encode_base64(esk_pub.as_bytes());

            // Protected Header aufbauen (RFC 7516)
            let protected_header = json!({
                "alg": "ECDH-ES+A256KW",
                "enc": "C20P", // ChaCha20-Poly1305
                "typ": content_type.to_didcomm_uri(),
                "epk": epk_b64
            });
            let protected_json = serde_json::to_string(&protected_header)
                .map_err(|e| VoucherCoreError::Crypto(format!("Failed to serialize protected header: {}", e)))?;
            let protected_b64 = encode_base64(protected_json.as_bytes());

            // Payload-Key generieren und verschlüsseln
            let (recipients_vec, mut payload_key) = {
                let mut payload_key = [0u8; 32];
                OsRng.fill_bytes(&mut payload_key);

                let mut recipients = Vec::new();

                // Key Wrapping für alle Empfänger
                for recipient_id in recipient_ids {
                    let recipient_pubkey_ed = get_pubkey_from_user_id(&recipient_id)?;
                    let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);

                    let shared_secret = esk_priv_static.diffie_hellman(&recipient_pubkey_x);
                    let kek = derive_kek(shared_secret.as_bytes())?;
                    let encrypted_payload_key = crypto_utils::encrypt_data(&kek, &payload_key)?;

                    // Header basierend auf PrivacyMode setzen
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

                // Double-Key-Wrapping für den Sender
                let sender_static_sk_x = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);
                let shared_secret_sender = sender_static_sk_x.diffie_hellman(&esk_pub);
                let kek_sender = derive_kek(shared_secret_sender.as_bytes())?;
                let encrypted_payload_key_sender = crypto_utils::encrypt_data(&kek_sender, &payload_key)?;

                // Header für Sender basierend auf PrivacyMode setzen
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

            // Payload mit AAD (Protected Header) verschlüsseln
            // In JWE ist AAD der base64url-encodierte Protected Header String (ASCII)
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
            // Symmetrische Verschlüsselung mit Passwort
            let (ciphertext, salt) = encrypt_symmetric_password(payload, &password)?;
            let encrypted_payload_b64 = encode_base64(&ciphertext);
            let salt_b64 = encode_base64(&salt);

            // Leerer Protected Header für symmetrische Verschlüsselung
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
            // Keine Verschlüsselung (Base64-kodierter Klartext)
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

    // Container zusammenbauen (JWE-Format)
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

    // Die container_id aus dem Hash des kanonischen Inhalts generieren
    let container_json_for_id = to_canonical_json(&container)?;
    container.i = get_hash(container_json_for_id);

    // Die container_id signieren
    let signature = crypto_utils::sign_ed25519(&sender_identity.signing_key, container.i.as_bytes());
    container.signature = encode_base64(&signature.to_bytes());

    Ok(container)
}

/// Entschlüsselt den Payload eines JWE-kompatiblen `SecureContainer` mit konfigurierbarer Verschlüsselung.
/// **Achtung:** Diese Funktion verifiziert NICHT die Signatur des Containers, da
/// dafür die `sender_id` aus dem (noch verschlüsselten) Payload benötigt wird.
/// Die Signatur-Verifizierung ist die Verantwortung des Aufrufers (z.B. `bundle_processor`).
///
/// # Arguments
/// * `container` - Der zu öffnende `SecureContainer`.
/// * `recipient_identity` - Die Identität des Empfängers (des aktuellen Nutzers).
/// * `password` - Optionales Passwort für symmetrische Verschlüsselung.
///
/// # Returns
/// Ein `Result`, das die entschlüsselten Payload-Daten oder einen `VoucherCoreError` enthält.
pub fn open_secure_container(
    container: &SecureContainer,
    recipient_identity: &UserIdentity,
    password: Option<&str>,
) -> Result<Vec<u8>, VoucherCoreError> {
    match container.et {
        EncryptionType::Asymmetric => {
            // JWE-Format für asymmetrische Verschlüsselung
            let recipient_x25519_sk = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);

            // Protected Header dekodieren und epk extrahieren
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

            // Suche den passenden Empfänger im recipients-Array
            let mut decrypted_payload_key: Option<[u8; 32]> = None;

            // Hash der eigenen ID einmalig berechnen für HashedRouting
            let my_hash = get_hash(&recipient_identity.user_id);

            for recipient in &container.recipients {
                let should_try_decrypt = match recipient.header.as_ref().and_then(|h| h.get("kid")).and_then(|v| v.as_str()) {
                    // Wenn eine kid vorhanden ist, prüfe ob es meine Klartext-ID oder mein Hash ist
                    Some(kid) => kid == recipient_identity.user_id || kid == my_hash,
                    // Wenn kein Header/kid vorhanden ist, MÜSSEN wir es versuchen (Trial Decryption Fallback)
                    None => true,
                };

                if should_try_decrypt {
                    let encrypted_payload_key = decode_base64(&recipient.encrypted_key)?;
                    let shared_secret = recipient_x25519_sk.diffie_hellman(&esk_pub);
                    let kek = derive_kek(shared_secret.as_bytes())?;

                    if let Ok(payload_key_bytes) = crypto_utils::decrypt_data(&kek, &encrypted_payload_key) {
                        if let Ok(key_array) = payload_key_bytes.try_into() {
                            decrypted_payload_key = Some(key_array);
                            break;
                        }
                    }
                }
            }

            let mut payload_key = decrypted_payload_key
                .ok_or(ContainerManagerError::NotAnIntendedRecipient)?;

            // Ciphertext und Tag dekodieren
            let iv = decode_base64(&container.iv)?;
            let ciphertext = decode_base64(&container.ciphertext)?;
            let tag = decode_base64(&container.tag)?;

            // Protected Header als AAD verwenden
            let aad = container.protected.as_bytes();

            // Payload mit AAD entschlüsseln
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
            // Symmetrische Verschlüsselung mit Passwort
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
            // Keine Verschlüsselung (einfach base64-dekodieren)
            decode_base64(&container.ciphertext)
        }
    }
}

/// Leitet einen Key-Encryption-Key (KEK) aus einem Shared Secret mittels HKDF ab.
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
    use crate::services::crypto_utils::{create_user_id, generate_ed25519_keypair_for_tests};

    #[test]
    fn test_jwe_container_creation_and_opening() {
        // Erstelle Sender- und Empfänger-Identitäten
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

        // Erstelle einen Container mit JWE-Format
        let payload = b"Test payload data";
        let config = ContainerConfig::TargetDid(recipient_id.clone(), PrivacyMode::TrialDecryption);
        let content_type = PayloadType::TransactionBundle;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        // Verifiziere JWE-Struktur
        assert!(!container.protected.is_empty(), "Protected header should not be empty");
        assert!(!container.recipients.is_empty(), "Recipients should not be empty");
        assert!(!container.iv.is_empty(), "IV should not be empty");
        assert!(!container.ciphertext.is_empty(), "Ciphertext should not be empty");
        assert!(!container.tag.is_empty(), "Tag should not be empty");
        assert!(!container.signature.is_empty(), "Signature should not be empty");

        // Öffne den Container als Empfänger
        let decrypted_payload = open_secure_container(&container, &recipient_identity, None)
            .expect("Failed to open container");

        assert_eq!(decrypted_payload, payload, "Decrypted payload should match original");
    }

    #[test]
    fn test_jwe_container_sender_can_open() {
        // Erstelle Sender-Identität
        let (sender_pub, sender_sk) = generate_ed25519_keypair_for_tests(Some("sender_seed"));
        let sender_id = create_user_id(&sender_pub, Some("sender")).unwrap();
        let sender_identity = UserIdentity {
            user_id: sender_id.clone(),
            signing_key: sender_sk.clone(),
            public_key: sender_pub,
        };

        let (recipient_pub, _) = generate_ed25519_keypair_for_tests(Some("recipient_seed"));
        let recipient_id = create_user_id(&recipient_pub, Some("recipient")).unwrap();

        // Erstelle einen Container
        let payload = b"Test payload for sender";
        let config = ContainerConfig::TargetDid(recipient_id, PrivacyMode::TrialDecryption);
        let content_type = PayloadType::VoucherForSigning;

        let container = create_secure_container(&sender_identity, config, payload, content_type)
            .expect("Failed to create container");

        // Öffne den Container als Sender (sollte funktionieren dank Double-Key-Wrapping)
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

        // Beide Empfänger sollten den Container öffnen können
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
