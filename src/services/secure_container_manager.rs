//! # src/services/secure_container_manager.rs
//!
//! Enthält die Kernlogik zur Erstellung, Verschlüsselung, Entschlüsselung und Verifizierung
//! des anonymisierten `SecureContainer`. Implementiert Forward Secrecy und Double-Key-Wrapping.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{ContainerConfig, EncryptionType, PayloadType, SecureContainer, WrappedKey};
use crate::services::crypto_utils::{
    self, decode_base64, decrypt_symmetric_password, ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk, encode_base64, encrypt_symmetric_password, get_hash,
    get_pubkey_from_user_id,
};
use crate::services::utils::to_canonical_json;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
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

/// Erstellt, verschlüsselt und signiert einen anonymen `SecureContainer` mit konfigurierbarer Verschlüsselung.
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

    let recipient_ids = match &config {
        ContainerConfig::TargetDid(id) => vec![id.clone()],
        ContainerConfig::TargetDids(ids) => ids.clone(),
        _ => Vec::new(),
    };

    let (encryption_type, encrypted_payload_b64, wrapped_keys, salt, esk_b64) = match config {
        ContainerConfig::TargetDid(_) | ContainerConfig::TargetDids(_) => {
            // Asymmetrische Verschlüsselung (bestehende Logik)
            let esk_priv_static = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let esk_pub = x25519_dalek::PublicKey::from(&esk_priv_static);

            let (encrypted_payload_b64, wrapped_keys) = {
                let mut payload_key = [0u8; 32];
                OsRng.fill_bytes(&mut payload_key);

                let encrypted_payload = crypto_utils::encrypt_data(&payload_key, payload)?;
                let encrypted_payload_b64 = encode_base64(&encrypted_payload);

                let mut wrapped_keys = Vec::new();

                // Key Wrapping für alle Empfänger
                for recipient_id in recipient_ids {
                    let recipient_pubkey_ed = get_pubkey_from_user_id(&recipient_id)?;
                    let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);

                    let shared_secret = esk_priv_static.diffie_hellman(&recipient_pubkey_x);
                    let kek = derive_kek(shared_secret.as_bytes())?;
                    let encrypted_payload_key = crypto_utils::encrypt_data(&kek, &payload_key)?;

                    wrapped_keys.push(WrappedKey {
                        r: Some(encode_base64(&encrypted_payload_key)),
                        m: Some(get_hash(&recipient_id)),
                        s: None,
                    });
                }

                // Double-Key-Wrapping für den Sender
                let sender_static_sk_x = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);
                let shared_secret_sender = sender_static_sk_x.diffie_hellman(&esk_pub);
                let kek_sender = derive_kek(shared_secret_sender.as_bytes())?;
                let encrypted_payload_key_sender = crypto_utils::encrypt_data(&kek_sender, &payload_key)?;
                wrapped_keys.push(WrappedKey {
                    s: Some(encode_base64(&encrypted_payload_key_sender)),
                    r: None,
                    m: None,
                });

                payload_key.zeroize();
                (encrypted_payload_b64, wrapped_keys)
            };

            let esk_b64 = encode_base64(esk_pub.as_bytes());
            (EncryptionType::Asymmetric, encrypted_payload_b64, wrapped_keys, None, esk_b64)
        }
        ContainerConfig::Password(password) => {
            // Symmetrische Verschlüsselung mit Passwort
            let (ciphertext, salt) = encrypt_symmetric_password(payload, &password)?;
            let encrypted_payload_b64 = encode_base64(&ciphertext);
            let salt_b64 = encode_base64(&salt);

            // Keine wrapped_keys bei symmetrischer Verschlüsselung
            let wrapped_keys = Vec::new();

            // Platzhalter für esk (leerer String, da nicht benötigt)
            let esk_b64 = String::new();

            (EncryptionType::Symmetric, encrypted_payload_b64, wrapped_keys, Some(salt_b64), esk_b64)
        }
        ContainerConfig::Cleartext => {
            // Keine Verschlüsselung (Base64-kodierter Klartext)
            let encrypted_payload_b64 = encode_base64(payload);
            let wrapped_keys = Vec::new();
            let esk_b64 = String::new();

            (EncryptionType::None, encrypted_payload_b64, wrapped_keys, None, esk_b64)
        }
    };

    // Container zusammenbauen
    let mut container = SecureContainer {
        i: "".to_string(),
        c: content_type,
        esk: esk_b64,
        wk: wrapped_keys,
        p: encrypted_payload_b64,
        t: "".to_string(),
        et: encryption_type,
        salt,
    };

    // Die container_id aus dem Hash des kanonischen Inhalts generieren
    let container_json_for_id = to_canonical_json(&container)?;
    container.i = get_hash(container_json_for_id);

    // Die container_id signieren
    let signature = crypto_utils::sign_ed25519(&sender_identity.signing_key, container.i.as_bytes());
    container.t = encode_base64(&signature.to_bytes());

    Ok(container)
}

/// Entschlüsselt den Payload eines `SecureContainer` mit konfigurierbarer Verschlüsselung.
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
            // Bestehende Logik für asymmetrische Verschlüsselung
            let my_id_hash = get_hash(&recipient_identity.user_id);
            let recipient_x25519_sk = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);
            let esk_pub_bytes = decode_base64(&container.esk)?;
            let esk_pub = x25519_dalek::PublicKey::from(
                <[u8; 32]>::try_from(esk_pub_bytes)
                    .map_err(|_| VoucherCoreError::Crypto("Invalid ephemeral key length".to_string()))?,
            );

            // Versuche, den Payload-Schlüssel zu entschlüsseln.
            for wrapped_key in &container.wk {
                let encrypted_payload_key_b64 = if wrapped_key.s.is_some() {
                    // Bin ich der Sender?
                    wrapped_key.s.as_deref()
                } else if wrapped_key.m.as_deref() == Some(&my_id_hash) {
                    // Bin ich der Empfänger?
                    wrapped_key.r.as_deref()
                } else {
                    None
                };

                if let Some(b64_key) = encrypted_payload_key_b64 {
                    let encrypted_payload_key = decode_base64(b64_key)?;
                    let shared_secret = recipient_x25519_sk.diffie_hellman(&esk_pub);
                    let kek = derive_kek(shared_secret.as_bytes())?;

                    if let Ok(payload_key_bytes) = crypto_utils::decrypt_data(&kek, &encrypted_payload_key)
                    {
                        let payload_key: [u8; 32] = payload_key_bytes.try_into().map_err(|_| {
                            VoucherCoreError::Crypto(
                                "Decrypted payload key has incorrect length".to_string(),
                            )
                        })?;

                        let encrypted_payload = decode_base64(&container.p)?;
                        return Ok(crypto_utils::decrypt_data(
                            &payload_key,
                            &encrypted_payload,
                        )?);
                    }
                }
            }

            Err(ContainerManagerError::NotAnIntendedRecipient.into())
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
            let encrypted_payload = decode_base64(&container.p)?;
            decrypt_symmetric_password(&encrypted_payload, password, &salt_array)
        }
        EncryptionType::None => {
            // Keine Verschlüsselung (einfach base64-dekodieren)
            decode_base64(&container.p)
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
