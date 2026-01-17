//! # src/services/secure_container_manager.rs
//!
//! Enthält die Kernlogik zur Erstellung, Verschlüsselung, Entschlüsselung und Verifizierung
//! des anonymisierten `SecureContainer`. Implementiert Forward Secrecy und Double-Key-Wrapping.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::secure_container::{PayloadType, SecureContainer, WrappedKey};
use crate::services::crypto_utils::{
    self, decode_base64, ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk, encode_base64, get_hash,
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
}

/// Erstellt, verschlüsselt und signiert einen anonymen `SecureContainer` für mehrere Empfänger.
///
/// # Arguments
/// * `sender_identity` - Die Identität des Senders, inklusive seiner Schlüssel.
/// * `recipient_ids` - Eine Liste der User-IDs der Empfänger.
/// * `payload` - Die zu verschlüsselnden Rohdaten (z.B. ein serialisiertes JSON-Objekt).
///
/// # Returns
/// Ein `Result`, das den vollständig konfigurierten `SecureContainer` oder einen `VoucherCoreError` enthält.
pub fn create_secure_container(
    sender_identity: &UserIdentity,
    recipient_ids: &[String],
    payload: &[u8],
    content_type: PayloadType,
) -> Result<SecureContainer, VoucherCoreError> {
    // KORREKTUR: Erzeuge direkt ein wiederverwendbares `StaticSecret`.
    let esk_priv_static = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let esk_pub = x25519_dalek::PublicKey::from(&esk_priv_static);

    // Scope, um sicherzustellen, dass der ephemere private Schlüssel so schnell wie möglich gelöscht wird.
    let (encrypted_payload_b64, wrapped_keys) = {
        // 1. Einen einmaligen, symmetrischen Schlüssel für den Payload generieren.
        let mut payload_key = [0u8; 32];
        OsRng.fill_bytes(&mut payload_key);

        // 2. Den Payload mit diesem symmetrischen Schlüssel verschlüsseln und Base64-kodieren.
        let encrypted_payload = crypto_utils::encrypt_data(&payload_key, payload)?;
        let encrypted_payload_b64 = encode_base64(&encrypted_payload);

        let mut wrapped_keys = Vec::new();

        // 3. Den `payload_key` für jeden Empfänger einzeln verschlüsseln (Key Wrapping).
        for recipient_id in recipient_ids {
            // TODO: Future Feature for Perfect Forward Secrecy (PFS)
            // Check if an ephemeral "One-Time Pre-Key" (e.g., from an invoice/payment request) 
            // is available for this recipient_id. If yes, use it instead of the static DID key.
            let recipient_pubkey_ed = get_pubkey_from_user_id(recipient_id)?;
            let recipient_pubkey_x = ed25519_pub_to_x25519(&recipient_pubkey_ed);

            let shared_secret = esk_priv_static.diffie_hellman(&recipient_pubkey_x);
            let kek = derive_kek(shared_secret.as_bytes())?;
            let encrypted_payload_key = crypto_utils::encrypt_data(&kek, &payload_key)?;

            wrapped_keys.push(WrappedKey {
                r: Some(encode_base64(&encrypted_payload_key)),
                m: Some(get_hash(recipient_id)),
                s: None,
            });
        }

        // 4. Double-Key-Wrapping: Den `payload_key` auch für den Sender verschlüsseln.
        let sender_static_sk_x = ed25519_sk_to_x25519_sk(&sender_identity.signing_key);
        let shared_secret_sender = sender_static_sk_x.diffie_hellman(&esk_pub);
        let kek_sender = derive_kek(shared_secret_sender.as_bytes())?;
        let encrypted_payload_key_sender = crypto_utils::encrypt_data(&kek_sender, &payload_key)?;
        wrapped_keys.push(WrappedKey {
            s: Some(encode_base64(&encrypted_payload_key_sender)),
            r: None,
            m: None,
        });

        // WICHTIG: payload_key und KEKs aus dem Speicher entfernen.
        payload_key.zeroize();
        (encrypted_payload_b64, wrapped_keys)
    };
    // Ephemeren privaten Schlüssel sicher aus dem Speicher entfernen.
    // esk_priv_static wird automatisch ge-zeroized, wenn es aus dem Scope fällt.

    // 5. Den Container zusammenbauen (vorerst ohne ID und Signatur).
    let mut container = SecureContainer {
        i: "".to_string(),
        c: content_type,
        esk: encode_base64(esk_pub.as_bytes()),
        wk: wrapped_keys,
        p: encrypted_payload_b64,
        t: "".to_string(),
    };

    // 6. Die `container_id` (`i`) aus dem Hash des kanonischen Inhalts generieren.
    let container_json_for_id = to_canonical_json(&container)?;
    container.i = get_hash(container_json_for_id);

    // 7. Die `container_id` signieren und dem Container hinzufügen.
    let signature =
        crypto_utils::sign_ed25519(&sender_identity.signing_key, container.i.as_bytes());
    container.t = encode_base64(&signature.to_bytes());

    Ok(container)
}

/// Entschlüsselt den Payload eines `SecureContainer`.
/// **Achtung:** Diese Funktion verifiziert NICHT die Signatur des Containers, da
/// dafür die `sender_id` aus dem (noch verschlüsselten) Payload benötigt wird.
/// Die Signatur-Verifizierung ist die Verantwortung des Aufrufers (z.B. `bundle_processor`).
///
/// # Arguments
/// * `container` - Der zu öffnende `SecureContainer`.
/// * `recipient_identity` - Die Identität des Empfängers (des aktuellen Nutzers).
///
/// # Returns
/// Ein `Result`, das die entschlüsselten Payload-Daten oder einen `VoucherCoreError` enthält.
pub fn open_secure_container(
    container: &SecureContainer,
    recipient_identity: &UserIdentity,
    // Gibt nun nur die Bytes zurück. Der Payload-Typ ist über `container.c` zugänglich.
) -> Result<Vec<u8>, VoucherCoreError> {
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

/// Leitet einen Key-Encryption-Key (KEK) aus einem Shared Secret mittels HKDF ab.
fn derive_kek(shared_secret: &[u8]) -> Result<[u8; 32], ContainerManagerError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut kek = [0u8; 32];
    hkdf.expand(b"secure-container-kek", &mut kek)
        .map_err(|e| ContainerManagerError::KeyDerivationError(e.to_string()))?;
    Ok(kek)
}
