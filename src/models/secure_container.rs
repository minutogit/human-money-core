//! # src/models/secure_container.rs
//!
//! Defines the data structure for an anonymized, signed, and multi-recipient
//! encrypted data container. This container serves as a universal and secure
//! transport medium for arbitrary data between users.

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::services::crypto::dh::{ed25519_pub_to_x25519, ed25519_sk_to_x25519_sk};
use crate::services::crypto::identity::get_pubkey_from_user_id;
use crate::services::crypto::symmetric::{
    decrypt_data, decrypt_data_with_aad, decrypt_symmetric_password, encrypt_data,
    encrypt_data_with_aad, encrypt_symmetric_password,
};
use crate::services::crypto::{self, decode_base64, encode_base64, get_hash};
use crate::services::utils::to_canonical_json;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use zeroize::Zeroize;

/// Defines the type of content transported in the `SecureContainer`.
///
/// Using an enum instead of a plain string increases type safety
/// and makes the sender's intent explicit in the code.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PayloadType {
    /// The payload is a `TransactionBundle` for a voucher transaction.
    TransactionBundle,
    /// The payload is a `Voucher` submitted to a guarantor for signing.
    VoucherForSigning,
    /// The payload is a `DetachedSignature` response in the signing workflow.
    DetachedSignature,
    /// The payload is a `TrustAssertion` for the Web-of-Trust.
    TrustAssertion,
    /// The payload is a `ProofOfDoubleSpend` (fraud proof).
    ProofOfDoubleSpend,
    /// The payload is a `VoucherStandardDefinition` (.standard TOML file).
    VoucherStandardDefinition,
    /// A generic type for future, not yet defined use cases.
    Generic(String),
}

impl Default for PayloadType {
    /// The default payload is a `TransactionBundle`, as this is the most common use case.
    fn default() -> Self {
        PayloadType::TransactionBundle
    }
}

impl PayloadType {
    /// Maps the internal payload type to a standardized DIDComm URI.
    ///
    /// These URIs are used in the JWE header as the `typ` field to indicate the type
    /// of content in a standard-compliant manner (DIDComm V2 compatibility).
    pub fn to_didcomm_uri(&self) -> String {
        let base_url = "https://github.com/minutogit/human-money-core/tree/main/protocols";
        match self {
            PayloadType::TransactionBundle => format!("{}/transfer/1.0/bundle.md", base_url),
            PayloadType::VoucherForSigning => format!("{}/signing/1.0/request.md", base_url),
            PayloadType::DetachedSignature => format!("{}/signing/1.0/response.md", base_url),
            PayloadType::ProofOfDoubleSpend => format!("{}/conflict/1.0/proof.md", base_url),
            PayloadType::TrustAssertion => format!("{}/trust/1.0/assertion.md", base_url),
            PayloadType::VoucherStandardDefinition => format!("{}/standard/1.0/definition.md", base_url),
            PayloadType::Generic(s) => format!("{}/generic/1.0/{}.md", base_url, s),
        }
    }
}

/// Defines the type of encryption for the container.
///
/// Backward compatibility is ensured via the `Default` trait:
/// Legacy containers without the `et` field are automatically parsed as `Asymmetric`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionType {
    /// Default: Encrypted with ephemeral key and recipient DID(s) (asymmetric).
    Asymmetric,
    /// Encrypted with a one-time password/PIN via PBKDF2 (symmetric).
    Symmetric,
    /// Unencrypted (cleartext, only for signing requests and other non-financial payloads!).
    None,
}

impl Default for EncryptionType {
    /// The default is `Asymmetric` to ensure backward compatibility.
    fn default() -> Self {
        EncryptionType::Asymmetric
    }
}

/// Defines the privacy mode for asymmetric encryption.
///
/// This mode determines whether and how the recipient ID is stored in the JWE header
/// (kid field).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub enum PrivacyMode {
    /// Maximum privacy: JWE header remains empty. Recipients use trial decryption.
    #[default]
    TrialDecryption,
    /// Obfuscated routing: The ID is stored hashed in the `kid` field (allows fast lookup without cleartext ID).
    HashedRouting,
    /// Cleartext routing: The did:key is stored in cleartext in the `kid` field (maximum transparency / for simple offline routing).
    CleartextRouting,
}

/// Configuration for container encryption.
///
/// This enum is used to configure the type of encryption when creating
/// a SecureContainer. It is passed directly through the API layers
/// down to the wallet level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ContainerConfig {
    /// Asymmetric encryption with a single DID and PrivacyMode.
    TargetDid(String, PrivacyMode),
    /// Asymmetric encryption with multiple DIDs and PrivacyMode.
    TargetDids(Vec<String>, PrivacyMode),
    /// Symmetric encryption with a password/PIN.
    Password(String),
    /// No encryption (cleartext, only for non-financial payloads!).
    Cleartext,
}

/// JWE recipient structure (RFC 7516).
///
/// Contains the data encrypted for a specific recipient.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct JweRecipient {
    /// Optional headers per recipient (e.g. 'kid' = recipient's did:key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,

    /// Base64url-encoded encrypted payload key.
    pub encrypted_key: String,
}

/// RFC 7516 JSON Web Encryption (JWE) General Serialization.
///
/// This structure implements the JWE standard for encrypted containers.
/// It replaces the proprietary format and is DIDComm V2-compatible.
///
/// The structure implements Forward Secrecy through ephemeral keys in the
/// Protected Header and supports multiple recipients via the recipients array.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[derive(Default)]
pub struct SecureContainer {
    /// Base64url-encoded Protected Header as string.
    /// Must contain at least 'alg', 'enc', 'typ' and 'epk' (Ephemeral Public Key).
    pub protected: String,

    /// Unprotected Header (optional). Can be used e.g. for sender IDs
    /// if these do not need to be encrypted or signed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<serde_json::Value>,

    /// Array of recipients with their specific encrypted payload keys.
    pub recipients: Vec<JweRecipient>,

    /// Base64url-encoded Initialization Vector (nonce for ChaCha20-Poly1305).
    pub iv: String,

    /// Base64url-encoded ciphertext (the encrypted payload).
    pub ciphertext: String,

    /// Base64url-encoded authentication tag (from ChaCha20-Poly1305).
    pub tag: String,

    /// Sender's digital signature (Ed25519) signing the container hash,
    /// thereby ensuring authenticity and integrity of the entire container.
    /// This field is NOT part of the JWE standard, but is used for container signature.
    pub signature: String,

    /// `encryption_type`: Configuration of encryption (Asymmetric, Symmetric, None).
    /// For JWE this is implicitly determined by the presence of recipients,
    /// but is retained for internal logic.
    #[serde(default)]
    pub et: EncryptionType,

    /// `salt`: Salt for PBKDF2 derivation (only set for Symmetric).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,

    /// `id`: A unique ID for this container, generated from the hash of its contents.
    /// This field is NOT part of the JWE standard, but is used for container identification.
    pub i: String,

    /// `content_type`: Indicates what type of data is contained in the payload.
    /// This field is NOT part of the JWE standard (located in protected header as 'typ'),
    /// but is retained for internal logic.
    pub c: PayloadType,
}

impl SecureContainer {
    /// Creates, encrypts, and signs a JWE-compatible `SecureContainer` with configurable encryption.
    ///
    /// This method implements RFC 7516 JSON Web Encryption (JWE) General Serialization.
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
    pub fn seal(
        sender_identity: &UserIdentity,
        config: &ContainerConfig,
        payload: &[u8],
        content_type: PayloadType,
    ) -> Result<Self, VoucherCoreError> {
        // Security check: Plaintext must not be used for financial payloads
        if *config == ContainerConfig::Cleartext && content_type == PayloadType::TransactionBundle {
            return Err(VoucherCoreError::PlaintextNotAllowedForFinancialPayload);
        }

        let (recipient_ids, privacy_mode) = match config {
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
            ContainerConfig::Password(password) if password.is_empty() => {
                return Err(VoucherCoreError::Crypto("Password cannot be empty".to_string()));
            }
            ContainerConfig::Password(password) => {
                // Symmetric encryption with password
                let (ciphertext, salt) = encrypt_symmetric_password(payload, password)?;
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
        let signature = crypto::sign_ed25519(&sender_identity.signing_key, container.i.as_bytes());
        container.signature = encode_base64(&signature.to_bytes());

        Ok(container)
    }

    /// Alias for `seal` (ergonomics).
    pub fn create(
        sender_identity: &UserIdentity,
        config: &ContainerConfig,
        payload: &[u8],
        content_type: PayloadType,
    ) -> Result<Self, VoucherCoreError> {
        Self::seal(sender_identity, config, payload, content_type)
    }

    /// HMSEC-SA06-09: Verifies the wrapper-vs-payload binding of a
    /// `SecureContainer` by recomputing the integrity id from the received
    /// bytes. `i` and `signature` are excluded exactly as during creation,
    /// so the check covers ALL AEAD-exempt envelope fields (`unprotected`, `salt`, `et`, `c`, recipients, ...).
    pub fn verify_integrity(&self) -> Result<(), VoucherCoreError> {
        let mut container_for_hash = self.clone();
        container_for_hash.i = String::new();
        container_for_hash.signature = String::new();
        let expected_i = get_hash(to_canonical_json(&container_for_hash)?);
        if self.i != expected_i {
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
    /// * `recipient_identity` - The identity of the recipient (the current user).
    /// * `password` - Optional password for symmetric encryption.
    ///
    /// # Returns
    /// A `Result` containing the decrypted payload data or a `VoucherCoreError`.
    pub fn open(
        &self,
        recipient_identity: &UserIdentity,
        password: Option<&str>,
    ) -> Result<Vec<u8>, VoucherCoreError> {
        match self.et {
            EncryptionType::Asymmetric => {
                // JWE format for asymmetric encryption
                let recipient_x25519_sk = ed25519_sk_to_x25519_sk(&recipient_identity.signing_key);

                // Decode protected header and extract epk
                if self.protected.is_empty() {
                    return Err(VoucherCoreError::Crypto("Protected header is required for asymmetric encryption".to_string()));
                }

                let protected_bytes = decode_base64(&self.protected)?;
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

                for recipient in &self.recipients {
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

                        if let Ok(payload_key_bytes) = decrypt_data(&kek, &encrypted_payload_key)
                            && let Ok(key_array) = payload_key_bytes.try_into() {
                                decrypted_payload_key = Some(key_array);
                                break;
                            }
                    }
                }

                let mut payload_key = decrypted_payload_key
                    .ok_or(VoucherCoreError::NotAnIntendedRecipient)?;

                // Decode ciphertext and tag
                let iv = decode_base64(&self.iv)?;
                let ciphertext = decode_base64(&self.ciphertext)?;
                let tag = decode_base64(&self.tag)?;

                // Use protected header as AAD
                let aad = self.protected.as_bytes();

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
                let password = password.ok_or(VoucherCoreError::PasswordRequired)?;
                let salt_b64 = self.salt.as_ref().ok_or_else(|| {
                    VoucherCoreError::Crypto("Salt missing for symmetric encryption".to_string())
                })?;
                let salt = decode_base64(salt_b64)?;
                let salt_array: [u8; 16] = salt.try_into().map_err(|_| {
                    VoucherCoreError::Crypto("Invalid salt length (expected 16 bytes)".to_string())
                })?;

                let encrypted_payload = decode_base64(&self.ciphertext)?;
                decrypt_symmetric_password(&encrypted_payload, password, &salt_array)
            }
            EncryptionType::None => {
                // No encryption (simply base64-decode)
                decode_base64(&self.ciphertext)
            }
        }
    }
}

/// Derives a Key-Encryption-Key (KEK) from a shared secret via HKDF.
fn derive_kek(shared_secret: &[u8]) -> Result<[u8; 32], VoucherCoreError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut kek = [0u8; 32];
    hkdf.expand(b"secure-container-kek", &mut kek)
        .map_err(|e| VoucherCoreError::KeyDerivationError(e.to_string()))?;
    Ok(kek)
}

/// Implements `Drop` to securely zeroize sensitive fields in `SecureContainer`.
///
/// Coverage note (HMSEC-SA05-06): besides the JWE transport fields, every
/// per-recipient wrapped payload key (`encrypted_key`) and the symmetric KDF
/// salt are sensitive key-material remnants and MUST be cleared as well —
/// recovering a wrapped payload key from stale heap memory defeats the
/// forward-secrecy design of the ephemeral key wrapping.
///
/// Known limitation (defense-in-depth): JSON header structures
/// (`unprotected`, `JweRecipient::header`) may carry identifiers but cannot be
/// reliably zeroized (nested Strings inside `serde_json::Value`); they are
/// released by setting them to `None`. String zeroization also cannot cover
/// reallocated copies — this is in-place hygiene, not an allocator strategy.
impl Drop for SecureContainer {
    fn drop(&mut self) {
        self.protected.zeroize();
        self.iv.zeroize();
        self.ciphertext.zeroize();
        self.tag.zeroize();
        self.signature.zeroize();
        // Wrapped per-recipient payload keys: the most sensitive remnants.
        for recipient in &mut self.recipients {
            recipient.encrypted_key.zeroize();
        }
        // Symmetric-mode PBKDF2 salt.
        if let Some(salt) = self.salt.as_mut() {
            salt.zeroize();
        }
        // Release identifier-bearing JSON headers (cannot be byte-zeroized).
        self.unprotected = None;
        for recipient in &mut self.recipients {
            recipient.header = None;
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_container_drop() {
        // We just ensure that drop doesn't panic.
        // Verifying actual zeroization requires unsafe memory inspection which is beyond unit tests.
        let container = SecureContainer::default();
        drop(container);
    }

    #[test]
    fn test_payload_type_to_didcomm_uri() {
        let base = "https://github.com/minutogit/human-money-core/tree/main/protocols";
        assert_eq!(
            PayloadType::TransactionBundle.to_didcomm_uri(),
            format!("{}/transfer/1.0/bundle.md", base)
        );
        assert_eq!(
            PayloadType::VoucherForSigning.to_didcomm_uri(),
            format!("{}/signing/1.0/request.md", base)
        );
        assert_eq!(
            PayloadType::DetachedSignature.to_didcomm_uri(),
            format!("{}/signing/1.0/response.md", base)
        );
        assert_eq!(
            PayloadType::ProofOfDoubleSpend.to_didcomm_uri(),
            format!("{}/conflict/1.0/proof.md", base)
        );
        assert_eq!(
            PayloadType::TrustAssertion.to_didcomm_uri(),
            format!("{}/trust/1.0/assertion.md", base)
        );
        assert_eq!(
            PayloadType::VoucherStandardDefinition.to_didcomm_uri(),
            format!("{}/standard/1.0/definition.md", base)
        );
        assert_eq!(
            PayloadType::Generic("custom".to_string()).to_didcomm_uri(),
            format!("{}/generic/1.0/custom.md", base)
        );
    }

    #[test]
    fn test_container_config_serialization() {
        // This test ensures that the JSON structure of ContainerConfig
        // (especially TargetDid) remains stable and matches the expectations
        // of the frontend (arrays for tuple variants).
        
        let did = "did:key:z6MkiaMJCkd36qJ3FMgfqj9PFDsAqVF3aY8mEaa4t46Yr9Px";
        let config = ContainerConfig::TargetDid(did.to_string(), PrivacyMode::TrialDecryption);
        
        let json = serde_json::to_string(&config).unwrap();
        
        // Expected format with #[serde(tag = "type", content = "value")] and tuple variant:
        // value must be an array.
        assert!(json.contains("\"type\":\"TargetDid\""));
        assert!(json.contains(&format!("\"value\":[\"{}\",\"TrialDecryption\"]", did)));
        
        // Cross-check: Deserialization of manual JSON (as received from TS)
        let ts_json = format!(r#"{{"type": "TargetDid", "value": ["{}", "TrialDecryption"]}}"#, did);
        let deserialized: ContainerConfig = serde_json::from_str(&ts_json).expect("TS JSON should be valid");
        
        match deserialized {
            ContainerConfig::TargetDid(d, m) => {
                assert_eq!(d, did);
                assert_eq!(m, PrivacyMode::TrialDecryption);
            },
            _ => panic!("Wrong variant deserialized"),
        }
    }
}

