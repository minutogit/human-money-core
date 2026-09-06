//! # src/models/secure_container.rs
//!
//! Defines the data structure for an anonymized, signed, and multi-recipient
//! encrypted data container. This container serves as a universal and secure
//! transport medium for arbitrary data between users.

use serde::{Deserialize, Serialize};
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

impl Default for SecureContainer {
    fn default() -> Self {
        Self {
            protected: String::new(),
            unprotected: None,
            recipients: Vec::new(),
            iv: String::new(),
            ciphertext: String::new(),
            tag: String::new(),
            signature: String::new(),
            et: EncryptionType::default(),
            salt: None,
            i: String::new(),
            c: PayloadType::default(),
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

