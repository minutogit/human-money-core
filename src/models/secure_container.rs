//! # src/models/secure_container.rs
//!
//! Definiert die Datenstruktur für einen anonymisierten, signierten und für
//! mehrere Empfänger verschlüsselten Daten-Container. Dieser Container dient als
//! universelles und sicheres Transportmittel für beliebige Daten zwischen Nutzern.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Definiert die Art des Inhalts, der im `SecureContainer` transportiert wird.
///
/// Die Verwendung eines Enums anstelle eines reinen Strings erhöht die Typsicherheit
/// und macht die Absicht des Senders im Code explizit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum PayloadType {
    /// Der Payload ist ein `TransactionBundle` für eine Gutschein-Transaktion.
    TransactionBundle,
    /// Der Payload ist ein `Voucher`, der einem Bürgen zur Signierung vorgelegt wird.
    VoucherForSigning,
    /// Der Payload ist eine `DetachedSignature`-Antwort im Signatur-Workflow.
    DetachedSignature,
    /// Der Payload ist eine `TrustAssertion` für das Web-of-Trust.
    TrustAssertion,
    /// Der Payload ist ein `ProofOfDoubleSpend` (Betrugsbeweis).
    ProofOfDoubleSpend,
    /// Ein generischer Typ für zukünftige, noch nicht definierte Anwendungsfälle.
    Generic(String),
}

impl Default for PayloadType {
    /// Der Standard-Payload ist ein `TransactionBundle`, da dies der häufigste Anwendungsfall ist.
    fn default() -> Self {
        PayloadType::TransactionBundle
    }
}

impl PayloadType {
    /// Mappt den internen Payload-Typen auf eine standardisierte DIDComm-URI.
    ///
    /// Diese URIs werden im JWE-Header als `typ`-Feld verwendet, um die Art des
    /// Inhalts standardkonform zu kennzeichnen (DIDComm V2-Kompatibilität).
    pub fn to_didcomm_uri(&self) -> String {
        let base_url = "https://github.com/minutogit/human-money-core/tree/main/protocols";
        match self {
            PayloadType::TransactionBundle => format!("{}/transfer/1.0/bundle.md", base_url),
            PayloadType::VoucherForSigning => format!("{}/signing/1.0/request.md", base_url),
            PayloadType::DetachedSignature => format!("{}/signing/1.0/response.md", base_url),
            PayloadType::ProofOfDoubleSpend => format!("{}/conflict/1.0/proof.md", base_url),
            PayloadType::TrustAssertion => format!("{}/trust/1.0/assertion.md", base_url),
            PayloadType::Generic(s) => format!("{}/generic/1.0/{}.md", base_url, s),
        }
    }
}

/// Definiert die Art der Verschlüsselung für den Container.
///
/// Durch das `Default` Trait wird Abwärtskompatibilität gewährleistet:
/// Alte Container ohne das `et` Feld werden automatisch als `Asymmetric` geparst.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum EncryptionType {
    /// Standard: Verschlüsselt mit ephemeral key und DID(s) des Empfängers (asymmetrisch).
    Asymmetric,
    /// Verschlüsselt mit einem Einweg-Passwort/PIN via PBKDF2 (symmetrisch).
    Symmetric,
    /// Unverschlüsselt (Klartext, nur für Signaturanfragen und andere nicht-finanzielle Payloads!).
    None,
}

impl Default for EncryptionType {
    /// Der Standard ist `Asymmetric`, um Abwärtskompatibilität zu gewährleisten.
    fn default() -> Self {
        EncryptionType::Asymmetric
    }
}

/// Definiert den Privatsphäre-Modus für die asymmetrische Verschlüsselung.
///
/// Dieser Modus bestimmt, ob und wie die Empfänger-ID im JWE-Header
/// (kid-Feld) hinterlegt wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub enum PrivacyMode {
    /// Maximale Privatsphäre: JWE-Header bleibt leer. Empfänger nutzen Trial Decryption.
    #[default]
    TrialDecryption,
    /// Verdecktes Routing: Die ID wird gehasht im `kid`-Feld hinterlegt (erlaubt schnelles Finden ohne ID-Klartext).
    HashedRouting,
    /// Offenes Routing: Die did:key wird im Klartext im `kid`-Feld hinterlegt (maximale Transparenz/für einfaches Offline-Routing).
    CleartextRouting,
}

/// Konfiguration für die Container-Verschlüsselung.
///
/// Dieses Enum wird verwendet, um die Art der Verschlüsselung beim Erstellen
/// eines SecureContainer zu konfigurieren. Es wird direkt durch die API-Schichten
/// bis in die Wallet-Ebene durchgereicht.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum ContainerConfig {
    /// Asymmetrische Verschlüsselung mit einer einzelnen DID und PrivacyMode.
    TargetDid(String, PrivacyMode),
    /// Asymmetrische Verschlüsselung mit mehreren DIDs und PrivacyMode.
    TargetDids(Vec<String>, PrivacyMode),
    /// Symmetrische Verschlüsselung mit einem Passwort/PIN.
    Password(String),
    /// Keine Verschlüsselung (Klartext, nur für nicht-finanzielle Payloads!).
    Cleartext,
}

/// JWE-Empfänger-Struktur (RFC 7516).
///
/// Enthält die für einen spezifischen Empfänger verschlüsselten Daten.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct JweRecipient {
    /// Optionale Header pro Empfänger (z.B. 'kid' = did:key des Empfängers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,

    /// Base64url-encodierter, verschlüsselter Payload-Key.
    pub encrypted_key: String,
}

/// RFC 7516 JSON Web Encryption (JWE) General Serialization.
///
/// Diese Struktur implementiert den JWE-Standard für verschlüsselte Container.
/// Sie ersetzt das proprietäre Format und ist DIDComm V2-kompatibel.
///
/// Die Struktur implementiert Forward Secrecy durch ephemere Schlüssel im
/// Protected Header und unterstützt mehrere Empfänger über das recipients-Array.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SecureContainer {
    /// Base64url-encodierter Protected Header als String.
    /// Muss mindestens 'alg', 'enc', 'typ' und 'epk' (Ephemeral Public Key) enthalten.
    pub protected: String,

    /// Unprotected Header (optional). Kann z.B. für Sender-IDs genutzt werden,
    /// falls diese nicht verschlüsselt oder signiert sein müssen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unprotected: Option<serde_json::Value>,

    /// Array der Empfänger mit ihren spezifisch verschlüsselten Payload-Keys.
    pub recipients: Vec<JweRecipient>,

    /// Base64url-encodierter Initialization Vector (Nonce für ChaCha20-Poly1305).
    pub iv: String,

    /// Base64url-encodierter Ciphertext (die verschlüsselten Nutzdaten).
    pub ciphertext: String,

    /// Base64url-encodiertes Authentication Tag (von ChaCha20-Poly1305).
    pub tag: String,

    /// Die digitale Signatur des Senders (Ed25519), die den Container-Hash unterzeichnet
    /// und somit die Authentizität und Integrität des gesamten Containers sicherstellt.
    /// Dieses Feld ist NICHT Teil des JWE-Standards, wird aber für die Container-Signatur verwendet.
    pub signature: String,

    /// `encryption_type`: Konfiguration der Verschlüsselung (Asymmetric, Symmetric, None).
    /// Für JWE ist dies implizit durch das Vorhandensein von recipients festgelegt,
    /// wird aber für interne Logik beibehalten.
    #[serde(default)]
    pub et: EncryptionType,

    /// `salt`: Salt für die PBKDF2 Ableitung (nur bei Symmetric gesetzt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,

    /// `id`: Eine eindeutige ID für diesen Container, generiert aus dem Hash seines Inhalts.
    /// Dieses Feld ist NICHT Teil des JWE-Standards, wird aber für Container-Identifikation verwendet.
    pub i: String,

    /// `content_type`: Gibt an, welche Art von Daten im Payload enthalten ist.
    /// Dieses Feld ist NICHT Teil des JWE-Standards (steht im protected Header als 'typ'),
    /// wird aber für interne Logik beibehalten.
    pub c: PayloadType,
}

/// Implementiert `Drop`, um sensible Felder im `SecureContainer` sicher zu löschen.
impl Drop for SecureContainer {
    fn drop(&mut self) {
        self.protected.zeroize();
        self.iv.zeroize();
        self.ciphertext.zeroize();
        self.tag.zeroize();
        self.signature.zeroize();
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
            PayloadType::Generic("custom".to_string()).to_didcomm_uri(),
            format!("{}/generic/1.0/custom.md", base)
        );
    }

    #[test]
    fn test_container_config_serialization() {
        // Dieser Test stellt sicher, dass die JSON-Struktur von ContainerConfig
        // (insbesondere TargetDid) stabil bleibt und mit den Erwartungen des
        // Frontends (Arrays für Tupel-Variants) übereinstimmt.
        
        let did = "did:key:z6MkiaMJCkd36qJ3FMgfqj9PFDsAqVF3aY8mEaa4t46Yr9Px";
        let config = ContainerConfig::TargetDid(did.to_string(), PrivacyMode::TrialDecryption);
        
        let json = serde_json::to_string(&config).unwrap();
        
        // Erwartetes Format bei #[serde(tag = "type", content = "value")] und Tupel-Variant:
        // value muss ein Array sein.
        assert!(json.contains("\"type\":\"TargetDid\""));
        assert!(json.contains(&format!("\"value\":[\"{}\",\"TrialDecryption\"]", did)));
        
        // Gegenprobe: Deserialisierung von manuellem JSON (wie es vom TS kommt)
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

