//! # src/models/secure_container.rs
//!
//! Definiert die Datenstruktur für einen anonymisierten, signierten und für
//! mehrere Empfänger verschlüsselten Daten-Container. Dieser Container dient als
//! universelles und sicheres Transportmittel für beliebige Daten zwischen Nutzern.

use serde::{Serialize, Deserialize};
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
    /// Ein generischer Typ für zukünftige, noch nicht definierte Anwendungsfälle.
    Generic(String),
}

impl Default for PayloadType {
    /// Der Standard-Payload ist ein `TransactionBundle`, da dies der häufigste Anwendungsfall ist.
    fn default() -> Self {
        PayloadType::TransactionBundle
    }
}

/// Enthält einen verschlüsselten Payload-Schlüssel für einen Empfänger oder den Sender.
///
/// - `r`: Wrapped key für einen Empfänger (`recipient`).
/// - `s`: Wrapped key für den Sender (`sender`) für permanenten Zugriff.
/// - `m`: Ein "Matcher" oder Identifikator (Hash der User-ID des Empfängers), damit
///        dieser seinen Schlüssel schnell finden kann, ohne alle entschlüsseln zu müssen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default, Zeroize)]
#[zeroize(drop)]
pub struct WrappedKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub m: Option<String>,
}

/// Repräsentiert einen anonymen, sicheren Container für den Datenaustausch.
///
/// Die Struktur implementiert Forward Secrecy durch ephemere Schlüssel (`esk`) und
/// Anonymität, indem keine direkten Identifikatoren im Container-Header enthalten sind.
/// Alle binären Daten werden als Base64-Strings kodiert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SecureContainer {
    /// `id`: Eine eindeutige ID für diesen Container, generiert aus dem Hash seines Inhalts.
    pub i: String,
    /// `content_type`: Gibt an, welche Art von Daten im `encrypted_payload` (`p`) enthalten ist.
    pub c: PayloadType,
    /// `ephemeral_key`: Der öffentliche Teil des ephemeren Diffie-Hellman-Schlüssels (X25519).
    pub esk: String,
    /// `wrapped_keys`: Eine Liste von verschlüsselten Payload-Schlüsseln.
    pub wk: Vec<WrappedKey>,
    /// `payload`: Die verschlüsselten Nutzdaten als Base64-String.
    pub p: String,
    /// `tag`: Die digitale Signatur des Senders (Ed25519), die die `id` (`i`) unterzeichnet
    /// und somit die Authentizität und Integrität des gesamten Containers sicherstellt.
    pub t: String,
}

/// Implementiert `Drop`, um sensible Felder im `SecureContainer` sicher zu löschen.
impl Drop for SecureContainer {
    fn drop(&mut self) {
        self.esk.zeroize();
        self.wk.zeroize();
        self.p.zeroize();
        self.t.zeroize();
    }
}