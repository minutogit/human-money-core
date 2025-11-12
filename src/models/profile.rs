//! # src/models/profile.rs
//!
//! Definiert die Datenstrukturen für ein vollständiges Nutzerprofil,
//! inklusive Identität, Gutschein-Bestand und einer Historie von Transaktionsbündeln.
//! Diese Strukturen sind für die Verwaltung der "Wallet" eines Nutzers zuständig.

use crate::models::voucher::Voucher;
use crate::models::voucher::Address; // Importiert die Address-Struktur
use crate::models::conflict::TransactionFingerprint;
use crate::wallet::instance::VoucherInstance;
use ed25519_dalek::{SigningKey, VerifyingKey as EdPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap};
use zeroize::ZeroizeOnDrop;

/// Repräsentiert die kryptographische Identität eines Nutzers.
/// Der private Schlüssel wird sicher im Speicher gehalten und beim Verlassen des Gültigkeitsbereichs genullt.
#[derive(ZeroizeOnDrop)]
#[derive(Clone)]
pub struct UserIdentity {
    /// Der private Ed25519-Schlüssel des Nutzers.
    /// **Wichtig:** Dieser Schlüssel wird nicht serialisiert und verlässt niemals das Profil.
    /// `ed25519_dalek::SigningKey` implementiert `ZeroizeOnDrop` bereits von Haus aus.
    pub signing_key: SigningKey,
    /// Der öffentliche Ed25519-Schlüssel, abgeleitet vom privaten Schlüssel.
    #[zeroize(skip)]
    pub public_key: EdPublicKey,
    /// Die öffentliche, teilbare User-ID, generiert aus dem Public Key.
    #[zeroize(skip)]
    pub user_id: String,
}

/// Ein Enum, das die Richtung einer Transaktion aus der Perspektive des Profilinhabers angibt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TransactionDirection {
    Sent,
    Received,
}

impl Default for TransactionDirection {
    fn default() -> Self {
        TransactionDirection::Sent
    }
}


/// Eine leichtgewichtige Zusammenfassung eines `TransactionBundle` für die Anzeige in einer Historie.
/// Enthält alle Metadaten, aber anstelle der vollständigen Gutscheine nur deren IDs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransactionBundleHeader {
    /// Die eindeutige ID des zugehörigen Bündels.
    pub bundle_id: String,
    /// Die User-ID des Senders.
    pub sender_id: String,
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste der IDs der in diesem Bündel übertragenen Gutscheine.
    pub voucher_ids: Vec<String>,
    /// Der Zeitstempel der Bündel-Erstellung im ISO 8601-Format.
    pub timestamp: String,
    /// Eine optionale, vom Sender hinzugefügte Notiz.
    pub notes: Option<String>,
    /// Die digitale Signatur des Senders, die die Authentizität des Bündels bestätigt.
    pub sender_signature: String,
    /// Gibt an, ob das Bündel gesendet oder empfangen wurde.
    pub direction: TransactionDirection,
    /// Optionaler Profilname des Senders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

/// Repräsentiert ein vollständiges, signiertes Bündel für einen Austausch von Gutscheinen.
/// Dies ist die atomare Einheit, die zwischen Nutzern ausgetauscht wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransactionBundle {
    /// Eine eindeutige ID für dieses Bündel, generiert aus dem Hash seines Inhalts (ohne Signatur).
    pub bundle_id: String,
    /// Die User-ID des Senders.
    pub sender_id: String,
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste der vollständigen `Voucher`-Objekte, die übertragen werden.
    pub vouchers: Vec<Voucher>,
    /// Der Zeitstempel der Bündel-Erstellung im ISO 8601-Format.
    pub timestamp: String,
    /// Eine optionale, für den Empfänger sichtbare Notiz.
    pub notes: Option<String>,
    /// Die digitale Signatur des Senders, die die `bundle_id` unterzeichnet und somit das
    /// gesamte Bündel fälschungssicher macht.
    pub sender_signature: String,

    /// NEU: Die Liste der weitergeleiteten Fingerprints zur Unterstützung der Double-Spend-Erkennung.
    #[serde(default)]
    pub forwarded_fingerprints: Vec<TransactionFingerprint>,

    /// NEU: Die zugehörigen 'depth'-Werte für die weitergeleiteten Fingerprints.
    /// Key: prvhash_senderid_hash des Fingerprints.
    #[serde(default)]
    pub fingerprint_depths: HashMap<String, u8>,

    /// Optionaler Profilname des Senders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

impl TransactionBundle {
    /// Erstellt einen `TransactionBundleHeader` aus einem `TransactionBundle`.
    pub fn to_header(&self, direction: TransactionDirection) -> TransactionBundleHeader {
        TransactionBundleHeader {
            bundle_id: self.bundle_id.clone(),
            sender_id: self.sender_id.clone(),
            recipient_id: self.recipient_id.clone(),
            voucher_ids: self.vouchers.iter().map(|v| v.voucher_id.clone()).collect(),
            timestamp: self.timestamp.clone(),
            notes: self.notes.clone(),
            sender_signature: self.sender_signature.clone(),
            direction,
            sender_profile_name: self.sender_profile_name.clone(),
        }
    }
}

/// Repräsentiert den persistenten Speicher für alle Gutscheine eines Nutzers.
/// Diese Struktur wird separat vom `UserProfile` gehalten, um die Metadaten
/// leichtgewichtig zu halten und die Gutscheinsammlung effizient zu verwalten.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VoucherStore {
    /// Der Bestand an Gutscheinen, indiziert nach ihrer lokalen Instanz-ID (`local_voucher_instance_id`).
    pub vouchers: HashMap<String, VoucherInstance>,
}

/// Repräsentiert den persistenten Speicher für die Metadaten von Transaktionsbündeln.
/// Diese Struktur wird separat vom `UserProfile` in einer eigenen verschlüsselten Datei gehalten.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BundleMetadataStore {
    /// Eine Historie aller gesendeten und empfangenen Transaktionsbündel,
    /// indiziert nach der `bundle_id`.
    pub history: HashMap<String, TransactionBundleHeader>,
}

/// Ein standardisiertes öffentliches Profil, das in Signaturen und
/// im Creator-Feld wiederverwendet werden kann.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct PublicProfile {
    /// Die User-ID (did:key) des Profilinhabers.
    /// Optional, da es oft redundant zur übergeordneten ID (z.B. signer_id) ist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,

    /// Geschlecht des Erstellers ISO 5218 (1 = male, 2 = female, 0 = not known, 9 = Not applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,

    /// Geografische Koordinaten (z.B. "Breitengrad, Längengrad").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Eine textuelle Beschreibung der angebotenen Dienstleistungen oder Waren.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_offer: Option<String>,

    /// Eine textuelle Beschreibung der gesuchten Dienstleistungen oder Waren.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
}

/// Die Hauptstruktur, die den gesamten Zustand eines Nutzer-Wallets repräsentiert.
/// Sie enthält die Identität, den Bestand an Gutscheinen und die Transaktionshistorie.
/// Diese Struktur wird serialisiert und verschlüsselt auf der Festplatte gespeichert.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserProfile {
    /// Die öffentliche User-ID. Wird aus `identity` abgeleitet und hier für einfachen Zugriff dupliziert.
    pub user_id: String,
    // HINZUFÜGEN: Felder für die Profil-Details
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coordinates: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_offer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<String>,
}

// Implementiere `Default` für UserProfile, um eine leere Instanz zu erzeugen, die dann gefüllt wird.
// Die `identity` wird nach der Erstellung separat hinzugefügt.
impl Default for UserProfile {
    fn default() -> Self {
        Self { 
            user_id: String::new(),
            first_name: None,
            last_name: None,
            organization: None,
            community: None,
            address: None,
            gender: None,
            email: None,
            phone: None,
            coordinates: None,
            url: None,
            service_offer: None,
            needs: None,
        }
    }
}