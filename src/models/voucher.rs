//! # voucher.rs
//!
//! Definiert die Kern-Datenstrukturen für das universelle Gutschein-Container-Format.
//! Diese Strukturen bilden das im `llm-context.md` definierte JSON-Schema exakt ab
//! und verwenden `serde` für die Serialisierung und Deserialisierung.

use crate::models::profile::PublicProfile;
use serde::{Deserialize, Serialize};

/// Definiert den Standard, zu dem ein Gutschein gehört.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandard {
    /// Der Name des Standards (z.B. "Minuto-Gutschein").
    pub name: String,
    /// Die eindeutige Kennung (UUID) des Standards.
    pub uuid: String,
    /// Der Hash der kanonisierten Standard-Definition, der diesen Gutschein an eine spezifische Version bindet.
    pub standard_definition_hash: String,
    /// Die Template-Daten, die aus dem Standard-TOML kopiert wurden.
    pub template: VoucherTemplateData,
}

/// Definiert einen Wert (Betrag und Einheit),
/// der für Nennwerte oder Besicherungen verwendet wird.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ValueDefinition {
    pub unit: String,
    pub amount: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub abbreviation: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Definiert die (optionale) Besicherung eines Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Collateral {
    /// Die Felder 'unit', 'amount', 'abbreviation', 'description'
    /// werden direkt von ValueDefinition hier eingebettet.
    #[serde(flatten)]
    pub value: ValueDefinition,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub collateral_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_condition: Option<String>,
}

/// Detaillierte Adressinformationen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Address {
    /// Straße.
    pub street: String,
    /// Hausnummer.
    pub house_number: String,
    /// Postleitzahl.
    pub zip_code: String,
    /// Stadt.
    pub city: String,
    /// Land.
    pub country: String,
    /// Vollständige, formatierte Adresse.
    pub full_address: String,
}

/// Daten für die Identity-Trap (Betrugserkennung).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TrapData {
    pub ds_tag: String,
    pub u: String,
    pub blinded_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// Der entschlüsselte Payload des Privacy-Guards.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct RecipientPayload {
    /// Die vollständige Composite-DID des Absenders.
    pub sender_permanent_did: String,
    /// Das Ziel-Präfix (z.B. "creator:fY7") zur Validierung.
    pub target_prefix: String,
    /// Zeitstempel der Erstellung.
    pub timestamp: u64,
    /// Der Seed für den nächsten ephemeren Schlüssel.
    pub next_key_seed: String,
}

/// Repräsentiert eine einzelne Transaktion in der Transaktionskette des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    /// Eindeutige ID der Transaktion.
    pub t_id: String,
    /// Art der Transaktion. Leer für einen vollen Transfer, "init" für die Erstellung, "split" für Teilbeträge.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t_type: String,
    /// Zeitpunkt der Transaktion im ISO 8601-Format.
    pub t_time: String,

    // --- TECHNISCHER LAYER (Layer 2 - Immer vorhanden) ---
    /// Der Hash des vorherigen Private-Public-Keys oder Transaktions-Hash.
    pub prev_hash: String,

    /// Der Hash des ephemeren Public Keys des Empfängers (Private Key).
    /// Existiert IMMER, auch wenn recipient_id öffentlich ist.
    /// Option nur für Abwärtskompatibilität bzw. Init-Sonderfälle,
    /// aber im Standard-Flow nun Pflicht.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_ephemeral_pub_hash: Option<String>,

    // --- SOZIALER LAYER (Layer 1 - Abhängig vom Privacy Mode) ---
    /// ID des Senders der Transaktion.
    /// Optional, abhängig vom Privacy Mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,

    /// Die Signatur ausgeführt durch den Identity-Key (sender_id).
    /// Muss vorhanden sein, wenn sender_id gesetzt ist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_identity_signature: Option<String>,

    /// ID des Empfängers der Transaktion.
    /// Kann public (did:key) oder anonymisiert sein.
    pub recipient_id: String,

    /// Der Betrag, der bei dieser Transaktion bewegt wurde.
    pub amount: String,
    /// Der Restbetrag beim Sender nach einer Teilung. Nur bei `t_type: "split"` vorhanden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_remaining_amount: Option<String>,

    // --- Layer 2 & Privacy Fields ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ephemeral_pub: Option<String>, // Der enthüllte Key (Preimage) für L2-Signatur

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ephemeral_pub_hash: Option<String>, // Der Anker-Hash für das Restgeld

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_data: Option<TrapData>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer2_signature: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,
}

/// Repräsentiert eine universelle Signatur (ehemals AdditionalSignature),
/// die an den Gutschein angehängt wird. Sie kann durch das Feld `role` semantisch
/// unterschieden werden (z.B. "guarantor").
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherSignature {
    /// Die eindeutige ID des Gutscheins, auf den sich diese Signatur bezieht.
    pub voucher_id: String,
    /// Die eindeutige ID dieser Signatur.
    pub signature_id: String,
    /// Eindeutige ID des zusätzlichen Unterzeichners.
    pub signer_id: String,

    /// Die digitale Signatur.
    pub signature: String,
    /// Zeitpunkt der Signatur im ISO 8601-Format.
    pub signature_time: String,
    /// Definiert die Rolle oder den Zweck dieser Signatur (z.B. "guarantor", "notary").
    pub role: String,

    /// Optionale, detaillierte Profil-Informationen über den Unterzeichner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<PublicProfile>,
}

/// Definiert die Template-Daten, die aus dem Standard-TOML kopiert wurden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherTemplateData {
    /// Eine allgemeine, menschenlesbare Beschreibung des spezifischen Gutscheins.
    pub description: String,
    /// Der primäre Einlösezweck, übernommen vom Standard (z.B. "goods_or_services").
    pub primary_redemption_type: String,
    /// Gibt an, ob der Gutschein in kleinere Einheiten aufgeteilt werden kann.
    pub allow_partial_transfers: bool,
    /// Die bei der Erstellung gültige Mindestgültigkeitsdauer aus dem Standard (ISO 8601 Duration).
    pub issuance_minimum_validity_duration: String,
    /// Ein optionaler Fußnotentext, der vom Standard vorgegeben wird.
    pub footnote: String,
}

/// Das Haupt-Struct, das den universellen Gutschein-Container repräsentiert.
/// Es fasst alle anderen Strukturen und Felder gemäß dem allgemeinen JSON-Schema zusammen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Voucher {
    /// Definiert den Standard, dem dieser Gutschein folgt.
    pub voucher_standard: VoucherStandard,
    /// Die eindeutige ID dieses spezifischen Gutscheins.
    pub voucher_id: String,
    /// Ein zufälliges Nonce, um den ersten `prev_hash` unvorhersehbar zu machen.
    pub voucher_nonce: String,
    /// Das Erstellungsdatum des Gutscheins im ISO 8601-Format.
    pub creation_date: String,
    /// Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
    pub valid_until: String,
    /// Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt.
    pub non_redeemable_test_voucher: bool,
    /// Definiert den Nennwert des Gutscheins.
    pub nominal_value: ValueDefinition,
    /// Informationen zur Besicherung des Gutscheins.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral: Option<Collateral>,
    /// Detaillierte Informationen zum Ersteller des Gutscheins.
    #[serde(rename = "creator")]
    pub creator_profile: PublicProfile,
    /// Eine chronologische Liste aller Transaktionen dieses Gutscheins.
    pub transactions: Vec<Transaction>,
    /// Ein Array für alle Signaturen (inkl. Bürgen).
    pub signatures: Vec<VoucherSignature>,
}
