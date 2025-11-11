//! # voucher.rs
//!
//! Definiert die Kern-Datenstrukturen für das universelle Gutschein-Container-Format.
//! Diese Strukturen bilden das im `llm-context.md` definierte JSON-Schema exakt ab
//! und verwenden `serde` für die Serialisierung und Deserialisierung.

use crate::models::profile::PublicProfile;
use serde::{Serialize, Deserialize};

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

/// Definiert den Nennwert, den ein Gutschein repräsentiert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct NominalValue {
    /// Die Einheit des Gutscheinwerts (z.B. "Minuten", "Unzen").
    pub unit: String,
    /// Die genaue Menge des Werts, als String für maximale Flexibilität.
    pub amount: String,
    /// Eine gängige Abkürzung der Einheit (z.B. "m", "oz").
    pub abbreviation: String,
    /// Eine Beschreibung des Werts (z.B. "Objektive Zeit").
    pub description: String,
}

/// Enthält Informationen zur Besicherung des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Collateral {
    /// Die Art der Besicherung (z.B. "Physisches Edelmetall").
    #[serde(rename = "type")]
    pub type_: String,
    /// Die Einheit der Besicherung (z.B. "Unzen").
    pub unit: String,
    /// Die Menge der Besicherung.
    pub amount: String,
    /// Eine gängige Abkürzung für die Besicherungseinheit.
    pub abbreviation: String,
    /// Eine detailliertere Beschreibung der Besicherung.
    pub description: String,
    /// **Extrem wichtig:** Bedingungen, unter denen die Besicherung eingelöst werden kann.
    pub redeem_condition: String,
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

/// Repräsentiert eine einzelne Transaktion in der Transaktionskette des Gutscheins.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    /// Eindeutige ID der Transaktion.
    pub t_id: String,
    /// Art der Transaktion. Leer für einen vollen Transfer, "init" für die Erstellung, "split" für Teilbeträge.
    /// Das Feld wird bei der Serialisierung weggelassen, wenn es leer ist.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t_type: String,
    /// Zeitpunkt der Transaktion im ISO 8601-Format.
    pub t_time: String,
    /// ID des Senders der Transaktion.
    pub sender_id: String,
    /// ID des Empfängers der Transaktion.
    pub recipient_id: String,
    /// Der Betrag, der bei dieser Transaktion bewegt wurde.
    pub amount: String,
    /// Der Restbetrag beim Sender nach einer Teilung. Nur bei `t_type: "split"` vorhanden.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_remaining_amount: Option<String>,
    /// Digitale Signatur des Senders für diese Transaktion.
    pub sender_signature: String,
    /// Der Hash der vorhergehenden Transaktion oder der voucher_id für die init-Transaktion.
    pub prev_hash: String,
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
    pub divisible: bool,
    /// Die bei der Erstellung gültige Mindestgültigkeitsdauer aus dem Standard (ISO 8601 Duration).
    pub standard_minimum_issuance_validity: String,
    /// Eine menschenlesbare Beschreibung der Signaturanforderungen (früher Bürgenanforderungen), übernommen vom Standard.
    pub signature_requirements_description: String,
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
    pub nominal_value: NominalValue,
    /// Informationen zur Besicherung des Gutscheins.
    pub collateral: Collateral,
    /// Detaillierte Informationen zum Ersteller des Gutscheins.
    #[serde(rename = "creator")]
    pub creator_profile: PublicProfile,
    /// Eine chronologische Liste aller Transaktionen dieses Gutscheins.
    pub transactions: Vec<Transaction>,
    /// Ein Array für alle Signaturen (inkl. Bürgen).
    pub signatures: Vec<VoucherSignature>,
}