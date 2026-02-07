//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für die Gutschein-Standards.
//! Diese Struktur trennt klar zwischen Metadaten, Kopiervorlagen und Validierungsregeln
//! und fügt die Unterstützung für kryptographische Signaturen und Mehrsprachigkeit hinzu.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Bestehende Strukturen (unverändert) ---

/// Repräsentiert einen einzelnen, sprachabhängigen Text.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct LocalizedText {
    pub lang: String,
    pub text: String,
}

/// Metadaten, die den Standard selbst beschreiben, inklusive optionaler Felder.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct StandardMetadata {
    pub uuid: String,
    pub name: String,
    pub abbreviation: String,
    pub issuer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// Vorlage für den Nennwert (nur die Einheit wird vom Standard vorgegeben).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateNominalValue {
    pub unit: String,
}

/// Vorlage für die Besicherung.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateCollateral {
    #[serde(rename = "type")]
    pub type_: String,
    pub description: String,
    pub redeem_condition: String,
}

/// Vorlage für die Bürgen-Informationen, die in den Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateGuarantorInfo {
    pub needed_count: i64,
    pub description: String,
}

/// Enthält alle Werte, die vom Standard zwingend und unveränderlich vorgegeben werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateFixed {
    // Mehrsprachige Beschreibung wird jetzt als Liste von Tabellen im TOML abgebildet.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<LocalizedText>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub footnote: Option<String>,
    pub primary_redemption_type: String,
    pub is_summable: bool,
    pub is_divisible: bool,
    pub nominal_value: TemplateNominalValue,
    pub collateral: TemplateCollateral,
    pub guarantor_info: TemplateGuarantorInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
}

/// Enthält alle Werte, die als Vorschläge dienen und überschrieben werden können.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TemplateDefault {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
}

/// Eine Vorlage für Felder, die in einen neuen Gutschein kopiert werden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherTemplate {
    pub fixed: TemplateFixed,
    #[serde(default)]
    pub default: TemplateDefault,
}

/// Enthält die kryptographische Signatur, die die Authentizität des Standards beweist.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignatureBlock {
    /// Die `did:key` des Herausgebers.
    pub issuer_id: String,
    /// Die Base58-kodierte Ed25519-Signatur.
    pub signature: String,
}

// --- Neue, erweiterte Validierungs-Strukturen ---

/// Definiert Min/Max-Grenzen für quantitative Prüfungen.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MinMax {
    pub min: u32,
    pub max: u32,
}

/// Bündelt alle Regeln zur Zählung von Elementen (z.B. Signaturen, Transaktionen).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct CountRules {
    pub transactions: Option<MinMax>,
}

/// Definiert eine Regel für eine erforderliche Signatur.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RequiredSignatureRule {
    pub role_description: String,
    pub allowed_signer_ids: Vec<String>,
    /// Die Rolle (z.B. "guarantor"), die diese Signatur haben muss.
    pub required_role: String,
    pub is_mandatory: bool,
}

/// Bündelt alle Regeln, die den Inhalt von Feldern im Gutschein betreffen.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct ContentRules {
    /// Key ist der JSON-Pfad, z.B. "nominal_value.unit"
    pub fixed_fields: Option<HashMap<String, serde_json::Value>>,
    pub allowed_values: Option<HashMap<String, Vec<serde_json::Value>>>,
    pub regex_patterns: Option<HashMap<String, String>>,
}

/// Bündelt alle Regeln, die das Verhalten und die Aktionen des Gutscheins steuern.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct BehaviorRules {
    pub allowed_t_types: Option<Vec<String>>,
    pub max_creation_validity_duration: Option<String>,
    pub issuance_minimum_validity_duration: Option<String>,
    pub amount_decimal_places: Option<u8>,
}

/// Definiert die exakte Anzahl für einen bestimmten Wert in einer Gruppenprüfung.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ValueCountRule {
    /// Der Wert, der gezählt werden soll (als String, da aus JSON kommend).
    pub value: String,
    /// Die minimale Anzahl, die erwartet wird.
    pub min: u32,
    /// Die maximale Anzahl, die erwartet wird.
    pub max: u32,
}

/// Definiert eine Regel für eine Gruppe von Feldern in einer Objektliste.
/// Beispiel: "Prüfe das 'gender'-Feld in allen 'guarantor_signatures'".
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FieldGroupRule {
    /// Das zu prüfende Feld innerhalb jedes Objekts der Liste (z.B. "gender").
    pub field: String,
    /// Eine Liste von Regeln, die die Häufigkeit bestimmter Werte vorschreiben.
    pub value_counts: Vec<ValueCountRule>,
}

/// Die Hauptstruktur für alle Validierungsregeln.
/// Alle Felder sind optional, um eine flexible Definition zu ermöglichen.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct Validation {
    pub counts: Option<CountRules>,
    pub required_signatures: Option<Vec<RequiredSignatureRule>>,
    pub content_rules: Option<ContentRules>,
    pub behavior_rules: Option<BehaviorRules>,
    pub field_group_rules: Option<HashMap<String, FieldGroupRule>>,
}

/// Konfiguration für die Privatsphäre-Modi.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct PrivacySettings {
    /// Der Modus: "public", "stealth" oder "flexible".
    pub mode: String,
}

// --- Haupt-Struct ---

/// Das Haupt-Struct, das die gesamte, nun signierte Standard-Definition kapselt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandardDefinition {
    pub metadata: StandardMetadata,
    pub template: VoucherTemplate,
    // Ersetzt die alte `ValidationRules` durch die flexible Struktur.
    pub validation: Option<Validation>,
    /// Die Konfiguration der Privatsphäre-Modi.
    #[serde(default)]
    pub privacy: Option<PrivacySettings>,
    // Die Signatur ist optional, da sie für die Kanonisierung temporär entfernt wird.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}
