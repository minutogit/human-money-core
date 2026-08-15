//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für Gutschein-Standards (`standard.toml`).
//!
//! Ein Gutschein-Standard fungiert als die verfassungsartige Grundlage einer spezifischen
//! Währung oder Verrechnungseinheit. Diese Struktur trennt strikt zwischen unratifizierbaren
//! Konsensregeln (Immutable Zone) und anpassbaren Präsentationsdaten (Mutable Zone).
//!
//! ## Das Zwei-Zonen-Modell
//! - **Immutable Zone (`[immutable]`):** Enthält alle konsensrelevanten Parameter (Identität,
//!   Blueprint, Features, Issuance, CEL-Regeln). Aus dieser Zone wird der deterministische
//!   `logic_hash` (SHA-256) berechnet. Jede Änderung in dieser Zone führt zu einem neuen `logic_hash`
//!   und bricht die Kompatibilität zu bereits erstellten Gutscheinen.
//! - **Mutable Zone (`[mutable]`):** Enthält UI-relevante Metadaten, App-Konfigurationen und
//!   i18n-Übersetzungen. Änderungen hier verändern den `logic_hash` **nicht**, erfordern jedoch
//!   eine Erneuerung der Herausgeber-Signatur im `[signature]`-Block.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Definiert eine dynamische CEL-Regel (Common Expression Language).
///
/// Dynamische Regeln erlauben Deep-Inspection bei der Gutschein-Validierung,
/// die über den deklarativen Fast-Path hinausgeht.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DynamicRule {
    /// Der auszuführende CEL-Ausdruck (z. B. `Transaction.amount <= 5000` oder `Voucher.signatures.exists(...)`).
    pub expression: String,
    /// Die Fehlermeldung, die zurückgegeben wird, wenn der CEL-Ausdruck zu `false` evaluiert.
    pub message: String,
}

/// Enthält die eindeutigen Identitätsmerkmale eines Standards.
///
/// Diese Daten liegen in der Immutable Zone und sind kryptographisch an den `logic_hash` gebunden.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIdentity {
    /// Der ökonomische Anker als UUID v4 (z. B. `"123e4567-e89b-12d3-a456-426614174000"`).
    /// Überlebt Standard-Updates, solange die Währung ökonomisch identisch bleibt.
    pub uuid: String,
    /// Der offizielle Name des Standards (z. B. `"Minuto Regional"`).
    pub name: String,
    /// Das offizielle Währungskürzel (z. B. `"MIN"`). Empfohlen: Max. 5 Zeichen.
    pub abbreviation: String,
}

/// Der primäre Einlösungszweck eines Gutscheins.
///
/// Dient der steuerlichen und juristischen Klassifizierung auf Anwendungsebene.
/// Serde-Serialisierung erfolgt im `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryRedemptionType {
    /// Gegenwerte in Waren oder Dienstleistungen (Standard).
    #[default]
    GoodsOrServices,
    /// Zeitwertbasierte Gutscheine (z. B. Stunden/Minuten Arbeitszeit).
    Time,
    /// Sach- oder Rohstoffbesicherte Gutscheine (z. B. Edelmetalle, Ernteanteile).
    PhysicalAsset,
}

/// Die Art der Besicherung eines Gutscheins.
///
/// Definiert den ökonomischen Schutz- und Vertrauensmechanismus der Währung.
/// Serde-Serialisierung erfolgt im `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CollateralType {
    /// Persönliche Leistungsgarantie und Bürgschaften durch Personen (Standard).
    #[default]
    PersonalGuarantee,
    /// Gedeckt durch Fiat-Geldguthaben.
    FiatBacked,
    /// Gedeckt durch Kryptowährungen oder Smart-Contract-Reserven.
    CryptoBacked,
    /// Gedeckt durch physische Werte oder Vermögensgegenstände.
    PhysicalAsset,
}

/// Der Datenschutz- und Transparenz-Modus für L2-Transaktionen.
///
/// Steuert, wie Transaktionsdaten auf Layer 2 verarbeitet und verschleiert werden dürfen.
/// Serde-Serialisierung erfolgt im `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Transaktionen sind vollständig öffentlich und nachvollziehbar.
    #[default]
    Public,
    /// Transaktionen erzwingen Zero-Knowledge-Proofs / Stealth-Adressen zur Verschleierung.
    Stealth,
    /// Der Absender/Nutzer kann pro Transaktion zwischen öffentlich und verschleiert wählen.
    Flexible,
}

/// Feste Startwerte und Basiseigenschaften für Gutscheine dieses Standards.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableBlueprint {
    /// Die Nennwert-Einheit des Gutscheins (z. B. `"Minuten"`, `"Taler"`).
    pub unit: String,
    /// Der primäre Einlösungszweck (Enum: `goods_or_services`, `time`, `physical_asset`).
    pub primary_redemption_type: PrimaryRedemptionType,
    /// Die Art der Besicherung (Enum: `personal_guarantee`, `fiat_backed`, `crypto_backed`, `physical_asset`).
    pub collateral_type: CollateralType,
}

/// Steuert das funktionale Verhalten und die Einschränkungen in der Wallet-Software.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableFeatures {
    /// Erlaubt Teilübertragungen (`split`). Wenn `false`, kann der Gutschein nur als Ganzes weitergegeben werden.
    pub allow_partial_transfers: bool,
    /// Fungibility and balance aggregation rule: defines whether vouchers of this standard represent
    /// interchangeable/summable currency units (`true`) or distinct non-fungible certificates (`false`).
    /// Directly controls balance and transfer aggregation (`TransferSummary`) in core logic and is therefore
    /// an essential part of the immutable `logic_hash`.
    pub balances_are_summable: bool,
    /// Maximale Anzahl an Nachkommastellen (`0` für Ganzzahlen wie Minuten, `2` für Währungen).
    pub amount_decimal_places: u8,
    /// Transparenz- und Datenschutz-Modus (`public`, `stealth`, `flexible`).
    pub privacy_mode: PrivacyMode,
    /// Erlaubte Transaktions-Typen für Gutscheine dieses Standards (z. B. `["init", "transfer", "split"]`).
    pub allowed_t_types: Vec<String>,
}

/// Regeln zur Erstellung und Ausgabe neuer Gutscheine (Issuance Firewall).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIssuance {
    /// ISO 8601 Zeiträume für erlaubte Gesamtlaufzeiten [Min, Max] (z. B. `["P1Y", "P5Y"]`).
    pub validity_duration_range: Vec<String>,
    /// Zirkulations-Firewall: Erforderliche Restgültigkeit bei Erstellung/Erstausgabe (z. B. `"P1Y"`).
    pub issuance_minimum_validity_duration: String,
    /// Erforderliche Anzahl zusätzlicher Signaturen (z. B. Bürgen, Revisoren, Zeugen) [Min, Max] (z. B. `[2, 2]` oder `[0, 0]`).
    pub additional_signatures_range: Vec<u32>,
    /// Erlaubte Signatur-Rollen für Zusatz-Signaturen (z. B. `["guarantor"]`, `["auditor"]`, `["witness"]`).
    pub allowed_signature_roles: Vec<String>,
}

/// Die unratifizierbare Konsens-Zone (`[immutable]`).
///
/// Alle hier enthaltenen Daten fließen direkt in den deterministischen SHA-256 `logic_hash` ein.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableZone {
    /// Identitätsmerkmale (UUID, Name, Kürzel).
    pub identity: ImmutableIdentity,
    /// Basiskonfiguration und Einlösungsart.
    pub blueprint: ImmutableBlueprint,
    /// Funktionsumfang und Wallet-Einschränkungen.
    pub features: ImmutableFeatures,
    /// Regeln für Gutschein-Erstellung und Mitunterzeichner.
    pub issuance: ImmutableIssuance,
    /// Dynamische CEL-Validierungsregeln für Deep-Inspection.
    #[serde(default)]
    pub custom_rules: HashMap<String, DynamicRule>,
}

/// Metadaten des Herausgebers zur Auffindbarkeit und Dokumentation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableMetadata {
    /// Offizieller Name der ausgebenden Organisation oder Gemeinschaft.
    pub issuer_name: String,
    /// Optionale Webadresse zur Homepage des Standards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    /// Optionale Webadresse zur rechtlichen oder technischen Dokumentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Stichwörter zur Kategorisierung in Standard-Verzeichnissen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// App- und UX-Empfehlungen für Wallet-Clients und L2-Nodes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableAppConfig {
    /// Empfohlener Standardwert für die Gültigkeitsdauer im Erstellungs-Formular (ISO 8601, z. B. `"P5Y"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
    /// UI-Hinweis zur Aufrundung des Ablaufdatums (z. B. `"P1Y"` für Ende des Zieljahres).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
    /// Anforderung an L2-Nodes zur Historien-Aufbewahrung nach Ablauf des Gutscheins (ISO 8601, z. B. `"P6M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_history_retention: Option<String>,
}

/// Mehrsprachige Texte und Beschreibungen (i18n-Autarkie).
///
/// Schlüssel entsprechen den ISO-Sprachcodes (z. B. `"de"`, `"en"`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableI18n {
    /// Haupt-Vertragstexte mit Platzhaltern wie `{{amount}}`.
    #[serde(default)]
    pub descriptions: HashMap<String, String>,
    /// Rechtliche Hinweise oder Kleingedrucktes.
    #[serde(default)]
    pub footnotes: HashMap<String, String>,
    /// Beschreibungen des Besicherungs-Mechanismus.
    #[serde(default)]
    pub collateral_descriptions: HashMap<String, String>,
}

/// Die anpassbare Präsentations-Zone (`[mutable]`).
///
/// Änderungen in dieser Zone verändern den `logic_hash` **nicht**. Sie erlauben es dem Herausgeber,
/// Beschreibungen, Links oder i18n-Texte zu aktualisieren, ohne bestehende Gutscheine zu entwerten.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableZone {
    /// Herausgeber-Metadaten und Links.
    pub metadata: MutableMetadata,
    /// UX-Defaults und L2-Retention-Einstellungen.
    #[serde(default)]
    pub app_config: MutableAppConfig,
    /// Mehrsprachige Vertragstexte und Beschreibungen.
    #[serde(default)]
    pub i18n: MutableI18n,
}

/// Enthält die kryptographische Signatur, die die Authentizität des Standards beweist.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignatureBlock {
    /// Die `did:key` des Herausgebers (enthält den öffentlichen Schlüssel).
    pub issuer_id: String,
    /// Die Base58-kodierte Ed25519-Signatur über den kanonisierten Inhalt der Standard-Datei.
    pub signature: String,
}

/// Das Haupt-Struct, das die gesamte signierte Gutschein-Standard-Definition kapselt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandardDefinition {
    /// Unveränderlicher Konsens-Kern (bestimmt den `logic_hash`).
    pub immutable: ImmutableZone,
    /// Anpassbare Metadaten und i18n-Übersetzungen.
    pub mutable: MutableZone,
    /// Kryptographische Signatur des Herausgebers (optional bei unvollständig geladenen oder noch unsignierten Standards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

