//! # voucher_standard_definition.rs
//!
//! Definiert die Rust-Datenstrukturen für die Gutschein-Standards.
//! Diese Struktur trennt klar zwischen Metadaten, Kopiervorlagen und Validierungsregeln
//! und fügt die Unterstützung für kryptographische Signaturen und Mehrsprachigkeit hinzu.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Definiert eine dynamische CEL-Regel.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DynamicRule {
    pub expression: String,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIdentity {
    pub uuid: String,
    pub name: String,
    pub abbreviation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryRedemptionType {
    #[default]
    GoodsOrServices,
    Time,
    PhysicalAsset,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CollateralType {
    #[default]
    PersonalGuarantee,
    FiatBacked,
    CryptoBacked,
    PhysicalAsset,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    #[default]
    Public,
    Private,
    Flexible,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableBlueprint {
    pub unit: String,
    pub primary_redemption_type: PrimaryRedemptionType,
    pub collateral_type: CollateralType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableFeatures {
    pub allow_partial_transfers: bool,
    pub balances_are_summable: bool,
    pub amount_decimal_places: u8,
    pub privacy_mode: PrivacyMode,
    pub allowed_t_types: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIssuance {
    pub validity_duration_range: Vec<String>,
    pub issuance_minimum_validity_duration: String,
    pub additional_signatures_range: Vec<u32>,
    pub allowed_signature_roles: Vec<String>,
}



#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableZone {
    pub identity: ImmutableIdentity,
    pub blueprint: ImmutableBlueprint,
    pub features: ImmutableFeatures,
    pub issuance: ImmutableIssuance,
    #[serde(default)]
    pub custom_rules: HashMap<String, DynamicRule>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableMetadata {
    pub issuer_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableAppConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_history_retention: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableI18n {
    #[serde(default)]
    pub descriptions: HashMap<String, String>,
    #[serde(default)]
    pub footnotes: HashMap<String, String>,
    #[serde(default)]
    pub collateral_descriptions: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableZone {
    pub metadata: MutableMetadata,
    #[serde(default)]
    pub app_config: MutableAppConfig,
    #[serde(default)]
    pub i18n: MutableI18n,
}

/// Enthält die kryptographische Signatur, die die Authentizität des Standards beweist.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignatureBlock {
    /// Die `did:key` des Herausgebers.
    pub issuer_id: String,
    /// Die Base58-kodierte Ed25519-Signatur.
    pub signature: String,
}

/// Das Haupt-Struct, das die gesamte, nun signierte Standard-Definition kapselt.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandardDefinition {
    pub immutable: ImmutableZone,
    pub mutable: MutableZone,
    // Die Signatur ist optional, da sie für die Kanonisierung temporär entfernt wird.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}
