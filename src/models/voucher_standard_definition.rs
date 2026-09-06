//! # voucher_standard_definition.rs
//!
//! Defines the Rust data structures for Voucher Standards (`standard.toml`).
//!
//! A Voucher Standard acts as the constitution-like foundation of a specific
//! currency or unit of account. This structure strictly separates unratifiable
//! consensus rules (Immutable Zone) from customizable presentation data (Mutable Zone).
//!
//! ## The Two-Zone Model
//! - **Immutable Zone (`[immutable]`):** Contains all consensus-relevant parameters (identity,
//!   blueprint, features, issuance, CEL rules). The deterministic `logic_hash` (SHA-256) is
//!   calculated from this zone. Any change in this zone results in a new `logic_hash`
//!   and breaks compatibility with previously created vouchers.
//! - **Mutable Zone (`[mutable]`):** Contains UI-relevant metadata, app configurations, and
//!   i18n translations. Changes here do **not** alter the `logic_hash`, but require
//!   renewing the issuer signature in the `[signature]` block.

use crate::error::{StandardDefinitionError, VoucherCoreError};
use crate::services::crypto::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Defines a dynamic CEL (Common Expression Language) rule.
///
/// Dynamic rules allow deep inspection during voucher validation
/// that goes beyond the declarative fast path.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DynamicRule {
    /// The CEL expression to execute (e.g. `Transaction.amount <= 5000` or `Voucher.signatures.exists(...)`).
    pub expression: String,
    /// The error message returned when the CEL expression evaluates to `false`.
    pub message: String,
}

/// Contains the unique identity attributes of a standard.
///
/// This data resides in the Immutable Zone and is cryptographically bound to the `logic_hash`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIdentity {
    /// The economic anchor as UUID v4 (e.g. `"123e4567-e89b-12d3-a456-426614174000"`).
    /// Survives standard updates as long as the currency remains economically identical.
    pub uuid: String,
    /// The official name of the standard (e.g. `"Minuto Regional"`).
    pub name: String,
    /// The official currency abbreviation (e.g. `"MIN"`). Recommended: Max. 5 characters.
    pub abbreviation: String,
}

/// The primary redemption type of a voucher.
///
/// Used for tax and legal classification at the application layer.
/// Serde serialization uses `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrimaryRedemptionType {
    /// Countervalues in goods or services (default).
    #[default]
    GoodsOrServices,
    /// Time-value based vouchers (e.g. hours/minutes of labor).
    Time,
    /// Physical-asset or commodity backed vouchers (e.g. precious metals, harvest shares).
    PhysicalAsset,
}

/// The type of collateral / backing for a voucher.
///
/// Defines the economic protection and trust mechanism of the currency.
/// Serde serialization uses `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CollateralType {
    /// Personal performance guarantee and personal guarantees by individuals (default).
    #[default]
    PersonalGuarantee,
    /// Backed by fiat money balances.
    FiatBacked,
    /// Backed by cryptocurrencies or smart contract reserves.
    CryptoBacked,
    /// Backed by physical assets or commodities.
    PhysicalAsset,
}

/// The privacy and transparency mode for L2 transactions.
///
/// Controls how transaction data may be processed and obfuscated on Layer 2.
/// Serde serialization uses `snake_case`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Transactions are fully public and traceable.
    #[default]
    Public,
    /// Transactions enforce zero-knowledge proofs / stealth addresses for obfuscation.
    Stealth,
    /// The sender/user can choose between public and obfuscated per transaction.
    Flexible,
}

/// Fixed initial values and base properties for vouchers of this standard.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableBlueprint {
    /// The nominal unit of the voucher (e.g. `"Minuten"`, `"Taler"`).
    pub unit: String,
    /// The primary redemption purpose (Enum: `goods_or_services`, `time`, `physical_asset`).
    pub primary_redemption_type: PrimaryRedemptionType,
    /// The type of collateral (Enum: `personal_guarantee`, `fiat_backed`, `crypto_backed`, `physical_asset`).
    pub collateral_type: CollateralType,
}

/// Controls functional behavior and restrictions in wallet software.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableFeatures {
    /// Allows partial transfers (`split`). If `false`, the voucher can only be transferred in its entirety.
    pub allow_partial_transfers: bool,
    /// Fungibility and balance aggregation rule: defines whether vouchers of this standard represent
    /// interchangeable/summable currency units (`true`) or distinct non-fungible certificates (`false`).
    /// Directly controls balance and transfer aggregation (`TransferSummary`) in core logic and is therefore
    /// an essential part of the immutable `logic_hash`.
    pub balances_are_summable: bool,
    /// Maximum number of decimal places (`0` for integers like minutes, `2` for currencies).
    pub amount_decimal_places: u8,
    /// Transparency and privacy mode (`public`, `stealth`, `flexible`).
    pub privacy_mode: PrivacyMode,
    /// Allowed transaction types for vouchers of this standard (e.g. `["init", "transfer", "split"]`).
    pub allowed_t_types: Vec<String>,
}

/// Rules for creating and issuing new vouchers (Issuance Firewall).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableIssuance {
    /// ISO 8601 duration ranges for allowed total validity durations [Min, Max] (e.g. `["P1Y", "P5Y"]`).
    pub validity_duration_range: Vec<String>,
    /// Circulation firewall: Required remaining validity duration upon creation/issuance (e.g. `"P1Y"`).
    pub issuance_minimum_validity_duration: String,
    /// Required number of additional signatures (e.g. guarantors, auditors, witnesses) [Min, Max] (e.g. `[2, 2]` or `[0, 0]`).
    pub additional_signatures_range: Vec<u32>,
    /// Allowed signature roles for additional signatures (e.g. `["guarantor"]`, `["auditor"]`, `["witness"]`).
    pub allowed_signature_roles: Vec<String>,
}

/// The unratifiable consensus zone (`[immutable]`).
///
/// All data contained here directly feeds into the deterministic SHA-256 `logic_hash`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct ImmutableZone {
    /// Identity attributes (UUID, name, abbreviation).
    pub identity: ImmutableIdentity,
    /// Base configuration and redemption type.
    pub blueprint: ImmutableBlueprint,
    /// Functional scope and wallet restrictions.
    pub features: ImmutableFeatures,
    /// Rules for voucher creation and co-signers.
    pub issuance: ImmutableIssuance,
    /// Dynamic CEL validation rules for deep inspection.
    #[serde(default)]
    pub custom_rules: HashMap<String, DynamicRule>,
}

/// Issuer metadata for discoverability and documentation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableMetadata {
    /// Official name of the issuing organization or community.
    pub issuer_name: String,
    /// Optional website URL for the standard's homepage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage_url: Option<String>,
    /// Optional web URL for legal or technical documentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documentation_url: Option<String>,
    /// Keywords for categorization in standard directories.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
}

/// App and UX recommendations for wallet clients and L2 nodes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableAppConfig {
    /// Recommended default value for the validity duration in the creation form (ISO 8601, e.g. `"P5Y"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_validity_duration: Option<String>,
    /// UI hint for rounding up the expiration date (e.g. `"P1Y"` for the end of the target year).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub round_up_validity_to: Option<String>,
    /// Requirement for L2 nodes regarding history retention after voucher expiration (ISO 8601, e.g. `"P6M"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_history_retention: Option<String>,
}

/// Multilingual texts and descriptions (i18n self-containment).
///
/// Keys correspond to ISO language codes (e.g. `"de"`, `"en"`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableI18n {
    /// Main contract texts with placeholders such as `{{amount}}`.
    #[serde(default)]
    pub descriptions: HashMap<String, String>,
    /// Legal notices or fine print.
    #[serde(default)]
    pub footnotes: HashMap<String, String>,
    /// Descriptions of the collateral mechanism.
    #[serde(default)]
    pub collateral_descriptions: HashMap<String, String>,
}

/// The customizable presentation zone (`[mutable]`).
///
/// Changes in this zone do **not** alter the `logic_hash`. They allow the issuer to
/// update descriptions, links, or i18n texts without invalidating existing vouchers.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct MutableZone {
    /// Issuer metadata and links.
    pub metadata: MutableMetadata,
    /// UX defaults and L2 retention settings.
    #[serde(default)]
    pub app_config: MutableAppConfig,
    /// Multilingual contract texts and descriptions.
    #[serde(default)]
    pub i18n: MutableI18n,
}

/// Contains the cryptographic signature proving the authenticity of the standard.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct SignatureBlock {
    /// The `did:key` of the issuer (contains the public key).
    pub issuer_id: String,
    /// The Base58-encoded Ed25519 signature over the canonical content of the standard file.
    pub signature: String,
}

/// The main struct encapsulating the entire signed voucher standard definition.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandardDefinition {
    /// Immutable consensus core (determines the `logic_hash`).
    pub immutable: ImmutableZone,
    /// Customizable metadata and i18n translations.
    pub mutable: MutableZone,
    /// Cryptographic signature of the issuer (optional for incompletely loaded or unsigned standards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

impl VoucherStandardDefinition {
    /// Computes the deterministic logic_hash over the `[immutable]` zone ONLY.
    pub fn compute_logic_hash(&self) -> Result<String, VoucherCoreError> {
        let canonical_json_immutable = to_canonical_json(&self.immutable)?;
        Ok(get_hash(canonical_json_immutable.as_bytes()))
    }

    /// Verifies the Ed25519 issuer signature against the canonical JSON representation
    /// of the entire standard (excluding the signature block itself).
    pub fn verify_signature(&self) -> Result<bool, VoucherCoreError> {
        let signature_block = self.signature.as_ref().ok_or({
            VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)
        })?;

        let mut body = self.clone();
        body.signature = None;
        let canonical_json_all = to_canonical_json(&body)?;
        let signature_hash = get_hash(canonical_json_all.as_bytes());

        let signature_bytes = bs58::decode(&signature_block.signature)
            .into_vec()
            .map_err(|e| {
                VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
            })?;

        let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
            VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
        })?;

        let public_key = get_pubkey_from_user_id(&signature_block.issuer_id)?;

        #[cfg(feature = "test-utils")]
        {
            if crate::is_signature_bypass_active() {
                return Ok(true);
            }
        }

        Ok(verify_ed25519(&public_key, signature_hash.as_bytes(), &signature))
    }

    /// Parses and verifies a TOML string into `(VoucherStandardDefinition, logic_hash)`.
    pub fn from_toml(toml_str: &str) -> Result<(Self, String), VoucherCoreError> {
        Self::from_toml_with_issuer_pin(toml_str, None)
    }

    /// Parses and verifies a TOML string with optional trust-on-first-use issuer pinning.
    ///
    /// SECURITY (AUDIT-W4-CEL-102): trust-on-first-use issuer pinning.
    /// When a pin is supplied, additionally enforces that the signature block's
    /// issuer resolves to the SAME public key as the pinned identity.
    pub fn from_toml_with_issuer_pin(
        toml_str: &str,
        pinned_issuer_id: Option<&str>,
    ) -> Result<(Self, String), VoucherCoreError> {
        let standard: VoucherStandardDefinition = toml::from_str(toml_str)?;

        if !standard.verify_signature()? {
            return Err(VoucherCoreError::Standard(
                StandardDefinitionError::InvalidSignature,
            ));
        }

        if let Some(expected_issuer_id) = pinned_issuer_id {
            let signature_block = standard.signature.as_ref().ok_or({
                VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)
            })?;
            let expected_pk = get_pubkey_from_user_id(expected_issuer_id)
                .map_err(|e| crate::error::ValidationError::InvalidCreatorId(e.to_string()))?;
            let actual_pk = get_pubkey_from_user_id(&signature_block.issuer_id)
                .map_err(|e| crate::error::ValidationError::InvalidCreatorId(e.to_string()))?;
            if expected_pk.to_bytes() != actual_pk.to_bytes() {
                return Err(VoucherCoreError::Standard(
                    StandardDefinitionError::IssuerPinViolation,
                ));
            }
        }

        let logic_hash = standard.compute_logic_hash()?;
        Ok((standard, logic_hash))
    }

    /// Resolves localized text according to fallback logic defined in the specification.
    ///
    /// Search order:
    /// 1. Direct match with `lang_preference`.
    /// 2. Fallback to English ("en").
    /// 3. Fallback to lexicographically first element.
    pub fn get_localized_text<'a>(
        texts: &'a HashMap<String, String>,
        lang_preference: &str,
    ) -> Option<&'a str> {
        if texts.is_empty() {
            return None;
        }

        if let Some(text) = texts.get(lang_preference) {
            return Some(text.as_str());
        }

        if let Some(text) = texts.get("en") {
            return Some(text.as_str());
        }

        let mut keys: Vec<&String> = texts.keys().collect();
        keys.sort();
        keys.first()
            .and_then(|k| texts.get(*k))
            .map(|t| t.as_str())
    }
}


