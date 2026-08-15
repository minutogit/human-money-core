//! # human_money_wasm
//!
//! WebAssembly bindings for `human_money_core`.
//! Exposes cryptographic functions, standard definition signing, TOML canonicalization,
//! and browser-side CEL expression syntax validation.

use human_money_core::{
    crypto_utils::{self, get_hash},
    models::voucher_standard_definition::{SignatureBlock, VoucherStandardDefinition},
    services::standard_manager,
    to_canonical_json, MnemonicLanguage,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use wasm_bindgen::prelude::*;

/// Sign standard response payload.
#[derive(Serialize, Deserialize)]
pub struct SignStandardResult {
    pub toml: String,
    pub signature: String,
    pub issuer_id: String,
    pub logic_hash: String,
}

/// Verify standard response payload.
#[derive(Serialize, Deserialize)]
pub struct VerifyStandardResult {
    pub valid: bool,
    pub logic_hash: String,
    pub issuer_id: String,
    pub signature: String,
}

/// CEL Diagnostic result per rule.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CelDiagnostic {
    pub rule_id: String,
    pub expression: String,
    pub message: String,
    pub valid: bool,
    pub error: Option<String>,
}

/// Summary representation of standard zones for frontend visualization.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StandardSummary {
    pub uuid: String,
    pub name: String,
    pub abbreviation: String,
    pub unit: String,
    pub primary_redemption_type: String,
    pub collateral_type: String,
    pub allow_partial_transfers: bool,
    pub balances_are_summable: bool,
    pub amount_decimal_places: u8,
    pub privacy_mode: String,
    pub allowed_t_types: Vec<String>,
    pub validity_duration_range: Vec<String>,
    pub issuance_minimum_validity_duration: String,
    pub additional_signatures_range: Vec<u32>,
    pub allowed_signature_roles: Vec<String>,
    pub issuer_name: String,
    pub homepage_url: Option<String>,
    pub documentation_url: Option<String>,
    pub keywords: Vec<String>,
    pub default_validity_duration: Option<String>,
    pub round_up_validity_to: Option<String>,
    pub server_history_retention: Option<String>,
    pub i18n_languages: Vec<String>,
}

/// Comprehensive diagnostic result of standard TOML parsing & inspection.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StandardDiagnosticResult {
    pub valid: bool,
    pub clean_toml: String,
    pub logic_hash: Option<String>,
    pub is_signed: bool,
    pub signature_valid: Option<bool>,
    pub issuer_id: Option<String>,
    pub summary: Option<StandardSummary>,
    pub cel_diagnostics: Vec<CelDiagnostic>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub standard: Option<VoucherStandardDefinition>,
}

/// Sanitizes raw input by stripping Markdown code fences or surrounding text.
pub fn sanitize_toml_content(raw: &str) -> String {
    let text = raw.trim().replace("\r\n", "\n");

    // Case 1: Markdown code fence ```toml ... ``` or ``` ... ```
    if let Some(start_fence) = text.find("```") {
        let after_start = &text[start_fence + 3..];
        // Skip possible "toml" or language identifier on the same line
        let content_start = if let Some(newline_pos) = after_start.find('\n') {
            &after_start[newline_pos + 1..]
        } else {
            after_start
        };

        if let Some(end_fence) = content_start.find("```") {
            let extracted = content_start[..end_fence].trim();
            if !extracted.is_empty() {
                return extracted.to_string();
            }
        }
    }

    // Case 2: Extract text starting from first section header '[' if present
    if let Some(first_bracket) = text.find('[') {
        let candidate = text[first_bracket..].trim();
        // Check if there are trailing markdown blocks or fences
        if let Some(end_fence) = candidate.find("```") {
            let extracted = candidate[..end_fence].trim();
            if !extracted.is_empty() {
                return extracted.to_string();
            }
        }
        return candidate.to_string();
    }

    text
}

/// Safely validates CEL expression without panicking even on malformed antlr tokens.
pub fn safe_validate_cel(expr: &str) -> Result<(), String> {
    if expr.trim().is_empty() {
        return Err("CEL expression cannot be empty".to_string());
    }
    let expr_owned = expr.to_string();
    let res = std::panic::catch_unwind(move || {
        cel_interpreter::Program::compile(&expr_owned)
    });
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!("CEL syntax error: {}", e)),
        Err(_) => Err("CEL syntax error: expression contains invalid tokens or structure".to_string()),
    }
}

/// Generates a new BIP-39 mnemonic phrase (12 or 24 words).
#[wasm_bindgen]
pub fn generate_mnemonic(word_count: u32) -> Result<String, JsError> {
    crypto_utils::generate_mnemonic(word_count as usize, MnemonicLanguage::English)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Validates a BIP-39 mnemonic phrase in English.
#[wasm_bindgen]
pub fn validate_mnemonic(phrase: &str) -> Result<bool, JsError> {
    match crypto_utils::validate_mnemonic_phrase(phrase, MnemonicLanguage::English) {
        Ok(()) => Ok(true),
        Err(e) => Err(JsError::new(&e)),
    }
}

/// Derives the `did:key` issuer ID from a given mnemonic, optional prefix (defaults to "0"), and optional passphrase / extra words.
#[wasm_bindgen]
pub fn derive_issuer_id(
    mnemonic: &str,
    prefix: Option<String>,
    passphrase: Option<String>,
) -> Result<String, JsError> {
    let pref = prefix.unwrap_or_else(|| "0".to_string());
    let pass = passphrase.as_deref().filter(|p| !p.is_empty());
    let (public_key, _) = crypto_utils::derive_ed25519_keypair(mnemonic, pass, MnemonicLanguage::English)
        .map_err(|e| JsError::new(&e.to_string()))?;

    crypto_utils::create_user_id(&public_key, Some(&pref))
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Validates a CEL (Common Expression Language) expression for syntax correctness.
#[wasm_bindgen]
pub fn validate_cel_expression(expression: &str) -> Result<(), JsError> {
    safe_validate_cel(expression).map_err(|e| JsError::new(&e))
}

/// Sanitizes Markdown / text wrapper and returns clean TOML.
#[wasm_bindgen]
pub fn sanitize_markdown_toml(raw_input: &str) -> String {
    sanitize_toml_content(raw_input)
}

/// Parses and thoroughly diagnoses a standard TOML input (including Markdown stripping,
/// schema check, CEL syntax validation, and logic hash computation).
#[wasm_bindgen]
pub fn parse_and_diagnose_standard(raw_input: &str) -> Result<String, JsError> {
    let clean_toml = sanitize_toml_content(raw_input);

    if clean_toml.trim().is_empty() {
        let res = StandardDiagnosticResult {
            valid: false,
            clean_toml: String::new(),
            logic_hash: None,
            is_signed: false,
            signature_valid: None,
            issuer_id: None,
            summary: None,
            cel_diagnostics: Vec::new(),
            errors: vec!["Eingabe ist leer oder enthält kein gültiges TOML.".to_string()],
            warnings: Vec::new(),
            standard: None,
        };
        return serde_json::to_string(&res).map_err(|e| JsError::new(&e.to_string()));
    }

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // 1. Parse into VoucherStandardDefinition
    let standard_opt: Option<VoucherStandardDefinition> = match toml::from_str(&clean_toml) {
        Ok(std) => Some(std),
        Err(err) => {
            errors.push(format!("TOML-Schemafehler: {}", err));
            None
        }
    };

    if let Some(standard) = standard_opt {
        // 2. Compute logic hash
        let logic_hash = match to_canonical_json(&standard.immutable) {
            Ok(canonical_json) => Some(get_hash(canonical_json.as_bytes())),
            Err(e) => {
                errors.push(format!("Kanonisierungsfehler der Immutable-Zone: {}", e));
                None
            }
        };

        // 3. Check CEL rules individually
        let mut cel_diagnostics = Vec::new();
        for (rule_id, rule) in &standard.immutable.custom_rules {
            match safe_validate_cel(&rule.expression) {
                Ok(_) => {
                    cel_diagnostics.push(CelDiagnostic {
                        rule_id: rule_id.clone(),
                        expression: rule.expression.clone(),
                        message: rule.message.clone(),
                        valid: true,
                        error: None,
                    });
                }
                Err(err_msg) => {
                    let full_err = format!("CEL-Fehler in Regel '{}': {}", rule_id, err_msg);
                    errors.push(full_err.clone());
                    cel_diagnostics.push(CelDiagnostic {
                        rule_id: rule_id.clone(),
                        expression: rule.expression.clone(),
                        message: rule.message.clone(),
                        valid: false,
                        error: Some(full_err),
                    });
                }
            }
        }

        // Sort CEL diagnostics by rule_id for deterministic order
        cel_diagnostics.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

        // 4. Check Signature if present
        let is_signed = standard.signature.is_some();
        let (signature_valid, issuer_id) = if let Some(ref sig_block) = standard.signature {
            let is_valid = standard_manager::verify_and_parse_standard(&clean_toml).is_ok();
            (Some(is_valid), Some(sig_block.issuer_id.clone()))
        } else {
            (None, None)
        };

        if is_signed && signature_valid == Some(false) {
            warnings.push("Signaturblock ist vorhanden, aber die Signatur ist ungültig oder passt nicht zum Inhalt.".to_string());
        }

        // 5. Extract language keys
        let mut languages_set: HashSet<String> = HashSet::new();
        for k in standard.mutable.i18n.descriptions.keys() {
            languages_set.insert(k.clone());
        }
        for k in standard.mutable.i18n.footnotes.keys() {
            languages_set.insert(k.clone());
        }
        for k in standard.mutable.i18n.collateral_descriptions.keys() {
            languages_set.insert(k.clone());
        }
        let mut i18n_languages: Vec<String> = languages_set.into_iter().collect();
        i18n_languages.sort();

        // 6. Build summary
        let summary = StandardSummary {
            uuid: standard.immutable.identity.uuid.clone(),
            name: standard.immutable.identity.name.clone(),
            abbreviation: standard.immutable.identity.abbreviation.clone(),
            unit: standard.immutable.blueprint.unit.clone(),
            primary_redemption_type: serde_json::to_value(&standard.immutable.blueprint.primary_redemption_type)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "goods_or_services".to_string()),
            collateral_type: serde_json::to_value(&standard.immutable.blueprint.collateral_type)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "personal_guarantee".to_string()),
            allow_partial_transfers: standard.immutable.features.allow_partial_transfers,
            balances_are_summable: standard.immutable.features.balances_are_summable,
            amount_decimal_places: standard.immutable.features.amount_decimal_places,
            privacy_mode: serde_json::to_value(&standard.immutable.features.privacy_mode)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "flexible".to_string()),
            allowed_t_types: standard.immutable.features.allowed_t_types.clone(),
            validity_duration_range: standard.immutable.issuance.validity_duration_range.clone(),
            issuance_minimum_validity_duration: standard.immutable.issuance.issuance_minimum_validity_duration.clone(),
            additional_signatures_range: standard.immutable.issuance.additional_signatures_range.clone(),
            allowed_signature_roles: standard.immutable.issuance.allowed_signature_roles.clone(),
            issuer_name: standard.mutable.metadata.issuer_name.clone(),
            homepage_url: standard.mutable.metadata.homepage_url.clone(),
            documentation_url: standard.mutable.metadata.documentation_url.clone(),
            keywords: standard.mutable.metadata.keywords.clone(),
            default_validity_duration: standard.mutable.app_config.default_validity_duration.clone(),
            round_up_validity_to: standard.mutable.app_config.round_up_validity_to.clone(),
            server_history_retention: standard.mutable.app_config.server_history_retention.clone(),
            i18n_languages,
        };

        let valid = errors.is_empty();

        let result = StandardDiagnosticResult {
            valid,
            clean_toml,
            logic_hash,
            is_signed,
            signature_valid,
            issuer_id,
            summary: Some(summary),
            cel_diagnostics,
            errors,
            warnings,
            standard: Some(standard),
        };

        serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
    } else {
        let result = StandardDiagnosticResult {
            valid: false,
            clean_toml,
            logic_hash: None,
            is_signed: false,
            signature_valid: None,
            issuer_id: None,
            summary: None,
            cel_diagnostics: Vec::new(),
            errors,
            warnings,
            standard: None,
        };

        serde_json::to_string(&result).map_err(|e| JsError::new(&e.to_string()))
    }
}

/// Converts a JSON string representation of a VoucherStandardDefinition to canonical TOML string.
#[wasm_bindgen]
pub fn to_toml_preview(standard_json: &str) -> Result<String, JsError> {
    let standard: VoucherStandardDefinition = serde_json::from_str(standard_json)
        .map_err(|e| JsError::new(&format!("Invalid standard JSON: {}", e)))?;

    toml::to_string_pretty(&standard)
        .map_err(|e| JsError::new(&format!("TOML serialization error: {}", e)))
}

/// Signs a VoucherStandardDefinition JSON string using an Ed25519 key derived from a mnemonic phrase and optional passphrase.
/// Returns a JSON string containing the final signed TOML, signature, issuer_id, and logic_hash.
#[wasm_bindgen]
pub fn sign_standard(
    standard_json: &str,
    mnemonic: &str,
    prefix: Option<String>,
    passphrase: Option<String>,
) -> Result<String, JsError> {
    // 1. Parse JSON standard definition
    let mut standard: VoucherStandardDefinition = serde_json::from_str(standard_json)
        .map_err(|e| JsError::new(&format!("Invalid standard JSON: {}", e)))?;

    // 2. Validate mnemonic and derive Ed25519 keypair
    let pref = prefix.unwrap_or_else(|| "0".to_string());
    let pass = passphrase.as_deref().filter(|p| !p.is_empty());
    let (public_key, signing_key) = crypto_utils::derive_ed25519_keypair(mnemonic, pass, MnemonicLanguage::English)
        .map_err(|e| JsError::new(&format!("Key derivation error: {}", e)))?;

    let issuer_id = crypto_utils::create_user_id(&public_key, Some(&pref))
        .map_err(|e| JsError::new(&format!("Issuer ID generation error: {}", e)))?;

    // 3. Clear existing signature block for canonical hash calculation
    standard.signature = None;

    // 4. Create canonical JSON representation of entire standard
    let canonical_json_all = to_canonical_json(&standard)
        .map_err(|e| JsError::new(&format!("Canonical JSON error: {}", e)))?;

    // 5. Compute hash to sign
    let hash_to_sign = get_hash(canonical_json_all.as_bytes());

    // 6. Produce Ed25519 signature
    let signature = crypto_utils::sign_ed25519(&signing_key, hash_to_sign.as_bytes());
    let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

    // 7. Attach signature block
    let sig_block = SignatureBlock {
        issuer_id: issuer_id.clone(),
        signature: signature_b58.clone(),
    };
    standard.signature = Some(sig_block);

    // 8. Compute immutable logic_hash
    let canonical_json_immutable = to_canonical_json(&standard.immutable)
        .map_err(|e| JsError::new(&format!("Immutable canonical JSON error: {}", e)))?;
    let logic_hash = get_hash(canonical_json_immutable.as_bytes());

    // 9. Format as TOML
    let toml_str = toml::to_string_pretty(&standard)
        .map_err(|e| JsError::new(&format!("TOML formatting error: {}", e)))?;

    let result = SignStandardResult {
        toml: toml_str,
        signature: signature_b58,
        issuer_id,
        logic_hash,
    };

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON response error: {}", e)))
}

/// Verifies a signed standard TOML string and returns logic_hash and issuer details.
#[wasm_bindgen]
pub fn verify_standard(toml_content: &str) -> Result<String, JsError> {
    let (standard, logic_hash) = standard_manager::verify_and_parse_standard(toml_content)
        .map_err(|e| JsError::new(&format!("Standard verification failed: {}", e)))?;

    let sig_block = standard.signature.ok_or_else(|| {
        JsError::new("Missing signature block")
    })?;

    let result = VerifyStandardResult {
        valid: true,
        logic_hash,
        issuer_id: sig_block.issuer_id,
        signature: sig_block.signature,
    };

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON response error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cel_validation() {
        assert!(safe_validate_cel("1 + 1 == 2").is_ok());
        assert!(safe_validate_cel("invalid (( expression").is_err());
        assert!(safe_validate_cel("").is_err());
    }

    #[test]
    fn test_sanitize_toml_content_with_markdown() {
        let md = r#"
Here is the standard definition:
```toml
[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Test"
abbreviation = "TST"
```
Hope that helps!
"#;
        let clean = sanitize_toml_content(md);
        assert!(clean.starts_with("[immutable.identity]"));
        assert!(clean.ends_with("abbreviation = \"TST\""));
    }

    #[test]
    fn test_diagnose_valid_standard() {
        let toml_sample = r#"
[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Minuto Regional"
abbreviation = "MIN"

[immutable.blueprint]
unit = "Minuten"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 0
privacy_mode = "flexible"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P5Y"]
issuance_minimum_validity_duration = "P1Y"
additional_signatures_range = [2, 2]
allowed_signature_roles = ["guarantor"]

[immutable.custom_rules.max_transfer]
expression = "Transaction.amount <= 5000"
message = "Max transfer is 5000"

[mutable.metadata]
issuer_name = "Minuto Association"

[mutable.app_config]
default_validity_duration = "P5Y"

[mutable.i18n.descriptions]
de = "Beschreibung"
en = "Description"

[mutable.i18n.footnotes]
de = "Fussnote"
"#;
        let diag_json = parse_and_diagnose_standard(toml_sample).unwrap();
        let diag: StandardDiagnosticResult = serde_json::from_str(&diag_json).unwrap();
        assert!(diag.valid);
        assert!(diag.logic_hash.is_some());
        assert_eq!(diag.cel_diagnostics.len(), 1);
        assert!(diag.cel_diagnostics[0].valid);
        assert_eq!(diag.summary.unwrap().name, "Minuto Regional");
    }

    #[test]
    fn test_diagnose_invalid_cel() {
        let toml_sample = r#"
[immutable.identity]
uuid = "123e4567-e89b-12d3-a456-426614174000"
name = "Minuto Regional"
abbreviation = "MIN"

[immutable.blueprint]
unit = "Minuten"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 0
privacy_mode = "flexible"
allowed_t_types = ["init", "transfer", "split"]

[immutable.issuance]
validity_duration_range = ["P1Y", "P5Y"]
issuance_minimum_validity_duration = "P1Y"
additional_signatures_range = [2, 2]
allowed_signature_roles = ["guarantor"]

[immutable.custom_rules.broken_rule]
expression = "Transaction.amount <<<<< 5000"
message = "Invalid"

[mutable.metadata]
issuer_name = "Minuto Association"
"#;
        let diag_json = parse_and_diagnose_standard(toml_sample).unwrap();
        let diag: StandardDiagnosticResult = serde_json::from_str(&diag_json).unwrap();
        assert!(!diag.valid);
        assert!(!diag.errors.is_empty());
        assert_eq!(diag.cel_diagnostics.len(), 1);
        assert!(!diag.cel_diagnostics[0].valid);
    }
}
