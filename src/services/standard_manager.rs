//! # src/services/standard_manager.rs
//!
//! This module contains core logic for processing and verifying
//! `VoucherStandardDefinition` files (standard.toml).

use crate::error::{StandardDefinitionError, VoucherCoreError};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use std::collections::HashMap;

use ed25519_dalek::Signature;

/// Processes a TOML string containing a voucher standard definition.
///
/// This function performs the following steps:
/// 1. Parses the TOML string into the `VoucherStandardDefinition` struct.
/// 2. Canonicalizes the definition (without signature) into a stable JSON string.
/// 3. Computes the hash of the full canonical JSON string for signature verification.
/// 4. Verifies the Ed25519 signature contained in the TOML.
/// 5. Computes the `logic_hash` separately over the `[immutable]` zone only.
///
/// # Arguments
/// * `toml_str` - The content of the `standard.toml` file as a string.
///
/// # Returns
/// A `Result` containing, on success, a tuple with the verified `VoucherStandardDefinition`
/// and the computed `String` of the `logic_hash`. On error, a `VoucherCoreError` is returned.
pub fn verify_and_parse_standard(
    toml_str: &str,
) -> Result<(VoucherStandardDefinition, String), VoucherCoreError> {
    // 1. Parse the TOML string into the Rust struct.
    let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)?;

    // Ensure that the signature block is present.
    let signature_block = standard.signature.clone().ok_or_else(|| {
        VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)
    })?;

    // 2. Create a temporary version of the struct WITHOUT signature for canonicalization.
    standard.signature = None;

    // 3. Serialize struct (immutable + mutable, without signature) into a canonical JSON string.
    let canonical_json_all = to_canonical_json(&standard)?;

    // 4. Compute hash for signature verification.
    let signature_hash = get_hash(canonical_json_all.as_bytes());

    // 5. Decode signature, validate its format, and extract public key.
    let signature_bytes = bs58::decode(&signature_block.signature)
        .into_vec()
        .map_err(|e| {
            VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
        })?;

    let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
        VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
    })?;

    let public_key = get_pubkey_from_user_id(&signature_block.issuer_id)?;

    // 6. Verify signature against hash of the entire (signed) body.
    #[cfg(feature = "test-utils")]
    {
        if !crate::is_signature_bypass_active() {
            if !verify_ed25519(&public_key, signature_hash.as_bytes(), &signature) {
                return Err(VoucherCoreError::Standard(
                    StandardDefinitionError::InvalidSignature,
                ));
            }
        }
    }
    #[cfg(not(feature = "test-utils"))]
    {
        if !verify_ed25519(&public_key, signature_hash.as_bytes(), &signature) {
            return Err(VoucherCoreError::Standard(
                StandardDefinitionError::InvalidSignature,
            ));
        }
    }

    // 7. Compute logic_hash over the [immutable] zone ONLY.
    let canonical_json_immutable = to_canonical_json(&standard.immutable)?;
    let logic_hash = get_hash(canonical_json_immutable.as_bytes());

    // 8. Restore signature block in struct and return result.
    standard.signature = Some(signature_block);

    Ok((standard, logic_hash))
}

/// Resolves localized text according to fallback logic defined in the specification.
///
/// Search order:
/// 1. Direct match with `lang_preference`.
/// 2. Fallback to English ("en").
/// 3. Fallback to any available text in the list.
///
/// # Arguments
/// * `texts` - A map of language codes to texts.
/// * `lang_preference` - Preferred language code (e.g. "de", "es").
///
/// # Returns
/// An `Option<&str>` containing the found text, or `None` if the list is empty.
pub fn get_localized_text<'a>(
    texts: &'a HashMap<String, String>,
    lang_preference: &str,
) -> Option<&'a str> {
    if texts.is_empty() {
        return None;
    }

    // 1. Search for direct match.
    if let Some(text) = texts.get(lang_preference) {
        return Some(text.as_str());
    }

    // 2. Fallback to English.
    if let Some(text) = texts.get("en") {
        return Some(text.as_str());
    }

    // 3. Fallback to lexicographically first element (for determinism).
    let mut keys: Vec<&String> = texts.keys().collect();
    keys.sort();
    keys.first()
        .and_then(|k| texts.get(*k))
        .map(|t| t.as_str())
}
