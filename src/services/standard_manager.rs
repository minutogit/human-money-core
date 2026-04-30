//! # src/services/standard_manager.rs
//!
//! Dieses Modul enthält die Kernlogik zur Verarbeitung und Verifizierung
//! von `VoucherStandardDefinition`-Dateien (standard.toml).

use crate::error::{StandardDefinitionError, VoucherCoreError};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use std::collections::HashMap;

use ed25519_dalek::Signature;

/// Verarbeitet einen TOML-String, der eine Gutschein-Standard-Definition enthält.
///
/// Diese Funktion führt die folgenden Schritte aus:
/// 1. Parst den TOML-String in die `VoucherStandardDefinition`-Struktur.
/// 2. Kanonisiert die Definition (ohne Signatur) in einen stabilen JSON-String.
/// 3. Berechnet den Hash des gesamten kanonischen JSON-Strings für die Signaturprüfung.
/// 4. Verifiziert die im TOML enthaltene Ed25519-Signatur.
/// 5. Berechnet den `logic_hash` separat nur über die [immutable]-Zone.
///
/// # Arguments
/// * `toml_str` - Der Inhalt der `standard.toml`-Datei als String.
///
/// # Returns
/// Ein `Result`, das bei Erfolg ein Tupel mit der verifizierten `VoucherStandardDefinition`
/// und dem berechneten `String` des `logic_hash` enthält. Bei einem Fehler wird
/// ein `VoucherCoreError` zurückgegeben.
pub fn verify_and_parse_standard(
    toml_str: &str,
) -> Result<(VoucherStandardDefinition, String), VoucherCoreError> {
    // 1. Parse den TOML-String in die Rust-Struktur.
    let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)?;

    // Stelle sicher, dass der Signatur-Block vorhanden ist.
    let signature_block = standard.signature.clone().ok_or_else(|| {
        VoucherCoreError::Standard(StandardDefinitionError::MissingSignatureBlock)
    })?;

    // 2. Erstelle eine temporäre Version der Struktur OHNE die Signatur für die Kanonisierung.
    standard.signature = None;

    // 3. Serialisiere die Struktur (immutable + mutable, ohne Signatur) in einen kanonischen JSON-String.
    let canonical_json_all = to_canonical_json(&standard)?;

    // 4. Berechne den Hash zur Signaturprüfung.
    let signature_hash = get_hash(canonical_json_all.as_bytes());

    // 5. Dekodiere die Signatur, validiere ihr Format und extrahiere den Public Key.
    let signature_bytes = bs58::decode(&signature_block.signature)
        .into_vec()
        .map_err(|e| {
            VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
        })?;

    let signature = Signature::from_slice(&signature_bytes).map_err(|e| {
        VoucherCoreError::Standard(StandardDefinitionError::SignatureDecode(e.to_string()))
    })?;

    let public_key = get_pubkey_from_user_id(&signature_block.issuer_id)?;

    // 6. Verifiziere die Signatur gegen den Hash des gesamten (signierten) Bodys.
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

    // 7. Berechne den logic_hash NUR über die [immutable]-Zone.
    let canonical_json_immutable = to_canonical_json(&standard.immutable)?;
    let logic_hash = get_hash(canonical_json_immutable.as_bytes());

    // 8. Setze den Signaturblock wieder in die Struktur ein und gib das Ergebnis zurück.
    standard.signature = Some(signature_block);

    Ok((standard, logic_hash))
}

/// Löst einen lokalisierten Text gemäß der im Plan definierten Fallback-Logik auf.
///
/// Die Suchreihenfolge ist:
/// 1. Direkte Übereinstimmung mit `lang_preference`.
/// 2. Fallback auf Englisch ("en").
/// 3. Fallback auf einen beliebigen verfügbaren Text in der Liste.
///
/// # Arguments
/// * `texts` - Eine Map von Sprachcodes zu Texten.
/// * `lang_preference` - Der bevorzugte Sprachcode (z.B. "de", "es").
///
/// # Returns
/// Ein `Option<&str>`, das den gefundenen Text enthält oder `None`, wenn die Liste leer ist.
pub fn get_localized_text<'a>(
    texts: &'a HashMap<String, String>,
    lang_preference: &str,
) -> Option<&'a str> {
    if texts.is_empty() {
        return None;
    }

    // 1. Suche nach direkter Übereinstimmung.
    if let Some(text) = texts.get(lang_preference) {
        return Some(text.as_str());
    }

    // 2. Fallback auf Englisch.
    if let Some(text) = texts.get("en") {
        return Some(text.as_str());
    }

    // 3. Fallback auf das lexikographisch erste Element (für Determinismus).
    let mut keys: Vec<&String> = texts.keys().collect();
    keys.sort();
    keys.first()
        .and_then(|k| texts.get(*k))
        .map(|t| t.as_str())
}
