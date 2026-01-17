//! # src/services/standard_manager.rs
//!
//! Dieses Modul enthält die Kernlogik zur Verarbeitung und Verifizierung
//! von `VoucherStandardDefinition`-Dateien (standard.toml).

use crate::error::{StandardDefinitionError, VoucherCoreError};
use crate::models::voucher_standard_definition::{LocalizedText, VoucherStandardDefinition};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;

use ed25519_dalek::Signature;

/// Verarbeitet einen TOML-String, der eine Gutschein-Standard-Definition enthält.
///
/// Diese Funktion führt die folgenden Schritte aus:
/// 1. Parst den TOML-String in die `VoucherStandardDefinition`-Struktur.
/// 2. Kanonisiert die Definition (ohne Signatur) in einen stabilen JSON-String.
/// 3. Berechnet den SHA3-256 Hash des kanonischen JSON-Strings (dies ist der "Konsistenz-Hash").
/// 4. Verifiziert die im TOML enthaltene Ed25519-Signatur gegen den berechneten Hash.
///
/// # Arguments
/// * `toml_str` - Der Inhalt der `standard.toml`-Datei als String.
///
/// # Returns
/// Ein `Result`, das bei Erfolg ein Tupel mit der verifizierten `VoucherStandardDefinition`
/// und dem berechneten `String` des Konsistenz-Hashes enthält. Bei einem Fehler wird
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

    // 3. Serialisiere die Struktur in einen kanonischen JSON-String.
    let canonical_json = to_canonical_json(&standard)?;

    // 4. Berechne den Hash des kanonischen JSONs. Dies ist der Konsistenz-Hash.
    let consistency_hash = get_hash(canonical_json.as_bytes());

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

    // 6. Verifiziere die Signatur gegen den Konsistenz-Hash.
    if !verify_ed25519(&public_key, consistency_hash.as_bytes(), &signature) {
        return Err(VoucherCoreError::Standard(
            StandardDefinitionError::InvalidSignature,
        ));
    }

    // 7. Setze den Signaturblock wieder in die Struktur ein und gib das Ergebnis zurück.
    standard.signature = Some(signature_block);

    Ok((standard, consistency_hash))
}

/// Löst einen lokalisierten Text gemäß der im Plan definierten Fallback-Logik auf.
///
/// Die Suchreihenfolge ist:
/// 1. Direkte Übereinstimmung mit `lang_preference`.
/// 2. Fallback auf Englisch ("en").
/// 3. Fallback auf den allerersten verfügbaren Text in der Liste.
///
/// # Arguments
/// * `texts` - Ein Slice von `LocalizedText`-Strukturen.
/// * `lang_preference` - Der bevorzugte Sprachcode (z.B. "de", "es").
///
/// # Returns
/// Ein `Option<&str>`, das den gefundenen Text-Slice enthält oder `None`, wenn die Liste leer ist.
pub fn get_localized_text<'a>(
    texts: &'a [LocalizedText],
    lang_preference: &str,
) -> Option<&'a str> {
    if texts.is_empty() {
        return None;
    }

    // 1. Suche nach direkter Übereinstimmung.
    if let Some(text) = texts.iter().find(|t| t.lang == lang_preference) {
        return Some(&text.text);
    }

    // 2. Fallback auf Englisch.
    if let Some(text) = texts.iter().find(|t| t.lang == "en") {
        return Some(&text.text);
    }

    // 3. Fallback auf das erste Element.
    texts.first().map(|t| t.text.as_str())
}
