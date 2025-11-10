//! # src/services/signature_manager.rs
//!
//! Enthält die zustandslose Geschäftslogik für die Erstellung und kryptographische
//! Validierung von losgelösten Signaturen (`DetachedSignature`).
use crate::error::ValidationError;

use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::signature::DetachedSignature;
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

/// Vervollständigt und signiert eine `DetachedSignature`.
///
/// Diese Funktion nimmt ein teilweise ausgefülltes `DetachedSignature`-Objekt,
/// füllt die kryptographischen Felder (`signature_id`, `signature`, `signature_time`),
/// und gibt das vollständige, signierte Objekt zurück.
///
/// # Arguments
/// * `signature_data` - Das `DetachedSignature`-Enum mit den Metadaten des Unterzeichners.
/// * `voucher_id` - Die ID des Gutscheins, auf den sich die Signatur bezieht (zur Validierung).
/// * `signer_identity` - Die Identität des Unterzeichners.
///
/// # Returns
/// Eine `Result` mit der vervollständigten `DetachedSignature`.
pub fn complete_and_sign_detached_signature(
    mut signature_data: DetachedSignature,
    voucher_id: &str,
    signer_identity: &UserIdentity,
) -> Result<DetachedSignature, VoucherCoreError> {
    let (signature_voucher_id, signer_id) = match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            sig.signer_id = signer_identity.user_id.clone();
            (sig.voucher_id.clone(), sig.signer_id.clone())
        }
    };

    if voucher_id != signature_voucher_id {
        return Err(VoucherCoreError::MismatchedSignatureData(
            "Voucher ID in signature does not match target voucher".to_string(),
        ));
    }
    if signer_identity.user_id != signer_id {
        return Err(VoucherCoreError::MismatchedSignatureData(
            "Signer ID in signature does not match signer identity".to_string(),
        ));
    }

    // Setze kryptographische Felder zurück, um einen deterministischen Hash zu gewährleisten
    let signature_json_for_id = match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            sig.signature_id = "".to_string();
            sig.signature = "".to_string();
            sig.signature_time = get_current_timestamp();
            to_canonical_json(sig)?
        }
    };

    let signature_id = get_hash(signature_json_for_id);
    let digital_signature =
        sign_ed25519(&signer_identity.signing_key, signature_id.as_bytes());
    let signature_str = bs58::encode(digital_signature.to_bytes()).into_string();

    match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            sig.signature_id = signature_id;
            sig.signature = signature_str;
        }
    }

    Ok(signature_data)
}

/// Validiert die kryptographische Integrität einer `DetachedSignature`.
///
/// Überprüft, ob die `signature_id` mit den Metadaten übereinstimmt und ob die
/// digitale `signature` gültig ist.
///
/// # Arguments
/// * `signature_data` - Die zu validierende Signatur.
///
/// # Returns
/// Ein leeres `Result`, wenn die Validierung erfolgreich ist.
pub fn validate_detached_signature(
    signature_data: &DetachedSignature,
) -> Result<(), VoucherCoreError> {
    let (mut sig_obj_to_verify, signer_id, expected_sig_id, signature_b58) = match signature_data {
        DetachedSignature::Signature(sig) => (
            serde_json::to_value(sig)?,
            sig.signer_id.clone(),
            sig.signature_id.clone(),
            sig.signature.clone(),
        ),
    };

    // Entferne die kryptographischen Felder, um den Hash der Metadaten neu zu berechnen
    let obj = sig_obj_to_verify.as_object_mut().unwrap();
    obj.insert("signature_id".to_string(), "".into());
    obj.insert("signature".to_string(), "".into());

    let canonical_json = to_canonical_json(&obj)?;
    let calculated_sig_id = get_hash(canonical_json);

    if calculated_sig_id != expected_sig_id {
        return Err(VoucherCoreError::Validation(ValidationError::InvalidSignatureId(expected_sig_id)));
    }

    let public_key = get_pubkey_from_user_id(&signer_id)?;
    let signature_bytes: Vec<u8> = bs58::decode(signature_b58).into_vec()?;

    // Konvertiere den Vec<u8> in ein [u8; 64] Array, wie es von `from_bytes` erwartet wird.
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        VoucherCoreError::Validation(
            ValidationError::SignatureDecodeError(
                "Invalid signature length: must be 64 bytes".to_string(),
            ),
        )
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);

    if !verify_ed25519(&public_key, expected_sig_id.as_bytes(), &signature) {
        return Err(VoucherCoreError::Validation(ValidationError::InvalidSignature {
            signer_id: signer_id.to_string(), // KORREKTUR E0308
        }));
    }

    Ok(())
}