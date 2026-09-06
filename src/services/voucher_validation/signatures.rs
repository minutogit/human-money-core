use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_identity::{get_pubkey_from_user_id, validate_user_id};
use crate::services::crypto_utils::{get_hash_from_slices, verify_ed25519};
use crate::services::utils::to_canonical_json;
use ed25519_dalek::Signature;
use std::collections::HashSet;

pub fn verify_signatures(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    let mut seen_signers: HashSet<[u8; 32]> = HashSet::new();

    let init_t_id = voucher
        .transactions
        .first()
        .map(|tx| tx.t_id.as_str())
        .ok_or_else(|| {
            VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                "Voucher must have at least one (init) transaction.".to_string(),
            ))
        })?;

    let allowed_roles = standard.immutable.issuance.allowed_signature_roles.as_slice();
    let min_sigs = standard.immutable.issuance.additional_signatures_range.get(0).copied().unwrap_or(0);
    let max_sigs = standard.immutable.issuance.additional_signatures_range.get(1).copied().unwrap_or(0);

    let mut additional_sig_count = 0;

    for signature_obj in &voucher.signatures {
        if signature_obj.role != "creator" {
            if !allowed_roles.contains(&signature_obj.role) {
                return Err(ValidationError::BusinessRuleViolated(format!(
                    "Role '{}' is not an allowed signature role.",
                    signature_obj.role
                ))
                .into());
            }
            additional_sig_count += 1;
        }

        // SECURITY: Canonical identity firewall. Only user IDs that satisfy
        // the canonical grammar (as produced by `create_user_id`) may enter
        // signed containers. Lenient alias representations tolerated by the
        // rfind-based parser (e.g. multiple '@' separators) are rejected
        // before key extraction.
        if !validate_user_id(&signature_obj.signer_id) {
            return Err(ValidationError::BusinessRuleViolated(format!(
                "Signer ID '{}' violates the canonical identity grammar.",
                signature_obj.signer_id
            ))
            .into());
        }

        let pk = match get_pubkey_from_user_id(&signature_obj.signer_id) {
            Ok(pk) => pk,
            Err(e) => return Err(ValidationError::InvalidCreatorId(e).into()),
        };

        // SECURITY: Creator attribution binding (HMC-SEC-02-04). A signature
        // claiming the "creator" role must resolve to the exact public key
        // named by `voucher.creator_profile.id`. The comparison is performed
        // on the raw 32-byte keys (not identity strings), so root and
        // prefixed SAI representations of the SAME permanent key remain
        // interchangeable, while a foreign key can never hijack the creator
        // attribution (guaranty/reputation fraud vector).
        if signature_obj.role == "creator" {
            let creator_id = voucher
                .creator_profile
                .id
                .as_deref()
                .ok_or_else(|| {
                    ValidationError::BusinessRuleViolated(
                        "Creator-role signature present but the creator profile has no id."
                            .to_string(),
                    )
                })?;
            let creator_pk = get_pubkey_from_user_id(creator_id)
                .map_err(ValidationError::InvalidCreatorId)?;
            if pk.to_bytes() != creator_pk.to_bytes() {
                return Err(ValidationError::BusinessRuleViolated(format!(
                    "Creator-role signer '{}' does not match the attributed creator '{}'.",
                    signature_obj.signer_id, creator_id
                ))
                .into());
            }
        }

        if !seen_signers.insert(pk.to_bytes()) {
            return Err(ValidationError::DuplicateIdentityDetected {
                signer_id: signature_obj.signer_id.clone(),
            }
            .into());
        }

        // SECURITY (AUDIT-W4-INT-502): instant-based comparison, mirroring
        // the chain-level time-ordering hardening (offset confusion).
        if super::chain::parse_rfc3339_instant(
            &signature_obj.signature_time,
            "Signature",
            &signature_obj.signature_id,
        )? < super::chain::parse_rfc3339_instant(
            &voucher.creation_date,
            "Signature",
            &signature_obj.signature_id,
        )? {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Signature".to_string(),
                id: signature_obj.signature_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: signature_obj.signature_time.clone(),
            }
            .into());
        }

        is_signature_valid(signature_obj, init_t_id)?;
    }

    if additional_sig_count < min_sigs || additional_sig_count > max_sigs {
        return Err(ValidationError::CountOutOfBounds {
            field: "additional_signatures".to_string(),
            min: min_sigs,
            max: max_sigs,
            found: additional_sig_count as usize,
        }
        .into());
    }

    Ok(())
}

fn is_signature_valid(
    signature_obj: &VoucherSignature,
    init_t_id: &str,
) -> Result<(), ValidationError> {
    #[cfg(feature = "test-utils")]
    if crate::is_signature_bypass_active() {
        return Ok(());
    }

    let mut obj_to_verify = signature_obj.clone();
    obj_to_verify.signature_id = "".to_string();
    obj_to_verify.signature = "".to_string();

    let calculated_id_hash = get_hash_from_slices(&[
        to_canonical_json(&obj_to_verify)
            .unwrap_or_default()
            .as_bytes(),
        init_t_id.as_bytes(),
    ]);

    if calculated_id_hash != signature_obj.signature_id {
        return Err(ValidationError::InvalidSignatureId(
            signature_obj.signature_id.clone(),
        ));
    }

    let public_key = match get_pubkey_from_user_id(&signature_obj.signer_id) {
        Ok(pk) => pk,
        Err(e) => return Err(ValidationError::InvalidCreatorId(e)),
    };
    let signature_bytes = match bs58::decode(&signature_obj.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => return Err(ValidationError::SignatureDecodeError(e.to_string())),
    };

    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        ValidationError::SignatureDecodeError(
            "Invalid signature length: must be 64 bytes".to_string(),
        )
    })?;
    let signature = Signature::from_bytes(&signature_array);

    if !verify_ed25519(
        &public_key,
        signature_obj.signature_id.as_bytes(),
        &signature,
    ) {
        return Err(ValidationError::InvalidSignature {
            signer_id: signature_obj.signer_id.clone(),
        });
    }

    Ok(())
}
