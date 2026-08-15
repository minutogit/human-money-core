//! # src/services/signature_manager.rs
//!
//! Contains stateless business logic for creating and cryptographically
//! validating detached signatures (`DetachedSignature`).
use crate::error::ValidationError;

use crate::error::VoucherCoreError;
use crate::models::profile::{PublicProfile, UserIdentity};
use crate::models::signature::DetachedSignature;
use crate::services::crypto_utils::{
    get_hash_from_slices, get_pubkey_from_user_id, sign_ed25519, verify_ed25519,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::voucher_validation::get_failing_custom_rules;
use serde::{Deserialize, Serialize};

/// Completes and signs a `DetachedSignature`.
///
/// This function takes a partially populated `DetachedSignature` object,
/// fills the cryptographic fields (`signature_id`, `signature`, `signature_time`),
/// and returns the complete, signed object.
/// # Arguments
/// * `signature_data` - The `DetachedSignature` enum with the signer's metadata.
/// * `signer_identity` - The identity of the signer.
/// * `details` - The optional `PublicProfile` of the signer.
/// * `voucher_id` - The voucher ID to which the signature relates.
/// * `init_t_id` - The transaction ID of the genesis (init) transaction.
///
/// # Returns
/// A `Result` containing the completed `DetachedSignature`.
pub fn complete_and_sign_detached_signature(
    mut signature_data: DetachedSignature,
    signer_identity: &UserIdentity,
    details: Option<PublicProfile>,
    voucher_id: &str,
    init_t_id: &str,
) -> Result<DetachedSignature, VoucherCoreError> {
    let signer_id = match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            sig.signer_id = signer_identity.user_id.clone();
            sig.voucher_id = voucher_id.to_string();

            // If details parameter is Some, use it to complete the signature by merging
            // with existing details, giving priority to values in the details parameter.
            // If details parameter is None, explicitly clear the details (e.g., for include_details=false).
            match &details {
                Some(profile_details) => {
                    // Details are provided - merge with existing details or use entirely
                    match &sig.details {
                        Some(sig_details) => {
                            // Both signature and profile have details - merge giving priority to profile where it has values
                            let mut merged_details = sig_details.clone();

                            // Replace with profile values where they exist
                            if profile_details.first_name.is_some() {
                                merged_details.first_name = profile_details.first_name.clone();
                            }
                            if profile_details.last_name.is_some() {
                                merged_details.last_name = profile_details.last_name.clone();
                            }
                            if profile_details.gender.is_some() {
                                merged_details.gender = profile_details.gender.clone();
                            }
                            if profile_details.organization.is_some() {
                                merged_details.organization = profile_details.organization.clone();
                            }
                            if profile_details.community.is_some() {
                                merged_details.community = profile_details.community.clone();
                            }
                            if profile_details.email.is_some() {
                                merged_details.email = profile_details.email.clone();
                            }
                            if profile_details.phone.is_some() {
                                merged_details.phone = profile_details.phone.clone();
                            }
                            if profile_details.url.is_some() {
                                merged_details.url = profile_details.url.clone();
                            }
                            if profile_details.coordinates.is_some() {
                                merged_details.coordinates = profile_details.coordinates.clone();
                            }
                            if profile_details.address.is_some() {
                                merged_details.address = profile_details.address.clone();
                            }

                            sig.details = Some(merged_details);
                        }
                        None => {
                            // Signature has no details, use profile details entirely
                            sig.details = Some(profile_details.clone());
                        }
                    }
                }
                None => {
                    // No details should be included - explicitly set to None
                    sig.details = None;
                }
            }

            sig.signer_id.clone()
        }
    };

    if signer_identity.user_id != signer_id {
        return Err(VoucherCoreError::MismatchedSignatureData(
            "Signer ID in signature does not match signer identity".to_string(),
        ));
    }

    // Reset cryptographic fields and determine timestamp uniformly
    let signature_time = get_current_timestamp(); // Determine single timestamp
    let signature_json_for_id = match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            // Clone and modify for hash
            let mut sig_clone = sig.clone();
            sig_clone.signature_id = "".to_string();
            sig_clone.signature = "".to_string();
            sig_clone.signature_time = signature_time.clone(); // Use same timestamp

            to_canonical_json(&sig_clone)?.into_bytes()
        }
    };

    let signature_id =
        get_hash_from_slices(&[signature_json_for_id.as_slice(), init_t_id.as_bytes()]);
    let digital_signature = sign_ed25519(&signer_identity.signing_key, signature_id.as_bytes());
    let signature_str = bs58::encode(digital_signature.to_bytes()).into_string();

    match &mut signature_data {
        DetachedSignature::Signature(sig) => {
            sig.signature_id = signature_id;
            sig.signature = signature_str;
            sig.signature_time = signature_time; // Use same timestamp
        }
    }

    Ok(signature_data)
}

/// Validates the cryptographic integrity of a `DetachedSignature`.
///
/// Checks whether `signature_id` matches metadata and whether
/// the digital `signature` is valid.
///
/// # Arguments
/// * `signature_data` - The signature to validate.
/// * `init_t_id` - The transaction ID of the genesis (init) transaction.
///
/// # Returns
/// An empty `Result` if validation succeeds.
pub fn validate_detached_signature(
    signature_data: &DetachedSignature,
    init_t_id: &str,
) -> Result<(), VoucherCoreError> {
    // --- BYPASS CHECK START ---
    #[cfg(feature = "test-utils")]
    {
        if crate::is_signature_bypass_active() {
            // Output warning (only visible with --nocapture or on error)
            // so that one knows what is happening during debugging.
            // eprintln!("[TEST-MODE] WARNING: Signature check skipped.");
            return Ok(());
        }
    }
    // --- BYPASS CHECK END ---

    let (mut sig_obj_to_verify, signer_id, expected_sig_id, signature_b58) = match signature_data {
        DetachedSignature::Signature(sig) => (
            serde_json::to_value(sig)?,
            sig.signer_id.clone(),
            sig.signature_id.clone(),
            sig.signature.clone(),
        ),
    };

    // Remove cryptographic fields to recalculate metadata hash
    let obj = sig_obj_to_verify.as_object_mut().unwrap();
    obj.insert("signature_id".to_string(), "".into());
    obj.insert("signature".to_string(), "".into());

    // voucher_id is now part of hashing and is not removed

    let calculated_sig_id = get_hash_from_slices(&[
        to_canonical_json(&sig_obj_to_verify)?.as_bytes(),
        init_t_id.as_bytes(),
    ]);

    if calculated_sig_id != expected_sig_id {
        return Err(VoucherCoreError::Validation(
            ValidationError::InvalidSignatureId(expected_sig_id),
        ));
    }

    let public_key = get_pubkey_from_user_id(&signer_id)?;
    let signature_bytes: Vec<u8> = bs58::decode(signature_b58).into_vec()?;

    // Convert Vec<u8> into [u8; 64] array as expected by `from_bytes`
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        VoucherCoreError::Validation(ValidationError::SignatureDecodeError(
            "Invalid signature length: must be 64 bytes".to_string(),
        ))
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_array);

    if !verify_ed25519(&public_key, expected_sig_id.as_bytes(), &signature) {
        return Err(VoucherCoreError::Validation(
            ValidationError::InvalidSignature {
                signer_id: signer_id.to_string(),
            },
        ));
    }

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureImpact {
    pub is_allowed_role: bool,
    pub fatal_conflicts: Vec<String>,
    pub resolved_rules: Vec<String>,
    pub gentle_hints: Vec<String>,
}

/// Evaluates the hypothetical impact of adding a signature with the given role and profile
pub fn evaluate_signature_impact(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    role: &str,
    profile: &PublicProfile,
) -> Result<SignatureImpact, VoucherCoreError> {
    // Step 1 (Status Quo): Call get_failing_custom_rules on the unmodified voucher (List A).
    let failing_status_quo = get_failing_custom_rules(voucher, standard)?;

    // Step 2 (Hypothesis): Clone voucher. Append a dummy VoucherSignature
    let mut hyp_voucher = voucher.clone();
    
    // Check if role is allowed
    let allowed_roles = &standard.immutable.issuance.allowed_signature_roles;
    let is_allowed_role = allowed_roles.contains(&role.to_string());
    
    let dummy_sig = VoucherSignature {
        signature_id: "dummy_id".to_string(),
        signature: "dummy_sig".to_string(),
        signer_id: "dummy_signer".to_string(),
        signature_time: crate::services::utils::get_current_timestamp(),
        role: role.to_string(),
        details: Some(profile.clone()),
        voucher_id: voucher.voucher_id.clone(),
    };
    hyp_voucher.signatures.push(dummy_sig);

    // Step 3 (Hypothesis testing): Call get_failing_custom_rules on the clone (List B).
    let failing_hyp = get_failing_custom_rules(&hyp_voucher, standard)?;

    // Step 4 (Delta & Analysis):
    // fatal_conflicts: Rules in List B that are NOT in List A.
    let mut fatal_conflicts = Vec::new();
    for rule in &failing_hyp {
        if !failing_status_quo.contains(rule) {
            fatal_conflicts.push(rule.clone());
        }
    }

    // resolved_rules: Rules in List A that are NOT in List B.
    let mut resolved_rules = Vec::new();
    for rule in &failing_status_quo {
        if !failing_hyp.contains(rule) {
            resolved_rules.push(rule.clone());
        }
    }

    // gentle_hints: Scan the raw CEL expressions of the rules in List B for known profile attributes
    let mut gentle_hints = Vec::new();
    let keywords = vec![
        ".gender", "gender",
        ".location", "location",
        ".age", "age",
        ".first_name", "first_name",
        ".last_name", "last_name",
        ".email", "email",
        ".phone", "phone",
        ".organization", "organization",
        ".community", "community"
    ];
    
    for rule_msg in &failing_hyp {
        // Find the rule expression for this message
        for (_, rule_def) in &standard.immutable.custom_rules {
            if rule_def.message == *rule_msg {
                let expr = &rule_def.expression;
                // Add a specific hint based on what field is missing or checked
                for kw in &keywords {
                    if expr.contains(kw) && !gentle_hints.contains(&format!("Note: An open rule checks for your {}", kw.trim_start_matches('.'))) {
                        gentle_hints.push(format!("Note: An open rule checks for your {}", kw.trim_start_matches('.')));
                    }
                }
            }
        }
    }

    Ok(SignatureImpact {
        is_allowed_role,
        fatal_conflicts,
        resolved_rules,
        gentle_hints,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::voucher_standard_definition::{ImmutableFeatures, VoucherStandardDefinition, ImmutableZone, ImmutableIdentity, ImmutableIssuance, ImmutableBlueprint, DynamicRule};
    use crate::models::profile::PublicProfile;
    use crate::models::voucher::Voucher;
    use std::collections::HashMap;

    fn create_test_standard() -> VoucherStandardDefinition {
        let mut custom_rules = HashMap::new();
        custom_rules.insert(
            "require_female".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.exists(s, s.details.gender == 'Female')".to_string(),
                message: "A female profile is required.".to_string(),
            }
        );
        custom_rules.insert(
            "no_males".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.all(s, s.details.gender != 'Male')".to_string(),
                message: "Males are not allowed.".to_string(),
            }
        );
        custom_rules.insert(
            "require_location".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.exists(s, s.details.location == 'Berlin')".to_string(),
                message: "Location must be Berlin.".to_string(),
            }
        );
        
        let mut issuance = ImmutableIssuance::default();
        issuance.allowed_signature_roles = vec!["guarantor".to_string()];

        let immutable = ImmutableZone {
            identity: ImmutableIdentity { uuid: "test-uuid".to_string(), ..Default::default() },
            blueprint: ImmutableBlueprint::default(),
            features: ImmutableFeatures::default(),
            issuance,
            custom_rules,
        };
        
        VoucherStandardDefinition {
            immutable,
            ..Default::default()
        }
    }

    fn create_test_voucher() -> Voucher {
        Voucher {
            voucher_id: "vid123".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_evaluate_signature_impact_fatal_conflict() {
        let standard = create_test_standard();
        let voucher = create_test_voucher();
        
        let mut profile = PublicProfile::default();
        profile.gender = Some("Male".to_string());
        
        let impact = evaluate_signature_impact(&voucher, &standard, "guarantor", &profile).unwrap();
        
        assert!(impact.is_allowed_role);
        assert!(impact.fatal_conflicts.contains(&"Males are not allowed.".to_string()));
        assert!(!impact.resolved_rules.contains(&"A female profile is required.".to_string()));
        // Note: The expression contains 'gender', but gentle hints are only generated if the rule fails in the hypothesis.
        // It does fail in the hypothesis, meaning a gentle hint about 'gender' should be present.
        assert!(impact.gentle_hints.iter().any(|h| h.contains("gender")));
    }

    #[test]
    fn test_evaluate_signature_impact_resolved() {
        let standard = create_test_standard();
        let voucher = create_test_voucher();
        
        let mut profile = PublicProfile::default();
        profile.gender = Some("Female".to_string());
        profile.coordinates = Some("Berlin".to_string());
        
        let impact = evaluate_signature_impact(&voucher, &standard, "guarantor", &profile).unwrap();
        
        assert!(impact.is_allowed_role);
        assert!(!impact.fatal_conflicts.contains(&"A female profile is required.".to_string()));
        assert!(impact.resolved_rules.contains(&"A female profile is required.".to_string()));
    }
}
