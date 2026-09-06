use crate::error::{ValidationError, VoucherCoreError};
use crate::models::profile::PublicProfile;
use crate::models::voucher::{Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto::{get_pubkey_from_user_id, validate_user_id, verify_ed25519};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
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
            VoucherCoreError::Validation(ValidationError::VoucherMustHaveInitTransaction)
        })?;

    let allowed_roles = standard.immutable.issuance.allowed_signature_roles.as_slice();
    let min_sigs = standard.immutable.issuance.additional_signatures_range.first().copied().unwrap_or(0);
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
            Err(e) => return Err(ValidationError::InvalidCreatorId(e.to_string()).into()),
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
                .map_err(|e| ValidationError::InvalidCreatorId(e.to_string()))?;
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

    let calculated_id_hash = signature_obj
        .calculate_signature_id(init_t_id)
        .unwrap_or_default();

    if calculated_id_hash != signature_obj.signature_id {
        return Err(ValidationError::InvalidSignatureId(
            signature_obj.signature_id.clone(),
        ));
    }

    let public_key = match get_pubkey_from_user_id(&signature_obj.signer_id) {
        Ok(pk) => pk,
        Err(e) => return Err(ValidationError::InvalidCreatorId(e.to_string())),
    };
    let signature_array = crate::services::crypto::decode_bs58_fixed::<64>(
        &signature_obj.signature,
        "signature",
    )
    .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    let failing_status_quo = super::rules::get_failing_custom_rules(voucher, standard)?;

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
    let failing_hyp = super::rules::get_failing_custom_rules(&hyp_voucher, standard)?;

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
        ".community", "community",
    ];

    for rule_msg in &failing_hyp {
        // Find the rule expression for this message
        for rule_def in standard.immutable.custom_rules.values() {
            if rule_def.message == *rule_msg {
                let expr = &rule_def.expression;
                // Add a specific hint based on what field is missing or checked
                for kw in &keywords {
                    if expr.contains(kw)
                        && !gentle_hints.contains(&format!(
                            "Note: An open rule checks for your {}",
                            kw.trim_start_matches('.')
                        ))
                    {
                        gentle_hints.push(format!(
                            "Note: An open rule checks for your {}",
                            kw.trim_start_matches('.')
                        ));
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
    use crate::models::profile::PublicProfile;
    use crate::models::voucher::Voucher;
    use crate::models::voucher_standard_definition::{
        DynamicRule, ImmutableBlueprint, ImmutableFeatures, ImmutableIdentity, ImmutableIssuance,
        ImmutableZone, VoucherStandardDefinition,
    };
    use std::collections::HashMap;

    fn create_test_standard() -> VoucherStandardDefinition {
        let mut custom_rules = HashMap::new();
        custom_rules.insert(
            "require_female".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.exists(s, s.details.gender == 'Female')".to_string(),
                message: "A female profile is required.".to_string(),
            },
        );
        custom_rules.insert(
            "no_males".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.all(s, s.details.gender != 'Male')".to_string(),
                message: "Males are not allowed.".to_string(),
            },
        );
        custom_rules.insert(
            "require_location".to_string(),
            DynamicRule {
                expression: "Voucher.signatures.exists(s, s.details.location == 'Berlin')".to_string(),
                message: "Location must be Berlin.".to_string(),
            },
        );

        let mut issuance = ImmutableIssuance::default();
        issuance.allowed_signature_roles = vec!["guarantor".to_string()];

        let immutable = ImmutableZone {
            identity: ImmutableIdentity {
                uuid: "test-uuid".to_string(),
                ..Default::default()
            },
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
