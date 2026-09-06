use crate::models::voucher_standard_definition::{SignatureBlock, VoucherStandardDefinition};
use crate::services::crypto::{get_hash, sign_ed25519};
use crate::services::utils::to_canonical_json;
use super::{ACTORS, TEST_ISSUER};
use ed25519_dalek::Signer;
use lazy_static::lazy_static;
use std::path::PathBuf;
use toml;

lazy_static! {
    /// Loads the Minuto standard and signs it at runtime for tests.
    pub static ref MINUTO_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../../voucher_standards/minuto_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse Minuto TOML template for tests");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Minuto standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };

    /// Loads the FreeTaler standard and signs it at runtime for tests.
    pub static ref FREETALER_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer = &TEST_ISSUER;
        let toml_str = include_str!("../../voucher_standards/freetaler_v1/standard.toml");

        let mut standard: VoucherStandardDefinition = toml::from_str(toml_str)
            .expect("Failed to parse FreeTaler TOML template for tests");

        standard.signature = None;
        let canonical_json = to_canonical_json(&standard).unwrap();
        let hash = get_hash(canonical_json.as_bytes());
        let signature = sign_ed25519(&issuer.identity.signing_key, hash.as_bytes());
        standard.signature = Some(SignatureBlock { issuer_id: issuer.identity.user_id.clone(), signature: bs58::encode(signature.to_bytes()).into_string() });
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };

    /// Loads the `required_signatures` test standard and signs it at runtime.
    pub static ref REQUIRED_SIG_STANDARD: (VoucherStandardDefinition, String) = {
        let issuer_for_signing = &TEST_ISSUER;
        let toml_str = include_str!("../../tests/test_data/standards/standard_required_signatures.toml");

        let mut standard_value: toml::Value = toml::from_str(toml_str)
            .expect("Failed to parse Required Sig TOML as toml::Value");

        let correct_issuer_id = ACTORS.issuer.user_id.clone();
        let correct_charlie_id = ACTORS.charlie.user_id.clone();

        if let Some(toml::Value::Table(validation)) = standard_value.get_mut("validation")
            && let Some(toml::Value::Array(sig_rules)) = validation.get_mut("required_signatures")
        {
            for rule_value in sig_rules.iter_mut() {
                if let Some(rule) = rule_value.as_table_mut()
                    && let Some(toml::Value::String(desc)) = rule.get("role_description")
                    && desc == "Official stamp from the authority"
                {
                    let new_allowed_ids = toml::Value::Array(vec![
                        toml::Value::String(correct_issuer_id.clone()),
                        toml::Value::String(correct_charlie_id.clone()),
                    ]);
                    rule.insert("allowed_signer_ids".to_string(), new_allowed_ids);
                    break;
                }
            }
        }

        let mut standard: VoucherStandardDefinition = standard_value.try_into()
            .expect("Failed to deserialize modified TOML value into VoucherStandardDefinition");

        standard.signature = None;
        let canonical_json_for_signing = to_canonical_json(&standard)
            .expect("Failed to create canonical JSON for Required Sig standard");
        let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

        let signature = sign_ed25519(&issuer_for_signing.identity.signing_key, hash_to_sign.as_bytes());
        let signature_block = SignatureBlock {
            issuer_id: issuer_for_signing.identity.user_id.clone(),
            signature: bs58::encode(signature.to_bytes()).into_string(),
        };
        standard.signature = Some(signature_block);
        let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
        let logic_hash = get_hash(canonical_json_immutable.as_bytes());
        (standard, logic_hash)
    };
}

#[allow(dead_code)]
pub fn generate_signed_standard_toml(template_path: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut absolute_path = PathBuf::from(manifest_dir);
    absolute_path.push(template_path);

    let issuer = &TEST_ISSUER;
    let toml_str = std::fs::read_to_string(&absolute_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read TOML template at '{:?}': {}",
            absolute_path, e
        )
    });

    let mut standard: VoucherStandardDefinition =
        toml::from_str(&toml_str).expect("Failed to parse TOML template for signing");

    standard.signature = None;
    let canonical_json_for_signing =
        to_canonical_json(&standard).expect("Failed to create canonical JSON for standard");
    let hash_to_sign = get_hash(canonical_json_for_signing.as_bytes());

    let signature = sign_ed25519(&issuer.identity.signing_key, hash_to_sign.as_bytes());
    let signature_block = SignatureBlock {
        issuer_id: issuer.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    };
    standard.signature = Some(signature_block);

    toml::to_string(&standard).expect("Failed to serialize standard back to TOML string")
}

#[allow(dead_code)]
pub fn create_custom_standard(
    base_standard: &VoucherStandardDefinition,
    modifier: impl FnOnce(&mut VoucherStandardDefinition),
) -> (VoucherStandardDefinition, String) {
    let mut standard = base_standard.clone();
    modifier(&mut standard);

    standard.signature = None;
    let canonical_json = to_canonical_json(&standard).unwrap();
    let hash = get_hash(canonical_json.as_bytes());

    let signature = TEST_ISSUER
        .identity
        .signing_key
        .sign(hash.as_bytes());

    standard.signature = Some(SignatureBlock {
        issuer_id: TEST_ISSUER.identity.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });

    let canonical_json_immutable = to_canonical_json(&standard.immutable).unwrap();
    let logic_hash = get_hash(canonical_json_immutable.as_bytes());

    (standard, logic_hash)
}
