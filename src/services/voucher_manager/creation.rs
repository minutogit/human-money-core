//! # Voucher Creation
//!
//! Handles the creation of new vouchers and their initial "init" transaction.

use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::models::voucher::{
    Collateral, Transaction, ValueDefinition, Voucher, VoucherSignature, VoucherStandard,
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{
    derive_ephemeral_key_pair, get_hash, get_hash_from_slices, get_prefix_from_user_id, sign_ed25519,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::{decimal_utils, standard_manager};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand::Rng;
use rust_decimal::Decimal;
use std::str::FromStr;
use super::VoucherManagerError;
use super::date_utils::{add_iso8601_duration, round_up_date};

/// Deserializes a JSON string into a `Voucher` struct.
pub fn from_json(json_str: &str) -> Result<Voucher, VoucherCoreError> {
    let voucher: Voucher = serde_json::from_str(json_str)?;
    Ok(voucher)
}

/// Serializes a `Voucher` struct into a formatted JSON string.
pub fn to_json(voucher: &Voucher) -> Result<String, VoucherCoreError> {
    let json_str = serde_json::to_string_pretty(voucher)?;
    Ok(json_str)
}

/// Helper structure bundling all necessary data for creating a new voucher.
#[derive(Default, Clone)]
pub struct NewVoucherData {
    pub validity_duration: Option<String>,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: ValueDefinition,
    pub collateral: Option<Collateral>,
    pub creator_profile: PublicProfile,
}

/// Creates a new, signed `Voucher` struct.
///
/// # Arguments
/// * `data` - The `NewVoucherData` structure with voucher-specific information.
/// * `verified_standard` - The already verified `VoucherStandardDefinition`.
/// * `standard_hash` - The consistency hash of the verified standard.
/// * `creator_signing_key` - The creator's private Ed25519 key for signing.
/// * `lang_preference` - Preferred language code (e.g., "de") for localized texts.
///
/// # Returns
/// A `Result` containing the fully created `Voucher` or a `VoucherCoreError`.
pub fn create_voucher(
    data: NewVoucherData,
    verified_standard: &VoucherStandardDefinition,
    standard_hash: &str,
    creator_signing_key: &SigningKey,
    lang_preference: &str,
) -> Result<Voucher, VoucherCoreError> {
    // SECURITY PATCH: Validate critical template values from standard.
    if verified_standard
        .immutable
        .blueprint
        .unit
        .is_empty()
    {
        return Err(VoucherManagerError::InvalidTemplateValue(
            "immutable.blueprint.unit cannot be empty".to_string(),
        )
        .into());
    }

    let creation_date_str = get_current_timestamp();
    let nonce_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
    let nonce = bs58::encode(nonce_bytes).into_string();
    let creation_dt = DateTime::parse_from_rfc3339(&creation_date_str)
        .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse creation date: {}", e)))?
        .with_timezone(&Utc);

    let duration_str = data
        .validity_duration
        .as_deref()
        .or(verified_standard
            .mutable
            .app_config
            .default_validity_duration
            .as_deref())
        .ok_or_else(|| {
            VoucherManagerError::Generic(
                "No validity duration specified and no default found in standard.".to_string(),
            )
        })?;

    let initial_valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    let min_duration_opt = Some(&verified_standard.immutable.issuance.issuance_minimum_validity_duration);

    // Prevents creation of vouchers that would immediately violate the "firewall" rule.
    if let Some(min_duration_str) = min_duration_opt {
        if !min_duration_str.is_empty() {
            let required_end_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
            if initial_valid_until_dt < required_end_dt {
                return Err(VoucherManagerError::InvalidValidityDuration(format!(
                    "Initial validity ({}) is less than the required minimum standard validity ({}).",
                    initial_valid_until_dt.to_rfc3339(),
                    required_end_dt.to_rfc3339()
                )).into());
            }
        }
    }

    // CHECK MIN RANGE
    if let Some(min_duration_str) = verified_standard.immutable.issuance.validity_duration_range.get(0) {
        if !min_duration_str.is_empty() {
            let min_allowed_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
            if initial_valid_until_dt < min_allowed_dt {
                return Err(VoucherManagerError::InvalidValidityDuration(format!(
                    "Initial validity ({}) is less than the minimum allowed standard validity range ({}).",
                    initial_valid_until_dt.to_rfc3339(),
                    min_allowed_dt.to_rfc3339()
                )).into());
            }
        }
    }

    // CHECK MAX RANGE
    if let Some(max_duration_str) = verified_standard.immutable.issuance.validity_duration_range.get(1) {
        if !max_duration_str.is_empty() {
            let max_allowed_dt = add_iso8601_duration(creation_dt, max_duration_str)?;
            if initial_valid_until_dt > max_allowed_dt {
                return Err(VoucherManagerError::InvalidValidityDuration(format!(
                    "Initial validity ({}) exceeds the maximum allowed standard validity ({}).",
                    initial_valid_until_dt.to_rfc3339(),
                    max_allowed_dt.to_rfc3339()
                )).into());
            }
        }
    }

    let final_valid_until_dt =
        if let Some(rounding_str) = &verified_standard.mutable.app_config.round_up_validity_to {
            round_up_date(initial_valid_until_dt, rounding_str)?
        } else {
            initial_valid_until_dt
        };
    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = verified_standard.immutable.blueprint.unit.clone();

    // Prioritize user-defined abbreviation. Fallback to standard's metadata abbreviation.
    if final_nominal_value.abbreviation.is_none() {
        final_nominal_value.abbreviation = Some(verified_standard.immutable.identity.abbreviation.clone());
    }

    // Collateral is only filled if provided by the user.
    let final_collateral = data.collateral.map(|user_collateral| {
        let col_type_str = serde_json::to_value(&verified_standard.immutable.blueprint.collateral_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        
        Collateral {
            value: user_collateral.value,
            collateral_type: col_type_str,
            redeem_condition: None,
        }
    });

    let description_template = standard_manager::get_localized_text(
        &verified_standard.mutable.i18n.descriptions,
        lang_preference,
    )
    .unwrap_or("");

    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    let voucher_standard = VoucherStandard {
        name: verified_standard.immutable.identity.name.clone(),
        uuid: verified_standard.immutable.identity.uuid.clone(),
        standard_definition_hash: standard_hash.to_string(),
        template: crate::models::voucher::VoucherTemplateData {
            description: final_description.clone(),
            primary_redemption_type: serde_json::to_value(&verified_standard.immutable.blueprint.primary_redemption_type)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default(),
            allow_partial_transfers: verified_standard.immutable.features.allow_partial_transfers,
            issuance_minimum_validity_duration: verified_standard.immutable.issuance.issuance_minimum_validity_duration.clone(),
            footnote: standard_manager::get_localized_text(&verified_standard.mutable.i18n.footnotes, lang_preference).unwrap_or("").to_string(),
        },
    };

    let mut temp_voucher = Voucher {
        voucher_standard,
        voucher_id: "".to_string(),
        voucher_nonce: nonce,
        creation_date: creation_date_str.clone(),
        valid_until: final_valid_until_dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        non_redeemable_test_voucher: data.non_redeemable_test_voucher,
        nominal_value: final_nominal_value,
        collateral: final_collateral,
        creator_profile: data.creator_profile,
        transactions: vec![],
        signatures: vec![],
    };

    let creator_id = temp_voucher
        .creator_profile
        .id
        .as_ref()
        .ok_or_else(|| VoucherManagerError::Generic("Creator profile must have an ID".to_string()))?
        .clone();

    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash = get_hash(voucher_json_for_signing);

    temp_voucher.voucher_id = voucher_hash.clone();

    let mut init_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash: {
            let voucher_id_bytes = bs58::decode(&temp_voucher.voucher_id)
                .into_vec()
                .map_err(|_| VoucherCoreError::Generic("Invalid voucher_id format".to_string()))?;
            let nonce_bytes = bs58::decode(&temp_voucher.voucher_nonce)
                .into_vec()
                .map_err(|_| {
                    VoucherCoreError::Generic("Invalid voucher_nonce format".to_string())
                })?;
            get_hash_from_slices(&[&voucher_id_bytes, &nonce_bytes])
        },
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: Some(creator_id.clone()), // Init is always public
        recipient_id: creator_id.clone(),    // Init goes to the creator themselves
        amount: "".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: {
            let retention_period = verified_standard.mutable.app_config.server_history_retention.as_ref();

            if let Some(duration) = retention_period {
                add_iso8601_duration(final_valid_until_dt, duration)
                    .ok()
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
            } else {
                Some(temp_voucher.valid_until.clone())
            }
        },
        change_ephemeral_pub_hash: None,
        sender_identity_signature: None,
    };

    let decimal_places = verified_standard.immutable.features.amount_decimal_places as u32;

    let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;
    init_transaction.amount = decimal_utils::format_for_storage(&initial_amount, decimal_places);

    let creator_prefix = get_prefix_from_user_id(&creator_id);
    let (genesis_secret, genesis_public) = derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_bytes,
        "genesis",
        creator_prefix,
    )?;
    let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();
    init_transaction.sender_ephemeral_pub = Some(genesis_pub_str.clone());

    let (_, holder_public) = derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_bytes,
        "holder",
        creator_prefix,
    )?;
    let holder_anchor_hash = get_hash(holder_public.to_bytes());
    init_transaction.receiver_ephemeral_pub_hash = Some(holder_anchor_hash);

    let tx_json_for_id = to_canonical_json(&init_transaction)?;
    let init_t_id = get_hash(tx_json_for_id);
    init_transaction.t_id = init_t_id.clone();

    // Signature Logic
    let mut creator_sig_obj = VoucherSignature {
        voucher_id: voucher_hash.clone(),
        signature_id: "".to_string(),
        signer_id: creator_id.clone(),
        signature: "".to_string(),
        signature_time: creation_date_str.clone(),
        role: "creator".to_string(),
        details: None,
    };

    creator_sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&creator_sig_obj)?.as_bytes(),
        init_t_id.as_bytes(),
    ]);
    let creator_signature =
        sign_ed25519(creator_signing_key, creator_sig_obj.signature_id.as_bytes());
    creator_sig_obj.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // L2 & IDENTITY SIGNATURES
    let t_id_raw = bs58::decode(&init_transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;

    let sender_pub_raw = bs58::decode(&genesis_pub_str).into_vec().map_err(|_| {
        VoucherCoreError::InvalidHashFormat("Invalid genesis_pub format".to_string())
    })?;

    let v_id = crate::services::l2_gateway::calculate_layer2_voucher_id(&init_transaction)?;
    let challenge_ds_tag = init_transaction.t_id.clone();

    let receiver_hash_str = init_transaction
        .receiver_ephemeral_pub_hash
        .as_ref()
        .ok_or_else(|| {
            VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(
                "Genesis transaction missing receiver_ephemeral_pub_hash".to_string(),
            ))
        })?;
    let receiver_hash_raw = bs58::decode(receiver_hash_str)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid receiver hash".to_string()))?;

    let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
        vec.try_into()
            .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
    };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &v_id,
        &to_32_bytes(t_id_raw.clone(), "t_id")?,
        &to_32_bytes(sender_pub_raw.clone(), "sender_pub")?,
        Some(&to_32_bytes(receiver_hash_raw.clone(), "receiver_hash")?),
        None,
        init_transaction.deletable_at.as_deref(),
    );

    let l2_sig_bytes = sign_ed25519(&genesis_secret, &payload_hash);
    init_transaction.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

    let identity_sig_bytes = sign_ed25519(creator_signing_key, &t_id_raw);
    init_transaction.sender_identity_signature =
        Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());

    temp_voucher.signatures.push(creator_sig_obj);
    temp_voucher.transactions.push(init_transaction);

    Ok(temp_voucher)
}
