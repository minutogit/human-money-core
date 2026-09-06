//! # voucher.rs
//!
//! Defines the core data structures for the universal voucher container format.
//! These structures exactly map the JSON schema defined in `llm-context.md`
//! and use `serde` for serialization and deserialization.

use crate::error::VoucherCoreError;
use crate::models::profile::{PublicProfile, UserIdentity};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use ed25519_dalek::SigningKey;
use rand::Rng;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Helper structure bundling all necessary data for creating a new voucher.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct NewVoucherData {
    pub validity_duration: Option<String>,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: ValueDefinition,
    pub collateral: Option<Collateral>,
    pub creator_profile: PublicProfile,
}

/// Contains the sensitive secrets generated during transaction creation.
/// These MUST be securely stored by the caller (Wallet) as they are only
/// present in the voucher in encrypted or hashed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionSecrets {
    pub recipient_seed: String,      // BS58 encoded seed for the recipient
    pub change_seed: Option<String>, // BS58 encoded seed for change (if split)
}

/// The ID used for anonymous participants in transactions.
pub const ANONYMOUS_ID: &str = "anonymous";

/// Defines the standard to which a voucher belongs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherStandard {
    /// The name of the standard (e.g. "Minuto-Gutschein").
    pub name: String,
    /// The unique identifier (UUID) of the standard.
    pub uuid: String,
    /// The hash of the canonicalized standard definition binding this voucher to a specific version.
    pub standard_definition_hash: String,
}

/// Defines a value (amount and unit),
/// used for nominal values or collateral.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct ValueDefinition {
    pub unit: String,
    pub amount: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub abbreviation: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Defines the (optional) collateral/backing of a voucher (extension point for physical assets or fiat).
///
/// Design note:
/// For standards using `collateral_type = "personal_guarantee"` (e.g. Minuto), this object remains
/// `None` by default, as the backing is natively represented via the cryptographic signatures
/// of guarantors (`signatures`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct Collateral {
    /// The fields 'unit', 'amount', 'abbreviation', 'description'
    /// are embedded directly from ValueDefinition.
    #[serde(flatten)]
    pub value: ValueDefinition,

    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub collateral_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub redeem_condition: Option<String>,
}

/// Detailed address information.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Address {
    /// Street.
    pub street: String,
    /// House number.
    pub house_number: String,
    /// Postal code.
    pub zip_code: String,
    /// City.
    pub city: String,
    /// Country.
    pub country: String,
    /// Full, formatted address.
    pub full_address: String,
}

/// Data for the identity trap (fraud detection).
///
/// # V3 Protocol (Shared-Signature Trap / SST)
/// A transaction stores only its *shard* of a shared Schnorr signature
/// $\sigma = (R_{sig}, s_{sig})$ over the spend input:
///
/// - `trap_r` = $R_i = R_{sig} + \tau_i \cdot M_R$ (32 bytes, Base58)
/// - `trap_s` = $s_i = s_{sig} + \tau_i \cdot m_s \pmod q$ (32 bytes, Base58)
///
/// where $\tau_i = H(\text{"HMC\_TAU\_V1"} \parallel ds\_tag \parallel t\_id)$
/// and $(M_R, m_s)$ are masking values derived exclusively from the sender's
/// long-term key. Before a collision each shard is information-theoretically
/// anonymous (4 unknowns); two colliding shards reconstruct the underlying
/// Schnorr signature and mathematically reveal the offender's `did:key`
/// identity with EUF-CMA security (no framing possible).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TrapData {
    pub ds_tag: String,
    /// The spend-specific commitment shard $R_i$ (compressed point, Base58).
    #[serde(default)]
    pub trap_r: String,
    /// The spend-specific response shard $s_i$ (canonical scalar, Base58).
    #[serde(default)]
    pub trap_s: String,
}

/// The decrypted payload of the privacy guard.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct RecipientPayload {
    /// The sender's full composite DID.
    pub sender_permanent_did: String,
    /// The target prefix (e.g. "creator:fY7") for validation.
    pub target_prefix: String,
    /// Timestamp of creation.
    pub timestamp: u64,
    /// The seed for the next ephemeral key.
    pub next_key_seed: String,
    /// The public point K of the identity trap derived from sender_permanent_key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap_k_point: Option<String>,
    /// Challenge c component of the DLEQ proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dleq_c: Option<String>,
    /// Response s component of the DLEQ proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dleq_s: Option<String>,
    /// # V3 Protocol (SST): private trap witness $\sigma = (R_{sig}, s_{sig})$
    /// The Schnorr commitment over the spend input (32 bytes, Base58).
    /// Handed over privately at L1 so the recipient can reject garbage traps
    /// immediately (fraud *prevention* at handover, R5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_r_sig: Option<String>,
    /// The Schnorr response over the spend input (32 bytes, Base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_s_sig: Option<String>,
    /// The masking point $M_R$ of the shared-signature trap (Base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_m_r: Option<String>,
    /// The masking scalar $m_s$ of the shared-signature trap (Base58).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_m_s: Option<String>,
}

/// Represents a single transaction in the voucher's transaction chain.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Transaction {
    /// Unique ID of the transaction.
    pub t_id: String,
    /// Type of transaction. Empty for a full transfer, "init" for creation, "split" for partial amounts.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub t_type: String,
    /// Timestamp of the transaction in ISO 8601 format.
    pub t_time: String,

    // --- TECHNICAL LAYER (Layer 2 - Always present) ---
    /// The hash of the previous private-public key or transaction hash.
    pub prev_hash: String,

    /// The hash of the recipient's ephemeral public key (private key).
    /// ALWAYS exists, even if recipient_id is public.
    /// Option only for backward compatibility or init special cases,
    /// but now mandatory in the standard flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receiver_ephemeral_pub_hash: Option<String>,

    // --- SOCIAL LAYER (Layer 1 - Dependent on Privacy Mode) ---
    /// ID of the transaction sender.
    /// Optional, dependent on Privacy Mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<String>,

    /// The signature executed by the identity key (sender_id).
    /// Must be present if sender_id is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_identity_signature: Option<String>,

    /// ID of the transaction recipient.
    /// Can be public (did:key) or anonymized.
    pub recipient_id: String,

    /// The amount moved in this transaction.
    pub amount: String,
    /// The remaining amount with the sender after a split. Only present for `t_type: "split"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_remaining_amount: Option<String>,

    // --- Layer 2 & Privacy Fields ---
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_ephemeral_pub: Option<String>, // The revealed key (preimage) for L2 signature

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_ephemeral_pub_hash: Option<String>, // The anchor hash for change amount

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy_guard: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap_data: Option<TrapData>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer2_signature: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletable_at: Option<String>,
}

/// Represents a universal signature (formerly AdditionalSignature)
/// attached to the voucher. It can be semantically distinguished
/// via the `role` field (e.g. "guarantor").
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct VoucherSignature {
    /// The unique ID of the voucher to which this signature refers.
    pub voucher_id: String,
    /// The unique ID of this signature.
    pub signature_id: String,
    /// Unique ID of the additional signer.
    pub signer_id: String,

    /// The digital signature.
    pub signature: String,
    /// Timestamp of the signature in ISO 8601 format.
    pub signature_time: String,
    /// Defines the role or purpose of this signature (e.g. "guarantor", "notary").
    pub role: String,

    /// Optional detailed profile information about the signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<PublicProfile>,
}

/// The main struct representing the universal voucher container.
/// It combines all other structures and fields according to the general JSON schema.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Voucher {
    /// Defines the standard followed by this voucher.
    pub voucher_standard: VoucherStandard,
    /// The unique ID of this specific voucher.
    pub voucher_id: String,
    /// A random nonce to make the first `prev_hash` unpredictable.
    pub voucher_nonce: String,
    /// The creation date of the voucher in ISO 8601 format.
    pub creation_date: String,
    /// The expiration date of the voucher in ISO 8601 format.
    pub valid_until: String,
    /// A flag indicating whether this is a non-redeemable test voucher.
    pub non_redeemable_test_voucher: bool,
    /// Defines the nominal value of the voucher.
    pub nominal_value: ValueDefinition,
    /// Optional collateral/backing information for the voucher (typically `None` for personal_guarantee).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral: Option<Collateral>,
    /// Detailed information about the creator of the voucher.
    #[serde(rename = "creator")]
    pub creator_profile: PublicProfile,
    /// A chronological list of all transactions of this voucher.
    pub transactions: Vec<Transaction>,
    /// An array for all signatures (incl. guarantors).
    pub signatures: Vec<VoucherSignature>,
}

impl ValueDefinition {
    /// Validates that the scale/precision of `amount` does not exceed the allowed decimal places of this value.
    pub fn validate_precision(&self, amount: &Decimal) -> Result<(), VoucherCoreError> {
        let allowed = Decimal::from_str(&self.amount)?.scale();
        if amount.scale() > allowed {
            Err(VoucherCoreError::AmountPrecisionExceeded {
                allowed,
                found: amount.scale(),
            })
        } else {
            Ok(())
        }
    }

    /// Formats the given `amount` with the canonical decimal places of this value definition.
    pub fn format_amount(&self, amount: &Decimal) -> String {
        let allowed = Decimal::from_str(&self.amount)
            .map(|d| d.scale())
            .unwrap_or(0);
        format!("{:.1$}", amount, allowed as usize)
    }
}

impl Voucher {
    /// Creates a new `Voucher` using the given identity.
    pub fn create(
        identity: &UserIdentity,
        standard: &VoucherStandardDefinition,
        standard_hash: &str,
        mut data: NewVoucherData,
    ) -> Result<Self, VoucherCoreError> {
        if data.creator_profile.id.is_none() {
            data.creator_profile.id = Some(identity.user_id.clone());
        }
        Self::create_with_key(data, standard, standard_hash, &identity.signing_key)
    }

    /// Creates a new `Voucher` using the creator's signing key.
    pub fn create_with_key(
        data: NewVoucherData,
        verified_standard: &VoucherStandardDefinition,
        standard_hash: &str,
        creator_signing_key: &SigningKey,
    ) -> Result<Self, VoucherCoreError> {
        if verified_standard
            .immutable
            .blueprint
            .unit
            .is_empty()
        {
            return Err(VoucherCoreError::InvalidTemplateValue(
                "immutable.blueprint.unit cannot be empty".to_string(),
            ));
        }

        let creation_date_str = crate::services::utils::get_current_timestamp();
        let nonce_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
        let nonce = bs58::encode(nonce_bytes).into_string();
        let creation_dt = chrono::DateTime::parse_from_rfc3339(&creation_date_str)
            .map_err(|e| crate::Error::Wallet(crate::error::WalletError::InvalidCreationDate { reason: format!("Failed to parse creation date: {}", e) }))?
            .with_timezone(&chrono::Utc);

        let duration_str = data
            .validity_duration
            .as_deref()
            .or(verified_standard
                .mutable
                .app_config
                .default_validity_duration
                .as_deref())
            .ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::InvalidDuration { reason: 
                    "No validity duration specified and no default found in standard.".to_string(),
                 })
            })?;

        let initial_valid_until_dt = crate::services::utils::add_iso8601_duration(creation_dt, duration_str)?;

        let min_duration_opt = Some(&verified_standard.immutable.issuance.issuance_minimum_validity_duration);

        if let Some(min_duration_str) = min_duration_opt
            && !min_duration_str.is_empty() {
                let required_end_dt = crate::services::utils::add_iso8601_duration(creation_dt, min_duration_str)?;
                if initial_valid_until_dt < required_end_dt {
                    return Err(VoucherCoreError::InvalidValidityDuration(format!(
                        "Initial validity ({}) is less than the required minimum standard validity ({}).",
                        initial_valid_until_dt.to_rfc3339(),
                        required_end_dt.to_rfc3339()
                    )));
                }
            }

        if let Some(min_duration_str) = verified_standard.immutable.issuance.validity_duration_range.first()
            && !min_duration_str.is_empty() {
                let min_allowed_dt = crate::services::utils::add_iso8601_duration(creation_dt, min_duration_str)?;
                if initial_valid_until_dt < min_allowed_dt {
                    return Err(VoucherCoreError::InvalidValidityDuration(format!(
                        "Initial validity ({}) is less than the minimum allowed standard validity range ({}).",
                        initial_valid_until_dt.to_rfc3339(),
                        min_allowed_dt.to_rfc3339()
                    )));
                }
            }

        if let Some(max_duration_str) = verified_standard.immutable.issuance.validity_duration_range.get(1)
            && !max_duration_str.is_empty() {
                let max_allowed_dt = crate::services::utils::add_iso8601_duration(creation_dt, max_duration_str)?;
                if initial_valid_until_dt > max_allowed_dt {
                    return Err(VoucherCoreError::InvalidValidityDuration(format!(
                        "Initial validity ({}) exceeds the maximum allowed standard validity ({}).",
                        initial_valid_until_dt.to_rfc3339(),
                        max_allowed_dt.to_rfc3339()
                    )));
                }
            }

        let final_valid_until_dt =
            if let Some(rounding_str) = &verified_standard.mutable.app_config.round_up_validity_to {
                crate::services::utils::round_up_date(initial_valid_until_dt, rounding_str)?
            } else {
                initial_valid_until_dt
            };
        let mut final_nominal_value = data.nominal_value;
        final_nominal_value.unit = verified_standard.immutable.blueprint.unit.clone();

        if final_nominal_value.abbreviation.is_none() {
            final_nominal_value.abbreviation = Some(verified_standard.immutable.identity.abbreviation.clone());
        }

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

        let voucher_standard = VoucherStandard {
            name: verified_standard.immutable.identity.name.clone(),
            uuid: verified_standard.immutable.identity.uuid.clone(),
            standard_definition_hash: standard_hash.to_string(),
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
            .ok_or_else(|| crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: "Creator profile must have an ID".to_string() }))?
            .clone();

        let voucher_json_for_signing = crate::services::utils::to_canonical_json(&temp_voucher)?;
        let voucher_hash = crate::services::crypto::get_hash(voucher_json_for_signing);

        temp_voucher.voucher_id = voucher_hash.clone();

        let mut init_transaction = Transaction {
            t_id: "".to_string(),
            prev_hash: {
                let voucher_id_bytes = bs58::decode(&temp_voucher.voucher_id)
                    .into_vec()
                    .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid voucher_id format".to_string()))?;
                let nonce_bytes = bs58::decode(&temp_voucher.voucher_nonce)
                    .into_vec()
                    .map_err(|_| {
                        VoucherCoreError::InvalidHashFormat("Invalid voucher_nonce format".to_string())
                    })?;
                crate::services::crypto::get_hash_from_slices(&[&voucher_id_bytes, &nonce_bytes])
            },
            t_type: "init".to_string(),
            t_time: creation_date_str.clone(),
            sender_id: Some(creator_id.clone()),
            recipient_id: creator_id.clone(),
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
                    crate::services::utils::add_iso8601_duration(final_valid_until_dt, duration)
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
        init_transaction.amount = format!("{:.1$}", initial_amount, decimal_places as usize);

        let creator_prefix = crate::services::crypto::get_prefix_from_user_id(&creator_id);
        let (genesis_secret, genesis_public) = crate::services::crypto::derive_ephemeral_key_pair(
            creator_signing_key,
            &nonce_bytes,
            "genesis",
            creator_prefix,
        )?;
        let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();
        init_transaction.sender_ephemeral_pub = Some(genesis_pub_str.clone());

        let (_, holder_public) = crate::services::crypto::derive_ephemeral_key_pair(
            creator_signing_key,
            &nonce_bytes,
            "holder",
            creator_prefix,
        )?;
        let holder_anchor_hash = crate::services::crypto::get_hash(holder_public.to_bytes());
        init_transaction.receiver_ephemeral_pub_hash = Some(holder_anchor_hash);

        let tx_json_for_id = crate::services::utils::to_canonical_json(&init_transaction)?;
        let init_t_id = crate::services::crypto::get_hash(tx_json_for_id);
        init_transaction.t_id = init_t_id.clone();

        let mut creator_sig_obj = VoucherSignature {
            voucher_id: voucher_hash.clone(),
            signature_id: "".to_string(),
            signer_id: creator_id.clone(),
            signature: "".to_string(),
            signature_time: creation_date_str.clone(),
            role: "creator".to_string(),
            details: None,
        };

        creator_sig_obj.signature_id = crate::services::crypto::get_hash_from_slices(&[
            crate::services::utils::to_canonical_json(&creator_sig_obj)?.as_bytes(),
            init_t_id.as_bytes(),
        ]);
        let creator_signature =
            crate::services::crypto::sign_ed25519(creator_signing_key, creator_sig_obj.signature_id.as_bytes());
        creator_sig_obj.signature = bs58::encode(creator_signature.to_bytes()).into_string();

        let t_id_raw = bs58::decode(&init_transaction.t_id)
            .into_vec()
            .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;

        let sender_pub_raw = bs58::decode(&genesis_pub_str).into_vec().map_err(|_| {
            VoucherCoreError::InvalidHashFormat("Invalid genesis_pub format".to_string())
        })?;

        let challenge_ds_tag = init_transaction.t_id.clone();

        let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
            vec.try_into()
                .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
        };

        let encrypted_timestamp =
            crate::services::conflict_manager::encrypt_transaction_timestamp(&init_transaction)?;

        let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
            &challenge_ds_tag,
            &to_32_bytes(t_id_raw.clone(), "t_id")?,
            &to_32_bytes(sender_pub_raw.clone(), "sender_pub")?,
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
            encrypted_timestamp,
            init_transaction.deletable_at.as_deref(),
            "",
        );

        let l2_sig_bytes = crate::services::crypto::sign_ed25519(&genesis_secret, &payload_hash);
        init_transaction.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

        let identity_sig_bytes = crate::services::crypto::sign_ed25519(creator_signing_key, &t_id_raw);
        init_transaction.sender_identity_signature =
            Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());

        temp_voucher.signatures.push(creator_sig_obj);
        temp_voucher.transactions.push(init_transaction);

        Ok(temp_voucher)
    }

    /// Creates a new transaction on this voucher.
    #[allow(clippy::too_many_arguments)]
    pub fn create_transaction(
        &self,
        standard: &VoucherStandardDefinition,
        sender_id: &str,
        sender_permanent_key: &SigningKey,
        sender_ephemeral_key: &SigningKey,
        recipient_id: &str,
        amount_to_send_str: &str,
        use_privacy_mode: Option<bool>,
    ) -> Result<(Voucher, TransactionSecrets), VoucherCoreError> {
        crate::services::voucher_validation::validate_voucher_against_standard(self, standard)?;

        self.validate_issuance_firewall(standard, sender_id, recipient_id)?;

        let decimal_places = standard.immutable.features.amount_decimal_places as u32;

        let revealed_pub_bytes = sender_ephemeral_key.verifying_key().to_bytes();
        let revealed_pub_hash = crate::services::crypto::get_hash(revealed_pub_bytes);
        
        let spendable_balance = self.spendable_balance_for_user(
            sender_id, 
            standard, 
            Some(&revealed_pub_hash)
        )?;

        let amount_to_send = Decimal::from_str(amount_to_send_str)?;
        if amount_to_send.scale() > decimal_places {
            return Err(VoucherCoreError::AmountPrecisionExceeded {
                allowed: decimal_places,
                found: amount_to_send.scale(),
            });
        }

        if amount_to_send <= Decimal::ZERO {
            return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                "Transaction amount must be positive.".to_string(),
             }));
        }
        if amount_to_send > spendable_balance {
            return Err(VoucherCoreError::InsufficientFunds {
                available: spendable_balance,
                needed: amount_to_send,
            });
        }

        let (t_type, sender_remaining_amount) = if amount_to_send < spendable_balance {
            if !standard.immutable.features.allow_partial_transfers {
                return Err(VoucherCoreError::VoucherPartialTransferNotAllowed);
            }
            let remaining = spendable_balance - amount_to_send;
            (
                "split".to_string(),
                Some(format!("{:.1$}", remaining, decimal_places as usize)),
            )
        } else {
            ("transfer".to_string(), None)
        };

        if !standard.immutable.features.allowed_t_types.contains(&t_type) {
            return Err(crate::error::ValidationError::TransactionTypeNotAllowed {
                t_type,
                allowed: standard.immutable.features.allowed_t_types.clone(),
            }
            .into());
        }

        let prev_hash = crate::services::crypto::get_hash(
            crate::services::utils::to_canonical_json(self.transactions.last().unwrap())?
        );
        let t_time = crate::services::utils::get_current_timestamp();

        let (final_sender_id, recipient_id_check) = match standard.immutable.features.privacy_mode {
            crate::models::voucher_standard_definition::PrivacyMode::Stealth => {
                (None, ANONYMOUS_ID.to_string())
            }
            crate::models::voucher_standard_definition::PrivacyMode::Flexible => {
                let actually_private = use_privacy_mode.unwrap_or(false);
                let s_id = if actually_private { None } else { Some(sender_id.to_string()) };
                (s_id, ANONYMOUS_ID.to_string())
            }
            crate::models::voucher_standard_definition::PrivacyMode::Public => {
                if use_privacy_mode.unwrap_or(false) {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                        "Cannot use privacy mode on a public standard".to_string(),
                     }));
                }
                let recipient_is_did = recipient_id.starts_with("did:") || recipient_id.contains("@did:");
                if !recipient_is_did {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                        "Public mode requires DID recipient.".to_string(),
                     }));
                }
                if sender_id == ANONYMOUS_ID {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                        "Public mode forbids anonymous sender.".to_string(),
                     }));
                }
                (Some(sender_id.to_string()), recipient_id.to_string())
            }
        };

        let sender_ephemeral_pub =
            bs58::encode(sender_ephemeral_key.verifying_key().to_bytes()).into_string();

        let mut recipient_seed = [0u8; 32];
        rand::thread_rng().fill(&mut recipient_seed);
        let recipient_signing_key = SigningKey::from_bytes(&recipient_seed);
        let recipient_ephemeral_pub = recipient_signing_key.verifying_key();
        let receiver_ephemeral_pub_hash = Some(crate::services::crypto::get_hash(recipient_ephemeral_pub.to_bytes()));

        let (change_ephemeral_pub_hash, change_key_seed_opt) = if t_type == "split" {
            let sender_id_prefix = crate::services::crypto::get_prefix_from_user_id(sender_id);

            let salt = prev_hash.as_bytes();
            let ikm = sender_permanent_key.to_bytes();
            let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), &ikm);
            let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(&prk)
                .map_err(|_| VoucherCoreError::Crypto("Invalid PRK length".to_string()))?;

            let info = if let Some(p) = sender_id_prefix {
                format!("{}change_seed", p)
            } else {
                "change_seed".to_string()
            };
            let mut change_seed = [0u8; 32];
            hkdf.expand(info.as_bytes(), &mut change_seed)
                .map_err(|_| {
                    VoucherCoreError::Crypto("HKDF expand failed for change seed".to_string())
                })?;

            let change_signing_key = SigningKey::from_bytes(&change_seed);
            let change_pub = change_signing_key.verifying_key();
            let change_hash = crate::services::crypto::get_hash(change_pub.to_bytes());
            (
                Some(change_hash),
                Some(bs58::encode(change_seed).into_string()),
            )
        } else {
            (None, None)
        };

        let prev_hash_bytes = bs58::decode(&prev_hash)
            .into_vec()
            .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
        let sender_ephem_pub_bytes = bs58::decode(&sender_ephemeral_pub)
            .into_vec()
            .map_err(|_| VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string()))?;

        let ds_tag = crate::services::crypto::get_hash_from_slices(&[&prev_hash_bytes, &sender_ephem_pub_bytes]);
        let amount_str = format!("{:.1$}", amount_to_send, decimal_places as usize);

        let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
            vec.try_into()
                .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
        };

        let mut new_transaction = Transaction {
            t_id: "".to_string(),
            prev_hash: prev_hash.clone(),
            t_type,
            t_time,
            sender_id: final_sender_id,
            recipient_id: recipient_id_check.to_string(),
            amount: amount_str,
            sender_remaining_amount,
            receiver_ephemeral_pub_hash,
            sender_ephemeral_pub: Some(sender_ephemeral_pub.clone()),
            privacy_guard: None,
            trap_data: None,
            layer2_signature: None,
            deletable_at: None,
            change_ephemeral_pub_hash,
            sender_identity_signature: None,
        };

        let tx_json_for_id = crate::services::utils::to_canonical_json(&new_transaction)?;
        new_transaction.t_id = crate::services::crypto::get_hash(tx_json_for_id);

        let eph_pub_32 = to_32_bytes(sender_ephem_pub_bytes, "sender_ephemeral_pub")?;
        let (sst_trap, sst_witness) =
            crate::services::trap_manager::generate_sst_trap(
                sender_permanent_key,
                &ds_tag,
                &eph_pub_32,
                &new_transaction.t_id,
            )?;
        new_transaction.trap_data = Some(sst_trap);

        let encoded_recipient_seed = bs58::encode(recipient_seed).into_string();

        let privacy_guard = if recipient_id.contains(":z") {
            let target_prefix = recipient_id
                .split(':')
                .next()
                .unwrap_or("unknown")
                .to_string();

            let payload = RecipientPayload {
                sender_permanent_did: sender_id.to_string(),
                target_prefix,
                timestamp: chrono::Utc::now().timestamp() as u64,
                next_key_seed: encoded_recipient_seed.clone(),
                trap_k_point: None,
                dleq_c: None,
                dleq_s: None,
                trap_r_sig: Some(sst_witness.r_sig),
                trap_s_sig: Some(sst_witness.s_sig),
                trap_m_r: Some(sst_witness.m_r),
                trap_m_s: Some(sst_witness.m_s),
            };

            let (ephemeral_pk, ephemeral_sk) = crate::services::crypto::generate_ephemeral_x25519_keypair();
            let recipient_ed_pk = crate::services::crypto::get_pubkey_from_user_id(recipient_id)?;
            let recipient_x_pk = crate::services::crypto::ed25519_pub_to_x25519(&recipient_ed_pk);
            let shared_secret = crate::services::crypto::perform_diffie_hellman(ephemeral_sk, &recipient_x_pk, recipient_id)?;
            let payload_json = crate::services::utils::to_canonical_json(&payload)?;
            let encrypted_bytes = crate::services::crypto::encrypt_data(&shared_secret, payload_json.as_bytes())?;

            let mut privacy_guard_bytes = Vec::new();
            privacy_guard_bytes.extend_from_slice(ephemeral_pk.as_bytes());
            privacy_guard_bytes.extend_from_slice(&encrypted_bytes);
            Some(crate::services::crypto::encode_base64(&privacy_guard_bytes))
        } else {
            None
        };
        new_transaction.privacy_guard = privacy_guard;

        let t_id_raw = bs58::decode(&new_transaction.t_id)
            .into_vec()
            .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;
        let sender_pub_raw = bs58::decode(&sender_ephemeral_pub)
            .into_vec()
            .map_err(|_| {
                VoucherCoreError::InvalidHashFormat("Invalid sender_ephemeral_pub format".to_string())
            })?;

        let challenge_ds_tag = ds_tag.clone();

        let trap = new_transaction.trap_data.as_ref().ok_or(VoucherCoreError::MissingTrapData)?;
        let encrypted_timestamp =
            crate::services::conflict_manager::encrypt_transaction_timestamp(&new_transaction)?;
        let l2_voucher_id = crate::services::l2_gateway::extract_layer2_voucher_id(self)?;

        let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
            &l2_voucher_id,
            &challenge_ds_tag,
            &to_32_bytes(t_id_raw.clone(), "t_id")?,
            &to_32_bytes(sender_pub_raw.clone(), "sender_pub")?,
            &trap.trap_r,
            &trap.trap_s,
            encrypted_timestamp,
            new_transaction.deletable_at.as_deref(),
            crate::services::l2_gateway::privacy_guard_commitment(
                new_transaction.privacy_guard.as_deref(),
            )
            .as_str(),
        );

        let l2_sig_bytes = crate::services::crypto::sign_ed25519(sender_ephemeral_key, &payload_hash);
        new_transaction.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

        if new_transaction.sender_id.is_some() {
            let identity_sig_bytes = crate::services::crypto::sign_ed25519(sender_permanent_key, &t_id_raw);
            new_transaction.sender_identity_signature =
                Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());
        }

        let mut new_voucher = self.clone();
        new_voucher.transactions.push(new_transaction);

        crate::services::voucher_validation::validate_voucher_against_standard(&new_voucher, standard)?;

        let secrets = TransactionSecrets {
            recipient_seed: encoded_recipient_seed,
            change_seed: change_key_seed_opt,
        };

        Ok((new_voucher, secrets))
    }

    /// Validates the "Circulation Firewall" (`issuance_minimum_validity_duration`).
    pub fn validate_issuance_firewall(
        &self,
        standard: &VoucherStandardDefinition,
        sender_id: &str,
        recipient_id: &str,
    ) -> Result<(), VoucherCoreError> {
        let min_duration_str = match Some(&standard.immutable.issuance.issuance_minimum_validity_duration) {
            Some(duration) if !duration.is_empty() => duration,
            _ => return Ok(()),
        };

        let creator_id = match &self.creator_profile.id {
            Some(id) => id,
            None => return Ok(()),
        };
        if sender_id != creator_id {
            return Ok(());
        }

        if recipient_id.contains(':') {
            let sender_pk = crate::services::crypto::get_pubkey_from_user_id(sender_id)?;
            let recipient_pk = crate::services::crypto::get_pubkey_from_user_id(recipient_id)?;

            if sender_pk == recipient_pk {
                return Ok(());
            }
        }

        let now_str = crate::services::utils::get_current_timestamp();
        let now = chrono::DateTime::parse_from_rfc3339(&now_str)
            .map_err(|e| crate::Error::Wallet(crate::error::WalletError::InvalidVoucherDate { field: "now".to_string(), reason: format!("Failed to parse now date: {}", e) }))?
            .with_timezone(&chrono::Utc);

        let valid_until_dt = chrono::DateTime::parse_from_rfc3339(&self.valid_until)
            .map_err(|e| crate::Error::Wallet(crate::error::WalletError::InvalidVoucherDate { field: "valid_until".to_string(), reason: format!("Failed to parse voucher valid_until date: {}", e) }))?
            .with_timezone(&chrono::Utc);

        let required_end_dt = crate::services::utils::add_iso8601_duration(now, min_duration_str)?;

        if valid_until_dt < required_end_dt {
            Err(VoucherCoreError::InvalidValidityDuration(format!(
                "Issuance failed: Voucher validity ({}) is less than the required minimum remaining duration ({} from now).",
                valid_until_dt.to_rfc3339(),
                required_end_dt.to_rfc3339()
            )))
        } else {
            Ok(())
        }
    }

    /// Calculates the spendable balance of this voucher as of a given timestamp for a given identity.
    pub fn spendable_balance(
        &self,
        as_of: Option<&str>,
        identity: Option<&UserIdentity>,
    ) -> Decimal {
        if self.transactions.is_empty() {
            return Decimal::ZERO;
        }

        let txs: Vec<&Transaction> = if let Some(as_of_time) = as_of {
            self.transactions
                .iter()
                .filter(|tx| tx.t_time.as_str() <= as_of_time)
                .collect()
        } else {
            self.transactions.iter().collect()
        };

        let last_tx = match txs.last() {
            Some(tx) => *tx,
            None => return Decimal::ZERO,
        };

        if let Some(id) = identity {
            let mut holder_match = false;
            let mut change_match = false;

            // A) Check receiver key via Privacy Guard (Stealth mode)
            if let Some(guard_base64) = &last_tx.privacy_guard
                && let Ok(decrypted_payload_bytes) = crate::services::crypto::decrypt_recipient_payload(
                    guard_base64,
                    &id.signing_key,
                    &id.user_id,
                )
                    && let Ok(payload) = serde_json::from_slice::<RecipientPayload>(&decrypted_payload_bytes)
                        && let Ok(seed_bytes) = bs58::decode(&payload.next_key_seed).into_vec()
                            && let Ok(seed_arr) = seed_bytes.try_into() {
                                let candidate_key = SigningKey::from_bytes(&seed_arr);
                                let candidate_hash = crate::services::crypto::get_hash(candidate_key.verifying_key().to_bytes());
                                if Some(&candidate_hash) == last_tx.receiver_ephemeral_pub_hash.as_ref() {
                                    holder_match = true;
                                }
                            }

            // B) Check change key via HKDF (Change mode)
            let sender_id_prefix = crate::services::crypto::get_prefix_from_user_id(&id.user_id);
            let ikm = id.signing_key.to_bytes();
            let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(last_tx.prev_hash.as_bytes()), &ikm);
            if let Ok(hkdf) = hkdf::Hkdf::<sha2::Sha256>::from_prk(&prk) {
                let info = if let Some(p) = sender_id_prefix {
                    format!("{}change_seed", p)
                } else {
                    "change_seed".to_string()
                };
                let mut change_seed = [0u8; 32];
                if hkdf.expand(info.as_bytes(), &mut change_seed).is_ok() {
                    let candidate_key = SigningKey::from_bytes(&change_seed);
                    let candidate_hash = crate::services::crypto::get_hash(candidate_key.verifying_key().to_bytes());
                    if Some(&candidate_hash) == last_tx.change_ephemeral_pub_hash.as_ref() {
                        change_match = true;
                    }
                }
            }

            // C) Init transaction check for creator
            if last_tx.t_type == "init" && (last_tx.recipient_id == id.user_id || last_tx.sender_id.as_ref() == Some(&id.user_id)) {
                holder_match = true;
            }

            // SECURITY (AUDIT-00-WILDCARD-13): If amount parsing fails, return Decimal::MIN
            // as a sentinel rather than Decimal::ZERO to prevent forensic masking where
            // corrupted/malformed transactions would be silently displayed as empty/unfunded.
            if holder_match {
                Decimal::from_str(&last_tx.amount).unwrap_or(Decimal::MIN)
            } else if change_match {
                last_tx.sender_remaining_amount
                    .as_deref()
                    .and_then(|a| Decimal::from_str(a).ok())
                    .unwrap_or(Decimal::MIN)
            } else {
                // Fallback to DID check (Public mode)
                if last_tx.recipient_id == id.user_id {
                    Decimal::from_str(&last_tx.amount).unwrap_or(Decimal::MIN)
                } else if last_tx.sender_id.as_deref() == Some(&id.user_id) {
                    last_tx.sender_remaining_amount
                        .as_deref()
                        .and_then(|a| Decimal::from_str(a).ok())
                        .unwrap_or(Decimal::MIN)
                } else {
                    Decimal::ZERO
                }
            }
        } else {
            // No identity provided: return amount of last transaction.
            // SECURITY (AUDIT-00-WILDCARD-13): Fail-closed with Decimal::MIN on malformed amount strings.
            Decimal::from_str(&last_tx.amount).unwrap_or(Decimal::MIN)
        }
    }

    /// Calculates the spendable balance for a specific user ID against a standard.
    pub fn spendable_balance_for_user(
        &self,
        user_id: &str,
        standard: &VoucherStandardDefinition,
        current_holder_pub_hash: Option<&str>,
    ) -> Result<Decimal, VoucherCoreError> {
        if self.transactions.is_empty() {
            return Ok(Decimal::ZERO);
        }

        match crate::services::voucher_validation::validate_voucher_against_standard(self, standard) {
            Ok(_) => (),
            Err(VoucherCoreError::Validation(_)) => (),
            Err(e) => return Err(e),
        };

        let last_tx = self.transactions.last().unwrap();
        let decimal_places = standard.immutable.features.amount_decimal_places as u32;

        let balance_str = if let Some(hash) = current_holder_pub_hash {
            if Some(hash) == last_tx.receiver_ephemeral_pub_hash.as_deref() {
                &last_tx.amount
            } else if Some(hash) == last_tx.change_ephemeral_pub_hash.as_deref() {
                last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
            } else {
                "0"
            }
        } else {
            if last_tx.t_type == "init" && last_tx.recipient_id == user_id {
                &last_tx.amount
            } else if last_tx.t_type == "init" {
                "0"
            } else if last_tx.sender_id.as_deref() == Some(user_id) {
                last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
            } else if last_tx.recipient_id == user_id {
                &last_tx.amount
            } else {
                "0"
            }
        };

        let balance = Decimal::from_str(balance_str)?;
        Ok(balance.round_dp(decimal_places))
    }

    /// Checks whether this voucher is expired relative to `current_time` (or now if `None`).
    pub fn is_expired(&self, current_time: Option<&str>) -> bool {
        let now_dt = if let Some(ct) = current_time {
            chrono::DateTime::parse_from_rfc3339(ct)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now())
        } else {
            chrono::Utc::now()
        };

        if let Ok(valid_until_dt) = chrono::DateTime::parse_from_rfc3339(&self.valid_until) {
            now_dt > valid_until_dt.with_timezone(&chrono::Utc)
        } else {
            false
        }
    }

    /// Serializes this voucher to pretty JSON.
    pub fn to_json_string(&self) -> Result<String, VoucherCoreError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserializes a voucher from JSON.
    pub fn from_json_str(json_str: &str) -> Result<Self, VoucherCoreError> {
        Ok(serde_json::from_str(json_str)?)
    }
}

impl Transaction {
    /// Creates a new transaction on the given voucher.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        voucher: &Voucher,
        standard: &VoucherStandardDefinition,
        sender_id: &str,
        sender_permanent_key: &SigningKey,
        sender_ephemeral_key: &SigningKey,
        recipient_id: &str,
        amount_to_send_str: &str,
        use_privacy_mode: Option<bool>,
    ) -> Result<(Voucher, TransactionSecrets), VoucherCoreError> {
        voucher.create_transaction(
            standard,
            sender_id,
            sender_permanent_key,
            sender_ephemeral_key,
            recipient_id,
            amount_to_send_str,
            use_privacy_mode,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::PublicProfile;
    use crate::test_utils::standards::FREETALER_STANDARD;
    use crate::test_utils::ACTORS;
    use rust_decimal_macros::dec;

    #[test]
    fn test_value_definition_precision_and_formatting() {
        let val_def = ValueDefinition {
            unit: "MIN".to_string(),
            amount: "100.00".to_string(),
            abbreviation: Some("M".to_string()),
            description: None,
        };

        // Precision checks
        assert!(val_def.validate_precision(&dec!(50.00)).is_ok());
        assert!(val_def.validate_precision(&dec!(50.5)).is_ok());
        assert!(val_def.validate_precision(&dec!(50)).is_ok());
        assert!(val_def.validate_precision(&dec!(50.001)).is_err());

        // Malformed definition amount fails closed (H-02-01)
        let malformed_val_def = ValueDefinition {
            unit: "MIN".to_string(),
            amount: "invalid-num".to_string(),
            abbreviation: None,
            description: None,
        };
        assert!(malformed_val_def.validate_precision(&dec!(50.00)).is_err());

        // Formatting checks
        assert_eq!(val_def.format_amount(&dec!(50)), "50.00");
        assert_eq!(val_def.format_amount(&dec!(50.5)), "50.50");
    }

    #[test]
    fn test_voucher_expiration() {
        let mut voucher = Voucher::default();
        voucher.valid_until = "2025-01-01T00:00:00Z".to_string();

        assert!(voucher.is_expired(Some("2025-01-02T00:00:00Z")));
        assert!(!voucher.is_expired(Some("2024-12-31T00:00:00Z")));
    }

    #[test]
    fn test_voucher_create_balance_and_transaction_flow() {
        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;
        let (standard, standard_hash) = &*FREETALER_STANDARD;

        let data = NewVoucherData {
            validity_duration: Some("P4Y".to_string()),
            non_redeemable_test_voucher: false,
            nominal_value: ValueDefinition {
                unit: "MIN".to_string(),
                amount: "100.00".to_string(),
                abbreviation: Some("M".to_string()),
                description: None,
            },
            collateral: None,
            creator_profile: PublicProfile {
                id: Some(alice.user_id.clone()),
                first_name: Some("Alice".to_string()),
                ..Default::default()
            },
        };

        // 1. Create voucher via model method
        let voucher = Voucher::create(alice, standard, standard_hash, data)
            .expect("Failed to create voucher");
        assert_eq!(voucher.nominal_value.amount, "100.00");

        // 2. Spendable balance for creator (Alice)
        let alice_balance = voucher.spendable_balance(None, Some(alice));
        assert_eq!(alice_balance, dec!(100.00));

        let bob_balance = voucher.spendable_balance(None, Some(bob));
        assert_eq!(bob_balance, dec!(0.00));

        // 3. JSON roundtrip
        let json_str = voucher.to_json_string().expect("to_json_string failed");
        let parsed = Voucher::from_json_str(&json_str).expect("from_json_str failed");
        assert_eq!(voucher.voucher_id, parsed.voucher_id);
    }
}


