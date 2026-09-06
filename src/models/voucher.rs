//! # voucher.rs
//!
//! Defines the core data structures for the universal voucher container format.
//! These structures exactly map the JSON schema defined in `llm-context.md`
//! and use `serde` for serialization and deserialization.

use crate::models::profile::PublicProfile;
use serde::{Deserialize, Serialize};

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
