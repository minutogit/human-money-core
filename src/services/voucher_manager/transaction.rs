//! # Transaction Creation
//!
//! Handles the creation of new transactions (transfer or split) within a voucher,
//! implementing privacy flows and cryptographic anchor/SST-trap logic.

use crate::error::VoucherCoreError;
use crate::models::voucher::{RecipientPayload, Transaction, Voucher};
use crate::models::voucher_standard_definition::{PrivacyMode, VoucherStandardDefinition};
use crate::services::crypto_utils::{
    encrypt_data, generate_ephemeral_x25519_keypair, get_hash, get_hash_from_slices,
    get_prefix_from_user_id, get_pubkey_from_user_id, perform_diffie_hellman, sign_ed25519,
    encode_base64,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::decimal_utils;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use rust_decimal::Decimal;
use std::str::FromStr;
use super::VoucherManagerError;
use super::balance::{get_spendable_balance, validate_issuance_firewall};

/// Contains the sensitive secrets generated during transaction creation.
/// These MUST be securely stored by the caller (Wallet) as they are only
/// present in the voucher in encrypted or hashed form.
#[derive(Debug, Clone)]
pub struct TransactionSecrets {
    pub recipient_seed: String,      // BS58 encoded seed for the recipient
    pub change_seed: Option<String>, // BS58 encoded seed for change (if split)
}

/// Creates a new transaction and appends it to a copy of the voucher.
///
/// Implements the privacy flow: Anchor (P2PKH), Trap (ZKP), and Payload Encryption.
pub fn create_transaction(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_permanent_key: &SigningKey,
    sender_ephemeral_key: &SigningKey,
    recipient_id: &str,
    amount_to_send_str: &str,
    use_privacy_mode: Option<bool>,
) -> Result<(Voucher, TransactionSecrets), VoucherCoreError> {
    crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)?;

    validate_issuance_firewall(voucher, standard, sender_id, recipient_id)?;

    let decimal_places = standard.immutable.features.amount_decimal_places as u32;

    // BALANCE CALCULATION (Crypto-Matching):
    let revealed_pub_bytes = sender_ephemeral_key.verifying_key().to_bytes();
    let revealed_pub_hash = get_hash(revealed_pub_bytes);
    
    let spendable_balance = get_spendable_balance(
        voucher, 
        sender_id, 
        standard, 
        Some(&revealed_pub_hash)
    )?;

    let amount_to_send = Decimal::from_str(amount_to_send_str)?;
    decimal_utils::validate_precision(&amount_to_send, decimal_places)?;

    if amount_to_send <= Decimal::ZERO {
        return Err(VoucherManagerError::Generic(
            "Transaction amount must be positive.".to_string(),
        )
        .into());
    }
    if amount_to_send > spendable_balance {
        return Err(VoucherManagerError::InsufficientFunds {
            available: spendable_balance,
            needed: amount_to_send,
        }
        .into());
    }

    let (t_type, sender_remaining_amount) = if amount_to_send < spendable_balance {
        if !standard.immutable.features.allow_partial_transfers {
            return Err(VoucherManagerError::VoucherPartialTransferNotAllowed.into());
        }
        let remaining = spendable_balance - amount_to_send;
        (
            "split".to_string(),
            Some(decimal_utils::format_for_storage(
                &remaining,
                decimal_places,
            )),
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

    let prev_hash = get_hash(to_canonical_json(voucher.transactions.last().unwrap())?);
    let t_time = get_current_timestamp();

    // Determine Identities based on Privacy Mode (Core Regulation)
    let (final_sender_id, recipient_id_check) = match standard.immutable.features.privacy_mode {
        PrivacyMode::Stealth => {
            // Stealth Mode: Everything is anonymous.
            (None, crate::models::voucher::ANONYMOUS_ID.to_string())
        }
        PrivacyMode::Flexible => {
            // Flexible Mode: Sender chooses for self, recipient is ALWAYS anonymous.
            let actually_private = use_privacy_mode.unwrap_or(false);
            let s_id = if actually_private { None } else { Some(sender_id.to_string()) };
            (s_id, crate::models::voucher::ANONYMOUS_ID.to_string())
        }
        PrivacyMode::Public => {
            if use_privacy_mode.unwrap_or(false) {
                return Err(VoucherManagerError::Generic(
                    "Cannot use privacy mode on a public standard".to_string(),
                ).into());
            }
            // Public Mode: Plaintext DIDs required for both.
            let recipient_is_did = recipient_id.starts_with("did:") || recipient_id.contains("@did:");
            if !recipient_is_did {
                return Err(VoucherManagerError::Generic(
                    "Public mode requires DID recipient.".to_string(),
                ).into());
            }
            if sender_id == crate::models::voucher::ANONYMOUS_ID {
                 return Err(VoucherManagerError::Generic(
                    "Public mode forbids anonymous sender.".to_string(),
                ).into());
            }
            (Some(sender_id.to_string()), recipient_id.to_string())
        }
    };

    // 1. REVEAL: Current ephemeral key is published.
    let sender_ephemeral_pub =
        bs58::encode(sender_ephemeral_key.verifying_key().to_bytes()).into_string();

    // 2. ANCHOR: New key for recipient (and change if needed).
    // a) Recipient
    let mut recipient_seed = [0u8; 32];
    rand::thread_rng().fill(&mut recipient_seed);
    let recipient_signing_key = SigningKey::from_bytes(&recipient_seed);
    let recipient_ephemeral_pub = recipient_signing_key.verifying_key();
    let receiver_ephemeral_pub_hash = Some(get_hash(recipient_ephemeral_pub.to_bytes()));

    // b) Change
    let (change_ephemeral_pub_hash, change_key_seed_opt) = if t_type == "split" {
        let sender_id_prefix = get_prefix_from_user_id(sender_id);

        let salt = prev_hash.as_bytes();
        let ikm = sender_permanent_key.to_bytes();
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &ikm);
        let hkdf = Hkdf::<Sha256>::from_prk(&prk)
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
        let change_hash = get_hash(change_pub.to_bytes());
        (
            Some(change_hash),
            Some(bs58::encode(change_seed).into_string()),
        )
    } else {
        (None, None)
    };

    // 3. TRAP CONTEXT (input tag derivation)
    let prev_hash_bytes = bs58::decode(&prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
    let sender_ephem_pub_bytes = bs58::decode(&sender_ephemeral_pub)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string()))?;

    let ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &sender_ephem_pub_bytes]);
    let amount_str = decimal_utils::format_for_storage(&amount_to_send, decimal_places);

    let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
        vec.try_into()
            .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
    };

    // 4. TRANSACTION STRUCT
    // V3 (SST) rule: `trap_data` and `privacy_guard` are attached AFTER the
    // t_id computation below, so the canonical preimage naturally excludes
    // them. The trap shards depend on tau(t_id) (circularity), and the
    // privacy guard is AEAD-protected + recipient-verified anyway; both are
    // separately authenticated via the HMC_TX_AUTH_V3 layer2_signature digest.
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

    // Canonical t_id over the transaction WITHOUT trap_data/privacy_guard.
    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    // 5. TRAP GENERATION (V3 / Shared-Signature Trap)
    let eph_pub_32 = to_32_bytes(sender_ephem_pub_bytes, "sender_ephemeral_pub")?;
    let (sst_trap, sst_witness) =
        crate::services::trap_manager::generate_sst_trap(
            sender_permanent_key,
            &ds_tag,
            &eph_pub_32,
            &new_transaction.t_id,
        )?;
    new_transaction.trap_data = Some(sst_trap);

    // 6. PAYLOAD ENCRYPTION: Send next_key_seed to recipient.
    // Built AFTER t_id/trap generation because it embeds the private SST
    // witness and must not influence the canonical t_id preimage (see above).
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
            timestamp: Utc::now().timestamp() as u64,
            next_key_seed: encoded_recipient_seed.clone(),
            // Legacy V2 DLEQ fields are no longer generated under V3.
            trap_k_point: None,
            dleq_c: None,
            dleq_s: None,
            // V3 (SST): private witness for the recipient's handover check
            // (fraud *prevention* at L1).
            trap_r_sig: Some(sst_witness.r_sig),
            trap_s_sig: Some(sst_witness.s_sig),
            trap_m_r: Some(sst_witness.m_r),
            trap_m_s: Some(sst_witness.m_s),
        };

        let (ephemeral_pk, ephemeral_sk) = generate_ephemeral_x25519_keypair();
        let recipient_ed_pk = get_pubkey_from_user_id(recipient_id)?;
        let recipient_x_pk = crate::services::crypto_utils::ed25519_pub_to_x25519(&recipient_ed_pk);
        let shared_secret = perform_diffie_hellman(ephemeral_sk, &recipient_x_pk, recipient_id)?;
        let payload_json = to_canonical_json(&payload)?;
        let encrypted_bytes = encrypt_data(&shared_secret, payload_json.as_bytes())?;

        let mut privacy_guard_bytes = Vec::new();
        privacy_guard_bytes.extend_from_slice(ephemeral_pk.as_bytes());
        privacy_guard_bytes.extend_from_slice(&encrypted_bytes);
        Some(encode_base64(&privacy_guard_bytes))
    } else {
        None
    };
    new_transaction.privacy_guard = privacy_guard;

    // L2 & IDENTITY SIGNATURES
    let t_id_raw = bs58::decode(&new_transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;
    let sender_pub_raw = bs58::decode(&sender_ephemeral_pub)
        .into_vec()
        .map_err(|_| {
            VoucherCoreError::InvalidHashFormat("Invalid sender_ephemeral_pub format".to_string())
        })?;

    let challenge_ds_tag = ds_tag.clone();

    // V3 Protocol (HMC_TX_AUTH_V3): bind the SST trap shards and the
    // encrypted timestamp into the digest so gossip fingerprints carrying
    // (ds_tag, trap_r, trap_s, encrypted_timestamp) become self-authenticating.
    // SECURITY (audit_02_11): the voucher id is signature-bound so lock
    // authorizations cannot be transplanted between containers.
    // SECURITY (HMSEC-SA04-08): the canonical privacy-guard commitment is
    // bound so guard equivocation yields distinguishable evidence.
    let trap = new_transaction.trap_data.as_ref().ok_or(VoucherCoreError::MissingTrapData)?;
    let encrypted_timestamp =
        crate::services::conflict_manager::encrypt_transaction_timestamp(&new_transaction)?;
    let l2_voucher_id = crate::services::l2_gateway::extract_layer2_voucher_id(voucher)?;

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

    let l2_sig_bytes = sign_ed25519(sender_ephemeral_key, &payload_hash);
    new_transaction.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

    if new_transaction.sender_id.is_some() {
        let identity_sig_bytes = sign_ed25519(sender_permanent_key, &t_id_raw);
        new_transaction.sender_identity_signature =
            Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());
    }

    let mut new_voucher = voucher.clone();
    new_voucher.transactions.push(new_transaction);

    crate::services::voucher_validation::validate_voucher_against_standard(&new_voucher, standard)?;

    let secrets = TransactionSecrets {
        recipient_seed: encoded_recipient_seed,
        change_seed: change_key_seed_opt,
    };

    Ok((new_voucher, secrets))
}
