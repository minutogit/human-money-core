//! # Transaction Creation
//!
//! Handles the creation of new transactions (transfer or split) within a voucher,
//! implementing privacy flows and cryptographic anchor/trap logic.

use crate::error::VoucherCoreError;
use crate::models::voucher::{RecipientPayload, Transaction, Voucher};
use crate::models::voucher_standard_definition::{PrivacyMode, VoucherStandardDefinition};
use crate::services::crypto_utils::{
    encrypt_data, generate_ephemeral_x25519_keypair, get_hash, get_hash_from_slices,
    get_prefix_from_user_id, get_pubkey_from_user_id, perform_diffie_hellman, sign_ed25519,
    ed25519_pk_to_curve_point, encode_base64,
};
use crate::services::trap_manager::{derive_m, generate_trap, hash_to_scalar};
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
        if !voucher.voucher_standard.template.allow_partial_transfers {
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

    // 3. TRAP Generation
    let prev_hash_bytes = bs58::decode(&prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
    let sender_ephem_pub_bytes = bs58::decode(&sender_ephemeral_pub)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string()))?;

    let ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &sender_ephem_pub_bytes]);
    let amount_str = decimal_utils::format_for_storage(&amount_to_send, decimal_places);

    let u_input_varying = format!(
        "{}{}{}",
        ds_tag,
        amount_str,
        receiver_ephemeral_pub_hash.as_deref().unwrap_or("")
    );
    let u_scalar = hash_to_scalar(u_input_varying.as_bytes());

    let sender_id_prefix = get_prefix_from_user_id(sender_id);
    let m = derive_m(
        &prev_hash,
        &sender_permanent_key.to_bytes(),
        sender_id_prefix,
    )?;

    let my_id_point = ed25519_pk_to_curve_point(&sender_permanent_key.verifying_key())?;
    
    let sk_sender_scalar = crate::services::crypto_utils::get_secret_scalar(sender_permanent_key);
    let p_point = crate::services::crypto_utils::hash_to_curve(&prev_hash_bytes);

    let (trap_data_val, dleq_proof_opt) = generate_trap(
        ds_tag.clone(),
        &u_scalar,
        &m,
        &my_id_point,
        sender_id_prefix,
        Some(&sk_sender_scalar),
        Some(&p_point),
    )?;

    let trap_data = Some(trap_data_val);

    // 4. PAYLOAD ENCRYPTION: Send next_key_seed to recipient.
    let encoded_recipient_seed = bs58::encode(recipient_seed).into_string();

    let privacy_guard = if recipient_id.contains(":z") {
        let target_prefix = recipient_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();

        let (trap_k_point_str, dleq_c_str, dleq_s_str) = if let Some(dleq) = &dleq_proof_opt {
            (
                Some(bs58::encode(dleq.trap_k_point).into_string()),
                Some(bs58::encode(dleq.dleq_c).into_string()),
                Some(bs58::encode(dleq.dleq_s).into_string()),
            )
        } else {
            (None, None, None)
        };

        let payload = RecipientPayload {
            sender_permanent_did: sender_id.to_string(),
            target_prefix,
            timestamp: Utc::now().timestamp() as u64,
            next_key_seed: encoded_recipient_seed.clone(),
            trap_k_point: trap_k_point_str,
            dleq_c: dleq_c_str,
            dleq_s: dleq_s_str,
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
        privacy_guard,
        trap_data,
        layer2_signature: None,
        deletable_at: None,
        change_ephemeral_pub_hash,
        sender_identity_signature: None,
    };

    // L2 & IDENTITY SIGNATURES
    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    let t_id_raw = bs58::decode(&new_transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;
    let sender_pub_raw = bs58::decode(&sender_ephemeral_pub)
        .into_vec()
        .map_err(|_| {
            VoucherCoreError::InvalidHashFormat("Invalid sender_ephemeral_pub format".to_string())
        })?;

    let v_id = crate::services::l2_gateway::extract_layer2_voucher_id(voucher)?;
    let challenge_ds_tag = ds_tag.clone();

    let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
        vec.try_into()
            .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
    };

    let receiver_hash_raw = if let Some(h) = &new_transaction.receiver_ephemeral_pub_hash {
        let decoded = bs58::decode(h).into_vec().map_err(|_| {
            VoucherCoreError::InvalidHashFormat("Invalid receiver_hash".to_string())
        })?;
        Some(to_32_bytes(decoded, "receiver_hash")?)
    } else {
        None
    };

    let change_hash_raw = if let Some(h) = &new_transaction.change_ephemeral_pub_hash {
        let decoded = bs58::decode(h)
            .into_vec()
            .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid change_hash".to_string()))?;
        Some(to_32_bytes(decoded, "change_hash")?)
    } else {
        None
    };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &v_id,
        &to_32_bytes(t_id_raw.clone(), "t_id")?,
        &to_32_bytes(sender_pub_raw.clone(), "sender_pub")?,
        receiver_hash_raw.as_ref().map(|v| &*v),
        change_hash_raw.as_ref().map(|v| &*v),
        new_transaction.deletable_at.as_deref(),
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
