use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::{VoucherStandardDefinition, PrivacyMode};
use crate::services::crypto_identity::{get_pubkey_from_user_id, get_prefix_from_user_id};
use crate::services::crypto_utils::{get_hash, get_hash_from_slices, ed25519_pk_to_curve_point};
use crate::services::utils::to_canonical_json;
use crate::services::trap_manager::verify_trap;
use ed25519_dalek::{Signature, Verifier};
use rust_decimal::Decimal;
use std::str::FromStr;

pub fn validate_privacy_mode(voucher: &Voucher, mode: &PrivacyMode) -> Result<(), VoucherCoreError> {
    for (i, tx) in voucher.transactions.iter().enumerate() {
        if i == 0 {
            if tx.sender_id.is_none() {
                return Err(ValidationError::InvalidTransaction(
                    "Init transaction must always have a sender_id (creator).".to_string(),
                )
                .into());
            }
            continue;
        }

        if tx.t_type == "init" {
            continue;
        }

        if tx.recipient_id.trim() != tx.recipient_id {
            return Err(ValidationError::InvalidTransaction(
                format!("Transaction {} has recipient_id with leading/trailing whitespace (obfuscation attempt).", tx.t_id)
            ).into());
        }

        match mode {
            PrivacyMode::Public => {
                match &tx.sender_id {
                    None => return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: "Missing sender_id in 'public' mode.".to_string(),
                    }.into()),
                    Some(id) if id == crate::models::voucher::ANONYMOUS_ID => {
                        return Err(ValidationError::PrivacyModeViolation {
                            t_id: tx.t_id.clone(),
                            reason: "Explicit anonymous sender_id in 'public' mode.".to_string(),
                        }.into());
                    }
                    _ => {}
                }
                if tx.recipient_id == crate::models::voucher::ANONYMOUS_ID {
                    return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: "Anonymous recipient_id in 'public' mode.".to_string(),
                    }.into());
                }
                if !tx.recipient_id.starts_with("did:") && !tx.recipient_id.contains("@did:") {
                    return Err(ValidationError::InvalidTransaction(format!(
                        "Transaction {} has non-DID recipient in 'public' mode.",
                        tx.t_id
                    ))
                    .into());
                }
            }
            PrivacyMode::Stealth => {
                if tx.sender_id.is_some() {
                    return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: "Explicit sender_id in 'stealth' mode.".to_string(),
                    }.into());
                }
                if tx.sender_identity_signature.is_some() {
                    return Err(ValidationError::PrivateSignatureLeak {
                        t_id: tx.t_id.clone(),
                    }
                    .into());
                }
                if tx.recipient_id != crate::models::voucher::ANONYMOUS_ID {
                    return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: format!(
                            "Non-anonymous recipient_id ('{}') in 'stealth' mode. DIDs are strictly forbidden.",
                            tx.recipient_id
                        ),
                    }.into());
                }
            }
            PrivacyMode::Flexible => {
                if tx.recipient_id.contains(':') || tx.recipient_id.contains('@') {
                     return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: format!(
                            "Identity leak detected: recipient_id ('{}') contains DID markers in 'flexible' mode.",
                            tx.recipient_id
                        ),
                    }.into());
                }
                if tx.recipient_id != crate::models::voucher::ANONYMOUS_ID {
                    return Err(ValidationError::PrivacyModeViolation {
                        t_id: tx.t_id.clone(),
                        reason: format!(
                            "Non-anonymous recipient_id ('{}') in 'flexible' mode.",
                            tx.recipient_id
                        ),
                    }.into());
                }
                if tx.sender_id.is_none() && tx.sender_identity_signature.is_some() {
                    return Err(ValidationError::FlexibleModeIdentityInconsistency {
                        t_id: tx.t_id.clone(),
                    }
                    .into());
                }
            }
        }
    }
    Ok(())
}

pub fn verify_transactions(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(VoucherCoreError::Validation(
            ValidationError::InvalidTransaction("Transaction list is empty.".to_string()),
        ));
    }

    let allowed_decimal_places = standard.immutable.features.amount_decimal_places as u32;

    for (i, tx) in voucher.transactions.iter().enumerate() {
        let amt = Decimal::from_str(&tx.amount)?;
        if amt.scale() > allowed_decimal_places {
            return Err(ValidationError::InvalidAmountPrecision {
                path: if tx.t_type == "init" { "nominal_value.amount".to_string() } else { format!("transactions[{}].amount", i) },
                max_places: allowed_decimal_places as u8,
                found: amt.scale(),
            }.into());
        }
        if let Some(rem) = &tx.sender_remaining_amount {
            let rem_amt = Decimal::from_str(rem)?;
            if rem_amt.scale() > allowed_decimal_places {
                return Err(ValidationError::InvalidAmountPrecision {
                    path: format!("transactions[{}].sender_remaining_amount", i),
                    max_places: allowed_decimal_places as u8,
                    found: rem_amt.scale(),
                }.into());
            }
        }
    }

    let init_tx = voucher.transactions.get(0).ok_or_else(|| {
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(
            "Transaction list is empty.".to_string(),
        ))
    })?;
    let layer2_voucher_id = crate::services::l2_gateway::extract_layer2_voucher_id(voucher)?;

    verify_transaction_basics(init_tx, voucher, true)?;
    verify_transaction_integrity_and_signature(init_tx, &layer2_voucher_id)?;

    let mut last_tx_hash = get_hash(to_canonical_json(init_tx)?);
    let mut last_tx_time = init_tx.t_time.clone();

    let mut valid_previous_outputs = vec![Decimal::from_str(&init_tx.amount)?];

    for (i, tx) in voucher.transactions.iter().enumerate().skip(1) {
        let prev_tx = &voucher.transactions[i - 1];

        verify_transaction_basics(tx, voucher, false)?;
        verify_transaction_integrity_and_signature(tx, &layer2_voucher_id)?;

        if tx.prev_hash != last_tx_hash {
            return Err(ValidationError::InvalidTransaction(
                "Transaction chain broken: prev_hash does not match hash of previous transaction."
                    .to_string(),
            )
            .into());
        }
        if tx.t_time <= last_tx_time {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Transaction".to_string(),
                id: tx.t_id.clone(),
                time1: last_tx_time,
                time2: tx.t_time.clone(),
            }
            .into());
        }

        let current_amount = Decimal::from_str(&tx.amount)?;
        let current_remainder = if let Some(rem) = &tx.sender_remaining_amount {
            Decimal::from_str(rem)?
        } else {
            Decimal::ZERO
        };
        let total_input_needed = current_amount + current_remainder;

        let mut match_found = false;
        for valid_out in &valid_previous_outputs {
            if total_input_needed.normalize() == valid_out.normalize() {
                match_found = true;
                break;
            }
        }

        if !match_found {
            return Err(ValidationError::InsufficientFundsInChain {
                user_id: tx
                    .sender_id
                    .clone()
                    .unwrap_or_else(|| crate::models::voucher::ANONYMOUS_ID.to_string()),
                needed: total_input_needed.to_string(),
                available: valid_previous_outputs
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
                    .join(" or "),
            }
            .into());
        }

        valid_previous_outputs.clear();
        valid_previous_outputs.push(current_amount);
        if let Some(rem) = &tx.sender_remaining_amount {
            valid_previous_outputs.push(Decimal::from_str(rem)?);
        }

        if let Some(revealed_pub) = &tx.sender_ephemeral_pub {
            let correct_anchor = if prev_tx.recipient_id == tx.sender_id.clone().unwrap_or_default()
            {
                let pub_bytes = bs58::decode(revealed_pub).into_vec().map_err(|_| {
                    VoucherCoreError::Crypto("Invalid base58 encoding in revealed_pub".to_string())
                })?;
                let hash_pub = get_hash(pub_bytes);
                if let Some(prev_recv_hash) = &prev_tx.receiver_ephemeral_pub_hash {
                    if hash_pub == *prev_recv_hash {
                        Some(prev_recv_hash)
                    } else if let Some(prev_change_hash) = &prev_tx.change_ephemeral_pub_hash {
                        if hash_pub == *prev_change_hash {
                            Some(prev_change_hash)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                if Some(prev_tx.recipient_id.clone()) == tx.sender_id {
                    prev_tx.receiver_ephemeral_pub_hash.as_ref()
                } else if tx.sender_id.is_some() && tx.sender_id == prev_tx.sender_id {
                    prev_tx.change_ephemeral_pub_hash.as_ref()
                } else {
                    let pub_bytes = bs58::decode(revealed_pub).into_vec().map_err(|_| {
                        VoucherCoreError::Crypto(
                            "Invalid base58 encoding in revealed_pub".to_string(),
                        )
                    })?;
                    let hash_pub = get_hash(pub_bytes);
                    if let Some(prev_recv_hash) = &prev_tx.receiver_ephemeral_pub_hash {
                        if hash_pub == *prev_recv_hash {
                            Some(prev_recv_hash)
                        } else if let Some(prev_change_hash) = &prev_tx.change_ephemeral_pub_hash {
                            if hash_pub == *prev_change_hash {
                                Some(prev_change_hash)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            };

            if correct_anchor.is_none() {
                return Err(ValidationError::InvalidTransaction(
                    "P2PKH chain broken: sender_ephemeral_pub does not match any previous anchor."
                        .to_string(),
                )
                .into());
            }
        }

        if let Some(trap) = &tx.trap_data {
            if trap.blinded_id.contains(':') || trap.blinded_id.contains('@') {
                return Err(ValidationError::TrapDataInvalid {
                    t_id: tx.t_id.clone(),
                }
                .into());
            }

            let prev_hash_bytes = bs58::decode(&tx.prev_hash)
                .into_vec()
                .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
            let ephem_pub_bytes = tx
                .sender_ephemeral_pub
                .as_ref()
                .map(|s| bs58::decode(s).into_vec())
                .transpose()
                .map_err(|_| {
                    VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string())
                })?
                .unwrap_or_default();

            let expected_ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &ephem_pub_bytes]);

            if trap.ds_tag != expected_ds_tag {
                return Err(VoucherCoreError::Crypto(format!(
                    "Trap DS-Tag does not match expected input (Context Mismatch/Replay). Expected: {}, Found: {}",
                    expected_ds_tag, trap.ds_tag
                )));
            }

            if let Some(sender_id) = &tx.sender_id {
                if let Ok(signer_pk) = get_pubkey_from_user_id(sender_id) {
                    if let Ok(signer_id_point) = ed25519_pk_to_curve_point(&signer_pk) {
                        let sender_prefix = get_prefix_from_user_id(sender_id);

                        let u_input_varying = format!(
                            "{}{}{}",
                            expected_ds_tag,
                            tx.amount,
                            tx.receiver_ephemeral_pub_hash.as_deref().unwrap_or("")
                        );

                        if let Err(e) = verify_trap(
                            trap,
                            &expected_ds_tag,
                            u_input_varying.as_bytes(),
                            &signer_id_point,
                            sender_prefix,
                        ) {
                            return Err(ValidationError::InvalidTransaction(format!(
                                "Trap verification failed: {}",
                                e
                            ))
                            .into());
                        }
                    }
                }
            }
        }

        let sender_balance_before_tx = {
            let my_revealed_pub_hash = if let Some(k) = &tx.sender_ephemeral_pub {
                let bytes = bs58::decode(k).into_vec().map_err(|_| {
                    VoucherCoreError::Crypto(
                        "Invalid base58 encoding in sender_ephemeral_pub".to_string(),
                    )
                })?;
                get_hash(bytes)
            } else {
                "".to_string()
            };

            if Some(&my_revealed_pub_hash) == prev_tx.receiver_ephemeral_pub_hash.as_ref() {
                Decimal::from_str(&prev_tx.amount)?
            } else if Some(&my_revealed_pub_hash) == prev_tx.change_ephemeral_pub_hash.as_ref() {
                Decimal::from_str(prev_tx.sender_remaining_amount.as_deref().unwrap_or("0"))?
            } else {
                if tx.t_type == "init" {
                    Decimal::ZERO
                } else {
                    Decimal::ZERO
                }
            }
        };

        let amount_to_send = Decimal::from_str(&tx.amount)?;
        if sender_balance_before_tx < amount_to_send {
            return Err(ValidationError::InsufficientFundsInChain {
                user_id: tx.sender_id.clone().unwrap_or("anonymous".to_string()),
                needed: amount_to_send.to_string(),
                available: sender_balance_before_tx.to_string(),
            }
            .into());
        }

        if tx.t_type == "transfer" && sender_balance_before_tx != amount_to_send {
            return Err(ValidationError::FullTransferAmountMismatch {
                expected: sender_balance_before_tx.to_string(),
                found: amount_to_send.to_string(),
            }
            .into());
        }

        if tx.t_type == "transfer" && tx.sender_remaining_amount.is_some() {
            return Err(ValidationError::InvalidTransaction(
                "A 'transfer' transaction must not have a sender_remaining_amount.".to_string(),
            )
            .into());
        }

        if tx.t_type == "split" {
            let remaining_amount = match tx.sender_remaining_amount.as_deref() {
                Some(rem_str) => Decimal::from_str(rem_str)?,
                None => {
                    return Err(ValidationError::InvalidTransaction(
                        "Split transaction must have a sender_remaining_amount.".to_string(),
                    )
                    .into());
                }
            };

            if sender_balance_before_tx != (amount_to_send + remaining_amount) {
                return Err(ValidationError::InvalidTransaction(format!(
                    "Invalid split balance: previous balance ({}) does not equal sent amount ({}) + remaining amount ({}).",
                    sender_balance_before_tx, amount_to_send, remaining_amount
                )).into());
            }
        }

        last_tx_hash = get_hash(to_canonical_json(tx)?);
        last_tx_time = tx.t_time.clone();
    }

    Ok(())
}

pub fn verify_transaction_basics(
    tx: &Transaction,
    voucher: &Voucher,
    is_init: bool,
) -> Result<(), VoucherCoreError> {
    if is_init {
        if tx.t_type != "init" {
            return Err(ValidationError::InvalidTransaction(
                "First transaction must be of type 'init'.".to_string(),
            )
            .into());
        }
        let nonce_bytes = bs58::decode(&voucher.voucher_nonce)
            .into_vec()
            .map_err(|_| {
                VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                    "Invalid voucher_nonce format".to_string(),
                ))
            })?;
        let voucher_id_bytes = bs58::decode(&voucher.voucher_id).into_vec().map_err(|_| {
            VoucherCoreError::Validation(ValidationError::InvalidTransaction(
                "Invalid voucher_id format".to_string(),
            ))
        })?;
        let expected_prev_hash = get_hash_from_slices(&[&voucher_id_bytes, &nonce_bytes]);
        if tx.prev_hash != expected_prev_hash {
            return Err(ValidationError::InvalidTransaction(
                "Initial transaction has invalid prev_hash.".to_string(),
            )
            .into());
        }
        if (voucher.creator_profile.id.is_some() && tx.sender_id != voucher.creator_profile.id)
            || (voucher.creator_profile.id.is_some()
                && Some(&tx.recipient_id) != voucher.creator_profile.id.as_ref())
        {
            return Err(ValidationError::InitPartyMismatch {
                expected: voucher.creator_profile.id.clone().unwrap_or_default(),
                found: tx.sender_id.clone().unwrap_or_default(),
            }
            .into());
        }
        let nominal_amount = Decimal::from_str(&voucher.nominal_value.amount)?;
        let init_amount = Decimal::from_str(&tx.amount)?;
        if init_amount.normalize() != nominal_amount.normalize() {
            return Err(ValidationError::InitAmountMismatch {
                expected: nominal_amount.to_string(),
                found: init_amount.to_string(),
            }
            .into());
        }
        if tx.t_time < voucher.creation_date {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Initial Transaction".to_string(),
                id: tx.t_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: tx.t_time.clone(),
            }
            .into());
        }
    } else {
        if tx.t_type == "init" {
            return Err(ValidationError::InvalidTransaction(
                "Found subsequent transaction with invalid type 'init'.".to_string(),
            )
            .into());
        }
        if tx.sender_id.is_some() && tx.sender_id == Some(tx.recipient_id.clone()) {
            return Err(ValidationError::InvalidTransaction(
                "Sender and recipient cannot be the same in a non-init transaction.".to_string(),
            )
            .into());
        }
    }

    if tx.t_type == "split" {
        if tx.sender_remaining_amount.is_none() {
            return Err(ValidationError::InvalidTransaction(
                "Transaction of type 'split' must have a sender_remaining_amount.".to_string(),
            )
            .into());
        }
    } else if tx.t_type == "transfer" {
        if tx.sender_remaining_amount.is_some() {
            return Err(ValidationError::InvalidTransaction(
                "Transaction of type 'transfer' must not have a sender_remaining_amount."
                    .to_string(),
            )
            .into());
        }
    } else if !is_init {
        return Err(ValidationError::InvalidTransaction(format!(
            "Unknown transaction type: {}",
            tx.t_type
        ))
        .into());
    }

    if Decimal::from_str(&tx.amount)? <= Decimal::ZERO {
        return Err(ValidationError::NegativeOrZeroAmount {
            amount: tx.amount.clone(),
        }
        .into());
    }

    if let Some(rem) = &tx.sender_remaining_amount {
        if Decimal::from_str(rem)? <= Decimal::ZERO {
            return Err(ValidationError::NegativeOrZeroAmount {
                amount: rem.clone(),
            }
            .into());
        }
    }

    Ok(())
}

pub fn verify_transaction_integrity_and_signature(
    transaction: &Transaction,
    layer2_voucher_id: &str,
) -> Result<(), VoucherCoreError> {
    #[cfg(feature = "test-utils")]
    if crate::is_signature_bypass_active() {
        return Ok(());
    }

    let mut tx_for_tid_calc = transaction.clone();

    tx_for_tid_calc.t_id = "".to_string();
    tx_for_tid_calc.layer2_signature = None;
    tx_for_tid_calc.sender_identity_signature = None;

    let calculated_tid = get_hash(to_canonical_json(&tx_for_tid_calc)?);
    if transaction.t_id != calculated_tid {
        return Err(ValidationError::MismatchedTransactionId {
            t_id: transaction.t_id.clone(),
        }
        .into());
    }

    if let Some(l2_sig) = &transaction.layer2_signature {
        if let Some(sender_ephem_pub) = &transaction.sender_ephemeral_pub {
            let ephem_pub_bytes = bs58::decode(sender_ephem_pub).into_vec().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid ephemeral pubkey".into())
            })?;
            let l2_sig_bytes = bs58::decode(l2_sig).into_vec().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid l2 signature".into())
            })?;

            let ephem_key = ed25519_dalek::VerifyingKey::from_bytes(
                ephem_pub_bytes.as_slice().try_into().map_err(|_| {
                    ValidationError::SignatureDecodeError("Invalid ephemeral pubkey length".into())
                })?,
            )
            .map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid ephemeral pubkey bytes".into())
            })?;
            let signature =
                Signature::from_bytes(l2_sig_bytes.as_slice().try_into().map_err(|_| {
                    ValidationError::SignatureDecodeError("Invalid l2 signature length".into())
                })?);

            let t_id_raw = bs58::decode(&transaction.t_id)
                .into_vec()
                .map_err(|_| ValidationError::SignatureDecodeError("Invalid t_id format".into()))?;

            let challenge_ds_tag = if transaction.t_type == "init" {
                transaction.t_id.clone()
            } else {
                transaction
                    .trap_data
                    .as_ref()
                    .map(|td| td.ds_tag.clone())
                    .ok_or_else(|| {
                        ValidationError::InvalidTransaction(
                            "Missing trap_data for non-init transaction".to_string(),
                        )
                    })?
            };

            let to_32_bytes = |vec: Vec<u8>| -> Result<[u8; 32], ValidationError> {
                vec.try_into().map_err(|_| {
                    ValidationError::SignatureDecodeError("Hash must be 32 bytes".into())
                })
            };

            let receiver_hash_raw = transaction
                .receiver_ephemeral_pub_hash
                .as_ref()
                .map(|h| {
                    bs58::decode(h).into_vec().map_err(|_| {
                        ValidationError::SignatureDecodeError(
                            "Invalid receiver_ephemeral_pub_hash encoding".into(),
                        )
                    })
                })
                .transpose()?;

            let change_hash_raw = transaction
                .change_ephemeral_pub_hash
                .as_ref()
                .map(|h| {
                    bs58::decode(h).into_vec().map_err(|_| {
                        ValidationError::SignatureDecodeError(
                            "Invalid change_ephemeral_pub_hash encoding".into(),
                        )
                    })
                })
                .transpose()?;

            let t_id_32 = to_32_bytes(t_id_raw)?;
            let ephem_pub_32 = to_32_bytes(ephem_pub_bytes)?;

            let receiver_hash_32 = match receiver_hash_raw {
                Some(v) => Some(to_32_bytes(v)?),
                None => None,
            };

            let change_hash_32 = match change_hash_raw {
                Some(v) => Some(to_32_bytes(v)?),
                None => None,
            };

            let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
                &challenge_ds_tag,
                layer2_voucher_id,
                &t_id_32,
                &ephem_pub_32,
                receiver_hash_32.as_ref(),
                change_hash_32.as_ref(),
                transaction.deletable_at.as_deref(),
            );

            if ephem_key.verify(&payload_hash, &signature).is_err() {
                return Err(ValidationError::InvalidTransaction(
                    "Invalid layer2_signature (Technical Proof)".to_string(),
                )
                .into());
            }
        } else {
            return Err(ValidationError::InvalidTransaction(
                "Missing sender_ephemeral_pub for L2 signature".to_string(),
            )
            .into());
        }
    } else {
        return Err(
            ValidationError::InvalidTransaction("Missing layer2_signature".to_string()).into(),
        );
    }

    if let Some(sender_id) = &transaction.sender_id {
        let identity_sig_enc = transaction
            .sender_identity_signature
            .as_ref()
            .ok_or_else(|| {
                ValidationError::InvalidTransaction(
                    "Missing sender_identity_signature for public sender".to_string(),
                )
            })?;

        let pub_key = get_pubkey_from_user_id(sender_id)?;
        let sig_bytes = bs58::decode(identity_sig_enc)
            .into_vec()
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
            ValidationError::SignatureDecodeError("Invalid identity signature length".into())
        })?);

        let t_id_raw = bs58::decode(&transaction.t_id)
            .into_vec()
            .map_err(|_| ValidationError::SignatureDecodeError("Invalid t_id format".into()))?;
        if pub_key.verify(&t_id_raw, &signature).is_err() {
            return Err(ValidationError::InvalidTransaction(
                "Invalid sender_identity_signature".to_string(),
            )
            .into());
        }
    }

    Ok(())
}
