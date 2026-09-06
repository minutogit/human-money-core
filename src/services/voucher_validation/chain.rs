#![allow(clippy::manual_filter, clippy::get_first, clippy::if_same_then_else, clippy::collapsible_if)]
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::{VoucherStandardDefinition, PrivacyMode};
use crate::services::crypto::{get_hash, get_hash_from_slices, get_pubkey_from_user_id};
use crate::services::utils::to_canonical_json;
use ed25519_dalek::{Signature, Verifier};
use rust_decimal::Decimal;
use std::str::FromStr;

/// SECURITY (AUDIT-W4-INT-502): parses an RFC 3339 timestamp into an instant
/// for ordering comparisons. Chain time-ordering invariants must hold on
/// parsed INSTANTS, not on raw strings: RFC 3339 allows arbitrary UTC
/// offsets, so lexicographic string comparison does not imply chronological
/// order (e.g. `"2026-01-02T00:00:00Z"` vs `"2026-01-01T23:59:59-14:00"`).
/// Unparseable timestamps are rejected fail-closed.
pub(crate) fn parse_rfc3339_instant(
    timestamp: &str,
    entity: &str,
    id: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, VoucherCoreError> {
    chrono::DateTime::parse_from_rfc3339(timestamp).map_err(|_| {
        ValidationError::InvalidTimeOrder {
            entity: entity.to_string(),
            id: id.to_string(),
            time1: timestamp.to_string(),
            time2: "unparseable RFC 3339 timestamp".to_string(),
        }
        .into()
    })
}

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
        // SECURITY (AUDIT-W4-INT-502): compare parsed instants, not raw
        // RFC 3339 strings (offset confusion would defeat string ordering).
        if parse_rfc3339_instant(&tx.t_time, "Transaction", &tx.t_id)?
            <= parse_rfc3339_instant(&last_tx_time, "Transaction", &tx.t_id)?
        {
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
        // SECURITY (HMC-SEC-04-02): Both amounts are attacker-controlled and
        // their sum may exceed the Decimal range. The addition must be checked
        // BEFORE the conservation comparison, otherwise rust_decimal panics
        // instead of rejecting the hostile chain.
        let total_input_needed = match current_amount.checked_add(current_remainder) {
            Some(sum) => sum,
            None => {
                return Err(ValidationError::InsufficientFundsInChain {
                    user_id: tx
                        .sender_id
                        .clone()
                        .unwrap_or_else(|| crate::models::voucher::ANONYMOUS_ID.to_string()),
                    needed: format!(
                        "overflow (amount {} + remaining {})",
                        current_amount, current_remainder
                    ),
                    available: valid_previous_outputs
                        .iter()
                        .map(|d| d.to_string())
                        .collect::<Vec<_>>()
                        .join(" or "),
                }
                .into());
            }
        };

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
                let pub_bytes = crate::services::crypto::decode_bs58_fixed::<32>(
                    revealed_pub, "revealed_pub",
                )?;
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
                    let pub_bytes = crate::services::crypto::decode_bs58_fixed::<32>(
                        revealed_pub, "revealed_pub",
                    )?;
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
            // Base58 hygiene / DID-injection guard: shards are pure
            // cryptographic material and must never smuggle DID marker
            // characters (':' / '@').
            if trap.trap_r.contains(':')
                || trap.trap_r.contains('@')
                || trap.trap_s.contains(':')
                || trap.trap_s.contains('@')
            {
                return Err(ValidationError::TrapDataInvalid {
                    t_id: tx.t_id.clone(),
                }
                .into());
            }

            // Structural ds_tag hygiene: must be valid Base58 32-byte hash.
            let _ = crate::services::crypto::decode_bs58_fixed::<32>(
                &trap.ds_tag, "ds_tag",
            )?;

            // SECURITY (HMSEC-SA04-09): Structural shard sanity. The V3
            // digest binds the shard STRINGS verbatim, so a malicious payer
            // could otherwise sign arbitrary garbage as trap shards and
            // permanently blind the SST against double-spend attribution.
            // Enforce the generation contract (decompressable Edwards point
            // for R_i, canonical scalar encoding for s_i) BEFORE acceptance;
            // the genesis placeholder pair ("none"/"none") fails these gates
            // by design. Honest sends always satisfy this via
            // generate_sst_trap, so no legitimate path regresses.
            crate::services::trap_manager::validate_shard_structure(
                &trap.trap_r,
                &trap.trap_s,
            )?;

            let expected_ds_tag = crate::services::crypto::get_ds_tag(
                &tx.prev_hash,
                tx.sender_ephemeral_pub.as_deref().unwrap_or(""),
            )?;

            if trap.ds_tag != expected_ds_tag {
                return Err(VoucherCoreError::Crypto(format!(
                    "Trap DS-Tag does not match expected input (Context Mismatch/Replay). Expected: {}, Found: {}",
                    expected_ds_tag, trap.ds_tag
                )));
            }

            // V3 (SST): The shards cannot be verified standalone against a
            // claimed identity on-chain. They are authenticated indirectly by
            // the HMC_TX_AUTH_V3 layer2_signature digest checked below, while
            // attribution happens autonomously via SST collision extraction in
            // conflict handling (two colliding shards mathematically reveal
            // the signer).
        }

        let sender_balance_before_tx = {
            let my_revealed_pub_hash = if let Some(k) = &tx.sender_ephemeral_pub {
                let bytes = crate::services::crypto::decode_bs58_fixed::<32>(
                    k, "sender_ephemeral_pub",
                )?;
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
            // SECURITY (HMSEC-SA04-05): Split-Anchor Separation invariant.
            // The receiver output and the change output must be committed to
            // two DIFFERENT keys. A split with identical anchors is fully
            // self-consistent and would otherwise pass every signature and
            // conservation check, but it places BOTH branches under the
            // control of a single key: whoever holds that key can spend the
            // recipient branch before the honest recipient, framing them as
            // a double-spender, and transfer/change fingerprints become
            // trivially linkable. No legitimate creation path can produce
            // this state (recipient seed is randomly generated, the change
            // seed is deterministically derived from the sender's permanent
            // key via HKDF).
            if tx.receiver_ephemeral_pub_hash.is_some()
                && tx.receiver_ephemeral_pub_hash == tx.change_ephemeral_pub_hash
            {
                return Err(ValidationError::InvalidTransaction(
                    "Split transaction must commit DISTINCT anchors for the receiver and change outputs (anchor overlap detected).".to_string(),
                )
                .into());
            }

            let remaining_amount = match tx.sender_remaining_amount.as_deref() {
                Some(rem_str) => Decimal::from_str(rem_str)?,
                None => {
                    return Err(ValidationError::InvalidTransaction(
                        "Split transaction must have a sender_remaining_amount.".to_string(),
                    )
                    .into());
                }
            };

            // SECURITY (HMC-SEC-04-02): The split sum is attacker-controlled
            // and may overflow the Decimal range; compute it checked to avoid
            // a panic on impossible split declarations.
            let split_total = match amount_to_send.checked_add(remaining_amount) {
                Some(sum) => sum,
                None => {
                    return Err(ValidationError::InvalidTransaction(format!(
                        "Impossible split: sent amount ({}) plus remaining amount ({}) overflows the maximum representable value.",
                        amount_to_send, remaining_amount
                    ))
                    .into());
                }
            };

            if sender_balance_before_tx != split_total {
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
        // SECURITY (AUDIT-W4-TRAP-202): Genesis/init transactions must not contain
        // non-trivial trap_data. Shards / foreign ds_tags in the init row are
        // rejected fail-closed to prevent authenticated spend-claim masquerades.
        if let Some(trap) = &tx.trap_data {
            let is_trivial = (trap.trap_r.is_empty() || trap.trap_r == "none")
                && (trap.trap_s.is_empty() || trap.trap_s == "none")
                && (trap.ds_tag.is_empty() || trap.ds_tag == "none");
            if !is_trivial {
                return Err(ValidationError::InvalidTransaction(
                    "Initial ('init') transaction must not contain non-trivial trap_data.".to_string(),
                )
                .into());
            }
        }
        // SECURITY (AUDIT-W4-INT-501): issuer attribution is MANDATORY for
        // issuance. Previously every attribution gate was conditional on
        // `creator_profile.id` being present, so a hand-crafted voucher with
        // `creator_profile.id = None` bypassed the init party check, the
        // creator-signature binding and the issuance firewall entirely —
        // enabling unaccountable self-minting under trusted standard UUIDs.
        let creator_id = voucher.creator_profile.id.as_deref().ok_or_else(|| {
            ValidationError::BusinessRuleViolated(
                "Initial transaction has no attributed creator (creator_profile.id is \
                 missing); unattributed issuance is rejected."
                    .to_string(),
            )
        })?;
        if Some(creator_id) != tx.sender_id.as_deref()
            || creator_id != tx.recipient_id
        {
            return Err(ValidationError::InitPartyMismatch {
                expected: creator_id.to_string(),
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
        // SECURITY (AUDIT-W4-INT-502): instant-based comparison (see above).
        if parse_rfc3339_instant(&tx.t_time, "Initial Transaction", &tx.t_id)?
            < parse_rfc3339_instant(
                &voucher.creation_date,
                "Initial Transaction",
                &tx.t_id,
            )?
        {
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
    // SECURITY (audit_02_11): the layer2_voucher_id is signature-bound again
    // (HMC_TX_AUTH_V3 digest, field 2). Genesis transactions signed the
    // canonical "none" placeholder; callers pass the voucher's derived id.
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
    // V3 (SST) rule: The canonical t_id preimage EXCLUDES `trap_data` AND
    // `privacy_guard`. The trap shards depend on tau(t_id) (circularity), and
    // the privacy guard is AEAD-protected + recipient-verified anyway; both
    // are separately authenticated via the HMC_TX_AUTH_V3 layer2_signature
    // digest.
    tx_for_tid_calc.trap_data = None;
    tx_for_tid_calc.privacy_guard = None;

    let calculated_tid = get_hash(to_canonical_json(&tx_for_tid_calc)?);
    if transaction.t_id != calculated_tid {
        return Err(ValidationError::MismatchedTransactionId {
            t_id: transaction.t_id.clone(),
        }
        .into());
    }

    if let Some(l2_sig) = &transaction.layer2_signature {
        if let Some(sender_ephem_pub) = &transaction.sender_ephemeral_pub {
            let ephem_pub_32 = crate::services::crypto::decode_bs58_fixed::<32>(
                sender_ephem_pub,
                "sender_ephemeral_pub",
            )
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
            let l2_sig_bytes = crate::services::crypto::decode_bs58_fixed::<64>(
                l2_sig,
                "layer2_signature",
            )
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

            let ephem_key = ed25519_dalek::VerifyingKey::from_bytes(&ephem_pub_32)
                .map_err(|_| {
                    ValidationError::SignatureDecodeError("Invalid ephemeral pubkey bytes".into())
                })?;
            let signature = Signature::from_bytes(&l2_sig_bytes);

            let t_id_32 = crate::services::crypto::decode_bs58_fixed::<32>(
                &transaction.t_id,
                "t_id",
            )
            .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;

            let challenge_ds_tag = crate::services::l2_gateway::derive_challenge_tag(transaction)
                .map_err(|_| {
                    ValidationError::InvalidTransaction(
                        "Missing trap_data for non-init transaction".to_string(),
                    )
                })?;

            // V3 Protocol (HMC_TX_AUTH_V3): verify against the unified,
            // domain-separated digest binding the voucher id (audit_02_11),
            // the SST trap shards (trap_r, trap_s), the encrypted timestamp
            // and the canonical privacy-guard commitment (HMSEC-SA04-08).
            // This makes the layer2_signature serve simultaneously as L1
            // ownership proof and gossip ingress proof.
            let (trap_r_str, trap_s_str) = match &transaction.trap_data {
                Some(td) => (td.trap_r.as_str(), td.trap_s.as_str()),
                None => (
                    crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
                    crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
                ),
            };
            let encrypted_timestamp = crate::services::conflict_manager::
                encrypt_transaction_timestamp(transaction)?;

            let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
                if transaction.t_type == "init" {
                    crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
                } else {
                    layer2_voucher_id
                },
                &challenge_ds_tag,
                &t_id_32,
                &ephem_pub_32,
                trap_r_str,
                trap_s_str,
                encrypted_timestamp,
                transaction.deletable_at.as_deref(),
                &crate::services::l2_gateway::privacy_guard_commitment(
                    transaction.privacy_guard.as_deref(),
                ),
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
        let sig_bytes = crate::services::crypto::decode_bs58_fixed::<64>(
            identity_sig_enc,
            "sender_identity_signature",
        )
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let t_id_raw = crate::services::crypto::decode_bs58_fixed::<32>(
            &transaction.t_id,
            "t_id",
        )
        .map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        if pub_key.verify(&t_id_raw, &signature).is_err() {
            return Err(ValidationError::InvalidTransaction(
                "Invalid sender_identity_signature".to_string(),
            )
            .into());
        }
    }

    Ok(())
}
