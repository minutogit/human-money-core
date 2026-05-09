//! # Balance and Firewall Logic
//!
//! Handles spendable balance calculations and issuance firewall validations.

use crate::error::VoucherCoreError;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::get_pubkey_from_user_id;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use std::str::FromStr;
use super::VoucherManagerError;
use super::date_utils::add_iso8601_duration;

/// Validates the "Circulation Firewall" (`issuance_minimum_validity_duration`).
///
/// This rule is a transaction firewall that only applies to the creator
/// when sending to a third party.
pub fn validate_issuance_firewall(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    recipient_id: &str,
) -> Result<(), VoucherCoreError> {
    // 1. Extract rule
    let min_duration_str = match Some(&standard.immutable.issuance.issuance_minimum_validity_duration)
    {
        Some(duration) if !duration.is_empty() => duration,
        _ => return Ok(()), // Rule not defined
    };

    // 2. Creator check
    let creator_id = match &voucher.creator_profile.id {
        Some(id) => id,
        None => return Ok(()), // No creator ID field, cannot be the creator
    };
    if sender_id != creator_id {
        return Ok(()); // Sender is not the creator
    }

    // 3. SAI exception check (Redemption / Self-transfer)
    // If the recipient is not a DID (e.g., a hash), it cannot be the creator themselves.
    if recipient_id.contains(':') {
        let sender_pk = get_pubkey_from_user_id(sender_id)?;
        let recipient_pk = get_pubkey_from_user_id(recipient_id)?;

        if sender_pk == recipient_pk {
            return Ok(()); // Internal transfer
        }
    }

    // 4. Time check
    // Sender is creator, recipient is third party, rule exists.
    let now_str = crate::services::utils::get_current_timestamp();
    let now = DateTime::parse_from_rfc3339(&now_str)
        .map_err(|e| {
            VoucherManagerError::Generic(format!("Failed to parse now date: {}", e))
        })?
        .with_timezone(&Utc);

    let valid_until_dt = DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|e| {
            VoucherManagerError::Generic(format!("Failed to parse voucher valid_until date: {}", e))
        })?
        .with_timezone(&Utc);

    // Calculate the date that must be reached (now + P1Y)
    let required_end_dt = add_iso8601_duration(now, min_duration_str)?;

    if valid_until_dt < required_end_dt {
        // Block: Remaining time is too short.
        Err(VoucherManagerError::InvalidValidityDuration(format!(
            "Issuance failed: Voucher validity ({}) is less than the required minimum remaining duration ({} from now).",
            valid_until_dt.to_rfc3339(),
            required_end_dt.to_rfc3339()
        )).into())
    } else {
        Ok(())
    }
}

/// Calculates the spendable balance for a specific user.
///
/// This function traverses the transaction history of a voucher to determine
/// the current balance of a user.
pub fn get_spendable_balance(
    voucher: &Voucher,
    user_id: &str,
    standard: &VoucherStandardDefinition,
    current_holder_pub_hash: Option<&str>,
) -> Result<Decimal, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Ok(Decimal::ZERO);
    }

    // Check voucher validity before calculating balance.
    // Intentionally ignore errors caused only by missing guarantors,
    // as this is not relevant for a pure balance check.
    match crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)
    {
        Ok(_) => (),
        Err(VoucherCoreError::Validation(_)) => (), // Ignore validation errors for balance check
        Err(e) => return Err(e),
    };

    let last_tx = voucher.transactions.last().unwrap();
    let decimal_places = standard.immutable.features.amount_decimal_places as u32;

    let balance_str = if let Some(hash) = current_holder_pub_hash {
        // --- Mathematical UTXO assignment via Stealth Key Hash ---
        if Some(hash) == last_tx.receiver_ephemeral_pub_hash.as_deref() {
            &last_tx.amount
        } else if Some(hash) == last_tx.change_ephemeral_pub_hash.as_deref() {
            last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
        } else {
            // User has no balance in this voucher if hash doesn't match.
            "0"
        }
    } else {
        // --- Fallback to ID-based logic (Public Mode) ---
        if last_tx.t_type == "init" && last_tx.recipient_id == user_id {
            // In the initial transaction, the creator is always the recipient of the total value.
            &last_tx.amount
        } else if last_tx.t_type == "init" {
            "0"
        } else if last_tx.sender_id.as_deref() == Some(user_id) {
            // We are the explicit sender -> Show our change
            last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
        } else if last_tx.recipient_id == user_id {
            // We are the explicit recipient -> Show received amount
            &last_tx.amount
        } else {
            "0"
        }
    };

    let balance = Decimal::from_str(balance_str)?;
    Ok(balance.round_dp(decimal_places))
}
