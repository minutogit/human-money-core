//! # voucher_validation.rs
//!
//! Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts
//! gegen die Regeln eines `VoucherStandardDefinition`.

use crate::error::{StandardDefinitionError, ValidationError, VoucherCoreError};
use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::{BehaviorRules, ContentRules, CountRules, FieldGroupRule,
    RequiredSignatureRule, VoucherStandardDefinition
};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use crate::services::voucher_manager::add_iso8601_duration;

use ed25519_dalek::Signature;
use regex::Regex;
use rust_decimal::Decimal;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

/// Hauptfunktion zur Validierung eines Gutscheins gegen seinen Standard.
/// Dies ist der zentrale Orchestrator, der alle untergeordneten Validierungsschritte aufruft.
pub fn validate_voucher_against_standard(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    // Grundlegende Prüfungen, die immer gelten müssen.
    verify_standard_identity(voucher, standard)?;

    // Logische Prüfung der Datenkonsistenz
    if voucher.valid_until < voucher.creation_date {
        return Err(ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        }.into());
    }
    verify_creator_signature(voucher)?;

    // Führe die datengesteuerten Validierungsregeln aus, falls sie im Standard definiert sind.
    if let Some(rules) = &standard.validation {
        let voucher_json = serde_json::to_value(voucher)?;

        if let Some(count_rules) = &rules.counts {
            validate_counts(voucher, count_rules)?;
        }
        if let Some(signature_rules) = &rules.required_signatures {
            validate_required_signatures(voucher, signature_rules)?;
        }
        if let Some(content_rules) = &rules.content_rules {
            validate_content_rules(&voucher_json, content_rules)?;
        }
        if let Some(behavior_rules) = &rules.behavior_rules {
            validate_behavior_rules(voucher, behavior_rules)?;
        }
        if let Some(field_group_rules) = &rules.field_group_rules {
            validate_field_group_rules(&voucher_json, field_group_rules)?;
        }
    }

    // Die komplexen, zustandsbehafteten Prüfungen für Signaturen und Transaktionen
    // werden weiterhin ausgeführt, da sie die Kernintegrität sichern.
    verify_guarantor_signatures(voucher)?;
    verify_additional_signatures(voucher)?;
    verify_transactions(voucher, standard)?;

    Ok(())
}

/// Stellt sicher, dass der Gutschein zum richtigen Standard gehört (UUID und Hash-Abgleich).
fn verify_standard_identity(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.voucher_standard.uuid != standard.metadata.uuid {
        return Err(ValidationError::StandardUuidMismatch {
            expected: standard.metadata.uuid.clone(),
            found: voucher.voucher_standard.uuid.clone(),
        }
            .into());
    }

    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let expected_hash = get_hash(to_canonical_json(&standard_to_hash)?);

    if voucher.voucher_standard.standard_definition_hash != expected_hash {
        return Err(VoucherCoreError::Standard(
            StandardDefinitionError::StandardHashMismatch,
        ));
    }
    Ok(())
}

/// Prüft die quantitativen Regeln aus dem Standard (z.B. Anzahl der Signaturen).
pub fn validate_counts(voucher: &Voucher, rules: &CountRules) -> Result<(), ValidationError> {
    if let Some(rule) = &rules.guarantor_signatures {
        let count = voucher.guarantor_signatures.len();
        if count < rule.min as usize || count > rule.max as usize {
            return Err(ValidationError::CountOutOfBounds {
                field: "guarantor_signatures".to_string(),
                min: rule.min,
                max: rule.max,
                found: count,
            });
        }
    }
    if let Some(rule) = &rules.additional_signatures {
        let count = voucher.additional_signatures.len();
        if count < rule.min as usize || count > rule.max as usize {
            return Err(ValidationError::CountOutOfBounds {
                field: "additional_signatures".to_string(),
                min: rule.min,
                max: rule.max,
                found: count,
            });
        }
    }
    if let Some(rule) = &rules.transactions {
        let count = voucher.transactions.len();
        if count < rule.min as usize || count > rule.max as usize {
            return Err(ValidationError::CountOutOfBounds {
                field: "transactions".to_string(),
                min: rule.min,
                max: rule.max,
                found: count,
            });
        }
    }
    Ok(())
}

/// Prüft, ob alle im Standard geforderten Signaturen vorhanden und kryptographisch gültig sind.
pub fn validate_required_signatures(
    voucher: &Voucher,
    rules: &[RequiredSignatureRule],
) -> Result<(), ValidationError> {
    // Sammle alle zusätzlichen Signaturen zur einfachen Suche.
    let all_additional_signatures: Vec<_> = voucher
        .additional_signatures
        .iter()
        .map(|sig| (
            &sig.signer_id,
            &sig.description,
            is_additional_signature_valid(sig, &voucher.voucher_id),
        ))
        .collect();

    for rule in rules {
        if !rule.is_mandatory {
            continue;
        }

        let is_fulfilled = all_additional_signatures.iter().any(|(signer_id, description, is_valid)| {
            let id_matches = rule.allowed_signer_ids.contains(signer_id);
            let description_matches = rule
                .required_signature_description
                .as_ref()
                .map_or(true, |req_desc| req_desc == *description);

            id_matches && description_matches && *is_valid
        });

        if !is_fulfilled {
            println!("[DEBUG] Rule was NOT fulfilled. Returning MissingRequiredSignature error.");
            return Err(ValidationError::MissingRequiredSignature {
                role: rule.role_description.clone(),
            });
        }
    }
    Ok(())
}

/// Prüft die Inhaltsregeln (feste Werte, erlaubte Werte, Regex-Muster).
pub fn validate_content_rules(
    voucher_json: &Value,
    rules: &ContentRules,
) -> Result<(), ValidationError> {
    if let Some(fixed_fields) = &rules.fixed_fields {
        for (path, expected_value) in fixed_fields {
            let found_value =
                get_value_by_path(voucher_json, path).ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
            if found_value != expected_value {
                return Err(ValidationError::FieldValueMismatch {
                    field: path.clone(),
                    expected: expected_value.clone(),
                    found: found_value.clone(),
                });
            }
        }
    }

    if let Some(allowed_values) = &rules.allowed_values {
        for (path, allowed_list) in allowed_values {
            let found_value =
                get_value_by_path(voucher_json, path).ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
            if !allowed_list.contains(found_value) {
                return Err(ValidationError::FieldValueNotAllowed {
                    field: path.clone(),
                    found: found_value.clone(),
                    allowed: allowed_list.clone(),
                });
            }
        }
    }

    if let Some(regex_patterns) = &rules.regex_patterns {
        for (path, pattern) in regex_patterns {
            let found_value =
                get_value_by_path(voucher_json, path).ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
            let found_str = found_value.as_str().unwrap_or_default();
            let re = Regex::new(pattern).map_err(|e| ValidationError::FieldRegexMismatch {
                field: path.clone(), pattern: pattern.clone(), found: e.to_string()
            })?;
            if !re.is_match(found_str) {
                return Err(ValidationError::FieldRegexMismatch {
                    field: path.clone(),
                    pattern: pattern.clone(),
                    found: found_str.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Prüft Verhaltensregeln (erlaubte Transaktionstypen, Gültigkeitsdauer).
pub fn validate_behavior_rules(voucher: &Voucher, rules: &BehaviorRules) -> Result<(), ValidationError> {
    if let Some(allowed_types) = &rules.allowed_t_types {
        for tx in &voucher.transactions {
            if !allowed_types.contains(&tx.t_type) {
                return Err(ValidationError::TransactionTypeNotAllowed {
                    t_type: tx.t_type.clone(),
                    allowed: allowed_types.clone(),
                });
            }
        }
    }

    // Check that the rule stored in the voucher matches the one in the standard
    if let Some(min_validity_rule) = &rules.issuance_minimum_validity_duration {
        if &voucher.standard_minimum_issuance_validity != min_validity_rule {
            return Err(ValidationError::MismatchedMinimumValidity {
                expected: min_validity_rule.clone(),
                found: voucher.standard_minimum_issuance_validity.clone(),
            }.into());
        }
    }

    // NEU: Prüfung der maximal erlaubten Gültigkeitsdauer bei Erstellung.
    if let Some(max_duration_str) = &rules.max_creation_validity_duration {
        if !max_duration_str.is_empty() {
            let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
                .map_err(|_| ValidationError::InvalidDateLogic { creation: voucher.creation_date.clone(), valid_until: voucher.valid_until.clone() })?
                .with_timezone(&chrono::Utc);
            let valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
                .map_err(|_| ValidationError::InvalidDateLogic { creation: voucher.creation_date.clone(), valid_until: voucher.valid_until.clone() })?
                .with_timezone(&chrono::Utc);

            let max_end_dt = add_iso8601_duration(creation_dt, max_duration_str).map_err(|e| {
                ValidationError::InvalidTransaction(format!(
                    "Failed to calculate max allowed validity duration: {}",
                    e
                ))
            })?;

            if valid_until_dt > max_end_dt {
                return Err(ValidationError::ValidityDurationTooLong {
                    max_allowed: max_duration_str.clone(),
                }.into());
            }
        }
    }
    // NEU: Prüfung der maximal erlaubten Nachkommastellen für alle Beträge.
    if let Some(max_places) = rules.amount_decimal_places {
        // Prüfe den Nennwert des Gutscheins
        check_decimal_places(&voucher.nominal_value.amount, max_places, "nominal_value.amount")?;

        // Prüfe alle Transaktionen
        for (i, tx) in voucher.transactions.iter().enumerate() {
            let amount_path = format!("transactions[{}].amount", i);
            check_decimal_places(&tx.amount, max_places, &amount_path)?;

            if let Some(remainder) = &tx.sender_remaining_amount {
                let remainder_path = format!("transactions[{}].sender_remaining_amount", i);
                check_decimal_places(remainder, max_places, &remainder_path)?;
            }
        }
    }
    Ok(())
}

/// Prüft Regeln, die sich auf die Werteverteilung von Feldern in einer Liste von Objekten beziehen.
/// z.B. "In der Liste der Bürgen muss das Feld 'gender' genau einmal den Wert '1' und einmal '2' haben."
pub fn validate_field_group_rules(
    voucher_json: &Value,
    rules: &HashMap<String, FieldGroupRule>,
) -> Result<(), ValidationError> {
    for (path, rule) in rules {
        let array_value =
            get_value_by_path(voucher_json, path).ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;

        let array = array_value.as_array().ok_or_else(|| ValidationError::InvalidDataType {
            path: path.clone(),
            expected: "Array".to_string(),
        })?;

        let mut value_occurrences: HashMap<String, u32> = HashMap::new();

        for item in array {
            // Wir extrahieren den Wert des relevanten Feldes als String, um ihn zu zählen.
            if let Some(value_node) = item.get(&rule.field) {
                if let Some(s) = value_node.as_str() {
                    *value_occurrences.entry(s.to_string()).or_insert(0) += 1;
                } else if value_node.is_number() || value_node.is_boolean() {
                     *value_occurrences.entry(value_node.to_string()).or_insert(0) += 1;
                }
            }
        }

        for count_rule in &rule.value_counts {
            let found_count = value_occurrences.get(&count_rule.value).copied().unwrap_or(0);
            if found_count < count_rule.min || found_count > count_rule.max {
                return Err(ValidationError::FieldValueCountOutOfBounds {
                    path: path.clone(),
                    field: rule.field.clone(),
                    value: count_rule.value.clone(),
                    min: count_rule.min,
                    max: count_rule.max,
                    found: found_count,
                });
            }
        }
    }
    Ok(())
}

// --- HILFSFUNKTIONEN UND BESTEHENDE KRYPTO-PRÜFUNGEN (leicht angepasst) ---

/// Private Hilfsfunktion zur Überprüfung der Nachkommastellen eines Betrags.
fn check_decimal_places(amount_str: &str, max_places: u8, field_path: &str) -> Result<(), ValidationError> {
    let dec = Decimal::from_str(amount_str).map_err(|_| ValidationError::InvalidAmountFormat {
        path: field_path.to_string(),
        found: amount_str.to_string(),
    })?;
    if dec.scale() > max_places as u32 {
        return Err(ValidationError::InvalidAmountPrecision {
            path: field_path.to_string(),
            max_places,
            found: dec.scale(),
        });
    }
    Ok(())
}
/// Hilfsfunktion, um einen verschachtelten Wert aus einem `serde_json::Value` anhand eines Pfades zu extrahieren.
fn get_value_by_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |current, key| current.get(key)).filter(|v| !v.is_null())
}

/// Hilfsfunktion, die prüft, ob eine einzelne zusätzliche Signatur gültig ist. Gibt bool zurück.
fn is_additional_signature_valid(
    signature_obj: &crate::models::voucher::AdditionalSignature,
    voucher_id: &str,
) -> bool {
    if signature_obj.voucher_id != voucher_id { return false; }

    let mut obj_to_verify = signature_obj.clone();
    obj_to_verify.signature_id = "".to_string();
    obj_to_verify.signature = "".to_string();
    let calculated_id_hash = get_hash(to_canonical_json(&obj_to_verify).unwrap_or_default());
    if calculated_id_hash != signature_obj.signature_id { return false; }

    let public_key = match get_pubkey_from_user_id(&signature_obj.signer_id) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let signature_bytes = match bs58::decode(&signature_obj.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    verify_ed25519(&public_key, signature_obj.signature_id.as_bytes(), &signature)
}

/// Verifiziert die Signatur des Erstellers. (Unverändert)
fn verify_creator_signature(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    let public_key = get_pubkey_from_user_id(&voucher.creator.id)
        .map_err(ValidationError::InvalidCreatorId)?;
    let mut voucher_to_verify = voucher.clone();
    let signature_b58 = voucher_to_verify.creator.signature.clone();
    voucher_to_verify.creator.signature = "".to_string();
    voucher_to_verify.voucher_id = "".to_string();
    voucher_to_verify.transactions.clear();
    voucher_to_verify.guarantor_signatures.clear();
    voucher_to_verify.additional_signatures.clear();
    let signature_bytes = bs58::decode(signature_b58).into_vec().map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
    let voucher_json = to_canonical_json(&voucher_to_verify)?;
    let voucher_hash = get_hash(voucher_json);
    if !verify_ed25519(&public_key, voucher_hash.as_bytes(), &signature) {
        return Err(ValidationError::InvalidCreatorSignature {
            creator_id: voucher.creator.id.clone(),
            data_hash: voucher_hash,
        }.into());
    }
    Ok(())
}

/// Verifiziert die kryptographische Gültigkeit aller Bürgen-Signaturen. (Angepasst)
fn verify_guarantor_signatures(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    let mut seen_guarantors = HashSet::new();

    for guarantor_signature in &voucher.guarantor_signatures {
        // NEU: Sicherheitsprüfung, ob der Ersteller versucht, für sich selbst zu bürgen.
        if guarantor_signature.guarantor_id == voucher.creator.id {
            return Err(ValidationError::CreatorAsGuarantor {
                creator_id: voucher.creator.id.clone(),
            }
            .into());
        }

        // NEU: Prüfung auf doppelte Bürgen
        if !seen_guarantors.insert(&guarantor_signature.guarantor_id) {
            return Err(ValidationError::DuplicateGuarantor {
                guarantor_id: guarantor_signature.guarantor_id.clone(),
            }.into());
        }

        // NEU: Prüfung auf chronologische Korrektheit der Signatur
        if guarantor_signature.signature_time < voucher.creation_date {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "GuarantorSignature".to_string(),
                id: guarantor_signature.signature_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: guarantor_signature.signature_time.clone(),
            }.into());
        }

        if guarantor_signature.voucher_id != voucher.voucher_id {
            return Err(ValidationError::MismatchedVoucherIdInSignature {
                expected: voucher.voucher_id.clone(),
                found: guarantor_signature.voucher_id.clone(),
            }.into());
        }
        let mut signature_to_verify = guarantor_signature.clone();
        signature_to_verify.signature_id = "".to_string();
        signature_to_verify.signature = "".to_string();
        let calculated_signature_id_hash = get_hash(to_canonical_json(&signature_to_verify)?);
        if calculated_signature_id_hash != guarantor_signature.signature_id {
            return Err(ValidationError::InvalidSignatureId(guarantor_signature.signature_id.clone()).into());
        }
        let public_key = get_pubkey_from_user_id(&guarantor_signature.guarantor_id)
            .map_err(|_| ValidationError::InvalidSignature { signer_id: guarantor_signature.guarantor_id.clone() })?;
        let signature_bytes = bs58::decode(&guarantor_signature.signature).into_vec().map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
        if !verify_ed25519(&public_key, guarantor_signature.signature_id.as_bytes(), &signature) {
            return Err(ValidationError::InvalidSignature { signer_id: guarantor_signature.guarantor_id.clone() }.into());
        }
    }
    Ok(())
}

/// Verifiziert die kryptographische Gültigkeit aller zusätzlichen Signaturen. (Angepasst)
fn verify_additional_signatures(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    for signature_obj in &voucher.additional_signatures {
        // NEU: Prüfung auf chronologische Korrektheit der Signatur.
        // Eine Signatur kann nicht vor der Erstellung des Gutscheins existieren.
        if signature_obj.signature_time < voucher.creation_date {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "AdditionalSignature".to_string(),
                id: signature_obj.signature_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: signature_obj.signature_time.clone(),
            }
            .into());
        }

        if !is_additional_signature_valid(signature_obj, &voucher.voucher_id) {
            return Err(ValidationError::InvalidSignature { signer_id: signature_obj.signer_id.clone() }.into());
        }
    }
    Ok(())
}


/// Verifiziert die Integrität, Signaturen und Geschäftslogik der Transaktionsliste. (Weitgehend unverändert)
fn verify_transactions(voucher: &Voucher, _standard: &VoucherStandardDefinition) -> Result<(), VoucherCoreError> {
    if voucher.transactions.is_empty() {
        // This is caught by the data-driven `validate_counts` rule, which should require min=1.
        return Ok(());
    }

    // --- Phase 1: Verify the 'init' transaction basics ---
    let init_tx = &voucher.transactions[0];
    verify_transaction_basics(init_tx, voucher, true)?;
    verify_transaction_integrity_and_signature(init_tx)?;

    // --- Phase 2: Verify all subsequent transactions in the chain ---
    let mut last_tx_hash = get_hash(to_canonical_json(init_tx)?);
    let mut last_tx_time = init_tx.t_time.clone();

    for (i, tx) in voucher.transactions.iter().enumerate().skip(1) {
        let prev_tx = &voucher.transactions[i - 1];

        // Basic and cryptographic checks
        verify_transaction_basics(tx, voucher, false)?;
        verify_transaction_integrity_and_signature(tx)?;

        // Chain integrity checks
        if tx.prev_hash != last_tx_hash {
            return Err(ValidationError::InvalidTransaction("Transaction chain broken: prev_hash does not match hash of previous transaction.".to_string()).into());
        }
        // Prüfe chronologische Reihenfolge
        if tx.t_time < last_tx_time {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Transaction".to_string(),
                id: tx.t_id.clone(),
                time1: last_tx_time,
                time2: tx.t_time.clone(),
            }.into());
        }

        // --- Financial Consistency Check (Look-behind-by-one) ---
        let sender_balance_before_tx = {
            if prev_tx.recipient_id == tx.sender_id {
                Decimal::from_str(&prev_tx.amount)?
            } else if prev_tx.sender_id == tx.sender_id {
                Decimal::from_str(prev_tx.sender_remaining_amount.as_deref().unwrap_or("0"))?
            } else {
                Decimal::ZERO
            }
        };

        let amount_to_send = Decimal::from_str(&tx.amount)?;
        if sender_balance_before_tx < amount_to_send {
            return Err(ValidationError::InsufficientFundsInChain {
                user_id: tx.sender_id.clone(),
                needed: amount_to_send.to_string(),
                available: sender_balance_before_tx.to_string(),
            }.into());
        }

        if tx.t_type == "transfer" && sender_balance_before_tx != amount_to_send {
            return Err(ValidationError::FullTransferAmountMismatch {
                expected: sender_balance_before_tx.to_string(),
                found: amount_to_send.to_string(),
            }.into());
        }

        // HÄRTUNG: Ein 'transfer' darf keinen Restbetrag haben. Dies verhindert mehrdeutige Zustände.
        if tx.t_type == "transfer" && tx.sender_remaining_amount.is_some() {
            return Err(ValidationError::InvalidTransaction(
                "A 'transfer' transaction must not have a sender_remaining_amount.".to_string(),
            )
            .into());
        }

        // NEU: Zusätzliche Prüfung für Split-Transaktionen auf korrekte Bilanz.
        // Dies schließt die "Gelderschaffungs"-Lücke.
        if tx.t_type == "split" {
            let remaining_amount = match tx.sender_remaining_amount.as_deref() {
                Some(rem_str) => Decimal::from_str(rem_str)?,
                None => {
                    return Err(ValidationError::InvalidTransaction(
                        "Split transaction must have a sender_remaining_amount.".to_string(),
                    )
                    .into())
                }
            };

            if sender_balance_before_tx != (amount_to_send + remaining_amount) {
                return Err(ValidationError::InvalidTransaction(format!(
                    "Invalid split balance: previous balance ({}) does not equal sent amount ({}) + remaining amount ({}).",
                    sender_balance_before_tx, amount_to_send, remaining_amount
                )).into());
            }
        }

        // Update state for the next iteration
        last_tx_hash = get_hash(to_canonical_json(tx)?);
        last_tx_time = tx.t_time.clone();
    }

    Ok(())
}
/// Hilfsfunktion, die grundlegende, zustandslose Prüfungen für eine einzelne Transaktion durchführt.
fn verify_transaction_basics(tx: &Transaction, voucher: &Voucher, is_init: bool) -> Result<(), VoucherCoreError> {
    if is_init {
        if tx.t_type != "init" { return Err(ValidationError::InvalidTransaction("First transaction must be of type 'init'.".to_string()).into()); }
        let expected_prev_hash = get_hash(format!("{}{}", &voucher.voucher_id, &voucher.voucher_nonce));
        if tx.prev_hash != expected_prev_hash { return Err(ValidationError::InvalidTransaction("Initial transaction has invalid prev_hash.".to_string()).into()); }
        if tx.sender_id != voucher.creator.id || tx.recipient_id != voucher.creator.id {
            return Err(ValidationError::InitPartyMismatch { expected: voucher.creator.id.clone(), found: tx.sender_id.clone() }.into());
        }
        let nominal_amount = Decimal::from_str(&voucher.nominal_value.amount)?;
        let init_amount = Decimal::from_str(&tx.amount)?;
        if init_amount.normalize() != nominal_amount.normalize() {
            return Err(ValidationError::InitAmountMismatch { expected: nominal_amount.to_string(), found: init_amount.to_string() }.into());
        }
        if tx.t_time < voucher.creation_date {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Initial Transaction".to_string(),
                id: tx.t_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: tx.t_time.clone(),
            }.into());
        }
    } else {
        if tx.t_type == "init" { return Err(ValidationError::InvalidTransaction("Found subsequent transaction with invalid type 'init'.".to_string()).into()); }
        if tx.sender_id == tx.recipient_id { return Err(ValidationError::InvalidTransaction("Sender and recipient cannot be the same in a non-init transaction.".to_string()).into()); }
    }

    if Decimal::from_str(&tx.amount)? <= Decimal::ZERO {
        return Err(ValidationError::NegativeOrZeroAmount { amount: tx.amount.clone() }.into());
    }

    Ok(())
}

/// Hilfsfunktion zur Überprüfung der internen Integrität und Signatur einer Transaktion. (Unverändert)
fn verify_transaction_integrity_and_signature(transaction: &Transaction) -> Result<(), VoucherCoreError> {
    let mut tx_for_tid_calc = transaction.clone();
    tx_for_tid_calc.t_id = "".to_string();
    tx_for_tid_calc.sender_signature = "".to_string();
    let calculated_tid = get_hash(to_canonical_json(&tx_for_tid_calc)?);
    if transaction.t_id != calculated_tid {
        return Err(ValidationError::MismatchedTransactionId {
            t_id: transaction.t_id.clone(),
        }.into());
    }

    let signature_payload = json!({
        "prev_hash": transaction.prev_hash,
        "sender_id": transaction.sender_id,
        "t_id": transaction.t_id
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
    let sender_pub_key = get_pubkey_from_user_id(&transaction.sender_id)?;
    let signature_bytes = bs58::decode(&transaction.sender_signature).into_vec()?;
    let signature = Signature::from_slice(&signature_bytes)?;
    if !verify_ed25519(&sender_pub_key, signature_payload_hash.as_bytes(), &signature) {
        return Err(ValidationError::InvalidTransactionSignature {
            t_id: transaction.t_id.clone(),
            sender_id: transaction.sender_id.clone(),
        }.into());
    }
    Ok(())
}