//! # src/services/voucher_validation.rs
//!
//! Dieses Modul enthält die Logik zur Validierung eines `Voucher`-Objekts
//! gegen die Regeln eines `VoucherStandardDefinition`.

use crate::error::{StandardDefinitionError, ValidationError, VoucherCoreError};
use crate::models::voucher::{Transaction, Voucher, VoucherSignature};
use crate::models::voucher_standard_definition::{
    BehaviorRules, ContentRules, CountRules, FieldGroupRule, RequiredSignatureRule,
    VoucherStandardDefinition,
};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, verify_ed25519};
use crate::services::utils::to_canonical_json;
use crate::services::voucher_manager::add_iso8601_duration;

use ed25519_dalek::{Signature, Verifier};
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
    // --- Grundlegende Identitäts- und Integritätsprüfungen (MUSS ZUERST ERFOLGEN) ---
    // 1. Stelle sicher, dass der Gutschein zu diesem Standard gehört.
    verify_standard_identity(voucher, standard)?;
    // 2. Stelle sicher, dass die Stammdaten des Gutscheins nicht manipuliert wurden.
    //    (Prüft voucher.voucher_id gegen hash(voucher_stammdaten))
    verify_voucher_hash(voucher)?;

    // --- FIX (FEHLER 5): Datum-Parsing HÄRTEN ---
    // Parsen der Zeitstempel MUSS vor dem Vergleich erfolgen.
    let creation_dt = chrono::DateTime::parse_from_rfc3339(&voucher.creation_date)
        .map_err(|_| ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        })?
        .with_timezone(&chrono::Utc);
    let valid_until_dt = chrono::DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|_| ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        })?
        .with_timezone(&chrono::Utc);

    if valid_until_dt < creation_dt {
        return Err(ValidationError::InvalidDateLogic {
            creation: voucher.creation_date.clone(),
            valid_until: voucher.valid_until.clone(),
        }
        .into());
    }

    // Führe die datengesteuerten Validierungsregeln aus, falls sie im Standard definiert sind.
    if let Some(rules) = &standard.validation {
        let voucher_json = serde_json::to_value(voucher)?;

        if let Some(count_rules) = &rules.counts {
            // HINWEIS: Signaturen werden jetzt über FieldGroupRules gezählt.
            validate_transaction_count(voucher, count_rules)?;
        }
        if let Some(signature_rules) = &rules.required_signatures {
            validate_required_signatures(voucher, signature_rules)?;
        }
        if let Some(content_rules) = &rules.content_rules {
            validate_content_rules(&voucher_json, content_rules)?;
        }
        if let Some(behavior_rules) = &rules.behavior_rules {
            validate_behavior_rules(voucher, behavior_rules, creation_dt, valid_until_dt)?;
        }
        if let Some(field_group_rules) = &rules.field_group_rules {
            validate_field_group_rules(&voucher_json, field_group_rules)?;
        }
    }

    verify_transactions(voucher, standard)?;

    // Signaturen als letztes prüfen, da sie auf den IDs/Hashes der anderen Komponenten basieren.
    verify_signatures(voucher)?;
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
pub fn validate_transaction_count(
    voucher: &Voucher,
    rules: &CountRules,
) -> Result<(), ValidationError> {
    // HINWEIS: Signatur-Zählungen wurden entfernt und werden nun über FieldGroupRules gehandhabt.
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
    let all_signatures: Vec<_> = voucher
        .signatures
        .iter()
        .map(|sig| (&sig.signer_id, &sig.role, is_signature_valid(sig)))
        .collect();

    for rule in rules {
        if !rule.is_mandatory {
            continue;
        }

        let is_fulfilled = all_signatures.iter().any(|(signer_id, role, is_valid)| {
            let id_matches = rule.allowed_signer_ids.contains(signer_id);
            let role_matches = &rule.required_role == *role;

            id_matches && role_matches && is_valid.is_ok()
        });

        if !is_fulfilled {
            return Err(ValidationError::MissingRequiredSignature {
                role: rule.required_role.clone(),
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
            let found_value = get_value_by_path(voucher_json, path)
                .ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
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
            let found_value = get_value_by_path(voucher_json, path)
                .ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
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
            let found_value = get_value_by_path(voucher_json, path)
                .ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;
            let found_str = found_value.as_str().unwrap_or_default();
            let re = Regex::new(pattern).map_err(|e| ValidationError::FieldRegexMismatch {
                field: path.clone(),
                pattern: pattern.clone(),
                found: e.to_string(),
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
pub fn validate_behavior_rules(
    voucher: &Voucher,
    rules: &BehaviorRules,
    creation_dt: chrono::DateTime<chrono::Utc>,
    valid_until_dt: chrono::DateTime<chrono::Utc>,
) -> Result<(), ValidationError> {
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
        if &voucher
            .voucher_standard
            .template
            .standard_minimum_issuance_validity
            != min_validity_rule
        {
            return Err(ValidationError::MismatchedMinimumValidity {
                expected: min_validity_rule.clone(),
                found: voucher
                    .voucher_standard
                    .template
                    .standard_minimum_issuance_validity
                    .clone(),
            }
            .into());
        }
    }

    // NEU: Prüfung der maximal erlaubten Gültigkeitsdauer bei Erstellung.
    if let Some(max_duration_str) = &rules.max_creation_validity_duration {
        if !max_duration_str.is_empty() {
            let max_end_dt = add_iso8601_duration(creation_dt, max_duration_str).map_err(|e| {
                ValidationError::InvalidTransaction(format!(
                    "Failed to calculate max allowed validity duration: {}",
                    e
                ))
            })?;

            if valid_until_dt > max_end_dt {
                return Err(ValidationError::ValidityDurationTooLong {
                    max_allowed: max_duration_str.clone(),
                }
                .into());
            }
        }
    }
    // NEU: Prüfung der maximal erlaubten Nachkommastellen für alle Beträge.
    if let Some(max_places) = rules.amount_decimal_places {
        // Prüfe den Nennwert des Gutscheins
        check_decimal_places(
            &voucher.nominal_value.amount,
            max_places,
            "nominal_value.amount",
        )?;

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
        let array_value = get_value_by_path(voucher_json, path)
            .ok_or_else(|| ValidationError::PathNotFound { path: path.clone() })?;

        let array = array_value
            .as_array()
            .ok_or_else(|| ValidationError::InvalidDataType {
                path: path.clone(),
                expected: "Array".to_string(),
            })?;

        // HINWEIS: Der 'effective_field_path' (z.B. "details.gender") kommt direkt
        // aus der TOML-Regel. Der Diagnose-Test in `tests/validation/unit_service.rs`
        // bestätigt, dass `serde` das Feld wie erwartet als "details" serialisiert.
        let effective_field_path = rule.field.clone();

        // [DEBUG]
        println!(
            "[DEBUG VALIDATION] Checking field_group_rule for path: '{}', field: '{}'",
            path, &effective_field_path
        );

        let mut value_occurrences: HashMap<String, u32> = HashMap::new();

        for item in array {
            // [DEBUG]
            // println!("[DEBUG VALIDATION]   Item: {:?}", item); // Kann sehr gesprächig sein, optional einkommentieren

            // KORREKTUR: Der Pfad ist 'details.'. Die 'creator'-Signatur hat (absichtlich) keine 'details'.
            if effective_field_path.starts_with("details.")
                && item.get("role").and_then(Value::as_str) == Some("creator")
            {
                continue; // Die 'creator'-Signatur wird bei 'details'-Regeln übersprungen.
                          // [DEBUG]
                          // println!("[DEBUG VALIDATION]     Skipping rule for 'creator'.");
            }

            // Wir extrahieren den Wert des relevanten Feldes als String, um ihn zu zählen.
            if let Some(value_node) = get_value_by_path(item, &effective_field_path) {
                // [DEBUG]
                println!("[DEBUG VALIDATION]     Found value_node: {:?}", value_node);

                if let Some(s) = value_node.as_str() {
                    *value_occurrences.entry(s.to_string()).or_insert(0) += 1;
                } else if value_node.is_number() || value_node.is_boolean() {
                    *value_occurrences.entry(value_node.to_string()).or_insert(0) += 1;
                }
            } else {
                // [DEBUG]
                // HINWEIS: Dies ist normal für den 'creator', wenn die Regel 'details.gender' ist.
                println!(
                    "[DEBUG VALIDATION]     Field '{}' not found in item (Role: {:?}).",
                    &effective_field_path,
                    item.get("role").and_then(Value::as_str).unwrap_or("N/A")
                );
            }
        }

        for count_rule in &rule.value_counts {
            let found_count = value_occurrences
                .get(&count_rule.value)
                .copied()
                .unwrap_or(0);
            if found_count < count_rule.min || found_count > count_rule.max {
                return Err(ValidationError::FieldValueCountOutOfBounds {
                    path: path.clone(),
                    field: rule.field.clone(), // Im Fehler den *Originalpfad* aus der TOML anzeigen
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
fn check_decimal_places(
    amount_str: &str,
    max_places: u8,
    field_path: &str,
) -> Result<(), ValidationError> {
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
pub fn get_value_by_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, key| current.get(key))
        .filter(|v| !v.is_null())
}

/// Hilfsfunktion, die prüft, ob eine einzelne zusätzliche Signatur gültig ist. Gibt bool zurück.
fn is_signature_valid(signature_obj: &VoucherSignature) -> Result<(), ValidationError> {
    let mut obj_to_verify = signature_obj.clone();
    obj_to_verify.signature_id = "".to_string();
    obj_to_verify.signature = "".to_string();
    let calculated_id_hash = get_hash(to_canonical_json(&obj_to_verify).unwrap_or_default());

    if calculated_id_hash != signature_obj.signature_id {
        return Err(ValidationError::InvalidSignatureId(
            signature_obj.signature_id.clone(),
        ));
    }

    // Prüfung 3: Ist die kryptographische Signatur selbst gültig?
    let public_key = match get_pubkey_from_user_id(&signature_obj.signer_id) {
        Ok(pk) => pk,
        Err(e) => return Err(ValidationError::InvalidCreatorId(e)), // Wiederverwenden des Creator-ID-Fehlers
    };
    let signature_bytes = match bs58::decode(&signature_obj.signature).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => return Err(ValidationError::SignatureDecodeError(e.to_string())),
    };

    // KORREKTUR: Verwende die robustere Pars-Logik aus `signature_manager.rs`,
    // um die 64-Byte-Länge explizit zu prüfen.
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        ValidationError::SignatureDecodeError(
            "Invalid signature length: must be 64 bytes".to_string(),
        )
    })?;
    // KORREKTUR: Verwende `from_bytes` statt `from_slice`
    let signature = Signature::from_bytes(&signature_array);

    if !verify_ed25519(
        &public_key,
        signature_obj.signature_id.as_bytes(),
        &signature,
    ) {
        return Err(ValidationError::InvalidSignature {
            signer_id: signature_obj.signer_id.clone(),
        });
    }

    Ok(())
}

/// Verifiziert die kryptographische Gültigkeit, Einzigartigkeit und chronologische
/// Korrektheit aller Signaturen in der `signatures`-Liste.
fn verify_signatures(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    let mut seen_signers = HashSet::new();

    for signature_obj in &voucher.signatures {
        // --- FIX (FEHLER 3): Reihenfolge geändert ---
        // Sicherheitsprüfung, ob der Ersteller versucht, als Bürge zu agieren.
        // Muss VOR der Duplikatsprüfung stattfinden.
        if signature_obj.role == "guarantor"
            && Some(&signature_obj.signer_id) == voucher.creator_profile.id.as_ref()
        {
            return Err(ValidationError::CreatorAsGuarantor {
                creator_id: voucher.creator_profile.id.clone().unwrap_or_default(),
            }
            .into());
        }

        // Prüfung auf doppelte Unterzeichner
        if !seen_signers.insert(&signature_obj.signer_id) {
            return Err(ValidationError::DuplicateGuarantor {
                guarantor_id: signature_obj.signer_id.clone(), // Behalte den Fehlertyp bei, auch wenn er "DuplicateSigner" sein sollte
            }
            .into());
        }
        // Prüfung auf chronologische Korrektheit der Signatur.
        // Eine Signatur kann nicht vor der Erstellung des Gutscheins existieren.
        if signature_obj.signature_time < voucher.creation_date {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Signature".to_string(),
                id: signature_obj.signature_id.clone(),
                time1: voucher.creation_date.clone(),
                time2: signature_obj.signature_time.clone(),
            }
            .into());
        }

        // Kryptographische Prüfung der Signatur selbst.
        // HIER IST DIE ÄNDERUNG: Wir rufen die Funktion auf und leiten den
        // spezifischen Fehler (z.B. InvalidSignatureId, MismatchedVoucherId,
        // InvalidSignature) direkt per '?' weiter.
        is_signature_valid(signature_obj)?;
    }
    Ok(())
}

/// --- NEUE FUNKTION (FIX FÜR FEHLER 4) ---
/// Verifiziert, dass der `voucher_id` (der Hash der Stammdaten) mit den
/// tatsächlichen Stammdaten übereinstimmt.
fn verify_voucher_hash(voucher: &Voucher) -> Result<(), VoucherCoreError> {
    let mut voucher_to_hash = voucher.clone();
    // Entferne die Felder, die nicht Teil des ursprünglichen Hashes sind.
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();

    let calculated_hash = get_hash(to_canonical_json(&voucher_to_hash)?);

    if calculated_hash != voucher.voucher_id {
        Err(ValidationError::InvalidVoucherHash.into())
    } else {
        Ok(())
    }
}

/// Verifiziert die Integrität, Signaturen und Geschäftslogik der Transaktionsliste. (Weitgehend unverändert)
fn verify_transactions(
    voucher: &Voucher,
    _standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.transactions.is_empty() {
        // This is caught by the data-driven `validate_counts` rule, which should require min=1.
        return Ok(()); // TODO: Sollte dies nicht ein Fehler sein? Oder wird es von `validate_transaction_count` abgefangen?
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
            return Err(ValidationError::InvalidTransaction(
                "Transaction chain broken: prev_hash does not match hash of previous transaction."
                    .to_string(),
            )
            .into());
        }
        // Prüfe chronologische Reihenfolge
        if tx.t_time < last_tx_time {
            return Err(ValidationError::InvalidTimeOrder {
                entity: "Transaction".to_string(),
                id: tx.t_id.clone(),
                time1: last_tx_time,
                time2: tx.t_time.clone(),
            }
            .into());
        }

        // --- P2PKH Verkettungs-Validierung ---
        // Prüfe, dass der in dieser Tx enthüllte sender_ephemeral_pub
        // dem Hash in der vorherigen Tx entspricht (receiver_ephemeral_pub_hash)
        if let (Some(revealed_pub), Some(prev_anchor)) = (
            &tx.sender_ephemeral_pub,
            &prev_tx.receiver_ephemeral_pub_hash,
        ) {
            let calculated_hash = get_hash(revealed_pub.clone());
            if calculated_hash != *prev_anchor {
                return Err(ValidationError::InvalidTransaction(
                    "P2PKH chain broken: sender_ephemeral_pub does not match previous receiver_ephemeral_pub_hash".to_string(),
                )
                .into());
            }
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

        // Update state for the next iteration
        last_tx_hash = get_hash(to_canonical_json(tx)?);
        last_tx_time = tx.t_time.clone();
    }

    Ok(())
}
/// Hilfsfunktion, die grundlegende, zustandslose Prüfungen für eine einzelne Transaktion durchführt.
fn verify_transaction_basics(
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
        let expected_prev_hash =
            get_hash(format!("{}{}", &voucher.voucher_id, &voucher.voucher_nonce));
        if tx.prev_hash != expected_prev_hash {
            return Err(ValidationError::InvalidTransaction(
                "Initial transaction has invalid prev_hash.".to_string(),
            )
            .into());
        }
        if Some(&tx.sender_id) != voucher.creator_profile.id.as_ref()
            || Some(&tx.recipient_id) != voucher.creator_profile.id.as_ref()
        {
            return Err(ValidationError::InitPartyMismatch {
                expected: voucher.creator_profile.id.clone().unwrap_or_default(),
                found: tx.sender_id.clone(),
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
        if tx.sender_id == tx.recipient_id {
            return Err(ValidationError::InvalidTransaction(
                "Sender and recipient cannot be the same in a non-init transaction.".to_string(),
            )
            .into());
        }
    }

    if Decimal::from_str(&tx.amount)? <= Decimal::ZERO {
        return Err(ValidationError::NegativeOrZeroAmount {
            amount: tx.amount.clone(),
        }
        .into());
    }

    Ok(())
}

/// Hilfsfunktion zur Überprüfung der internen Integrität und Signatur einer Transaktion. (Unverändert)
fn verify_transaction_integrity_and_signature(
    transaction: &Transaction,
) -> Result<(), VoucherCoreError> {
    // 1. Basis-Integrität prüfen (t_id Berechnung)
    let mut tx_for_tid_calc = transaction.clone();

    // WICHTIG: Um die ID zu validieren, müssen wir die Sender-Signatur entfernen.
    tx_for_tid_calc.t_id = "".to_string();
    tx_for_tid_calc.sender_signature = "".to_string();

    // L2-Logik: Falls eine Layer-2-Signatur vorhanden ist, ist sie Teil des JSONs
    // und somit Teil der t_id. Wir müssen sie hier NICHT entfernen für die t_id Prüfung,
    // da die t_id im Voucher die L2-Sig inkludiert.

    let calculated_tid = get_hash(to_canonical_json(&tx_for_tid_calc)?);
    if transaction.t_id != calculated_tid {
        return Err(ValidationError::MismatchedTransactionId {
            t_id: transaction.t_id.clone(),
        }
        .into());
    }

    // 2. Layer-2 Signatur Validierung (Optional, wenn vorhanden)
    if let Some(l2_sig) = &transaction.layer2_signature {
        // P2PKH Logik: Wir verifizieren gegen den SENDER PubKey (der enthüllt wurde),
        // nicht gegen den Receiver (der jetzt ein Hash ist).
        if let Some(sender_ephem_pub) = &transaction.sender_ephemeral_pub {
            // Um den Hash für die L2-Signatur zu rekonstruieren, brauchen wir die ID
            // so wie sie WAR, BEVOR die L2-Signatur hinzugefügt wurde.
            let mut tx_pre_l2 = tx_for_tid_calc.clone();
            tx_pre_l2.layer2_signature = None; // Entfernen für pre-l2-hash

            let pre_l2_tid = get_hash(to_canonical_json(&tx_pre_l2)?);
            let valid_until = transaction.valid_until.as_deref().unwrap_or("");

            let l2_payload = format!("{}{}{}", pre_l2_tid, valid_until, sender_ephem_pub);
            let l2_hash = get_hash(l2_payload);

            // Dekodiere Key & Sig
            let ephem_pub_bytes = bs58::decode(sender_ephem_pub).into_vec().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid ephemeral pubkey".into())
            })?;
            let l2_sig_bytes = bs58::decode(l2_sig).into_vec().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid l2 signature".into())
            })?;

            // Verifiziere (Low-Level-Call wäre besser, hier manuell via dalek Wrapper logic)
            let ephem_key = ed25519_dalek::VerifyingKey::from_bytes(
                ephem_pub_bytes.as_slice().try_into().unwrap(),
            )
            .map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid ephemeral pubkey bytes".into())
            })?;
            let signature = Signature::from_bytes(l2_sig_bytes.as_slice().try_into().unwrap());

            if ephem_key.verify(l2_hash.as_bytes(), &signature).is_err() {
                return Err(ValidationError::InvalidSignature {
                    signer_id: "Layer2-Anchor".to_string(),
                }
                .into());
            }
        }
    }

    // 3. Sender Signatur Validierung
    let signature_payload = json!({
        "prev_hash": transaction.prev_hash,
        "sender_id": transaction.sender_id,
        "t_id": transaction.t_id
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
    let sender_pub_key = get_pubkey_from_user_id(&transaction.sender_id)?;
    let signature_bytes = bs58::decode(&transaction.sender_signature).into_vec()?;

    // KORREKTUR: Verwende die robuste Pars-Logik, um 64-Byte-Länge zu prüfen.
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        ValidationError::SignatureDecodeError(
            "Invalid transaction signature length: must be 64 bytes".to_string(),
        )
    })?;
    let signature = Signature::from_bytes(&signature_array);

    if !verify_ed25519(
        &sender_pub_key,
        signature_payload_hash.as_bytes(),
        &signature,
    ) {
        return Err(ValidationError::InvalidTransactionSignature {
            t_id: transaction.t_id.clone(),
            sender_id: transaction.sender_id.clone(),
        }
        .into());
    }
    Ok(())
}
