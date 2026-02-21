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
use crate::services::crypto_utils::{
    ed25519_pk_to_curve_point, get_hash, get_hash_from_slices, get_pubkey_from_user_id,
    verify_ed25519,
};
use crate::services::trap_manager::verify_trap;
use crate::services::utils::to_canonical_json;
use crate::services::voucher_manager::add_iso8601_duration;

use ed25519_dalek::{Signature, Verifier};
use regex::Regex;
use rust_decimal::Decimal;
use serde_json::Value;
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

    // NEU: Validierung des Privacy-Modes
    let privacy_mode = standard.privacy.as_ref().map(|p| p.mode.as_str()).unwrap_or("public");
    validate_privacy_mode(voucher, privacy_mode)?;

    verify_transactions(voucher, standard)?;

    // Signaturen als letztes prüfen, da sie auf den IDs/Hashes der anderen Komponenten basieren.
    verify_signatures(voucher)?;
    Ok(())
}

/// Validiert die Einhaltung des Privacy-Modes für alle Transaktionen.
fn validate_privacy_mode(voucher: &Voucher, mode: &str) -> Result<(), VoucherCoreError> {
    for (i, tx) in voucher.transactions.iter().enumerate() {
        // Init-Transaktion (Index 0) ist IMMER public (Creator ist bekannt).
        if i == 0 {
            if tx.sender_id.is_none() {
                return Err(ValidationError::InvalidTransaction(
                    "Init transaction must always have a sender_id (creator).".to_string()
                ).into());
            }
            continue;
        }

        if tx.t_type == "init" {
            continue;
        }

        // Global check for whitespace obfuscation (Test 4)
        if tx.recipient_id.trim() != tx.recipient_id {
             return Err(ValidationError::InvalidTransaction(
                format!("Transaction {} has recipient_id with leading/trailing whitespace (obfuscation attempt).", tx.t_id)
            ).into());
        }

        match mode {
            "public" => {
                // 1. sender_id muss vorhanden sein.
                if tx.sender_id.is_none() {
                    return Err(ValidationError::InvalidTransaction(
                        format!("Transaction {} missing sender_id in 'public' mode.", tx.t_id)
                    ).into());
                }
                // 2. recipient_id muss eine DID sein.
                if !tx.recipient_id.starts_with("did:") && !tx.recipient_id.contains("@did:") {
                    return Err(ValidationError::InvalidTransaction(
                        format!("Transaction {} has non-DID recipient in 'public' mode.", tx.t_id)
                    ).into());
                }
            }
            "stealth" => {
                // 1. sender_id darf NICHT vorhanden sein.
                if tx.sender_id.is_some() {
                    return Err(ValidationError::InvalidTransaction(
                        format!("Transaction {} has sender_id in 'stealth' mode.", tx.t_id)
                    ).into());
                }
                // 2. sender_identity_signature darf NICHT vorhanden sein (Test 1).
                if tx.sender_identity_signature.is_some() {
                    return Err(ValidationError::StealthSignatureLeak { t_id: tx.t_id.clone() }.into());
                }
                // 3. recipient_id darf KEINE DID sein (muss anonym sein).
                if tx.recipient_id.starts_with("did:") {
                     return Err(ValidationError::InvalidTransaction(
                        format!("Transaction {} has public DID recipient in 'stealth' mode.", tx.t_id)
                    ).into());
                }
            }
            "flexible" => {
                // Check consistency: If anonymous (no sender_id), there must be no identity signature (Test 2).
                if tx.sender_id.is_none() && tx.sender_identity_signature.is_some() {
                    return Err(ValidationError::FlexibleModeIdentityInconsistency { t_id: tx.t_id.clone() }.into());
                }
            }
            _ => return Err(VoucherCoreError::Standard(StandardDefinitionError::InvalidMode(mode.to_string()))),
        }
    }
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
                if let Some(s) = value_node.as_str() {
                    *value_occurrences.entry(s.to_string()).or_insert(0) += 1;
                } else if value_node.is_number() || value_node.is_boolean() {
                    *value_occurrences.entry(value_node.to_string()).or_insert(0) += 1;
                }
            } else {
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
    #[cfg(feature = "test-utils")]
    if crate::is_signature_bypass_active() {
        return Ok(());
    }

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
pub fn verify_transactions(
    voucher: &Voucher,
    _standard: &VoucherStandardDefinition,
) -> Result<(), VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(VoucherCoreError::Validation(ValidationError::InvalidTransaction(
            "Transaction list is empty.".to_string(),
        )));
    }

    // --- Phase 1: Verify the 'init' transaction basics ---
    let init_tx = voucher.transactions.get(0).ok_or_else(|| {
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(
            "Transaction list is empty.".to_string(),
        ))
    })?;
    let layer2_voucher_id = crate::services::l2_gateway::extract_layer2_voucher_id(voucher)?;

    verify_transaction_basics(init_tx, voucher, true)?;
    verify_transaction_integrity_and_signature(init_tx, &layer2_voucher_id)?;

    // --- Phase 2: Verify all subsequent transactions in the chain ---
    let mut last_tx_hash = get_hash(to_canonical_json(init_tx)?);
    let mut last_tx_time = init_tx.t_time.clone();
    
    // Track valid outputs from the previous transaction that can be spent.
    // For init/transfer: [amount]
    // For split: [amount, remaining]
    // The next transaction MUST consume exactly one of these values.
    let mut valid_previous_outputs = vec![Decimal::from_str(&init_tx.amount)?];

    for (i, tx) in voucher.transactions.iter().enumerate().skip(1) {
        let prev_tx = &voucher.transactions[i - 1];

        // Basic and cryptographic checks
        verify_transaction_basics(tx, voucher, false)?;
        verify_transaction_integrity_and_signature(tx, &layer2_voucher_id)?;

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
        
        // --- Amount Continuity Check ---
        let current_amount = Decimal::from_str(&tx.amount)?;
        let current_remainder = if let Some(rem) = &tx.sender_remaining_amount {
             Decimal::from_str(rem)?
        } else {
             Decimal::ZERO
        };
        let total_input_needed = current_amount + current_remainder;
        
        // Check if `total_input_needed` matches any of the valid previous outputs
        let mut match_found = false;
        for valid_out in &valid_previous_outputs {
             // Use normalize() for comparison to handle trailing zeros (e.g. 100.00 vs 100)
             if total_input_needed.normalize() == valid_out.normalize() {
                 match_found = true;
                 break;
             }
        }
        
        if !match_found {
             return Err(ValidationError::InsufficientFundsInChain {
                 user_id: tx.sender_id.clone().unwrap_or_else(|| "anonymous".to_string()),
                 needed: total_input_needed.to_string(),
                 // We just show the first valid output for simplicity in error message, 
                 // or maybe format all of them?
                 available: valid_previous_outputs.iter().map(|d| d.to_string()).collect::<Vec<_>>().join(" or "),
             }.into());
        }
        
        // Update valid outputs for next iteration
        valid_previous_outputs.clear();
        valid_previous_outputs.push(current_amount);
        if let Some(rem) = &tx.sender_remaining_amount {
             valid_previous_outputs.push(Decimal::from_str(rem)?);
        }


        // --- P2PKH Verkettungs-Validierung ---
        // Prüfe, dass der in dieser Tx enthüllte sender_ephemeral_pub
        // dem Hash in der vorherigen Tx entspricht.
        if let Some(revealed_pub) = &tx.sender_ephemeral_pub {
            let correct_anchor = if prev_tx.recipient_id == tx.sender_id.clone().unwrap_or_default() { // Fall: Sender identifiziert sich als Empfänger
                 // ACHTUNG: Wenn sender_id NONE ist (Stealth), matcht das hier nicht auf recipient_id (die ja meist auch Hash/Anon ist).
                 // In Stealth müssen wir rein kryptographisch prüfen.
                 // Aber: Wir wissen nicht, OB wir der Empfänger waren, außer wir probieren es?
                 // Nein, Validierung ist öffentlich. Jeder muss es prüfen können.
                 // LÖSUNG: Wir können nicht rein an IDs festmachen, wer der Parent war, wenn IDs fehlen.
                 // Wir müssen PRÜFEN, ob der Hash passt.
                 
                 // Versuch 1: Passt es zum Receiver Hash der Vor-Tx?
                  // SECURITY FIX: Decode Base58 and hash raw bytes
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
                 // Fallback für explizite ID Matches (Public Mode)
                 if Some(prev_tx.recipient_id.clone()) == tx.sender_id {
                      prev_tx.receiver_ephemeral_pub_hash.as_ref()
                 } else if tx.sender_id.is_some() && tx.sender_id == prev_tx.sender_id {
                      prev_tx.change_ephemeral_pub_hash.as_ref()
                 } else {
                     // Wenn keine ID Matcht, versuchen wir den Hash-Match (siehe oben)
                     // SECURITY FIX: Decode Base58 and hash raw bytes
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
                 }
            };

            if correct_anchor.is_none() {
                 return Err(ValidationError::InvalidTransaction(
                    "P2PKH chain broken: sender_ephemeral_pub does not match any previous anchor.".to_string(),
                )
                .into());
            }
        }

        // --- TRAP Validierung ---
        if let Some(trap) = &tx.trap_data {
            // TEST 3: Prevent Trapezoidal Identity Leak
            if trap.blinded_id.contains(':') || trap.blinded_id.contains('@') {
                 return Err(ValidationError::TrapDataInvalid { t_id: tx.t_id.clone() }.into());
            }

            // GLOBAL CHECK (Context Binding):
            // The DS-Tag MUST be derived from the transaction context (prev_hash + sender_ephemeral_pub).
            // This prevents Replay Attacks where a valid Trap is reused in a different transaction context.
            // This check applies to BOTH Public and Stealth modes.
            
            // SECURITY FIX: Decode to raw bytes to prevent string malleability
            let prev_hash_bytes = bs58::decode(&tx.prev_hash).into_vec().map_err(|_| {
                VoucherCoreError::Crypto("Invalid prev_hash format".to_string())
            })?;
            let ephem_pub_bytes = tx.sender_ephemeral_pub.as_ref().map(|s| bs58::decode(s).into_vec()).transpose().map_err(|_| {
                VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string())
            })?.unwrap_or_default();

            let expected_ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &ephem_pub_bytes]);
            
            if trap.ds_tag != expected_ds_tag {
                 return Err(VoucherCoreError::Crypto(
                     format!("Trap DS-Tag does not match expected input (Context Mismatch/Replay). Expected: {}, Found: {}", expected_ds_tag, trap.ds_tag)
                 ));
            }

            // Full ZKP Verification (Only possible if sender_id is known)
            if let Some(sender_id) = &tx.sender_id {
                if let Ok(signer_pk) = get_pubkey_from_user_id(sender_id) {
                    if let Ok(signer_id_point) = ed25519_pk_to_curve_point(&signer_pk) {
                         let sender_prefix = sender_id.split('@').next().unwrap_or(sender_id).to_string();
                         
                        let u_input_varying = format!(
                            "{}{}{}",
                            expected_ds_tag,
                            tx.amount,
                            tx.receiver_ephemeral_pub_hash.as_deref().unwrap_or("")
                        );
                        
                        if let Err(e) = verify_trap(trap, &expected_ds_tag, u_input_varying.as_bytes(), &signer_id_point, &sender_prefix) {
                             return Err(ValidationError::InvalidTransaction(format!("Trap verification failed: {}", e)).into());
                        }
                    }
                }
            }
        }

        // --- Financial Consistency Check (Look-behind-by-one) ---
        let sender_balance_before_tx = {
            // Wir müssen herausfinden, ob wir der Recipient oder der Sender (Change) der Vor-Tx waren.
            // Da wir ggf. keine IDs haben, nutzen wir den Match aus der P2PKH Prüfung?
            // Vereinfachung: Wir schauen auf die Beträge und P2PKH Link.
            // Da wir oben "correct_anchor" nicht exponiert haben, hier heuristisch:
            
            // Wenn Recipient Balance matching?
            // "Look-behind": 
            // - War prev_tx.recipient der Vorbesitzer?
            // - War prev_tx.sender (Change) der Vorbesitzer?
            
            // Wenn wir den Key revealt haben, der zu RecipientHash passt -> Balance = Amount
            // Wenn wir den Key revealt haben, der zu ChangeHash passt -> Balance = Remaining
            
            // AUSTAUSCH DER LOGIK: Statt ID-Check nun Hash-Check
            let my_revealed_pub_hash = if let Some(k) = &tx.sender_ephemeral_pub {
                let bytes = bs58::decode(k).into_vec().map_err(|_| {
                    VoucherCoreError::Crypto("Invalid base58 encoding in sender_ephemeral_pub".to_string())
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
                // Fallback für alte Logik / Init
                if tx.t_type == "init" {
                    Decimal::ZERO // Init hat keinen Vorgänger in dem Sinne, Balance Check ist anders
                } else {
                     // Wenn keine kryptographische Verbindung -> Error (wurde oben schon gefangen eigentlich)
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
        // SECURITY FIX: Use raw bytes for concatenation to avoid malleability
        let nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().map_err(|_| {
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
            || (voucher.creator_profile.id.is_some() && Some(&tx.recipient_id) != voucher.creator_profile.id.as_ref())
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
                "Transaction of type 'transfer' must not have a sender_remaining_amount.".to_string(),
            )
            .into());
        }
    } else if !is_init {
         // Allow unknown types? Probably not safe.
         // For now, let's stick to known types.
         return Err(ValidationError::InvalidTransaction(
             format!("Unknown transaction type: {}", tx.t_type)
         ).into());
    }

    if Decimal::from_str(&tx.amount)? <= Decimal::ZERO {
        return Err(ValidationError::NegativeOrZeroAmount {
            amount: tx.amount.clone(),
        }
        .into());
    }
    
    // Check remaining amount positivity if present
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

/// Prüft die kryptographische Integrität und die Signatur einer einzelnen Transaktion.
pub fn verify_transaction_integrity_and_signature(
    transaction: &Transaction,
    layer2_voucher_id: &str,
) -> Result<(), VoucherCoreError> {
    #[cfg(feature = "test-utils")]
    if crate::is_signature_bypass_active() {
        return Ok(());
    }

    // 1. Basis-Integrität prüfen (t_id Berechnung)
    let mut tx_for_tid_calc = transaction.clone();

    // WICHTIG: Um die ID zu validieren, müssen wir die Signaturen entfernen.
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

    // 2. Layer 2 Signature Validierung (Pflichtfeld)
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
            let signature = Signature::from_bytes(l2_sig_bytes.as_slice().try_into().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid l2 signature length".into())
            })?);

            let t_id_raw = bs58::decode(&transaction.t_id).into_vec().map_err(|_| {
                ValidationError::SignatureDecodeError("Invalid t_id format".into())
            })?;

            // Herausfinden des challenge_ds_tag
            let challenge_ds_tag = if transaction.t_type == "init" {
                transaction.t_id.clone()
            } else {
                transaction.trap_data.as_ref().map(|td| td.ds_tag.clone()).ok_or_else(|| {
                    ValidationError::InvalidTransaction("Missing trap_data for non-init transaction".to_string())
                })?
            };

            let to_32_bytes = |vec: Vec<u8>| -> Result<[u8; 32], ValidationError> {
                vec.try_into().map_err(|_| ValidationError::SignatureDecodeError("Hash must be 32 bytes".into()))
            };

            let receiver_hash_raw = transaction.receiver_ephemeral_pub_hash.as_ref().map(|h| {
                bs58::decode(h).into_vec().map_err(|_| {
                    ValidationError::SignatureDecodeError("Invalid receiver_ephemeral_pub_hash encoding".into())
                })
            }).transpose()?;

            let change_hash_raw = transaction.change_ephemeral_pub_hash.as_ref().map(|h| {
                bs58::decode(h).into_vec().map_err(|_| {
                    ValidationError::SignatureDecodeError("Invalid change_ephemeral_pub_hash encoding".into())
                })
            }).transpose()?;

            let t_id_32 = to_32_bytes(t_id_raw)?;
            let ephem_pub_32 = to_32_bytes(ephem_pub_bytes)?;

            let receiver_hash_32 = match receiver_hash_raw {
                Some(v) => Some(to_32_bytes(v)?),
                None => None
            };

            let change_hash_32 = match change_hash_raw {
                Some(v) => Some(to_32_bytes(v)?),
                None => None
            };

            let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
                &challenge_ds_tag,
                layer2_voucher_id,
                &t_id_32,
                &ephem_pub_32,
                receiver_hash_32.as_ref(),
                change_hash_32.as_ref(),
                transaction.valid_until.as_deref(),
            );

            if ephem_key.verify(&payload_hash, &signature).is_err() {
                return Err(ValidationError::InvalidTransaction("Invalid layer2_signature (Technical Proof)".to_string()).into());
            }
        } else {
            return Err(ValidationError::InvalidTransaction("Missing sender_ephemeral_pub for L2 signature".to_string()).into());
        }
    } else {
        return Err(ValidationError::InvalidTransaction("Missing layer2_signature".to_string()).into());
    }

    // 3. Sender Identity Signature (L1) - Nur prüfen wenn sender_id vorhanden
    if let Some(sender_id) = &transaction.sender_id {
         let identity_sig_enc = transaction.sender_identity_signature.as_ref()
            .ok_or_else(|| ValidationError::InvalidTransaction("Missing sender_identity_signature for public sender".to_string()))?;
            
         let pub_key = get_pubkey_from_user_id(sender_id)?;
          let sig_bytes = bs58::decode(identity_sig_enc).into_vec().map_err(|e| ValidationError::SignatureDecodeError(e.to_string()))?;
          let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
              ValidationError::SignatureDecodeError("Invalid identity signature length".into())
          })?);
         
         // NEU: Signatur prüft direkt die t_id (raw bytes)
         let t_id_raw = bs58::decode(&transaction.t_id).into_vec().map_err(|_| {
             ValidationError::SignatureDecodeError("Invalid t_id format".into())
         })?;
         if pub_key.verify(&t_id_raw, &signature).is_err() {
            return Err(ValidationError::InvalidTransaction("Invalid sender_identity_signature".to_string()).into());
         }
    }

    Ok(())
}
