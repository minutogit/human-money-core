use crate::models::voucher::{
    Collateral, ValueDefinition, Transaction, Voucher, VoucherStandard, VoucherSignature,
};
use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::models::voucher_standard_definition::{VoucherStandardDefinition};
use crate::services::{decimal_utils, standard_manager};
use crate::services::crypto_utils::{get_hash, get_pubkey_from_user_id, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use rand::Rng;
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use std::str::FromStr;
use std::fmt;

// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    /// Der Gutschein ist laut Standard nicht teilbar.
    VoucherNotDivisible,
    /// Das verfügbare Guthaben ist für die Transaktion nicht ausreichend.
    InsufficientFunds { available: Decimal, needed: Decimal },
    /// Der Betrag hat mehr Nachkommastellen als vom Standard erlaubt.
    AmountPrecisionExceeded {
        allowed: u32,
        found: u32,
    },
    /// Ein Template-Wert aus dem Standard ist ungültig (z.B. leer).
    InvalidTemplateValue(String),
    /// Die angegebene Gültigkeitsdauer erfüllt nicht die Mindestanforderungen des Standards.
    InvalidValidityDuration(String),
    /// Ein allgemeiner Fehler mit einer Beschreibung.
    Generic(String),
    /// Ein Validierungsfehler aus dem Validierungsmodul ist aufgetreten.
    ValidationError(String),
}

impl fmt::Display for VoucherManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoucherManagerError::VoucherNotDivisible => write!(f, "Voucher is not divisible according to its standard."),
            VoucherManagerError::InsufficientFunds { available, needed } => {
                write!(f, "Insufficient funds: Available: {}, Needed: {}", available, needed)
            }
            VoucherManagerError::AmountPrecisionExceeded { allowed, found } => {
                write!(f, "Amount precision exceeds standard limit. Allowed: {}, Found: {}", allowed, found)
            }
            VoucherManagerError::InvalidTemplateValue(s) => {
                write!(f, "Invalid template value from standard: {}", s)
            }
            VoucherManagerError::InvalidValidityDuration(s) => write!(f, "Invalid validity duration: {}", s),
            VoucherManagerError::Generic(s) => write!(f, "Voucher Manager Error: {}", s),
            VoucherManagerError::ValidationError(s) => write!(f, "Validation Error: {}", s),
        }
    }
}

impl std::error::Error for VoucherManagerError {}

/// Nimmt einen JSON-String entgegen und deserialisiert ihn in ein `Voucher`-Struct.
pub fn from_json(json_str: &str) -> Result<Voucher, VoucherCoreError> {
    let voucher: Voucher = serde_json::from_str(json_str)?;
    Ok(voucher)
}

/// Serialisiert ein `Voucher`-Struct in einen formatierten JSON-String.
pub fn to_json(voucher: &Voucher) -> Result<String, VoucherCoreError> {
    let json_str = serde_json::to_string_pretty(voucher)?;
    Ok(json_str)
}

/// Eine Hilfsstruktur, die alle notwendigen Daten zur Erstellung eines neuen Gutscheins bündelt.
#[derive(Default, Clone)]
pub struct NewVoucherData {
    pub validity_duration: Option<String>,
    pub non_redeemable_test_voucher: bool,
    pub nominal_value: ValueDefinition,
    pub collateral: Option<Collateral>,
    pub creator_profile: PublicProfile,
}

/// Erstellt ein neues, signiertes `Voucher`-Struct.
///
/// # Arguments
/// * `data` - Die `NewVoucherData`-Struktur mit allen für diesen Gutschein spezifischen Informationen.
/// * `verified_standard` - Die **bereits verifizierte** `VoucherStandardDefinition`.
/// * `standard_hash` - Der **Konsistenz-Hash** des verifizierten Standards.
/// * `creator_signing_key` - Der private Ed25519-Schlüssel des Erstellers zum Signieren.
/// * `lang_preference` - Der bevorzugte Sprachcode (z.B. "de") zur Auswahl des Beschreibungstextes.
///
/// # Returns
/// Ein `Result`, das entweder den vollständig erstellten `Voucher` oder einen `VoucherCoreError` enthält.
pub fn create_voucher(
    data: NewVoucherData,
    verified_standard: &VoucherStandardDefinition,
    standard_hash: &str,
    creator_signing_key: &SigningKey,
    lang_preference: &str,
) -> Result<Voucher, VoucherCoreError> {
    // SICHERHEITSPATCH: Validiere kritische Template-Werte aus dem Standard,
    // um sicherzustellen, dass keine ungültigen Gutscheine erstellt werden.
    if verified_standard.template.fixed.nominal_value.unit.is_empty() {
        return Err(VoucherManagerError::InvalidTemplateValue(
            "template.fixed.nominal_value.unit cannot be empty".to_string(),
        ).into());
    }
    if verified_standard.template.fixed.primary_redemption_type.is_empty() {
        return Err(VoucherManagerError::InvalidTemplateValue(
            "template.fixed.primary_redemption_type cannot be empty".to_string(),
        ).into());
    }

    let creation_date_str = get_current_timestamp();
    let nonce_bytes = rand::thread_rng().gen::<[u8; 16]>();
    let nonce = bs58::encode(nonce_bytes).into_string();
    let creation_dt = DateTime::parse_from_rfc3339(&creation_date_str).unwrap().with_timezone(&Utc);

    let duration_str = data.validity_duration
        .as_deref()
        .or(verified_standard.template.default.default_validity_duration.as_deref())
        .ok_or_else(|| VoucherManagerError::Generic("No validity duration specified and no default found in standard.".to_string()))?;

    let initial_valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    // KORREKTUR: Zugriff auf die neue, verschachtelte Validierungsstruktur
    let min_duration_opt = verified_standard.validation.as_ref()
        .and_then(|v| v.behavior_rules.as_ref())
        .and_then(|b| b.issuance_minimum_validity_duration.as_ref());

    // NEU: "Gatekeeper"-Prüfung bei Erstellung.
    // Verhindert die Erstellung von Gutscheinen, die sofort gegen die "Firewall"-Regel
    // verstoßen würden ("Dead-on-Arrival").
    if let Some(min_duration_str) = min_duration_opt {
        if !min_duration_str.is_empty() {
            let required_end_dt = add_iso8601_duration(creation_dt, min_duration_str)?;
            if initial_valid_until_dt < required_end_dt {
                return Err(VoucherManagerError::InvalidValidityDuration(format!(
                    "Initial validity ({}) is less than the required minimum standard validity ({}).",
                    initial_valid_until_dt.to_rfc3339(),
                    required_end_dt.to_rfc3339()
                )).into());
            }
        }
    }

    let final_valid_until_dt = if let Some(rounding_str) = &verified_standard.template.fixed.round_up_validity_to {
        round_up_date(initial_valid_until_dt, rounding_str)?
    } else {
        initial_valid_until_dt
    };
    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = verified_standard.template.fixed.nominal_value.unit.clone();

    // Prioritize user-defined abbreviation. Fallback to standard's metadata abbreviation.
    if final_nominal_value.abbreviation.is_none() {
        final_nominal_value.abbreviation = Some(verified_standard.metadata.abbreviation.clone());
    }

    // KORRIGIERT: Collateral wird NUR befüllt, wenn der Standard es erlaubt
    // UND der Benutzer (data) es bereitstellt.
    let final_collateral = if !verified_standard.template.fixed.collateral.type_.is_empty() {
        // Standard allows it. Now check if user provided it.
        data.collateral.map(|user_collateral| {
            // User provided it. Use their values but enforce standard's type/condition.
            Collateral {
                value: user_collateral.value, // Take the user's value block directly
                // Enforce standard's type and condition
                collateral_type: Some(verified_standard.template.fixed.collateral.type_.clone()),
                redeem_condition: Some(verified_standard.template.fixed.collateral.redeem_condition.clone()),
            }
        }) // .map() gracefully handles None -> None
    } else {
        None // Standard forbids it.
    };

    // NEU: Logik zur Auswahl des mehrsprachigen Beschreibungstextes
    let description_template = standard_manager::get_localized_text(
        &verified_standard.template.fixed.description,
        lang_preference
    ).unwrap_or(""); // Fallback auf leeren String, falls Liste leer ist

    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    let voucher_standard = VoucherStandard {
        name: verified_standard.metadata.name.clone(),
        uuid: verified_standard.metadata.uuid.clone(),
        standard_definition_hash: standard_hash.to_string(), // NEU: Hash einbetten
        template: crate::models::voucher::VoucherTemplateData {
            description: final_description.clone(),
            primary_redemption_type: verified_standard.template.fixed.primary_redemption_type.clone(),
            divisible: verified_standard.template.fixed.is_divisible,
            standard_minimum_issuance_validity: verified_standard.validation.as_ref()
                .and_then(|v| v.behavior_rules.as_ref())
                .and_then(|b| b.issuance_minimum_validity_duration.clone())
                .unwrap_or_default(),
            signature_requirements_description: verified_standard.template.fixed.guarantor_info.description.clone(),
            footnote: verified_standard.template.fixed.footnote.clone().unwrap_or_default(),
        },
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

    // KORREKTUR: Holen Sie die ID und schlagen Sie früh fehl, wenn sie fehlt.
    let creator_id = temp_voucher.creator_profile.id.as_ref()
        .ok_or_else(|| VoucherManagerError::Generic("Creator profile must have an ID".to_string()))?
        .clone();

    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash = get_hash(voucher_json_for_signing);

    temp_voucher.voucher_id = voucher_hash.clone();

    // --- NEUE SIGNATUR-LOGIK (SCHRITT 3) ---
    // Ersetzt die alte `creator.signature`-Logik.
    // Die Signatur wird nun als `VoucherSignature` mit `role: "creator"`
    // in das `signatures`-Array eingefügt.
    // Sie signiert *exakt dieselben Daten* wie zuvor (den `voucher_hash`).
    // KORREKTUR: Sie signiert ihre eigene `signature_id`.

    let mut creator_sig_obj = VoucherSignature {
        voucher_id: voucher_hash.clone(), // <-- HINZUFÜGEN
        signature_id: "".to_string(), // Wird unten berechnet
        signer_id: creator_id.clone(),
        signature: "".to_string(), // Platzhalter, wird neu berechnet
        signature_time: creation_date_str.clone(),
        role: "creator".to_string(),
        details: None, // Creator-Details sind bereits im Hauptobjekt
    };

    // Berechne die `signature_id` (Hash der Signatur-Metadaten)
    let mut sig_to_hash = creator_sig_obj.clone();
    sig_to_hash.signature_id = "".to_string();
    sig_to_hash.signature = "".to_string();
    // sig_to_hash.voucher_id ist bereits durch das Klonen vorhanden.
    creator_sig_obj.signature_id = get_hash(to_canonical_json(&sig_to_hash)?);

    // KORREKTUR: Signatur ERST JETZT erstellen, basierend auf der signature_id
    let creator_signature = sign_ed25519(creator_signing_key, creator_sig_obj.signature_id.as_bytes());
    creator_sig_obj.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // KORREKTUR: Zugriff auf die neue, verschachtelte Validierungsstruktur mit Fallback
    let decimal_places = verified_standard.validation.as_ref()
        .and_then(|v| v.behavior_rules.as_ref())
        .and_then(|b| b.amount_decimal_places)
        .unwrap_or(2) as u32; // Fallback auf 2, falls nicht definiert

    let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;

    let mut init_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash: get_hash(format!("{}{}", &temp_voucher.voucher_id, &temp_voucher.voucher_nonce)),
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: creator_id.clone(),
        recipient_id: creator_id.clone(),
        amount: decimal_utils::format_for_storage(&initial_amount, decimal_places),
        sender_remaining_amount: None,
        sender_signature: "".to_string(),
    };

    let tx_json_for_id = to_canonical_json(&init_transaction)?;
    let final_t_id = get_hash(tx_json_for_id);
    init_transaction.t_id = final_t_id;

    let signature_payload = serde_json::json!({
        "prev_hash": init_transaction.prev_hash,
        "sender_id": init_transaction.sender_id,
        "t_id": init_transaction.t_id
    });
    let signature_payload_json = to_canonical_json(&signature_payload)?;
    let signature_hash = get_hash(signature_payload_json);

    let transaction_signature = sign_ed25519(creator_signing_key, signature_hash.as_bytes());
    init_transaction.sender_signature = bs58::encode(transaction_signature.to_bytes()).into_string();

    temp_voucher.signatures.push(creator_sig_obj); // Füge die Creator-Signatur hinzu
    temp_voucher.transactions.push(init_transaction);

    Ok(temp_voucher)
}

/// Hilfsfunktion zum Parsen einer einfachen ISO 8601 Duration und Addieren zu einem Datum.
pub fn add_iso8601_duration(start_date: DateTime<Utc>, duration_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!("Invalid ISO 8601 duration format: {}", duration_str)));
    }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str)))?;
    match unit {
        "Y" => {
            let new_year = start_date.year() + value as i32;
            let new_date = start_date.with_year(new_year).unwrap_or_else(|| {
                Utc.with_ymd_and_hms(new_year, 2, 28, start_date.hour(), start_date.minute(), start_date.second()).unwrap()
            });
            Ok(new_date)
        }
        "M" => {
            let current_month0 = start_date.month0();
            let total_months0 = current_month0 + value;
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();
            let days_in_target_month = Utc.with_ymd_and_hms(
                if new_month == 12 { new_year + 1 } else { new_year },
                if new_month == 12 { 1 } else { new_month + 1 },
                1, 0, 0, 0
            ).unwrap()
                .signed_duration_since(Utc.with_ymd_and_hms(new_year, new_month, 1, 0, 0, 0).unwrap())
                .num_days() as u32;
            let new_day = original_day.min(days_in_target_month);
            let new_date = Utc.with_ymd_and_hms(new_year, new_month, new_day, start_date.hour(), start_date.minute(), start_date.second())
                .unwrap()
                .with_nanosecond(start_date.nanosecond())
                .unwrap();
            Ok(new_date)
        }
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherManagerError::Generic(format!("Unsupported duration unit in: {}", duration_str))),
    }
}

/// Hilfsfunktion, um ein Datum auf das Ende des Tages, Monats oder Jahres aufzurunden.
pub fn round_up_date(date: DateTime<Utc>, rounding_str: &str) -> Result<DateTime<Utc>, VoucherManagerError> {
    match rounding_str {
        "P1D" => Ok(date.with_hour(23).unwrap().with_minute(59).unwrap().with_second(59).unwrap().with_nanosecond(999_999_999).unwrap()),
        "P1M" => {
            let next_month = if date.month() == 12 { 1 } else { date.month() + 1 };
            let year = if date.month() == 12 { date.year() + 1 } else { date.year() };
            let first_of_next_month = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_month - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => {
            let first_of_next_year = Utc.with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!("Unsupported rounding unit: {}", rounding_str))),
    }
}

/// Erstellt eine neue Transaktion und hängt sie an eine Kopie des Gutscheins an.
pub fn create_transaction(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_key: &SigningKey,
    recipient_id: &str,
    amount_to_send_str: &str,
) -> Result<Voucher, VoucherCoreError> {
    crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)?;

    // NEU: Prüfe die "Zirkulations-Firewall" (issuance_minimum_validity_duration).
    validate_issuance_firewall(voucher, standard, sender_id, recipient_id)?;

    // KORREKTUR: Zugriff auf die neue, verschachtelte Validierungsstruktur mit Fallback
    let decimal_places = standard.validation.as_ref()
        .and_then(|v| v.behavior_rules.as_ref())
        .and_then(|b| b.amount_decimal_places)
        .unwrap_or(2) as u32; // Fallback auf 2, falls nicht definiert

    let spendable_balance = get_spendable_balance(voucher, sender_id, standard)?;
    let amount_to_send = Decimal::from_str(amount_to_send_str)?;
    decimal_utils::validate_precision(&amount_to_send, decimal_places)?;

    if amount_to_send <= Decimal::ZERO {
        return Err(VoucherManagerError::Generic("Transaction amount must be positive.".to_string()).into());
    }
    if amount_to_send > spendable_balance {
        return Err(VoucherManagerError::InsufficientFunds {
            available: spendable_balance,
            needed: amount_to_send,
        }.into());
    }

    let (t_type, sender_remaining_amount) = if amount_to_send < spendable_balance {
        if !voucher.voucher_standard.template.divisible {
            return Err(VoucherManagerError::VoucherNotDivisible.into());
        }
        let remaining = spendable_balance - amount_to_send;
        ("split".to_string(), Some(decimal_utils::format_for_storage(&remaining, decimal_places)))
    } else {
        ("transfer".to_string(), None)
    };

    let prev_hash = get_hash(to_canonical_json(voucher.transactions.last().unwrap())?);
    let t_time = get_current_timestamp();

    let mut new_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash,
        t_type,
        t_time,
        sender_id: sender_id.to_string(),
        recipient_id: recipient_id.to_string(),
        amount: decimal_utils::format_for_storage(&amount_to_send, decimal_places),
        sender_remaining_amount,
        sender_signature: "".to_string(),
    };

    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    let signature_payload = serde_json::json!({
        "prev_hash": new_transaction.prev_hash,
        "sender_id": new_transaction.sender_id,
        "t_id": new_transaction.t_id
    });
    let signature_payload_hash = get_hash(to_canonical_json(&signature_payload)?);
    let signature = sign_ed25519(sender_key, signature_payload_hash.as_bytes());
    new_transaction.sender_signature = bs58::encode(signature.to_bytes()).into_string();

    let mut new_voucher = voucher.clone();
    new_voucher.transactions.push(new_transaction);

    // SICHERHEITSPATCH: Validiere den *neuen* Gutschein-Zustand, BEVOR er zurückgegeben wird.
    // Dies stellt sicher, dass keine Transaktion erstellt werden kann, die gegen die Regeln des Standards verstößt.
    crate::services::voucher_validation::validate_voucher_against_standard(&new_voucher, standard)?;
    Ok(new_voucher)
}

/// NEU: Prüft die "Zirkulations-Firewall" (`issuance_minimum_validity_duration`).
///
/// Diese Regel ist eine *Transaktions-Firewall*, die *nur* für den *Ersteller* gilt,
/// wenn er an einen *Dritten* sendet.
fn validate_issuance_firewall(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    recipient_id: &str,
) -> Result<(), VoucherCoreError> {
    // 1. Regel extrahieren
    let min_duration_str = match standard.validation.as_ref()
        .and_then(|v| v.behavior_rules.as_ref())
        .and_then(|b| b.issuance_minimum_validity_duration.as_ref())
    {
        Some(duration) if !duration.is_empty() => duration,
        _ => return Ok(()), // 3. Ausnahme: Regel nicht definiert
    };

    // 2. Ersteller-Prüfung
    let creator_id = match &voucher.creator_profile.id {
        Some(id) => id,
        None => return Ok(()), // Kein Creator-ID-Feld, kann nicht der Ersteller sein
    };
    if sender_id != creator_id {
        return Ok(()); // 1. Ausnahme: Sender ist nicht der Ersteller
    }

    // 3. SAI-Ausnahme-Prüfung (Einlösung / Transfer an sich selbst)
    // Wir vergleichen die Basis-Public-Keys, nicht die vollen User-IDs
    let sender_pk = get_pubkey_from_user_id(sender_id)?;
    let recipient_pk = get_pubkey_from_user_id(recipient_id)?;

    if sender_pk == recipient_pk {
        return Ok(()); // 2. Ausnahme: Interne Übertragung
    }

    // 4. Zeit-Prüfung (Der Kern)
    // Sender ist Ersteller, Empfänger ist Dritter, Regel existiert.
    let now = Utc::now();
    let valid_until_dt = DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|e| VoucherManagerError::Generic(format!("Failed to parse voucher valid_until date: {}", e)))?
        .with_timezone(&Utc);

    // Berechne das Datum, das *mindestens* erreicht werden muss (jetzt + P1Y)
    let required_end_dt = add_iso8601_duration(now, min_duration_str)?;

    if valid_until_dt < required_end_dt {
        // Blockade: Die verbleibende Zeit ist zu kurz.
        Err(VoucherManagerError::InvalidValidityDuration(format!(
            "Issuance failed: Voucher validity ({}) is less than the required minimum remaining duration ({} from now).",
            valid_until_dt.to_rfc3339(),
            required_end_dt.to_rfc3339()
        )).into())
    } else {
        Ok(())
    }
}

/// Berechnet das ausgebbare Guthaben für einen bestimmten Benutzer.
///
/// Diese Funktion durchläuft die Transaktionshistorie eines Gutscheins, um den
/// aktuellen Kontostand eines Benutzers zu ermitteln.
pub fn get_spendable_balance(
    voucher: &Voucher,
    user_id: &str,
    standard: &VoucherStandardDefinition,
) -> Result<Decimal, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Ok(Decimal::ZERO);
    }

    // Die Gültigkeit des Gutscheins prüfen, bevor das Guthaben berechnet wird.
    // Wir ignorieren absichtlich Fehler, die nur durch fehlende Bürgen entstehen,
    // da dies für eine reine Guthabenprüfung nicht relevant ist.
    match crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard) {
        Ok(_) => (),
        Err(VoucherCoreError::Validation(_)) => (), // Ignoriere Validierungsfehler für Guthabenprüfung
        Err(e) => return Err(e),
    };

    let last_tx = voucher.transactions.last().unwrap();
    let decimal_places = standard.validation.as_ref()
        .and_then(|v| v.behavior_rules.as_ref())
        .and_then(|b| b.amount_decimal_places)
        .unwrap_or(2) as u32;

    let balance_str = if last_tx.recipient_id == user_id {
        &last_tx.amount
    } else if last_tx.sender_id == user_id {
        last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
    } else {
        "0"
    };

    let balance = Decimal::from_str(balance_str)?;
    Ok(balance.round_dp(decimal_places))
}
