//! # src/services/voucher_manager.rs
use crate::error::VoucherCoreError;
use crate::models::profile::PublicProfile;
use crate::models::voucher::{
    Collateral, RecipientPayload, Transaction, ValueDefinition, Voucher, VoucherSignature,
    VoucherStandard,
};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::crypto_utils::{
    derive_ephemeral_key_pair, ed25519_pk_to_curve_point, encode_base64, encrypt_data,
    generate_ephemeral_x25519_keypair, get_hash, get_hash_from_slices, get_pubkey_from_user_id,
    perform_diffie_hellman, sign_ed25519,
};
use crate::services::trap_manager::{derive_m, generate_trap, hash_to_scalar};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::services::{decimal_utils, standard_manager};
use hkdf::Hkdf;
use sha2::Sha256;

use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};
use ed25519_dalek::SigningKey;
use rand::Rng;
use rust_decimal::Decimal;
use std::fmt;
use std::str::FromStr;

/// Enthält die vertraulichen Geheimnisse, die während einer Transaktionserstellung generiert wurden.
/// Diese MÜSSEN vom Aufrufer (Wallet) sicher gespeichert werden, da sie im Voucher nur verschlüsselt
/// oder als Hash vorliegen. Ohne diese Geheimnisse können Gelder nicht empfangen oder Restgeld ausgegeben werden.
#[derive(Debug, Clone)]
pub struct TransactionSecrets {
    pub recipient_seed: String,      // BS58 encoded seed for the recipient
    pub change_seed: Option<String>, // BS58 encoded seed for change (if split)
}

// Definiert die Fehler, die im `voucher_manager`-Modul auftreten können.
#[derive(Debug)]
pub enum VoucherManagerError {
    /// Der Gutschein erlaubt laut Standard keine Teilbeträge.
    VoucherPartialTransferNotAllowed,
    /// Das verfügbare Guthaben ist für die Transaktion nicht ausreichend.
    InsufficientFunds { available: Decimal, needed: Decimal },
    /// Der Betrag hat mehr Nachkommastellen als vom Standard erlaubt.
    AmountPrecisionExceeded { allowed: u32, found: u32 },
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
            VoucherManagerError::VoucherPartialTransferNotAllowed => {
                write!(f, "Voucher does not allow partial transfers according to its standard.")
            }
            VoucherManagerError::InsufficientFunds { available, needed } => {
                write!(
                    f,
                    "Insufficient funds: Available: {}, Needed: {}",
                    available, needed
                )
            }
            VoucherManagerError::AmountPrecisionExceeded { allowed, found } => {
                write!(
                    f,
                    "Amount precision exceeds standard limit. Allowed: {}, Found: {}",
                    allowed, found
                )
            }
            VoucherManagerError::InvalidTemplateValue(s) => {
                write!(f, "Invalid template value from standard: {}", s)
            }
            VoucherManagerError::InvalidValidityDuration(s) => {
                write!(f, "Invalid validity duration: {}", s)
            }
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
    if verified_standard
        .immutable
        .blueprint
        .unit
        .is_empty()
    {
        return Err(VoucherManagerError::InvalidTemplateValue(
            "immutable.blueprint.unit cannot be empty".to_string(),
        )
        .into());
    }
    // Enums are strictly typed, so they are never "empty" in the sense a string could be.
    // The TOML parser will ensure they match one of the valid variants.

    let creation_date_str = get_current_timestamp();
    let nonce_bytes = rand::thread_rng().r#gen::<[u8; 16]>();
    let nonce = bs58::encode(nonce_bytes).into_string();
    let creation_dt = DateTime::parse_from_rfc3339(&creation_date_str)
        .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse creation date: {}", e)))?
        .with_timezone(&Utc);

    let duration_str = data
        .validity_duration
        .as_deref()
        .or(verified_standard
            .mutable
            .app_config
            .default_validity_duration
            .as_deref())
        .ok_or_else(|| {
            VoucherManagerError::Generic(
                "No validity duration specified and no default found in standard.".to_string(),
            )
        })?;

    let initial_valid_until_dt = add_iso8601_duration(creation_dt, duration_str)?;

    let min_duration_opt = Some(&verified_standard.immutable.issuance.issuance_minimum_validity_duration);

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

    // CHECK MAX RANGE
    if let Some(max_duration_str) = verified_standard.immutable.issuance.validity_duration_range.get(1) {
        if !max_duration_str.is_empty() {
            let max_allowed_dt = add_iso8601_duration(creation_dt, max_duration_str)?;
            if initial_valid_until_dt > max_allowed_dt {
                return Err(VoucherManagerError::InvalidValidityDuration(format!(
                    "Initial validity ({}) exceeds the maximum allowed standard validity ({}).",
                    initial_valid_until_dt.to_rfc3339(),
                    max_allowed_dt.to_rfc3339()
                )).into());
            }
        }
    }

    let final_valid_until_dt =
        if let Some(rounding_str) = &verified_standard.mutable.app_config.round_up_validity_to {
            round_up_date(initial_valid_until_dt, rounding_str)?
        } else {
            initial_valid_until_dt
        };
    let mut final_nominal_value = data.nominal_value;
    final_nominal_value.unit = verified_standard.immutable.blueprint.unit.clone();

    // Prioritize user-defined abbreviation. Fallback to standard's metadata abbreviation.
    if final_nominal_value.abbreviation.is_none() {
        final_nominal_value.abbreviation = Some(verified_standard.immutable.identity.abbreviation.clone());
    }

    // KORRIGIERT: Collateral wird NUR befüllt, wenn der Standard es erlaubt
    // UND der Benutzer (data) es bereitstellt.
    // KORRIGIERT: Collateral wird befüllt, wenn der Benutzer (data) es bereitstellt.
    let final_collateral = data.collateral.map(|user_collateral| {
        let col_type_str = serde_json::to_value(&verified_standard.immutable.blueprint.collateral_type)
            .ok()
            .and_then(|v| v.as_str().map(|s| s.to_string()));
        
        Collateral {
            value: user_collateral.value,
            collateral_type: col_type_str,
            redeem_condition: None,
        }
    });

    let description_template = standard_manager::get_localized_text(
        &verified_standard.mutable.i18n.descriptions,
        lang_preference,
    )
    .unwrap_or(""); // Fallback auf leeren String, falls Liste leer ist

    let final_description = description_template.replace("{{amount}}", &final_nominal_value.amount);

    let voucher_standard = VoucherStandard {
        name: verified_standard.immutable.identity.name.clone(),
        uuid: verified_standard.immutable.identity.uuid.clone(),
        standard_definition_hash: standard_hash.to_string(),
        template: crate::models::voucher::VoucherTemplateData {
            description: final_description.clone(),
            primary_redemption_type: serde_json::to_value(&verified_standard.immutable.blueprint.primary_redemption_type)
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default(),
            allow_partial_transfers: verified_standard.immutable.features.allow_partial_transfers,
            issuance_minimum_validity_duration: verified_standard.immutable.issuance.issuance_minimum_validity_duration.clone(),
            footnote: standard_manager::get_localized_text(&verified_standard.mutable.i18n.footnotes, lang_preference).unwrap_or("").to_string(),
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
    let creator_id = temp_voucher
        .creator_profile
        .id
        .as_ref()
        .ok_or_else(|| VoucherManagerError::Generic("Creator profile must have an ID".to_string()))?
        .clone();

    let voucher_json_for_signing = to_canonical_json(&temp_voucher)?;
    let voucher_hash = get_hash(voucher_json_for_signing);

    temp_voucher.voucher_id = voucher_hash.clone();

    let mut init_transaction = Transaction {
        t_id: "".to_string(),
        // SECURITY FIX: Use raw bytes for prev_hash truncation/concatenation
        prev_hash: {
            let voucher_id_bytes = bs58::decode(&temp_voucher.voucher_id)
                .into_vec()
                .map_err(|_| VoucherCoreError::Generic("Invalid voucher_id format".to_string()))?;
            let nonce_bytes = bs58::decode(&temp_voucher.voucher_nonce)
                .into_vec()
                .map_err(|_| {
                    VoucherCoreError::Generic("Invalid voucher_nonce format".to_string())
                })?;
            get_hash_from_slices(&[&voucher_id_bytes, &nonce_bytes])
        },
        t_type: "init".to_string(),
        t_time: creation_date_str.clone(),
        sender_id: Some(creator_id.clone()), // Init ist immer public
        recipient_id: creator_id.clone(),    // Init: geht an Creator selbst
        amount: "".to_string(),              // Wird unten befüllt
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: None, // Wird unten befüllt
        sender_ephemeral_pub: None,        // Wird unten befüllt
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: {
            let retention_period = verified_standard.mutable.app_config.server_history_retention.as_ref();

            if let Some(duration) = retention_period {
                add_iso8601_duration(final_valid_until_dt, duration)
                    .ok()
                    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
            } else {
                Some(temp_voucher.valid_until.clone())
            }
        },
        change_ephemeral_pub_hash: None,
        sender_identity_signature: None,
    };

    let decimal_places = verified_standard.immutable.features.amount_decimal_places as u32;

    let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;
    init_transaction.amount = decimal_utils::format_for_storage(&initial_amount, decimal_places);

    let creator_prefix = creator_id.split(':').next().unwrap_or("unknown");
    let (genesis_secret, genesis_public) = derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_bytes,
        "genesis",
        Some(creator_prefix),
    )?;
    let genesis_pub_str = bs58::encode(genesis_public.to_bytes()).into_string();
    init_transaction.sender_ephemeral_pub = Some(genesis_pub_str.clone());

    let (_, holder_public) = derive_ephemeral_key_pair(
        creator_signing_key,
        &nonce_bytes,
        "holder",
        Some(creator_prefix),
    )?;
    let holder_anchor_hash = get_hash(holder_public.to_bytes());
    init_transaction.receiver_ephemeral_pub_hash = Some(holder_anchor_hash);

    let tx_json_for_id = to_canonical_json(&init_transaction)?;
    let init_t_id = get_hash(tx_json_for_id);
    init_transaction.t_id = init_t_id.clone();

    // --- NEUE SIGNATUR-LOGIK (SCHRITT 3) ---
    let mut creator_sig_obj = VoucherSignature {
        voucher_id: voucher_hash.clone(),
        signature_id: "".to_string(),
        signer_id: creator_id.clone(),
        signature: "".to_string(),
        signature_time: creation_date_str.clone(),
        role: "creator".to_string(),
        details: None,
    };

    creator_sig_obj.signature_id = get_hash_from_slices(&[
        to_canonical_json(&creator_sig_obj)?.as_bytes(),
        init_t_id.as_bytes(),
    ]);
    let creator_signature =
        sign_ed25519(creator_signing_key, creator_sig_obj.signature_id.as_bytes());
    creator_sig_obj.signature = bs58::encode(creator_signature.to_bytes()).into_string();

    // --- L2 & IDENTITY SIGNATUREN (NEUES MODELL) ---
    // Resigning for Technical Proofs

    // 2. Layer 2 Signature: Signiert den L2-Payload-Hash mit dem ephemeralen Key (Genesis Secret)
    let t_id_raw = bs58::decode(&init_transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id hash".to_string()))?;

    let sender_pub_raw = bs58::decode(&genesis_pub_str).into_vec().map_err(|_| {
        VoucherCoreError::InvalidHashFormat("Invalid genesis_pub format".to_string())
    })?;

    let v_id = crate::services::l2_gateway::calculate_layer2_voucher_id(&init_transaction)?;
    let challenge_ds_tag = init_transaction.t_id.clone();

    let receiver_hash_str = init_transaction
        .receiver_ephemeral_pub_hash
        .as_ref()
        .ok_or_else(|| {
            VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(
                "Genesis transaction missing receiver_ephemeral_pub_hash".to_string(),
            ))
        })?;
    let receiver_hash_raw = bs58::decode(receiver_hash_str)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid receiver hash".to_string()))?;

    let to_32_bytes = |vec: Vec<u8>, name: &str| -> Result<[u8; 32], VoucherCoreError> {
        vec.try_into()
            .map_err(|_| VoucherCoreError::InvalidHashFormat(format!("{} must be 32 bytes", name)))
    };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &v_id,
        &to_32_bytes(t_id_raw.clone(), "t_id")?,
        &to_32_bytes(sender_pub_raw.clone(), "sender_pub")?,
        Some(&to_32_bytes(receiver_hash_raw.clone(), "receiver_hash")?),
        None,
        init_transaction.deletable_at.as_deref(),
    );

    let l2_sig_bytes = sign_ed25519(&genesis_secret, &payload_hash);
    init_transaction.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

    // 3. Sender Identity Signature: Signiert t_id (raw bytes) mit Creator Key (Permanent)
    let identity_sig_bytes = sign_ed25519(creator_signing_key, &t_id_raw);
    init_transaction.sender_identity_signature =
        Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());

    temp_voucher.signatures.push(creator_sig_obj); // Füge die Creator-Signatur hinzu
    temp_voucher.transactions.push(init_transaction);

    Ok(temp_voucher)
}

/// Hilfsfunktion zum Parsen einer einfachen ISO 8601 Duration und Addieren zu einem Datum.
pub fn add_iso8601_duration(
    start_date: DateTime<Utc>,
    duration_str: &str,
) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!(
            "Invalid ISO 8601 duration format: {}",
            duration_str
        )));
    }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| {
        VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str))
    })?;
    match unit {
        "Y" => {
            let new_year = start_date.year() + value as i32;
            let new_date = start_date.with_year(new_year).unwrap_or_else(|| {
                Utc.with_ymd_and_hms(
                    new_year,
                    2,
                    28,
                    start_date.hour(),
                    start_date.minute(),
                    start_date.second(),
                )
                .unwrap()
            });
            Ok(new_date)
        }
        "M" => {
            let current_month0 = start_date.month0();
            let total_months0 = current_month0 + value;
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();
            let days_in_target_month = Utc
                .with_ymd_and_hms(
                    if new_month == 12 {
                        new_year + 1
                    } else {
                        new_year
                    },
                    if new_month == 12 { 1 } else { new_month + 1 },
                    1,
                    0,
                    0,
                    0,
                )
                .unwrap()
                .signed_duration_since(
                    Utc.with_ymd_and_hms(new_year, new_month, 1, 0, 0, 0)
                        .unwrap(),
                )
                .num_days() as u32;
            let new_day = original_day.min(days_in_target_month);
            let new_date = Utc
                .with_ymd_and_hms(
                    new_year,
                    new_month,
                    new_day,
                    start_date.hour(),
                    start_date.minute(),
                    start_date.second(),
                )
                .unwrap()
                .with_nanosecond(start_date.nanosecond())
                .unwrap();
            Ok(new_date)
        }
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherManagerError::Generic(format!(
            "Unsupported duration unit in: {}",
            duration_str
        ))),
    }
}

/// Hilfsfunktion, um ein Datum auf das Ende des Tages, Monats oder Jahres aufzurunden.
pub fn round_up_date(
    date: DateTime<Utc>,
    rounding_str: &str,
) -> Result<DateTime<Utc>, VoucherManagerError> {
    match rounding_str {
        "P1D" => Ok(date
            .with_hour(23)
            .unwrap()
            .with_minute(59)
            .unwrap()
            .with_second(59)
            .unwrap()
            .with_nanosecond(999_999_999)
            .unwrap()),
        "P1M" => {
            let next_month = if date.month() == 12 {
                1
            } else {
                date.month() + 1
            };
            let year = if date.month() == 12 {
                date.year() + 1
            } else {
                date.year()
            };
            let first_of_next_month = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_month - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => {
            let first_of_next_year = Utc
                .with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0)
                .unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!(
            "Unsupported rounding unit: {}",
            rounding_str
        ))),
    }
}

/// Erstellt eine neue Transaktion und hängt sie an eine Kopie des Gutscheins an.
/// Implementiert den Privacy-Flow: Anchor (P2PKH), Trap (ZKP), Payload Encryption.
pub fn create_transaction(
    voucher: &Voucher,
    standard: &VoucherStandardDefinition,
    sender_id: &str,
    sender_permanent_key: &SigningKey, // Für Trap (ID)
    sender_ephemeral_key: &SigningKey, // Für L2-Signatur und Anker-Auflösung
    recipient_id: &str,
    amount_to_send_str: &str,
) -> Result<(Voucher, TransactionSecrets), VoucherCoreError> {
    crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)?;

    validate_issuance_firewall(voucher, standard, sender_id, recipient_id)?;

    let decimal_places = standard.immutable.features.amount_decimal_places as u32;

    let spendable_balance = get_spendable_balance(voucher, sender_id, standard)?;
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

    // PRIVACY MODE CHECK
    use crate::models::voucher_standard_definition::PrivacyMode;
    let privacy_mode = &standard.immutable.features.privacy_mode;

    // Determine Sender ID Visibility
    let final_sender_id = match privacy_mode {
        PrivacyMode::Public => Some(sender_id.to_string()),
        PrivacyMode::Private => None,
        PrivacyMode::Flexible => {
            // Flexible: Sender decides.
            // For this implementation: We use sender_id as explicit intent to be public.
            Some(sender_id.to_string())
        }
    };


    // Validate Recipient ID against Mode
    let recipient_is_did = recipient_id.starts_with("did:") || recipient_id.contains("@did:");
    let recipient_id_check = match privacy_mode {
        PrivacyMode::Public => {
            if !recipient_is_did {
                return Err(VoucherManagerError::Generic(
                    "Public mode requires DID recipient.".to_string(),
                )
                .into());
            }
            recipient_id
        }
        PrivacyMode::Private => {
            if recipient_is_did {
                return Err(VoucherManagerError::Generic(
                    "Private mode forbids DID recipient.".to_string(),
                )
                .into());
            }
            recipient_id
        }
        PrivacyMode::Flexible => recipient_id, // Both allowed
    };

    // 1. REVEAL: Der aktuelle Ephemeral Key wird veröffentlicht.
    let sender_ephemeral_pub =
        bs58::encode(sender_ephemeral_key.verifying_key().to_bytes()).into_string();

    // 2. ANCHOR: Neuer Key für den Empfänger (und ggf. für Change).
    // a) Empfänger
    // Wir generieren ein EINMALIGES Keypair für den Empfänger.
    // Der Empfänger erhält den Private Key (Seed) über den RecipientPayload.
    // Wir nutzen einen sicheren RNG für den Seed.
    let mut recipient_seed = [0u8; 32];
    rand::thread_rng().fill(&mut recipient_seed);
    let recipient_signing_key = SigningKey::from_bytes(&recipient_seed);
    let recipient_ephemeral_pub = recipient_signing_key.verifying_key();
    let receiver_ephemeral_pub_hash = Some(get_hash(recipient_ephemeral_pub.to_bytes()));

    // b) Change (falls nötig)
    let (change_ephemeral_pub_hash, change_key_seed_opt) = if t_type == "split" {
        // Für das Restgeld generiert der Sender einen NEUEN Key für SICH SELBST.
        // NEU: Deterministische Ableitung via HKDF, damit der Seed nicht gespeichert werden muss.
        // Wir nutzen denselben PRK wie für m (Trap), aber mit anderem Info-String.

        let sender_id_prefix = sender_id.split('@').next().unwrap_or(sender_id).to_string();

        let salt = prev_hash.as_bytes();
        let ikm = sender_permanent_key.to_bytes(); // Master Key
        let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &ikm);
        let hkdf = Hkdf::<Sha256>::from_prk(&prk)
            .map_err(|_| VoucherCoreError::Crypto("Invalid PRK length".to_string()))?;

        // Info-String für Change-Seed: "[prefix]change_seed"
        let info = format!("{}change_seed", sender_id_prefix);
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

    // 3. PAYLOAD ENCRYPTION: Sende next_key_seed an Empfänger.
    let encoded_recipient_seed = bs58::encode(recipient_seed).into_string();

    let privacy_guard = if recipient_id.contains(":z") {
        // Extrahiere Präfix aus sender_id für Payload (Sender-Info).
        let _sender_prefix = sender_id.split(':').next().unwrap_or("unknown").to_string();
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
        };

        // Encrypt Payload:
        let (ephemeral_pk, ephemeral_sk) = generate_ephemeral_x25519_keypair();
        let recipient_ed_pk = get_pubkey_from_user_id(recipient_id)?;
        let recipient_x_pk = crate::services::crypto_utils::ed25519_pub_to_x25519(&recipient_ed_pk);
        let shared_secret = perform_diffie_hellman(ephemeral_sk, &recipient_x_pk)?;
        let payload_json = to_canonical_json(&payload)?;
        let encrypted_bytes = encrypt_data(&shared_secret, payload_json.as_bytes())?;

        let mut privacy_guard_bytes = Vec::new();
        privacy_guard_bytes.extend_from_slice(ephemeral_pk.as_bytes());
        privacy_guard_bytes.extend_from_slice(&encrypted_bytes);
        Some(encode_base64(&privacy_guard_bytes))
    } else {
        // Im Private-Mode (Empfänger ist ein Hash) gibt es keinen öffentlichen Schlüssel
        // für DH. Der Empfänger muss seinen Key-Seed anderweitig (z.B. Offline-Übergabe) erhalten.
        None
    };

    // CHANGE PAYLOAD? Das "Restgeld" bleibt beim Sender.
    // Der Sender MUSS change_key_seed speichern.
    // Das geschieht hier NICHT im Voucher, sondern muss vom Wallet gehandhabt werden!
    // -> Rückgabewert muss change_key_seed enthalten?
    // Der Wrapper (AppService/Wallet) muss dies handhaben.
    // ACHTUNG: Der `Voucher` struct speichert das NICHT.
    // Lösung: Wir sollten change_key_seed in `sender_remaining_amount` embedded?
    // Nein. Wir lassen es hier so, dass wir es NICHT zurückgeben?
    // Das ist ein Problem für die Offline-Fähigkeit.
    // TODO: Über Local Storage nachdenken.
    // Für jetzt: Wir ignorieren das Speichern des Change-Keys hier (Verlustrisiko!),
    // aber das ist ok da dies nur die Voucher-Erstellung ist.

    // 4. TRAP Generation & Identity Recovery Logic
    //
    // a) Calculate CONSTANT DS-Tag (Index):
    //    Depends ONLY on Input (prev_hash, input_key).
    //    This ensures O(1) detection of Double Spends, independent of the identity used.
    let sender_id_prefix = sender_id.split('@').next().unwrap_or(sender_id).to_string(); // "prefix:checksum"
    let amount_str = decimal_utils::format_for_storage(&amount_to_send, decimal_places);

    // SECURITY FIX: Use raw bytes for ds_tag derivation
    let prev_hash_bytes = bs58::decode(&prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid prev_hash format".to_string()))?;
    let sender_ephem_pub_bytes = bs58::decode(&sender_ephemeral_pub)
        .into_vec()
        .map_err(|_| VoucherCoreError::Crypto("Invalid sender_ephemeral_pub format".to_string()))?;

    let ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &sender_ephem_pub_bytes]);

    // b) Calculate VARYING Challenge U:
    //    Depends on Output (amount, receiver, etc.) via ds_tag.
    //    This ensures that two different transactions have DIFFERENT U points,
    //    allowing the calculation of 'm' and thus the Identity ID.
    let u_input_varying = format!(
        "{}{}{}",
        ds_tag,
        amount_str,
        receiver_ephemeral_pub_hash.as_deref().unwrap_or("")
    );
    let u_scalar = hash_to_scalar(u_input_varying.as_bytes());

    // m derivation
    let m = derive_m(
        &prev_hash,
        &sender_permanent_key.to_bytes(),
        &sender_id_prefix,
    )?;

    // My ID Point
    let my_id_point = ed25519_pk_to_curve_point(&sender_permanent_key.verifying_key())?;

    let trap_data = Some(generate_trap(
        ds_tag.clone(),
        &u_scalar,
        &m,
        &my_id_point,
        &sender_id_prefix,
    )?);

    let mut new_transaction = Transaction {
        t_id: "".to_string(),
        prev_hash: prev_hash.clone(), // Clone here needed? prev_hash is String
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

    // --- L2 & IDENTITY SIGNATUREN (NEUES MODELL) ---
    // 1. Berechne die t_id OHNE Signaturen
    let tx_json_for_id = to_canonical_json(&new_transaction)?;
    new_transaction.t_id = get_hash(tx_json_for_id);

    // 2. Layer 2 Signature: Signiert den L2-Payload-Hash mit dem ephemeralen Key (Input Key)
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

    // 3. Sender Identity Signature (L1): Signiert t_id (raw bytes) mit Sender Permanent Key
    // NUR wenn sender_id gesetzt ist (Public/Flexible Mode).
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
    let min_duration_str = match Some(&standard.immutable.issuance.issuance_minimum_validity_duration)
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
    // Wenn der Empfänger kein DID (z.B. ein Hash) ist, kann es nicht der Ersteller selbst sein.
    if recipient_id.contains(':') {
        let sender_pk = get_pubkey_from_user_id(sender_id)?;
        let recipient_pk = get_pubkey_from_user_id(recipient_id)?;

        if sender_pk == recipient_pk {
            return Ok(()); // 2. Ausnahme: Interne Übertragung
        }
    }

    // 4. Zeit-Prüfung (Der Kern)
    // Sender ist Ersteller, Empfänger ist Dritter, Regel existiert.
    let now = Utc::now();
    let valid_until_dt = DateTime::parse_from_rfc3339(&voucher.valid_until)
        .map_err(|e| {
            VoucherManagerError::Generic(format!("Failed to parse voucher valid_until date: {}", e))
        })?
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
    match crate::services::voucher_validation::validate_voucher_against_standard(voucher, standard)
    {
        Ok(_) => (),
        Err(VoucherCoreError::Validation(_)) => (), // Ignoriere Validierungsfehler für Guthabenprüfung
        Err(e) => return Err(e),
    };

    let last_tx = voucher.transactions.last().unwrap();
    let decimal_places = standard.immutable.features.amount_decimal_places as u32;

    let balance_str = if last_tx.recipient_id == user_id {
        &last_tx.amount
    } else if last_tx.sender_id.as_deref() == Some(user_id) {
        last_tx.sender_remaining_amount.as_deref().unwrap_or("0")
    } else {
        "0"
    };

    let balance = Decimal::from_str(balance_str)?;
    Ok(balance.round_dp(decimal_places))
}
