//! # src/services/conflict_manager.rs
//!
//! Dieses Modul kapselt die gesamte Geschäftslogik zur Erkennung, Verifizierung
//! und Verwaltung von Double-Spending-Konflikten. Es operiert auf den
//! Datenstrukturen des Wallets, ist aber von der `Wallet`-Fassade entkoppelt.

use std::collections::HashMap;

use crate::error::VoucherCoreError;
use crate::models::conflict::{
    KnownFingerprints, OwnFingerprints, ProofOfDoubleSpend, ResolutionEndorsement,
    TransactionFingerprint,
};
use crate::models::profile::{UserIdentity, VoucherStore};
use crate::models::voucher::{Transaction, Voucher};
use crate::services::crypto_utils::{get_hash, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::wallet::DoubleSpendCheckResult;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};

/// Erstellt einen einzelnen, anonymisierten Fingerprint für eine gegebene Transaktion.
/// Enthält die Logik zur Anonymisierung des `valid_until`-Zeitstempels.
pub fn create_fingerprint_for_transaction(
    transaction: &Transaction,
    voucher: &Voucher,
) -> Result<TransactionFingerprint, VoucherCoreError> {
    // 1. Anonymisiere den `valid_until`-Zeitstempel durch Runden auf das Monatsende.
    let valid_until_rounded = {
        let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until).map_err(|e| {
            VoucherCoreError::Generic(format!("Failed to parse valid_until: {}", e))
        })?;

        let year = parsed_date.year();
        let month = parsed_date.month();

        let first_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
        .ok_or_else(|| {
            VoucherCoreError::Generic("Failed to calculate next month's date".to_string())
        })?;

        let last_day_of_month = first_of_next_month.pred_opt().unwrap();
        let end_of_month_dt = last_day_of_month
            .and_hms_micro_opt(23, 59, 59, 999999)
            .unwrap()
            .and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    // 2. Erstelle den Fingerprint mit dem gerundeten Zeitstempel.
    // NEU: Wir verwenden das 'ds_tag' aus den TrapData als kanonischen DS-Tag.
    // Dies stellt sicher, dass der Fingerprint exakt mit der mathematischen Falle
    // übereinstimmt. Nur für 'init' (die keine Trap hat) berechnen wir den Tag manuell.
    let tag = if let Some(trap) = &transaction.trap_data {
        trap.ds_tag.clone()
    } else {
        // Fallback für 'init' oder Legacy: Manuelle Berechnung
        // WICHTIG: Wenn sender_id vorhanden ist (wie bei 'init'), verwenden wir sie
        // für die Konsistenz mit bestehenden Tests und der Dokumentation.
        let sender_part = transaction
            .sender_id
            .as_deref()
            .or(transaction.sender_ephemeral_pub.as_deref())
            .unwrap_or("anon");
        get_hash(format!("{}{}", transaction.prev_hash, sender_part))
    };

    Ok(TransactionFingerprint {
        ds_tag: tag,
        t_id: transaction.t_id.clone(),
        sender_signature: transaction.sender_proof_signature.clone(),
        valid_until: valid_until_rounded,
        encrypted_timestamp: encrypt_transaction_timestamp(transaction)?,
    })
}

/// Durchsucht den `VoucherStore` und erstellt die aktuellen Fingerprint-Sammlungen.
/// Diese Funktion partitioniert die Fingerprints korrekt in die kritischen "eigenen"
/// und die allgemeine "bekannte" Historie.
pub fn scan_and_rebuild_fingerprints(
    voucher_store: &VoucherStore,
    user_id: &str,
) -> Result<(OwnFingerprints, KnownFingerprints), VoucherCoreError> {
    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    for instance in voucher_store.vouchers.values() {
        for tx in &instance.voucher.transactions {
            let fingerprint = create_fingerprint_for_transaction(tx, &instance.voucher)?;
            // DEBUG: Log the components of the hash being generated
            println!(
               "[Scan/Rebuild] Gen FP for t_id: '{}'. Using prev_hash: '{}', sender_id: '{}'. Resulting ds_tag: '{}'",
                tx.t_id, tx.prev_hash, tx.sender_id.as_deref().unwrap_or("anon"), fingerprint.ds_tag
            );

            // Jede Transaktion wird zur allgemeinen lokalen Historie hinzugefügt.
            // KORREKTUR: Duplikate verhindern. Ein Vec wird verwendet, um die Reihenfolge
            // zu bewahren, aber wir prüfen vor dem Hinzufügen auf Eindeutigkeit.
            let known_entry = known
                .local_history
                .entry(fingerprint.ds_tag.clone())
                .or_default();
            if !known_entry.contains(&fingerprint) {
                known_entry.push(fingerprint.clone());
            }

            // Nur wenn der Nutzer der Sender war, wird der Fingerprint auch zu den
            // kritischen "eigenen" Fingerprints hinzugefügt.
            if tx.sender_id.as_deref() == Some(user_id) {
                own.history
                    .entry(fingerprint.ds_tag.clone())
                    .or_default()
                    .push(fingerprint.clone()); // Duplikate hier sind unwahrscheinlich, aber zur Sicherheit

                // Wenn der Gutschein zusätzlich noch aktiv ist, kommt er in die "Hot-List".
                if matches!(
                    instance.status,
                    crate::wallet::instance::VoucherStatus::Active
                ) {
                    let active_entry = own
                        .active_fingerprints
                        .entry(fingerprint.ds_tag.clone())
                        .or_default();
                    if !active_entry.contains(&fingerprint) {
                        active_entry.push(fingerprint);
                    }
                }
            }
        }
    }
    Ok((own, known))
}

/// Führt eine vollständige Double-Spend-Prüfung durch, indem eigene und fremde
/// Fingerprints kombiniert und auf Kollisionen geprüft werden.
pub fn check_for_double_spend(
    own_fingerprints: &OwnFingerprints,
    known_fingerprints: &KnownFingerprints,
) -> DoubleSpendCheckResult {
    println!("\n[DEBUG CONFLICT_MANAGER] --- Starte check_for_double_spend ---");
    let mut result = DoubleSpendCheckResult::default();

    // 1. Alle bekannten Fingerprints aus allen Quellen dedupliziert zusammenführen.
    // Wir verwenden ein HashSet, um Duplikate (z.B. zwischen history und current_own)
    // automatisch zu eliminieren.
    let mut all_fingerprints_map: HashMap<
        String,
        std::collections::HashSet<TransactionFingerprint>,
    > = HashMap::new();

    println!("[DEBUG CONFLICT_MANAGER] Quellen werden zusammengeführt...");
    let sources = [
        &own_fingerprints.history,
        &known_fingerprints.local_history,
        &known_fingerprints.foreign_fingerprints,
    ];

    for (i, source) in sources.iter().enumerate() {
        for (hash, fps) in *source {
            println!(
                "[DEBUG CONFLICT_MANAGER] Quelle[{}]: Hash '{}' mit {} Fingerprints gefunden.",
                i,
                hash,
                fps.len()
            );
            let entry = all_fingerprints_map.entry(hash.clone()).or_default();
            for fp in fps {
                entry.insert(fp.clone());
            }
        }
    }

    // 2. Jede Gruppe von Fingerprints auf Konflikte prüfen (mehr als eine eindeutige t_id).
    println!(
        "[DEBUG CONFLICT_MANAGER] Prüfe {} eindeutige Hashes auf Konflikte...",
        all_fingerprints_map.len()
    );
    for (hash, fps_set) in all_fingerprints_map {
        let fps_vec: Vec<TransactionFingerprint> = fps_set.into_iter().collect();
        let unique_t_ids = fps_vec
            .iter()
            .map(|fp| &fp.t_id)
            .collect::<std::collections::HashSet<_>>();

        println!(
            "[DEBUG CONFLICT_MANAGER] Hash '{}' hat {} eindeutige t_ids.",
            hash,
            unique_t_ids.len()
        );
        if unique_t_ids.len() > 1 {
            println!(
                "[DEBUG CONFLICT_MANAGER] -> KONFLIKT für Hash '{}' entdeckt!",
                hash
            );
            // 3. Einen Konflikt als "verifizierbar" einstufen, wenn der Wallet-Besitzer
            // mindestens eine der beteiligten Transaktionen selbst kennt (aus seiner Historie).
            let is_verifiable = known_fingerprints.local_history.contains_key(&hash);
            println!(
                "[DEBUG CONFLICT_MANAGER] -> Klassifizierung: Ist verifizierbar? (local_history enthält den Hash) -> {}",
                is_verifiable
            );
            if is_verifiable {
                result.verifiable_conflicts.insert(hash.clone(), fps_vec);
            } else {
                result.unverifiable_warnings.insert(hash.clone(), fps_vec);
            }
        }
    }
    result
}

/// Erstellt einen fälschungssicheren, portablen Beweis (`ProofOfDoubleSpend`).
///
/// Diese Funktion ist rein für die Erstellung des Beweis-Objekts zuständig.
/// Sie erhält alle notwendigen, bereits validierten Daten und signiert sie.
/// Die deterministische `proof_id` wird hier generiert.
///
/// # Arguments
/// * `offender_id` - Die ID des Verursachers.
/// * `fork_point_prev_hash` - Der `prev_hash`, an dem die Transaktionen abzweigen.
/// * `conflicting_transactions` - Die bereits verifizierten, widersprüchlichen Transaktionen.
/// * `voucher_valid_until` - Das Gültigkeitsdatum des betroffenen Gutscheins.
/// * `reporter_identity` - Die Identität des Wallet-Besitzers, der den Beweis erstellt.
///
/// # Returns
/// Ein `Result`, das bei Erfolg das erstellte `ProofOfDoubleSpend`-Objekt enthält.
pub fn create_proof_of_double_spend(
    offender_id: String,
    fork_point_prev_hash: String,
    conflicting_transactions: Vec<Transaction>,
    voucher_valid_until: String,
    reporter_identity: &UserIdentity,
) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
    // 1. Beweis-Objekt erstellen und signieren.
    let proof_id = get_hash(format!("{}{}", offender_id, fork_point_prev_hash));
    let reporter_signature_bytes =
        sign_ed25519(&reporter_identity.signing_key, proof_id.as_bytes());
    let reporter_signature = bs58::encode(reporter_signature_bytes.to_bytes()).into_string();

    let proof = ProofOfDoubleSpend {
        proof_id,
        offender_id,
        fork_point_prev_hash,
        conflicting_transactions,
        voucher_valid_until,
        reporter_id: reporter_identity.user_id.clone(),
        report_timestamp: get_current_timestamp(),
        reporter_signature,
        resolutions: None,
        layer2_verdict: None,
    };

    Ok(proof)
}

/// Erstellt und signiert eine Beilegungserklärung (`ResolutionEndorsement`) für einen
/// bestehenden Konfliktbeweis.
///
/// # Arguments
/// * `proof_id` - Die ID des `ProofOfDoubleSpend`, der beigelegt wird.
/// * `victim_identity` - Die Identität des Opfers, das die Beilegung bestätigt.
/// * `notes` - Eine optionale, menschenlesbare Notiz.
///
/// # Returns
/// Ein `Result`, das die signierte `ResolutionEndorsement` enthält.
pub fn create_and_sign_resolution_endorsement(
    proof_id: &str,
    victim_identity: &UserIdentity,
    notes: Option<String>,
) -> Result<ResolutionEndorsement, VoucherCoreError> {
    let resolution_timestamp = get_current_timestamp();

    // 1. Temporäres Objekt für Hashing erstellen (ohne ID und Signatur)
    let endorsement_data = serde_json::json!({
        "proof_id": proof_id,
        "victim_id": victim_identity.user_id,
        "resolution_timestamp": resolution_timestamp,
        "notes": notes
    });

    // 2. ID und Signatur erzeugen
    let endorsement_id = get_hash(to_canonical_json(&endorsement_data)?);
    let signature_bytes = sign_ed25519(&victim_identity.signing_key, endorsement_id.as_bytes());
    let victim_signature = bs58::encode(signature_bytes.to_bytes()).into_string();

    // 3. Finales Objekt zusammenbauen
    Ok(ResolutionEndorsement {
        endorsement_id,
        proof_id: proof_id.to_string(),
        victim_id: victim_identity.user_id.clone(),
        resolution_timestamp,
        notes,
        victim_signature,
    })
}

/// Entfernt alle abgelaufenen Fingerprints aus den nicht-kritischen Speichern.
pub fn cleanup_known_fingerprints(known_fingerprints: &mut KnownFingerprints) {
    let now = get_current_timestamp();
    known_fingerprints.foreign_fingerprints.retain(|_, fps| {
        fps.retain(|fp| fp.valid_until > now);
        !fps.is_empty()
    });
}

/// Bereinigt die persistente Fingerprint-History basierend auf einer längeren Aufbewahrungsfrist.
pub fn cleanup_expired_histories(
    own_fingerprints: &mut OwnFingerprints,
    known_fingerprints: &mut KnownFingerprints,
    now: &DateTime<chrono::Utc>,
    grace_period: &chrono::Duration,
) {
    own_fingerprints.history.retain(|_, fps| {
        fps.retain(|fp| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.valid_until)
                .map(|dt| dt.with_timezone(&chrono::Utc))
            {
                let purge_date = valid_until + *grace_period;
                return *now < purge_date;
            }
            true // Bei Parse-Fehler vorsichtshalber behalten
        });
        !fps.is_empty()
    });
    known_fingerprints.local_history.retain(|_, fps| {
        fps.retain(|fp| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.valid_until)
                .map(|dt| dt.with_timezone(&chrono::Utc))
            {
                let purge_date = valid_until + *grace_period;
                return *now < purge_date;
            }
            true // Bei Parse-Fehler vorsichtshalber behalten
        });
        !fps.is_empty()
    });
}

/// Serialisiert die Historie der eigenen gesendeten Transaktionen für den Export.
pub fn export_own_fingerprints(
    own_fingerprints: &OwnFingerprints,
) -> Result<Vec<u8>, VoucherCoreError> {
    // HINWEIS: Exportiert wird die gesamte bekannte Historie, da dies die wertvollste
    // Information für den Abgleich mit Peers ist.
    Ok(serde_json::to_vec(&own_fingerprints.history)?)
}

/// Importiert und merged fremde Fingerprints in den Speicher.
pub fn import_foreign_fingerprints(
    known_fingerprints: &mut KnownFingerprints,
    data: &[u8],
) -> Result<usize, VoucherCoreError> {
    let incoming: HashMap<String, Vec<TransactionFingerprint>> = serde_json::from_slice(data)?;
    let mut new_count = 0;
    for (hash, fps) in incoming {
        let entry = known_fingerprints
            .foreign_fingerprints
            .entry(hash)
            .or_default();
        for fp in fps {
            if !entry.contains(&fp) {
                entry.push(fp);
                new_count += 1;
            }
        }
    }
    Ok(new_count)
}

/// Verschlüsselt den Zeitstempel einer Transaktion für die Verwendung in einem L2-Kontext.
///
/// Die Verschlüsselung erfolgt via XOR mit einem Schlüssel, der deterministisch aus der
/// Transaktion selbst abgeleitet wird. Dies stellt sicher, dass jeder, der die
/// widersprüchlichen Transaktionen besitzt, den Zeitstempel entschlüsseln kann.
///
/// # Arguments
/// * `transaction` - Die Transaktion, deren Zeitstempel verschlüsselt werden soll.
///
/// # Returns
/// Ein `u128` Wert, der den verschlüsselten Zeitstempel in Nanosekunden darstellt.
pub fn encrypt_transaction_timestamp(transaction: &Transaction) -> Result<u128, VoucherCoreError> {
    // a. Zeitstempel parsen und in Nanosekunden (u128) umwandeln.
    let nanos = DateTime::parse_from_rfc3339(&transaction.t_time)
        .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse timestamp: {}", e)))?
        .timestamp_nanos_opt()
        .ok_or_else(|| {
            VoucherCoreError::Generic("Invalid timestamp for nanosecond conversion".to_string())
        })? as u128;

    // b. Schlüssel (u128) aus dem Hash von prev_hash und t_id ableiten.
    let key_material = format!("{}{}", transaction.prev_hash, transaction.t_id);
    let key_hash_b58 = get_hash(key_material);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string())
    })?;

    // Wir nehmen die ersten 16 Bytes (128 Bits) des Hashes als Schlüssel.
    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    // c. Zeitstempel via XOR verschlüsseln und zurückgeben.
    Ok(nanos ^ key)
}

/// Entschlüsselt den Zeitstempel einer Transaktion, der mit `encrypt_transaction_timestamp`
/// verschlüsselt wurde.
///
/// Da die Verschlüsselung auf XOR basiert, ist die Entschlüsselungsfunktion identisch.
///
/// # Arguments
/// * `transaction` - Die Transaktion, zu der der Zeitstempel gehört.
/// * `encrypted_nanos` - Der verschlüsselte Zeitstempel in Nanosekunden (`u128`).
///
/// # Returns
/// Der ursprüngliche, entschlüsselte Zeitstempel in Nanosekunden.
pub fn decrypt_transaction_timestamp(
    transaction: &Transaction,
    encrypted_nanos: u128,
) -> Result<u128, VoucherCoreError> {
    let key_material = format!("{}{}", transaction.prev_hash, transaction.t_id);
    let key_hash_b58 = get_hash(key_material);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string())
    })?;

    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    Ok(encrypted_nanos ^ key)
}
