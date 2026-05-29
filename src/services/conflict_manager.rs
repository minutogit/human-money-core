//! # src/services/conflict_manager.rs
//!
//! This module encapsulates the entire business logic for detection, verification,
//! and management of double-spending conflicts. It operates on the wallet's
//! data structures but is decoupled from the `Wallet` facade.

use std::collections::HashMap;

use crate::error::VoucherCoreError;
use crate::models::conflict::{
    KnownFingerprints, OwnFingerprints, ProofOfDoubleSpend, ResolutionEndorsement,
    TransactionFingerprint,
};
use crate::models::profile::{UserIdentity, VoucherStore};
use crate::models::voucher::{Transaction, Voucher};
use crate::services::crypto_utils::{get_hash, get_hash_from_slices, sign_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::wallet::DoubleSpendCheckResult;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};

/// Creates a single, anonymized fingerprint for a given transaction.
/// Contains the logic for anonymizing the `valid_until` timestamp.
pub fn create_fingerprint_for_transaction(
    transaction: &Transaction,
    voucher: &Voucher,
) -> Result<TransactionFingerprint, VoucherCoreError> {
    // 1. Anonymize the `valid_until` timestamp by rounding to the end of the month.
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

        let last_day_of_month = first_of_next_month.pred_opt().ok_or_else(|| {
            VoucherCoreError::Generic("Failed to get last day of month".to_string())
        })?;
        let end_of_month_dt = last_day_of_month
            .and_hms_micro_opt(23, 59, 59, 999999)
            .ok_or_else(|| {
                VoucherCoreError::Generic("Failed to set time for end of month".to_string())
            })?
            .and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    // 2. Create the fingerprint with the rounded timestamp.
    // NEW: We use the 'ds_tag' from the TrapData as the canonical DS tag.
    // This ensures that the fingerprint matches the mathematical trap exactly.
    // Only for 'init' (which has no trap) do we calculate the tag manually.
    let (tag, u, blinded_id) = if let Some(trap) = &transaction.trap_data {
        (trap.ds_tag.clone(), trap.u.clone(), trap.blinded_id.clone())
    } else {
        // Pad with zeros if the hash is shorter.
        // SECURITY FIX: Use raw bytes for concatenation
        let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
            .into_vec()
            .map_err(|_| VoucherCoreError::Generic("Invalid prev_hash format".to_string()))?;
        let ephem_key_bytes = if let Some(s) = &transaction.sender_ephemeral_pub {
            bs58::decode(s).into_vec().map_err(|_| {
                VoucherCoreError::Generic("Invalid sender_ephemeral_pub format".to_string())
            })?
        } else {
            Vec::new()
        };

        let fallback_tag = get_hash_from_slices(&[&prev_hash_bytes, &ephem_key_bytes]);
        (fallback_tag, "none".to_string(), "none".to_string())
    };

    Ok(TransactionFingerprint {
        ds_tag: tag,
        u,
        blinded_id,
        t_id: transaction.t_id.clone(),
        layer2_signature: transaction.layer2_signature.clone().unwrap_or_default(),
        deletable_at: valid_until_rounded,
        encrypted_timestamp: encrypt_transaction_timestamp(transaction)?,
    })
}

/// Scans the `VoucherStore` and builds the current fingerprint collections.
/// This function correctly partitions the fingerprints into the critical "own"
/// history and the general "known" history.
pub fn scan_and_rebuild_fingerprints(
    voucher_store: &VoucherStore,
    user_id: &str,
) -> Result<(OwnFingerprints, KnownFingerprints), VoucherCoreError> {
    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    for instance in voucher_store.vouchers.values() {
        // Ignore endorsed vouchers during fingerprint scan, since they do not belong
        // to the user and must not contribute to double-spend detection.
        if matches!(
            instance.status,
            crate::wallet::instance::VoucherStatus::Endorsed { .. }
        ) {
            continue;
        }
        for tx in &instance.voucher.transactions {
            let fingerprint = create_fingerprint_for_transaction(tx, &instance.voucher)?;

            // Jede Transaktion wird zur allgemeinen lokalen Historie hinzugefügt.
            // CORRECTION: Prevent duplicates. A Vec is used to preserve order,
            // but we check for uniqueness before adding.
            let known_entry = known
                .local_history
                .entry(fingerprint.ds_tag.clone())
                .or_default();
            if !known_entry.contains(&fingerprint) {
                known_entry.push(fingerprint.clone());
            }

            // Only if the user was the sender is the fingerprint also added to
            // the critical "own" fingerprints.
            if tx.sender_id.as_deref() == Some(user_id) {
                own.history
                    .entry(fingerprint.ds_tag.clone())
                    .or_default()
                    .push(fingerprint.clone()); // Duplicates here are unlikely, but just to be safe

                // If the voucher is also active, it is added to the "Hot-List".
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

/// Performs a complete double-spend check by combining own and foreign
/// fingerprints and checking for collisions.
pub fn check_for_double_spend(
    own_fingerprints: &OwnFingerprints,
    known_fingerprints: &KnownFingerprints,
) -> DoubleSpendCheckResult {
    println!("\n[DEBUG CONFLICT_MANAGER] --- Starting check_for_double_spend ---");
    let mut result = DoubleSpendCheckResult::default();

    // 1. Deduplicate and merge all known fingerprints from all sources.
    // We use a HashSet to automatically eliminate duplicates
    // (e.g., between history and current_own).
    let mut all_fingerprints_map: HashMap<
        String,
        std::collections::HashSet<TransactionFingerprint>,
    > = HashMap::new();

    let sources = [
        &own_fingerprints.history,
        &known_fingerprints.local_history,
        &known_fingerprints.foreign_fingerprints,
    ];

    for source in sources.iter() {
        for (hash, fps) in *source {
            let entry = all_fingerprints_map.entry(hash.clone()).or_default();
            for fp in fps {
                entry.insert(fp.clone());
            }
        }
    }

    for (hash, fps_set) in all_fingerprints_map {
        let fps_vec: Vec<TransactionFingerprint> = fps_set.into_iter().collect();
        let unique_t_ids = fps_vec
            .iter()
            .map(|fp| &fp.t_id)
            .collect::<std::collections::HashSet<_>>();

        if unique_t_ids.len() > 1 {
            // 3. Classify a conflict as "verifiable" if the wallet owner
            // knows the involved fingerprints from any source — either from
            // the own transaction history (local_history) or received via gossip
            // (foreign_fingerprints). In both cases, the fingerprints carry the
            // cryptographic data (u, blinded_id) for DID key extraction.
            let is_verifiable = known_fingerprints.local_history.contains_key(&hash)
                || known_fingerprints.foreign_fingerprints.contains_key(&hash);
            if is_verifiable {
                result.verifiable_conflicts.insert(hash.clone(), fps_vec);
            } else {
                result.unverifiable_warnings.insert(hash.clone(), fps_vec);
            }
        }
    }
    result
}

/// Creates a tamper-proof, portable proof (`ProofOfDoubleSpend`).
///
/// This function is solely responsible for creating the proof object.
/// It receives all necessary, already validated data and signs it.
/// The deterministic `proof_id` is generated here.
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
    deletable_at: String,
    reporter_identity: &UserIdentity,
    non_redeemable_test_voucher: bool,
) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
    // 1. Create and sign the proof object.
    // SECURITY FIX: Use raw bytes for proof_id derivation
    let offender_pk_bytes = if let Some(pos) = offender_id.find("@did:key:z") {
        bs58::decode(&offender_id[pos + 10..])
            .into_vec()
            .map_err(|_| VoucherCoreError::Generic("Invalid offender_id did format".to_string()))?
    } else {
        // Fallback for anonymous offenders (Gossip soft proofs):
        // If there is no DID format, use the hash of the offender_id string
        // as a replacement for the public key bytes. This enables deterministic
        // proof_id calculation even for conflicts where the identity of the
        // offender has not yet been mathematically extracted.
        offender_id.as_bytes().to_vec()
    };

    let fork_prev_hash_bytes = bs58::decode(&fork_point_prev_hash)
        .into_vec()
        .map_err(|_| {
            VoucherCoreError::Generic("Invalid fork_point_prev_hash format".to_string())
        })?;

    let proof_id = get_hash_from_slices(&[&offender_pk_bytes, &fork_prev_hash_bytes]);
    let reporter_signature_bytes =
        sign_ed25519(&reporter_identity.signing_key, proof_id.as_bytes());
    let reporter_signature = bs58::encode(reporter_signature_bytes.to_bytes()).into_string();

    let proof = ProofOfDoubleSpend {
        proof_id,
        offender_id,
        fork_point_prev_hash,
        conflicting_transactions,
        deletable_at,
        reporter_id: reporter_identity.user_id.clone(),
        report_timestamp: get_current_timestamp(),
        reporter_signature,
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher,
    };

    Ok(proof)
}

/// Creates and signs a resolution endorsement (`ResolutionEndorsement`) for an
/// existing conflict proof.
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

    // 1. Create temporary object for hashing (without ID and signature)
    let endorsement_data = serde_json::json!({
        "proof_id": proof_id,
        "victim_id": victim_identity.user_id,
        "resolution_timestamp": resolution_timestamp,
        "notes": notes
    });

    // 2. Generate ID and signature
    let endorsement_id = get_hash(to_canonical_json(&endorsement_data)?);
    let signature_bytes = sign_ed25519(&victim_identity.signing_key, endorsement_id.as_bytes());
    let victim_signature = bs58::encode(signature_bytes.to_bytes()).into_string();

    // 3. Assemble final object
    Ok(ResolutionEndorsement {
        endorsement_id,
        proof_id: proof_id.to_string(),
        victim_id: victim_identity.user_id.clone(),
        resolution_timestamp,
        notes,
        victim_signature,
    })
}

/// Removes all expired fingerprints from non-critical stores.
/// Returns the number of removed entries.
pub fn cleanup_known_fingerprints(known_fingerprints: &mut KnownFingerprints) -> usize {
    let now = get_current_timestamp();
    let mut count: usize = 0;
    known_fingerprints.foreign_fingerprints.retain(|_, fps| {
        let before = fps.len();
        fps.retain(|fp| fp.deletable_at > now);
        count += before - fps.len();
        !fps.is_empty()
    });
    count
}

/// Cleans up the persistent fingerprint history based on a longer retention period.
/// Returns the number of removed entries.
pub fn cleanup_expired_histories(
    own_fingerprints: &mut OwnFingerprints,
    known_fingerprints: &mut KnownFingerprints,
    now: &DateTime<chrono::Utc>,
    grace_period: &chrono::Duration,
) -> usize {
    let mut count: usize = 0;
    own_fingerprints.history.retain(|_, fps| {
        let before = fps.len();
        fps.retain(|fp| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.deletable_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
            {
                let purge_date = valid_until + *grace_period;
                return *now < purge_date;
            }
            true // In case of a parse error, keep it to be safe
        });
        count += before - fps.len();
        !fps.is_empty()
    });
    known_fingerprints.local_history.retain(|_, fps| {
        let before = fps.len();
        fps.retain(|fp| {
            if let Ok(valid_until) = DateTime::parse_from_rfc3339(&fp.deletable_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
            {
                let purge_date = valid_until + *grace_period;
                return *now < purge_date;
            }
            true // In case of a parse error, keep it to be safe
        });
        count += before - fps.len();
        !fps.is_empty()
    });
    count
}

/// Serializes the history of own sent transactions for export.
pub fn export_own_fingerprints(
    own_fingerprints: &OwnFingerprints,
) -> Result<Vec<u8>, VoucherCoreError> {
    // NOTE: The entire known history is exported, as this is the most valuable
    // information for matching with peers.
    Ok(serde_json::to_vec(&own_fingerprints.history)?)
}

/// Imports and merges foreign fingerprints into memory.
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

/// Encrypts the timestamp of a transaction for use in an L2 context.
///
/// Encryption is performed via XOR with a key that is deterministically derived from the
/// transaction itself. This ensures that anyone who possesses the
/// conflicting transactions can decrypt the timestamp.
///
/// # Arguments
/// * `transaction` - Die Transaktion, deren Zeitstempel verschlüsselt werden soll.
///
/// # Returns
/// Ein `u128` Wert, der den verschlüsselten Zeitstempel in Nanosekunden darstellt.
pub fn encrypt_transaction_timestamp(transaction: &Transaction) -> Result<u128, VoucherCoreError> {
    // a. Parse timestamp and convert to nanoseconds (u128).
    let nanos = DateTime::parse_from_rfc3339(&transaction.t_time)
        .map_err(|e| VoucherCoreError::Generic(format!("Failed to parse timestamp: {}", e)))?
        .timestamp_nanos_opt()
        .ok_or_else(|| {
            VoucherCoreError::Generic("Invalid timestamp for nanosecond conversion".to_string())
        })? as u128;

    // b. Derive key (u128) from the hash of prev_hash and t_id.
    // SECURITY FIX: Use raw bytes for key derivation hash
    let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Invalid prev_hash format".to_string()))?;
    let t_id_bytes = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Invalid t_id format".to_string()))?;

    let key_hash_b58 = get_hash_from_slices(&[&prev_hash_bytes, &t_id_bytes]);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string())
    })?;

    // We take the first 16 bytes (128 bits) of the hash as the key.
    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    // c. Encrypt timestamp via XOR and return it.
    Ok(nanos ^ key)
}

/// Decrypts the timestamp of a transaction that was encrypted with `encrypt_transaction_timestamp`.
///
/// Since encryption is based on XOR, the decryption function is identical.
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
    // SECURITY FIX: Use raw bytes for key derivation hash (identical to encryption)
    let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Invalid prev_hash format".to_string()))?;
    let t_id_bytes = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::Generic("Invalid t_id format".to_string()))?;

    let key_hash_b58 = get_hash_from_slices(&[&prev_hash_bytes, &t_id_bytes]);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Generic("Failed to decode base58 hash for key derivation".to_string())
    })?;

    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Generic("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    Ok(encrypted_nanos ^ key)
}
