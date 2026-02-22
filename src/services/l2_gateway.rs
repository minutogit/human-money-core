use crate::error::VoucherCoreError;
use crate::models::layer2_api::{L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2Verdict};
use crate::models::voucher::Transaction;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Definiert die Aktion, die der AppService nach der Auswertung des Urteils durchführen soll.
pub enum VerdictAction {
    /// Das L2-Netzwerk hat die Transaktion als gültig bestätigt.
    ConfirmLocal,
    /// Ein Double-Spend wurde erkannt, das Wallet/der Gutschein muss zwingend in Quarantäne.
    TriggerQuarantine(String),
    /// Eine Synchronisation ist erforderlich. Beinhaltet den sync_point (Präfix).
    TriggerSync { sync_point: String },
}

/// Generiert einen L2LockRequest basierend auf der gegebenen Transaktion.
pub fn generate_lock_request(
    _voucher_id: &str,
    transaction: &Transaction,
    ephemeral_key: &[u8; 32],
) -> Result<L2LockRequest, VoucherCoreError> {
    let is_genesis = transaction.t_type == "init";

    let l2_voucher_id = if is_genesis {
        calculate_layer2_voucher_id(transaction)?
    } else {
        // Für Nicht-Genesis Transaktionen muss die ID des Gutscheins bekannt sein.
        // In der aktuellen Implementierung nehmen wir an, dass sie extern übergeben wird
        // oder aus dem prev_hash/traps abgeleitet werden kann.
        // Für den Moment nehmen wir an, dass `_voucher_id` (sofern im Hex-Format) die ID ist,
        // oder wir berechnen sie aus dem genesis_hash (prev_hash bei der ersten Tx nach init).
        // Laut Anforderung wird sie bei jeder L2-Anfrage mitgeschickt.
        _voucher_id.to_string()
    };

    let ds_tag = if is_genesis {
        None
    } else {
        match &transaction.trap_data {
            Some(td) => {
                // Verwende direkt den Base58 ds_tag aus den TrapData (Spec-Konformität)
                Some(td.ds_tag.clone())
            }
            None => return Err(VoucherCoreError::MissingTrapData),
        }
    };

    let mut t_id = [0u8; 32];
    let decoded_t_id = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for t_id".to_string()))?;
    if decoded_t_id.len() != 32 {
        return Err(VoucherCoreError::InvalidHashFormat(
            "t_id must be 32 bytes".to_string(),
        ));
    }
    t_id.copy_from_slice(&decoded_t_id);

    // Dummy Auth-Daten für den Moment (wie gefordert)
    let auth = L2AuthPayload {
        ephemeral_pubkey: *ephemeral_key,
        auth_signature: None,
    };

    let mut sender_ephemeral_pub = [0u8; 32];
    let decoded_sep = bs58::decode(transaction.sender_ephemeral_pub.as_deref().unwrap_or(""))
        .into_vec()
        .unwrap_or_else(|_| vec![0; 32]);
    if decoded_sep.len() == 32 {
        sender_ephemeral_pub.copy_from_slice(&decoded_sep);
    }

    let receiver_ephemeral_pub_hash =
        transaction
            .receiver_ephemeral_pub_hash
            .as_ref()
            .and_then(|h| {
                bs58::decode(h).into_vec().ok().and_then(|v| {
                    if v.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&v);
                        Some(arr)
                    } else {
                        None
                    }
                })
            });

    let change_ephemeral_pub_hash = transaction
        .change_ephemeral_pub_hash
        .as_ref()
        .and_then(|h| {
            bs58::decode(h).into_vec().ok().and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    None
                }
            })
        });

    let mut layer2_signature = [0u8; 64];
    let decoded_sig = bs58::decode(transaction.layer2_signature.as_deref().unwrap_or(""))
        .into_vec()
        .unwrap_or_else(|_| vec![0; 64]);
    if decoded_sig.len() == 64 {
        layer2_signature.copy_from_slice(&decoded_sig);
    }

    Ok(L2LockRequest {
        auth,
        layer2_voucher_id: l2_voucher_id,
        ds_tag,
        transaction_hash: t_id,
        is_genesis,
        sender_ephemeral_pub,
        receiver_ephemeral_pub_hash,
        change_ephemeral_pub_hash,
        layer2_signature,
        deletable_at: if is_genesis {
            transaction.deletable_at.clone()
        } else {
            None
        },
    })
}

/// Berechnet die layer2_voucher_id aus einer Genesis-Transaktion.
pub fn calculate_layer2_voucher_id(transaction: &Transaction) -> Result<String, VoucherCoreError> {
    if transaction.t_type != "init" {
        return Err(VoucherCoreError::Generic(
            "Only init transactions can define a voucher id".to_string(),
        ));
    }

    let mut t_id = [0u8; 32];
    let decoded_t_id = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for t_id".to_string()))?;
    if decoded_t_id.len() != 32 {
        return Err(VoucherCoreError::InvalidHashFormat(
            "t_id must be 32 bytes".to_string(),
        ));
    }
    t_id.copy_from_slice(&decoded_t_id);

    let mut sender_pub = [0u8; 32];
    let decoded_pub = bs58::decode(transaction.sender_ephemeral_pub.as_deref().unwrap_or(""))
        .into_vec()
        .unwrap_or_else(|_| vec![0; 32]);
    if decoded_pub.len() == 32 {
        sender_pub.copy_from_slice(&decoded_pub);
    }

    let receiver_hash = transaction
        .receiver_ephemeral_pub_hash
        .as_ref()
        .and_then(|h| {
            bs58::decode(h).into_vec().ok().and_then(|v| {
                if v.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&v);
                    Some(arr)
                } else {
                    None
                }
            })
        });

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(t_id);
    hasher.update(sender_pub);
    if let Some(r) = receiver_hash {
        hasher.update(r);
    }
    if let Some(v) = &transaction.deletable_at {
        hasher.update(v.as_bytes());
    }

    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Generiert einen deterministischen Hash des L2-Payloads für die Signaturprüfung.
pub fn calculate_l2_payload_hash(req: &L2LockRequest) -> [u8; 32] {
    let challenge_ds_tag = if req.is_genesis {
        bs58::encode(req.transaction_hash).into_string()
    } else {
        req.ds_tag.clone().unwrap_or_default()
    };

    calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &req.layer2_voucher_id,
        &req.transaction_hash,
        &req.sender_ephemeral_pub,
        req.receiver_ephemeral_pub_hash.as_ref(),
        req.change_ephemeral_pub_hash.as_ref(),
        req.deletable_at.as_deref(),
    )
}

/// Innere Logik für das Hashing des L2-Payloads (wird auch vom Wallet genutzt).
pub fn calculate_l2_payload_hash_raw(
    challenge_ds_tag: &str,
    layer2_voucher_id: &str,
    transaction_hash: &[u8; 32],
    sender_pub: &[u8; 32],
    receiver_hash: Option<&[u8; 32]>,
    change_hash: Option<&[u8; 32]>,
    deletable_at: Option<&str>,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();

    hasher.update(challenge_ds_tag.as_bytes());
    hasher.update(layer2_voucher_id.as_bytes());
    hasher.update(transaction_hash);
    hasher.update(sender_pub);
    if let Some(r) = receiver_hash {
        hasher.update(r);
    }
    if let Some(c) = change_hash {
        hasher.update(c);
    }
    if let Some(v) = deletable_at {
        hasher.update(v.as_bytes());
    }

    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Leitet den Challenge-DS-Tag für eine Transaktion ab.
/// Bei Genesis ist dies die t_id, andernfalls der ds_tag aus den TrapData.
pub fn derive_challenge_tag(tx: &Transaction) -> Result<String, VoucherCoreError> {
    if tx.t_type == "init" {
        Ok(tx.t_id.clone())
    } else {
        match &tx.trap_data {
            Some(td) => Ok(td.ds_tag.clone()),
            None => Err(VoucherCoreError::MissingTrapData),
        }
    }
}

/// Extrahiert die layer2_voucher_id aus einem Gutschein (basierend auf der Genesis-Tx).
pub fn extract_layer2_voucher_id(
    voucher: &crate::models::voucher::Voucher,
) -> Result<String, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(VoucherCoreError::Generic(
            "Voucher has no transactions".to_string(),
        ));
    }
    calculate_layer2_voucher_id(&voucher.transactions[0])
}

/// Verarbeitet das L2Verdict und bestimmt die darauffolgende Wallet-Aktion.
pub fn process_l2_verdict(
    verdict_bytes: &[u8],
    server_pubkey: &[u8; 32],
    local_t_id: &str,       // Die lokale t_id der angefragten Transaktion
    challenge_ds_tag: &str, // Der für die Abfrage genutzte Challenge-Tag
    expected_ephemeral_pub: Option<&str>, // Der erwartete Key laut lokaler Historie
    expected_voucher_id: &str, // Die erwartete Voucher ID
) -> Result<VerdictAction, VoucherCoreError> {
    let envelope: L2ResponseEnvelope = serde_json::from_slice(verdict_bytes).map_err(|e| {
        VoucherCoreError::DeserializationError(format!("Invalid response envelope: {}", e))
    })?;

    // 1. Verifiziere die Server-Authentizität
    let server_key = VerifyingKey::from_bytes(server_pubkey)
        .map_err(|_| VoucherCoreError::ValidationFailed("Invalid server public key".to_string()))?;
    let server_sig = Signature::from_bytes(&envelope.server_signature);

    let verdict_serialized = serde_json::to_vec(&envelope.verdict).map_err(|e| {
        VoucherCoreError::DeserializationError(format!(
            "Failed to serialize verdict for verification: {}",
            e
        ))
    })?;

    // Wir hashen das Urteil für die Signaturprüfung
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&verdict_serialized);
    let verdict_hash = hasher.finalize();

    #[cfg(feature = "test-utils")]
    let server_sig_valid = server_key.verify(&verdict_hash, &server_sig).is_ok()
        || crate::is_signature_bypass_active();
    #[cfg(not(feature = "test-utils"))]
    let server_sig_valid = server_key.verify(&verdict_hash, &server_sig).is_ok();

    if !server_sig_valid {
        return Err(VoucherCoreError::ValidationFailed(
            "Server-Signatur ist ungültig (Authentizität fehlgeschlagen)".to_string(),
        ));
    }

    let verdict = envelope.verdict;

    match verdict {
        L2Verdict::Verified { lock_entry } => {
            // 0. Verifiziere Voucher ID Match
            if lock_entry.layer2_voucher_id != expected_voucher_id {
                return Err(VoucherCoreError::ValidationFailed(format!(
                    "Voucher ID Mix-up erkannt: L2-Server meldet Beweis für einen anderen Gutschein ({} != {})",
                    lock_entry.layer2_voucher_id, expected_voucher_id
                )));
            }

            // 1. Verifiziere die L2-Signatur mathematisch (Proof of Truth)
            let ephem_key =
                VerifyingKey::from_bytes(&lock_entry.sender_ephemeral_pub).map_err(|_| {
                    VoucherCoreError::ValidationFailed(
                        "Invalid ephemeral key in lock entry".to_string(),
                    )
                })?;
            let signature = Signature::from_bytes(&lock_entry.layer2_signature);

            // Payload rekonstruieren: challenge_ds_tag + t_id + sender_ephemeral_pub + hashes + ...
            let payload_hash = calculate_l2_payload_hash_raw(
                challenge_ds_tag,
                &lock_entry.layer2_voucher_id,
                &lock_entry.t_id,
                &lock_entry.sender_ephemeral_pub,
                lock_entry.receiver_ephemeral_pub_hash.as_ref(),
                lock_entry.change_ephemeral_pub_hash.as_ref(),
                lock_entry.deletable_at.as_deref(),
            );

            #[cfg(feature = "test-utils")]
            let signature_valid = ephem_key.verify(&payload_hash, &signature).is_ok()
                || crate::is_signature_bypass_active();
            #[cfg(not(feature = "test-utils"))]
            let signature_valid = ephem_key.verify(&payload_hash, &signature).is_ok();

            if !signature_valid {
                return Err(VoucherCoreError::ValidationFailed(
                    "Kryptografischer Beweis des L2-Servers ist ungültig".to_string(),
                ));
            }

            // 2. Verifiziere, dass der Key in der Antwort unserem erwarteten Key entspricht
            if let Some(expected) = expected_ephemeral_pub {
                let actual_bs58 = bs58::encode(&lock_entry.sender_ephemeral_pub).into_string();
                if actual_bs58 != expected {
                    return Err(VoucherCoreError::ValidationFailed(format!(
                        "Gefälschter Beweis erkannt: L2-Server meldet Double-Spend mit einem fremden Key ({} != {})",
                        actual_bs58, expected
                    )));
                }
            }

            // 2. Vergleiche t_id
            let server_t_id = bs58::encode(lock_entry.t_id).into_string();
            if server_t_id == local_t_id {
                Ok(VerdictAction::ConfirmLocal)
            } else {
                // Double-Spend erkannt!
                Ok(VerdictAction::TriggerQuarantine(server_t_id))
            }
        }
        L2Verdict::MissingLocks { sync_point } => {
            // Signalisiere, dass wir synchronisieren müssen
            Ok(VerdictAction::TriggerSync { sync_point })
        }
        L2Verdict::UnknownVoucher => {
            // Signalisiere, dass der Gutschein unbekannt ist (Full Upload nötig)
            Ok(VerdictAction::TriggerSync {
                sync_point: "genesis".to_string(),
            })
        }
        L2Verdict::Ok { .. } => {
            // Fallback für alte Implementationen
            Ok(VerdictAction::ConfirmLocal)
        }
        L2Verdict::Rejected { reason } => Err(VoucherCoreError::ValidationFailed(format!(
            "L2 Server hat die Anfrage abgelehnt: {}",
            reason
        ))),
    }
}

/// Generiert die logarithmischen Locators für einen Zustandsabgleich.
/// Sendet Präfixe der ds_tags (10 Zeichen Base58) in exponentiellen Abständen zurück.
pub fn generate_locator_prefixes(voucher: &crate::models::voucher::Voucher) -> Vec<String> {
    let mut prefixes = Vec::new();
    let n = voucher.transactions.len();
    if n == 0 {
        return prefixes;
    }

    // Wir gehen rückwärts von der aktuellen Transaktion (n-1)
    let mut step = 1;
    let mut i = n - 1;

    while i > 0 {
        if let Some(td) = &voucher.transactions[i].trap_data {
            // Nimm die ersten 10 Zeichen des Base58 ds_tags
            prefixes.push(td.ds_tag.chars().take(10).collect());
        }

        if i < step {
            break;
        }
        i -= step;
        step *= 2; // Exponentielle Abstände: 1, 2, 4, 8, 16...
    }

    // Immer den ersten (Genesis) Lock mitschicken (falls vorhanden und nicht schon drin)
    if let Ok(first_tag) = derive_challenge_tag(&voucher.transactions[0]) {
        let first_prefix: String = first_tag.chars().take(10).collect();
        if !prefixes.contains(&first_prefix) {
            prefixes.push(first_prefix);
        }
    }

    prefixes
}
