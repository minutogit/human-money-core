use crate::error::VoucherCoreError;
use crate::models::layer2_api::{L2AuthPayload, L2LockRequest, L2Verdict};
use crate::models::voucher::Transaction;

/// Definiert die Aktion, die der AppService nach der Auswertung des Urteils durchführen soll.
pub enum VerdictAction {
    /// Das L2-Netzwerk hat die Transaktion als gültig bestätigt.
    ConfirmLocal,
    /// Ein Double-Spend wurde erkannt, das Wallet/der Gutschein muss zwingend in Quarantäne.
    TriggerQuarantine(String),
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
                // Konvertiere Base58 ds_tag zu Hex
                let decoded = bs58::decode(&td.ds_tag).into_vec().map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for ds_tag".to_string()))?;
                Some(hex::encode(decoded))
            },
            None => return Err(VoucherCoreError::MissingTrapData),
        }
    };

    let mut t_id = [0u8; 32];
    let decoded_t_id = bs58::decode(&transaction.t_id).into_vec().map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for t_id".to_string()))?;
    if decoded_t_id.len() != 32 {
        return Err(VoucherCoreError::InvalidHashFormat("t_id must be 32 bytes".to_string()));
    }
    t_id.copy_from_slice(&decoded_t_id);

    // Dummy Auth-Daten für den Moment (wie gefordert)
    let auth = L2AuthPayload {
        ephemeral_pubkey: *ephemeral_key,
        auth_signature: None,
    };

    let mut sender_ephemeral_pub = [0u8; 32];
    let decoded_sep = bs58::decode(transaction.sender_ephemeral_pub.as_deref().unwrap_or("")).into_vec().unwrap_or_else(|_| vec![0; 32]);
    if decoded_sep.len() == 32 {
        sender_ephemeral_pub.copy_from_slice(&decoded_sep);
    }

    let receiver_ephemeral_pub_hash = transaction.receiver_ephemeral_pub_hash.as_ref().and_then(|h| {
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

    let change_ephemeral_pub_hash = transaction.change_ephemeral_pub_hash.as_ref().and_then(|h| {
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
    let decoded_sig = bs58::decode(transaction.layer2_signature.as_deref().unwrap_or("")).into_vec().unwrap_or_else(|_| vec![0; 64]);
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
        valid_until: if is_genesis { transaction.valid_until.clone() } else { None },
    })
}

/// Berechnet die layer2_voucher_id aus einer Genesis-Transaktion.
pub fn calculate_layer2_voucher_id(transaction: &Transaction) -> Result<String, VoucherCoreError> {
    if transaction.t_type != "init" {
        return Err(VoucherCoreError::Generic("Only init transactions can define a voucher id".to_string()));
    }

    let mut t_id = [0u8; 32];
    let decoded_t_id = bs58::decode(&transaction.t_id).into_vec().map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for t_id".to_string()))?;
    if decoded_t_id.len() != 32 { return Err(VoucherCoreError::InvalidHashFormat("t_id must be 32 bytes".to_string())); }
    t_id.copy_from_slice(&decoded_t_id);

    let mut sender_pub = [0u8; 32];
    let decoded_pub = bs58::decode(transaction.sender_ephemeral_pub.as_deref().unwrap_or("")).into_vec().unwrap_or_else(|_| vec![0; 32]);
    if decoded_pub.len() == 32 { sender_pub.copy_from_slice(&decoded_pub); }

    let receiver_hash = transaction.receiver_ephemeral_pub_hash.as_ref().and_then(|h| {
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
    if let Some(v) = &transaction.valid_until {
        hasher.update(v.as_bytes());
    }
    
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Generiert einen deterministischen Hash des L2-Payloads für die Signaturprüfung.
pub fn calculate_l2_payload_hash(req: &L2LockRequest) -> [u8; 32] {
    calculate_l2_payload_hash_raw(
        &req.layer2_voucher_id,
        req.ds_tag.as_deref(),
        &req.transaction_hash,
        &req.sender_ephemeral_pub,
        req.receiver_ephemeral_pub_hash.as_ref(),
        req.change_ephemeral_pub_hash.as_ref(),
        req.valid_until.as_deref(),
    )
}

/// Innere Logik für das Hashing des L2-Payloads (wird auch vom Wallet genutzt).
pub fn calculate_l2_payload_hash_raw(
    layer2_voucher_id: &str,
    ds_tag: Option<&str>,
    transaction_hash: &[u8; 32],
    sender_pub: &[u8; 32],
    receiver_hash: Option<&[u8; 32]>,
    change_hash: Option<&[u8; 32]>,
    valid_until: Option<&str>,
) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    
    hasher.update(layer2_voucher_id.as_bytes());
    if let Some(ds) = ds_tag {
        hasher.update(ds.as_bytes());
    }
    hasher.update(transaction_hash);
    hasher.update(sender_pub);
    if let Some(r) = receiver_hash {
        hasher.update(r);
    }
    if let Some(c) = change_hash {
        hasher.update(c);
    }
    if let Some(v) = valid_until {
        hasher.update(v.as_bytes());
    }
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Extrahiert die layer2_voucher_id aus einem Gutschein (basierend auf der Genesis-Tx).
pub fn extract_layer2_voucher_id(voucher: &crate::models::voucher::Voucher) -> Result<String, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(VoucherCoreError::Generic("Voucher has no transactions".to_string()));
    }
    calculate_layer2_voucher_id(&voucher.transactions[0])
}

/// Verarbeitet das L2Verdict und bestimmt die darauffolgende Wallet-Aktion.
pub fn process_l2_verdict(
    verdict_bytes: &[u8],
    _server_pubkey: &[u8; 32], // Platzhalter für zukünftige Signaturprüfung
) -> Result<VerdictAction, VoucherCoreError> {
    let verdict: L2Verdict = serde_json::from_slice(verdict_bytes)
        .map_err(|e| VoucherCoreError::DeserializationError(e.to_string()))?;

    // In der Zukunft würde hier `server_pubkey` genutzt werden, 
    // um die Signatur in `verdict` zu überprüfen.

    match verdict {
        L2Verdict::Ok { .. } | L2Verdict::Verified { .. } => Ok(VerdictAction::ConfirmLocal),
        L2Verdict::DoubleSpend { conflicting_t_id, .. } => {
            let t_id_str = bs58::encode(conflicting_t_id).into_string();
            Ok(VerdictAction::TriggerQuarantine(t_id_str))
        }
        L2Verdict::ConflictFound { conflicting_t_id } => {
            let t_id_str = bs58::encode(conflicting_t_id).into_string();
            Ok(VerdictAction::TriggerQuarantine(t_id_str))
        }
    }
}
