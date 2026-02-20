use crate::error::VoucherCoreError;
use crate::models::layer2_api::{L2AuthPayload, L2LockRequest, L2Verdict};
use crate::models::voucher::Transaction;
use crate::services::crypto_utils;

/// Definiert die Aktion, die der AppService nach der Auswertung des Urteils durchführen soll.
pub enum VerdictAction {
    /// Das L2-Netzwerk hat die Transaktion als gültig bestätigt.
    ConfirmLocal,
    /// Ein Double-Spend wurde erkannt, das Wallet/der Gutschein muss zwingend in Quarantäne.
    TriggerQuarantine(String),
}


/// Generiert einen L2LockRequest basierend auf der gegebenen Transaktion.
pub fn generate_lock_request(
    voucher_id: &str,
    transaction: &Transaction,
    ephemeral_key: &[u8; 32],
) -> Result<L2LockRequest, VoucherCoreError> {
    let is_genesis = transaction.t_type == "init";

    let ds_tag_str = if is_genesis {
        // Bei Genesis gibt es keinen Input, daher nehmen wir den ds_tag als Hash der voucher_id
        crypto_utils::get_hash(voucher_id.as_bytes())
    } else {
        match &transaction.trap_data {
            Some(td) => td.ds_tag.clone(),
            None => return Err(VoucherCoreError::MissingTrapData),
        }
    };

    let mut ds_tag = [0u8; 32];
    let decoded_ds_tag = bs58::decode(&ds_tag_str).into_vec().map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid base58 for ds_tag".to_string()))?;
    if decoded_ds_tag.len() != 32 {
        return Err(VoucherCoreError::InvalidHashFormat("ds_tag must be 32 bytes".to_string()));
    }
    ds_tag.copy_from_slice(&decoded_ds_tag);

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
        ds_tag,
        transaction_hash: t_id,
        is_genesis,
        sender_ephemeral_pub,
        receiver_ephemeral_pub_hash,
        change_ephemeral_pub_hash,
        layer2_signature,
    })
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
