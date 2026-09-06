use crate::error::VoucherCoreError;
use crate::models::layer2_api::{L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2Verdict};
use crate::models::voucher::Transaction;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Defines the action that AppService should perform after evaluating the verdict.
pub enum VerdictAction {
    /// The L2 network confirmed the transaction as valid.
    ConfirmLocal,
    /// A double-spend was detected; the wallet/voucher must be placed in quarantine.
    TriggerQuarantine(String),
    /// Synchronization is required. Contains the sync_point (prefix).
    TriggerSync { sync_point: String },
}

/// Generates an L2LockRequest based on the given transaction.
pub fn generate_lock_request(
    _voucher_id: &str,
    transaction: &Transaction,
    ephemeral_key: &[u8; 32],
) -> Result<L2LockRequest, VoucherCoreError> {
    let is_genesis = transaction.t_type == "init";

    let l2_voucher_id = if is_genesis {
        calculate_layer2_voucher_id(transaction)?
    } else {
        // For non-genesis transactions, the voucher ID must be known.
        // In the current implementation, we assume it is passed externally
        // or can be derived from prev_hash/traps.
        // For now, we assume `_voucher_id` (if in hex format) is the ID,
        // or we compute it from genesis_hash (prev_hash on the first tx after init).
        // According to requirements, it is sent with every L2 request.
        _voucher_id.to_string()
    };

    let ds_tag = if is_genesis {
        None
    } else {
        match &transaction.trap_data {
            Some(td) => {
                // Use the Base58 ds_tag directly from TrapData (spec compliance)
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

    // Dummy auth data for now (as required)
    let auth = L2AuthPayload {
        ephemeral_pubkey: *ephemeral_key,
        auth_signature: None,
    };

    // SECURITY: Fail closed on malformed data. Silent zero-filling would
    // create lock requests that cannot be verified server-side.
    let sender_ephemeral_pub_str = transaction.sender_ephemeral_pub.as_deref().ok_or_else(|| {
        crate::Error::Wallet(crate::error::WalletError::MissingSenderEphemeralPub)
    })?;
    let decoded_sep = bs58::decode(sender_ephemeral_pub_str).into_vec().map_err(|_| {
        VoucherCoreError::InvalidHashFormat("Invalid base58 for sender_ephemeral_pub".to_string())
    })?;
    let mut sender_ephemeral_pub = [0u8; 32];
    if decoded_sep.len() != 32 {
        return Err(VoucherCoreError::InvalidHashFormat(
            "sender_ephemeral_pub must be 32 bytes".to_string(),
        ));
    }
    sender_ephemeral_pub.copy_from_slice(&decoded_sep);

    // SECURITY (HMSEC-SA06-14): Metadata minimization on the L2 wire.
    // The receiver-/change-anchor hashes of both output branches are NOT
    // consumed by the lock protocol (the reference client sends none) and
    // are NOT bound into the authenticating digest, so publishing them would
    // leak the topology/split-degree of otherwise-anonymous spends and
    // enable output-graph correlation across lock requests. They are
    // therefore never emitted; the fields remain in the wire model for
    // deserialization compatibility with legacy peers.
    let receiver_ephemeral_pub_hash: Option<[u8; 32]> = None;
    let change_ephemeral_pub_hash: Option<[u8; 32]> = None;

    // SECURITY: Fail closed on malformed signatures as well.
    let layer2_sig_str = transaction.layer2_signature.as_deref().ok_or_else(|| {
        crate::Error::Wallet(crate::error::WalletError::MissingLayer2Signature)
    })?;
    let decoded_sig = bs58::decode(layer2_sig_str).into_vec().map_err(|_| {
        VoucherCoreError::InvalidHashFormat("Invalid base58 for layer2_signature".to_string())
    })?;
    let mut layer2_signature = [0u8; 64];
    if decoded_sig.len() != 64 {
        return Err(VoucherCoreError::InvalidHashFormat(
            "layer2_signature must be 64 bytes".to_string(),
        ));
    }
    layer2_signature.copy_from_slice(&decoded_sig);

    // V3 Protocol (SST): bind the trap shards and the encrypted timestamp into
    // the payload digest. Genesis transactions have no trap ("none"/"none").
    let (trap_r, trap_s) = match &transaction.trap_data {
        Some(td) => (Some(td.trap_r.clone()), Some(td.trap_s.clone())),
        None => (
            Some(TRAP_NONE_PLACEHOLDER.to_string()),
            Some(TRAP_NONE_PLACEHOLDER.to_string()),
        ),
    };
    let encrypted_timestamp =
        crate::services::conflict_manager::encrypt_transaction_timestamp(transaction)?;

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
        trap_r,
        trap_s,
        encrypted_timestamp,
        deletable_at: if is_genesis {
            transaction.deletable_at.clone()
        } else {
            None
        },
        // SECURITY (HMSEC-SA04-08): transport the guard so the L2 server can
        // recompute its canonical commitment and verify the V3 digest of
        // guarded spends. Genesis / public-mode spends carry None.
        privacy_guard: transaction.privacy_guard.clone(),
    })
}

/// Domain-separation tag for the V3 transaction-authentication digest.
///
/// The digest simultaneously serves as:
/// - **L1 ownership proof** (chain validation of `layer2_signature`),
/// - **L2 lock proof** (server-side verification of lock requests), and
/// - **Gossip proof** (self-authenticating fingerprints / instant proofs).
///
/// # V3 Protocol (Shared-Signature Trap)
/// The digest binds the SST trap shards (`trap_r`, `trap_s`) instead of the
/// V2 `u`/`blinded_id` components, coupling gossip fingerprints to the
/// EUF-CMA security of the underlying Schnorr signature.
pub const HMC_TX_AUTH_V3_DOMAIN: &[u8] = b"HMC_TX_AUTH_V3";

/// Canonical placeholder for absent trap components (genesis transactions).
pub const TRAP_NONE_PLACEHOLDER: &str = "none";

/// Calculates the layer2_voucher_id from a genesis transaction.
pub fn calculate_layer2_voucher_id(transaction: &Transaction) -> Result<String, VoucherCoreError> {
    if transaction.t_type != "init" {
        return Err(crate::Error::Wallet(crate::error::WalletError::OnlyInitTransactionsAllowed));
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

/// SECURITY (HMSEC-SA04-08): Canonical commitment of a transaction's
/// `privacy_guard` that is bound into the V3 payload digest.
///
/// - `Some(guard)` binds the SHA3-256 hash (Base58) of the Base64 guard
///   payload — committing the handover context WITHOUT publishing the
///   (recipient-scoped) AEAD blob itself on the wire.
/// - `None` binds the empty string.
///
/// Guard equivocation (one input handed to two victims under two different
/// guards) therefore produces two distinct digests/signatures and becomes
/// distinguishable, attributable fraud evidence instead of silently
/// collapsing into byte-identical fingerprints.
pub fn privacy_guard_commitment(privacy_guard: Option<&str>) -> String {
    match privacy_guard {
        Some(guard) if !guard.is_empty() => {
            crate::services::crypto::get_hash(guard.as_bytes())
        }
        _ => String::new(),
    }
}

/// Generates a deterministic, domain-separated digest of the L2 payload for
/// signature verification (**V3 protocol**, digest `HMC_TX_AUTH_V3`).
///
/// # V3 Protocol — Self-Authenticating Payloads (SST)
/// The signature over this digest simultaneously authorizes:
/// 1. the transaction itself (L1 ownership proof),
/// 2. the Layer-2 lock request (L2 lock proof), and
/// 3. the gossip fingerprint (instant-proof ingress gate + SST collision input).
///
/// All fields are bound with length prefixes via
/// [`crate::services::crypto::get_raw_hash_from_slices`], which fixes
/// legacy **AUDIT-01-F03** (unprefixed string concatenation) and makes every
/// field malleability-proof: any bit change in `trap_r`, `trap_s`,
/// `encrypted_timestamp`, `deletable_at` or the privacy-guard commitment
/// invalidates the signature.
pub fn calculate_l2_payload_hash(req: &L2LockRequest) -> [u8; 32] {
    let challenge_ds_tag = if req.is_genesis {
        bs58::encode(req.transaction_hash).into_string()
    } else {
        req.ds_tag.clone().unwrap_or_default()
    };

    // SECURITY (audit_02_11): genesis locks signed the canonical "none"
    // placeholder for the voucher-id field (a genesis lock cannot bind its
    // own derived id without circularity). Spends bind their real hex id.
    let effective_voucher_id = if req.is_genesis {
        TRAP_NONE_PLACEHOLDER
    } else {
        req.layer2_voucher_id.as_str()
    };

    calculate_l2_payload_hash_raw(
        effective_voucher_id,
        &challenge_ds_tag,
        &req.transaction_hash,
        &req.sender_ephemeral_pub,
        req.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        req.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
        req.encrypted_timestamp,
        req.deletable_at.as_deref(),
        privacy_guard_commitment(req.privacy_guard.as_deref()).as_str(),
    )
}

/// Inner logic for hashing the L2 payload (canonical V3 definition).
///
/// Slice order (all length-prefixed):
/// 1. Domain tag `b"HMC_TX_AUTH_V3"`
/// 2. `layer2_voucher_id` (hex string for spends, `"none"` for genesis) —
///    SECURITY (audit_02_11 / HMC-SEC-02-11): binds every lock authorization
///    to ITS voucher container so lock entries cannot be transplanted
///    between vouchers without breaking the signature.
/// 3. `challenge_ds_tag` (`t_id` for genesis, `ds_tag` for spends)
/// 4. `t_id_bytes` (32 bytes)
/// 5. `sender_pub_bytes` (32 bytes)
/// 6. SST commitment shard `trap_r` (Base58, `"none"` for genesis)
/// 7. SST response shard `trap_s` (Base58, `"none"` for genesis)
/// 8. `encrypted_timestamp` little-endian (16 bytes)
/// 9. `deletable_at` (empty slice when `None`)
/// 10. `privacy_guard_commitment` — SECURITY (HMSEC-SA04-08): the canonical
///     commitment ([`privacy_guard_commitment`]) of the transaction's
///     privacy guard (`""` when absent), making guard equivocation produce
///     distinct signatures and attributable evidence.
///
/// Signers and verifiers MUST agree on this exact serialization; it is the
/// single source of truth for L1 chain validation, L2 locks and gossip.
#[allow(clippy::too_many_arguments)]
pub fn calculate_l2_payload_hash_raw(
    layer2_voucher_id: &str,
    challenge_ds_tag: &str,
    t_id_bytes: &[u8; 32],
    sender_pub_bytes: &[u8; 32],
    trap_r_str: &str,
    trap_s_str: &str,
    encrypted_timestamp: u128,
    deletable_at: Option<&str>,
    privacy_guard_commitment: &str,
) -> [u8; 32] {
    crate::services::crypto::get_raw_hash_from_slices(&[
        HMC_TX_AUTH_V3_DOMAIN,
        layer2_voucher_id.as_bytes(),
        challenge_ds_tag.as_bytes(),
        t_id_bytes,
        sender_pub_bytes,
        trap_r_str.as_bytes(),
        trap_s_str.as_bytes(),
        &encrypted_timestamp.to_le_bytes(),
        deletable_at.unwrap_or("").as_bytes(),
        privacy_guard_commitment.as_bytes(),
    ])
}

/// Derives the challenge DS tag for a transaction.
/// For genesis, this is t_id, otherwise the ds_tag from TrapData.
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

/// Extracts the layer2_voucher_id from a voucher (based on the genesis tx).
pub fn extract_layer2_voucher_id(
    voucher: &crate::models::voucher::Voucher,
) -> Result<String, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(crate::Error::Wallet(crate::error::WalletError::MissingTransactions));
    }
    calculate_layer2_voucher_id(&voucher.transactions[0])
}

/// Processes the L2Verdict and determines the subsequent wallet action.
pub fn process_l2_verdict(
    verdict_bytes: &[u8],
    server_pubkey: &[u8; 32],
    local_t_id: &str,       // The local t_id of the requested transaction
    challenge_ds_tag: &str, // The challenge tag used for the query
    expected_ephemeral_pub: Option<&str>, // The expected key according to local history
    expected_voucher_id: &str, // The expected voucher ID
) -> Result<VerdictAction, VoucherCoreError> {
    let envelope: L2ResponseEnvelope = serde_json::from_slice(verdict_bytes).map_err(|e| {
        VoucherCoreError::DeserializationError(format!("Invalid response envelope: {}", e))
    })?;

    // 1. Verify server authenticity
    let server_key = VerifyingKey::from_bytes(server_pubkey)
        .map_err(|_| VoucherCoreError::Validation(crate::error::ValidationError::InvalidServerPublicKey))?;
    let server_sig = Signature::from_bytes(&envelope.server_signature);

    let verdict_serialized = serde_json::to_vec(&envelope.verdict).map_err(|e| {
        VoucherCoreError::DeserializationError(format!(
            "Failed to serialize verdict for verification: {}",
            e
        ))
    })?;

    // Hash verdict for signature verification
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
        return Err(VoucherCoreError::Validation(
            crate::error::ValidationError::ServerSignatureInvalid,
        ));
    }

    let verdict = envelope.verdict;

    match verdict {
        L2Verdict::Verified { lock_entry } => {
            // 0. Verify voucher ID match
            if lock_entry.layer2_voucher_id != expected_voucher_id {
                return Err(VoucherCoreError::Validation(
                    crate::error::ValidationError::VoucherIdMixup {
                        found: lock_entry.layer2_voucher_id.clone(),
                        expected: expected_voucher_id.to_string(),
                    },
                ));
            }

            // 1. Verify L2 signature mathematically (Proof of Truth)
            let ephem_key =
                VerifyingKey::from_bytes(&lock_entry.sender_ephemeral_pub).map_err(|_| {
                    VoucherCoreError::Validation(
                        crate::error::ValidationError::InvalidEphemeralKeyInLockEntry,
                    )
                })?;
            let signature = Signature::from_bytes(&lock_entry.layer2_signature);

            // Reconstruct payload: layer2_voucher_id + challenge_ds_tag + t_id
            // + sender_ephemeral_pub + trap shards (R_i, s_i) +
            // encrypted_timestamp + deletable_at + privacy-guard commitment.
            // SECURITY (audit_02_11): the voucher id is signature-bound, so a
            // lock entry relabeled onto a foreign container fails here.
            // Genesis lock entries signed the canonical "none" placeholder
            // (reliably detectable via the reserved shard pair — HMSEC-SA06-11
            // guarantees that spends can never carry it).
            let entry_is_genesis = lock_entry.trap_r.as_deref() == Some(TRAP_NONE_PLACEHOLDER)
                && lock_entry.trap_s.as_deref() == Some(TRAP_NONE_PLACEHOLDER);
            let effective_entry_voucher_id = if entry_is_genesis {
                TRAP_NONE_PLACEHOLDER
            } else {
                lock_entry.layer2_voucher_id.as_str()
            };
            let payload_hash = calculate_l2_payload_hash_raw(
                effective_entry_voucher_id,
                challenge_ds_tag,
                &lock_entry.t_id,
                &lock_entry.sender_ephemeral_pub,
                lock_entry.trap_r.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
                lock_entry.trap_s.as_deref().unwrap_or(TRAP_NONE_PLACEHOLDER),
                lock_entry.encrypted_timestamp,
                lock_entry.deletable_at.as_deref(),
                privacy_guard_commitment(lock_entry.privacy_guard.as_deref()).as_str(),
            );

            #[cfg(feature = "test-utils")]
            let signature_valid = ephem_key.verify(&payload_hash, &signature).is_ok()
                || crate::is_signature_bypass_active();
            #[cfg(not(feature = "test-utils"))]
            let signature_valid = ephem_key.verify(&payload_hash, &signature).is_ok();

            if !signature_valid {
                return Err(VoucherCoreError::Validation(
                    crate::error::ValidationError::InvalidL2Proof,
                ));
            }

            // 2. Verify that the key in response matches our expected key
            if let Some(expected) = expected_ephemeral_pub {
                let actual_bs58 = bs58::encode(&lock_entry.sender_ephemeral_pub).into_string();
                if actual_bs58 != expected {
                    return Err(VoucherCoreError::Validation(
                        crate::error::ValidationError::ForeignKeyProof {
                            actual: actual_bs58,
                            expected: expected.to_string(),
                        },
                    ));
                }
            }

            // 3. Compare t_id
            let server_t_id = bs58::encode(lock_entry.t_id).into_string();
            if server_t_id == local_t_id {
                Ok(VerdictAction::ConfirmLocal)
            } else {
                // Double-spend detected!
                Ok(VerdictAction::TriggerQuarantine(server_t_id))
            }
        }
        L2Verdict::MissingLocks { sync_point } => {
            // Signal that we need to synchronize
            Ok(VerdictAction::TriggerSync { sync_point })
        }
        L2Verdict::UnknownVoucher => {
            // Signal that voucher is unknown (full upload needed)
            Ok(VerdictAction::TriggerSync {
                sync_point: "genesis".to_string(),
            })
        }
        L2Verdict::Ok { .. } => {
            // Fallback for older implementations
            Ok(VerdictAction::ConfirmLocal)
        }
        L2Verdict::Rejected { reason } => Err(VoucherCoreError::Validation(
            crate::error::ValidationError::L2Rejected { reason },
        )),
    }
}

/// Generates logarithmic locators for state reconciliation.
/// Returns prefixes of ds_tags (10 characters Base58) at exponential intervals.
pub fn generate_locator_prefixes(voucher: &crate::models::voucher::Voucher) -> Vec<String> {
    let mut prefixes = Vec::new();
    let n = voucher.transactions.len();
    if n == 0 {
        return prefixes;
    }

    // We step backward from the current transaction (n-1)
    let mut step = 1;
    let mut i = n - 1;

    while i > 0 {
        if let Some(td) = &voucher.transactions[i].trap_data {
            // Take first 10 characters of the Base58 ds_tag
            prefixes.push(td.ds_tag.chars().take(10).collect());
        }

        if i < step {
            break;
        }
        i -= step;
        step *= 2; // Exponential intervals: 1, 2, 4, 8, 16...
    }

    // Always include the first (genesis) lock (if present and not already included)
    if let Ok(first_tag) = derive_challenge_tag(&voucher.transactions[0]) {
        let first_prefix: String = first_tag.chars().take(10).collect();
        if !prefixes.contains(&first_prefix) {
            prefixes.push(first_prefix);
        }
    }

    prefixes
}
