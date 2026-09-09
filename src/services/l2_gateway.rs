use crate::error::VoucherCoreError;
use crate::models::layer2_api::{L2AuthPayload, L2LockRequest, L2ResponseEnvelope, L2Verdict, QuorumCertificateDto};
use crate::models::voucher::Transaction;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Defines the action that AppService should perform after evaluating the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictAction {
    /// The L2 network confirmed the transaction as valid.
    ConfirmLocal,
    /// Confirmed with final quorum certificate (N >= 20, status == 1).
    ConfirmFinal { certificate: QuorumCertificateDto },
    /// Confirmed with provisional quorum certificate (N < 20 or provisional status).
    ConfirmProvisional { certificate: Option<QuorumCertificateDto> },
    /// A double-spend was detected; the wallet/voucher must be placed in quarantine.
    TriggerQuarantine(String),
    /// Synchronization is required. Contains the sync_point (prefix).
    TriggerSync { sync_point: String },
}

/// Verifies the plausibility of a QuorumCertificate according to order-statistics quorum rules.
/// Returns Ok((is_valid, is_final)).
pub fn verify_quorum_plausibility(
    cert: &QuorumCertificateDto,
    expected_shard_id: u16,
) -> Result<(bool, bool), VoucherCoreError> {
    if cert.shard_id != expected_shard_id {
        return Ok((false, false));
    }

    if cert.active_nodes_count == 0 || cert.signatures.is_empty() {
        return Ok((false, false));
    }

    let (required_q, is_final) = if cert.active_nodes_count < 20 {
        let q = (2 * cert.active_nodes_count) / 3 + 1;
        (q, false)
    } else {
        (14, true)
    };

    if required_q == 0 {
        return Ok((false, false));
    }

    // Derive signer node IDs (u16) and deduplicate
    let mut unique_signers = std::collections::HashSet::new();
    let mut scores = Vec::new();
    for att in &cert.signatures {
        // SECURITY (AUDIT-00-WILDCARD-16): Ensure every attestation binds strictly to cert.lock_id
        if att.lock_id != cert.lock_id {
            return Ok((false, false));
        }

        if unique_signers.insert(att.node_id) {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&att.node_id.to_le_bytes());
            hasher.update(&cert.shard_id.to_le_bytes());
            let hash = hasher.finalize();
            let val = u128::from_be_bytes(hash.as_bytes()[0..16].try_into().unwrap());
            let score = val as f64 / u128::MAX as f64;
            scores.push(score);
        }
    }

    if scores.len() < required_q {
        return Ok((false, false));
    }

    // Sort descending by HRW score
    scores.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

    // Threshold check at q-th best score (index required_q - 1)
    let threshold = (1.0 - (20.0 / cert.active_nodes_count as f64)).max(0.0);
    let q_th_score = scores[required_q - 1];

    let is_valid = q_th_score >= threshold;
    Ok((is_valid, is_final && is_valid))
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

    let t_id = crate::services::crypto::decode_bs58_fixed::<32>(&transaction.t_id, "t_id")?;

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
    let sender_ephemeral_pub =
        crate::services::crypto::decode_bs58_fixed::<32>(sender_ephemeral_pub_str, "sender_ephemeral_pub")?;

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
    let layer2_signature =
        crate::services::crypto::decode_bs58_fixed::<64>(layer2_sig_str, "layer2_signature")?;

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

    let t_id = crate::services::crypto::decode_bs58_fixed::<32>(&transaction.t_id, "t_id")?;

    let sender_pub = transaction
        .sender_ephemeral_pub
        .as_deref()
        .and_then(|s| crate::services::crypto::decode_bs58_fixed::<32>(s, "sender_pub").ok())
        .unwrap_or([0u8; 32]);
    let receiver_hash = transaction
        .receiver_ephemeral_pub_hash
        .as_deref()
        .and_then(|h| crate::services::crypto::decode_bs58_fixed::<32>(h, "receiver_hash").ok());

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

/// Helper to verify that a cert lock_id matches the lock entry's t_id.
/// Accepts case-insensitive hex (with optional 0x prefix) and Base58.
fn matches_lock_id(t_id_bytes: &[u8; 32], cert_lock_id: &str) -> bool {
    let trimmed = cert_lock_id.trim();
    let clean_hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex::encode(t_id_bytes).eq_ignore_ascii_case(clean_hex) {
        return true;
    }
    if bs58::encode(t_id_bytes).into_string() == trimmed {
        return true;
    }
    false
}

/// Verifies that a lock entry is mathematically authentic (Proof of Truth):
/// checks voucher ID, ephemeral key validity, canonical payload signature,
/// and optionally binds the ephemeral public key to the expected key.
fn verify_lock_entry_proof(
    lock_entry: &crate::models::layer2_api::L2LockEntry,
    expected_voucher_id: &str,
    expected_ephemeral_pub: Option<&str>,
    challenge_ds_tag: &str,
) -> Result<(), VoucherCoreError> {
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

    // 2. Verify that the key in response matches our expected key (if required)
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

    Ok(())
}

/// Evaluates any optional QuorumCertificate present on a confirmed lock entry.
fn evaluate_quorum_certificate(
    certificate_opt: Option<QuorumCertificateDto>,
    lock_t_id: &[u8; 32],
    expected_voucher_id: &str,
) -> Result<VerdictAction, VoucherCoreError> {
    if let Some(certificate) = certificate_opt {
        // SECURITY (AUDIT-00-WILDCARD-16): Ensure certificate binds strictly to this lock
        if !matches_lock_id(lock_t_id, &certificate.lock_id) {
            return Err(VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidL2Proof,
            ));
        }

        let expected_shard_id = match hex::decode(expected_voucher_id) {
            Ok(b) if b.len() >= 2 => {
                let id_from_voucher = u16::from_be_bytes([b[0], b[1]]);
                let id_from_lock = u16::from_be_bytes([lock_t_id[0], lock_t_id[1]]);
                if certificate.shard_id == id_from_lock {
                    id_from_lock
                } else {
                    id_from_voucher
                }
            }
            _ => u16::from_be_bytes([lock_t_id[0], lock_t_id[1]]),
        };
        let (is_valid, is_final) = verify_quorum_plausibility(&certificate, expected_shard_id)?;
        if is_valid && is_final && certificate.status == 1 {
            Ok(VerdictAction::ConfirmFinal { certificate })
        } else if is_valid {
            Ok(VerdictAction::ConfirmProvisional {
                certificate: Some(certificate),
            })
        } else {
            Err(VoucherCoreError::Validation(
                crate::error::ValidationError::InvalidL2Proof,
            ))
        }
    } else {
        Ok(VerdictAction::ConfirmLocal)
    }
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
            // Cryptographically verify Proof of Truth and expected ephemeral key
            verify_lock_entry_proof(
                &lock_entry,
                expected_voucher_id,
                expected_ephemeral_pub,
                challenge_ds_tag,
            )?;

            // Compare t_id
            let server_t_id = bs58::encode(lock_entry.t_id).into_string();
            if server_t_id == local_t_id {
                evaluate_quorum_certificate(envelope.quorum_certificate, &lock_entry.t_id, expected_voucher_id)
            } else {
                // Double-spend detected!
                Ok(VerdictAction::TriggerQuarantine(server_t_id))
            }
        }
        L2Verdict::Conflict { existing_lock } => {
            let server_t_id = bs58::encode(existing_lock.t_id).into_string();
            if server_t_id == local_t_id {
                // Idempotent retry / already anchored on server:
                // Verify lock with expected ephemeral key and evaluate any QuorumCertificate
                verify_lock_entry_proof(
                    &existing_lock,
                    expected_voucher_id,
                    expected_ephemeral_pub,
                    challenge_ds_tag,
                )?;
                evaluate_quorum_certificate(envelope.quorum_certificate, &existing_lock.t_id, expected_voucher_id)
            } else {
                // Genuine conflict: verify proof of truth on the competing lock
                // (ephemeral key is verified mathematically without expecting our local key)
                verify_lock_entry_proof(
                    &existing_lock,
                    expected_voucher_id,
                    None,
                    challenge_ds_tag,
                )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::layer2_api::{AttestationDto, L2LockEntry, QuorumCertificateDto};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    fn make_dummy_attestation(node_id: u16, _shard_id: u16, lock_id: &str) -> AttestationDto {
        AttestationDto {
            lock_id: lock_id.to_string(),
            parent_lock: "test_parent_lock".to_string(),
            node_id,
            timestamp: 1_000_000,
            signature: "dummy_sig_hex".to_string(),
        }
    }

    #[test]
    fn test_quorum_certificate_dto_serde() {
        let cert = QuorumCertificateDto {
            lock_id: "lock_123".to_string(),
            shard_id: 42,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: vec![make_dummy_attestation(1, 42, "lock_123"), make_dummy_attestation(2, 42, "lock_123")],
        };

        let json = serde_json::to_string(&cert).expect("serialize cert");
        let deserialized: QuorumCertificateDto = serde_json::from_str(&json).expect("deserialize cert");
        assert_eq!(cert, deserialized);
    }

    #[test]
    fn test_verify_quorum_plausibility_bootstrap_n2() {
        let shard_id = 42u16;
        // N=2 -> required_q = (2*2)/3 + 1 = 2
        let cert_ok = QuorumCertificateDto {
            lock_id: "lock_1".to_string(),
            shard_id,
            status: 0,
            active_nodes_count: 2,
            signer_count: 2,
            signatures: vec![make_dummy_attestation(1, shard_id, "lock_1"), make_dummy_attestation(2, shard_id, "lock_1")],
        };
        let (valid, is_final) = verify_quorum_plausibility(&cert_ok, shard_id).unwrap();
        assert!(valid, "2 of 2 must be valid in bootstrap");
        assert!(!is_final, "N=2 must be provisional");

        // Only 1 signer -> must fail
        let cert_under = QuorumCertificateDto {
            lock_id: "lock_1".to_string(),
            shard_id,
            status: 0,
            active_nodes_count: 2,
            signer_count: 1,
            signatures: vec![make_dummy_attestation(1, shard_id, "lock_1")],
        };
        let (valid_under, _) = verify_quorum_plausibility(&cert_under, shard_id).unwrap();
        assert!(!valid_under, "1 of 2 must fail quorum");

        // Duplicate signer -> deduplicated -> only 1 unique signer -> must fail
        let cert_dup = QuorumCertificateDto {
            lock_id: "lock_1".to_string(),
            shard_id,
            status: 0,
            active_nodes_count: 2,
            signer_count: 2,
            signatures: vec![make_dummy_attestation(1, shard_id, "lock_1"), make_dummy_attestation(1, shard_id, "lock_1")],
        };
        let (valid_dup, _) = verify_quorum_plausibility(&cert_dup, shard_id).unwrap();
        assert!(!valid_dup, "Duplicate signers must not satisfy quorum");
    }

    #[test]
    fn test_verify_quorum_plausibility_boundary_n20() {
        let shard_id = 100u16;
        // Collect 20 distinct node ids
        let nodes: Vec<u16> = (1..=20).collect();

        // 14 signers (exactly meeting required_q for N=20)
        let sigs_14: Vec<AttestationDto> = nodes[0..14]
            .iter()
            .map(|&nid| make_dummy_attestation(nid, shard_id, "lock_20"))
            .collect();
        let cert_14 = QuorumCertificateDto {
            lock_id: "lock_20".to_string(),
            shard_id,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: sigs_14,
        };
        let (valid, is_final) = verify_quorum_plausibility(&cert_14, shard_id).unwrap();
        assert!(valid);
        assert!(is_final, "N=20 with 14 signers must be final");

        // 13 signers (under required_q of 14) -> must fail
        let sigs_13: Vec<AttestationDto> = nodes[0..13]
            .iter()
            .map(|&nid| make_dummy_attestation(nid, shard_id, "lock_20"))
            .collect();
        let cert_13 = QuorumCertificateDto {
            lock_id: "lock_20".to_string(),
            shard_id,
            status: 1,
            active_nodes_count: 20,
            signer_count: 13,
            signatures: sigs_13,
        };
        let (valid_13, _) = verify_quorum_plausibility(&cert_13, shard_id).unwrap();
        assert!(!valid_13, "13 of 20 must fail quorum");

        // Shard mismatch
        let (valid_mismatch, _) = verify_quorum_plausibility(&cert_14, 999).unwrap();
        assert!(!valid_mismatch, "Shard mismatch must return (false, false)");
    }

    #[test]
    fn test_l2_verdict_conflict_handling() {
        let mut rng = rand::thread_rng();
        let server_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let server_pk = server_sk.verifying_key();

        let conflict_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let conflict_pk = conflict_sk.verifying_key();

        let existing_t_id = [0x42u8; 32];
        let challenge_ds_tag = "challenge_tag";
        let voucher_id = "test_voucher_id";

        let payload_hash = calculate_l2_payload_hash_raw(
            TRAP_NONE_PLACEHOLDER,
            challenge_ds_tag,
            &existing_t_id,
            conflict_pk.as_bytes(),
            "none",
            "none",
            0,
            None,
            "",
        );
        let conflict_sig = conflict_sk.sign(&payload_hash);

        let existing_lock = L2LockEntry {
            layer2_voucher_id: voucher_id.to_string(),
            t_id: existing_t_id,
            sender_ephemeral_pub: *conflict_pk.as_bytes(),
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: conflict_sig.to_bytes(),
            trap_r: Some("none".to_string()),
            trap_s: Some("none".to_string()),
            encrypted_timestamp: 0,
            deletable_at: None,
            privacy_guard: None,
        };

        let verdict = L2Verdict::Conflict { existing_lock };
        let verdict_bytes = serde_json::to_vec(&verdict).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&verdict_bytes);
        let sig = server_sk.sign(&hasher.finalize());

        let envelope = L2ResponseEnvelope {
            verdict,
            server_signature: sig.to_bytes(),
            quorum_certificate: None,
        };
        let env_bytes = serde_json::to_vec(&envelope).unwrap();

        let action = process_l2_verdict(
            &env_bytes,
            server_pk.as_bytes(),
            "local_t_id",
            challenge_ds_tag,
            None,
            voucher_id,
        ).expect("process conflict verdict");

        let expected_server_t_id = bs58::encode(existing_t_id).into_string();
        assert_eq!(action, VerdictAction::TriggerQuarantine(expected_server_t_id));
    }

    #[test]
    fn test_l2_verdict_verified_with_quorum_certificate() {
        let mut rng = rand::thread_rng();
        let server_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let server_pk = server_sk.verifying_key();

        let client_sk = ed25519_dalek::SigningKey::generate(&mut rng);
        let client_pk = client_sk.verifying_key();

        let voucher_bytes = [0x55u8; 32];
        let voucher_id = hex::encode(voucher_bytes);
        let shard_id = u16::from_be_bytes([voucher_bytes[0], voucher_bytes[1]]);

        let t_id = [0x33u8; 32];
        let challenge_ds_tag = bs58::encode(t_id).into_string();

        let payload_hash = calculate_l2_payload_hash_raw(
            TRAP_NONE_PLACEHOLDER,
            &challenge_ds_tag,
            &t_id,
            client_pk.as_bytes(),
            TRAP_NONE_PLACEHOLDER,
            TRAP_NONE_PLACEHOLDER,
            0,
            None,
            "",
        );
        let client_sig = client_sk.sign(&payload_hash);

        let lock_entry = L2LockEntry {
            layer2_voucher_id: voucher_id.clone(),
            t_id,
            sender_ephemeral_pub: *client_pk.as_bytes(),
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: client_sig.to_bytes(),
            trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            encrypted_timestamp: 0,
            deletable_at: None,
            privacy_guard: None,
        };

        // 1. Without QuorumCertificate -> ConfirmLocal
        let verdict1 = L2Verdict::Verified { lock_entry: lock_entry.clone() };
        let v1_bytes = serde_json::to_vec(&verdict1).unwrap();
        let mut h1 = Sha256::new();
        h1.update(&v1_bytes);
        let sig1 = server_sk.sign(&h1.finalize());

        let env1 = L2ResponseEnvelope {
            verdict: verdict1,
            server_signature: sig1.to_bytes(),
            quorum_certificate: None,
        };
        let action1 = process_l2_verdict(
            &serde_json::to_vec(&env1).unwrap(),
            server_pk.as_bytes(),
            &bs58::encode(t_id).into_string(),
            &challenge_ds_tag,
            Some(&bs58::encode(client_pk.as_bytes()).into_string()),
            &voucher_id,
        ).unwrap();
        assert_eq!(action1, VerdictAction::ConfirmLocal);

        // 2. With FINAL QuorumCertificate -> ConfirmFinal
        let lock_id_hex = hex::encode(t_id);
        let cert_final = QuorumCertificateDto {
            lock_id: lock_id_hex.clone(),
            shard_id,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: (1..=14).map(|nid| make_dummy_attestation(nid, shard_id, &lock_id_hex)).collect(),
        };
        let env2 = L2ResponseEnvelope {
            verdict: L2Verdict::Verified { lock_entry: lock_entry.clone() },
            server_signature: sig1.to_bytes(),
            quorum_certificate: Some(cert_final.clone()),
        };
        let action2 = process_l2_verdict(
            &serde_json::to_vec(&env2).unwrap(),
            server_pk.as_bytes(),
            &bs58::encode(t_id).into_string(),
            &challenge_ds_tag,
            Some(&bs58::encode(client_pk.as_bytes()).into_string()),
            &voucher_id,
        ).unwrap();
        assert_eq!(action2, VerdictAction::ConfirmFinal { certificate: cert_final });

        // 3. With PROVISIONAL QuorumCertificate -> ConfirmProvisional
        let cert_prov = QuorumCertificateDto {
            lock_id: lock_id_hex.clone(),
            shard_id,
            status: 0,
            active_nodes_count: 2,
            signer_count: 2,
            signatures: vec![
                make_dummy_attestation(1, shard_id, &lock_id_hex),
                make_dummy_attestation(2, shard_id, &lock_id_hex),
            ],
        };
        let env3 = L2ResponseEnvelope {
            verdict: L2Verdict::Verified { lock_entry },
            server_signature: sig1.to_bytes(),
            quorum_certificate: Some(cert_prov.clone()),
        };
        let action3 = process_l2_verdict(
            &serde_json::to_vec(&env3).unwrap(),
            server_pk.as_bytes(),
            &bs58::encode(t_id).into_string(),
            &challenge_ds_tag,
            Some(&bs58::encode(client_pk.as_bytes()).into_string()),
            &voucher_id,
        ).unwrap();
        assert_eq!(action3, VerdictAction::ConfirmProvisional { certificate: Some(cert_prov) });
    }
}
