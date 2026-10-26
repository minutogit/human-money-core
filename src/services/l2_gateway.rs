//! # `src/services/l2_gateway.rs`
//!
//! Stateless business logic for interacting with the Layer-2 Collision Lock Registry (`humoco-node`).
//!
//! ## Protocol Architecture:
//! - **Canonical `HMC_TX_AUTH_V4` Payload Digest:** Length-prefixed domain-separated hash binding:
//!   domain, `layer2_voucher_id`, `challenge_ds_tag`, `t_id_bytes`, `sender_pub_bytes`,
//!   `trap_r`, `trap_s`, `encrypted_timestamp` (16 bytes LE), `created_at_ms` (8 bytes LE),
//!   `deletable_at`, and `privacy_guard_commitment`.
//! - **5-minute Time Bucket Allocation:** Layer-2 nodes assign incoming locks to discrete 5-minute buckets
//!   via `floor(created_at_ms / 300_000)` for BFT shard synchronization and immutable Merkle root sealing.
//! - **30-second Clock-Drift Window:** Nodes reject any lock request whose `created_at_ms` deviates
//!   from network time by more than 30 seconds (`|created_at_ms - net_time_ms| <= 30_000`).
//!
//! ## Gateway Retry & Multi-Homing Invariant:
//! When submitting lock requests across distributed gateway nodes (multi-homing) or retrying
//! upon network timeouts (typically 500–1500 ms):
//! - Clients **MUST resend the exact, identical byte payload** (`created_at_ms`, signatures, etc.).
//! - Clients **MUST NEVER** generate a fresh timestamp or re-sign on retry.
//! - Rationale:
//!   1. **Deterministic Bucket Allocation:** Regenerating timestamps could cross a 5-minute boundary,
//!      causing diverging nodes to assign the lock to different Merkle epoch trees.
//!   2. **Rule 3 Hot-Path Idempotency:** The Layer-2 registry recognizes identical payloads by `t_id`
//!      and immediately responds with `200 OK (Verified)` without re-running consensus or raising false conflicts.
//!   3. **Clock Drift Preservation:** Quick retries remain well within the 30-second drift acceptance window.

use crate::error::VoucherCoreError;
use crate::models::layer2_api::{
    L2AuthPayload, L2ChainLockRequest, L2LockEntry, L2LockRequest, L2ResponseEnvelope,
    L2StatusQuery, L2Verdict, QuorumCertificateDto, QuorumProof,
};
use crate::models::profile::UserIdentity;
use crate::models::voucher::Transaction;

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use humoco_proto::verify::verify_quorum_proof;

/// Defines the synchronization verdict of a state anchor against Layer 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorSyncVerdict {
    /// L2 tip is free/unspent and matches local state anchor.
    Synchronized,
    /// Local is ahead of L2 due to offline transactions.
    PendingLeapLock { sync_point: String },
    /// L2 has a lock on local tip -> local state is behind (rollback detected).
    RollbackDetected {
        remote_t_id: [u8; 32],
        lock_entry: L2LockEntry,
    },
    /// Conflicting lock entry exists on the challenged tag.
    ForkConflict { foreign_entry: L2LockEntry },
    /// Unknown voucher / initial state -> Genesis lock required.
    GenesisRequired,
}

/// Defines the action that AppService should perform after evaluating the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictAction {
    /// A matching lookup/registration was found; this is not payment clearance.
    ConfirmLocal,
    /// Mathematically verified FINAL original approval; not a fresh live-state proof.
    ConfirmFinal { certificate: QuorumCertificateDto },
    /// Confirmed with provisional quorum certificate (N < 20 or provisional status).
    ConfirmProvisional {
        certificate: Option<QuorumCertificateDto>,
    },
    /// A double-spend was detected; the wallet/voucher must be placed in quarantine.
    TriggerQuarantine(String),
    /// Synchronization is required. Contains the sync_point (prefix).
    TriggerSync { sync_point: String },
}

/// Evaluates whether an HTTP status code indicates a successful Layer-2 lock response.
///
/// Both `201 Created` (first-time registration) and `200 OK` (idempotent replay under Rule 3)
/// are successful transport/write outcomes, not independently verified payment clearance.
pub fn is_l2_success_http_status(status_code: u16) -> bool {
    matches!(status_code, 200 | 201)
}

/// Zero-trust 14/20-BFT receipt verification for PoS checkout receipts.
///
/// In accordance with zero-trust doctrine and DEC-080 / DEC-084:
/// PoS terminals MUST verify the full 14/20 cryptographic proof mathematically before payment completion.
pub fn verify_checkout_receipt(
    proof: &humoco_proto::types::QuorumProof,
    expected_digest: &[u8; 32],
    eligible_committee: &[[u8; 32]],
    required_quorum: usize, // Typically 14 for FINAL
) -> Result<(), VoucherCoreError> {
    verify_quorum_proof(proof, expected_digest, eligible_committee, required_quorum).map_err(
        |err| {
            VoucherCoreError::Validation(crate::error::ValidationError::SecurityViolation(format!(
                "L2 Quorum proof failed: {}",
                err
            )))
        },
    )
}

/// Verifies a QuorumCertificateDto receipt by converting it to canonical QuorumProof and running 14/20 verification.
pub fn verify_checkout_receipt_certificate(
    cert: &QuorumCertificateDto,
    expected_digest: &[u8; 32],
    eligible_committee: &[[u8; 32]],
    required_quorum: usize,
) -> Result<(), VoucherCoreError> {
    let proof = QuorumProof::try_from(cert).map_err(|err| {
        VoucherCoreError::Validation(crate::error::ValidationError::SecurityViolation(format!(
            "Invalid QuorumCertificateDto for BFT proof: {}",
            err
        )))
    })?;
    verify_checkout_receipt(&proof, expected_digest, eligible_committee, required_quorum)
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
///
/// # Gateway Retry & Multi-Homing Invariant
/// The returned [`L2LockRequest`] binds `created_at_ms` parsed from `transaction.t_time`.
/// Callers MUST reuse the exact same serialized byte payload across retries or fallback
/// gateway nodes. Callers must NEVER regenerate timestamps or re-sign on retry:
/// 1. `created_at_ms` deterministically maps the lock to a 5-minute bucket (`floor(created_at_ms / 300_000)`).
/// 2. Gateways recognize repeated requests by `transaction_hash` (`t_id`) and return `200 OK (Verified)`
///    under Rule 3 hot-path idempotency.
/// 3. Retrying the identical payload preserves the 30-second clock-drift window across quick retries.
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
    let sender_ephemeral_pub_str =
        transaction.sender_ephemeral_pub.as_deref().ok_or_else(|| {
            crate::Error::Wallet(crate::error::WalletError::MissingSenderEphemeralPub)
        })?;
    let sender_ephemeral_pub = crate::services::crypto::decode_bs58_fixed::<32>(
        sender_ephemeral_pub_str,
        "sender_ephemeral_pub",
    )?;

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
    let layer2_sig_str = transaction
        .layer2_signature
        .as_deref()
        .ok_or_else(|| crate::Error::Wallet(crate::error::WalletError::MissingLayer2Signature))?;
    let layer2_signature =
        crate::services::crypto::decode_bs58_fixed::<64>(layer2_sig_str, "layer2_signature")?;

    // V4 Protocol (SST): bind the trap shards and the encrypted timestamp into
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
    let created_at_ms = crate::services::utils::parse_timestamp_ms(&transaction.t_time)?;

    Ok(L2LockRequest {
        causal_output: None,
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
        created_at_ms,
        deletable_at: if is_genesis {
            transaction.deletable_at.clone()
        } else {
            None
        },
        // SECURITY (HMSEC-SA04-08): transport the guard so the L2 server can
        // recompute its canonical commitment and verify the V4 digest of
        // guarded spends. Genesis / public-mode spends carry None.
        privacy_guard: transaction.privacy_guard.clone(),
    })
}

/// Domain-separation tag for the V4 transaction-authentication digest.
///
/// The digest simultaneously serves as:
/// - **L1 ownership proof** (chain validation of `layer2_signature`),
/// - **L2 lock proof** (server-side verification of lock requests), and
/// - **Gossip proof** (self-authenticating fingerprints / instant proofs).
///
/// The digest authenticates the SST shards, guard commitment, timestamps, and
/// voucher/input context with the revealed ephemeral input key.
pub const HMC_TX_AUTH_V4_DOMAIN: &[u8] = b"HMC_TX_AUTH_V4";

/// Canonical placeholder for absent trap components (genesis transactions).
pub const TRAP_NONE_PLACEHOLDER: &str = "none";

/// Calculates the layer2_voucher_id from a genesis transaction.
pub fn calculate_layer2_voucher_id(transaction: &Transaction) -> Result<String, VoucherCoreError> {
    if transaction.t_type != "init" {
        return Err(crate::Error::Wallet(
            crate::error::WalletError::OnlyInitTransactionsAllowed,
        ));
    }

    let t_id = crate::services::crypto::decode_bs58_fixed::<32>(&transaction.t_id, "t_id")?;

    let sender_pub = match &transaction.sender_ephemeral_pub {
        Some(s) => crate::services::crypto::decode_bs58_fixed::<32>(s, "sender_pub")?,
        None => {
            return Err(crate::Error::Validation(
                crate::error::ValidationError::InvalidTransaction(
                    "Missing sender_ephemeral_pub in init transaction".to_string(),
                ),
            ));
        }
    };
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
/// `privacy_guard` that is bound into the V4 payload digest.
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
        Some(guard) if !guard.is_empty() => crate::services::crypto::get_hash(guard.as_bytes()),
        _ => String::new(),
    }
}

/// Generates a deterministic, domain-separated digest of the L2 payload for
/// signature verification (**V4 protocol**, digest `HMC_TX_AUTH_V4`).
///
/// # V4 Protocol — Self-Authenticating Payloads (SST)
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
        req.created_at_ms,
        req.deletable_at.as_deref(),
        privacy_guard_commitment(req.privacy_guard.as_deref()).as_str(),
    )
}

/// Inner logic for hashing the L2 payload (canonical V4 definition).
///
/// Slice order (all length-prefixed):
/// 1. Domain tag `b"HMC_TX_AUTH_V4"`
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
/// 9. `created_at_ms` little-endian (8 bytes) — Canonical Position (matching humoco-node)
/// 10. `deletable_at` (empty slice when `None`)
/// 11. `privacy_guard_commitment` — SECURITY (HMSEC-SA04-08): the canonical
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
    created_at_ms: u64,
    deletable_at: Option<&str>,
    privacy_guard_commitment: &str,
) -> [u8; 32] {
    crate::services::crypto::get_raw_hash_from_slices(&[
        HMC_TX_AUTH_V4_DOMAIN,
        layer2_voucher_id.as_bytes(),
        challenge_ds_tag.as_bytes(),
        t_id_bytes,
        sender_pub_bytes,
        trap_r_str.as_bytes(),
        trap_s_str.as_bytes(),
        &encrypted_timestamp.to_le_bytes(),
        &created_at_ms.to_le_bytes(),
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
        return Err(crate::Error::Wallet(
            crate::error::WalletError::MissingTransactions,
        ));
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
pub fn verify_lock_entry_proof(
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
    let ephem_key = VerifyingKey::from_bytes(&lock_entry.sender_ephemeral_pub).map_err(|_| {
        VoucherCoreError::Validation(crate::error::ValidationError::InvalidEphemeralKeyInLockEntry)
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
        lock_entry
            .trap_r
            .as_deref()
            .unwrap_or(TRAP_NONE_PLACEHOLDER),
        lock_entry
            .trap_s
            .as_deref()
            .unwrap_or(TRAP_NONE_PLACEHOLDER),
        lock_entry.encrypted_timestamp,
        lock_entry.created_at_ms,
        lock_entry.deletable_at.as_deref(),
        privacy_guard_commitment(lock_entry.privacy_guard.as_deref()).as_str(),
    );

    #[cfg(feature = "test-utils")]
    let signature_valid =
        ephem_key.verify(&payload_hash, &signature).is_ok() || crate::is_signature_bypass_active();
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

/// Recipient-established original write-committee context, never sourced from the response itself.
#[derive(Clone, Debug)]
pub struct CheckoutAuthority {
    /// Network domain: zero mainnet, one testnet.
    pub network: u8,
    /// Exact voucher shard.
    pub shard_id: u16,
    /// Expected predecessor/output hash.
    pub parent_lock: [u8; 32],
    /// Expected successor transaction hash.
    pub child_lock: [u8; 32],
    /// Independently established frozen committee in canonical order.
    pub committee: Vec<[u8; 32]>,
}

fn evaluate_quorum_certificate(
    certificate_opt: Option<QuorumCertificateDto>,
    lock_t_id: &[u8; 32],
    _expected_voucher_id: &str,
    authority: Option<&CheckoutAuthority>,
) -> Result<VerdictAction, VoucherCoreError> {
    let Some(certificate) = certificate_opt else {
        return Ok(VerdictAction::ConfirmLocal);
    };
    let invalid = || VoucherCoreError::Validation(crate::error::ValidationError::InvalidL2Proof);
    let authority = authority.ok_or_else(invalid)?;
    if &authority.child_lock != lock_t_id
        || !matches_lock_id(lock_t_id, &certificate.lock_id)
        || certificate.shard_id != authority.shard_id
        || authority.committee.is_empty()
        || authority.committee.len() > 20
        || certificate.signatures.len() > authority.committee.len()
    {
        return Err(invalid());
    }
    let distinct: std::collections::HashSet<_> = authority.committee.iter().collect();
    if distinct.len() != authority.committee.len() {
        return Err(invalid());
    }
    let final_mode = authority.committee.len() == 20;
    if certificate.status > 1 || (certificate.status == 1 && !final_mode) {
        return Err(invalid());
    }
    for att in &certificate.signatures {
        if att.lock_id != certificate.lock_id
            || att.shard_id != authority.shard_id
            || hex::decode(&att.parent_lock).ok().as_deref()
                != Some(authority.parent_lock.as_slice())
        {
            return Err(invalid());
        }
    }
    let digest = humoco_proto::live::original_approval_digest(
        authority.network,
        authority.shard_id,
        certificate.status,
        &authority.parent_lock,
        &authority.child_lock,
    )
    .map_err(|_| invalid())?;
    let threshold = if final_mode {
        14
    } else {
        (2 * authority.committee.len()) / 3 + 1
    };
    verify_checkout_receipt_certificate(&certificate, &digest, &authority.committee, threshold)?;
    if final_mode && certificate.status == 1 {
        Ok(VerdictAction::ConfirmFinal { certificate })
    } else {
        Ok(VerdictAction::ConfirmProvisional {
            certificate: Some(certificate),
        })
    }
}

/// Verifies ephemeral current state against the recipient's independently justified exact challenge/context.
pub fn verify_current_checkout(
    proof: &humoco_proto::live::LiveStateProof,
    expected: &humoco_proto::live::LiveStateContext,
) -> Result<(), VoucherCoreError> {
    humoco_proto::live::verify_live_state_proof(proof, expected)
        .map_err(|_| VoucherCoreError::Validation(crate::error::ValidationError::InvalidL2Proof))
}

/// Processes the L2Verdict and determines the subsequent wallet action.
/// Processes legacy lookup responses without treating response-supplied quorum metadata as authority.
pub fn process_l2_verdict(
    verdict_bytes: &[u8],
    server_pubkey: &[u8; 32],
    local_t_id: &str,
    challenge_ds_tag: &str,
    expected_ephemeral_pub: Option<&str>,
    expected_voucher_id: &str,
) -> Result<VerdictAction, VoucherCoreError> {
    process_l2_verdict_internal(
        verdict_bytes,
        server_pubkey,
        local_t_id,
        challenge_ds_tag,
        expected_ephemeral_pub,
        expected_voucher_id,
        None,
    )
}

/// Processes original write receipts with independently established committee authority and real signatures.
pub fn process_l2_verdict_with_authority(
    verdict_bytes: &[u8],
    server_pubkey: &[u8; 32],
    local_t_id: &str,
    challenge_ds_tag: &str,
    expected_ephemeral_pub: Option<&str>,
    expected_voucher_id: &str,
    authority: &CheckoutAuthority,
) -> Result<VerdictAction, VoucherCoreError> {
    process_l2_verdict_internal(
        verdict_bytes,
        server_pubkey,
        local_t_id,
        challenge_ds_tag,
        expected_ephemeral_pub,
        expected_voucher_id,
        Some(authority),
    )
}

fn process_l2_verdict_internal(
    verdict_bytes: &[u8],
    server_pubkey: &[u8; 32],
    local_t_id: &str,       // The local t_id of the requested transaction
    challenge_ds_tag: &str, // The challenge tag used for the query
    expected_ephemeral_pub: Option<&str>, // The expected key according to local history
    expected_voucher_id: &str, // The expected voucher ID
    authority: Option<&CheckoutAuthority>,
) -> Result<VerdictAction, VoucherCoreError> {
    let envelope: L2ResponseEnvelope = serde_json::from_slice(verdict_bytes).map_err(|e| {
        VoucherCoreError::DeserializationError(format!("Invalid response envelope: {}", e))
    })?;

    // 1. Verify server authenticity
    let server_key = VerifyingKey::from_bytes(server_pubkey).map_err(|_| {
        VoucherCoreError::Validation(crate::error::ValidationError::InvalidServerPublicKey)
    })?;
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
        L2Verdict::Confirmed { proof } => {
            let local_t_id_bytes =
                crate::services::crypto::decode_bs58_fixed::<32>(local_t_id, "local_t_id")
                    .unwrap_or([0u8; 32]);
            let cert = envelope
                .quorum_certificate
                .unwrap_or_else(|| QuorumCertificateDto::from(proof.clone()));
            evaluate_quorum_certificate(
                Some(cert),
                &local_t_id_bytes,
                expected_voucher_id,
                authority,
            )
        }
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
                evaluate_quorum_certificate(
                    envelope.quorum_certificate,
                    &lock_entry.t_id,
                    expected_voucher_id,
                    authority,
                )
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
                evaluate_quorum_certificate(
                    envelope.quorum_certificate,
                    &existing_lock.t_id,
                    expected_voucher_id,
                    authority,
                )
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

// --- State Anchor (Virtual Voucher) Gateway Operations ---

/// Builds an L2LockRequest for the genesis anchor of a wallet state anchor.
pub fn build_anchor_genesis_lock(
    identity: &UserIdentity,
    epoch: u64,
    state_hash: &[u8; 32],
    deletable_at: Option<String>,
) -> Result<L2LockRequest, VoucherCoreError> {
    let anchor_id = crate::models::seal::derive_l2_anchor_id(identity, epoch);
    let (step_key, step_pub) =
        crate::models::seal::derive_anchor_step_key(&identity.signing_key, epoch, 0);
    let step_pub_bytes = step_pub.to_bytes();
    let state_hash_bs58 = bs58::encode(state_hash).into_string();

    let del = deletable_at.unwrap_or_else(|| {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        (now_ms + 2 * 365 * 24 * 3600 * 1000).to_string()
    });

    let created_at_ms = crate::services::utils::current_unix_timestamp_ms();

    let payload_hash = calculate_l2_payload_hash_raw(
        TRAP_NONE_PLACEHOLDER,
        &state_hash_bs58,
        state_hash,
        &step_pub_bytes,
        TRAP_NONE_PLACEHOLDER,
        TRAP_NONE_PLACEHOLDER,
        0,
        created_at_ms,
        Some(&del),
        "",
    );
    let sig = step_key.sign(&payload_hash);

    Ok(L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: step_pub_bytes,
            auth_signature: None,
        },
        layer2_voucher_id: anchor_id,
        ds_tag: None,
        transaction_hash: *state_hash,
        is_genesis: true,
        sender_ephemeral_pub: step_pub_bytes,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some(TRAP_NONE_PLACEHOLDER.into()),
        trap_s: Some(TRAP_NONE_PLACEHOLDER.into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at: Some(del),
        privacy_guard: None,
    })
}

/// Builds an L2LockRequest for a fast-forward leap-lock transition from an unspent L2 tag to a target state hash.
pub fn build_anchor_leap_lock(
    identity: &UserIdentity,
    epoch: u64,
    current_tx_nonce: u64,
    ds_tag: &str,
    target_state_hash: &[u8; 32],
) -> Result<L2LockRequest, VoucherCoreError> {
    let anchor_id = crate::models::seal::derive_l2_anchor_id(identity, epoch);
    let (step_key, step_pub) =
        crate::models::seal::derive_anchor_step_key(&identity.signing_key, epoch, current_tx_nonce);
    let step_pub_bytes = step_pub.to_bytes();
    let created_at_ms = crate::services::utils::current_unix_timestamp_ms();

    let payload_hash = calculate_l2_payload_hash_raw(
        &anchor_id,
        ds_tag,
        target_state_hash,
        &step_pub_bytes,
        TRAP_NONE_PLACEHOLDER,
        TRAP_NONE_PLACEHOLDER,
        0,
        created_at_ms,
        None,
        "",
    );
    let sig = step_key.sign(&payload_hash);

    Ok(L2LockRequest {
        causal_output: None,
        auth: L2AuthPayload {
            ephemeral_pubkey: step_pub_bytes,
            auth_signature: None,
        },
        layer2_voucher_id: anchor_id,
        ds_tag: Some(ds_tag.to_string()),
        transaction_hash: *target_state_hash,
        is_genesis: false,
        sender_ephemeral_pub: step_pub_bytes,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: sig.to_bytes(),
        trap_r: Some(TRAP_NONE_PLACEHOLDER.into()),
        trap_s: Some(TRAP_NONE_PLACEHOLDER.into()),
        encrypted_timestamp: 0,
        created_at_ms,
        deletable_at: None,
        privacy_guard: None,
    })
}

/// Builds an L2StatusQuery for state anchor synchronization.
pub fn build_anchor_status_query(
    identity: &UserIdentity,
    epoch: u64,
    tx_nonce: u64,
    challenge_ds_tag: &str,
    locator_prefixes: Vec<String>,
    read_quorum: u8,
) -> Result<L2StatusQuery, VoucherCoreError> {
    let anchor_id = crate::models::seal::derive_l2_anchor_id(identity, epoch);
    let (_sk, pk) =
        crate::models::seal::derive_anchor_step_key(&identity.signing_key, epoch, tx_nonce);

    Ok(L2StatusQuery {
        auth: L2AuthPayload {
            ephemeral_pubkey: pk.to_bytes(),
            auth_signature: None,
        },
        layer2_voucher_id: anchor_id,
        challenge_ds_tag: challenge_ds_tag.to_string(),
        locator_prefixes,
        read_quorum,
    })
}

/// Evaluates a single L2Verdict response against the local wallet state.
pub fn evaluate_anchor_verdict(
    verdict: &L2Verdict,
    local_t_id: &[u8; 32],
    local_tag: &str,
) -> AnchorSyncVerdict {
    match verdict {
        L2Verdict::Confirmed { .. } => AnchorSyncVerdict::Synchronized,
        L2Verdict::Verified { lock_entry } => {
            if &lock_entry.t_id == local_t_id {
                AnchorSyncVerdict::Synchronized
            } else {
                AnchorSyncVerdict::RollbackDetected {
                    remote_t_id: lock_entry.t_id,
                    lock_entry: lock_entry.clone(),
                }
            }
        }
        L2Verdict::Conflict { existing_lock } => {
            if &existing_lock.t_id == local_t_id {
                AnchorSyncVerdict::Synchronized
            } else {
                AnchorSyncVerdict::ForkConflict {
                    foreign_entry: existing_lock.clone(),
                }
            }
        }
        L2Verdict::MissingLocks { sync_point } => {
            if sync_point == local_tag {
                AnchorSyncVerdict::Synchronized
            } else {
                AnchorSyncVerdict::PendingLeapLock {
                    sync_point: sync_point.clone(),
                }
            }
        }
        L2Verdict::UnknownVoucher => AnchorSyncVerdict::GenesisRequired,
        L2Verdict::Ok { .. } => AnchorSyncVerdict::Synchronized,
        L2Verdict::Rejected { .. } => AnchorSyncVerdict::GenesisRequired,
    }
}

/// Calculates the fault-tolerant read quorum based on shard node count $N$.
pub fn calculate_read_quorum(total_nodes: usize) -> u8 {
    match total_nodes {
        0 | 1 => 1,
        2 | 3 => 2,
        n => (n / 2 + 1) as u8,
    }
}

/// Evaluates multi-node responses with CFT majority-quorum rules and quorum-gated rollback protection.
pub fn evaluate_multi_node_anchor_verdicts(
    verdicts: &[L2Verdict],
    local_t_id: &[u8; 32],
    local_tag: &str,
    total_nodes: usize,
) -> AnchorSyncVerdict {
    let required_q = calculate_read_quorum(total_nodes) as usize;
    let mut syncd_count = 0;
    let mut leap_count = 0;
    let mut last_leap_point = String::new();
    let mut unknown_count = 0;
    let mut rollback_count = 0;
    let mut fork_count = 0;
    let mut first_rollback: Option<AnchorSyncVerdict> = None;
    let mut first_fork: Option<AnchorSyncVerdict> = None;

    for v in verdicts {
        match evaluate_anchor_verdict(v, local_t_id, local_tag) {
            AnchorSyncVerdict::Synchronized => syncd_count += 1,
            AnchorSyncVerdict::PendingLeapLock { sync_point } => {
                leap_count += 1;
                last_leap_point = sync_point;
            }
            AnchorSyncVerdict::GenesisRequired => unknown_count += 1,
            AnchorSyncVerdict::RollbackDetected {
                remote_t_id,
                lock_entry,
            } => {
                rollback_count += 1;
                if first_rollback.is_none() {
                    first_rollback = Some(AnchorSyncVerdict::RollbackDetected {
                        remote_t_id,
                        lock_entry: lock_entry.clone(),
                    });
                }
            }
            AnchorSyncVerdict::ForkConflict { foreign_entry } => {
                fork_count += 1;
                if first_fork.is_none() {
                    first_fork = Some(AnchorSyncVerdict::ForkConflict {
                        foreign_entry: foreign_entry.clone(),
                    });
                }
            }
        }
    }

    if rollback_count >= required_q {
        return first_rollback.unwrap();
    }
    if fork_count >= required_q {
        return first_fork.unwrap();
    }

    if syncd_count >= required_q {
        AnchorSyncVerdict::Synchronized
    } else if leap_count >= required_q {
        AnchorSyncVerdict::PendingLeapLock {
            sync_point: last_leap_point,
        }
    } else if unknown_count >= required_q {
        AnchorSyncVerdict::GenesisRequired
    } else if let Some(first) = verdicts.first() {
        evaluate_anchor_verdict(first, local_t_id, local_tag)
    } else {
        AnchorSyncVerdict::GenesisRequired
    }
}

/// Determines whether a voucher can be skipped when creating Layer 2 spend locks.
///
/// # Architectural Invariant
/// A freshly created voucher that only has its initial (`init`) transaction (`transactions.len() <= 1`)
/// has never circulated or undergone spend operations. Such vouchers have no outgoing spend locks
/// that must be registered on Layer 2 and can safely be skipped when constructing outgoing
/// spend lock requests or synchronizing spend history.
pub fn can_skip_l2_spend_lock(voucher: &crate::models::voucher::Voucher) -> bool {
    voucher.transactions.len() <= 1
}

/// Builds an ordered, prefix-preserving `L2ChainLockRequest`. Genesis is only
/// a root proof and never occupies a collision slot.
///
/// - If `sync_point` is `None` or `"genesis"` the chain starts at index 0
///   (root proof), included if the voucher is not yet anchored on L2.
/// - Otherwise all transactions strictly *after* the transaction identified by
///   `sync_point` up to and including the transaction referenced by
///   `target_spend_req` are collected.
///
/// `sync_point` may be a full `t_id`, a full `ds_tag`, or a 10-character
/// prefix (as emitted by [`L2Verdict::MissingLocks`]); it is resolved in that
/// order. `target_spend_req` itself is reused verbatim as the final chain
/// element so callers can preserve their pre-signed payload; preceding elements
/// are freshly derived via [`generate_lock_request`].
pub fn build_voucher_lock_chain(
    voucher: &crate::models::voucher::Voucher,
    sync_point: Option<&str>,
    target_spend_req: L2LockRequest,
) -> Result<L2ChainLockRequest, VoucherCoreError> {
    build_voucher_lock_chain_with_outputs(
        voucher,
        sync_point,
        target_spend_req,
        &Default::default(),
    )
}

/// Attach original author sidecars without re-signing any L1 transaction. A
/// legacy history lacking these proofs cannot fabricate predecessor authority.
pub fn build_voucher_lock_chain_with_outputs(
    voucher: &crate::models::voucher::Voucher,
    sync_point: Option<&str>,
    target_spend_req: L2LockRequest,
    outputs: &std::collections::BTreeMap<String, humoco_proto::causal::CausalOutputProof>,
) -> Result<L2ChainLockRequest, VoucherCoreError> {
    if voucher.transactions.is_empty() {
        return Err(crate::Error::Wallet(
            crate::error::WalletError::MissingTransactions,
        ));
    }

    let expected_voucher_id = extract_layer2_voucher_id(voucher)?;

    // Locate the target transaction index by matching transaction_hash.
    let target_idx = voucher
        .transactions
        .iter()
        .position(|tx| {
            crate::services::crypto::decode_bs58_fixed::<32>(&tx.t_id, "t_id")
                .map(|b| b == target_spend_req.transaction_hash)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            VoucherCoreError::Validation(crate::error::ValidationError::InvalidTransaction(
                "target transaction not found in voucher".to_string(),
            ))
        })?;

    let start_idx = match sync_point {
        None => 0,
        Some("genesis") => 0,
        Some(sp) => {
            let sync_idx = voucher
                .transactions
                .iter()
                .rposition(|tx| {
                    tx.t_id == sp || tx.trap_data.as_ref().is_some_and(|td| td.ds_tag == sp)
                })
                .or_else(|| {
                    voucher.transactions.iter().rposition(|tx| {
                        tx.t_id.starts_with(sp)
                            || tx
                                .trap_data
                                .as_ref()
                                .is_some_and(|td| td.ds_tag.starts_with(sp))
                    })
                });
            match sync_idx {
                Some(idx) => idx + 1,
                None => {
                    return Err(VoucherCoreError::Validation(
                        crate::error::ValidationError::InvalidTransaction(format!(
                            "sync_point '{}' not found in voucher chain",
                            sp
                        )),
                    ));
                }
            }
        }
    };

    if start_idx > target_idx {
        return Err(VoucherCoreError::Validation(
            crate::error::ValidationError::InvalidTransaction(format!(
                "sync_point is beyond target transaction (start {} > target {})",
                start_idx, target_idx
            )),
        ));
    }

    let mut chain = Vec::with_capacity(target_idx - start_idx + 1);
    for idx in start_idx..=target_idx {
        if idx == target_idx {
            chain.push(target_spend_req.clone());
        } else {
            let tx = &voucher.transactions[idx];
            let sender_str = tx.sender_ephemeral_pub.as_deref().ok_or_else(|| {
                crate::Error::Wallet(crate::error::WalletError::MissingSenderEphemeralPub)
            })?;
            let sender_bytes = crate::services::crypto::decode_bs58_fixed::<32>(
                sender_str,
                "sender_ephemeral_pub",
            )?;
            let mut req = generate_lock_request(&expected_voucher_id, tx, &sender_bytes)?;
            req.causal_output = outputs.get(&tx.t_id).cloned();
            if let Some(proof) = &req.causal_output {
                crate::services::l2_causality::validate_output_proof(voucher, tx, proof)?;
            }
            chain.push(req);
        }
    }

    Ok(L2ChainLockRequest {
        auth: target_spend_req.auth.clone(),
        layer2_voucher_id: expected_voucher_id,
        chain,
    })
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
            node_pubkey: String::new(),
            timestamp: 1_000_000,
            signature: "dummy_sig_hex".to_string(),
            shard_id: _shard_id,
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
            signatures: vec![
                make_dummy_attestation(1, 42, "lock_123"),
                make_dummy_attestation(2, 42, "lock_123"),
            ],
        };

        let json = serde_json::to_string(&cert).expect("serialize cert");
        let deserialized: QuorumCertificateDto =
            serde_json::from_str(&json).expect("deserialize cert");
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
            signatures: vec![
                make_dummy_attestation(1, shard_id, "lock_1"),
                make_dummy_attestation(2, shard_id, "lock_1"),
            ],
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
            signatures: vec![
                make_dummy_attestation(1, shard_id, "lock_1"),
                make_dummy_attestation(1, shard_id, "lock_1"),
            ],
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
            0,
            None,
            "",
        );
        let conflict_sig = conflict_sk.sign(&payload_hash);

        let existing_lock = L2LockEntry {
            causal_output: None,
            layer2_voucher_id: voucher_id.to_string(),
            t_id: existing_t_id,
            sender_ephemeral_pub: *conflict_pk.as_bytes(),
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: conflict_sig.to_bytes(),
            trap_r: Some("none".to_string()),
            trap_s: Some("none".to_string()),
            encrypted_timestamp: 0,
            created_at_ms: 0,
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
        )
        .expect("process conflict verdict");

        let expected_server_t_id = bs58::encode(existing_t_id).into_string();
        assert_eq!(
            action,
            VerdictAction::TriggerQuarantine(expected_server_t_id)
        );
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
            0,
            None,
            "",
        );
        let client_sig = client_sk.sign(&payload_hash);

        let lock_entry = L2LockEntry {
            causal_output: None,
            layer2_voucher_id: voucher_id.clone(),
            t_id,
            sender_ephemeral_pub: *client_pk.as_bytes(),
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: client_sig.to_bytes(),
            trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            encrypted_timestamp: 0,
            created_at_ms: 0,
            deletable_at: None,
            privacy_guard: None,
        };

        // 1. Without QuorumCertificate -> ConfirmLocal
        let verdict1 = L2Verdict::Verified {
            lock_entry: lock_entry.clone(),
        };
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
        )
        .unwrap();
        assert_eq!(action1, VerdictAction::ConfirmLocal);

        // 2. Claimed FINAL with dummy signatures and no independent authority is rejected.
        let lock_id_hex = hex::encode(t_id);
        let cert_final = QuorumCertificateDto {
            lock_id: lock_id_hex.clone(),
            shard_id,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: (1..=14)
                .map(|nid| make_dummy_attestation(nid, shard_id, &lock_id_hex))
                .collect(),
        };
        let env2 = L2ResponseEnvelope {
            verdict: L2Verdict::Verified {
                lock_entry: lock_entry.clone(),
            },
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
        );
        assert!(action2.is_err());

        // 3. Claimed PROVISIONAL with dummy signatures is also rejected.
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
        );
        assert!(action3.is_err());
    }

    #[test]
    fn test_l2_chain_lock_request_serde() {
        use crate::models::layer2_api::{L2AuthPayload, L2ChainLockRequest, L2LockRequest};
        let mut rng = rand::thread_rng();
        let sk1 = ed25519_dalek::SigningKey::generate(&mut rng);
        let pk1 = sk1.verifying_key().to_bytes();
        let sk2 = ed25519_dalek::SigningKey::generate(&mut rng);
        let pk2 = sk2.verifying_key().to_bytes();

        let auth_top = L2AuthPayload {
            ephemeral_pubkey: pk1,
            auth_signature: None,
        };
        let t_id = [0x11u8; 32];
        let sig = [0x22u8; 64];
        let lock1 = L2LockRequest {
            causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: pk1,
                auth_signature: None,
            },
            layer2_voucher_id: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                .to_string(),
            ds_tag: None,
            transaction_hash: t_id,
            is_genesis: true,
            sender_ephemeral_pub: pk1,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig,
            trap_r: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            trap_s: Some(TRAP_NONE_PLACEHOLDER.to_string()),
            encrypted_timestamp: 12345,
            created_at_ms: 0,
            deletable_at: Some("2026-01-01T00:00:00Z".to_string()),
            privacy_guard: None,
        };
        let lock2 = L2LockRequest {
            causal_output: None,
            auth: L2AuthPayload {
                ephemeral_pubkey: pk2,
                auth_signature: None,
            },
            layer2_voucher_id: lock1.layer2_voucher_id.clone(),
            ds_tag: Some("some_ds_tag".to_string()),
            transaction_hash: [0x33u8; 32],
            is_genesis: false,
            sender_ephemeral_pub: pk2,
            receiver_ephemeral_pub_hash: None,
            change_ephemeral_pub_hash: None,
            layer2_signature: sig,
            trap_r: Some("trapR".to_string()),
            trap_s: Some("trapS".to_string()),
            encrypted_timestamp: 999,
            created_at_ms: 0,
            deletable_at: None,
            privacy_guard: Some("guard".to_string()),
        };
        let chain_req = L2ChainLockRequest {
            auth: auth_top.clone(),
            layer2_voucher_id: lock1.layer2_voucher_id.clone(),
            chain: vec![lock1.clone(), lock2.clone()],
        };
        let json = serde_json::to_string(&chain_req).expect("serialize chain req");
        let de: L2ChainLockRequest = serde_json::from_str(&json).expect("deserialize chain req");
        assert_eq!(de.layer2_voucher_id, chain_req.layer2_voucher_id);
        assert_eq!(de.chain.len(), 2);
        assert_eq!(de.auth.ephemeral_pubkey, auth_top.ephemeral_pubkey);
        assert_eq!(de.chain[0].transaction_hash, lock1.transaction_hash);
        assert_eq!(de.chain[1].transaction_hash, lock2.transaction_hash);
        // Roundtrip determinism
        let json2 = serde_json::to_string(&de).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn test_build_voucher_lock_chain_genesis_variants() {
        use crate::test_utils::ACTORS;
        use crate::test_utils::voucher_setup::{
            create_transaction_with_auto_decrypt, setup_voucher_with_one_tx,
        };

        let (standard, _hash, _creator, _recipient, voucher1, secrets1) =
            setup_voucher_with_one_tx();
        // Build second tx: bob -> charlie
        let bob = &ACTORS.bob.identity;
        let charlie = &ACTORS.charlie.identity;
        let bob_eph = crate::test_utils::voucher_setup::derive_recipient_holder_key(bob, &secrets1.recipient_seed);
        let (voucher2, _next_seed) = create_transaction_with_auto_decrypt(
            &voucher1,
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_eph,
            &charlie.user_id,
            &charlie.signing_key,
            "10.00",
        )
        .expect("second tx");

        assert_eq!(voucher2.transactions.len(), 3);
        let layer2_id = extract_layer2_voucher_id(&voucher2).unwrap();

        // Generate target request for last tx (bob->charlie)
        let last_tx = voucher2.transactions.last().unwrap();
        let last_sender_str = last_tx.sender_ephemeral_pub.as_deref().unwrap();
        let last_sender_bytes =
            crate::services::crypto::decode_bs58_fixed::<32>(last_sender_str, "sender_pub")
                .unwrap();
        let target_req = generate_lock_request(&layer2_id, last_tx, &last_sender_bytes).unwrap();

        // Case A: sync_point None -> genesis inclusive chain of length 3
        let chain_none = build_voucher_lock_chain(&voucher2, None, target_req.clone()).unwrap();
        assert_eq!(chain_none.chain.len(), 3);
        assert!(chain_none.chain[0].is_genesis);
        assert_eq!(
            chain_none.chain[2].transaction_hash,
            target_req.transaction_hash
        );
        assert_eq!(chain_none.layer2_voucher_id, layer2_id);

        // Case B: sync_point "genesis" -> also starts at 0
        let chain_genesis =
            build_voucher_lock_chain(&voucher2, Some("genesis"), target_req.clone()).unwrap();
        assert_eq!(chain_genesis.chain.len(), 3);
        assert!(chain_genesis.chain[0].is_genesis);

        // Case C: sync_point = t_id of genesis -> chain after genesis (len 2)
        let genesis_tid = voucher2.transactions[0].t_id.clone();
        let chain_after_genesis =
            build_voucher_lock_chain(&voucher2, Some(&genesis_tid), target_req.clone()).unwrap();
        assert_eq!(chain_after_genesis.chain.len(), 2);
        assert!(!chain_after_genesis.chain[0].is_genesis);
        // first element should correspond to tx1
        let tx1_hash = crate::services::crypto::decode_bs58_fixed::<32>(
            &voucher2.transactions[1].t_id,
            "t_id",
        )
        .unwrap();
        assert_eq!(chain_after_genesis.chain[0].transaction_hash, tx1_hash);

        // Case D: sync_point = ds_tag of first spend -> only last tx
        let tx1_ds = voucher2.transactions[1]
            .trap_data
            .as_ref()
            .unwrap()
            .ds_tag
            .clone();
        let chain_after_tx1 =
            build_voucher_lock_chain(&voucher2, Some(&tx1_ds), target_req.clone()).unwrap();
        assert_eq!(chain_after_tx1.chain.len(), 1);
        assert_eq!(
            chain_after_tx1.chain[0].transaction_hash,
            target_req.transaction_hash
        );

        // Case E: sync_point prefix (10 chars) of genesis t_id
        let genesis_prefix: String = genesis_tid.chars().take(10).collect();
        let chain_prefix =
            build_voucher_lock_chain(&voucher2, Some(&genesis_prefix), target_req.clone()).unwrap();
        assert_eq!(chain_prefix.chain.len(), 2);

        // Case F: Exact match takes priority and rposition finds latest match
        let tx1_tid = voucher2.transactions[1].t_id.clone();
        let chain_tx1_exact =
            build_voucher_lock_chain(&voucher2, Some(&tx1_tid), target_req.clone()).unwrap();
        assert_eq!(chain_tx1_exact.chain.len(), 1); // Only tx2 remains
        assert_eq!(
            chain_tx1_exact.chain[0].transaction_hash,
            target_req.transaction_hash
        );

        // Serde roundtrip of built chain
        let json = serde_json::to_string(&chain_none).unwrap();
        let de: crate::models::layer2_api::L2ChainLockRequest =
            serde_json::from_str(&json).unwrap();
        assert_eq!(de.chain.len(), 3);
    }

    #[test]
    fn test_build_voucher_lock_chain_error_cases() {
        use crate::test_utils::ACTORS;
        use crate::test_utils::voucher_setup::{
            create_transaction_with_auto_decrypt, setup_voucher_with_one_tx,
        };

        let (standard, _hash, _creator, _recipient, voucher1, secrets1) =
            setup_voucher_with_one_tx();
        let bob = &ACTORS.bob.identity;
        let charlie = &ACTORS.charlie.identity;
        let bob_eph = crate::test_utils::voucher_setup::derive_recipient_holder_key(bob, &secrets1.recipient_seed);
        let (voucher2, _) = create_transaction_with_auto_decrypt(
            &voucher1,
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_eph,
            &charlie.user_id,
            &charlie.signing_key,
            "10.00",
        )
        .unwrap();
        let layer2_id = extract_layer2_voucher_id(&voucher2).unwrap();
        let last_tx = voucher2.transactions.last().unwrap();
        let last_sender_bytes = crate::services::crypto::decode_bs58_fixed::<32>(
            last_tx.sender_ephemeral_pub.as_deref().unwrap(),
            "sender_pub",
        )
        .unwrap();
        let target_req = generate_lock_request(&layer2_id, last_tx, &last_sender_bytes).unwrap();

        // Unknown sync_point
        let err = build_voucher_lock_chain(
            &voucher2,
            Some("nonexistent_sync_point"),
            target_req.clone(),
        )
        .unwrap_err();
        assert!(format!("{:?}", err).contains("sync_point"));

        // sync beyond target (use last tx's t_id as sync)
        let last_tid = last_tx.t_id.clone();
        let err2 =
            build_voucher_lock_chain(&voucher2, Some(&last_tid), target_req.clone()).unwrap_err();
        assert!(format!("{:?}", err2).contains("beyond"));

        // target not in voucher
        let fake_target = L2LockRequest {
            causal_output: None,
            transaction_hash: [0xFFu8; 32],
            ..target_req.clone()
        };
        let err3 = build_voucher_lock_chain(&voucher2, None, fake_target).unwrap_err();
        assert!(format!("{:?}", err3).contains("target"));

        // empty voucher
        let empty_voucher = crate::models::voucher::Voucher::default();
        let err4 = build_voucher_lock_chain(&empty_voucher, None, target_req).unwrap_err();
        assert!(
            format!("{:?}", err4).contains("MissingTransactions")
                || format!("{:?}", err4).contains("transactions")
        );
    }

    #[test]
    fn test_l2_lock_request_signature_commits_to_created_at_ms() {
        use crate::test_utils::voucher_setup::setup_voucher_with_one_tx;

        #[cfg(feature = "test-utils")]
        crate::set_signature_bypass(false);

        let (_standard, _hash, _creator, _recipient, voucher1, _secrets1) =
            setup_voucher_with_one_tx();
        assert!(voucher1.transactions.len() >= 2);
        let layer2_id = extract_layer2_voucher_id(&voucher1).expect("extract layer2 id");
        let spend_tx = &voucher1.transactions[1];

        let sender_str = spend_tx
            .sender_ephemeral_pub
            .as_deref()
            .expect("sender ephemeral pub");
        let sender_bytes =
            crate::services::crypto::decode_bs58_fixed::<32>(sender_str, "sender_pub").unwrap();

        let req = generate_lock_request(&layer2_id, spend_tx, &sender_bytes)
            .expect("generate lock request");
        let challenge_ds_tag = derive_challenge_tag(spend_tx).expect("derive challenge ds tag");

        let lock_entry = L2LockEntry::from(req);

        // 1. Valid lock entry proof must verify successfully
        verify_lock_entry_proof(&lock_entry, &layer2_id, Some(sender_str), &challenge_ds_tag)
            .expect("Valid signature verification must succeed");

        // 2. Mutating created_at_ms (+1) must invalidate the signature proof
        let mut mutated_created_at = lock_entry.clone();
        mutated_created_at.created_at_ms = mutated_created_at.created_at_ms.wrapping_add(1);
        let err_created_at = verify_lock_entry_proof(
            &mutated_created_at,
            &layer2_id,
            Some(sender_str),
            &challenge_ds_tag,
        )
        .unwrap_err();
        assert!(
            matches!(
                err_created_at,
                VoucherCoreError::Validation(crate::error::ValidationError::InvalidL2Proof)
            ),
            "Mutated created_at_ms must fail with InvalidL2Proof, got {:?}",
            err_created_at
        );

        // 3. Mutating encrypted_timestamp (+1) must invalidate the signature proof
        let mut mutated_enc_ts = lock_entry.clone();
        mutated_enc_ts.encrypted_timestamp = mutated_enc_ts.encrypted_timestamp.wrapping_add(1);
        let err_enc_ts = verify_lock_entry_proof(
            &mutated_enc_ts,
            &layer2_id,
            Some(sender_str),
            &challenge_ds_tag,
        )
        .unwrap_err();
        assert!(
            matches!(
                err_enc_ts,
                VoucherCoreError::Validation(crate::error::ValidationError::InvalidL2Proof)
            ),
            "Mutated encrypted_timestamp must fail with InvalidL2Proof, got {:?}",
            err_enc_ts
        );
    }

    #[test]
    fn test_verify_checkout_receipt_14_of_20_bft() {
        let digest = [0x7au8; 32];
        let mut committee = Vec::new();
        let mut signers = Vec::new();

        for i in 0..20u8 {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[i + 1; 32]);
            let pk = sk.verifying_key().to_bytes();
            committee.push(pk);
            signers.push((sk, pk));
        }

        // 1. Exactly 14 of 20 valid signers -> Ok(())
        let votes_14: Vec<humoco_proto::types::AttestationVote> = signers[0..14]
            .iter()
            .map(|(sk, pk)| humoco_proto::types::AttestationVote {
                signer_pubkey: *pk,
                signature: sk.sign(&digest).to_bytes(),
            })
            .collect();
        let proof_14 = humoco_proto::types::QuorumProof {
            shard_id: 1,
            votes: votes_14,
        };
        let res_14 = verify_checkout_receipt(&proof_14, &digest, &committee, 14);
        assert!(res_14.is_ok(), "14 of 20 must be accepted");

        // 2. 13 of 20 signers -> Err (insufficient votes)
        let proof_13 = humoco_proto::types::QuorumProof {
            shard_id: 1,
            votes: proof_14.votes[0..13].to_vec(),
        };
        let res_13 = verify_checkout_receipt(&proof_13, &digest, &committee, 14);
        assert!(res_13.is_err(), "13 of 20 must fail threshold 14");

        // 3. Duplicate signer among 14 -> Err
        let mut votes_dup = proof_14.votes[0..13].to_vec();
        votes_dup.push(proof_14.votes[0].clone());
        let proof_dup = humoco_proto::types::QuorumProof {
            shard_id: 1,
            votes: votes_dup,
        };
        let res_dup = verify_checkout_receipt(&proof_dup, &digest, &committee, 14);
        assert!(res_dup.is_err(), "Duplicate signers must be rejected");

        // 4. Rogue non-committee signer -> Err
        let rogue_sk = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
        let rogue_pk = rogue_sk.verifying_key().to_bytes();
        let mut votes_rogue = proof_14.votes[0..13].to_vec();
        votes_rogue.push(humoco_proto::types::AttestationVote {
            signer_pubkey: rogue_pk,
            signature: rogue_sk.sign(&digest).to_bytes(),
        });
        let proof_rogue = humoco_proto::types::QuorumProof {
            shard_id: 1,
            votes: votes_rogue,
        };
        let res_rogue = verify_checkout_receipt(&proof_rogue, &digest, &committee, 14);
        assert!(res_rogue.is_err(), "Non-committee signer must be rejected");

        // 5. verify_checkout_receipt_certificate via DTO conversion
        let cert = QuorumCertificateDto::from(proof_14);
        let res_cert = verify_checkout_receipt_certificate(&cert, &digest, &committee, 14);
        assert!(
            res_cert.is_ok(),
            "Certificate roundtrip verification must succeed"
        );
    }
}

#[cfg(test)]
mod recipient_authority_tests {
    use super::*;
    use crate::models::layer2_api::AttestationDto;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn canonical_original_proof_requires_independent_full_key_authority() {
        let keys: Vec<_> = (1..=20).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
        let authority = CheckoutAuthority {
            network: 0,
            shard_id: 9,
            parent_lock: [1; 32],
            child_lock: [2; 32],
            committee: keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        };
        let digest = humoco_proto::live::original_approval_digest(
            0,
            9,
            1,
            &authority.parent_lock,
            &authority.child_lock,
        )
        .unwrap();
        let certificate = QuorumCertificateDto {
            lock_id: hex::encode(authority.child_lock),
            shard_id: 9,
            status: 1,
            active_nodes_count: 20,
            signer_count: 14,
            signatures: keys
                .iter()
                .take(14)
                .enumerate()
                .map(|(i, key)| AttestationDto {
                    lock_id: hex::encode(authority.child_lock),
                    parent_lock: hex::encode(authority.parent_lock),
                    node_id: i as u16,
                    node_pubkey: hex::encode(key.verifying_key().to_bytes()),
                    timestamp: 0,
                    signature: hex::encode(key.sign(&digest).to_bytes()),
                    shard_id: 9,
                })
                .collect(),
        };
        assert!(matches!(
            evaluate_quorum_certificate(
                Some(certificate.clone()),
                &authority.child_lock,
                "voucher",
                Some(&authority)
            ),
            Ok(VerdictAction::ConfirmFinal { .. })
        ));
        assert!(
            evaluate_quorum_certificate(
                Some(certificate.clone()),
                &authority.child_lock,
                "voucher",
                None
            )
            .is_err()
        );
        let mut short = certificate.clone();
        short.signatures.pop();
        assert!(
            evaluate_quorum_certificate(
                Some(short),
                &authority.child_lock,
                "voucher",
                Some(&authority)
            )
            .is_err()
        );
        let mut duplicate = certificate.clone();
        duplicate.signatures[13] = duplicate.signatures[0].clone();
        assert!(
            evaluate_quorum_certificate(
                Some(duplicate),
                &authority.child_lock,
                "voucher",
                Some(&authority)
            )
            .is_err()
        );
        let mut forged = certificate.clone();
        forged.signatures[0].signature = hex::encode([0; 64]);
        assert!(
            evaluate_quorum_certificate(
                Some(forged),
                &authority.child_lock,
                "voucher",
                Some(&authority)
            )
            .is_err()
        );
        let mut wrong_network = authority.clone();
        wrong_network.network = 1;
        assert!(
            evaluate_quorum_certificate(
                Some(certificate.clone()),
                &authority.child_lock,
                "voucher",
                Some(&wrong_network)
            )
            .is_err()
        );
    }
}
