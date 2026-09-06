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
use crate::services::crypto::{
    get_hash, get_hash_from_slices, sign_ed25519, verify_ed25519,
};
use crate::services::utils::{get_current_timestamp, to_canonical_json};
use crate::wallet::DoubleSpendCheckResult;
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};

/// Canonical marker for fingerprints derived from MALFORMED spend
/// transactions whose trap shards are missing or carry the genesis
/// placeholder (HMSEC-SA06-11).
///
/// Such transactions claim to be spends (they carry `trap_data`) yet switch
/// the SST attribution channel off by format choice. Their fingerprints must
/// never classify as genesis entries (`is_init_fingerprint`), otherwise
/// gossip ingress, export filtering, cleanup and SST collision extraction
/// would silently skip them and double-spends of such forks could never
/// reach remote victims.
pub const VOID_SPEND_SHARD_MARKER: &str = "invalid";

/// Maximum number of foreign fingerprints admitted per `ds_tag` bucket (DoS prevention).
/// Symmetric to the outbound cap `MAX_FINGERPRINTS_TO_SEND = 150`.
pub const MAX_FOREIGN_BUCKET_CAP: usize = 150;

/// Creates a single, anonymized fingerprint for a given transaction.
/// Contains the logic for anonymizing the `valid_until` timestamp.
pub fn create_fingerprint_for_transaction(
    transaction: &Transaction,
    voucher: &Voucher,
) -> Result<TransactionFingerprint, VoucherCoreError> {
    // 1. Anonymize the `valid_until` timestamp by rounding to the end of the month.
    let valid_until_rounded = {
        let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until).map_err(|e| {
            VoucherCoreError::InvalidTimestamp(format!("Failed to parse valid_until: {}", e))
        })?;

        let year = parsed_date.year();
        let month = parsed_date.month();

        let first_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
        .ok_or_else(|| {
            VoucherCoreError::InvalidTimestamp("Failed to calculate next month's date".to_string())
        })?;

        let last_day_of_month = first_of_next_month.pred_opt().ok_or_else(|| {
            VoucherCoreError::InvalidTimestamp("Failed to get last day of month".to_string())
        })?;
        let end_of_month_dt = last_day_of_month
            .and_hms_micro_opt(23, 59, 59, 999999)
            .ok_or_else(|| {
                VoucherCoreError::InvalidTimestamp("Failed to set time for end of month".to_string())
            })?
            .and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    // 2. Create the fingerprint with the rounded timestamp.
    // NEW: We use the 'ds_tag' from the TrapData as the canonical DS tag and
    // carry the raw V3 (SST) shard pair (trap_r, trap_s) so any gossip peer
    // can authenticate the fingerprint and later extract identities on
    // collision. Only for 'init' (which has no trap) do we calculate the tag
    // manually and bind the canonical "none" placeholders.
    let (tag, trap_r, trap_s) = if transaction.t_type == "init" {
        // SECURITY (WH4-01-202): Genesis/init transactions NEVER carry spend traps.
        // Even if crafted trap_data was embedded, init fingerprints always bind
        // the canonical "none" placeholders and derive the fallback tag from
        // prev_hash and sender_ephemeral_pub.
        let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
            .into_vec()
            .map_err(|_| VoucherCoreError::Fingerprint("Invalid prev_hash format".to_string()))?;
        let ephem_key_bytes = if let Some(s) = &transaction.sender_ephemeral_pub {
            bs58::decode(s).into_vec().map_err(|_| {
                VoucherCoreError::Fingerprint("Invalid sender_ephemeral_pub format".to_string())
            })?
        } else {
            Vec::new()
        };

        let fallback_tag = get_hash_from_slices(&[&prev_hash_bytes, &ephem_key_bytes]);
        (
            fallback_tag,
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string(),
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string(),
        )
    } else if let Some(trap) = &transaction.trap_data {
        // SECURITY (HMSEC-SA06-11): a transaction WITH trap_data claims to be
        // a spend. If its shards are empty or carry the canonical genesis
        // placeholder, the SST attribution channel is switched off by format
        // choice. Such shards are replaced with the dedicated void marker so
        // the resulting fingerprint can never masquerade as a genesis entry
        // in gossip classification (ingress/export/cleanup/extraction).
        // Genuine genesis transactions have no trap_data and take the
        // fallback branch below, preserving the "none" placeholders.
        if trap.trap_r.is_empty()
            || trap.trap_s.is_empty()
            || trap.trap_r == crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
            || trap.trap_s == crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
        {
            (
                trap.ds_tag.clone(),
                VOID_SPEND_SHARD_MARKER.to_string(),
                VOID_SPEND_SHARD_MARKER.to_string(),
            )
        } else {
            (
                trap.ds_tag.clone(),
                trap.trap_r.clone(),
                trap.trap_s.clone(),
            )
        }
    } else {
        // Pad with zeros if the hash is shorter.
        // SECURITY FIX: Use raw bytes for concatenation
        let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
            .into_vec()
            .map_err(|_| VoucherCoreError::Fingerprint("Invalid prev_hash format".to_string()))?;
        let ephem_key_bytes = if let Some(s) = &transaction.sender_ephemeral_pub {
            bs58::decode(s).into_vec().map_err(|_| {
                VoucherCoreError::Fingerprint("Invalid sender_ephemeral_pub format".to_string())
            })?
        } else {
            Vec::new()
        };

        let fallback_tag = get_hash_from_slices(&[&prev_hash_bytes, &ephem_key_bytes]);
        (
            fallback_tag,
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string(),
            crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string(),
        )
    };

    // For 'init' fingerprints the RAW transaction-level deletable_at is kept
    // (it is cryptographically bound into the V3 layer2_signature and init
    // fingerprints never leave the wallet via gossip). For spends the
    // anonymized month-rounded voucher validity is used for retention only.
    let effective_deletable_at = if transaction.t_type == "init" {
        transaction.deletable_at.clone().unwrap_or(valid_until_rounded)
    } else {
        valid_until_rounded
    };

    // V3 Protocol (audit_02_11): the voucher container id is signature-bound.
    // Genesis locks signed the canonical "none" placeholder (a genesis lock
    // cannot bind its own derived id); spends bind their real hex id so the
    // fingerprint's embedded signature stays verifiable by every peer.
    let fp_layer2_voucher_id = if transaction.t_type == "init" {
        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string()
    } else {
        crate::services::l2_gateway::extract_layer2_voucher_id(voucher)?
    };

    Ok(TransactionFingerprint {
        ds_tag: tag,
        t_id: transaction.t_id.clone(),
        encrypted_timestamp: encrypt_transaction_timestamp(transaction)?,
        layer2_signature: transaction.layer2_signature.clone().unwrap_or_default(),
        sender_ephemeral_pub: transaction
            .sender_ephemeral_pub
            .clone()
            .unwrap_or_default(),
        deletable_at: effective_deletable_at,
        trap_r,
        trap_s,
        layer2_voucher_id: fp_layer2_voucher_id,
        privacy_guard_hash: crate::services::l2_gateway::privacy_guard_commitment(
            transaction.privacy_guard.as_deref(),
        ),
    })
}

/// SECURITY GATE (V3 Protocol): Verifies that a fingerprint's embedded
/// `layer2_signature` was produced by the holder of the ephemeral key named
/// in [`TransactionFingerprint::sender_ephemeral_pub`] over the canonical
/// `HMC_TX_AUTH_V3` digest.
///
/// This transforms gossip fingerprints from unauthenticated rumors into
/// self-authenticating instant proofs: any peer can verify authorship at
/// ingress without waiting for heavy transaction chains.
///
/// Challenge-tag selection mirrors [`crate::services::l2_gateway::derive_challenge_tag`]:
/// - init/no-trap fingerprint (see [`is_init_fingerprint`]): challenge tag is
///   `fp.t_id`, and the raw `deletable_at` is bound into the digest.
/// - otherwise (spend fingerprint): challenge tag is `fp.ds_tag`.
///
/// The hardened digest additionally binds the voucher container id
/// (`fp.layer2_voucher_id`, audit_02_11) and the canonical privacy-guard
/// commitment (`fp.privacy_guard_hash`, HMSEC-SA04-08).
///
/// Returns `false` for malformed inputs (invalid base58, wrong lengths,
/// missing key/signature) — fail-closed.
pub fn verify_fingerprint_signature(fp: &TransactionFingerprint) -> bool {
    let ephem_pub_bytes = match bs58::decode(&fp.sender_ephemeral_pub).into_vec() {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let t_id_bytes = match bs58::decode(&fp.t_id).into_vec() {
        Ok(v) if v.len() == 32 => v,
        _ => return false,
    };
    let sig_bytes = match bs58::decode(&fp.layer2_signature).into_vec() {
        Ok(v) if v.len() == 64 => v,
        _ => return false,
    };

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(
        ephem_pub_bytes.as_slice().try_into().expect("len checked"),
    ) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = ed25519_dalek::Signature::from_bytes(
        sig_bytes.as_slice().try_into().expect("len checked"),
    );

    let (challenge_tag, deletable_at) = if is_init_fingerprint(fp) {
        (fp.t_id.clone(), Some(fp.deletable_at.as_str()))
    } else {
        (fp.ds_tag.clone(), None)
    };

    // Genesis fingerprints signed the canonical "none" placeholder for the
    // voucher-id field (a genesis lock cannot bind its own derived id).
    let effective_voucher_id = if fp.layer2_voucher_id.is_empty()
        && is_init_fingerprint(fp)
    {
        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER.to_string()
    } else {
        fp.layer2_voucher_id.clone()
    };

    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
        &effective_voucher_id,
        &challenge_tag,
        t_id_bytes.as_slice().try_into().expect("len checked"),
        ephem_pub_bytes.as_slice().try_into().expect("len checked"),
        &fp.trap_r,
        &fp.trap_s,
        fp.encrypted_timestamp,
        deletable_at,
        &fp.privacy_guard_hash,
    );

    crate::services::crypto::verify_ed25519(&verifying_key, &payload_hash, &signature)
}

/// Canonical marker for genesis ('init') fingerprints, which carry no trap
/// shards and therefore have no gossip detection value.
///
/// # V3 Protocol (SST)
/// A fingerprint counts as init/no-trap ONLY when BOTH shards carry the
/// canonical `"none"` placeholder — exactly what
/// [`create_fingerprint_for_transaction`] emits for genuine genesis
/// transactions.
///
/// # SECURITY (WH3-00-902 / AUDIT-02-09): empty shards are NOT genesis
/// The previous rule additionally equated EMPTY shard strings with genesis.
/// That equivalence is attacker-exploitable: a hand-crafted SPEND transaction
/// with `TrapData { trap_r: "", trap_s: "" }` passes L1 chain validation (the
/// layer2_signature binds the empty shard strings verbatim), so its gossip
/// fingerprint is an authenticated spend claim. Classifying it as init made
/// every peer silently drop it at ingress, load purge and cleanup — a
/// double-spend fork broadcast this way stayed invisible network-wide while
/// its honestly-sharded sibling circulated. Empty-shard fingerprints are
/// therefore treated as spend-typed entries: they stay in the detection
/// pipeline and survive all gates only when their embedded signature
/// authenticates them (`verify_fingerprint_signature`), keeping collisions
/// visible without weakening any cryptographic gate.
pub fn is_init_fingerprint(fp: &TransactionFingerprint) -> bool {
    fp.trap_r == crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
        && fp.trap_s == crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER
}

/// Canonical "did THIS user author this transaction?" predicate.
///
/// # SECURITY (WH3-00-903): single source of truth for sender attribution
/// The transfer path (`transaction_handler::_execute_single_transfer`)
/// counts anonymous stealth/flexible spends (sender_id = None,
/// recipient = ANONYMOUS_ID) as own sends, and its direct fingerprint insert
/// stores them without a sender check. Every scan/rebuild that recomputes
/// own_fingerprints MUST apply the identical definition, otherwise each
/// full-replace silently drops the directly inserted stealth entries: the
/// proactive self-double-spend guard goes blind and
/// export_own_fingerprints stops shipping stealth evidence to peers.
///
/// Note on received vouchers: anonymity means authorship is intentionally
/// NOT derivable from chain data, so a received stealth voucher is counted
/// as own as well. This errs toward MORE protective self-double-spend
/// detection and richer evidence custody; distinct per-input ds_tags make
/// spurious guard trips cryptographically impossible.
pub fn is_own_transaction(tx: &Transaction, user_id: &str) -> bool {
    tx.sender_id.as_deref() == Some(user_id)
        || (tx.sender_id.is_none() && tx.recipient_id == crate::models::voucher::ANONYMOUS_ID)
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

            // Every transaction is added to the general local history.
            // CORRECTION: Prevent duplicates. A Vec is used to preserve order,
            // but we check for uniqueness before adding.
            let known_entry = known
                .local_history
                .entry(fingerprint.ds_tag.clone())
                .or_default();
            if !known_entry.contains(&fingerprint) {
                known_entry.push(fingerprint.clone());
            }

            // Only if the user authored the transaction is the fingerprint
            // also added to the critical "own" fingerprints.
            // SECURITY (WH3-00-903): the canonical is_sender definition
            // (see [`is_own_transaction`]) includes anonymous stealth/flexible
            // spends; a stricter filter here would make every full-replace
            // rebuild wipe the directly inserted stealth history.
            if is_own_transaction(tx, user_id) {
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
        let mut fps_vec: Vec<TransactionFingerprint> = fps_set.into_iter().collect();
        // SECURITY (AUDIT-01-F16): canonical ordering. HashSet iteration
        // order differs per process/call; downstream attribution consumed
        // positional pairs ([0]/[1]), so identical evidence sets produced
        // different offender identities across runs (dedup/immunity keyed on
        // proof_id, UI and forensics all broke). t_ids are unique per bucket,
        // making this a total deterministic order.
        fps_vec.sort_by(|a, b| a.t_id.cmp(&b.t_id));
        let unique_t_ids = fps_vec
            .iter()
            .map(|fp| &fp.t_id)
            .collect::<std::collections::HashSet<_>>();

        // SECURITY (HMSEC-SA04-08): guard/input EQUIVOCATION detection.
        // Two handovers of ONE input share a single t_id, so the classic
        // `unique_t_ids > 1` gate never fires. When two same-t_id entries
        // diverge in any SIGNATURE-BOUND evidence field (trap shards,
        // encrypted timestamp, layer2_signature or privacy-guard commitment),
        // the signer equivocated and this bucket IS genuine fraud evidence.
        // `deletable_at` is deliberately excluded: it is retention metadata
        // that legitimately differs between local and foreign stores.
        let has_equivocation = {
            let mut first_by_t_id: HashMap<&str, &TransactionFingerprint> = HashMap::new();
            let mut diverged = false;
            for fp in &fps_vec {
                match first_by_t_id.get(fp.t_id.as_str()) {
                    Some(prev) => {
                        if prev.trap_r != fp.trap_r
                            || prev.trap_s != fp.trap_s
                            || prev.encrypted_timestamp != fp.encrypted_timestamp
                            || prev.layer2_signature != fp.layer2_signature
                            || prev.privacy_guard_hash != fp.privacy_guard_hash
                        {
                            diverged = true;
                            break;
                        }
                    }
                    None => {
                        first_by_t_id.insert(fp.t_id.as_str(), fp);
                    }
                }
            }
            diverged
        };

        if unique_t_ids.len() > 1 || has_equivocation {
            // 3. Classify a conflict as "verifiable" if the wallet owner
            // knows the involved fingerprints from any source — either from
            // the own transaction history (local_history) or received via gossip
            // (foreign_fingerprints). In both cases, the fingerprints carry the
            // cryptographic SST shard data (trap_r, trap_s) for identity
            // extraction.
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

/// Derives the deterministic `proof_id` for a double-spend conflict.
///
/// Formula (canonical, shared by creation AND import verification):
/// `proof_id = SHA3-256_len_prefixed(offender_pk_bytes || fork_prev_hash_bytes)`.
///
/// For anonymous/unresolvable offender identifiers the raw bytes of the
/// identifier string are used as a deterministic fallback.
///
/// # Security (AUDIT-01-F10)
/// The offender_id is CANONICALIZED before hashing, exactly like
/// [`crate::services::crypto::get_pubkey_from_user_id`] parses it:
/// all whitespace is stripped and the LAST `@did:key:z` marker wins.
/// Otherwise render variants of the same logical identity derive different
/// proof_ids and the import immunity/dedup rule (keyed on proof_id) can be
/// bypassed. Canonical inputs are unaffected (byte-for-byte compatible).
pub fn derive_proof_id(
    offender_id: &str,
    fork_point_prev_hash: &str,
) -> Result<String, VoucherCoreError> {
    let sanitized: String = offender_id.chars().filter(|c| !c.is_whitespace()).collect();
    let offender_pk_bytes = if let Some(pos) = sanitized.rfind("@did:key:z") {
        bs58::decode(&sanitized[pos + 10..])
            .into_vec()
            .map_err(|_| VoucherCoreError::ProofImport("Invalid offender_id did format".to_string()))?
    } else {
        // Fallback for anonymous offenders (Gossip soft proofs):
        // If there is no DID format, use the hash of the offender_id string
        // as a replacement for the public key bytes. This enables deterministic
        // proof_id calculation even for conflicts where the identity of the
        // offender has not yet been mathematically extracted.
        sanitized.into_bytes()
    };

    let fork_prev_hash_bytes = bs58::decode(fork_point_prev_hash).into_vec().map_err(|_| {
        VoucherCoreError::ProofImport("Invalid fork_point_prev_hash format".to_string())
    })?;

    Ok(get_hash_from_slices(&[&offender_pk_bytes, &fork_prev_hash_bytes]))
}

/// SECURITY GATE: Verifies the reporter signature of an imported proof.
///
/// The reporter must have signed the `proof_id` bytes with the permanent
/// identity key referenced by `reporter_id`. Without this gate anyone could
/// fabricate proofs to quarantine arbitrary vouchers remotely.
pub fn verify_reporter_signature(proof: &ProofOfDoubleSpend) -> Result<(), VoucherCoreError> {
    let reporter_pk = crate::services::crypto::get_pubkey_from_user_id(&proof.reporter_id)
        .map_err(|_| {
            VoucherCoreError::ProofImport(format!(
                "Cannot import proof: reporter_id '{}' is not a valid DID identity.",
                proof.reporter_id
            ))
        })?;
    let sig_bytes = bs58::decode(&proof.reporter_signature)
        .into_vec()
        .map_err(|e| {
            VoucherCoreError::ProofImport(format!("Cannot import proof: invalid reporter_signature encoding: {}", e))
        })?;
    let signature = ed25519_dalek::Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| {
        VoucherCoreError::ProofImport("Cannot import proof: invalid reporter_signature length.".to_string())
    })?);

    if !verify_ed25519(&reporter_pk, proof.proof_id.as_bytes(), &signature) {
        return Err(VoucherCoreError::ProofImport(
            "Cannot import proof: reporter_signature does not verify over proof_id.".to_string(),
        ));
    }
    Ok(())
}

/// SECURITY GATE: Structural collision validation for imported proofs.
///
/// Ensures the contained transactions form a plausible double-spend:
/// - at least two transactions,
/// - all share `fork_point_prev_hash` as their direct predecessor,
/// - distinct `t_id`s,
/// - a revealed `sender_ephemeral_pub` (32 bytes),
/// - one identical recomputed `ds_tag` (`hash(prev_hash || sender_ephemeral_pub)`).
pub fn verify_proof_structure(proof: &ProofOfDoubleSpend) -> Result<(), VoucherCoreError> {
    let txs = &proof.conflicting_transactions;
    if txs.len() < 2 {
        return Err(VoucherCoreError::ProofImport(format!(
            "Cannot import proof: expected at least 2 conflicting transactions, found {}.",
            txs.len()
        )));
    }

    let mut seen_t_ids = std::collections::HashSet::new();
    let mut ds_tags = std::collections::HashSet::new();

    for tx in txs {
        if !seen_t_ids.insert(&tx.t_id) {
            return Err(VoucherCoreError::ProofImport(
                "Cannot import proof: duplicate t_id among conflicting transactions.".to_string(),
            ));
        }
        if tx.prev_hash != proof.fork_point_prev_hash {
            return Err(VoucherCoreError::ProofImport(
                "Cannot import proof: conflicting transactions do not share the fork point prev_hash.".to_string(),
            ));
        }

        // V2 Protocol (Gossip Soft Proofs): synthetic placeholder transactions
        // built from self-authenticating gossip fingerprints cannot recompute
        // their ds_tag from a real prev_hash (the true fork predecessor is not
        // part of the fingerprint). Their structural integrity instead follows
        // from the verified V2 layer2_signature checked at gossip ingress;
        // here we only enforce internal consistency: prev_hash == fork point
        // == claimed ds_tag and a well-formed revealed ephemeral key.
        if tx.t_type == "gossip_soft_placeholder" {
            let trap = tx.trap_data.as_ref().ok_or_else(|| {
                VoucherCoreError::ProofImport(
                    "Cannot import proof: gossip soft placeholder missing trap_data.".to_string(),
                )
            })?;
            if trap.ds_tag != proof.fork_point_prev_hash {
                return Err(VoucherCoreError::ProofImport(
                    "Cannot import proof: gossip soft placeholder ds_tag does not match the fork point.".to_string(),
                ));
            }
            // The claimed tag participates in the single-collision invariant.
            ds_tags.insert(trap.ds_tag.clone());
            let eph_pub_raw = tx.sender_ephemeral_pub.as_ref().ok_or_else(|| {
                VoucherCoreError::ProofImport(
                    "Cannot import proof: gossip soft placeholder missing sender_ephemeral_pub.".to_string(),
                )
            })?;
            let eph_ok = bs58::decode(eph_pub_raw)
                .into_vec()
                .map(|v| v.len() == 32)
                .unwrap_or(false);
            if !eph_ok {
                return Err(VoucherCoreError::ProofImport(
                    "Cannot import proof: gossip soft placeholder sender_ephemeral_pub must be 32 bytes.".to_string(),
                ));
            }
            continue;
        }

        let prev_hash_bytes = bs58::decode(&tx.prev_hash).into_vec().map_err(|_| {
            VoucherCoreError::ProofImport("Cannot import proof: invalid prev_hash encoding.".to_string())
        })?;
        let eph_pub_raw = tx.sender_ephemeral_pub.as_ref().ok_or_else(|| {
            VoucherCoreError::ProofImport(
                "Cannot import proof: conflicting transaction missing sender_ephemeral_pub.".to_string(),
            )
        })?;
        let eph_pub_bytes = bs58::decode(eph_pub_raw).into_vec().map_err(|_| {
            VoucherCoreError::ProofImport(
                "Cannot import proof: invalid sender_ephemeral_pub encoding.".to_string(),
            )
        })?;
        if eph_pub_bytes.len() != 32 {
            return Err(VoucherCoreError::ProofImport(
                "Cannot import proof: sender_ephemeral_pub must be 32 bytes.".to_string(),
            ));
        }

        let recomputed_ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &eph_pub_bytes]);
        if let Some(trap) = &tx.trap_data
            && trap.ds_tag != recomputed_ds_tag {
                return Err(VoucherCoreError::ProofImport(
                    "Cannot import proof: trap_data.ds_tag does not match recomputed input tag.".to_string(),
                ));
            }
        ds_tags.insert(recomputed_ds_tag);
    }

    if ds_tags.len() != 1 {
        return Err(VoucherCoreError::ProofImport(
            "Cannot import proof: transactions do not collide on a single ds_tag.".to_string(),
        ));
    }
    Ok(())
}

/// Creates a tamper-proof, portable proof (`ProofOfDoubleSpend`).
///
/// This function is solely responsible for creating the proof object.
/// It receives all necessary, already validated data and signs it.
/// The deterministic `proof_id` is generated here.
///
/// # Arguments
/// * `offender_id` - The ID of the offender.
/// * `fork_point_prev_hash` - The `prev_hash` where transactions branch off.
/// * `conflicting_transactions` - The verified conflicting transactions.
/// * `deletable_at` - The expiration/retention timestamp.
/// * `reporter_identity` - The identity of the wallet owner creating the proof.
/// * `non_redeemable_test_voucher` - Flag indicating whether it is a test voucher.
///
/// # Returns
/// A `Result` containing the created `ProofOfDoubleSpend` object on success.
pub fn create_proof_of_double_spend(
    offender_id: String,
    fork_point_prev_hash: String,
    conflicting_transactions: Vec<Transaction>,
    deletable_at: String,
    reporter_identity: &UserIdentity,
    non_redeemable_test_voucher: bool,
) -> Result<ProofOfDoubleSpend, VoucherCoreError> {
    // 1. Create and sign the proof object.
    // SECURITY FIX: Use raw bytes for proof_id derivation (centralized helper).
    let proof_id = derive_proof_id(&offender_id, &fork_point_prev_hash)?;
    let reporter_signature_bytes =
        sign_ed25519(&reporter_identity.signing_key, proof_id.as_bytes());
    let reporter_signature = bs58::encode(reporter_signature_bytes.to_bytes()).into_string();

    let proof = ProofOfDoubleSpend {
        proof_id,
        offender_id,
        suspected_identity: None,
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
/// * `proof_id` - The ID of the `ProofOfDoubleSpend` being resolved.
/// * `victim_identity` - The identity of the victim confirming the resolution.
/// * `notes` - An optional human-readable note.
///
/// # Returns
/// A `Result` containing the signed `ResolutionEndorsement`.
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
///
/// # V3 Protocol (Alt-Fingerprint Purge)
/// Foreign fingerprints that fail the V3 signature gate (legacy data or
/// tampered entries) are purged as well: they cannot be authenticated and
/// must never participate in instant-proof conflict resolution.
/// Returns the number of removed entries.
pub fn cleanup_known_fingerprints(known_fingerprints: &mut KnownFingerprints) -> usize {
    let now = get_current_timestamp();
    let mut count: usize = 0;
    known_fingerprints.foreign_fingerprints.retain(|_, fps| {
        let before = fps.len();
        fps.retain(|fp| {
            fp.deletable_at > now
                && !is_init_fingerprint(fp)
                && verify_fingerprint_signature(fp)
        });
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

/// SECURITY (HMSEC-SA06-15): Neutral wire marker that replaces the
/// voucher-derived retention timestamp in the GOSSIP WIRE FORMAT (export
/// blobs and forwarded bundle fingerprints). All transactions of one voucher
/// family share the same coarse voucher-validity-derived deadline; publishing
/// it verbatim lets passive observers cluster anonymous spends into origin
/// families. The exact value remains strictly local for retention cleanup.
pub const NEUTRAL_WIRE_DEADLINE: &str = "";

/// SECURITY (HMSEC-SA06-15): Uniform local retention period assigned to
/// FOREIGN fingerprints at ingress. Wire deadlines are untrusted (they may be
/// attacker-chosen to poison retention or to leak voucher validity); every
/// admitted foreign fingerprint receives this locally chosen deadline so the
/// existing string-comparison cleanup keeps working without carrying any
/// sender-controlled time information.
pub const FOREIGN_FINGERPRINT_RETENTION_DAYS: i64 = 180;

/// Replaces a foreign fingerprint's wire retention claim with the uniform
/// locally chosen deadline ([`FOREIGN_FINGERPRINT_RETENTION_DAYS`]).
///
/// Public because the bundle-gossip ingress path
/// (`wallet::conflict_handler::process_received_fingerprints`) applies the
/// same rule as [`import_foreign_fingerprints`].
pub fn assign_local_retention_to_wire_entry(fp: &mut TransactionFingerprint) {
    let deadline = chrono::Utc::now() + chrono::Duration::days(FOREIGN_FINGERPRINT_RETENTION_DAYS);
    fp.deletable_at = deadline.to_rfc3339_opts(SecondsFormat::Micros, true);
}

/// Serializes the history of own sent transactions for export.
pub fn export_own_fingerprints(
    own_fingerprints: &OwnFingerprints,
) -> Result<Vec<u8>, VoucherCoreError> {
    // NOTE: The entire known history is exported, as this is the most valuable
    // information for matching with peers.
    //
    // SECURITY (HMSEC-SA06-15): The gossip wire format must not carry the
    // voucher-derived retention timestamps: all spends of one voucher family
    // share the identical coarse deadline, which would let passive observers
    // link family members across hops. Egress neutralizes the field; receivers
    // assign their own uniform local retention at ingress
    // ([`import_foreign_fingerprints`]).
    let mut sanitized = own_fingerprints.history.clone();
    for fps in sanitized.values_mut() {
        for fp in fps.iter_mut() {
            fp.deletable_at = NEUTRAL_WIRE_DEADLINE.to_string();
        }
    }
    Ok(serde_json::to_vec(&sanitized)?)
}

/// Imports and merges foreign fingerprints into memory.
///
/// # V3 Protocol (Ingress Gate)
/// Only self-authenticating fingerprints are accepted: entries must carry a
/// valid `layer2_signature` over the canonical `HMC_TX_AUTH_V3` digest and
/// must not be genesis ('init') fingerprints (no detection value). Invalid
/// or legacy entries are silently dropped.
///
/// # Security (AUDIT-01-F11 / bucket-stuffing): content-addressed buckets
/// The transport map key of an export blob is ATTACKER-controlled and must
/// never become the bucket identity. Otherwise two genuine fingerprints from
/// DIFFERENT inputs (different `ds_tag`s) can be stuffed under one foreign
/// key, fabricating a "collision" that drives the offline Earliest-Wins race
/// and quarantines innocent active vouchers (`Lost offline race`). Imported
/// entries are therefore re-keyed by their CONTENT (`fp.ds_tag`) exactly like
/// every other ingress path (`process_received_fingerprints`,
/// `scan_and_rebuild_fingerprints`). Legitimate exports already use
/// `ds_tag` keys and are unaffected; coherent buckets collapse to their
/// single genuine member and can no longer form cross-voucher conflicts.
pub fn import_foreign_fingerprints(
    known_fingerprints: &mut KnownFingerprints,
    data: &[u8],
) -> Result<usize, VoucherCoreError> {
    let incoming: HashMap<String, Vec<TransactionFingerprint>> = serde_json::from_slice(data)?;
    let mut new_count = 0;
    let mut rejected_count = 0usize;
    for (_transport_key, fps) in incoming {
        for mut fp in fps {
            if is_init_fingerprint(&fp) || !verify_fingerprint_signature(&fp) {
                rejected_count += 1;
                continue;
            }
            // SECURITY (HMSEC-SA06-15): the wire deadline is untrusted
            // (neutralized by honest peers, attacker-chosen otherwise). It is
            // replaced with the uniform local retention deadline BEFORE any
            // comparison or storage.
            assign_local_retention_to_wire_entry(&mut fp);
            // SECURITY (AUDIT-01-F11): the bucket identity is ALWAYS the
            // fingerprint's own ds_tag — never the transport map key.
            let entry = known_fingerprints
                .foreign_fingerprints
                .entry(fp.ds_tag.clone())
                .or_default();
            // SECURITY (WH4-01-203): Bounded adversarial ingestion. Enforce bucket cap.
            if entry.len() >= MAX_FOREIGN_BUCKET_CAP {
                rejected_count += 1;
                continue;
            }
            // Dedupe: identical evidence (same t_id AND all signature-bound
            // fields) is a replay — drop it. A same-t_id entry with DIVERGENT
            // signature-bound fields (trap shards, encrypted timestamp,
            // layer2_signature, privacy_guard_hash) is equivocation / guard-
            // equivocation evidence (HMSEC-SA04-08) and MUST be retained so
            // `has_equivocation` in `check_for_double_spend` can observe it.
            // `deletable_at` is excluded: it is the locally assigned uniform
            // retention deadline and legitimately differs per import session.
            let is_exact_duplicate = entry.iter().any(|e| {
                e.t_id == fp.t_id
                    && e.trap_r == fp.trap_r
                    && e.trap_s == fp.trap_s
                    && e.encrypted_timestamp == fp.encrypted_timestamp
                    && e.layer2_signature == fp.layer2_signature
                    && e.privacy_guard_hash == fp.privacy_guard_hash
            });
            if is_exact_duplicate {
                rejected_count += 1;
                continue;
            }
            let is_equivocation = entry.iter().any(|e| e.t_id == fp.t_id);
            if is_equivocation {
                // Equivocation evidence shares the bucket but proves fraud via
                // the has_equivocation gate — admit it even if the t_id is
                // already present (counts toward the bucket cap already checked).
            }
            entry.push(fp);
            new_count += 1;
        }
    }
    known_fingerprints
        .foreign_fingerprints
        .retain(|_, fps| !fps.is_empty());
    log::debug!(
        "import_foreign_fingerprints: {} accepted, {} rejected/duplicate",
        new_count,
        rejected_count
    );
    Ok(new_count)
}

/// Encrypts the timestamp of a transaction for use in an L2 context.
///
/// Encryption is performed via XOR with a key that is deterministically derived from the
/// transaction itself. This ensures that anyone who possesses the
/// conflicting transactions can decrypt the timestamp.
///
/// # Arguments
/// * `transaction` - The transaction whose timestamp is to be encrypted.
///
/// # Returns
/// A `u128` value representing the encrypted timestamp in nanoseconds.
pub fn encrypt_transaction_timestamp(transaction: &Transaction) -> Result<u128, VoucherCoreError> {
    // a. Parse timestamp and convert to nanoseconds (u128).
    let nanos = DateTime::parse_from_rfc3339(&transaction.t_time)
        .map_err(|e| VoucherCoreError::InvalidTimestamp(format!("Failed to parse timestamp: {}", e)))?
        .timestamp_nanos_opt()
        .ok_or_else(|| {
            VoucherCoreError::InvalidTimestamp("Invalid timestamp for nanosecond conversion".to_string())
        })? as u128;

    // b. Derive key (u128) from the hash of prev_hash and t_id.
    // SECURITY FIX: Use raw bytes for key derivation hash
    let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Fingerprint("Invalid prev_hash format".to_string()))?;
    let t_id_bytes = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id format".to_string()))?;

    let key_hash_b58 = get_hash_from_slices(&[&prev_hash_bytes, &t_id_bytes]);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Fingerprint("Failed to decode base58 hash for key derivation".to_string())
    })?;

    // We take the first 16 bytes (128 bits) of the hash as the key.
    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Fingerprint("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    // c. Encrypt timestamp via XOR and return it.
    Ok(nanos ^ key)
}

/// Decrypts the timestamp of a transaction that was encrypted with `encrypt_transaction_timestamp`.
///
/// Since encryption is based on XOR, the decryption function is identical.
///
/// # Arguments
/// * `transaction` - The transaction to which the timestamp belongs.
/// * `encrypted_nanos` - The encrypted timestamp in nanoseconds (`u128`).
///
/// # Returns
/// The original decrypted timestamp in nanoseconds.
pub fn decrypt_transaction_timestamp(
    transaction: &Transaction,
    encrypted_nanos: u128,
) -> Result<u128, VoucherCoreError> {
    // SECURITY FIX: Use raw bytes for key derivation hash (identical to encryption)
    let prev_hash_bytes = bs58::decode(&transaction.prev_hash)
        .into_vec()
        .map_err(|_| VoucherCoreError::Fingerprint("Invalid prev_hash format".to_string()))?;
    let t_id_bytes = bs58::decode(&transaction.t_id)
        .into_vec()
        .map_err(|_| VoucherCoreError::InvalidHashFormat("Invalid t_id format".to_string()))?;

    let key_hash_b58 = get_hash_from_slices(&[&prev_hash_bytes, &t_id_bytes]);
    let key_hash_bytes = bs58::decode(key_hash_b58).into_vec().map_err(|_| {
        VoucherCoreError::Fingerprint("Failed to decode base58 hash for key derivation".to_string())
    })?;

    let key_bytes: [u8; 16] = key_hash_bytes[..16]
        .try_into()
        .map_err(|_| VoucherCoreError::Fingerprint("Hash too short for key derivation".to_string()))?;
    let key = u128::from_le_bytes(key_bytes);

    Ok(encrypted_nanos ^ key)
}