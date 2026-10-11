//! # src/wallet/conflicts/ingress.rs
//!
//! Ingress-related Wallet methods for fingerprint and proof handling.
//! Contains scanning, double-spend checks, foreign fingerprint import,
//! proof import with all security gates, and conflict resolution helpers.

use crate::archive::FileVoucherArchive;
use crate::error::{ValidationError, VoucherCoreError};
use crate::models::conflict::{ProofOfDoubleSpend, TransactionFingerprint};
use crate::models::profile::{TransactionBundleHeader, UserIdentity, VoucherStore};
use crate::models::voucher::Voucher;
use crate::services::conflict_manager;
use crate::wallet::instance::VoucherStatus;
use crate::wallet::{DoubleSpendCheckResult, Wallet};
use std::collections::HashMap;

impl Wallet {
    /// Scans all own vouchers and updates the `own_fingerprints` store.
    /// IMPORTANT: This function preserves already imported `foreign_fingerprints`.
    ///
    /// # V2 Protocol (Load-Time Purge)
    /// Persisted foreign fingerprints that fail the V2 signature gate (legacy
    /// V1 entries or tampered data) are dropped during the scan so they can
    /// never participate in instant-proof conflict resolution.
    pub fn scan_and_rebuild_fingerprints(&mut self) -> Result<(), VoucherCoreError> {
        let (own, mut known) = conflict_manager::scan_and_rebuild_fingerprints(
            &self.voucher_store,
            &self.profile.user_id,
        )?;
        // Preserve existing histories, as these cannot be (fully) reconstructed from the
        // local `voucher_store` (e.g. after archiving).
        let mut preserved_foreign =
            std::mem::take(&mut self.known_fingerprints.foreign_fingerprints);
        // SECURITY (V2): drop unauthenticated/legacy foreign fingerprints at load time.
        for (_, fps) in preserved_foreign.iter_mut() {
            fps.retain(|fp| {
                !conflict_manager::is_init_fingerprint(fp)
                    && conflict_manager::verify_fingerprint_signature(fp)
            });
        }
        preserved_foreign.retain(|_, fps| !fps.is_empty());
        known.foreign_fingerprints = preserved_foreign;

        // NEW: Also preserve/merge local_history
        let old_local_history = std::mem::take(&mut self.known_fingerprints.local_history);
        for (hash, fps) in old_local_history {
            let entry = known.local_history.entry(hash).or_default();
            for fp in fps {
                if !entry.iter().any(|e| e.t_id == fp.t_id) {
                    entry.push(fp);
                }
            }
        }

        self.own_fingerprints = own;
        self.known_fingerprints = known;
        Ok(())
    }

    /// Performs a full double-spend check.
    pub fn check_for_double_spend(&self) -> DoubleSpendCheckResult {
        conflict_manager::check_for_double_spend(&self.own_fingerprints, &self.known_fingerprints)
    }

    /// Imports and merges foreign fingerprints into storage.
    pub fn import_foreign_fingerprints(&mut self, data: &[u8]) -> Result<usize, VoucherCoreError> {
        conflict_manager::import_foreign_fingerprints(&mut self.known_fingerprints, data)
    }

    /// Imports an external proof into the ProofStore.
    ///
    /// # Security (authenticated import)
    /// Every import passes strict verification gates BEFORE any state change:
    /// 1. **Structural collision check** — at least two transactions sharing the
    ///    fork point, distinct t_ids and one identical recomputed ds_tag.
    /// 2. **Reporter signature** — must verify over `proof_id` with the key of
    ///    `reporter_id`.
    /// 3. **Proof-ID consistency** — `proof_id` is re-derived from
    ///    `(offender_id, fork_point_prev_hash)`.
    /// 4. **Attribution consistency (AUDIT-01-F05)** — if `offender_id` is a
    ///    did:key identity, the stored SST trap shards must verify against
    ///    it. Prevents forged attribution claims (framing).
    /// 5. **Cryptographic transaction verification** — if a matching voucher
    ///    exists locally, every conflicting transaction must pass integrity and
    ///    L2-signature checks; failures reject the proof entirely.
    ///
    /// If no local voucher context allows full cryptographic verification,
    /// the proof is stored as an *unverified witness note* WITHOUT any
    /// status mutation (no quarantine, no activation).
    ///
    /// # Immunity Rule (MVP):
    /// If the proof already exists locally, the import is ignored.
    /// This prevents external data from overwriting local decisions (overrides).
    pub fn import_proof(&mut self, mut proof: ProofOfDoubleSpend) -> Result<(), VoucherCoreError> {
        if self.proof_store.proofs.contains_key(&proof.proof_id) {
            // Already known -> Ignore (immunity of local decisions)
            return Ok(());
        }

        // --- SECURITY GATE 0 (HMSEC-SA06-12): neutralize unverifiable L2 verdicts ---
        //
        // A `Layer2Verdict` arriving through the proof-import channel carries
        // no trusted-server context: its `server_signature` cannot be checked
        // against a configured authority key here. Accepting it verbatim would
        // let any peer flip `check_reputation` to `Resolved` with a bogus
        // verdict (reputation laundering). Authoritative verdicts enter the
        // wallet exclusively via the authenticated gateway path
        // (`l2_gateway::process_l2_verdict`, trusted server pubkey), so any
        // verdict on the import path is stripped before it can influence
        // trust status.
        if proof.layer2_verdict.is_some() {
            log::warn!(
                "Imported proof '{}': dropping unverifiable layer2_verdict (no trusted server context on the import path).",
                proof.proof_id
            );
            proof.layer2_verdict = None;
        }

        // --- SECURITY GATE 0b (HMSEC-SA06-13): bind or neutralize the advisory ---
        //
        // `suspected_identity` is advisory metadata that is NOT covered by
        // `reporter_signature` (which signs only `proof_id`). For proofs with
        // `ephemeral:`/anonymous offenders the attribution gate below is
        // skipped entirely, so an in-transit attacker could otherwise inject
        // an arbitrary innocent third-party DID into the trusted conflict UI.
        // Documented semantics: the advisory may only mirror the offender_id
        // upon cryptographically verified extraction. Anything else in
        // transit is untrustworthy and is neutralized to `None`.
        if let Some(suspect) = &proof.suspected_identity
            && *suspect != proof.offender_id
        {
            log::warn!(
                "Imported proof '{}': neutralizing unbound advisory suspected_identity (not covered by reporter_signature).",
                proof.proof_id
            );
            proof.suspected_identity = None;
        }

        // --- SECURITY GATE 1-3: structure, reporter signature, proof id ---
        conflict_manager::verify_proof_structure(&proof)?;
        conflict_manager::verify_reporter_signature(&proof)?;
        let expected_proof_id = conflict_manager::derive_proof_id(
            &proof.offender_id,
            &proof.fork_point_prev_hash,
        )?;
        if expected_proof_id != proof.proof_id {
            return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                "Cannot import proof: proof_id is inconsistent with offender/fork-point data."
                    .to_string(),
             }));
        }

        // --- SECURITY GATE 3b (AUDIT-01-F05): attribution-consistency check ---
        //
        // The anti-framing invariant documented on
        // `ProofOfDoubleSpend.offender_id` states that a did:key identity may
        // only be claimed when the stored SST trap shards verify against the
        // mathematically extracted identity point. Creation time enforces
        // this (`verify_and_create_proof`); without this gate an importer
        // would trust the claim blindly, letting a real double-spender frame
        // any innocent did:key identity with a cryptographically genuine
        // report. Anonymous and `ephemeral:` fallback identifiers carry no
        // attribution claim and skip this gate.
        #[cfg(feature = "test-utils")]
        let bypass_active = crate::is_signature_bypass_active();
        #[cfg(not(feature = "test-utils"))]
        let bypass_active = false;

        if !bypass_active {
            let offender_pk = crate::services::crypto::get_pubkey_from_user_id(
                &proof.offender_id,
            );
            if let Ok(offender_pk) = offender_pk {
                use curve25519_dalek::edwards::CompressedEdwardsY;
                let claimed_point = CompressedEdwardsY::from_slice(offender_pk.as_bytes())
                    .ok()
                    .and_then(|c| c.decompress())
                    .ok_or_else(|| {
                        crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                            "Cannot import proof: offender identity point is not a valid curve point."
                                .to_string(),
                         })
                    })?;
                // V3 SST (AUDIT-01-F05): EUF-CMA-bound attribution, no prefix
                // ambiguity. The colliding shards must reconstruct a valid Schnorr
                // signature for exactly the claimed identity point; anything else
                // is a framing attempt and rejects the whole proof.
                let mut verified = false;
                let mut last_err: Option<VoucherCoreError> = None;
                match crate::services::trap_manager::verify_stored_trap_shards_against_identity(
                    &proof.conflicting_transactions,
                    &claimed_point,
                ) {
                    Ok(()) => {
                        verified = true;
                    }
                    Err(e) => last_err = Some(e),
                }
                if !verified {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: format!(
                        "Cannot import proof: did:key offender claim failed trap-proof verification ({}).",
                        last_err.map(|e| e.to_string()).unwrap_or_default()
                    ) }));
                }
            } else if let Some(claimed_eph) = proof.offender_id.strip_prefix("ephemeral:") {
                // SECURITY GATE 3c (AUDIT-W4-TRAP-201): ephemeral attribution gate.
                // When a proof claims an ephemeral key as offender, all conflicting
                // transactions under that claim must carry valid V3 layer2_signatures
                // under the claimed ephemeral public key. Unverified claims must never
                // gain persistent offender linkage.
                let eph_pub_bytes = crate::services::crypto::decode_bs58_fixed::<32>(
                    claimed_eph,
                    "claimed_eph",
                )
                .map_err(|_| {
                    crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                            "Cannot import proof: invalid ephemeral pubkey encoding in offender_id.".to_string(),
                         })
                })?;
            let ephem_key = ed25519_dalek::VerifyingKey::from_bytes(&eph_pub_bytes)
            .map_err(|_| {
                crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                    "Cannot import proof: invalid ephemeral pubkey in offender_id.".to_string(),
                 })
            })?;

            for tx in &proof.conflicting_transactions {
                if tx.sender_ephemeral_pub.as_deref() != Some(claimed_eph) {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                        "Cannot import proof: conflicting transaction sender_ephemeral_pub does not match claimed ephemeral offender.".to_string(),
                     }));
                }
                let sig_str = tx.layer2_signature.as_ref().ok_or_else(|| {
                    crate::Error::Wallet(crate::error::WalletError::MissingLayer2Signature)
                })?;
                let sig_bytes = crate::services::crypto::decode_bs58_fixed::<64>(
                    sig_str,
                    "layer2_signature",
                )
                .map_err(|_| {
                    crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                            "Cannot import proof: invalid layer2_signature encoding.".to_string(),
                         })
                })?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                let t_id_32 = crate::services::crypto::decode_bs58_fixed::<32>(&tx.t_id, "t_id")
                    .map_err(|_| {
                        crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                            "Cannot import proof: invalid t_id encoding.".to_string(),
                         })
                    })?;
                let ephem_pub_32: [u8; 32] = eph_pub_bytes;

                let challenge_ds_tag = if tx.t_type == "init" {
                    tx.t_id.clone()
                } else if let Some(td) = &tx.trap_data {
                    td.ds_tag.clone()
                } else {
                    tx.prev_hash.clone()
                };
                let (trap_r_str, trap_s_str) = match &tx.trap_data {
                    Some(td) => (td.trap_r.as_str(), td.trap_s.as_str()),
                    None => (
                        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
                        crate::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
                    ),
                };
                let encrypted_timestamp = if let Ok(raw_ts) = tx.t_time.parse::<u128>() {
                    raw_ts
                } else {
                    crate::services::conflict_manager::encrypt_transaction_timestamp(tx)?
                };
                let deletable_at = if tx.t_type == "init" {
                    tx.deletable_at.as_deref()
                } else {
                    None
                };
                let guard_commitment = crate::services::l2_gateway::privacy_guard_commitment(
                    tx.privacy_guard.as_deref(),
                );

                let candidates = ["", "none"];
                let valid = candidates.iter().any(|&vid| {
                    let payload_hash = crate::services::l2_gateway::calculate_l2_payload_hash_raw(
                        if tx.t_type == "init" { "none" } else { vid },
                        &challenge_ds_tag,
                        &t_id_32,
                        &ephem_pub_32,
                        trap_r_str,
                        trap_s_str,
                        encrypted_timestamp,
                        deletable_at,
                        &guard_commitment,
                    );
                    crate::services::crypto::verify_ed25519(&ephem_key, &payload_hash, &signature)
                });

                if !valid {
                    return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                        "Cannot import proof: conflicting transaction failed layer2_signature verification under claimed ephemeral offender.".to_string(),
                     }));
                }
            }
        }
    }

        // --- SECURITY GATE 4: cryptographically verify conflicting transactions ---
        let mut layer2_voucher_id: Option<String> = None;
        for tx in &proof.conflicting_transactions {
            if let Ok(Some(voucher)) =
                self.find_voucher_for_transaction(&tx.t_id, None)
                && let Ok(vid) = crate::services::l2_gateway::extract_layer2_voucher_id(&voucher)
            {
                layer2_voucher_id = Some(vid);
                break;
            }
        }

        enum VerificationOutcome {
            FullyVerified,
            NoLocalContext,
        }
        let outcome = match &layer2_voucher_id {
            Some(vid) => {
                for tx in &proof.conflicting_transactions {
                    if crate::services::voucher_validation::verify_transaction_integrity_and_signature(tx, vid).is_err() {
                        // A locally verifiable transaction that fails its
                        // integrity/L2 checks proves tampering -> hard reject.
                        return Err(crate::Error::Wallet(crate::error::WalletError::InvariantViolation { message: 
                            "Cannot import proof: conflicting transaction failed integrity/L2-signature verification.".to_string(),
                         }));
                    }
                }
                VerificationOutcome::FullyVerified
            }
            None => {
                log::warn!(
                    "Imported proof '{}': no local voucher context for cryptographic verification; storing as unverified witness note (no status mutation).",
                    proof.proof_id
                );
                VerificationOutcome::NoLocalContext
            }
        };

        // --- Conflict resolution (determine offline winner and quarantine losers) ---
        // Only executed for fully verified proofs; unverified witness notes
        // must never mutate local voucher states.
        let mut winner_tx_id: Option<String> = None;
        let mut earliest_dt: Option<chrono::DateTime<chrono::FixedOffset>> = None;

        for tx in &proof.conflicting_transactions {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&tx.t_time) {
                match earliest_dt {
                    None => {
                        earliest_dt = Some(dt);
                        winner_tx_id = Some(tx.t_id.clone());
                    }
                    Some(e_dt) if dt < e_dt => {
                        earliest_dt = Some(dt);
                        winner_tx_id = Some(tx.t_id.clone());
                    }
                    _ => {}
                }
            }
        }

        let tx_ids: std::collections::HashSet<_> = proof.conflicting_transactions.iter().map(|tx| &tx.t_id).collect();
        let mut quarantined_events = Vec::new();

        if let (VerificationOutcome::FullyVerified, Some(winner_id)) = (&outcome, winner_tx_id) {
            for instance in self.voucher_store.vouchers.values_mut() {
                if let Some(tx) = instance
                    .voucher
                    .transactions
                    .iter()
                    .find(|tx| tx_ids.contains(&tx.t_id))
                {
                    let prev_status = instance.status.clone();
                    instance.status = if tx.t_id == winner_id {
                        VoucherStatus::Active
                    } else {
                        VoucherStatus::Quarantined {
                            reason: "Lost race in imported proof".to_string(),
                        }
                    };
                    if !matches!(prev_status, VoucherStatus::Quarantined { .. })
                        && matches!(instance.status, VoucherStatus::Quarantined { .. })
                    {
                        let bff_data = crate::models::wallet_event::EventBffData {
                            display_currency: super::super::format_bff_name(
                                instance.voucher.nominal_value.abbreviation.as_deref().unwrap_or(&instance.voucher.nominal_value.unit),
                                instance.voucher.non_redeemable_test_voucher,
                            ),
                            amount: instance.voucher.nominal_value.amount.clone(),
                            is_test_voucher: instance.voucher.non_redeemable_test_voucher,
                            counterparty_id: None,
                            counterparty_name: None,
                        };
                        quarantined_events.push((
                            instance.local_instance_id.clone(),
                            instance.voucher.voucher_id.clone(),
                            bff_data,
                        ));
                    }
                }
            }
        }

        // Record emitted VoucherQuarantined events into pending_events.
        for (local_id, voucher_id, bff_data) in quarantined_events {
            self.emit_event(
                crate::models::wallet_event::WalletEventType::VoucherQuarantined,
                &local_id,
                &voucher_id,
                bff_data,
            );
        }

        // --- Role determination (victim vs. witness) ---
        // REFINEMENT: We are only a victim if we have NO active voucher for this
        // conflict tag, but at least one exists (which is now in quarantine).
        let mut has_active = false;
        let mut has_quarantined = false;
        
        for tx in &proof.conflicting_transactions {
            if let Some(instance) = self.find_local_voucher_by_tx_id(&tx.t_id) {
                if matches!(instance.status, VoucherStatus::Active) {
                    has_active = true;
                } else if matches!(instance.status, VoucherStatus::Quarantined { .. }) {
                    has_quarantined = true;
                }
            }
        }
        
        let conflict_role = if has_quarantined && !has_active {
            crate::models::conflict::ConflictRole::Victim
        } else {
            crate::models::conflict::ConflictRole::Witness
        };

        let entry = crate::models::conflict::ProofStoreEntry {
            proof,
            local_override: false,
            local_note: None,
            conflict_role,
        };

        // SECURITY (AUDIT-00-WILDCARD-42): Enforce upper bound on stored proofs to prevent memory bloat DoS
        const MAX_PROOFS: usize = 1000;
        if self.proof_store.proofs.len() >= MAX_PROOFS && !self.proof_store.proofs.contains_key(&entry.proof.proof_id) {
            // Evict the oldest proof by report_timestamp
            let oldest_id = self
                .proof_store
                .proofs
                .iter()
                .min_by_key(|(_, e)| e.proof.report_timestamp.as_str())
                .map(|(k, _)| k.clone());
            if let Some(id) = oldest_id {
                self.proof_store.proofs.remove(&id);
            }
        }

        self.proof_store.proofs.insert(entry.proof.proof_id.to_string(), entry);
        Ok(())
    }

    /// Verifies a conflict and creates a proof. Internal method.
    pub(crate) fn verify_and_create_proof(
        &self,
        identity: &UserIdentity,
        fingerprints: &[TransactionFingerprint],
        archive: Option<&FileVoucherArchive>,
    ) -> Result<Option<crate::models::conflict::ProofOfDoubleSpend>, VoucherCoreError> {
        let mut conflicting_transactions = Vec::new();
        let mut missing_t_ids = Vec::new();
        // V2 Protocol: canonical `ephemeral:<pub>` offender claim produced by
        // the pure-gossip branch (see below).
        let mut gossip_offender_override: Option<String> = None;

        // 1. Find the complete transactions corresponding to the fingerprints.
        for fp in fingerprints {
            if let Some(tx) = self.find_transaction_in_stores(&fp.t_id, archive)? {
                conflicting_transactions.push(tx);
            } else {
                missing_t_ids.push(fp.t_id.clone());
            }
        }

        if conflicting_transactions.is_empty() {
            // FIX: For pure gossip conflicts, the local wallet never has the transactions
            // in its store. If we have >= 2 fingerprints with distinct
            // t_ids, we can still create a "Gossip Soft Proof".
            //
            // V2/V3 Protocol (Instant Gossip Proofs): incoming fingerprints were
            // already authenticated at ingress (valid layer2_signature over
            // the canonical digest by the named ephemeral key). We therefore build
            // FULL synthetic placeholder transactions carrying the revealed
            // key and the SST trap shards (shards travel with the gossip
            // fingerprints) so that:
            // - the soft proofs pass `verify_proof_structure` on import, and
            // - a did:key attribution claim is only upheld when TWO colliding
            //   shards reconstruct a valid Schnorr signature for it
            //   (EUF-CMA-bound), keeping the anti-framing invariant intact.
            //
            // ATTRIBUTION HIERARCHY (AUDIT-01-F05): the canonical offender
            // identifier for instant gossip proofs is the unforgeable
            // ephemeral-key linkage `ephemeral:<sender_ephemeral_pub>`. A
            // mathematically extracted did:key identity is recorded ONLY as
            // advisory `suspected_identity` until full transaction chains
            // with verifiable Schnorr ZKPs are imported.
            if fingerprints.len() >= 2 {
                let unique_t_ids: std::collections::HashSet<_> =
                    fingerprints.iter().map(|fp| &fp.t_id).collect();
                if unique_t_ids.len() >= 2 {
                    let eph_pubs: std::collections::HashSet<&String> = fingerprints
                        .iter()
                        .map(|fp| &fp.sender_ephemeral_pub)
                        .collect();
                    // A genuine fork shares one input key per ds_tag; diverging
                    // keys would make a single linkage claim ambiguous.
                    let canonical_eph = if eph_pubs.len() == 1 {
                        Some((*eph_pubs.iter().next().unwrap()).clone())
                    } else {
                        None
                    };
                    let offender_id = canonical_eph
                        .as_ref()
                        .map(|p| format!("ephemeral:{}", p))
                        .unwrap_or_else(|| crate::models::voucher::ANONYMOUS_ID.to_string());

                    // Use ds_tag as a proxy for fork_point_prev_hash,
                    // as the actual prev_hash is not available.
                    let fork_point_prev_hash = fingerprints[0].ds_tag.clone();

                    for fp in fingerprints {
                        let synthetic_tx = crate::models::voucher::Transaction {
                            t_id: fp.t_id.clone(),
                            sender_id: None,
                            prev_hash: fork_point_prev_hash.clone(),
                            t_type: "gossip_soft_placeholder".to_string(),
                            amount: "0.00 (Gossip)".to_string(),
                            sender_ephemeral_pub: Some(fp.sender_ephemeral_pub.clone()),
                            layer2_signature: Some(fp.layer2_signature.clone()),
                            trap_data: Some(crate::models::voucher::TrapData {
                                ds_tag: fp.ds_tag.clone(),
                                trap_r: fp.trap_r.clone(),
                                trap_s: fp.trap_s.clone(),
                            }),
                            t_time: fp.encrypted_timestamp.to_string(),
                            ..Default::default()
                        };
                        conflicting_transactions.push(synthetic_tx);
                    }

                    // Skip missing generation (all already covered)
                    missing_t_ids.clear();

                    // Store for the attribution hierarchy below.
                    gossip_offender_override = Some(offender_id);
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }

        // 2. Extract core data from the FIRST found transaction.
        let mut offender_id = conflicting_transactions[0]
            .sender_id
            .clone()
            .unwrap_or(crate::models::voucher::ANONYMOUS_ID.to_string());

        // V2 Protocol: pure-gossip conflicts carry the unforgeable
        // `ephemeral:<sender_ephemeral_pub>` linkage as the canonical
        // offender identifier (set by the branch above).
        if let Some(eph_claim) = &gossip_offender_override {
            offender_id = eph_claim.clone();
        }

        // SECURITY (AUDIT-01-F08, false dispute injection): The >=2 verified
        // trap proofs anti-framing invariant applies to EVERY did:key
        // attribution claim — not only to the extraction branch below.
        // `conflicting_transactions[0].sender_id` originates from locally
        // held chain data whose SIBLING fork may be an unauthenticated gossip
        // fingerprint (a fabricated t_id colliding with a publicly derivable
        // ds_tag). Persisting the did:key verbatim would let any peer inject
        // a false dispute naming an arbitrary identity (typically the wallet
        // owner itself). If the stored trap proofs do not verify against the
        // claimed point, the claim is downgraded to ANONYMOUS and the
        // conservative extraction/ephemeral fallbacks below proceed
        // unchanged. Non-did:key identifiers carry no attribution claim and
        // are left untouched.
        if offender_id != crate::models::voucher::ANONYMOUS_ID
            && let Ok(claimed_pk) =
                crate::services::crypto::get_pubkey_from_user_id(&offender_id)
        {
            {
                use curve25519_dalek::edwards::CompressedEdwardsY;
                let attributed = CompressedEdwardsY::from_slice(claimed_pk.as_bytes())
                    .ok()
                    .and_then(|c| c.decompress())
                    .map(|claimed_point| {
                        // V3 SST (AUDIT-01-F08): single prefix-free gate — the
                        // colliding shards must reconstruct a valid Schnorr
                        // signature for exactly the claimed identity point.
                        crate::services::trap_manager::
                            verify_stored_trap_shards_against_identity(
                                &conflicting_transactions,
                                &claimed_point,
                            )
                            .is_ok()
                    })
                    .unwrap_or(false);
                if !attributed {
                    offender_id = crate::models::voucher::ANONYMOUS_ID.to_string();
                }
            }
        }

        let real_txs: Vec<&crate::models::voucher::Transaction> = conflicting_transactions
            .iter()
            .filter(|t| !t.t_type.contains("placeholder"))
            .collect();

        // 3. Attempt L2 verification for all available transactions.
        // (Moved BEFORE de-anonymization so attribution can rely on it.)
        let mut l2_verified_count = 0usize;
        let mut voucher_valid_until = "unknown".to_string();
        let mut affected_voucher_name = None;
        let mut voucher_standard_uuid = None;
        let mut is_test_voucher = false;

        let context_voucher = conflicting_transactions.iter().find_map(|tx| {
            self.find_voucher_for_transaction(&tx.t_id, archive)
                .ok()
                .flatten()
        });

        let l2_all_verified = if let Some(voucher) = &context_voucher {
            voucher_valid_until = voucher.valid_until.clone();
            affected_voucher_name = Some(voucher.voucher_standard.name.clone());
            voucher_standard_uuid = Some(voucher.voucher_standard.uuid.clone());
            is_test_voucher = voucher.non_redeemable_test_voucher;

            if let Ok(layer2_voucher_id) = crate::services::l2_gateway::extract_layer2_voucher_id(voucher) {
                for tx in &real_txs {
                    if crate::services::voucher_validation::verify_transaction_integrity_and_signature(
                        tx,
                        &layer2_voucher_id,
                    )
                    .is_ok()
                    {
                        l2_verified_count += 1;
                    }
                }
            }
            !real_txs.is_empty() && l2_verified_count == real_txs.len()
        } else {
            false
        };

        // --- MATHEMATICAL DE-ANONYMIZATION (V3 SST, anti-framing hardened) ---
        // Two colliding spend shards linearly reconstruct the underlying
        // Schnorr signature; its challenge binds the result to exactly one
        // public key. Attributing any other identity would constitute an
        // EUF-CMA forgery, so a successful autonomous extraction IS the
        // proof: it directly sets the definitive did:key offender identity
        // (mirrored as advisory `suspected_identity`). Without a successful
        // extraction the canonical `ephemeral:` linkage fallback applies.
        let mut suspected_identity: Option<String> = None;
        if fingerprints.len() >= 2 {
            // SECURITY (AUDIT-01-F16): deterministic pair evaluation. The
            // bucket order is canonical (sorted by t_id in
            // check_for_double_spend); attribution tries every colliding
            // pair in that canonical order and takes the FIRST successful
            // extraction instead of relying on positional members [0]/[1].
            // With >= 3 members (genuine forks + attacker-broadcast off-line
            // shards) the outcome is now a deterministic function of the
            // evidence set. Genuine multi-fork collisions (all shards on one
            // line) yield the same identity for every pair, so first-match
            // remains exact there.
            'extraction: for i in 0..fingerprints.len() {
                for j in (i + 1)..fingerprints.len() {
                    let f1 = &fingerprints[i];
                    let f2 = &fingerprints[j];
                    // Only genuine spend shards participate (genesis/legacy
                    // entries excluded); a genuine fork shares one input key,
                    // so diverging or missing ephemeral keys disqualify the
                    // pair (they make any linkage claim ambiguous).
                    if conflict_manager::is_init_fingerprint(f1)
                        || conflict_manager::is_init_fingerprint(f2)
                        || f1.sender_ephemeral_pub.is_empty()
                        || f1.sender_ephemeral_pub != f2.sender_ephemeral_pub
                    {
                        continue;
                    }
                    // mu derives from fingerprint data alone (ds_tag binds
                    // prev_hash), enabling fully autonomous extraction from
                    // gossip without transaction chains.
                    let Ok(eph) = crate::services::crypto::decode_bs58_fixed::<32>(
                        &f1.sender_ephemeral_pub,
                        "sender_ephemeral_pub",
                    ) else {
                        continue;
                    };
                    if let Ok(point) = crate::services::trap_manager::extract_sst_identity(
                        &f1.ds_tag,
                        &eph,
                        f1,
                        f2,
                    ) {
                        let pk_bytes = point.compress().to_bytes();
                        if let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
                            && let Ok(did_id) =
                                crate::services::crypto::create_user_id(&pk, None)
                        {
                            suspected_identity = Some(did_id.clone());
                            // V3 SST: extraction IS the proof (EUF-CMA) —
                            // definitive attribution that overrides any
                            // earlier heuristic/downgraded identifier.
                            offender_id = did_id;
                            break 'extraction;
                        }
                    }
                }
            }

            // Canonical fallback: ephemeral-key linkage over valid L2 signatures
            // (only when no cryptographic identity extraction succeeded).
            if suspected_identity.is_none()
                && offender_id == crate::models::voucher::ANONYMOUS_ID
                && l2_all_verified
            {
                let eph_pubs: std::collections::HashSet<&String> = real_txs
                    .iter()
                    .filter_map(|tx| tx.sender_ephemeral_pub.as_ref())
                    .collect();
                if eph_pubs.len() == 1 {
                    offender_id = format!("ephemeral:{}", eph_pubs.iter().next().unwrap());
                }
            }
        }

        let fork_point_prev_hash = conflicting_transactions[0].prev_hash.clone();

        for t_id in missing_t_ids {
            let synthetic_tx = crate::models::voucher::Transaction {
                t_id,
                sender_id: Some(offender_id.clone()),
                prev_hash: fork_point_prev_hash.clone(),
                t_type: "soft_placeholder".to_string(),
                amount: "0.00 (Synthetic)".to_string(),
                ..Default::default()
            };
            conflicting_transactions.push(synthetic_tx);
        }

        // 6. Create the proof object.
        // IMPORTANT: We NOW ALWAYS create the proof if we have >= 2 candidates,
        // even if they could not be fully cryptographically verified ("Soft Proof").
        if conflicting_transactions.len() < 2 {
            return Ok(None);
        }

        let mut proof = conflict_manager::create_proof_of_double_spend(
            offender_id,
            fork_point_prev_hash,
            conflicting_transactions,
            voucher_valid_until,
            identity,
            is_test_voucher,
        )?;

        // Set metadata
        proof.affected_voucher_name = affected_voucher_name;
        proof.voucher_standard_uuid = voucher_standard_uuid;
        proof.suspected_identity = suspected_identity;

        // If we already know the proof and have an L2 verdict or resolutions, adopt them!
        if let Some(existing_entry) = self.proof_store.proofs.get(&proof.proof_id) {
            proof.layer2_verdict = existing_entry.proof.layer2_verdict.clone();
            proof.resolutions = existing_entry.proof.resolutions.clone();
        }

        Ok(Some(proof))
    }

    /// Internal helper function for Layer 2 replay protection.
    ///
    /// Checks the fingerprints of the latest transactions of all incoming vouchers
    /// in a bundle against the entire known fingerprint history of the wallet.
    ///
    /// # Errors
    /// Returns `VoucherCoreError::TransactionFingerprintAlreadyKnown` if
    /// one of the fingerprints is already present in `own_fingerprints` or `known_fingerprints`
    /// (both `local_history` and `foreign_fingerprints`) AND
    /// the `t_id` also matches (replay attack).
    ///
    /// A double-spend (same `fingerprint_hash`, but NEW `t_id`) is
    /// *intentionally permitted* so that it can be handled by the downstream
    /// conflict resolution logic ("Earliest Wins").
    pub(crate) fn check_bundle_fingerprints_against_history(
        &self,
        vouchers: &[Voucher],
    ) -> Result<(), VoucherCoreError> {
        for voucher in vouchers {
            let last_tx = voucher.transactions.last().ok_or_else(|| {
                VoucherCoreError::Validation(ValidationError::ReceivedVoucherHasNoTransactions)
            })?;

            // Calculate the relevant fingerprint (the "collision ID")
            let fingerprint =
                conflict_manager::create_fingerprint_for_transaction(last_tx, voucher)?;
            let fingerprint_hash = fingerprint.ds_tag;

            // --- CORRECTED LOGIC: Distinguish replay vs. double spend ---

            // 1. Collect all known t_ids for this fingerprint hash (3-way helper)
            let known_t_ids: std::collections::HashSet<&String> = self
                .fingerprints_for_tag(&fingerprint_hash)
                .map(|fp| &fp.t_id)
                .collect();

            // 2. Check if the fingerprint hash is known at all.
            if !known_t_ids.is_empty() {
                // The fingerprint hash is known.
                // 3. Check if the *specific t_id* is also known.
                let incoming_t_id = &last_tx.t_id;

                if known_t_ids.contains(incoming_t_id) {
                    // --- CASE A (True replay) ---
                    // We have seen THIS EXACT transaction (same hash, same t_id)
                    // before. This is a replay attack.
                    return Err(VoucherCoreError::TransactionFingerprintAlreadyKnown {
                        fingerprint_hash,
                    });
                }
                // --- CASE B (Double spend) ---
                // The hash is known, but the t_id is NEW.
                // This is a double spend. We let it pass so that
                // the "Earliest Wins" heuristic can catch it.
            }
        }

        Ok(())
    }

    /// Processes received fingerprints (active and implicit) and updates gossip queues and archives.
    pub(crate) fn process_received_fingerprints(
        &mut self,
        _bundle_header: &TransactionBundleHeader,
        vouchers: &[Voucher],
        forwarded_fingerprints: &[TransactionFingerprint],
        quarantine_pairs: &[[TransactionFingerprint; 2]],
    ) -> Result<(), VoucherCoreError> {
        // --- Ingress Firewall: Hard rejection if quarantine pairs exceed V * 3 ---
        let max_allowed_q_pairs = vouchers.len() * 3;
        if quarantine_pairs.len() > max_allowed_q_pairs {
            return Err(VoucherCoreError::Validation(
                ValidationError::SecurityViolation(format!(
                    "Ingress rejected: quarantine pairs ({}) exceed maximum allowed ratio of 3 pairs per voucher ({})",
                    quarantine_pairs.len(),
                    max_allowed_q_pairs
                )),
            ));
        }

        // --- Phase 1: Incoming Vouchers (DirectQueue for Tx_N, Archive for predecessors) ---
        for voucher in vouchers {
            let tx_count = voucher.transactions.len();
            if tx_count == 0 {
                continue;
            }
            // Tip transaction Tx_N -> DirectQueue
            let last_tx = &voucher.transactions[tx_count - 1];
            let tip_fp = conflict_manager::create_fingerprint_for_transaction(last_tx, voucher)?;
            if !conflict_manager::is_init_fingerprint(&tip_fp) {
                // Deduplicate in direct_queue
                if !self.active_gossip.direct_queue.iter().any(|d| d.fingerprint.t_id == tip_fp.t_id) {
                    const MAX_DIRECT_QUEUE: usize = 1000;
                    if self.active_gossip.direct_queue.len() >= MAX_DIRECT_QUEUE {
                        self.active_gossip.direct_queue.pop_front();
                    }
                    self.active_gossip.direct_queue.push_back(
                        crate::models::conflict::DirectEntry {
                            fingerprint: tip_fp.clone(),
                            sent_to: Vec::new(),
                        },
                    );
                }
            }

            // All transactions (Tip + older) are added to local_history archive
            for tx in &voucher.transactions {
                let fp = conflict_manager::create_fingerprint_for_transaction(tx, voucher)?;
                let entry = self
                    .known_fingerprints
                    .local_history
                    .entry(fp.ds_tag.clone())
                    .or_default();
                if !entry.iter().any(|e| e.t_id == fp.t_id) {
                    entry.push(fp);
                }
            }
        }

        // --- Phase 2: Foreign Gossip -> FreshGossipPool ---
        let mut local_input_keys: HashMap<String, std::collections::HashSet<String>> =
            HashMap::new();
        let mut record_local_key = |tag: &str, eph_pub: &str| {
            local_input_keys
                .entry(tag.to_string())
                .or_default()
                .insert(eph_pub.to_string());
        };
        for instance in self.voucher_store.vouchers.values() {
            for tx in &instance.voucher.transactions {
                if let Some(trap) = &tx.trap_data
                    && let Some(eph) = &tx.sender_ephemeral_pub
                {
                    record_local_key(&trap.ds_tag, eph);
                }
            }
        }
        for source in [
            &self.own_fingerprints.active_fingerprints,
            &self.own_fingerprints.history,
            &self.known_fingerprints.local_history,
        ] {
            for (tag, fps) in source.iter() {
                for fp in fps {
                    record_local_key(tag, &fp.sender_ephemeral_pub);
                }
            }
        }

        let mut current_total_foreign: usize = self
            .known_fingerprints
            .foreign_fingerprints
            .values()
            .map(|v| v.len())
            .sum();

        for fp in forwarded_fingerprints {
            if conflict_manager::is_init_fingerprint(fp)
                || !conflict_manager::verify_fingerprint_signature(fp)
                || fp.trap_r == conflict_manager::VOID_SPEND_SHARD_MARKER
                || fp.trap_s == conflict_manager::VOID_SPEND_SHARD_MARKER
            {
                continue;
            }
            if let Some(keys) = local_input_keys.get(&fp.ds_tag) {
                if !keys.contains(&fp.sender_ephemeral_pub) {
                    continue;
                }
            }

            let mut fp_admitted = fp.clone();
            conflict_manager::assign_local_retention_to_wire_entry(&mut fp_admitted);

            // Push to FreshGossipPool for 70% lottery on future payments (bounded FIFO)
            const MAX_FRESH_GOSSIP_POOL: usize = 3000;
            while self.active_gossip.fresh_gossip_pool.len() >= MAX_FRESH_GOSSIP_POOL {
                self.active_gossip.fresh_gossip_pool.pop_front();
            }
            self.active_gossip.fresh_gossip_pool.push_back(fp_admitted.clone());

            // Also persist to foreign_fingerprints archive under caps
            if current_total_foreign < conflict_manager::MAX_TOTAL_FOREIGN_FINGERPRINTS {
                let entry = self
                    .known_fingerprints
                    .foreign_fingerprints
                    .entry(fp_admitted.ds_tag.clone())
                    .or_default();
                if entry.len() < conflict_manager::MAX_FOREIGN_BUCKET_CAP {
                    let is_exact_duplicate = entry.iter().any(|existing| {
                        existing.t_id == fp_admitted.t_id
                            && existing.trap_r == fp_admitted.trap_r
                            && existing.trap_s == fp_admitted.trap_s
                            && existing.encrypted_timestamp == fp_admitted.encrypted_timestamp
                            && existing.layer2_signature == fp_admitted.layer2_signature
                            && existing.privacy_guard_hash == fp_admitted.privacy_guard_hash
                    });
                    if !is_exact_duplicate {
                        entry.push(fp_admitted);
                        current_total_foreign += 1;
                    }
                }
            }
        }

        // --- Phase 3: Quarantine Pairs -> QuarantineRelayPool & Double-Spend Verification ---
        for pair in quarantine_pairs {
            let f1 = &pair[0];
            let f2 = &pair[1];
            if f1.ds_tag != f2.ds_tag || f1.t_id == f2.t_id {
                continue;
            }
            if conflict_manager::is_init_fingerprint(f1) || conflict_manager::is_init_fingerprint(f2) {
                continue;
            }
            if !conflict_manager::verify_fingerprint_signature(f1) || !conflict_manager::verify_fingerprint_signature(f2) {
                continue;
            }
            let Ok(eph) = crate::services::crypto::decode_bs58_fixed::<32>(
                &f1.sender_ephemeral_pub,
                "sender_ephemeral_pub",
            ) else {
                continue;
            };
            if let Ok(point) = crate::services::trap_manager::extract_sst_identity(
                &f1.ds_tag,
                &eph,
                f1,
                f2,
            ) {
                let pk_bytes = point.compress().to_bytes();
                // ARCHITECTURE (KISS-Gossip): `_did_id_opt` is verified cryptographically here.
                // We deliberately do not store it as redundant state in ActiveGossipState/QuarantineEntry;
                // the gossip relay only propagates minimal raw colliding pairs [f1, f2], and every
                // node can deterministically reconstruct the offender DID on-demand via `extract_sst_identity`.
                let _did_id_opt = if let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
                    crate::services::crypto::create_user_id(&pk, None).ok()
                } else {
                    None
                };

                let mut p0 = f1.clone();
                let mut p1 = f2.clone();
                conflict_manager::assign_local_retention_to_wire_entry(&mut p0);
                conflict_manager::assign_local_retention_to_wire_entry(&mut p1);

                const MAX_QUARANTINE_RELAY_POOL: usize = 500;
                while self.active_gossip.quarantine_relay_pool.len() >= MAX_QUARANTINE_RELAY_POOL {
                    self.active_gossip.quarantine_relay_pool.pop_front();
                }
                self.active_gossip
                    .quarantine_relay_pool
                    .push_back([p0.clone(), p1.clone()]);

                // Also record in foreign fingerprints archive
                for p in [&p0, &p1] {
                    let entry = self
                        .known_fingerprints
                        .foreign_fingerprints
                        .entry(p.ds_tag.clone())
                        .or_default();
                    if !entry.iter().any(|e| e.t_id == p.t_id) {
                        entry.push(p.clone());
                    }
                }
            }
        }

        Ok(())
    }
}

/// Encapsulated offline conflict resolution via "Earliest Wins" heuristic.
///
/// # V3 SST Protocol — Instant Quarantine via Self-Authenticating Fingerprints
///
/// ## Threat Model Boundary (accepted residual risk)
/// Admission of FOREIGN fingerprints into the winner race is restricted to
/// entries carrying a valid `layer2_signature` over the canonical
/// `HMC_TX_AUTH_V3` digest. This strictly reduces the attacker class from
/// "any external peer in the P2P network" (AUDIT-01-F01) to **"actors who at
/// some point possessed the private ephemeral one-time key for this output"**
/// (e.g. the issuer or a previous holder). A former key holder can
/// technically produce signed sibling fingerprints, since they know the
/// signing secret. This is mathematically indistinguishable from a genuine
/// double spend (possession of the key = disposal authority) and matches the
/// core paradigm *„Fraud Detection, Not Prevention“*.
///
/// ARCHITECTURAL INVARIANT: Signed gossip collisions MUST immediately
/// quarantine the losing branch in real-time (milliseconds) without waiting
/// for megabyte-heavy transaction chains to arrive.
pub(crate) fn resolve_conflict_offline(
    voucher_store: &mut VoucherStore,
    fingerprints: &[crate::models::conflict::TransactionFingerprint],
) {
    let tx_ids: std::collections::HashSet<_> = fingerprints.iter().map(|fp| &fp.t_id).collect();

    // --- 1. Read phase: Find the winner without mutating the store ---
    let conflicting_txs: Vec<_> = voucher_store
        .vouchers
        .values()
        .flat_map(|inst| &inst.voucher.transactions)
        .filter(|tx| tx_ids.contains(&tx.t_id))
        .collect();

    if conflicting_txs.is_empty() {
        return;
    }

    // Since all conflicting transactions branch from the same fork point, they share the same prev_hash.
    let prev_hash = &conflicting_txs[0].prev_hash;

    // SECURITY (AUDIT-01-F01 + V3 evolution): Participation in the
    // "Earliest Wins" race requires either
    //  - a LOCALLY-held transaction (chain-backed trust), or
    //  - a FOREIGN fingerprint that is self-authenticating under the V3 SST
    //    protocol (non-init, i.e. genuine SST trap shards, AND a valid
    //    `layer2_signature` by the named ephemeral key). See the
    //    threat-model documentation above.
    let local_t_ids: std::collections::HashSet<&String> =
        conflicting_txs.iter().map(|tx| &tx.t_id).collect();

    let mut winner_id: Option<String> = None;
    let mut earliest_time = u128::MAX;

    // SECURITY (V2 hardening): a third party WITHOUT the input key can
    // produce a correctly signed fingerprint (naming their own ephemeral
    // key), but CANNOT control the decrypted timestamp: the XOR key derives
    // from the secret-to-them prev_hash + their t_id. Without a plausibility
    // bound, a random 128-bit value would win the race ~50% of the time,
    // resurrecting the AUDIT-01-F01 remote DoS through the signature gate.
    // Genuine forks are produced by holders of the input key who know
    // prev_hash and always embed near-wall-clock timestamps, so the window
    // below never rejects honest evidence (success probability for blind
    // grinding is ~window/2^128).
    let now_nanos = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_default() as u128;
    const CLOCK_SKEW_NANOS: u128 = 24 * 3600 * 1_000_000_000;
    let max_plausible_nanos = now_nanos.saturating_add(CLOCK_SKEW_NANOS);
    // SECURITY (AUDIT-01-F14 / lower bound): the plausibility argument is
    // SYMMETRIC — genuine forks embed near-wall-clock timestamps, so a
    // candidate dated far in the past is forged evidence as well. Without a
    // floor, any holder of the input key dates siblings to the Unix epoch
    // and unconditionally wins the race against every genuine branch.
    // Lookback aligns with the shortest standard validity range (P1Y), so
    // collisions inside one voucher's lifetime stay adjudicable here; older
    // evidence is still served by the gated proof-import path. Blind
    // grinding success within the window is ~window/2^128.
    const DEFAULT_LOOKBACK_NANOS: u128 = 365 * 24 * 3600 * 1_000_000_000;
    let earliest_local_tx_nanos = conflicting_txs
        .iter()
        .filter_map(|tx| {
            chrono::DateTime::parse_from_rfc3339(&tx.t_time)
                .ok()
                .and_then(|dt| dt.timestamp_nanos_opt())
                .map(|n| n as u128)
        })
        .min();
    let earliest_local_creation_nanos = voucher_store
        .vouchers
        .values()
        .filter(|inst| inst.voucher.transactions.iter().any(|tx| tx_ids.contains(&tx.t_id)))
        .filter_map(|inst| {
            chrono::DateTime::parse_from_rfc3339(&inst.voucher.creation_date)
                .ok()
                .and_then(|dt| dt.timestamp_nanos_opt())
                .map(|n| n as u128)
        })
        .min();
    let dynamic_baseline_nanos = earliest_local_tx_nanos
        .or(earliest_local_creation_nanos)
        .map(|t| t.min(now_nanos))
        .unwrap_or(now_nanos);
    let min_plausible_nanos = dynamic_baseline_nanos.saturating_sub(DEFAULT_LOOKBACK_NANOS);

    // SECURITY (V2 hardening, cryptographic consistency): a genuine sibling
    // fork shares the identical input, i.e. the claimed `sender_ephemeral_pub`
    // MUST recompute the collision tag under the locally-known fork
    // prev_hash: `ds_tag == H(prev_hash || sender_ephemeral_pub)`. A foreign
    // fingerprint naming any other key is cryptographically impossible for a
    // real spender (second-preimage resistance) and is rejected regardless
    // of its valid signature.
    fn reproduces_local_tag(
        fp: &crate::models::conflict::TransactionFingerprint,
        prev_hash: &str,
        conflicting_txs: &[&crate::models::voucher::Transaction],
    ) -> bool {
        let prev_ok = crate::services::crypto::decode_bs58_fixed::<32>(prev_hash, "prev_hash").is_ok();
        if !prev_ok {
            return false;
        }
        let Ok(eph_bytes) =
            crate::services::crypto::decode_bs58_fixed::<32>(&fp.sender_ephemeral_pub, "sender_ephemeral_pub")
        else {
            return false;
        };
        // The claimed input key must equal the locally revealed key of the
        // fork AND recompute the collision tag: ds_tag == H(prev || eph).
        let expected_tag_ok = crate::services::crypto::get_ds_tag(prev_hash, &fp.sender_ephemeral_pub)
            .is_ok_and(|t| t == fp.ds_tag);
        if !expected_tag_ok {
            return false;
        }
        conflicting_txs.iter().any(|tx| {
            tx.prev_hash == prev_hash
                && tx
                    .sender_ephemeral_pub
                    .as_deref()
                    .and_then(|eph| {
                        crate::services::crypto::decode_bs58_fixed::<32>(eph, "sender_ephemeral_pub").ok()
                    })
                    .is_some_and(|p| p == eph_bytes)
        })
    }

    for fp in fingerprints.iter().filter(|fp| {
        local_t_ids.contains(&fp.t_id)
            || (!conflict_manager::is_init_fingerprint(fp)
                && conflict_manager::verify_fingerprint_signature(fp)
                && reproduces_local_tag(fp, prev_hash, &conflicting_txs))
    }) {
        // Construct a synthetic transaction to decrypt the timestamp
        let tx = crate::models::voucher::Transaction {
            t_id: fp.t_id.clone(),
            prev_hash: prev_hash.clone(),
            ..Default::default()
        };

        if let Ok(decrypted_nanos) =
            conflict_manager::decrypt_transaction_timestamp(&tx, fp.encrypted_timestamp)
        {
            // Plausibility gate: only admit foreign candidates whose decrypted
            // timestamp could plausibly originate from a real transaction.
            // Locally-held branches are always trusted (chain-backed).
            let is_local = local_t_ids.contains(&fp.t_id);
            if !is_local
                && (decrypted_nanos == 0
                    || decrypted_nanos > max_plausible_nanos
                    || decrypted_nanos < min_plausible_nanos)
            {
                log::warn!(
                    "Ignoring gossip fingerprint '{}': implausible timestamp (outside plausible window).",
                    fp.t_id
                );
                continue;
            }
            if decrypted_nanos < earliest_time
                || (decrypted_nanos == earliest_time
                    && winner_id.as_ref().is_some_and(|curr| fp.t_id < *curr))
            {
                earliest_time = decrypted_nanos;
                winner_id = Some(fp.t_id.clone());
            }
        }
    }

    // --- 2. Write phase: Update status based on winner ID ---
    if let Some(winner_id) = winner_id {
        let winner_is_local = local_t_ids.contains(&winner_id);
        let winner_has_cryptographic_proof = fingerprints
            .iter()
            .find(|fp| fp.t_id == winner_id)
            .is_some_and(|fp| {
                !conflict_manager::is_init_fingerprint(fp)
                    && conflict_manager::verify_fingerprint_signature(fp)
                    && reproduces_local_tag(fp, prev_hash, &conflicting_txs)
            });
        drop(conflicting_txs);

        for instance in voucher_store.vouchers.values_mut() {
            // Check if this instance contains one of the conflicting transactions.
            if let Some(tx) = instance
                .voucher
                .transactions
                .iter()
                .find(|tx| tx_ids.contains(&tx.t_id))
            {
                let is_winner = tx.t_id == winner_id;
                let prev_status = instance.status.clone();

                // SECURITY (Paket 5): Local possession priority for Active vouchers.
                // If the winner is a pure foreign gossip fingerprint without verified
                // cryptographic proof of double spend (HMC_TX_AUTH digest signature + reproduces local tag)
                // and the local voucher is Active, local possession takes precedence:
                // do NOT quarantine the active voucher!
                if !winner_is_local && !winner_has_cryptographic_proof && matches!(prev_status, VoucherStatus::Active) {
                    log::warn!(
                        "Possession priority: local active voucher '{}' retained; unconfirmed foreign gossip fingerprint '{}' cannot quarantine active voucher without verified double-spend proof.",
                        instance.voucher.voucher_id,
                        winner_id
                    );
                    continue;
                }

                // SECURITY (AUDIT-01-F15): monotonic status protection. The
                // offline race is a HEURISTIC; it may downgrade an Active
                // branch (safety-first quarantine) or confirm an existing
                // loss, but it must never reactivate a Quarantined instance
                // (an L2 verdict / resolution is cryptographic evidence that
                // outweighs a timestamp heuristic) nor touch adjudicated
                // escrow states (Endorsed) or terminal states. Reactivation
                // requires new cryptographic evidence via the gated paths.
                let mutation_allowed = match &prev_status {
                    VoucherStatus::Active => true,
                    VoucherStatus::Quarantined { .. } => !is_winner,
                    _ => false,
                };
                if mutation_allowed {
                    instance.status = if is_winner {
                        VoucherStatus::Active
                    } else {
                        VoucherStatus::Quarantined {
                            reason: "Lost offline race".to_string(),
                        }
                    };
                }
            }
        }
    }
}
