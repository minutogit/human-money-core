//! # Security Audit Module 01 — Double-Spend Trap, DS-Tags & Conflict Detection
//!
//! Reproduction tests for confirmed vulnerabilities found during the
//! security audit of the trap / conflict-detection subsystem.
//!
//! ## Standardized Finding Metadata
//!
//! ### AUDIT-01-F01 — Gossip-Poisoning False Quarantine
//! * **Finding-ID:** AUDIT-01-F01
//! * **Severity:** High (Denial of Service / forced quarantine of legitimate funds)
//! * **CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data in Trust Decision)
//! * **Target:** `src/wallet/conflict_handler.rs::resolve_conflict_offline`
//! * **Threat Model:** A gossip peer injects a forged `TransactionFingerprint` that
//!   reuses the ds_tag of a victim's real spend but carries an attacker-chosen
//!   `t_id` and an `encrypted_timestamp` that decrypts to 0 (the XOR key is
//!   publicly derivable from `prev_hash + t_id`). The "Earliest Wins" race then
//!   quarantines the victim's legitimate voucher upon receiving any bundle.
//! * **Impact:** Remote, unauthenticated DoS on a victim's active balance.
//! * **Root Cause:** The winner race iterates over ALL fingerprints, including
//!   foreign ones whose `t_id` does not correspond to any locally-held branch.
//! * **Remediation:** Restrict race candidates to fingerprints whose `t_id`
//!   exists in the local voucher store (path-reunion stays fully functional).
//! * **Test Semantics:** Fail-first. Asserts the secure invariant: after
//!   receiving a hostile fingerprint-only bundle, the victim's voucher status
//!   MUST remain `Active`.
//!
//! ### AUDIT-01-F02 — Schnorr Response Scalar Malleability
//! * **Finding-ID:** AUDIT-01-F02
//! * **Severity:** Medium
//! * **CWE:** CWE-347 (Improper Verification of Cryptographic Signature — malleability)
//! * **Target:** trap shard parsing (`src/services/trap_manager.rs`)
//! * **Threat Model:** A valid response scalar `s` can be transformed into
//!   `s + L` (group order) which decodes to the same group element under
//!   lenient parsing, producing two distinct byte encodings of the same
//!   mathematical value and violating the codebase-wide canonical-scalar
//!   invariant.
//! * **Impact:** Shard malleability; inconsistent fingerprints downstream.
//! * **Root Cause:** Lenient scalar parsing (`from_bytes_mod_order`) instead
//!   of strict canonical parsing before algebraic use.
//! * **Remediation (V3 SST):** All response scalars (`trap_s`, witness
//!   `s_sig`/`m_s`) are parsed strictly canonically
//!   (`Scalar::from_canonical_bytes`) before any algebraic use.
//! * **Test Semantics:** Fail-first. Asserts SST extraction rejects a colliding
//!   shard pair whose response scalar exceeds the group order encoding.
//!
//! ### AUDIT-01-F05 — Unverified Attribution Claim at Import Boundary
//! * **Finding-ID:** AUDIT-01-F05
//! * **Severity:** High (framing + targeted quarantine enabler)
//! * **CWE:** CWE-345 (Insufficient Verification of Data Authenticity)
//! * **Target:** `src/wallet/conflict_handler.rs::import_proof`
//! * **Threat Model:** The anti-framing invariant documented on
//!   `ProofOfDoubleSpend.offender_id` ("a did:key identity is only written if
//!   the stored trap shards verify") is enforced at creation time but NOT
//!   re-checked when importing a foreign proof. A real double-spender who
//!   owns both forks can sign a structurally valid report naming an INNOCENT
//!   victim as offender; all existing gates pass because the transactions are
//!   cryptographically genuine.
//! * **Impact:** Reputation framing; combined with the earliest-timestamp rule
//!   enables quarantine of the framed party's branch.
//! * **Root Cause:** Missing attribution-consistency gate in `import_proof`.
//! * **Remediation (V3 SST):** If `offender_id` parses to a did:key public
//!   key, the stored trap shards must pass
//!   `verify_stored_trap_shards_against_identity` (>= 2 colliding shards
//!   reconstructing a valid Schnorr signature under the claimed key) before
//!   import.
//! * **Test Semantics:** Fail-first. Asserts `import_proof(...).is_err()` for a
//!   forged did:key claim lacking verifiable shards; a control assertion proves
//!   anonymous witness notes remain importable.
//!
//! ### AUDIT-01-F06 — Placeholder Substring Skip Weakens Shard Count
//! * **Finding-ID:** AUDIT-01-F06
//! * **Severity:** Low (attribution degradation)
//! * **CWE:** CWE-354 (Improper Validation of Integrity Check Value)
//! * **Target:** attribution gates operating on conflicting transactions
//! * **Threat Model:** Skip conditions based on attacker-influenced `t_type`
//!   substrings also exclude REAL transactions bearing attacker-chosen
//!   transaction types from the >=2-shard requirement, degrading attribution
//!   to the anonymous fallback. Genuine synthetic placeholders are already
//!   skipped structurally (they carry no `trap_data`).
//! * **Impact:** Offender can evade did-key unmasking by typing one fork.
//! * **Root Cause:** Redundant substring-based skip on attacker-influenced data.
//! * **Remediation (V3 SST):** Rely solely on the structural marker
//!   (`trap_data` presence) when collecting shards for attribution.
//! * **Test Semantics:** Fail-first. Asserts two fully valid trap shards count
//!   even when one transaction carries a placeholder-like `t_type`.
//!
//! ### AUDIT-01-F07 — Trap-Anchoring Framing via Arbitrary-Slope Proofs
//! * **Finding-ID:** AUDIT-01-F07
//! * **Severity:** Critical (unrefutable reputation framing, persistent
//!   `TrustStatus::KnownOffender` for arbitrary innocents)
//! * **CWE:** CWE-347 (Improper Verification of Cryptographic Signature —
//!   proof binds the wrong statement) / CWE-345 (Insufficient Verification
//!   of Data Authenticity)
//! * **Target:** trap engine wire format + attribution/import gates
//! * **Threat Model (V2):** `verify_trap` proved knowledge of ONE arbitrary
//!   scalar `m` with respect to base `X = u*G`. Nothing bound `m` to
//!   `derive_m(sk_sender, prev_hash)` of the CLAIMED sender. An attacker who
//!   knew ANY slope `m'` (e.g. their own) could anchor both forks of a
//!   synthetic double spend at an innocent identity:
//!   `blinded_id = (u*m')*G + ID_victim`. The resulting Schnorr proofs were
//!   cryptographically GENUINE against the victim's point, so every
//!   `>=2 verified traps` gate passed and the forged did:key attribution was
//!   persisted, driving `check_reputation` to `KnownOffender`.
//! * **Impact (V2):** Any gossip peer could permanently defame any did:key
//!   identity in every wallet that receives the report.
//! * **Root Cause (V2):** The Schnorr statement ("knowledge of some slope")
//!   was weaker than the attribution claim made from it ("the trap belongs to
//!   sk_claimed").
//! * **Remediation (V3 SST — RESOLVED):** The Shared-Signature Trap shards a
//!   REAL deterministic Schnorr signature $\sigma = (R_{sig}, s_{sig})$ over
//!   the spend message $\mu$. A did:key attribution is published ONLY when
//!   two colliding shards reconstruct $(\hat{R}, \hat{s})$ that verify as a
//!   valid Schnorr signature under the extracted key. Fabricating shards that
//!   reconstruct to a CHOSEN victim key is equivalent to forging a Schnorr
//!   signature for that key (EUF-CMA hardness of Schnorr/Ed25519) — framing
//!   is computationally infeasible. The former exploit test is UN-IGNORED and
//!   kept as a permanent green invariant.
//! * **Test Semantics:** Builds fabricated shard pairs aimed at the victim and
//!   asserts `import_proof(...).is_err()`; positive controls prove that
//!   honestly bound double spends remain attributable/importable.

//! ### AUDIT-01-F08 — False Dispute Injection on the Local Creation Path
//! * **Finding-ID:** AUDIT-01-F08
//! * **Severity:** High (persistent false attribution / reputation damage)
//! * **CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data in Trust
//!   Decision) / CWE-345
//! * **Target:** `src/wallet/conflict_handler.rs::verify_and_create_proof`
//!   (`offender_id` taken verbatim from `conflicting_transactions[0].sender_id`)
//!   plus persistence in `src/wallet/transaction_handler.rs`.
//! * **Threat Model:** When a collision contains ONE real local transaction,
//!   its `sender_id` (a did:key) was adopted as the authoritative
//!   `offender_id` WITHOUT any trap verification. An attacker gossiping a
//!   poison fingerprint that reuses a publicly-known ds_tag of the victim's
//!   own spend/init transaction under a fabricated `t_id` caused the wallet
//!   to create and PERSIST a proof naming the victim as offender.
//! * **Impact:** False disputes injected into the victim's permanent proof
//!   store, self-naming the wallet owner.
//! * **Remediation (V3 SST):** Any did:key candidate derived from transaction
//!   data must pass `verify_stored_trap_shards_against_identity` against the
//!   claimed point; otherwise it is downgraded to `anonymous` and the
//!   conservative fallbacks apply. SST extractions are inherently verified.
//! * **Test Semantics:** Fail-first. Injects a poison-only bundle whose
//!   fingerprint collides with the victim's init anchor and asserts that no
//!   persisted conflict names the victim's did:key as offender.

//! ### AUDIT-01-F09 — Degenerate Fork Data (identical shards)
//! * **Finding-ID:** AUDIT-01-F09
//! * **Severity:** Medium (attacker-chosen "identity" instead of hard error;
//!   advisory impact via `suspected_identity`)
//! * **CWE:** CWE-20 (Improper Input Validation — missing degenerate-case
//!   guard before algebraic reconstruction) / CWE-754 (Improper Check for
//!   Unusual or Exceptional Conditions)
//! * **Target:** `src/services/trap_manager.rs` collision reconstruction
//! * **Threat Model:** Two colliding entries with byte-identical shard data
//!   carry no fork information. Lenient reconstruction degenerates and
//!   returns an attacker-chosen point instead of rejecting the non-fork.
//! * **Impact:** Attribution output becomes an arbitrary attacker point;
//!   violates the invariant that identity reconstruction only succeeds for
//!   GENUINE forks.
//! * **Root Cause:** Asymmetric guards: some degenerate cases were guarded
//!   while identical shard data was missed.
//! * **Remediation (V3 SST):** Hard guards fire BEFORE any inversion:
//!   identical evaluation points ($\tau_1 == \tau_2$), fully identical shards
//!   $(R_1,s_1) == (R_2,s_2)$, zero challenge and neutral-element identity.
//! * **Test Semantics:** Fail-first. Feeds two fingerprints with distinct
//!   t_ids but byte-identical shards and asserts an Err.

//! ### AUDIT-01-F10 — proof_id Canonicalization Desync (find vs. rfind/sanitize)
//! * **Finding-ID:** AUDIT-01-F10
//! * **Severity:** Medium (dedup/immunity bypass, resolution splitting)
//! * **CWE:** CWE-172 (Encoding Error — canonical representation not
//!   enforced) / CWE-592 (Incomplete Authentication... dedup keyed on
//!   non-canonical data; primary: CWE-172)
//! * **Target:** `src/services/conflict_manager.rs::derive_proof_id` vs.
//!   `src/services/crypto_identity.rs::get_pubkey_from_user_id`;
//!   consumer `src/wallet/conflict_handler.rs::import_proof` (immunity rule)
//! * **Threat Model:** `derive_proof_id` hashes the RAW offender_id bytes
//!   while `get_pubkey_from_user_id` sanitizes whitespace and splits at the
//!   LAST `@`. Render variants of the SAME logical offender identity
//!   therefore derive DIFFERENT proof_ids and bypass import immunity.
//! * **Impact:** Dedup/immunity bypass and inconsistent attribution-gate vs.
//!   proof-id byte representations for crafted inputs.
//! * **Root Cause:** Two different parsers for the same identifier field;
//!   no canonicalization before hashing.
//! * **Remediation:** Canonicalize offender_id in `derive_proof_id`
//!   identically to `get_pubkey_from_user_id`.
//! * **Test Semantics:** Fail-first. Asserts render-variant offender ids
//!   yield identical proof_ids AND that a second import of the same logical
//!   conflict under a render variant does not create a second store entry.

//! ### AUDIT-01-F11 — Cross-Voucher False Quarantine via Import Bucket-Stuffing
//! * **Finding-ID:** AUDIT-01-F11 (Wave-3 hypothesis WH3-01-101; folds
//!   WH3-01-107 cross-ds_tag junk soft proofs)
//! * **Severity:** Critical (remote, gate-conform quarantine of innocent
//!   ACTIVE vouchers; guaranteed collateral for >= 2 stuffed buckets)
//! * **CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data in Trust
//!   Decision) / CWE-20 (Improper Input Validation — attacker-controlled
//!   map key trusted as bucket identity)
//! * **Target:** `src/services/conflict_manager.rs::import_foreign_fingerprints`
//!   (map-key desync) + `src/wallet/conflict_handler.rs::resolve_conflict_offline`
//!   (unconditional local-candidate trust in the winner race)
//! * **Threat Model:** `import_foreign_fingerprints` inserts incoming
//!   fingerprints under the ATTACKER-controlled JSON map key instead of
//!   re-keying by content (`fp.ds_tag`) like every other ingress path.
//!   An attacker exports `{K: [fp_A, fp_B]}` where `fp_A`/`fp_B` are two
//!   GENUINE, individually well-signed gossip fingerprints of spends on two
//!   DIFFERENT vouchers (different ds_tags) under one arbitrary key `K`.
//!   `check_for_double_spend` then sees `unique_t_ids == 2` in bucket `K`
//!   -> "verifiable conflict". In `resolve_conflict_offline` BOTH t_ids
//!   match locally-held transactions, so both candidates enter the
//!   Earliest-Wins race UNCONDITIONALLY (no cross-member ds_tag/prev_hash
//!   coherence check). The member decoded against the wrong fork prev_hash
//!   yields a garbage timestamp, loses the race with probability ~1 and its
//!   INNOCENT instance is quarantined ("Lost offline race").
//! * **Impact:** Remote denial-of-service on active balances without any
//!   signature forgery; additionally a junk soft-proof is persisted that
//!   links unrelated vouchers to a fabricated conflict (WH3-01-107).
//! * **Root Cause:** (a) import trusts the transport map key as bucket
//!   identity (content/key desync), (b) the race trusts local t_id
//!   membership without verifying bucket-wide input coherence.
//! * **Remediation:** Re-key imported fingerprints by their CONTENT
//!   (`fp.ds_tag`), making bucket stuffing structurally impossible;
//!   coherent buckets then collapse to single-member entries.
//! * **Test Semantics:** Fail-first. Stuffs two genuine fingerprints of two
//!   different active vouchers under one foreign map key and asserts that
//!   BOTH instances stay Active and no junk conflict is persisted. On
//!   unpatched code one innocent instance is quarantined.

//! ### AUDIT-01-F12 — Guard-less Transfers Accept Poisoned Trap Shards (R5 Gap)
//! * **Finding-ID:** AUDIT-01-F12 (Wave-3 hypothesis WH3-01-103; cross-ref
//!   WH3-02-201)
//! * **Severity:** High (SST self-evasion: the documented R5 guarantee
//!   "recipients fail-closed reject garbage traps at L1 handover" becomes
//!   optional client behavior instead of cryptographic enforcement)
//! * **CWE:** CWE-354 (Improper Validation of Integrity Check Value) /
//!   CWE-20 (missing enforcement branch for guard-less trap carriers)
//! * **Target:** `src/wallet/transaction_handler.rs::process_encrypted_transaction_bundle_inner`
//!   (witness verification nested exclusively under `privacy_guard` presence)
//! * **Threat Model:** The ONLY cryptographic coercion forcing a spender to
//!   publish shards that reconstruct to THEIR identity is `verify_sst_witness`
//!   at L1 handover — executed solely inside the `if let Some(guard)` block.
//!   A malicious or patched payer delivers a PUBLIC-mode transaction whose
//!   recipient is a plain did:key (no Layer-0 anonymous-guard requirement),
//!   carries POISONED SST shards (garbage under the genuine ds_tag, correctly
//!   re-signed with the held input key per HMC_TX_AUTH_V3) and NO
//!   privacy_guard. Every structural/integrity gate passes; the shards are
//!   never identity-bound. When this branch later double-spends, pair
//!   extraction deterministically fails -> attribution downgrades to
//!   anonymous/ephemeral: the offender unilaterally blinds the SST.
//! * **Impact:** Autonomous did:key deanonymization (core SST promise) can be
//!   switched off by the offender exactly where privacy pressure is highest;
//!   Flexible/Stealth flows remain protected by the Layer-0 guard-decryption
//!   requirement, so the gap is Public-mode specific but architectural.
//! * **Root Cause:** Enforcement keyed on the transport envelope (guard
//!   presence) instead of the security-relevant payload (trap presence).
//! * **Remediation:** Reject any incoming LAST transaction carrying
//!   `trap_data` without a successfully verifying private SST witness,
//!   regardless of `privacy_guard` presence (fail-closed at handover).
//! * **Test Semantics:** Fail-first. An honestly signed public-mode transfer
//!   is accepted as control; then a well-formed sibling fork with poisoned
//!   shards and no guard is delivered and MUST be rejected. On unpatched
//!   code the poisoned payment is accepted and activated.

//! ### AUDIT-01-F13 — n>=3 Shard Firewall Weaponized Against Real Proofs
//! * **Finding-ID:** AUDIT-01-F13 (Wave-3 hypothesis WH3-01-102)
//! * **Severity:** High (cheap attribution evasion / propagation DoS at the
//!   weakest link of the SST de-anonymization chain)
//! * **CWE:** CWE-628 (Function Call with Incorrectly Specified Argument
//!   Set — asymmetric verification contract) / CWE-757 (Selection of
//!   Less-Secure Algorithm During Negotiation)
//! * **Target:** `src/services/trap_manager.rs::verify_sst_shards_consistency`
//!   (full-set line firewall over `parsed[2..]`) vs. the generation-side
//!   extraction in `src/wallet/conflict_handler.rs::verify_and_create_proof`
//!   (pair `[0]/[1]` only)
//! * **Threat Model:** Creation writes a did:key claim when the FIRST two
//!   bucket members reconstruct it; the import gate 3b instead demands that
//!   ALL n >= 3 stored shards lie exactly on the reconstructed line. A
//!   double-spender controls every shard of their own forks: broadcasting a
//!   third structurally valid but OFF-LINE shard (random point + canonical
//!   scalar, self-signed layer2 signature) makes every subsequent
//!   `import_proof` of the honestly attributed report fail hard
//!   ("inconsistent extra shard"). The report is persisted NOWHERE, no
//!   quarantine, no reputation entry at third parties — the spender evades
//!   the entire SST chain without breaking EUF-CMA.
//! * **Impact:** Trivial, cost-free evasion of autonomous deanonymization
//!   and suppression of authentic collision evidence network-wide.
//! * **Root Cause:** Generation and import enforce DIFFERENT attribution
//!   contracts over the same shard set (pair vs. full set).
//! * **Remediation:** Attribution is defined by ANY consistent colliding
//!   pair: `verify_stored_trap_shards_against_identity` evaluates all pairs
//!   and succeeds when one pair reconstructs a valid Schnorr signature under
//!   the claimed key. Extra shards neither contribute to nor veto the claim
//!   (they remain cryptographically inert); the strict full-set firewall in
//!   `verify_sst_shards_consistency` stays untouched for its direct callers.
//! * **Test Semantics:** Fail-first. Builds an honestly bound did:key report
//!   carrying ONE additional off-line shard and asserts the proof imports.
//!   On unpatched code the import rejects the whole authentic evidence.

//! ### AUDIT-01-F14 — Epoch-Near Candidates Win the Earliest-Wins Race
//! * **Finding-ID:** AUDIT-01-F14 (Wave-3 hypothesis WH3-01-104)
//! * **Severity:** Medium (within the documented former-holder attacker
//!   class: trivially wins every race by dating siblings to 1970)
//! * **CWE:** CWE-20 (Improper Input Validation — plausibility window
//!   missing its lower bound)
//! * **Target:** `src/wallet/conflict_handler.rs::resolve_conflict_offline`
//!   (timestamp plausibility gate)
//! * **Threat Model:** The V2 hardening only rejects `decrypted_nanos == 0`
//!   or timestamps more than 24h in the FUTURE. Anyone holding the input
//!   one-time key (documented accepted-risk class: issuer / former holder)
//!   freely chooses `t_id` and sets `encrypted_timestamp = target ^`
//!   `H(prev_hash || t_id)` with `target = 3600ns`: the candidate decrypts
//!   to 1970, passes the one-sided gate and beats EVERY genuine 2026-era
//!   branch. The code's own rationale ("genuine forks ... always embed
//!   near-wall-clock timestamps") is enforced symmetrically on top only.
//! * **Impact:** Any holder-class actor unconditionally quarantines the
//!   honest branch of a voucher they ever held; grinding success for the
//!   fixed window shrinks to ~window/2^128.
//! * **Root Cause:** Asymmetric plausibility bound (upper only).
//! * **Remediation:** Add a documented lower bound (now - 365d, aligned with
//!   the shortest standard validity range); genuine collisions between
//!   long-held vouchers are still served by the proof-import path.
//! * **Test Semantics:** Fail-first. A correctly signed sibling whose
//!   decrypted timestamp is 3600ns must NOT win the race; on unpatched code
//!   it quarantines the honest local branch.

//! ### Regression Guards (pass before AND after the fixes)
//! * `guard_extract_identity_rejects_identical_tau`: $\tau_1 == \tau_2$ must error.
//! * `guard_extract_identity_rejects_non_canonical_response`: non-canonical
//!   scalar encodings of shard responses must be rejected.

#[cfg(test)]
mod security_audit_module_01 {
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    use curve25519_dalek::edwards::EdwardsPoint;
    use ed25519_dalek::SigningKey;
    use human_money_core::models::conflict::{ProofOfDoubleSpend, TransactionFingerprint};
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::models::voucher::{Transaction, TrapData, ValueDefinition};
    use human_money_core::services::conflict_manager::derive_proof_id;
    use human_money_core::services::crypto_utils::{
        ed25519_pk_to_curve_point, get_hash_from_slices, sign_ed25519,
    };
    use human_money_core::services::trap_manager::{self, TrapWitness};
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::test_utils::{
        ACTORS, FREETALER_STANDARD, generate_signed_standard_toml, setup_service_with_profile,
    };
    use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use std::collections::HashMap;
    use tempfile::tempdir;

    const PASSWORD: &str = "audit-password";

    /// Ed25519 group order L (little-endian).
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
        0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10,
    ];

    fn random_b58_32() -> String {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        bs58::encode(buf).into_string()
    }

    /// Adds the Ed25519 group order to a 32-byte little-endian scalar modulo
    /// 2^256. Since s < L < 2^253, no overflow past 32 bytes can occur.
    fn add_group_order(bytes: &mut [u8; 32]) {
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = bytes[i] as u16 + L_BYTES[i] as u16 + carry;
            bytes[i] = (sum & 0xFF) as u8;
            carry = sum >> 8;
        }
    }

    fn fresh_key() -> SigningKey {
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);
        SigningKey::from_bytes(&sk)
    }

    fn identity_point_of(sk: &SigningKey) -> EdwardsPoint {
        ed25519_pk_to_curve_point(&sk.verifying_key()).unwrap()
    }

    /// Production-derived ds_tag of the input `(prev_hash, eph_pub)`.
    fn ds_tag_of(prev_hash_b58: &str, eph_pub_b58: &str) -> String {
        get_hash_from_slices(&[
            &bs58::decode(prev_hash_b58).into_vec().unwrap(),
            &bs58::decode(eph_pub_b58).into_vec().unwrap(),
        ])
    }

    /// Generates an honest SST fork pair for a synthetic double spend.
    ///
    /// Returns `(TrapData A, t_id A, TrapData B, t_id B, ds_tag)` where both
    /// forks share the same input anchor `(prev_hash, eph_pub)` and differ
    /// only in their transaction ids — exactly what `create_transaction`
    /// produces for a real double spend under the V3 SST protocol.
    fn build_honest_sst_forks(
        sk: &SigningKey,
        prev_hash_b58: &str,
        eph_pub_b58: &str,
    ) -> (TrapData, String, TrapData, String, String) {
        let ds_tag = ds_tag_of(prev_hash_b58, eph_pub_b58);
        let eph_bytes: [u8; 32] = bs58::decode(eph_pub_b58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let t_id_a = random_b58_32();
        let t_id_b = random_b58_32();
        let (trap_a, _) =
            trap_manager::generate_sst_trap(sk, &ds_tag, &eph_bytes, &t_id_a).unwrap();
        let (trap_b, _) =
            trap_manager::generate_sst_trap(sk, &ds_tag, &eph_bytes, &t_id_b).unwrap();
        (trap_a, t_id_a, trap_b, t_id_b, ds_tag)
    }

    /// Builds a shard-carrying fingerprint (test helper).
    fn shard_fp(ds_tag: &str, t_id: &str, trap: &TrapData) -> TransactionFingerprint {
        TransactionFingerprint {
            ds_tag: ds_tag.to_string(),
            t_id: t_id.to_string(),
            trap_r: trap.trap_r.clone(),
            trap_s: trap.trap_s.clone(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            ..Default::default()
        }
    }

    //==========================================================================
    // AUDIT-01-F01: Gossip poisoning must not quarantine legitimate vouchers
    //==========================================================================

    #[test]
    fn f01_gossip_poisoning_must_not_quarantine_local_voucher() {
        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;

        let (mut alice, _) = setup_service_with_profile(dir.path(), &ACTORS.alice, "A1", PASSWORD);
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V1", PASSWORD);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H1", PASSWORD);

        let id_alice = alice.get_user_id().unwrap();
        let id_victim = victim.get_user_id().unwrap();

        // Alice creates a voucher and fully transfers it to the victim.
        alice
            .unlock_session(PASSWORD, 300)
            .unwrap();
        alice
            .create_new_voucher(
                &standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "100".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(id_alice.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .expect("voucher creation failed");
        let summaries = alice.get_voucher_summaries(None, None, None).unwrap();
        assert!(!summaries.is_empty(), "alice must hold a voucher");
        let local_id = summaries[0].local_instance_id.clone();

        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );

        let request = MultiTransferRequest {
            recipient_id: id_victim.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };
        alice
            .unlock_session(PASSWORD, 300)
            .unwrap();
        let result = alice
            .create_transfer_bundle(request, &standards_map, None, Some(PASSWORD))
            .expect("transfer creation failed");
        victim
            .unlock_session(PASSWORD, 300)
            .unwrap();
        victim
            .receive_bundle(&result.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
            .expect("victim must accept the honest transfer");

        let victim_summaries = victim.get_voucher_summaries(None, None, None).unwrap();
        assert_eq!(victim_summaries.len(), 1, "victim holds exactly one voucher");
        assert_eq!(
            victim_summaries[0].status,
            human_money_core::VoucherStatus::Active,
            "precondition: victim holds an active voucher"
        );

        // Extract the victim's real spend anchor (public chain data).
        let (victim_wallet, _) = victim.get_unlocked_mut_for_test();
        let instance = victim_wallet.voucher_store.vouchers.values().next().unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap().clone();
        let real_ds_tag = last_tx
            .trap_data
            .as_ref()
            .map(|t| t.ds_tag.clone())
            .expect("spend tx carries trap data");
        let real_prev_hash = last_tx.prev_hash.clone();

        // Craft the poisoned fingerprint: same input anchor, fabricated sibling.
        let forged_t_id = random_b58_32();
        let prev_hash_bytes = bs58::decode(&real_prev_hash).into_vec().unwrap();
        let forged_bytes = bs58::decode(&forged_t_id).into_vec().unwrap();
        let key_b58 = get_hash_from_slices(&[&prev_hash_bytes, &forged_bytes]);
        let key_bytes = bs58::decode(&key_b58).into_vec().unwrap();
        let xor_key = u128::from_le_bytes(key_bytes[..16].try_into().unwrap());
        let poison_fp = TransactionFingerprint {
            ds_tag: real_ds_tag.clone(),
            trap_r: "none".to_string(),
            trap_s: "none".to_string(),
            t_id: forged_t_id,
            layer2_signature: String::new(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            encrypted_timestamp: xor_key, // decrypts to nanos = 0 -> always wins
            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: "none".to_string(),
            privacy_guard_hash: String::new(),
        };

        // Attacker ships the poison inside an otherwise harmless bundle.
        let depths: HashMap<String, i8> = [(real_ds_tag.clone(), 1i8)].into_iter().collect();
        let (hacker_wallet, hacker_identity) = hacker.get_unlocked_mut_for_test();
        let (poison_bundle, _) = hacker_wallet
            .create_and_encrypt_transaction_bundle(
                hacker_identity,
                vec![],
                &id_victim,
                None,
                vec![poison_fp],
                depths,
                None,
            )
            .expect("attacker bundle creation failed");

        // Victim processes the hostile fingerprint-only bundle.
        victim
            .unlock_session(PASSWORD, 300)
            .unwrap();
        victim
            .receive_bundle(&poison_bundle, &standards_map, None, Some(PASSWORD), false)
            .expect("processing a fingerprint-only bundle must succeed");

        // SECURE INVARIANT (Soll-Verhalten): the victim's voucher must NOT be
        // quarantined by unauthenticated gossip data.
        let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
            .status
            .clone();
        assert_eq!(
            status_after,
            human_money_core::VoucherStatus::Active,
            "AUDIT-01-F01: unauthenticated gossip fingerprints must never \
             quarantine a local voucher"
        );
    }

    //==========================================================================
    // AUDIT-01-F02: Non-canonical response scalars must be rejected (SST)
    //==========================================================================

    #[test]
    fn f02_shard_parsing_rejects_non_canonical_response_scalar() {
        let sk = fresh_key();
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();

        let (trap_a, t_id_a, trap_b, t_id_b, ds_tag) =
            build_honest_sst_forks(&sk, &prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        let fp_a = shard_fp(&ds_tag, &t_id_a, &trap_a);
        let fp_b = shard_fp(&ds_tag, &t_id_b, &trap_b);

        // Sanity: the honest pair extracts cleanly.
        assert!(
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp_a, &fp_b).is_ok(),
            "sanity: honest shards must extract"
        );

        // Malleate: s' = s + L (same group element, different byte encoding).
        let mut s_bytes: [u8; 32] = bs58::decode(&trap_b.trap_s)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        add_group_order(&mut s_bytes);
        let malleated_fp = TransactionFingerprint {
            trap_s: bs58::encode(s_bytes).into_string(),
            ..fp_b.clone()
        };
        assert_ne!(malleated_fp.trap_s, fp_b.trap_s, "encoding must differ");

        // SECURE INVARIANT: non-canonical response encodings must be rejected
        // during extraction (strict canonical parsing before any algebra).
        assert!(
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp_a, &malleated_fp).is_err(),
            "AUDIT-01-F02: SST extraction must reject non-canonical scalar \
             encodings of the shard response"
        );
    }

    //==========================================================================
    // AUDIT-01-F05: Forged did:key attribution claims must be rejected on import
    //==========================================================================

    /// Builds a structurally valid double-spend report whose transactions pass
    /// every structural gate but carry no trap proofs at all.
    fn build_structural_proof(
        offender_id: String,
        reporter: &human_money_core::UserIdentity,
    ) -> ProofOfDoubleSpend {
        let fork_point = get_hash_from_slices(&[b"audit-f05-fork"]);
        let shared_eph = random_b58_32(); // single input anchor => single ds_tag

        let make_tx = |t_id: String| {
            let mut tx = Transaction::default();
            tx.t_id = t_id;
            tx.prev_hash = fork_point.clone();
            tx.sender_ephemeral_pub = Some(shared_eph.clone());
            tx.t_time = "2026-08-24T12:00:00Z".to_string();
            tx.amount = "5.00".to_string();
            tx.recipient_id = "did:key:zSomeRecipient".to_string();
            tx
        };

        let conflicting_transactions = vec![make_tx(random_b58_32()), make_tx(random_b58_32())];

        let proof_id = derive_proof_id(&offender_id, &fork_point).unwrap();
        let signature = sign_ed25519(&reporter.signing_key, proof_id.as_bytes());

        ProofOfDoubleSpend {
            proof_id,
            offender_id,
            suspected_identity: None,
            fork_point_prev_hash: fork_point,
            conflicting_transactions,
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            reporter_id: reporter.user_id.clone(),
            report_timestamp: chrono::Utc::now().to_rfc3339(),
            reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
            affected_voucher_name: None,
            voucher_standard_uuid: None,
            resolutions: None,
            layer2_verdict: None,
            non_redeemable_test_voucher: false,
        }
    }

    #[test]
    fn f05_import_proof_rejects_forged_did_key_attribution_claim() {
        let dir = tempdir().unwrap();
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V5", PASSWORD);
        let reporter = ACTORS.hacker.identity.clone();

        // Control: anonymous witness note remains importable.
        let anon_proof = build_structural_proof("anonymous".to_string(), &reporter);
        {
            let (wallet, _) = victim.get_unlocked_mut_for_test();
            wallet
                .import_proof(anon_proof)
                .expect("control: anonymous witness notes stay importable");
        }

        // Attack: structurally identical report, but the offender claim names
        // a did:key identity WITHOUT any verifying trap proofs — a pure
        // forgery by the real double-spender to frame the named party.
        let framed_did = ACTORS.charlie.identity.user_id.clone();
        let forged_claim = build_structural_proof(framed_did, &reporter);

        let (wallet, _) = victim.get_unlocked_mut_for_test();
        let result = wallet.import_proof(forged_claim);
        assert!(
            result.is_err(),
            "AUDIT-01-F05: imported proofs claiming a did:key offender MUST \
             verify the attribution against stored trap proofs"
        );
    }

    //==========================================================================
    // AUDIT-01-F06: Placeholder-typed REAL shards must still count
    //==========================================================================

    #[test]
    fn f06_placeholder_t_type_must_not_weaken_shard_count() {
        let sk = fresh_key();
        let expected_x = identity_point_of(&sk);
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let ds_tag = ds_tag_of(&prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        // Two REAL forks sharing one input anchor.
        let t_id_a = random_b58_32();
        let t_id_b = random_b58_32();
        let (trap_a, _) =
            trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_id_a).unwrap();
        let (trap_b, _) =
            trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_id_b).unwrap();

        let make_tx = |t_type: &str, t_id: String, trap: Option<TrapData>| {
            let mut tx = Transaction::default();
            tx.t_type = t_type.to_string();
            tx.t_id = t_id;
            tx.prev_hash = prev_hash_b58.clone();
            tx.sender_ephemeral_pub = Some(eph_b58.clone());
            tx.t_time = "2026-08-24T12:00:00Z".to_string();
            tx.amount = "10.00".to_string();
            tx.trap_data = trap;
            tx
        };

        // Fork 1: REAL shard but attacker-chosen transaction type string.
        let tx1 = make_tx("gossip_soft_placeholder", t_id_a.clone(), Some(trap_a));
        // Fork 2: REAL shard with an ordinary (empty) type.
        let tx2 = make_tx("", t_id_b.clone(), Some(trap_b));
        // Fork 3: genuine synthetic placeholder (no trap data).
        let tx3 = make_tx("soft_placeholder", random_b58_32(), None);

        let transactions = vec![tx1, tx2, tx3];

        // SECURE INVARIANT: both REAL shards must verify regardless of their
        // t_type strings; the synthetic (trap-less) tx is skipped structurally.
        assert!(
            trap_manager::verify_stored_trap_shards_against_identity(&transactions, &expected_x)
                .is_ok(),
            "AUDIT-01-F06: attacker-controlled t_type strings must not reduce \
             the count of verified trap shards below the attribution threshold"
        );
    }

    //==========================================================================
    // AUDIT-01-F07 (UN-IGNORED — resolved by V3 SST): arbitrary-slope /
    // arbitrary-shard framing MUST be rejected
    //==========================================================================

    #[test]
    fn f07_trap_anchoring_framing_arbitrary_slope_must_be_rejected() {
        let dir = tempdir().unwrap();
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V9", PASSWORD);
        let reporter = ACTORS.hacker.identity.clone();

        // ------------------------------------------------------------------
        // Positive control: a genuine SST double spend bound to the reporter's
        // OWN key must stay importable with a did:key attribution claim.
        // ------------------------------------------------------------------
        let attacker_sk = reporter.signing_key.clone();
        let attacker_point = identity_point_of(&attacker_sk);
        let ctrl_prev = random_b58_32();
        let ctrl_eph = random_b58_32();
        let (ctrl_trap_a, ctrl_t_id_a, ctrl_trap_b, ctrl_t_id_b, _ctrl_ds_tag) =
            build_honest_sst_forks(&attacker_sk, &ctrl_prev, &ctrl_eph);

        let make_ctrl_tx = |t_id: String, trap: TrapData| {
            let mut tx = Transaction::default();
            tx.t_id = t_id;
            tx.prev_hash = ctrl_prev.clone();
            tx.sender_ephemeral_pub = Some(ctrl_eph.clone());
            tx.recipient_id = "did:key:zSomeRecipient".to_string();
            tx.trap_data = Some(trap);
            tx
        };
        let ctrl_txs = vec![
            make_ctrl_tx(ctrl_t_id_a, ctrl_trap_a),
            make_ctrl_tx(ctrl_t_id_b, ctrl_trap_b),
        ];

        // Sanity: the honest shards reconstruct exactly the reporter identity.
        assert!(
            trap_manager::verify_stored_trap_shards_against_identity(&ctrl_txs, &attacker_point)
                .is_ok(),
            "control precondition: honestly bound SST shards must verify"
        );

        let ctrl_offender = reporter.user_id.clone();
        let ctrl_proof_id = derive_proof_id(&ctrl_offender, &ctrl_prev).unwrap();
        let ctrl_signature = sign_ed25519(&reporter.signing_key, ctrl_proof_id.as_bytes());
        let honest_proof = ProofOfDoubleSpend {
            proof_id: ctrl_proof_id,
            offender_id: ctrl_offender,
            suspected_identity: None,
            fork_point_prev_hash: ctrl_prev,
            conflicting_transactions: ctrl_txs,
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            reporter_id: reporter.user_id.clone(),
            report_timestamp: chrono::Utc::now().to_rfc3339(),
            reporter_signature: bs58::encode(ctrl_signature.to_bytes()).into_string(),
            affected_voucher_name: None,
            voucher_standard_uuid: None,
            resolutions: None,
            layer2_verdict: None,
            non_redeemable_test_voucher: false,
        };
        {
            let (wallet, _) = victim.get_unlocked_mut_for_test();
            wallet
                .import_proof(honest_proof)
                .expect("control: genuinely bound did:key attribution stays importable");
        }

        // ------------------------------------------------------------------
        // Attack: anchor two synthetic forks at the INNOCENT victim's
        // identity. Under V2 the attacker knew an arbitrary slope `m'` and
        // produced cryptographically genuine proofs against the victim point.
        // Under V3 SST the attacker can only fabricate ARBITRARY shard bytes:
        // reconstruction yields some pseudorandom point that the attacker
        // CANNOT steer to the chosen victim key — steering would constitute
        // an EUF-CMA forgery against Schnorr/Ed25519.
        // ------------------------------------------------------------------
        let framed_did = ACTORS.charlie.identity.user_id.clone();
        let victim_point = identity_point_of(&ACTORS.charlie.identity.signing_key);
        let atk_prev = random_b58_32();
        let atk_eph = random_b58_32();
        let atk_ds_tag = ds_tag_of(&atk_prev, &atk_eph);

        // Fabricated shards: attacker-chosen compressed points / scalars (the
        // closest V3 analogue of the V2 arbitrary-slope anchoring attack).
        let forge_shard = || {
            let mut r = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut r);
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            (
                bs58::encode(r).into_string(),
                bs58::encode(s).into_string(),
            )
        };
        let (r1, s1) = forge_shard();
        let (r2, s2) = forge_shard();

        let attack_txs = vec![
            ("5.00", random_b58_32(), r1, s1),
            ("7.00", random_b58_32(), r2, s2),
        ]
        .into_iter()
        .map(|(_amount, t_id, trap_r, trap_s)| {
            let mut tx = Transaction::default();
            tx.t_id = t_id;
            tx.prev_hash = atk_prev.clone();
            tx.sender_ephemeral_pub = Some(atk_eph.clone());
            tx.recipient_id = "did:key:zSomeRecipient".to_string();
            tx.trap_data = Some(TrapData {
                ds_tag: atk_ds_tag.clone(),
                trap_r,
                trap_s,
            });
            tx
        })
        .collect::<Vec<_>>();

        // EXPLOIT MATH SANITY (inverted vs. V2): the fabricated shards do NOT
        // verify against the framed party's identity point. Whatever they
        // reconstruct to, it is never the CHOSEN victim key.
        assert!(
            trap_manager::verify_stored_trap_shards_against_identity(&attack_txs, &victim_point)
                .is_err(),
            "AUDIT-01-F07: fabricated shards must never reconstruct to the \
             attacker-chosen victim identity"
        );
        // Demonstrate non-steerability directly on the raw fingerprints.
        {
            let eph_bytes: [u8; 32] =
                bs58::decode(&atk_eph).into_vec().unwrap().try_into().unwrap();
            let fp1 = shard_fp(
                &atk_ds_tag,
                &attack_txs[0].t_id,
                attack_txs[0].trap_data.as_ref().unwrap(),
            );
            let fp2 = shard_fp(
                &atk_ds_tag,
                &attack_txs[1].t_id,
                attack_txs[1].trap_data.as_ref().unwrap(),
            );
            if let Ok(x) = trap_manager::extract_sst_identity(&atk_ds_tag, &eph_bytes, &fp1, &fp2) {
                assert_ne!(
                    x, victim_point,
                    "SST soundness: fabricated shards must not extract to the \
                     chosen victim key"
                );
            }
        }

        let forged_proof_id = derive_proof_id(&framed_did, &atk_prev).unwrap();
        let forged_signature = sign_ed25519(&reporter.signing_key, forged_proof_id.as_bytes());
        let forged_framing = ProofOfDoubleSpend {
            proof_id: forged_proof_id,
            offender_id: framed_did,
            suspected_identity: None,
            fork_point_prev_hash: atk_prev,
            conflicting_transactions: attack_txs,
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            reporter_id: reporter.user_id.clone(),
            report_timestamp: chrono::Utc::now().to_rfc3339(),
            reporter_signature: bs58::encode(forged_signature.to_bytes()).into_string(),
            affected_voucher_name: None,
            voucher_standard_uuid: None,
            resolutions: None,
            layer2_verdict: None,
            non_redeemable_test_voucher: false,
        };

        // SECURE INVARIANT (Soll-Verhalten): a did:key attribution claim whose
        // shards do NOT reconstruct a valid Schnorr signature under the
        // claimed key MUST be rejected at the import boundary.
        let (wallet, _) = victim.get_unlocked_mut_for_test();
        let result = wallet.import_proof(forged_framing);
        assert!(
            result.is_err(),
            "AUDIT-01-F07: did:key attribution from arbitrary fabricated \
             shards MUST be rejected (steering them to a chosen identity \
             would constitute an EUF-CMA forgery)"
        );
    }

    //==========================================================================
    // AUDIT-01-F08: Gossip fingerprints must not name a local did:key as offender
    //==========================================================================

    #[test]
    fn f08_poison_fingerprint_must_not_persist_local_did_key_offender_claim() {
        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;

        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V10", PASSWORD);
        let victim_did = victim.get_user_id().unwrap();

        // Victim holds one active voucher; the init transaction is the anchor.
        victim
            .unlock_session(PASSWORD, 300)
            .unwrap();
        victim
            .create_new_voucher(
                &standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "100".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(victim_did.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .expect("voucher creation failed");

        // Extract the public anchor of the local init transaction.
        let init_tx = {
            let (victim_wallet, _) = victim.get_unlocked_mut_for_test();
            let instance = victim_wallet.voucher_store.vouchers.values().next().unwrap();
            instance.voucher.transactions.last().unwrap().clone()
        };
        assert_eq!(
            init_tx.sender_id.as_deref(),
            Some(victim_did.as_str()),
            "precondition: the local anchor tx carries the victim's did:key"
        );
        let prev_hash_bytes = bs58::decode(&init_tx.prev_hash).into_vec().unwrap();
        let eph_bytes = init_tx
            .sender_ephemeral_pub
            .as_ref()
            .map(|s| bs58::decode(s).into_vec().unwrap())
            .unwrap_or_default();
        let real_ds_tag = get_hash_from_slices(&[&prev_hash_bytes, &eph_bytes]);

        // Poison fingerprint: same publicly-derivable ds_tag, fabricated t_id.
        let poison_fp = TransactionFingerprint {
            ds_tag: real_ds_tag.clone(),
            trap_r: "none".to_string(),
            trap_s: "none".to_string(),
            t_id: random_b58_32(),
            layer2_signature: String::new(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            encrypted_timestamp: 0,
            sender_ephemeral_pub: String::new(),
            layer2_voucher_id: "none".to_string(),
            privacy_guard_hash: String::new(),
        };

        let depths: HashMap<String, i8> = [(real_ds_tag.clone(), 1i8)].into_iter().collect();
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H10", PASSWORD);
        hacker.unlock_session(PASSWORD, 300).unwrap();
        let (hacker_wallet, hacker_identity) = hacker.get_unlocked_mut_for_test();
        let (poison_bundle, _) = hacker_wallet
            .create_and_encrypt_transaction_bundle(
                hacker_identity,
                vec![],
                &victim_did,
                None,
                vec![poison_fp],
                depths,
                None,
            )
            .expect("attacker bundle creation failed");

        // Victim processes the hostile fingerprint-only bundle.
        victim
            .unlock_session(PASSWORD, 300)
            .unwrap();
        victim
            .receive_bundle(&poison_bundle, &standards_map_for(&standard_def, &standard_toml), None, Some(PASSWORD), false)
            .expect("processing a fingerprint-only bundle must succeed");

        // SECURE INVARIANT (Soll-Verhalten): unverified gossip must never
        // create a persisted conflict that names a did:key identity as
        // offender — in particular not the wallet owner's own identity.
        let conflicts = {
            let (wallet, _) = victim.get_unlocked_mut_for_test();
            wallet.list_conflicts()
        };
        assert!(
            conflicts.iter().all(|c| c.offender_id != victim_did),
            "AUDIT-01-F08: a poison fingerprint colliding with a local \
             transaction anchor must never persist the local sender's did:key \
             as offender (got {:?})",
            conflicts.iter().map(|c| &c.offender_id).collect::<Vec<_>>()
        );
    }

    /// Small helper mirroring the standards_map construction used by F01.
    fn standards_map_for(
        standard_def: &human_money_core::models::voucher_standard_definition::VoucherStandardDefinition,
        standard_toml: &str,
    ) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.to_string(),
        );
        map
    }

    //==========================================================================
    // AUDIT-01-F09: Identical shards (degenerate fork data) must error
    //==========================================================================

    #[test]
    fn f09_extract_identity_rejects_identical_shards() {
        let sk = fresh_key();
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let (trap_a, t_id_a, _trap_b, _t_id_b, ds_tag) =
            build_honest_sst_forks(&sk, &prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        // Two DISTINCT t_ids (=> distinct canonical tau scalars!), but
        // byte-identical shard data: no genuine fork information exists.
        let fp1 = shard_fp(&ds_tag, &t_id_a, &trap_a);
        let fp2 = shard_fp(&ds_tag, &random_b58_32(), &trap_a);
        assert_ne!(fp1.t_id, fp2.t_id);

        // SECURE INVARIANT (Soll-Verhalten): degenerate fork data must be
        // rejected with a hard error — never yield Ok(attacker-chosen data).
        assert!(
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp1, &fp2).is_err(),
            "AUDIT-01-F09: identical trap shards must be rejected as a \
             degenerate fork instead of yielding attacker-chosen output"
        );
    }

    //==========================================================================
    // AUDIT-01-F10: proof_id derivation must be canonical across render variants
    //==========================================================================

    #[test]
    fn f10_proof_id_must_be_canonical_across_offender_render_variants() {
        let fork = get_hash_from_slices(&[b"audit-f10-fork"]);
        let reporter = ACTORS.hacker.identity.clone();

        // --- Unit level: render variants must collapse to ONE proof id. -----
        let canonical = derive_proof_id("anonymous", &fork).unwrap();
        for variant in ["anonymous ", " anonymous", "\tanonymous\n"] {
            assert_eq!(
                derive_proof_id(variant, &fork).unwrap(),
                canonical,
                "AUDIT-01-F10: offender render variant '{variant}' must derive \
                 the same proof_id as the canonical form"
            );
        }

        // did:key render variants (whitespace inside the identifier) must
        // also collapse; the pubkey extraction already tolerates them.
        let did = ACTORS.charlie.identity.user_id.clone();
        let did_canonical = derive_proof_id(&did, &fork).unwrap();
        assert_eq!(
            derive_proof_id(&format!(" {}", did), &fork).unwrap(),
            did_canonical,
            "AUDIT-01-F10: whitespace-prefixed did:key must derive the same \
             proof_id as the canonical form"
        );

        // --- Integration: immunity/dedup keyed on the canonical proof id. ---
        let dir = tempdir().unwrap();
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V11", PASSWORD);

        // First import: canonical anonymous soft proof.
        let proof_a = build_structural_proof("anonymous".to_string(), &reporter);
        {
            let (wallet, _) = victim.get_unlocked_mut_for_test();
            wallet
                .import_proof(proof_a)
                .expect("canonical conflict must import");
        }

        // Second import: byte-equivalent logical conflict, but the offender
        // uses a render variant -> must hit the SAME proof_id and be ignored.
        let proof_b = build_structural_proof("anonymous ".to_string(), &reporter);
        {
            let (wallet, _) = victim.get_unlocked_mut_for_test();
            wallet
                .import_proof(proof_b)
                .expect("render variant must not be rejected as a new conflict");
            let count = wallet.list_conflicts().len();
            assert_eq!(
                count, 1,
                "AUDIT-01-F10: dedup/immunity is keyed on proof_id — a render \
                 variant of the same logical conflict MUST NOT create a second \
                 store entry (got {count})"
            );
        }
    }

    //==========================================================================
    // AUDIT-01-F11 (WH3-01-101 + WH3-01-107): Import bucket-stuffing must not
    // quarantine cross-voucher instances nor persist junk soft proofs
    //==========================================================================

    #[test]
    fn f11_import_bucket_stuffing_must_not_quarantine_cross_voucher_instances() {
        use human_money_core::services::conflict_manager::verify_fingerprint_signature;

        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;
        let standards_map = standards_map_for(standard_def, &standard_toml);

        let (mut alice, _) =
            setup_service_with_profile(dir.path(), &ACTORS.alice, "A12", PASSWORD);
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V12", PASSWORD);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H12", PASSWORD);

        let id_alice = alice.get_user_id().unwrap();
        let id_victim = victim.get_user_id().unwrap();

        // Alice issues two vouchers and transfers BOTH to the victim in one
        // bundle -> the victim holds two independent ACTIVE voucher instances.
        alice.unlock_session(PASSWORD, 300).unwrap();
        for i in 0..2 {
            alice
                .create_new_voucher(
                    &standard_toml,
                    NewVoucherData {
                        nominal_value: ValueDefinition {
                            amount: "50".to_string(),
                            ..Default::default()
                        },
                        creator_profile: PublicProfile {
                            id: Some(id_alice.clone()),
                            ..Default::default()
                        },
                        validity_duration: Some("P4Y".to_string()),
                        ..Default::default()
                    },
                    Some(PASSWORD),
                )
                .unwrap_or_else(|e| panic!("voucher creation {i} failed: {e}"));
        }
        let sources = alice
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .into_iter()
            .map(|s| SourceTransfer {
                local_instance_id: s.local_instance_id,
                amount_to_send: "50".to_string(),
            })
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 2, "precondition: two issuable vouchers");
        let request = MultiTransferRequest {
            recipient_id: id_victim.clone(),
            sources,
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };
        let result = alice
            .create_transfer_bundle(request, &standards_map, None, Some(PASSWORD))
            .expect("transfer creation failed");
        victim.unlock_session(PASSWORD, 300).unwrap();
        victim
            .receive_bundle(&result.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
            .expect("victim must accept the honest transfer");

        // Collect the GENUINE spend fingerprints of both received vouchers
        // from the victim's local history (these are exactly what a gossip
        // peer could have copied legitimately).
        let spend_t_ids: Vec<String> = {
            let (vw, _) = victim.get_unlocked_mut_for_test();
            vw.voucher_store
                .vouchers
                .values()
                .map(|inst| inst.voucher.transactions.last().unwrap().t_id.clone())
                .collect()
        };
        assert_eq!(spend_t_ids.len(), 2);
        let genuine_fps: Vec<TransactionFingerprint> = {
            let (vw, _) = victim.get_unlocked_mut_for_test();
            vw.known_fingerprints
                .local_history
                .values()
                .flatten()
                .filter(|fp| spend_t_ids.contains(&fp.t_id))
                .cloned()
                .collect()
        };
        assert_eq!(
            genuine_fps.len(),
            2,
            "precondition: both spend fingerprints exist in local history"
        );
        let ds_tags: std::collections::HashSet<&String> =
            genuine_fps.iter().map(|fp| &fp.ds_tag).collect();
        assert_eq!(
            ds_tags.len(),
            2,
            "precondition: the two genuine fingerprints belong to DIFFERENT inputs"
        );
        for fp in &genuine_fps {
            assert!(
                verify_fingerprint_signature(fp),
                "precondition: copied fingerprint must be self-authenticating"
            );
        }

        // ATTACK: stuff both genuine fingerprints under ONE arbitrary map key.
        let mut stuffed: HashMap<String, Vec<TransactionFingerprint>> = HashMap::new();
        stuffed.insert("stuffkey".to_string(), genuine_fps.clone());
        let blob = serde_json::to_vec(&stuffed).unwrap();
        victim.unlock_session(PASSWORD, 300).unwrap();
        let imported = {
            let (vw, _) = victim.get_unlocked_mut_for_test();
            vw.import_foreign_fingerprints(&blob).expect("import ok")
        };
        assert_eq!(imported, 2, "attack precondition: both entries admitted");

        let statuses_before: Vec<bool> = victim
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .iter()
            .map(|s| s.status == human_money_core::VoucherStatus::Active)
            .collect();
        assert!(
            statuses_before.iter().all(|&a| a),
            "precondition: both victim vouchers are active before processing"
        );

        // Trigger conflict processing with an unrelated gossip bundle (the
        // receive path re-runs check_for_double_spend + offline resolution).
        send_gossip(&mut victim, &mut hacker, &id_victim, vec![], &standards_map);

        // SECURE INVARIANT (Soll-Verhalten): content-incoherent buckets must
        // never mutate voucher states — BOTH instances stay Active...
        let summaries_after = victim.get_voucher_summaries(None, None, None).unwrap();
        for s in &summaries_after {
            assert_eq!(
                s.status,
                human_money_core::VoucherStatus::Active,
                "AUDIT-01-F11: bucket-stuffed import data must never quarantine \
                 an innocent instance (voucher {} lost the fabricated race)",
                s.local_instance_id
            );
        }
        // ...and no junk soft proof may be persisted that links the innocent
        // vouchers to a fabricated cross-ds_tag conflict (WH3-01-107).
        let conflicts = {
            let (vw, _) = victim.get_unlocked_mut_for_test();
            let conflicts = vw.list_conflicts();
            // The invariant also demands content-addressed buckets: no
            // attacker-controlled transport key may survive as bucket identity.
            assert!(
                !vw.known_fingerprints.foreign_fingerprints.contains_key("stuffkey"),
                "AUDIT-01-F11: imported fingerprints must be re-keyed by their \
                 content ds_tag, never by the attacker-controlled map key"
            );
            conflicts
        };
        assert!(
            conflicts.is_empty(),
            "AUDIT-01-F11/WH3-01-107: no junk conflict may be persisted from \
             incoherent stuffed buckets (got {} entries)",
            conflicts.len()
        );
    }

    //==========================================================================
    // AUDIT-01-F12 (WH3-01-103, cross-ref WH3-02-201): guard-less transfers
    // must NOT accept poisoned trap shards (R5 fail-closed at handover)
    //==========================================================================

    #[test]
    fn f12_guardless_transfer_with_poisoned_trap_shards_must_be_rejected() {
        use human_money_core::models::voucher_standard_definition::PrivacyMode;
        use human_money_core::services::crypto_utils::{get_hash};
        use human_money_core::services::conflict_manager::encrypt_transaction_timestamp;
        use human_money_core::services::utils::to_canonical_json;
        use human_money_core::test_utils::create_custom_standard;

        // PUBLIC-mode variant of the FreeTaler standard: recipients are plain
        // did:key identities, so incoming transactions are NOT subject to the
        // Layer-0 anonymous privacy-guard decryption requirement.
        let (public_standard_def, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
            s.immutable.features.privacy_mode = PrivacyMode::Public;
        });
        let public_standard_toml = toml::to_string(&public_standard_def).unwrap();
        let mut standards_map = HashMap::new();
        standards_map.insert(
            public_standard_def.immutable.identity.uuid.clone(),
            public_standard_toml.clone(),
        );

        let dir = tempdir().unwrap();
        let (mut alice, _) =
            setup_service_with_profile(dir.path(), &ACTORS.alice, "A13", PASSWORD);
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V13", PASSWORD);
        let id_alice = alice.get_user_id().unwrap();
        let id_victim = victim.get_user_id().unwrap();

        // --- Control: honest public-mode transfer is accepted. --------------
        alice.unlock_session(PASSWORD, 300).unwrap();
        alice
            .create_new_voucher(
                &public_standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "100".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(id_alice.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .expect("voucher creation failed");
        // Capture the genesis voucher BEFORE spending so the retained input
        // one-time key can be reconstructed (former-holder attacker class).
        let init_voucher = {
            let (aw, _) = alice.get_unlocked_mut_for_test();
            aw.voucher_store.vouchers.values().next().unwrap().voucher.clone()
        };
        let input_key = derive_holder_key(&init_voucher, &ACTORS.alice.identity.signing_key);
        let local_id = alice.get_voucher_summaries(None, None, None).unwrap()[0]
            .local_instance_id
            .clone();
        let request = MultiTransferRequest {
            recipient_id: id_victim.clone(),
            sources: vec![SourceTransfer { local_instance_id: local_id, amount_to_send: "100".to_string() }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };
        let honest = alice
            .create_transfer_bundle(request, &standards_map, None, Some(PASSWORD))
            .expect("honest transfer creation failed");
        victim.unlock_session(PASSWORD, 300).unwrap();
        victim
            .receive_bundle(&honest.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
            .expect("CONTROL: honest transfer with witness-carrying guard accepted");
        assert_eq!(
            victim.get_voucher_summaries(None, None, None).unwrap()[0].status,
            human_money_core::VoucherStatus::Active,
            "control precondition"
        );

        // --- Attack: sibling fork with POISONED shards and NO guard. --------
        // Alice's archived copy holds the sent voucher state (full transfer).
        let mut poisoned = {
            let (aw, _) = alice.get_unlocked_mut_for_test();
            aw.voucher_store
                .vouchers
                .values()
                .find(|i| matches!(i.status, human_money_core::VoucherStatus::Archived))
                .expect("archived sender copy of the spend")
                .voucher
                .clone()
        };

        let original_ds_tag = poisoned
            .transactions
            .last()
            .unwrap()
            .trap_data
            .as_ref()
            .unwrap()
            .ds_tag
            .clone();

        let mut tx = poisoned.transactions.last().unwrap().clone();
        // Fresh t_time -> fresh canonical t_id (sibling of the honest spend).
        let dt = chrono::DateTime::parse_from_rfc3339(&tx.t_time).unwrap();
        tx.t_time = (dt.with_timezone(&chrono::Utc) + chrono::Duration::seconds(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        // Poison: garbage shards under the GENUINE input ds_tag.
        let mut junk_r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_r);
        let mut junk_s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_s);
        tx.trap_data = Some(TrapData {
            ds_tag: original_ds_tag,
            trap_r: bs58::encode(junk_r).into_string(),
            trap_s: bs58::encode(junk_s).into_string(),
        });
        // Strip the privacy guard entirely -> witness never verified.
        tx.privacy_guard = None;

        // Recompute the canonical t_id (preimage excludes trap/guard/sigs).
        let mut preimage = tx.clone();
        preimage.t_id = String::new();
        preimage.layer2_signature = None;
        preimage.sender_identity_signature = None;
        preimage.trap_data = None;
        preimage.privacy_guard = None;
        tx.t_id = get_hash(to_canonical_json(&preimage).unwrap());

        // Re-sign the V3 layer2 digest over the POISONED shards with the held
        // input key (the attacker class legitimately owns this key).
        let t_id_bytes: [u8; 32] = bs58::decode(&tx.t_id)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let eph_bytes: [u8; 32] = bs58::decode(tx.sender_ephemeral_pub.as_deref().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let enc_ts = encrypt_transaction_timestamp(&tx).unwrap();
        let trap = tx.trap_data.as_ref().unwrap();
        let l2_voucher_id = extract_layer2_voucher_id(&poisoned).unwrap();
        let payload_hash = calculate_l2_payload_hash_raw(
            &l2_voucher_id,
            &trap.ds_tag,
            &t_id_bytes,
            &eph_bytes,
            &trap.trap_r,
            &trap.trap_s,
            enc_ts,
            tx.deletable_at.as_deref(),
            &privacy_guard_commitment(tx.privacy_guard.as_deref()),
        );
        let l2_sig = sign_ed25519(&input_key, &payload_hash);
        tx.layer2_signature = Some(bs58::encode(l2_sig.to_bytes()).into_string());
        let id_sig = sign_ed25519(&ACTORS.alice.identity.signing_key, &t_id_bytes);
        tx.sender_identity_signature = Some(bs58::encode(id_sig.to_bytes()).into_string());

        *poisoned.transactions.last_mut().unwrap() = tx;

        // Ship the poisoned payment directly to the victim.
        let (attack_bundle, _) = {
            let (aw, a_identity) = alice.get_unlocked_mut_for_test();
            aw.create_and_encrypt_transaction_bundle(
                a_identity,
                vec![poisoned],
                &id_victim,
                None,
                vec![],
                HashMap::new(),
                None,
            )
            .expect("attacker bundle creation failed")
        };

        // SECURE INVARIANT (Soll-Verhalten): a transaction carrying trap
        // shards MUST present a verifying private SST witness at handover —
        // guard-less poison must be rejected fail-closed.
        victim.unlock_session(PASSWORD, 300).unwrap();
        let result = victim.receive_bundle(
            &attack_bundle,
            &standards_map,
            None,
            Some(PASSWORD),
            false,
        );
        assert!(
            result.is_err(),
            "AUDIT-01-F12: guard-less transfers carrying unverified trap \
             shards MUST be rejected at L1 handover (R5); unverified acceptance \
             lets offenders blind the SST autonomously"
        );
    }

    //==========================================================================
    // AUDIT-01-F13 (WH3-01-102): an off-line extra shard must not veto the
    // import of honestly attributed proofs
    //==========================================================================

    #[test]
    fn f13_offline_extra_shard_must_not_block_import_of_authentic_proof() {
        let dir = tempdir().unwrap();
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V14", PASSWORD);
        let reporter = ACTORS.hacker.identity.clone();

        // Genuine double spend bound to the offender's own key.
        let offender_sk = fresh_key();
        let offender_point = identity_point_of(&offender_sk);
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let (trap_a, t_id_a, trap_b, t_id_b, ds_tag) =
            build_honest_sst_forks(&offender_sk, &prev_hash_b58, &eph_b58);

        // The pair autonomously attributes the true did:key (generation side).
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();
        let extracted = trap_manager::extract_sst_identity(
            &ds_tag,
            &eph_bytes,
            &shard_fp(&ds_tag, &t_id_a, &trap_a),
            &shard_fp(&ds_tag, &t_id_b, &trap_b),
        )
        .expect("honest pair must extract");
        assert_eq!(extracted, offender_point);
        let offender_did =
            human_money_core::services::crypto_utils::create_user_id(
                &offender_sk.verifying_key(),
                None,
            )
            .unwrap();

        // Third shard: structurally valid (decompressable point + canonical
        // scalar) but OFF the reconstruction line — broadcast by the spender
        // to poison their own collision set.
        let mut junk_r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_r);
        let mut junk_s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut junk_s);
        let junk_trap = TrapData {
            ds_tag: ds_tag.clone(),
            trap_r: bs58::encode(junk_r).into_string(),
            trap_s: bs58::encode(junk_s).into_string(),
        };

        let make_tx = |t_id: String, trap: TrapData| {
            let mut tx = Transaction::default();
            tx.t_id = t_id;
            tx.prev_hash = prev_hash_b58.clone();
            tx.sender_ephemeral_pub = Some(eph_b58.clone());
            tx.recipient_id = "did:key:zSomeRecipient".to_string();
            tx.trap_data = Some(trap);
            tx
        };
        let conflicting = vec![
            make_tx(t_id_a, trap_a),
            make_tx(t_id_b, trap_b),
            make_tx(random_b58_32(), junk_trap),
        ];

        // Unpatched sanity: the full-set firewall (verify_sst_shards_consistency,
        // unchanged contract) rejects the poisoned set...
        {
            let fp_refs: Vec<TransactionFingerprint> = conflicting
                .iter()
                .map(|tx| TransactionFingerprint {
                    ds_tag: tx.trap_data.as_ref().unwrap().ds_tag.clone(),
                    t_id: tx.t_id.clone(),
                    trap_r: tx.trap_data.as_ref().unwrap().trap_r.clone(),
                    trap_s: tx.trap_data.as_ref().unwrap().trap_s.clone(),
                    ..Default::default()
                })
                .collect();
            let refs: Vec<&TransactionFingerprint> = fp_refs.iter().collect();
            assert!(
                trap_manager::verify_sst_shards_consistency(
                    &refs,
                    &offender_point,
                    &ds_tag,
                    &eph_bytes
                )
                .is_err(),
                "exploit precondition: full-set firewall rejects authentic \
                 evidence plus one off-line shard"
            );
        }

        // ...and therefore the whole honest report is unpersistable.
        let proof_id = derive_proof_id(&offender_did, &prev_hash_b58).unwrap();
        let signature = sign_ed25519(&reporter.signing_key, proof_id.as_bytes());
        let proof = ProofOfDoubleSpend {
            proof_id,
            offender_id: offender_did,
            suspected_identity: None,
            fork_point_prev_hash: prev_hash_b58,
            conflicting_transactions: conflicting,
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            reporter_id: reporter.user_id.clone(),
            report_timestamp: chrono::Utc::now().to_rfc3339(),
            reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
            affected_voucher_name: None,
            voucher_standard_uuid: None,
            resolutions: None,
            layer2_verdict: None,
            non_redeemable_test_voucher: false,
        };

        // SECURE INVARIANT (Soll-Verhalten): attribution stands on ANY
        // consistent colliding pair; extra shards must not veto authentic
        // evidence (anti-framing is untouched — a forged pair would still
        // constitute an EUF-CMA forgery).
        let (wallet, _) = victim.get_unlocked_mut_for_test();
        wallet
            .import_proof(proof)
            .expect("AUDIT-01-F13: an off-line extra shard must not block the \
                     import of an honestly attributed double-spend proof");
    }

    //==========================================================================
    // AUDIT-01-F14 (WH3-01-104): epoch-near sibling timestamps must lose
    // the Earliest-Wins race (plausibility window needs a lower bound)
    //==========================================================================

    #[test]
    fn f14_epoch_near_sibling_timestamp_must_not_win_offline_race() {
        let dir = tempdir().unwrap();
        let (mut victim, ds_tag, input_key, prev_hash, id_victim, standards_map) =
            setup_transfer_scenario(&dir);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H14", PASSWORD);

        assert_eq!(
            victim.get_voucher_summaries(None, None, None).unwrap()[0].status,
            human_money_core::VoucherStatus::Active,
            "precondition: local branch is active"
        );

        // Former-holder sibling dated to 3600ns after the Unix epoch: the
        // XOR key derives from the public prev_hash + chosen t_id, so the
        // attacker fully controls the decrypted timestamp. It passes the
        // upper-bound-only plausibility gate on unpatched code and beats
        // every genuine wall-clock-era branch.
        let mut sibling_t_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sibling_t_id);
        let enc_ts = 3600u128 ^ timestamp_xor_key(&prev_hash, &sibling_t_id);
        let poison_fp = make_v3_foreign_fp(
            &input_key,
            &ds_tag,
            &sibling_t_id,
            "forged_trap_r",
            "forged_trap_s",
            enc_ts,
        );

        send_gossip(&mut victim, &mut hacker, &id_victim, vec![poison_fp], &standards_map);

        // SECURE INVARIANT (Soll-Verhalten): a decrypted timestamp of 1970
        // (+1 microsecond-scale) is implausible for a genuine transaction —
        // the candidate must be discarded and the honest branch stays Active.
        let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
            .status
            .clone();
        assert_eq!(
            status_after,
            human_money_core::VoucherStatus::Active,
            "AUDIT-01-F14: epoch-near candidate timestamps must be rejected \
             by the lower plausibility bound instead of winning the \
             Earliest-Wins race"
        );
    }

    //==========================================================================
    // Regression Guards (already secure — must stay secure)
    //==========================================================================

    #[test]
    fn guard_extract_identity_rejects_identical_tau() {
        let sk = fresh_key();
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let (trap_a, t_id_a, _trap_b, _t_id_b, ds_tag) =
            build_honest_sst_forks(&sk, &prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        // Same t_id twice => identical evaluation points (tau) => no fork.
        let fp = shard_fp(&ds_tag, &t_id_a, &trap_a);
        assert!(
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp, &fp).is_err(),
            "identical tau values must never yield an identity"
        );
    }

    #[test]
    fn guard_extract_identity_rejects_non_canonical_response() {
        let sk = fresh_key();
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let (trap_a, t_id_a, trap_b, t_id_b, ds_tag) =
            build_honest_sst_forks(&sk, &prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();

        // s2' = s2 + L: same reduced scalar, non-canonical 32-byte encoding.
        let mut s2_bytes: [u8; 32] = bs58::decode(&trap_b.trap_s)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        add_group_order(&mut s2_bytes);

        let fp1 = shard_fp(&ds_tag, &t_id_a, &trap_a);
        let fp2 = TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: t_id_b,
            trap_r: trap_b.trap_r.clone(),
            trap_s: bs58::encode(s2_bytes).into_string(),
            ..Default::default()
        };

        let result =
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp1, &fp2);
        assert!(
            result.is_err(),
            "non-canonical response encodings (s and s+l) must be rejected \
             instead of being treated as distinct shard data"
        );
    }

    //==========================================================================
    // V3 PROTOCOL INVARIANTS — Self-Authenticating Fingerprints & Instant
    // Proofs (HMC_TX_AUTH_V3). These are hard architectural regression
    // firewalls: future changes must never weaken them.
    //==========================================================================

    use human_money_core::services::l2_gateway::{
        calculate_l2_payload_hash_raw, extract_layer2_voucher_id, privacy_guard_commitment,
    };
    use human_money_core::test_utils::derive_holder_key;

    /// Builds a self-authenticating (V3) spend fingerprint signed by `signer`
    /// over the canonical HMC_TX_AUTH_V3 digest.
    fn make_v3_foreign_fp(
        signer: &SigningKey,
        ds_tag: &str,
        t_id_bytes: &[u8; 32],
        trap_r: &str,
        trap_s: &str,
        encrypted_timestamp: u128,
    ) -> TransactionFingerprint {
        let eph_pub = signer.verifying_key().to_bytes();
        let payload_hash = calculate_l2_payload_hash_raw(
            "none",
            ds_tag,
            t_id_bytes,
            &eph_pub,
            trap_r,
            trap_s,
            encrypted_timestamp,
            None,
            "",
        );
        let sig = sign_ed25519(signer, &payload_hash);
        TransactionFingerprint {
            ds_tag: ds_tag.to_string(),
            trap_r: trap_r.to_string(),
            trap_s: trap_s.to_string(),
            t_id: bs58::encode(t_id_bytes).into_string(),
            layer2_signature: bs58::encode(sig.to_bytes()).into_string(),
            sender_ephemeral_pub: bs58::encode(eph_pub).into_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            encrypted_timestamp,
            layer2_voucher_id: "none".to_string(),
            privacy_guard_hash: String::new(),
        }
    }

    /// Derives the XOR key used by `encrypt_transaction_timestamp`.
    fn timestamp_xor_key(prev_hash_b58: &str, t_id_bytes: &[u8; 32]) -> u128 {
        let prev = bs58::decode(prev_hash_b58).into_vec().unwrap();
        let key_b58 = get_hash_from_slices(&[&prev, t_id_bytes]);
        let key = bs58::decode(key_b58).into_vec().unwrap();
        u128::from_le_bytes(key[..16].try_into().unwrap())
    }

    /// Shared scenario: Alice issues a voucher and transfers it to the victim.
    /// Returns everything needed to simulate a former-holder sibling fork:
    /// the victim service, the revealed INPUT ephemeral secret (the "holder"
    /// key of the genesis voucher, which Alice must keep after spending) and
    /// the fork anchor data of the victim's active branch.
    #[allow(clippy::type_complexity)]
    fn setup_transfer_scenario(
        dir: &tempfile::TempDir,
    ) -> (
        human_money_core::app_service::AppService,
        String,
        SigningKey,
        String,
        String,
        HashMap<String, String>,
    ) {
        use human_money_core::models::profile::PublicProfile;

        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;

        let (mut alice, _) = setup_service_with_profile(dir.path(), &ACTORS.alice, "A", PASSWORD);
        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V", PASSWORD);

        let id_alice = alice.get_user_id().unwrap();
        let id_victim = victim.get_user_id().unwrap();

        alice.unlock_session(PASSWORD, 300).unwrap();
        alice
            .create_new_voucher(
                &standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "100".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(id_alice.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .expect("voucher creation failed");

        // Reconstruct the holder (input) key Alice retains after spending.
        let init_voucher = {
            let (w, _) = alice.get_unlocked_mut_for_test();
            w.voucher_store
                .vouchers
                .values()
                .next()
                .unwrap()
                .voucher
                .clone()
        };
        let input_key =
            derive_holder_key(&init_voucher, &ACTORS.alice.identity.signing_key);

        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );

        let local_id = alice.get_voucher_summaries(None, None, None).unwrap()[0]
            .local_instance_id
            .clone();
        let request = MultiTransferRequest {
            recipient_id: id_victim.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: None,
        };
        let result = alice
            .create_transfer_bundle(request, &standards_map, None, Some(PASSWORD))
            .expect("transfer creation failed");
        victim.unlock_session(PASSWORD, 300).unwrap();
        victim
            .receive_bundle(&result.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
            .expect("victim must accept the honest transfer");

        // Extract the fork anchor from the victim's active branch.
        let (vw, _) = victim.get_unlocked_mut_for_test();
        let instance = vw.voucher_store.vouchers.values().next().unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();
        assert_eq!(
            last_tx.sender_ephemeral_pub.as_deref().unwrap(),
            bs58::encode(input_key.verifying_key().to_bytes()).into_string(),
            "precondition: the revealed input key matches the retained holder key"
        );
        let ds_tag = last_tx.trap_data.as_ref().unwrap().ds_tag.clone();
        let prev_hash = last_tx.prev_hash.clone();

        (victim, ds_tag, input_key, prev_hash, id_victim, standards_map)
    }

    /// Sends fingerprint-only gossip to `victim` as the hacker actor.
    fn send_gossip(
        victim: &mut human_money_core::app_service::AppService,
        hacker: &mut human_money_core::app_service::AppService,
        id_victim: &str,
        fps: Vec<TransactionFingerprint>,
        standards_map: &HashMap<String, String>,
    ) {
        let depths: HashMap<String, i8> =
            fps.iter().map(|f| (f.ds_tag.clone(), 1i8)).collect();
        hacker.unlock_session(PASSWORD, 300).unwrap();
        let (hw, hidentity) = hacker.get_unlocked_mut_for_test();
        let (bundle, _) = hw
            .create_and_encrypt_transaction_bundle(
                hidentity,
                vec![],
                id_victim,
                None,
                fps,
                depths,
                None,
            )
            .expect("gossip bundle creation failed");
        victim.unlock_session(PASSWORD, 300).unwrap();
        victim
            .receive_bundle(&bundle, standards_map, None, Some(PASSWORD), false)
            .expect("processing gossip bundle must succeed");
    }

    #[test]
    fn test_gossip_instant_proof_quarantines_loser_branch_in_realtime() {
        let dir = tempdir().unwrap();
        let (mut victim, ds_tag, input_key, prev_hash, id_victim, standards_map) =
            setup_transfer_scenario(&dir);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        assert_eq!(
            victim.get_voucher_summaries(None, None, None).unwrap()[0].status,
            human_money_core::VoucherStatus::Active,
            "precondition: local branch is active"
        );

        // Former-holder sibling fork: the attacker knows the fork prev_hash
        // and still holds the input one-time key, so they can produce a VALID
        // signature AND a decryptable, earlier timestamp for a fabricated
        // sibling transaction. This is exactly the reduced attacker class of
        // the V3 threat model.
        let mut sibling_t_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sibling_t_id);
        let early_nanos = (chrono::Utc::now().timestamp_nanos_opt().unwrap() as u128)
            .saturating_sub(3_600_000_000_000); // 1 hour earlier
        let enc_ts = early_nanos ^ timestamp_xor_key(&prev_hash, &sibling_t_id);
        let poison_fp = make_v3_foreign_fp(
            &input_key,
            &ds_tag,
            &sibling_t_id,
            "forged_trap_r",
            "forged_trap_s",
            enc_ts,
        );

        send_gossip(&mut victim, &mut hacker, &id_victim, vec![poison_fp], &standards_map);

        let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
            .status
            .clone();
        assert_eq!(
            status_after,
            human_money_core::VoucherStatus::Quarantined {
                reason: "Lost offline race".to_string()
            },
            "ARCHITECTURAL INVARIANT: Signed gossip collisions MUST immediately \
             quarantine the losing branch to block double-spends in real-time \
             without waiting for heavy transaction chains."
        );
    }

    #[test]
    fn test_unauthenticated_third_party_cannot_trigger_quarantine() {
        let dir = tempdir().unwrap();
        let (mut victim, ds_tag, _input_key, _prev_hash, id_victim, standards_map) =
            setup_transfer_scenario(&dir);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        // A pure third party signs with their OWN key (they never possessed
        // the input one-time key). The fingerprint is self-consistent and
        // passes verify_fingerprint_signature, but it cannot reproduce the
        // collision tag under the locally-known fork prev_hash.
        let attacker_key = SigningKey::generate(&mut OsRng);
        let mut forged_t_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut forged_t_id);
        let forged_fp = make_v3_foreign_fp(
            &attacker_key,
            &ds_tag,
            &forged_t_id,
            "third_party_trap_r",
            "third_party_trap_s",
            42, // would win the race if admitted
        );

        send_gossip(&mut victim, &mut hacker, &id_victim, vec![forged_fp], &standards_map);

        let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
            .status
            .clone();
        assert_eq!(
            status_after,
            human_money_core::VoucherStatus::Active,
            "SECURITY INVARIANT (AUDIT-01-F01 Remediation): Unsigned or forged \
             fingerprints must be dropped at ingress and never trigger quarantine."
        );
    }

    #[test]
    fn test_gossip_ingress_rejects_tampered_timestamp_or_trap_fields() {
        let dir = tempdir().unwrap();
        let (mut victim, _ds_tag, _input_key, _prev_hash, id_victim, standards_map) =
            setup_transfer_scenario(&dir);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        let base_ds_tag = random_b58_32();
        let signer = SigningKey::generate(&mut OsRng);
        let mut t_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut t_id);

        let valid = make_v3_foreign_fp(
            &signer,
            &base_ds_tag,
            &t_id,
            "trap_r_original",
            "trap_s_original",
            12345,
        );

        // Malleability firewall: ANY bit change in a digest-bound field breaks
        // the signature and the fingerprint is discarded at ingress.
        let mut tampered_ts = valid.clone();
        tampered_ts.encrypted_timestamp ^= 1;

        let mut tampered_r = valid.clone();
        tampered_r.trap_r = "trap_r_evil".to_string();

        let mut tampered_s = valid.clone();
        tampered_s.trap_s = "trap_s_evil".to_string();

        // Unsigned legacy data must be dropped as well.
        let mut unsigned = valid.clone();
        unsigned.layer2_signature = String::new();

        // Init-style fingerprints (shards == "none") are categorically
        // excluded: they have no detection value, regardless of any attached
        // signature.
        let mut init_style = valid;
        init_style.trap_r = "none".to_string();
        init_style.trap_s = "none".to_string();

        send_gossip(
            &mut victim,
            &mut hacker,
            &id_victim,
            vec![tampered_ts, tampered_r, tampered_s, unsigned, init_style],
            &standards_map,
        );

        let (vw, _) = victim.get_unlocked_mut_for_test();
        assert!(
            vw.known_fingerprints.foreign_fingerprints.is_empty(),
            "MALLEABILITY FIREWALL: every tampered / unsigned / init-style \
             fingerprint must be silently discarded at ingress, stored: {:?}",
            vw.known_fingerprints.foreign_fingerprints.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_former_holder_can_forge_collision_documented_behavior() {
        let dir = tempdir().unwrap();
        let (mut victim, ds_tag, input_key, prev_hash, id_victim, standards_map) =
            setup_transfer_scenario(&dir);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        // THREAT MODEL BOUNDARY (documented accepted residual risk):
        // A former key holder can produce technically signed sibling
        // fingerprints because they know the input secret. This is
        // mathematically indistinguishable from a genuine double spend
        // (possession of the key = disposal authority) and follows the core
        // paradigm "Fraud Detection, Not Prevention".
        //
        // The "Earliest Wins" heuristic stays FAIR within this class: a
        // sibling with a LATER timestamp loses the race and cannot quarantine
        // the honest earlier branch.
        let mut sibling_t_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sibling_t_id);
        let late_nanos = (chrono::Utc::now().timestamp_nanos_opt().unwrap() as u128)
            + 3_600_000_000_000; // 1 hour later than the real spend
        let enc_ts = late_nanos ^ timestamp_xor_key(&prev_hash, &sibling_t_id);
        let late_sibling = make_v3_foreign_fp(
            &input_key,
            &ds_tag,
            &sibling_t_id,
            "forged_trap_r",
            "forged_trap_s",
            enc_ts,
        );

        send_gossip(&mut victim, &mut hacker, &id_victim, vec![late_sibling], &standards_map);

        let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
            .status
            .clone();
        assert_eq!(
            status_after,
            human_money_core::VoucherStatus::Active,
            "THREAT MODEL INVARIANT: A former-holder sibling with a LATER \
             timestamp must lose the Earliest-Wins race; detection-not-\
             prevention keeps the honest earliest branch active."
        );
    }

    #[test]
    fn test_synthetic_placeholder_proof_import_structure() {
        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;
        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );

        // Witness wallet observes a pure-gossip collision between two signed
        // sibling fingerprints sharing one input key.
        let (mut witness, _) =
            setup_service_with_profile(dir.path(), &ACTORS.david, "W", PASSWORD);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        let input_key = SigningKey::generate(&mut OsRng);
        let collision_tag = random_b58_32();
        // NOTE: the shard strings deliberately contain '_' (invalid Base58) so
        // SST collision extraction deterministically fails — the soft proof
        // must then stay at the conservative `ephemeral:` linkage. (With
        // GENUINE shards, extraction succeeds and the offender becomes the
        // signer's did:key directly — see test_sst_instant_proof_* below.)
        let fp_a = make_v3_foreign_fp(
            &input_key,
            &collision_tag,
            &[1u8; 32],
            "shard_r_a",
            "shard_s_a",
            1000,
        );
        let fp_b = make_v3_foreign_fp(
            &input_key,
            &collision_tag,
            &[2u8; 32],
            "shard_r_b",
            "shard_s_b",
            2000,
        );

        let id_witness = witness.get_user_id().unwrap();
        send_gossip(&mut witness, &mut hacker, &id_witness, vec![fp_a, fp_b], &standards_map);

        // The witness auto-created a Gossip Soft Proof from placeholders.
        let proof = {
            let (ww, _) = witness.get_unlocked_mut_for_test();
            assert_eq!(ww.proof_store.proofs.len(), 1, "soft proof must be created");
            ww.proof_store.proofs.values().next().unwrap().proof.clone()
        };
        assert!(
            proof.offender_id.starts_with("ephemeral:"),
            "ANTI-FRAMING FIREWALL (AUDIT-01-F05): Instant Gossip Soft Proofs \
             must NEVER claim an unproven did:key identity as offender_id; got '{}'",
            proof.offender_id
        );
        let claimed_eph = proof
            .offender_id
            .strip_prefix("ephemeral:")
            .unwrap()
            .to_string();
        assert_eq!(
            claimed_eph,
            bs58::encode(input_key.verifying_key().to_bytes()).into_string(),
            "canonical linkage must name the revealed ephemeral key"
        );
        assert!(
            proof.conflicting_transactions.iter().all(|tx| {
                tx.t_type == "gossip_soft_placeholder"
                    && tx.prev_hash == collision_tag
                    && tx
                        .trap_data
                        .as_ref()
                        .map(|t| !t.trap_r.is_empty() && !t.trap_s.is_empty())
                        .unwrap_or(false)
            }),
            "placeholders must carry the gossip trap shards"
        );

        // Full importability: a fresh wallet accepts the serialized soft proof.
        let bytes = serde_json::to_vec(&proof).unwrap();
        let imported: human_money_core::models::conflict::ProofOfDoubleSpend =
            serde_json::from_slice(&bytes).unwrap();
        let (mut importer, _) =
            setup_service_with_profile(dir.path(), &ACTORS.bob, "I", PASSWORD);
        importer.unlock_session(PASSWORD, 300).unwrap();
        importer.import_proof(imported, Some(PASSWORD)).expect(
            "STRUCTURE INVARIANT: Gossip Soft Proofs built from complete \
             synthetic placeholders must pass all import gates",
        );
    }

    #[test]
    fn test_framed_did_key_offender_claim_is_rejected_at_import() {
        let dir = tempdir().unwrap();
        let (mut witness, _) =
            setup_service_with_profile(dir.path(), &ACTORS.david, "W", PASSWORD);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);

        let input_key = SigningKey::generate(&mut OsRng);
        let tag = random_b58_32();
        let fps = vec![
            make_v3_foreign_fp(&input_key, &tag, &[3u8; 32], "u_x", "V_x", 10),
            make_v3_foreign_fp(&input_key, &tag, &[4u8; 32], "u_y", "V_y", 20),
        ];
        let id_witness = witness.get_user_id().unwrap();
        send_gossip(&mut witness, &mut hacker, &id_witness, fps, &HashMap::new());

        let mut proof = {
            let (ww, _) = witness.get_unlocked_mut_for_test();
            ww.proof_store.proofs.values().next().unwrap().proof.clone()
        };

        // An attacker rewrites the attribution onto an innocent did:key and
        // re-signs the report (they control the reporter anyway).
        proof.offender_id = ACTORS.alice.identity.user_id.clone();
        proof.proof_id = derive_proof_id(&proof.offender_id, &proof.fork_point_prev_hash).unwrap();
        let reporter_sig = sign_ed25519(
            &ACTORS.hacker.identity.signing_key,
            proof.proof_id.as_bytes(),
        );
        proof.reporter_signature = bs58::encode(reporter_sig.to_bytes()).into_string();

        let (mut importer, _) =
            setup_service_with_profile(dir.path(), &ACTORS.bob, "I", PASSWORD);
        importer.unlock_session(PASSWORD, 300).unwrap();
        assert!(
            importer.import_proof(proof, Some(PASSWORD)).is_err(),
            "ANTI-FRAMING FIREWALL (AUDIT-01-F05): a did:key offender claim on \
             placeholder shards that verify against NO identity MUST fail the \
             SST shard-consistency attribution gate"
        );
    }

    #[test]
    fn test_init_fingerprints_excluded_from_gossip_export_and_ingress() {
        use human_money_core::models::profile::PublicProfile;

        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;
        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );

        let (mut alice, _) = setup_service_with_profile(dir.path(), &ACTORS.alice, "A", PASSWORD);
        let id_alice = alice.get_user_id().unwrap();
        alice.unlock_session(PASSWORD, 300).unwrap();
        alice
            .create_new_voucher(
                &standard_toml,
                NewVoucherData {
                    nominal_value: ValueDefinition {
                        amount: "50".to_string(),
                        ..Default::default()
                    },
                    creator_profile: PublicProfile {
                        id: Some(id_alice.clone()),
                        ..Default::default()
                    },
                    validity_duration: Some("P4Y".to_string()),
                    ..Default::default()
                },
                Some(PASSWORD),
            )
            .unwrap();

        // EXPORT FILTER: the genesis ('init') fingerprint exists locally but
        // must never be selected for gossip export.
        let bob_id = ACTORS.bob.identity.user_id.clone();
        let (selected, _) = {
            let (aw, _) = alice.get_unlocked_mut_for_test();
            assert!(
                aw.own_fingerprints
                    .history
                    .values()
                    .flatten()
                    .any(human_money_core::services::conflict_manager::is_init_fingerprint),
                "precondition: init fingerprint exists locally"
            );
            aw.select_fingerprints_for_bundle(&bob_id, &[]).unwrap()
        };
        assert!(
            selected
                .iter()
                .all(|fp| !human_money_core::services::conflict_manager::is_init_fingerprint(fp)),
            "GOSSIP EXPORT FILTER: init fingerprints must never leave the wallet"
        );

        // INGRESS FILTER: even a self-consistent init-style fingerprint
        // (shards == "none") is categorically dropped before any signature
        // check, because genesis gossip carries no detection value.
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H", PASSWORD);
        let mut init_fp = make_v3_foreign_fp(
            &SigningKey::generate(&mut OsRng),
            random_b58_32().as_str(),
            &[9u8; 32],
            "spend_trap_r",
            "spend_trap_s",
            0,
        );
        init_fp.trap_r = "none".to_string();
        init_fp.trap_s = "none".to_string();

        let (mut victim, _) =
            setup_service_with_profile(dir.path(), &ACTORS.charlie, "V", PASSWORD);
        let id_victim = victim.get_user_id().unwrap();
        send_gossip(&mut victim, &mut hacker, &id_victim, vec![init_fp], &standards_map);

        let (vw, _) = victim.get_unlocked_mut_for_test();
        assert!(
            vw.known_fingerprints.foreign_fingerprints.is_empty(),
            "INGRESS FILTER: init fingerprints must never enter foreign stores"
        );
    }

    //==========================================================================
    // V3 SST PROTOCOL EVOLUTION — Verification Plan (security core)
    //==========================================================================

    /// Zero-knowledge / no-registry-mining invariant (P-pre anonymity).
    ///
    /// A single gossip fingerprint $(R_i, s_i)$ must carry ZERO usable
    /// identity information. Formally, the recipient-consistency system has
    /// 4 unknowns $(R_{sig}, s_{sig}, M_R, m_s)$ and only 3 equations, so for
    /// EVERY candidate identity $X_c$ there exists a 1-parameter family of
    /// witnesses consistent with the very same shard ($m_s$ is the free
    /// parameter once $r$ is fixed). A registry mining shards therefore
    /// cannot decide which DID produced a fingerprint without solving
    /// discrete logarithms.
    ///
    /// This test demonstrates the witness-fiber property constructively: TWO
    /// completely independent witnesses (different Schnorr nonces AND
    /// different masking scalars) verify against the byte-identical shard,
    /// proving that the shard does not even uniquely determine its own
    /// witness — let alone the identity behind it.
    #[test]
    fn test_sst_zero_knowledge_no_p_pre_registry_mining() {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use human_money_core::services::crypto_utils::get_secret_scalar;
        use human_money_core::services::trap_manager::{
            compute_tau, hash_to_scalar,
        };

        let sk = fresh_key();
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let ds_tag = ds_tag_of(&prev_hash_b58, &eph_b58);
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();
        let t_id = random_b58_32();

        let (shard, witness_a) =
            trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_id).unwrap();

        // --- Constructive fiber demonstration -------------------------------
        // Build a SECOND witness from a fresh nonce r' and the corresponding
        // free parameter m_s' = (s_i - r' - c'*x)/tau. Only the TRUE signer
        // can perform this computation (it requires x) — which is exactly why
        // a shard alone binds nothing and cannot be mined for identities.
        let x = get_secret_scalar(&sk);
        let tau = compute_tau(&ds_tag, &t_id);
        let s_i = Scalar::from_canonical_bytes(
            bs58::decode(&shard.trap_s)
                .into_vec()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .into_option()
        .unwrap();

        let mut nonce_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_seed);
        let r_prime = hash_to_scalar(&nonce_seed);
        let r_prime_point = r_prime * ED25519_BASEPOINT_POINT;

        // Free parameter solving ALL three recipient checks for THIS signer:
        // s_i = r' + c'*x + tau*m_s'   =>   m_s' = (s_i - r' - c'*x)/tau
        // where c' is the challenge over (mu, R_sig').
        let mu = trap_manager::compute_trap_message_mu(&ds_tag, &eph_bytes);
        let c_prime = trap_manager::compute_sst_challenge(&mu, &r_prime_point);
        let m_s_prime = (s_i - r_prime - c_prime * x) * tau.invert();

        // M_R' follows from constraint (2): R_i = R_sig' + tau * M_R'.
        // We reuse the honest generation path instead of hand-deriving the
        // point algebra here: regenerate with overridden nonce semantics via
        // a fresh key would change s_sig; instead verify through the engine.
        let witness_b = TrapWitness {
            r_sig: bs58::encode(r_prime_point.compress().as_bytes()).into_string(),
            s_sig: bs58::encode((s_i - tau * m_s_prime).as_bytes()).into_string(),
            // M_R' = (R_i - R_sig') / tau
            m_r: {
                let r_bytes: [u8; 32] = bs58::decode(&shard.trap_r)
                    .into_vec()
                    .unwrap()
                    .try_into()
                    .unwrap();
                let r_i_pt = CompressedEdwardsY::from_slice(&r_bytes)
                    .unwrap()
                    .decompress()
                    .unwrap();
                let m_r_pt = (r_i_pt - r_prime_point) * tau.invert();
                bs58::encode(m_r_pt.compress().as_bytes()).into_string()
            },
            m_s: bs58::encode(m_s_prime.as_bytes()).into_string(),
        };

        // The true payer DID of `sk` in project-canonical multicodec format.
        let payer_did_true = {
            let vk = sk.verifying_key();
            let mut mc = vec![0xed_u8, 0x01];
            mc.extend_from_slice(vk.as_bytes());
            format!("did:key:z{}", bs58::encode(mc).into_string())
        };

        // Both structurally INDEPENDENT witnesses validate the same shard...
        trap_manager::verify_sst_witness(&witness_a, &shard, &payer_did_true, &ds_tag, &eph_bytes, &t_id)
            .expect("witness A (deterministic nonce) must verify");
        trap_manager::verify_sst_witness(&witness_b, &shard, &payer_did_true, &ds_tag, &eph_bytes, &t_id)
            .expect("witness B (fresh nonce + free parameter) must verify");
        assert_ne!(
            witness_a.r_sig, witness_b.r_sig,
            "the two witnesses must be genuinely independent fiber members"
        );

        // --- Avalanche: distinct evaluation points yield unrelated shards ---
        let other_t = random_b58_32();
        let (shard_other, _) =
            trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &other_t).unwrap();
        assert_ne!(
            shard.trap_r, shard_other.trap_r,
            "distinct t_ids must yield computationally unrelated shards"
        );

        // --- Single-shard mining impossibility -------------------------------
        let lone_fp = shard_fp(&ds_tag, &t_id, &shard);
        assert!(
            trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &lone_fp, &lone_fp).is_err(),
            "a single fingerprint must never enable identity extraction"
        );
        let stranger_pt = identity_point_of(&fresh_key());
        assert!(
            trap_manager::verify_sst_shards_consistency(&[&lone_fp], &stranger_pt, &ds_tag, &eph_bytes)
                .is_err(),
            "registry mining with fewer than two colliding shards is impossible"
        );
    }

    /// Instant deanonymization invariant (R2/R3): two colliding V3 gossip
    /// fingerprints autonomously reveal the offender's true `did:key` —
    /// without requesting transaction chains.
    #[test]
    fn test_sst_instant_proof_direct_did_deanonymization() {
        let offender_sk = fresh_key();
        let offender_point = identity_point_of(&offender_sk);
        let expected_did =
            human_money_core::services::crypto_utils::create_user_id(
                &offender_sk.verifying_key(),
                None,
            )
            .unwrap();

        // Genuine double spend: same input anchor, two distinct forks.
        let prev_hash_b58 = random_b58_32();
        let eph_k = SigningKey::generate(&mut OsRng);
        let eph_pub = eph_k.verifying_key().to_bytes();
        let eph_b58 = bs58::encode(eph_pub).into_string();
        let ds_tag = ds_tag_of(&prev_hash_b58, &eph_b58);

        let t_id_a = random_b58_32();
        let t_id_b = random_b58_32();
        let (trap_a, _) =
            trap_manager::generate_sst_trap(&offender_sk, &ds_tag, &eph_pub, &t_id_a).unwrap();
        let (trap_b, _) =
            trap_manager::generate_sst_trap(&offender_sk, &ds_tag, &eph_pub, &t_id_b).unwrap();

        // Unit level: extraction recovers exactly the signer identity point.
        let fp_a = shard_fp(&ds_tag, &t_id_a, &trap_a);
        let fp_b = shard_fp(&ds_tag, &t_id_b, &trap_b);
        let extracted =
            trap_manager::extract_sst_identity(&ds_tag, &eph_pub, &fp_a, &fp_b).unwrap();
        assert_eq!(extracted, offender_point, "extraction must recover the signer");

        // End-to-end: a witness wallet receives the two SIGNED gossip
        // fingerprints and auto-attributes the real did:key directly.
        let dir = tempdir().unwrap();
        let standard_toml =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let (standard_def, _) = &*FREETALER_STANDARD;
        let mut standards_map = HashMap::new();
        standards_map.insert(
            standard_def.immutable.identity.uuid.clone(),
            standard_toml.clone(),
        );
        let (mut witness, _) =
            setup_service_with_profile(dir.path(), &ACTORS.david, "W2", PASSWORD);
        let (mut hacker, _) =
            setup_service_with_profile(dir.path(), &ACTORS.hacker, "H2", PASSWORD);

        let signed_fps = vec![
            make_v3_foreign_fp(
                &eph_k,
                &ds_tag,
                &bs58::decode(&t_id_a).into_vec().unwrap().try_into().unwrap(),
                &trap_a.trap_r,
                &trap_a.trap_s,
                1000,
            ),
            make_v3_foreign_fp(
                &eph_k,
                &ds_tag,
                &bs58::decode(&t_id_b).into_vec().unwrap().try_into().unwrap(),
                &trap_b.trap_r,
                &trap_b.trap_s,
                2000,
            ),
        ];
        let id_witness = witness.get_user_id().unwrap();
        send_gossip(&mut witness, &mut hacker, &id_witness, signed_fps, &standards_map);

        let proof = {
            let (ww, _) = witness.get_unlocked_mut_for_test();
            ww.proof_store.proofs.values().next().expect("soft proof must exist").proof.clone()
        };
        assert_eq!(
            proof.offender_id, expected_did,
            "SST INSTANT PROOF: the collision must autonomously unmask the \
             offender's true did:key straight from gossip"
        );
        assert_eq!(
            proof.suspected_identity.as_deref(),
            Some(expected_did.as_str()),
            "advisory field mirrors the now-proven identity"
        );
    }

    /// L1 fraud prevention (R5): a recipient rejects payments whose private
    /// trap witness is garbage or manipulated.
    #[test]
    fn test_sst_l1_payment_rejection_on_corrupt_witness() {
        let sk = fresh_key();
        let payer_did = {
            let vk = sk.verifying_key();
            let mut mc = vec![0xed_u8, 0x01];
            mc.extend_from_slice(vk.as_bytes());
            format!("did:key:z{}", bs58::encode(mc).into_string())
        };
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();
        let ds_tag = ds_tag_of(&prev_hash_b58, &eph_b58);
        let t_id = random_b58_32();

        let (shard, witness) =
            trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_id).unwrap();

        // Honest control passes.
        trap_manager::verify_sst_witness(&witness, &shard, &payer_did, &ds_tag, &eph_bytes, &t_id)
            .expect("honest handover must verify");

        // Garbage trap shard (random bytes instead of the committed point).
        let mut garbage_shard = shard.clone();
        garbage_shard.trap_r = random_b58_32();
        assert!(
            trap_manager::verify_sst_witness(&witness, &garbage_shard, &payer_did, &ds_tag, &eph_bytes, &t_id)
                .is_err(),
            "MUST reject: garbage commitment shard"
        );

        // Manipulated response shard.
        let mut tampered_shard = shard.clone();
        let mut s = [0u8; 32];
        s[..31].copy_from_slice(&bs58::decode(&shard.trap_s).into_vec().unwrap()[..31]);
        s[31] = s[31].wrapping_sub(1);
        tampered_shard.trap_s = bs58::encode(s).into_string();
        assert!(
            trap_manager::verify_sst_witness(&witness, &tampered_shard, &payer_did, &ds_tag, &eph_bytes, &t_id)
                .is_err(),
            "MUST reject: manipulated response shard"
        );

        // Manipulated witness components (each individually fatal).
        let flip_point_str = |s: &str| {
            let mut b: [u8; 32] = bs58::decode(s).into_vec().unwrap().try_into().unwrap();
            b[0] ^= 0x01;
            bs58::encode(b).into_string()
        };
        let w_bad_r = TrapWitness { r_sig: flip_point_str(&witness.r_sig), ..witness.clone() };
        let w_bad_mr = TrapWitness { m_r: flip_point_str(&witness.m_r), ..witness.clone() };
        let wrong_payer = ACTORS.alice.identity.user_id.clone();
        let wrong_t_id = random_b58_32();

        for (label, w, p_did, t) in [
            ("R_sig", w_bad_r, payer_did.clone(), t_id.clone()),
            ("M_R", w_bad_mr, payer_did.clone(), t_id.clone()),
            ("wrong payer DID", witness.clone(), wrong_payer, t_id.clone()),
            ("wrong t_id", witness.clone(), payer_did, wrong_t_id),
        ] {
            assert!(
                trap_manager::verify_sst_witness(&w, &shard, &p_did, &ds_tag, &eph_bytes, &t)
                    .is_err(),
                "MUST reject corrupted witness component: {label}"
            );
        }
    }

    /// Degenerate-case firewall: every guard of the collision reconstruction
    /// fires BEFORE any algebraic inversion can produce garbage output.
    #[test]
    fn test_sst_degenerate_cases_firewall() {
        let sk = fresh_key();
        let expected_x = identity_point_of(&sk);
        let prev_hash_b58 = random_b58_32();
        let eph_b58 = random_b58_32();
        let eph_bytes: [u8; 32] =
            bs58::decode(&eph_b58).into_vec().unwrap().try_into().unwrap();
        let ds_tag = ds_tag_of(&prev_hash_b58, &eph_b58);

        // Guard 1: tau1 == tau2 (identical t_ids).
        let t_same = random_b58_32();
        let (t1, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_same).unwrap();
        let fp_same = shard_fp(&ds_tag, &t_same, &t1);
        assert!(trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp_same, &fp_same).is_err());

        // Guard 2: identical shards under distinct t_ids.
        let t_a = random_b58_32();
        let (t2, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_a).unwrap();
        let fp_i1 = shard_fp(&ds_tag, &t_a, &t2);
        let fp_i2 = shard_fp(&ds_tag, &random_b58_32(), &t2);
        assert!(trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp_i1, &fp_i2).is_err());

        // Guard 3: non-canonical response scalars (s >= q encodings).
        let t_b = random_b58_32();
        let t_c = random_b58_32();
        let (t3, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_b).unwrap();
        let (t4, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_c).unwrap();
        let mut s_nc: [u8; 32] =
            bs58::decode(&t4.trap_s).into_vec().unwrap().try_into().unwrap();
        add_group_order(&mut s_nc);
        let fp_nc1 = shard_fp(&ds_tag, &t_b, &t3);
        let fp_nc2 = TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: t_c,
            trap_r: t4.trap_r.clone(),
            trap_s: bs58::encode(s_nc).into_string(),
            ..Default::default()
        };
        assert!(trap_manager::extract_sst_identity(&ds_tag, &eph_bytes, &fp_nc1, &fp_nc2).is_err());

        // Guard 4: n >= 3 shard set with ONE inconsistent extra member.
        let t_d = random_b58_32();
        let t_e = random_b58_32();
        let t_f = random_b58_32();
        let (ta, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_d).unwrap();
        let (tb, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_e).unwrap();
        let (tc, _) = trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_f).unwrap();
        // Replace shard C's commitment with an unrelated valid point.
        let mut foreign_r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut foreign_r);
        let tc_off = TrapData {
            ds_tag: tc.ds_tag.clone(),
            trap_r: bs58::encode(foreign_r).into_string(),
            trap_s: tc.trap_s.clone(),
        };
        let fa = shard_fp(&ds_tag, &t_d, &ta);
        let fb = shard_fp(&ds_tag, &t_e, &tb);
        let fc = shard_fp(&ds_tag, &t_f, &tc_off);
        assert!(
            trap_manager::verify_sst_shards_consistency(&[&fa, &fb, &fc], &expected_x, &ds_tag, &eph_bytes)
                .is_err(),
            "inconsistent n>=3 shard sets must be rejected outright"
        );
        // The honest subset still verifies (guard precision check).
        assert!(trap_manager::verify_sst_shards_consistency(&[&fa, &fb], &expected_x, &ds_tag, &eph_bytes).is_ok());
    }
}
