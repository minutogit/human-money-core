//! # Security Audit Wave 4 — Module 01 Trap/Conflict Re-Audit (Fail-First)
//!
//! Fail-first reproduction tests for Wave-4 hypotheses WH4-01-201..203
//! against the post-Wave-3 baseline (branch `live`). Each test asserts the
//! SECURE required behavior (Soll-Verhalten); on unpatched code every test
//! MUST fail, proving the vulnerability. On fix, each test turns green and
//! becomes a permanent regression shield.
//!
//! ## Standardized Finding Metadata
//!
//! ### AUDIT-W4-TRAP-201 — Import boundary accepts fabricated evidence for
//! `ephemeral:`/anonymous soft proofs (no cryptographic evidence verification)
//! * **Finding-ID:** AUDIT-W4-TRAP-201 (Wave-4 hypothesis WH4-01-201)
//! * **Severity:** HIGH
//! * **CWE:** CWE-347 (Improper Verification of Cryptographic Signature) /
//!   CWE-345 (Insufficient Verification of Data Authenticity)
//! * **Target:** `src/wallet/conflict_handler.rs::import_proof` (~440–491,
//!   Gate 3b/4 + `VerificationOutcome::NoLocalContext`) in interaction with
//!   `src/services/conflict_manager.rs::verify_proof_structure`
//!   (~557–585, `gossip_soft_placeholder` shape-only branch)
//! * **Threat Model:** Gate 3b re-verifies SST shards ONLY when `offender_id`
//!   parses as a did:key. The sibling attribution class
//!   `ephemeral:<sender_ephemeral_pub>` (the canonical offender identifier for
//!   ALL gossip soft proofs) and `anonymous` skip every cryptographic gate.
//!   Without local voucher context Gate 4 is skipped entirely. An attacker
//!   takes a victim's publicly gossiped ephemeral key, fabricates two
//!   structurally consistent `gossip_soft_placeholder` transactions with
//!   garbage shards, self-signs the reporter signature and injects a
//!   persistent fraud record naming `ephemeral:E_victim`.
//! * **Impact:** Persistent defamatory proof-store entry + reputation flip to
//!   `TrustStatus::KnownOffender` (exact string match,
//!   `src/wallet/queries.rs::check_reputation`) on every importing peer —
//!   framing without any verifiable evidence binding the claimed spender key
//!   to the embedded transactions.
//! * **Root Cause:** The legitimacy source of an ephemeral claim (verified
//!   layer2_signature at gossip ingress) is not re-established at the trust
//!   boundary that grants persistence and reputation weight; no evidence-
//!   authenticity requirement exists for non-did:key offender claims.
//! * **Remediation Strategy:** Reject any imported proof whose `ephemeral:`
//!   offender claim is not backed by per-transaction V3 evidence verifying
//!   under the claimed ephemeral key (or, minimum, persist it stripped of all
//!   offender linkage so reputation stays untouched).
//! * **Test Semantics:** Fail-first. Asserts the secure invariant:
//!   `import_proof` rejects the forged claim OR the record is stored without
//!   any offender linkage (`check_reputation` stays clean). On unpatched code
//!   the import succeeds and reputation flips to KnownOffender.
//!
//! ### AUDIT-W4-TRAP-202 — Genesis/init transactions accept arbitrary
//! `trap_data` — authenticated spend-claim masquerade under attacker-chosen
//! DS-Tags
//! * **Finding-ID:** AUDIT-W4-TRAP-202 (Wave-4 hypothesis WH4-01-202)
//! * **Severity:** MEDIUM
//! * **CWE:** CWE-20 (Improper Input Validation) / CWE-349
//! * **Target:** `src/services/voucher_validation/chain.rs` (~164 `.skip(1)`
//!   loop scoping; trap block ~310–367 runs ONLY for non-init txs) feeding
//!   `src/services/conflict_manager.rs::create_fingerprint_for_transaction`
//!   (~77–123, trusts `trap.ds_tag` blindly whenever `trap_data.is_some()`)
//! * **Threat Model:** Any voucher author embeds
//!   `TrapData { ds_tag: D_attacker, well-formed SST shards }` into the INIT
//!   transaction. Chain validation never inspects init trap content (the
//!   shard-structure firewall and the ds_tag input-binding check live inside
//!   the `.skip(1)` loop). The resulting fingerprint is classified
//!   spend-typed (`is_init_fingerprint == false` because shards != "none"),
//!   inherits the attacker-chosen ds_tag and enters the detection pipeline /
//!   local history buckets as authenticated junk spend claims.
//! * **Impact:** Detection-grade noise minted at will: persistent junk
//!   conflicts, soft-proof creation, UI/event pollution and foreign-store
//!   occupancy on every peer lacking local context for D_attacker.
//! * **Root Cause:** The skip(1) scoping leaves the init row outside both the
//!   shard-structure firewall (HMSEC-SA04-09) and the ds_tag context-binding
//!   check; fingerprint creation trusts `trap.ds_tag` unconditionally.
//! * **Remediation Strategy:** Either reject trap-bearing init transactions
//!   during chain validation, or classify fingerprints of init transactions
//!   as init/no-trap regardless of embedded trap content so they cannot enter
//!   the gossip/detection pipeline.
//! * **Test Semantics:** Fail-first. A minimal valid voucher whose init tx
//!   carries genuine SST shards under an attacker-chosen ds_tag must EITHER
//!   fail chain validation OR produce an init-classified fingerprint.
//!   On unpatched code validation passes and the fingerprint is spend-typed.
//!
//! ### AUDIT-W4-TRAP-203 — Unbounded foreign fingerprint buckets: quadratic
//! SST extraction work and unbounded authenticated junk storage
//! * **Finding-ID:** AUDIT-W4-TRAP-203 (Wave-4 hypothesis WH4-01-203)
//! * **Severity:** MEDIUM
//! * **CWE:** CWE-770 (Allocation of Resources Without Limits) / CWE-407
//! * **Target:** `src/services/conflict_manager.rs::import_foreign_fingerprints`
//!   (~848–892, no per-bucket/global admission cap) feeding
//!   `src/wallet/conflict_handler.rs::verify_and_create_proof` (O(n²)
//!   pairwise `extract_sst_identity`)
//! * **Threat Model:** Fingerprints are self-authenticating by design; for
//!   ds_tags WITHOUT local input context the storage-time gate admits
//!   anything the attacker signs with their own keys. Outbound gossip is
//!   capped (`MAX_FINGERPRINTS_TO_SEND = 150`), inbound admission has NO
//!   symmetric limit. An attacker gossips N validly signed fingerprints
//!   sharing one attacker-chosen ds_tag; every receiving wallet stores all of
//!   them for uniform retention and later runs O(N²) shard-pair parse
//!   attempts inside synchronous wallet code.
//! * **Impact:** Cheap authenticated gossip channel converted into persistent
//!   CPU/memory amplification DoS against offline-first devices.
//! * **Root Cause:** Missing resource-bounded adversarial ingestion bound —
//!   no cap exists between the signature gate and the store.
//! * **Remediation Strategy:** Enforce a bounded admission cap per bucket /
//!   global foreign store size at ingress (cap value = design decision).
//! * **Test Semantics:** Fail-first, STATE-based (no wall-clock assertions):
//!   2000 hand-signed fingerprints under one ds_tag must NOT all be admitted.
//!   The proposed symmetric bound mirrors the outbound cap (150). On
//!   unpatched code `accepted == bucket_len == 2000`, which is itself the
//!   proof of the missing cap.

use ed25519_dalek::SigningKey;
use human_money_core::models::conflict::{
    ProofOfDoubleSpend, TransactionFingerprint, TrustStatus,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{TrapData, ValueDefinition};
use human_money_core::services::conflict_manager::{
    create_fingerprint_for_transaction, derive_proof_id, import_foreign_fingerprints,
    is_init_fingerprint,
};
use human_money_core::services::crypto::identity::get_prefix_from_user_id;
use human_money_core::services::crypto::keys::derive_ephemeral_key_pair;
use human_money_core::services::crypto::sign_ed25519;
use human_money_core::services::trap_manager::generate_sst_trap;
use human_money_core::NewVoucherData;
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::{create_test_wallet, ACTORS};
use rand::RngCore;

/// Proposed inbound admission bound, symmetric to the existing outbound cap
/// `MAX_FINGERPRINTS_TO_SEND = 150`
/// (src/wallet/conflict_handler.rs::select_fingerprints_for_bundle).
/// The concrete value is a design decision; SOME hard bound must exist.
const PROPOSED_INBOUND_BUCKET_CAP: usize = 150;

fn fresh_key() -> SigningKey {
    let mut sk = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk);
    SigningKey::from_bytes(&sk)
}

fn random_b58_32() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    bs58::encode(buf).into_string()
}

//==============================================================================
// AUDIT-W4-TRAP-201 (WH4-01-201, HIGH): fabricated `ephemeral:` soft-proof
// claims must not gain persistent offender linkage at the import boundary
//==============================================================================

#[test]
fn wh4_01_201_import_rejects_unverified_ephemeral_offender_claims() {
    let (mut wallet, _identity) =
        create_test_wallet("wave4-201", "w4-201".to_string())
            .expect("fresh witness wallet");

    // Victim ephemeral key: public data present in every spend fingerprint.
    let victim_eph = fresh_key();
    let victim_eph_b58 = bs58::encode(victim_eph.verifying_key().to_bytes()).into_string();
    let offender_claim = format!("ephemeral:{}", victim_eph_b58);

    // Attacker-chosen collision tag; the fork point proxy convention for
    // gossip soft proofs is fork_point_prev_hash == ds_tag.
    let ds_tag = random_b58_32();
    let attacker = &ACTORS.hacker.identity;

    // Two structurally consistent gossip_soft_placeholder transactions with
    // garbage (never-signed) SST shards attributed to the victim's key.
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
    let make_tx = |t_id: String| {
        let (trap_r, trap_s) = forge_shard();
        let mut tx = human_money_core::models::voucher::Transaction::default();
        tx.t_type = "gossip_soft_placeholder".to_string();
        tx.t_id = t_id;
        tx.prev_hash = ds_tag.clone();
        tx.sender_ephemeral_pub = Some(victim_eph_b58.clone());
        tx.t_time = "2026-08-26T12:00:00Z".to_string();
        tx.amount = "0.00 (Gossip)".to_string();
        tx.trap_data = Some(TrapData {
            ds_tag: ds_tag.clone(),
            trap_r,
            trap_s,
        });
        tx
    };
    let conflicting_transactions = vec![make_tx(random_b58_32()), make_tx(random_b58_32())];

    // Reporter authentication is genuinely signed BY THE ATTACKER — every
    // structural/reporter gate passes; only evidence-authenticity is missing.
    let proof_id = derive_proof_id(&offender_claim, &ds_tag).expect("proof_id");
    let reporter_sig = sign_ed25519(&attacker.signing_key, proof_id.as_bytes());

    let forged = ProofOfDoubleSpend {
        proof_id,
        offender_id: offender_claim.clone(),
        suspected_identity: None,
        fork_point_prev_hash: ds_tag,
        conflicting_transactions,
        deletable_at: "2099-01-01T00:00:00Z".to_string(),
        reporter_id: attacker.user_id.clone(),
        report_timestamp: chrono::Utc::now().to_rfc3339(),
        reporter_signature: bs58::encode(reporter_sig.to_bytes()).into_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
    };

    let import_result = wallet.import_proof(forged);
    let reputation = wallet.check_reputation(&offender_claim);

    // SECURE INVARIANT (Soll-Verhalten): either the import is rejected, or —
    // at minimum — the record persists WITHOUT any offender linkage intact so
    // no reputational weight can attach to the claimed key.
    assert!(
        import_result.is_err()
            || !matches!(reputation, TrustStatus::KnownOffender(_)),
        "AUDIT-W4-TRAP-201: fabricated `ephemeral:` soft-proof claim without \
         ANY cryptographic evidence gained persistent offender linkage \
         (import_result={:?}, reputation={:?}, persisted_conflicts={}). \
         Non-did:key attribution claims must be evidence-verified (or stripped) \
         at the import boundary.",
        import_result.is_ok(),
        match &reputation {
            TrustStatus::KnownOffender(id) => format!("KnownOffender({})", id),
            TrustStatus::Clean => "Clean".to_string(),
            TrustStatus::Resolved { .. } => "Resolved".to_string(),
        },
        wallet.list_conflicts().len(),
    );
}

//==============================================================================
// AUDIT-W4-TRAP-202 (WH4-01-202, MEDIUM): trap-bearing INIT transactions must
// not yield spend-typed fingerprints under attacker-chosen DS-Tags
//==============================================================================

#[test]
fn wh4_01_202_trap_bearing_init_must_not_classify_as_spend_claim() {
    let (standard_def, standard_hash) =
        &*human_money_core::test_utils::FREETALER_STANDARD;

    // Minimal honest voucher (init-only), authored by the attacker.
    let mut voucher = human_money_core::models::voucher::Voucher::create_with_key(
        NewVoucherData {
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: PublicProfile {
                id: Some(ACTORS.alice.user_id.clone()),
                ..Default::default()
            },
            validity_duration: Some("P4Y".to_string()),
            ..Default::default()
        },
        standard_def,
        standard_hash,
        &ACTORS.alice.identity.signing_key,
    )
    .expect("voucher creation");

    // Re-derive the genesis lock key exactly like creation.rs does, so the
    // mutated init transaction stays cryptographically consistent.
    let nonce_bytes = bs58::decode(&voucher.voucher_nonce)
        .into_vec()
        .expect("nonce b58");
    let creator_prefix = get_prefix_from_user_id(&ACTORS.alice.user_id);
    let (genesis_sk, _) = derive_ephemeral_key_pair(
        &ACTORS.alice.identity.signing_key,
        &nonce_bytes,
        "genesis",
        creator_prefix,
    )
    .expect("genesis key derivation");

    // Attack: embed genuine (well-formed) SST shards under an ATTACKER-chosen
    // ds_tag into the INIT transaction. The t_id preimage excludes trap_data,
    // so the recomputed t_id stays stable; only the V3 layer2_signature is
    // renewed (challenge tag = t_id for init, shards bound verbatim).
    let attacker_ds_tag = random_b58_32();
    let throwaway = fresh_key();
    let eph_bytes = throwaway.verifying_key().to_bytes();
    let init_t_id = voucher.transactions[0].t_id.clone();
    let (trap, _) =
        generate_sst_trap(&throwaway, &attacker_ds_tag, &eph_bytes, &init_t_id)
            .expect("genuine shard pair");
    voucher.transactions[0].trap_data = Some(trap);

    let resigned = human_money_core::test_utils::resign_transaction_ext(
        voucher.transactions[0].clone(),
        &ACTORS.alice.identity.signing_key,
        "",
        Some(&genesis_sk),
    );
    assert_eq!(
        resigned.t_id, init_t_id,
        "precondition: t_id preimage excludes trap_data"
    );
    voucher.transactions[0] = resigned;

    // Actual pipeline behavior on the crafted voucher.
    let validation_result = validate_voucher_against_standard(&voucher, standard_def);
    let fingerprint =
        create_fingerprint_for_transaction(&voucher.transactions[0], &voucher)
            .expect("fingerprint creation for init tx");
    let spend_typed = !is_init_fingerprint(&fingerprint);
    // Masquerade quality probe: does this fingerprint carry a verifiable V3
    // authorship signature under its own claimed tag? (Diagnostic only;
    // reported in the failure message.)
    let ingress_authentic =
        human_money_core::services::conflict_manager::verify_fingerprint_signature(&fingerprint);

    // SECURE INVARIANT (Soll-Verhalten): a trap-bearing INIT transaction must
    // EITHER be rejected by chain validation OR produce an init-classified
    // (no-trap) fingerprint that cannot enter gossip/detection.
    assert!(
        validation_result.is_err() || !spend_typed,
        "AUDIT-W4-TRAP-202: trap-bearing INIT transaction passed L1 validation \
         ({:?}) and produced a SPEND-TYPED fingerprint (is_init={}, \
         attacker_chosen_ds_tag='{}', ingress_authentic_probe={}) — an \
         authenticated spend-claim masquerade minted by any voucher author.",
        validation_result.is_ok(),
        !spend_typed,
        fingerprint.ds_tag,
        ingress_authentic,
    );
}

//==============================================================================
// AUDIT-W4-TRAP-203 (WH4-01-203, MEDIUM): foreign fingerprint ingress must be
// capacity-bounded (state-based proof, no wall-clock assertions)
//==============================================================================

#[test]
fn wh4_01_203_foreign_ingress_admission_must_be_capacity_bounded() {
    const N: usize = 2000;

    let (mut wallet, _identity) =
        create_test_wallet("wave4-203", "w4-203".to_string())
            .expect("fresh receiving wallet");

    // Attacker hand-signs N well-formed fingerprints sharing ONE
    // attacker-chosen ds_tag with distinct t_ids and valid-format-but-
    // unrelated shards. Each entry passes the V3 ingress signature gate
    // (signing via the library's own V3 fixture signer so the test stays
    // independent of the digest's internal field layout).
    let ds_tag = random_b58_32();

    let mut fps = Vec::with_capacity(N);
    for i in 0..N {
        // Distinct t_ids guaranteed via counter prefix.
        let mut t_id_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut t_id_bytes);
        t_id_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let t_id = bs58::encode(t_id_bytes).into_string();

        let mut r = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut r);
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);

        let mut fp = TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id,
            trap_r: bs58::encode(r).into_string(),
            trap_s: bs58::encode(s).into_string(),
            encrypted_timestamp: 0xdead_beef_u128 + i as u128,
            ..Default::default()
        };
        human_money_core::test_utils::sign_fingerprint_in_place(&mut fp);
        fps.push(fp);
    }

    // Fixture precondition (guards against vacuous passes): every crafted
    // entry must GENUINELY pass the V3 ingress signature gate BEFORE the
    // import. Otherwise a rejection at the gate — not a cap — would satisfy
    // the SOLL assertion below.
    assert!(
        human_money_core::services::conflict_manager::verify_fingerprint_signature(&fps[0])
            && human_money_core::services::conflict_manager::verify_fingerprint_signature(
                &fps[N - 1]
            ),
        "AUDIT-W4-TRAP-203 fixture broken: crafted fingerprints do not carry \
         valid V3 ingress signatures"
    );

    // Gossip-style transport blob keyed by the attacker-chosen bucket.
    let blob = serde_json::to_vec(&std::collections::HashMap::from([(
        ds_tag.clone(),
        fps,
    )]))
    .expect("serialize export blob");

    let accepted =
        import_foreign_fingerprints(&mut wallet.known_fingerprints, &blob)
            .expect("import must not error");
    let bucket_len = wallet
        .known_fingerprints
        .foreign_fingerprints
        .get(&ds_tag)
        .map(Vec::len)
        .unwrap_or(0);

    // SECURE INVARIANT (Soll-Verhalten): bounded adversarial ingestion. A
    // hard per-bucket/global admission cap must exist between the signature
    // gate and the store. STATE-based proof: on unpatched code
    // accepted == bucket_len == 2000 — the uncapped bucket IS the finding
    // (each stored member later costs O(n) pairwise SST extraction work).
    assert!(
        accepted <= PROPOSED_INBOUND_BUCKET_CAP && bucket_len <= PROPOSED_INBOUND_BUCKET_CAP,
        "AUDIT-W4-TRAP-203: unbounded foreign fingerprint ingress admitted {} \
         entries into bucket '{}' (bucket_len={}) — no admission cap exists \
         (proposed bound {}, symmetric to outbound MAX_FINGERPRINTS_TO_SEND). \
         This enables quadratic SST extraction work and unbounded \
         authenticated junk storage.",
        accepted,
        ds_tag,
        bucket_len,
        PROPOSED_INBOUND_BUCKET_CAP,
    );
}
