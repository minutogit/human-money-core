//! # tests/security_audit_wave4_integrity.rs
//!
//! Security Audit Wave 4 — Module 04: Transaction Logic & State Integrity.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. These tests turn green only after the
//! corresponding remediation has been implemented.
//!
//! Scope: `services/voucher_validation/{chain,signatures}.rs`,
//! `services/voucher_manager/balance.rs` (issuance attribution + ordering).

use ed25519_dalek::SigningKey;
use human_money_core::archive::{ArchiveError, VoucherArchive};
use human_money_core::error::ValidationError;
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{
    Transaction, ValueDefinition, Voucher, VoucherSignature, VoucherStandard,
};
use human_money_core::services::crypto_utils::{
    create_user_id, get_hash, get_hash_from_slices, sign_ed25519,
};
use human_money_core::services::l2_gateway::calculate_layer2_voucher_id;
use human_money_core::services::trap_manager::generate_sst_trap;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_validation::{
    validate_voucher_against_standard, verify_transactions,
};
use human_money_core::test_utils::{
    add_voucher_to_wallet, create_test_wallet, resign_transaction_ext, FREETALER_STANDARD,
    MINUTO_STANDARD,
};
use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
use human_money_core::VoucherCoreError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// =============================================================================
// FINDING AUDIT-W4-INT-501 (WH4-04-501)
// -----------------------------------------------------------------------------
// - Finding-ID:    AUDIT-W4-INT-501
// - Severity:      HIGH
// - CWE-Classification: CWE-347 (Improper Verification of Cryptographic
//                   Signature / missing issuer-binding enforcement)
// - Target Location: src/services/voucher_validation/chain.rs:511-520
//                   (`verify_transaction_basics`, init party gate) in
//                   interaction with signatures.rs:26-42,69-89 (creator-role
//                   signature optional) and voucher_manager/balance.rs:33-39
//                   (issuance firewall skipped when creator id absent)
//
// ## Threat Model & Exploitation
// An attacker hand-crafts a voucher whose header is byte-faithful to a
// genuine, loaded standard (correct `voucher_standard.uuid` +
// `standard_definition_hash`, correct unit, valid validity window) but sets
// `creator_profile.id = None`. Every issuance-attribution gate is conditional
// on that field being present:
//   * the init-party check only runs when `creator_profile.id.is_some()`
//     (both disjuncts of chain.rs:511-514 re-require `is_some()`),
//   * `verify_signatures` binds the "creator" role only IF such a signature
//     exists; the Minuto guarantor minima ([2,2], role "guarantor") are
//     satisfiable with ATTACKER-owned keys,
//   * the issuance firewall skips when the creator id is absent.
// The attacker signs init as themselves (sender = recipient = attacker DID,
// attacker-controlled genesis key for the HMC_TX_AUTH_V3 layer2_signature,
// identity signature over t_id), satisfying every remaining check.
//
// ## Impact Analysis
// Unlimited self-issuance of vouchers under trusted standard UUIDs with zero
// issuer accountability ("unauthorized minting"). Broken invariant: "Every
// init transaction commits to an attributed creator: init sender AND
// recipient MUST equal `voucher.creator_profile.id`, and a creator-role
// signature bound to that id MUST be present and verify."
//
// ## Root Cause
// Fail-open branch: attribution enforcement is gated on the very field the
// attacker controls/omits instead of rejecting an unattributed creator.
//
// ## Remediation Strategy
// Reject vouchers whose `creator_profile.id` is `None` (or whose init
// sender/recipient deviates from it) in `verify_transaction_basics`, and/or
// require a creator-role signature unconditionally; make the issuance
// firewall fail closed on absent creator ids.
//
// ## Test Semantics (Fail-First)
// Builds the fully self-consistent attacker voucher described above against
// the strict Minuto standard (guarantor minima satisfied by attacker keys)
// and asserts `validate_voucher_against_standard` is Err. On unpatched code
// it returns Ok(()), so this test FAILS and proves the gap.
// =============================================================================
#[test]
fn wh4_04_501_init_without_attributed_creator_must_fail_validation() {
    let (standard, logic_hash) = &*MINUTO_STANDARD;

    // --- Attacker key material (deterministic) ---
    let attacker_key = SigningKey::from_bytes(&[0x51u8; 32]); // permanent key
    let genesis_key = SigningKey::from_bytes(&[0x52u8; 32]); // ephemeral init key
    let holder_key = SigningKey::from_bytes(&[0x53u8; 32]); // future owner anchor
    let male_guarantor_key = SigningKey::from_bytes(&[0x54u8; 32]);
    let female_guarantor_key = SigningKey::from_bytes(&[0x55u8; 32]);

    let attacker_did = create_user_id(&attacker_key.verifying_key(), None)
        .expect("attacker DID creation failed");

    // --- Decodable identifiers (16-byte nonce) ---
    let nonce_bytes: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x41);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let voucher_nonce_decoded =
        bs58::decode(&voucher_nonce).into_vec().expect("decode nonce");

    const T0: &str = "2026-01-01T00:00:00.000000Z";
    const VALID_UNTIL: &str = "2031-01-01T00:00:00.000000Z"; // P5Y: within [P1Y, P10Y], satisfies P3Y firewall

    // THE ATTACK: creator_profile.id is None while the standard header is
    // byte-faithful (uuid + definition hash + unit copied from the loaded,
    // correctly issued standard).
    let mut voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            // Verified hash of the loaded standard's immutable zone.
            standard_definition_hash: logic_hash.clone(),
        },
        voucher_id: String::new(),
        voucher_nonce: voucher_nonce.clone(),
        creation_date: T0.to_string(),
        valid_until: VALID_UNTIL.to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: standard.immutable.blueprint.unit.clone(),
            amount: "100".to_string(), // Minuto: 0 decimal places
            abbreviation: Some(standard.immutable.identity.abbreviation.clone()),
            description: None,
        },
        collateral: None,
        creator_profile: PublicProfile {
            id: None, // <-- the attack: no attributed creator at all
            ..Default::default()
        },
        transactions: vec![],
        signatures: vec![],
    };

    // voucher_id = H(canonical header) with empty id and empty tx/sig lists
    // (mirrors identity.rs::verify_voucher_hash).
    voucher.voucher_id = get_hash(to_canonical_json(&voucher).expect("canonicalize header"));

    let voucher_id_bytes = bs58::decode(&voucher.voucher_id)
        .into_vec()
        .expect("decode voucher_id");

    // --- init transaction: attacker is sender AND recipient ---
    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash_from_slices(&[&voucher_id_bytes, &voucher_nonce_decoded]),
        t_type: "init".to_string(),
        t_time: T0.to_string(),
        sender_id: Some(attacker_did.clone()),
        recipient_id: attacker_did.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(
            bs58::encode(genesis_key.verifying_key().to_bytes()).into_string(),
        ),
        receiver_ephemeral_pub_hash: Some(get_hash(holder_key.verifying_key().to_bytes())),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: Some(VALID_UNTIL.to_string()),
        sender_identity_signature: None,
    };
    init_tx.t_id = get_hash(to_canonical_json(&init_tx).expect("canonicalize init tx"));

    let layer2_voucher_id =
        calculate_layer2_voucher_id(&init_tx).expect("l2 voucher id derivation failed");

    // L2 signature computed EXACTLY like production creation.rs / the shared
    // test helper resign_transaction_ext (V3 digest, genesis placeholders
    // "none"/"none"); identity signature over t_id by the attacker key.
    let signed_init = resign_transaction_ext(
        init_tx,
        &attacker_key,
        &layer2_voucher_id,
        Some(&genesis_key),
    );

    voucher.transactions.push(signed_init);

    // Guarantor minima of Minuto ([2,2], roles "guarantor", ISO-5218 gender
    // parity CEL rules) are satisfied entirely with ATTACKER-owned keys --
    // none of them is bound to any issuer identity.
    for (key, gender) in [
        (&male_guarantor_key, "1"),
        (&female_guarantor_key, "2"),
    ] {
        let guarantor_did = create_user_id(&key.verifying_key(), None)
            .expect("guarantor DID creation failed");
        let mut sig = VoucherSignature {
            voucher_id: voucher.voucher_id.clone(),
            signature_id: String::new(),
            signer_id: guarantor_did,
            signature: String::new(),
            signature_time: T0.to_string(),
            role: "guarantor".to_string(),
            details: Some(PublicProfile {
                gender: Some(gender.to_string()),
                ..Default::default()
            }),
        };
        sig.signature_id = get_hash_from_slices(&[
            to_canonical_json(&sig).expect("canonicalize signature").as_bytes(),
            voucher.transactions[0].t_id.as_bytes(),
        ]);
        sig.signature = bs58::encode(
            sign_ed25519(key, sig.signature_id.as_bytes()).to_bytes(),
        )
        .into_string();
        voucher.signatures.push(sig);
    }

    // Sanity precondition: the header really carries NO creator attribution.
    assert!(voucher.creator_profile.id.is_none());

    // SECURE INVARIANT (Soll-Verhalten): a voucher without ANY attributed
    // creator must be rejected end-to-end -- the init party gate must not
    // silently skip, and issuance attribution must be mandatory.
    let result = validate_voucher_against_standard(&voucher, standard);
    assert!(
        result.is_err(),
        "AUDIT-W4-INT-501 VIOLATION: accepted a voucher under trusted standard \
         UUID '{}' whose creator_profile.id is None and whose init transaction \
         is sent/received solely by the attacker's did:key. Every issuance \
         gate (init party check chain.rs:511-520, optional creator signature \
         signatures.rs:26-42/69-89, firewall balance.rs:33-39) is conditioned \
         on the omitted field, enabling unattributed self-issuance. Got: Ok(())",
        standard.immutable.identity.uuid
    );
}

// =============================================================================
// FINDING AUDIT-W4-INT-502 (WH4-04-502)
// -----------------------------------------------------------------------------
// - Finding-ID:    AUDIT-W4-INT-502
// - Severity:      LOW
// - CWE-Classification: CWE-20 (Improper Input Validation of timestamp encoding)
// - Target Location: src/services/voucher_validation/chain.rs:177
//                   (`tx.t_time <= last_tx_time`), chain.rs:530
//                   (`tx.t_time < voucher.creation_date`),
//                   signatures.rs:98 (`signature_time < voucher.creation_date`)
//
// ## Threat Model & Exploitation
// Chain-ordering invariants are enforced via RAW RFC3339 STRING comparison,
// but timestamps are free-form RFC3339 accepted with arbitrary UTC offsets.
// A crafted 2-tx public chain uses
//   init.t_time     = "2026-01-02T00:00:00Z"     (instant 2026-01-02T00:00:00Z)
//   transfer.t_time = "2026-01-02T13:00:00+14:00" (instant 2026-01-01T23:00:00Z)
// The transfer string sorts lexicographically AFTER the tip string
// ('1' > '0' at index 10), so the string guard ACCEPTS the chain -- yet the
// PARSED instant is one hour BEFORE the init instant (the +14:00 offset
// shifts the large local clock reading back across midnight). Interior
// timestamps are never parsed as instants during ingress
// (verify_not_far_in_future parses only the MAX tip plus signature times),
// so the past-shifted interior instant evades all temporal sanity checks
// and flows into fingerprint timestamps feeding the offline earliest-wins
// race inputs. (Note: pairs whose offset makes the string sort BELOW the
// tip, e.g. "-14:00", are accidentally rejected by the same string guard --
// fail-closed direction; the exploitable direction is the one proven here.)
//
// ## Impact Analysis
// Broken invariant: for every consecutive pair, parsed_instant(tx[i]) >
// parsed_instant(tx[i-1]). String ordering does not imply instant ordering
// under mixed offsets; race-window inputs can be biased into the past/future.
// Defense-in-depth class (race-level floors/ceiling bound residual abuse).
//
// ## Root Cause
// Lexicographic RFC3339 comparisons instead of instant-based comparison.
//
// ## Remediation Strategy
// Parse both operands as instants before comparing at chain.rs:177,
// chain.rs:530 and signatures.rs:98 (reject unparsable forms outright).
//
// ## Test Semantics (Fail-First)
// Builds a cryptographically fully self-consistent init->transfer chain
// (all hashes/t_ids/SST trap shards/L2 signatures recomputed via the shared
// helpers) with the mixed-offset times above and asserts
// `verify_transactions` returns Err(InvalidTimeOrder). On unpatched code the
// string comparison accepts the chain (Ok(())), so this test FAILS.
// =============================================================================
#[test]
fn wh4_04_502_chain_time_ordering_must_reject_offset_confusion() {
    let (standard, logic_hash) = &*FREETALER_STANDARD;

    // --- Key material ---
    let attacker_key = SigningKey::from_bytes(&[0x61u8; 32]); // permanent key
    let genesis_key = SigningKey::from_bytes(&[0x62u8; 32]); // holds value after init
    let next_output_key = SigningKey::from_bytes(&[0x63u8; 32]); // transfer output anchor

    let attacker_did = create_user_id(&attacker_key.verifying_key(), None)
        .expect("attacker DID creation failed");

    // --- Decodable identifiers ---
    let nonce_bytes: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x72);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let voucher_nonce_decoded =
        bs58::decode(&voucher_nonce).into_vec().expect("decode nonce");

    // Mixed-offset attack times:
    //   string order : T_TRANSFER > T_INIT   ('1' > '0' at index 10)
    //   instant order: T_TRANSFER < T_INIT   (+14:00 maps 13:00 back to
    //                                         2026-01-01T23:00:00Z)
    const T_INIT: &str = "2026-01-02T00:00:00Z";
    const T_TRANSFER: &str = "2026-01-02T13:00:00+14:00";

    // Header (voucher_id over canonical header, empty tx/sig lists).
    let mut voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            standard_definition_hash: logic_hash.clone(),
        },
        voucher_id: String::new(),
        voucher_nonce: voucher_nonce.clone(),
        creation_date: T_INIT.to_string(),
        valid_until: "2031-01-02T00:00:00Z".to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: standard.immutable.blueprint.unit.clone(),
            amount: "100.00".to_string(),
            abbreviation: Some(standard.immutable.identity.abbreviation.clone()),
            description: None,
        },
        collateral: None,
        creator_profile: PublicProfile {
            id: Some(attacker_did.clone()),
            ..Default::default()
        },
        transactions: vec![],
        signatures: vec![],
    };
    voucher.voucher_id = get_hash(to_canonical_json(&voucher).expect("canonicalize header"));
    let voucher_id_bytes = bs58::decode(&voucher.voucher_id)
        .into_vec()
        .expect("decode voucher_id");

    // --- init transaction (fully consistent, honest shape) ---
    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash_from_slices(&[&voucher_id_bytes, &voucher_nonce_decoded]),
        t_type: "init".to_string(),
        t_time: T_INIT.to_string(),
        sender_id: Some(attacker_did.clone()),
        recipient_id: attacker_did.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(
            bs58::encode(genesis_key.verifying_key().to_bytes()).into_string(),
        ),
        receiver_ephemeral_pub_hash: Some(get_hash(
            genesis_key.verifying_key().to_bytes(),
        )),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };

    init_tx.t_id = get_hash(to_canonical_json(&init_tx).expect("canonicalize init tx"));

    let layer2_voucher_id =
        calculate_layer2_voucher_id(&init_tx).expect("l2 voucher id derivation failed");
    let signed_init = resign_transaction_ext(
        init_tx,
        &attacker_key,
        &layer2_voucher_id,
        Some(&genesis_key),
    );

    // --- transfer transaction with hostile mixed-offset t_time ---
    let transfer_prev_hash =
        get_hash(to_canonical_json(&signed_init).expect("canonicalize signed init"));
    let input_pub_bytes = genesis_key.verifying_key().to_bytes();

    let mut transfer_tx = Transaction {
        t_id: String::new(),
        prev_hash: transfer_prev_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: T_TRANSFER.to_string(),
        sender_id: None, // stealth-style anonymous spend of the held input
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100.00".to_string(), // full-balance transfer
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(bs58::encode(input_pub_bytes).into_string()),
        receiver_ephemeral_pub_hash: Some(get_hash(
            next_output_key.verifying_key().to_bytes(),
        )),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    // t_id preimage excludes trap_data (V3 rule) -> compute id first...
    transfer_tx.t_id =
        get_hash(to_canonical_json(&transfer_tx).expect("canonicalize transfer tx"));

    // ...then attach structurally valid SST shards for THIS spend
    // (ds_tag = H(prev_hash || revealed eph pub), tau depends on t_id).
    let ds_tag = get_hash_from_slices(&[
        &bs58::decode(&transfer_prev_hash).into_vec().expect("decode prev_hash")[..],
        &input_pub_bytes[..],
    ]);
    let (trap, _witness) = generate_sst_trap(
        &genesis_key,
        &ds_tag,
        &input_pub_bytes,
        &transfer_tx.t_id,
    )
    .expect("SST trap generation failed");
    transfer_tx.trap_data = Some(trap);

    // L2 signature recomputed over the final tx (challenge = trap ds_tag,
    // shards + encrypted timestamp bound); resign_transaction_ext re-derives
    // t_id identically because trap_data is excluded from the preimage.
    let signed_transfer = resign_transaction_ext(
        transfer_tx,
        &attacker_key,
        &layer2_voucher_id,
        Some(&genesis_key),
    );

    voucher.transactions.push(signed_init);
    voucher.transactions.push(signed_transfer);

    // Precondition sanity (string domain): the hostile interior timestamp
    // sorts AFTER the tip, which is exactly why the raw string guard passes.
    assert!(
        T_TRANSFER > T_INIT,
        "test setup violated: expected lexicographically greater interior timestamp"
    );

    // SECURE INVARIANT (Soll-Verhalten): chronological chain order must be
    // evaluated on PARSED instants, not raw strings -- the offset-confused
    // interior transaction (instant 2026-01-01T23:00:00Z, i.e. BEFORE its
    // predecessor) must be rejected as InvalidTimeOrder.
    let result = verify_transactions(&voucher, standard);
    match result {
        Err(VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })) => {}
        other => panic!(
            "AUDIT-W4-INT-502 VIOLATION: verify_transactions accepted a chain \
             whose interior t_time '{}' (instant 2026-01-01T23:00:00Z) is \
             instant-wise BEFORE its predecessor '{}' (2026-01-02T00:00:00Z) \
             but sorts lexicographically after it. Raw RFC3339 string \
             comparison at chain.rs:177 defeats chronology. Got: {:?}",
            T_TRANSFER,
            T_INIT,
            other.map(|_| "Ok(())")
        ),
    }
}



// =============================================================================
// FINDING AUDIT-W4-INT-503 (WH4-04-K4)
// -----------------------------------------------------------------------------
// - Finding-ID:    AUDIT-W4-INT-503
// - Severity:      MEDIUM
// - CWE-Classification: CWE-662 (Improper Resource Shutdown or Release /
//                   inconsistent side-effect commit)
// - Target Location: src/wallet/transaction_handler.rs:1073-1097
//                   (`execute_multi_transfer_and_bundle`, post-commit
//                   best-effort archive loop, per-voucher skip on error)
//
// ## Threat Model & Exploitation
// The post-commit forensic archiving phase is deliberately best-effort
// (AUDIT-00-WILDCARD-02): individual `archive_voucher` failures are logged
// via eprintln! and silently skipped, and the operation still returns Ok.
// For an N-source transfer the loop iterates voucher-by-voucher, so a mid-
// loop persistent failure (e.g. one source's state hitting a storage/KDF/
// integrity error) yields a PARTIALLY populated forensic archive for an
// ATOMICALLY COMMITTED send.
//
// ## Impact Analysis
// Offline double-spend forensics relying on the archive fallback sees a
// truncated custody chain for exactly the fraud-relevant cases. Broken
// invariant: "After a committed multi-source transfer, the forensic archive
// contains ALL transferred pre-states OR the operation reports the forensic
// incompleteness to the caller" -- currently relaxed to "some subset,
// silently".
//
// ## Root Cause
// Best-effort loop with no completeness signal: partial success is
// indistinguishable from full success in the return value.
//
// ## Remediation Strategy
// Either (a) surface a result flag/error channel reporting archive
// incompleteness (e.g. CreateBundleResult metadata), or (b) journal-and-
// retry failed states until the archive is complete.
//
// ## Test Semantics (Fail-First)
// Sends two healthy sources through execute_multi_transfer_and_bundle with
// a spy archive that persists failing for exactly source #2. Asserts the
// committed operation must not silently lose forensics: BOTH states are in
// the archive OR the result reports incompleteness. On unpatched code the
// call returns Ok with only source #1 archived, so this test FAILS.
// =============================================================================
#[derive(Default, Clone)]
struct SelectivelyFailingArchive {
    fail_for: Arc<Mutex<Option<String>>>,
    archived: Arc<Mutex<Vec<String>>>,
}

impl SelectivelyFailingArchive {
    fn new(fail_for_voucher_id: String) -> Self {
        Self {
            fail_for: Arc::new(Mutex::new(Some(fail_for_voucher_id))),
            archived: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn archived_ids(&self) -> Vec<String> {
        self.archived.lock().expect("poisoned mutex").clone()
    }
}

impl VoucherArchive for SelectivelyFailingArchive {
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        _owner_id: &str,
        _standard: &human_money_core::VoucherStandardDefinition,
    ) -> Result<(), ArchiveError> {
        if self.fail_for.lock().expect("poisoned mutex").as_deref() == Some(voucher.voucher_id.as_str())
        {
            // Persistent failure for exactly this state (e.g. storage fault).
            return Err(ArchiveError::Generic(
                "injected persistent archive fault".to_string(),
            ));
        }
        self.archived
            .lock()
            .expect("poisoned mutex")
            .push(voucher.voucher_id.clone());
        Ok(())
    }

    fn get_archived_voucher(&self, _voucher_id: &str) -> Result<Voucher, ArchiveError> {
        Err(ArchiveError::NotFound)
    }

    fn find_transaction_by_id(
        &self,
        _t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError> {
        Err(ArchiveError::NotFound)
    }

    fn find_voucher_by_tx_id(&self, _t_id: &str) -> Result<Option<Voucher>, ArchiveError> {
        Err(ArchiveError::NotFound)
    }
}

#[test]
fn wh4_04_k4_committed_multi_send_must_not_silently_lose_forensics() {
    let (mut sender_wallet, sender_identity) =
        create_test_wallet("w4-k4-sender-seed", "sender-instance".to_string())
            .expect("sender wallet setup failed");

    let (standard, _logic_hash) = &*FREETALER_STANDARD;

    // Two healthy sources, fully sent in one atomic operation.
    let id_a = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        standard,
        true,
    )
    .expect("source A setup failed");
    let id_b = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        standard,
        true,
    )
    .expect("source B setup failed");

    let recipient_did = human_money_core::services::crypto_utils::create_user_id(
        &SigningKey::from_bytes(&[0x7Au8; 32]).verifying_key(),
        None,
    )
    .expect("recipient DID creation failed");

    let mut definitions = HashMap::new();
    definitions.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let archive = SelectivelyFailingArchive::new(id_b.clone());

    // The forensic archive and the incompleteness report are keyed by the
    // domain-stable voucher_id, not by the wallet-local instance id.
    let id_b_voucher_id = sender_wallet
        .get_voucher_instance(&id_b)
        .expect("source B instance missing")
        .voucher
        .voucher_id
        .clone();

    let request = MultiTransferRequest {
        recipient_id: recipient_did,
        sources: vec![
            SourceTransfer {
                local_instance_id: id_a.clone(),
                amount_to_send: "100".to_string(),
            },
            SourceTransfer {
                local_instance_id: id_b.clone(),
                amount_to_send: "100".to_string(),
            },
        ],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let result = sender_wallet.execute_multi_transfer_and_bundle(
        &sender_identity,
        &definitions,
        request,
        Some(&archive),
    );

    // Precondition: the financial commit itself must have succeeded (the
    // archive fault must NOT abort a committed send -- best-effort phase).
    assert!(
        result.is_ok(),
        "test precondition violated: injected archive fault aborted the send"
    );

    // SECURE INVARIANT (Soll-Verhalten): a committed multi-source send may
    // never SILENTLY truncate the forensic archive. Either every transferred
    // pre-state is archived, or the caller is informed about the gap.
    let archived = archive.archived_ids();
    let forensic_complete = archived.contains(&id_b_voucher_id);
    let gap_reported = result
        .as_ref()
        .map(|r| r.forensic_archive_incomplete.contains(&id_b_voucher_id))
        .unwrap_or(false);
    assert!(
        forensic_complete || gap_reported,
        "AUDIT-W4-INT-503 VIOLATION: atomically committed 2-source send \
         returned Ok(()) while the forensic archive holds only {:?} -- the \
         pre-state of voucher '{}' was lost to a per-voucher 'continue' in \
         the best-effort archiving loop with no completeness signal to the \
         caller (transaction_handler.rs:1073-1097).",
        archived,
        id_b
    );
}
