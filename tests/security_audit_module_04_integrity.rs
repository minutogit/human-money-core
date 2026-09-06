//! # tests/security_audit_module_04_integrity.rs
//!
//! Security Audit — Module 04: Transaction Logic, State Integrity & Rust Robustness.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. These tests are expected to turn green
//! only after the corresponding remediation has been implemented.
//!
//! Audit scope: src/services/bundle_processor.rs, secure_container_manager.rs,
//! integrity_manager.rs, decimal_utils.rs, models/voucher.rs, models/secure_container.rs
//! plus the downstream transaction lifecycle (wallet/transaction_handler.rs,
//! services/voucher_validation/chain.rs) reached through bundle ingestion.

use ed25519_dalek::SigningKey;
use human_money_core::archive::{ArchiveError, VoucherArchive};
use human_money_core::models::voucher::{Transaction, TrapData, ValueDefinition, Voucher};
use human_money_core::services::crypto_utils::{
    create_user_id, get_hash, get_hash_from_slices,
};
use human_money_core::services::l2_gateway::calculate_layer2_voucher_id;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_validation::verify_transactions;
use human_money_core::models::conflict::{
    KnownFingerprints, OwnFingerprints, TransactionFingerprint,
};
use human_money_core::services::conflict_manager::{
    check_for_double_spend, create_fingerprint_for_transaction, verify_fingerprint_signature,
};
use human_money_core::test_utils::{
    add_voucher_to_wallet, create_test_wallet, generate_signed_standard_toml,
    resign_transaction_ext, setup_in_memory_wallet, setup_service_with_profile,
    FREETALER_STANDARD, MINUTO_STANDARD,
};
use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
use rand::RngCore;
use human_money_core::{VoucherCoreError};
use std::collections::HashMap;
use std::panic::{catch_unwind, set_hook, take_hook, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

/// rust_decimal supports at most 96-bit mantissa values; this literal is
/// exactly `Decimal::MAX`. It parses successfully and passes every existing
/// precision/positivity validation in the chain validator.
const DECIMAL_MAX_STR: &str = "79228162514264337593543950335";

// =============================================================================
// FINDING HMSEC-SA04-01
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-01
// Severity:      Critical
// CWE:           CWE-190 (Integer Overflow) leading to CWE-248 (Uncaught Exception)
// Target:        src/wallet/transaction_handler.rs:400-410
//                (`process_encrypted_transaction_bundle` -> TransferSummary accumulation,
//                unchecked `val1 + val2`)
// Threat Model:  A remote peer sends a *cryptographically fully valid* bundle
//                containing two vouchers whose amounts sum beyond rust_decimal's
//                96-bit maximum (issuance magnitude is uncapped by design).
// Impact:        Remote, deterministic DoS: rust_decimal's `Add` impl panics on
//                overflow ("addition overflowed") regardless of debug/release
//                profile. The panic unwinds across the public API boundary; in
//                FFI/WASM contexts this aborts the host application. No
//                malformed input is required - valid data suffices.
// Root Cause:    Attacker-controlled `Decimal` amounts are summed with the
//                panicking `+` operator instead of `checked_add`.
// Remediation:   Use `checked_add` and map overflow to a graceful
//                `VoucherCoreError` variant; additionally consider an issuance
//                magnitude cap in standard validation.
// Test Semantics: Receiving such a bundle MUST return gracefully (Ok or Err)
//                 and never unwind. FAILS on unpatched code (panic is caught).
// =============================================================================
#[test]
fn sa04_01_receive_bundle_must_not_panic_on_amount_sum_overflow() {
    let (mut attacker_wallet, attacker_identity) =
        create_test_wallet("sa04-01-attacker-seed", "attacker-instance".to_string())
            .expect("attacker wallet setup failed");
    let (mut victim_wallet, victim_identity) =
        create_test_wallet("sa04-01-victim-seed", "victim-instance".to_string())
            .expect("victim wallet setup failed");

    let (standard, _logic_hash) = &*MINUTO_STANDARD;

    // Attacker mints two independent, fully valid vouchers of maximal value.
    let id_a = add_voucher_to_wallet(
        &mut attacker_wallet,
        &attacker_identity,
        DECIMAL_MAX_STR,
        standard,
        true,
    )
    .expect("voucher A creation failed");
    let id_b = add_voucher_to_wallet(
        &mut attacker_wallet,
        &attacker_identity,
        DECIMAL_MAX_STR,
        standard,
        true,
    )
    .expect("voucher B creation failed");

    let _ = (&id_a, &id_b);

    // Attacker transfers both vouchers to the victim in a single, legitimate bundle.
    let mut definitions = HashMap::new();
    definitions.insert(
        standard.immutable.identity.uuid.clone(),
        standard.clone(),
    );

    let request = MultiTransferRequest {
        recipient_id: victim_identity.user_id.clone(),
        sources: vec![
            SourceTransfer {
                local_instance_id: id_a,
                amount_to_send: DECIMAL_MAX_STR.to_string(),
            },
            SourceTransfer {
                local_instance_id: id_b,
                amount_to_send: DECIMAL_MAX_STR.to_string(),
            },
        ],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_result = attacker_wallet
        .execute_multi_transfer_and_bundle(&attacker_identity, &definitions, request, None)
        .expect("attacker multi-transfer must succeed on valid input");
    let bundle_bytes = bundle_result.bundle_bytes;

    // SECURE INVARIANT (Soll-Verhalten): ingestion of the bundle must be
    // panic-free. Overflowing sums must surface as a graceful error instead
    // of aborting the process.
    let previous_hook = take_hook();
    set_hook(Box::new(|_| {})); // silence expected panic output during PoC
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        victim_wallet.process_encrypted_transaction_bundle(
            &victim_identity,
            &bundle_bytes,
            None,
            &definitions,
        )
    }));
    set_hook(previous_hook);

    assert!(
        outcome.is_ok(),
        "HMSEC-SA04-01 VIOLATION: process_encrypted_transaction_bundle PANICKED \
         (unchecked Decimal addition in TransferSummary accumulation). The engine \
         must degrade to a graceful Result instead of aborting on untrusted input."
    );
    // Any graceful outcome (Ok or typed Err) satisfies the panic-freedom contract.
    let _ = outcome.unwrap();
}

// =============================================================================
// FINDING HMSEC-SA04-02
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-02
// Severity:      High
// CWE:           CWE-190 (Integer Overflow) / CWE-248 (Uncaught Exception)
// Target:        src/services/voucher_validation/chain.rs:194
//                (`let total_input_needed = current_amount + current_remainder;`
//                - same pattern again at line 428 inside the split-equality check)
// Threat Model:  An attacker embeds a hostile voucher chain in a bundle. During
//                ingestion each transaction is validated by
//                `verify_transactions`. For a "split" transaction the validator
//                computes amount + remainder BEFORE comparing it against the
//                parent output (the conservation comparison itself).
// Impact:        By declaring amounts near Decimal::MAX whose sum exceeds the
//                96-bit mantissa, the addition panics *before* the conservation
//                check can reject the chain. Deterministic remote DoS via the
//                standard validation pipeline (receive_bundle).
// Root Cause:    Conservation arithmetic uses the panicking `+` operator prior
//                to the equality comparison; no checked arithmetic on
//                untrusted strings.
// Remediation:   Replace with `checked_add(...)` and return
//                `ValidationError::InsufficientFundsInChain` (or a dedicated
//                ArithmeticOverflow error) when the sum does not fit.
// Test Semantics: `verify_transactions` MUST return Err for a hostile split
//                 chain with overflowing declared amounts - it MUST NOT panic.
//                 FAILS on unpatched code (panic is caught).
// =============================================================================
#[test]
fn sa04_02_chain_validation_must_not_panic_on_split_amount_overflow() {
    let voucher = craft_voucher_with_overflowing_split();

    let (standard, _logic_hash) = &*MINUTO_STANDARD;

    // SECURE INVARIANT (Soll-Verhalten): the conservation validator rejects
    // hostile chains with a typed error; evaluation itself stays panic-free.
    let previous_hook = take_hook();
    set_hook(Box::new(|_| {}));
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        verify_transactions(&voucher, standard)
    }));
    set_hook(previous_hook);

    assert!(
        outcome.is_ok(),
        "HMSEC-SA04-02 VIOLATION: verify_transactions PANICKED while evaluating \
         a split whose amount + sender_remaining_amount exceeds Decimal::MAX. \
         The unguarded addition at chain.rs executes BEFORE the conservation \
         comparison, so malformed amounts crash the validator."
    );

    let result = outcome.unwrap();
    assert!(
        result.is_err(),
        "Hostile chain with impossible split arithmetic must be rejected with Err."
    );
}

/// Builds a cryptographically self-consistent voucher chain:
/// init(amount = 100) followed by split(amount = Decimal::MAX, remaining = 1).
/// All hashes, t_ids, L2 signatures and identity signatures are computed
/// exactly like the production creation path (`resign_transaction_ext`),
/// so the chain passes every structural check until the vulnerable addition.
fn craft_voucher_with_overflowing_split() -> Voucher {
    // Deterministic key material for the attacker.
    let creator_key = SigningKey::from_bytes(&[0xA1u8; 32]);
    let genesis_key = SigningKey::from_bytes(&[0xB2u8; 32]); // ephemeral key of init tx
    let split_input_key = SigningKey::from_bytes(&[0xC3u8; 32]); // holds the value after init

    let creator_did = create_user_id(&creator_key.verifying_key(), None)
        .expect("creator DID creation failed");

    // Random-but-decodable identifiers (16-byte nonce, 32-byte id), as required
    // by verify_transaction_basics' bs58 decoding.
    let nonce_bytes: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let id_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xA5);
    let voucher_id = get_hash(get_hash_from_slices(&[
        &bs58::encode(id_bytes).into_vec()[..],
        &nonce_bytes[..],
    ]));

    // Anchor commitments: init locks the value for split_input_key.
    let receiver_anchor_init = get_hash(split_input_key.verifying_key().to_bytes());
    let next_anchor = get_hash(SigningKey::from_bytes(&[0xD4u8; 32]).verifying_key().to_bytes());

    const T0: &str = "2026-01-01T00:00:00.000000Z";
    const T1: &str = "2026-01-02T00:00:00.000000Z";

    let genesis_pub = bs58::encode(genesis_key.verifying_key().to_bytes()).into_string();
    let split_pub = bs58::encode(split_input_key.verifying_key().to_bytes()).into_string();

    // --- init transaction ---
    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash_from_slices(&[
            &bs58::decode(&voucher_id).into_vec().expect("decode voucher_id")[..],
            &bs58::decode(&voucher_nonce).into_vec().expect("decode nonce")[..],
        ]),
        t_type: "init".to_string(),
        t_time: T0.to_string(),
        sender_id: Some(creator_did.clone()),
        recipient_id: creator_did.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(genesis_pub),
        receiver_ephemeral_pub_hash: Some(receiver_anchor_init),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    init_tx.t_id = get_hash(
        to_canonical_json(&init_tx).expect("canonicalize init tx"),
    );
    let layer2_voucher_id =
        calculate_layer2_voucher_id(&init_tx).expect("l2 voucher id derivation failed");
    let signed_init = resign_transaction_ext(init_tx, &creator_key, &layer2_voucher_id, Some(&genesis_key));

    // --- hostile split transaction ---
    let mut split_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash(to_canonical_json(&signed_init).expect("canonicalize signed init")),
        t_type: "split".to_string(),
        t_time: T1.to_string(),
        sender_id: None, // stealth-style anonymous spend
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: DECIMAL_MAX_STR.to_string(),
        sender_remaining_amount: Some("1".to_string()),
        sender_ephemeral_pub: Some(split_pub),
        receiver_ephemeral_pub_hash: Some(next_anchor),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: Some(TrapData {
            ds_tag: "audit-hostile-ds-tag".to_string(),
            ..Default::default()
        }),
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    split_tx.t_id = get_hash(
        to_canonical_json(&split_tx).expect("canonicalize split tx"),
    );
    // The split input is held by split_input_key (revealed via sender_ephemeral_pub),
    // so its L2 signature must be produced by that key; challenge = trap ds_tag.
    let signed_split = resign_transaction_ext(split_tx, &creator_key, &layer2_voucher_id, Some(&split_input_key));

    Voucher {
        voucher_standard: Default::default(),
        voucher_id,
        voucher_nonce,
        creation_date: T0.to_string(),
        valid_until: "2031-01-01T00:00:00.000000Z".to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "Minuto".to_string(),
            amount: "100".to_string(),
            abbreviation: None,
            description: None,
        },
        collateral: None,
        creator_profile: Default::default(),
        transactions: vec![signed_init, signed_split],
        signatures: vec![],
    }
}

// =============================================================================
// FINDING HMSEC-SA04-03
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-03
// Severity:      High
// CWE:           CWE-667 (Improper Locking / Transaction Scoping) -> State Desynchronization
// Target:        src/wallet/transaction_handler.rs:810-816
//                (`archive_backend.archive_voucher(...)` executed inside
//                `_execute_single_transfer`, which runs on the TEMPORARY wallet
//                clone within `execute_multi_transfer_and_bundle`)
// Threat Model:  A multi-source transfer aborts midway (e.g. source #2 exceeds
//                its balance). The temporary wallet clone is discarded, so the
//                wallet state itself stays consistent - but archive side effects
//                have already escaped the simulated transaction boundary.
// Impact:        The forensic archive ("every state ever seen", basis for
//                double-spend path-union analysis) permanently contains
//                post-states for transfers THAT NEVER HAPPENED. The audit trail
//                is poisoned: ghost chain entries can later collide with real
//                fingerprints and corrupt conflict resolution / forensics.
// Root Cause:     Side-effectful I/O is performed before the atomic commit point
//                 (`*self = temp_wallet`) without journalling or rollback.
// Remediation:   Collect new voucher states during simulation and perform all
//                archiving AFTER the commit succeeds (or journal-and-replay).
// Test Semantics: A recording spy archive MUST stay EMPTY when the overall
//                 operation returns Err (atomicity invariant). FAILS on
//                 unpatched code (the ghost entry from source #1 is observed).
// =============================================================================
#[derive(Default, Clone)]
struct RecordingArchive {
    archived: Arc<Mutex<Vec<(String, String, usize)>>>,
}

impl RecordingArchive {
    fn recorded_count(&self) -> usize {
        self.archived.lock().expect("poisoned mutex").len()
    }
}

impl VoucherArchive for RecordingArchive {
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        owner_id: &str,
        _standard: &human_money_core::VoucherStandardDefinition,
    ) -> Result<(), ArchiveError> {
        self.archived
            .lock()
            .expect("poisoned mutex")
            .push((
                voucher.voucher_id.clone(),
                owner_id.to_string(),
                voucher.transactions.len(),
            ));
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
fn sa04_03_aborted_multi_transfer_must_leave_archive_untouched() {
    let (mut sender_wallet, sender_identity) =
        create_test_wallet("sa04-03-sender-seed", "sender-instance".to_string())
            .expect("sender wallet setup failed");

    let (standard, _logic_hash) = &*MINUTO_STANDARD;

    // Two healthy source vouchers, 100 units each.
    let id_a = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        standard,
        true,
    )
    .expect("voucher A setup failed");
    let id_b = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        standard,
        true,
    )
    .expect("voucher B setup failed");

    let recipient_did = create_user_id(
        &SigningKey::from_bytes(&[0xE5u8; 32]).verifying_key(),
        None,
    )
    .expect("recipient DID creation failed");

    // Source #2 requests more than its balance -> the OVERALL operation fails.
    let request = MultiTransferRequest {
        recipient_id: recipient_did,
        sources: vec![
            SourceTransfer {
                local_instance_id: id_a.clone(),
                amount_to_send: "100".to_string(), // will succeed...
            },
            SourceTransfer {
                local_instance_id: id_b.clone(),
                amount_to_send: "200".to_string(), // ...then this aborts everything
            },
        ],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut definitions = HashMap::new();
    definitions.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let archive = RecordingArchive::default();

    let result = sender_wallet.execute_multi_transfer_and_bundle(
        &sender_identity,
        &definitions,
        request,
        Some(&archive),
    );

    // Precondition: the operation must indeed fail (source #2 over-spend).
    assert!(
        result.is_err(),
        "Test precondition violated: oversized source transfer unexpectedly succeeded."
    );
    let _err: VoucherCoreError = result.unwrap_err();

    // Sanity: the WALLET state itself must be untouched (transactionality).
    for id in [&id_a, &id_b] {
        let instance = sender_wallet
            .voucher_store
            .vouchers
            .get(id)
            .unwrap_or_else(|| panic!("voucher {id} vanished from wallet store"));
        assert!(
            matches!(instance.status, human_money_core::VoucherStatus::Active),
            "Wallet state leaked mutation from aborted operation."
        );
    }

    // SECURE INVARIANT (Soll-Verhalten): if the overall operation failed, the
    // forensic archive must not contain ANY record of it (atomicity).
    assert_eq!(
        archive.recorded_count(),
        0,
        "HMSEC-SA04-03 VIOLATION: archive received ghost entries for a transfer \
         that was rolled back. Archive writes escape the temp-wallet transaction \
         boundary in execute_multi_transfer_and_bundle (_execute_single_transfer \
         archives before commit), desynchronizing forensic history from wallet state."
    );
}

// =============================================================================
// FINDING HMSEC-SA04-04
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-04
// Severity:      Critical
// CWE:           CWE-662 (Improper Synchronization / Partial Transaction Commit)
//                -> State Desynchronization
// Target:        src/wallet/transaction_handler.rs :: process_encrypted_transaction_bundle
//                (ingestion loop: `add_voucher_instance` per iteration ~line 361,
//                failure sources: unknown standard UUID ~215,
//                validate_voucher_against_standard ~222, guard decryption ~241)
// Threat Model:  A peer sends a multi-voucher bundle whose SECOND member is
//                unacceptable to the receiver (unknown standard UUID, standard
//                validation failure, or undecryptable privacy guard). The
//                ingestion loop commits each member incrementally BEFORE the
//                later member fails, so the function returns Err but vouchers
//                from earlier iterations remain permanently in `voucher_store`.
// Impact:        Phantom ownership without consistency: bundle_meta_store.history
//                (Layer-1 bundle_id replay protection), TransferReceived events
//                and fingerprint rebuilds never execute for the aborted run.
//                The store holds vouchers that a retry of the same bundle will
//                NOT be rejected for (replay gate unregistered) and that no UI
//                event ever accounted for - permanent wallet/archive/state desync.
// Root Cause:    Receive path mutates wallet state incrementally inside the
//                validation loop with no rollback, unlike the send path's
//                temp-wallet transactional commit pattern.
// Remediation:   Make ingestion all-or-nothing: snapshot the wallet before any
//                mutation and restore the snapshot when processing returns Err.
// Test Semantics: A 2-voucher bundle where the second member carries an unknown
//                 standard UUID MUST return Err AND leave the voucher_store and
//                 bundle history completely untouched (all-or-nothing).
//                 FAILS on unpatched code (first voucher stays committed).
// =============================================================================
#[test]
fn sa04_04_failed_multi_voucher_receive_must_not_partially_commit() {
    let (mut sender_wallet, sender_identity) =
        create_test_wallet("sa04-04-sender-seed", "sender-instance".to_string())
            .expect("sender wallet setup failed");
    let (mut victim_wallet, victim_identity) =
        create_test_wallet("sa04-04-victim-seed", "victim-instance".to_string())
            .expect("victim wallet setup failed");

    let (minuto, _minuto_hash) = &*MINUTO_STANDARD;
    let (freetaler, _freetaler_hash) = &*FREETALER_STANDARD;

    // Two healthy source vouchers of DIFFERENT standards. The receiver will
    // only know FreeTaler, so the Minuto bundle member must abort ingestion.
    let id_known = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        freetaler,
        true,
    )
    .expect("voucher A (known standard) setup failed");
    let id_unknown = add_voucher_to_wallet(
        &mut sender_wallet,
        &sender_identity,
        "100",
        minuto,
        true,
    )
    .expect("voucher B (unknown standard) setup failed");

    // Sender knows both standards; victim only knows FreeTaler.
    let mut sender_defs = HashMap::new();
    sender_defs.insert(
        freetaler.immutable.identity.uuid.clone(),
        freetaler.clone(),
    );
    sender_defs.insert(minuto.immutable.identity.uuid.clone(), minuto.clone());
    let mut victim_defs = HashMap::new();
    victim_defs.insert(
        freetaler.immutable.identity.uuid.clone(),
        freetaler.clone(),
    );

    let request = MultiTransferRequest {
        recipient_id: victim_identity.user_id.clone(),
        sources: vec![
            SourceTransfer {
                local_instance_id: id_known,
                amount_to_send: "100".to_string(), // processed first...
            },
            SourceTransfer {
                local_instance_id: id_unknown,
                amount_to_send: "100".to_string(), // ...then this aborts ingestion
            },
        ],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_result = sender_wallet
        .execute_multi_transfer_and_bundle(&sender_identity, &sender_defs, request, None)
        .expect("sender multi-transfer must succeed on valid input");

    // Precondition: victim store starts empty.
    assert_eq!(
        victim_wallet.voucher_store.vouchers.len(),
        0,
        "test setup violated: victim wallet already holds vouchers"
    );

    let result = victim_wallet.process_encrypted_transaction_bundle(
        &victim_identity,
        &bundle_result.bundle_bytes,
        None,
        &victim_defs,
    );

    // Precondition: ingestion must indeed fail (unknown standard UUID).
    assert!(
        result.is_err(),
        "Test precondition violated: bundle with unknown standard unexpectedly accepted."
    );

    // SECURE INVARIANT (Soll-Verhalten): a failed receive must leave NO traces.
    // All-or-nothing: neither voucher_store nor bundle history may mutate.
    assert_eq!(
        victim_wallet.voucher_store.vouchers.len(),
        0,
        "HMSEC-SA04-04 VIOLATION: partially committed receive detected - vouchers \
         from earlier loop iterations remain in voucher_store although the overall \
         operation returned Err. The Layer-1 replay gate (bundle_meta_store.history) \
         was never registered for them, so phantom ownership persists without any \
         TransferReceived event or fingerprint rebuild."
    );
    assert!(
        victim_wallet.bundle_meta_store.history.is_empty(),
        "HMSEC-SA04-04 VIOLATION: aborted receive left bundle history entries behind."
    );
}

// =============================================================================
// FINDING HMSEC-SA04-05
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-05
// Severity:      High
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature /
//                missing output-key separation check)
// Target:        src/services/voucher_validation/chain.rs :: verify_transactions
//                (split branch ~441-472: conservation + precision are checked,
//                but the two output anchors are never compared for equality)
// Threat Model:  An issuer crafts a "split" transaction with
//                receiver_ephemeral_pub_hash == change_ephemeral_pub_hash ==
//                H(X). The chain is perfectly self-consistent (signatures,
//                hashes, conservation all hold) and passes validation, but a
//                SINGLE key X controls both branches. The issuer knows X
//                (it chose or derived both seeds) and can spend the recipient
//                branch before the honest recipient does, framing the
//                recipient as a double-spender; identical anchors additionally
//                destroy transfer/change fingerprint unlinkability (trap
//                correlation).
// Impact:        Breaks the documented Split-Anchor Separation invariant
//                (Transfer-Branch key != Change-Branch key): single-key
//                control over both outputs enables framing attacks and
//                privacy-correlated fingerprints.
// Root Cause:    No anchor-separation validation exists anywhere in the
//                chain validator; nothing forbids degenerate identical (or
//                empty) output commitments.
// Remediation:   Reject any "split" transaction whose receiver and change
//                anchors are identical - no legitimate creation path can
//                produce one (recipient seed is random, change seed is HKDF-
//                derived from the sender's permanent key).
// Test Semantics: A cryptographically self-consistent init(100) ->
//                 split(60/40) chain with IDENTICAL output anchors MUST be
//                 rejected by verify_transactions. FAILS on unpatched code
//                 (validator returns Ok for the hostile chain).
// =============================================================================
#[test]
fn sa04_05_split_validator_must_reject_identical_output_anchors() {
    let voucher = craft_voucher_with_overlapping_split_anchors();

    let (standard, _logic_hash) = &*MINUTO_STANDARD;

    // SECURE INVARIANT (Soll-Verhalten): the chain validator enforces
    // Split-Anchor Separation - one key must never control both branches.
    let result = verify_transactions(&voucher, standard);
    assert!(
        result.is_err(),
        "HMSEC-SA04-05 VIOLATION: accepted a split transaction whose \
         receiver_ephemeral_pub_hash equals its change_ephemeral_pub_hash. \
         A single key controls both outputs, enabling double-spend framing \
         of the recipient and transfer/change fingerprint correlation."
    );
}

/// Builds a cryptographically self-consistent voucher chain:
/// init(amount = 100) followed by split(amount = 60, remaining = 40) where
/// BOTH output anchors commit to the SAME key (`single_branch_key`), exactly
/// like production creation code computes every hash/signature
/// (`resign_transaction_ext`), so only the missing separation check lets it pass.
fn craft_voucher_with_overlapping_split_anchors() -> Voucher {
    // Deterministic key material.
    let creator_key = SigningKey::from_bytes(&[0x21u8; 32]);
    let genesis_key = SigningKey::from_bytes(&[0x22u8; 32]); // ephemeral key of init tx
    let split_input_key = SigningKey::from_bytes(&[0x23u8; 32]); // holds the value after init
    let single_branch_key = SigningKey::from_bytes(&[0x24u8; 32]); // controls BOTH split outputs

    let creator_did = create_user_id(&creator_key.verifying_key(), None)
        .expect("creator DID creation failed");

    // Decodable identifiers (16-byte nonce, 32-byte id), as required by
    // verify_transaction_basics' bs58 decoding.
    let nonce_bytes: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x6B);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let id_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xB6);
    let voucher_id = get_hash(get_hash_from_slices(&[
        &bs58::encode(id_bytes).into_vec()[..],
        &nonce_bytes[..],
    ]));

    // Anchor commitments: init locks the value for split_input_key.
    let receiver_anchor_init = get_hash(split_input_key.verifying_key().to_bytes());
    // THE ATTACK: receiver branch AND change branch share one commitment.
    let overlapping_anchor = get_hash(single_branch_key.verifying_key().to_bytes());

    const T0: &str = "2026-01-01T00:00:00.000000Z";
    const T1: &str = "2026-01-02T00:00:00.000000Z";

    let genesis_pub = bs58::encode(genesis_key.verifying_key().to_bytes()).into_string();
    let split_pub = bs58::encode(split_input_key.verifying_key().to_bytes()).into_string();

    // --- init transaction ---
    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash_from_slices(&[
            &bs58::decode(&voucher_id).into_vec().expect("decode voucher_id")[..],
            &bs58::decode(&voucher_nonce).into_vec().expect("decode nonce")[..],
        ]),
        t_type: "init".to_string(),
        t_time: T0.to_string(),
        sender_id: Some(creator_did.clone()),
        recipient_id: creator_did.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(genesis_pub),
        receiver_ephemeral_pub_hash: Some(receiver_anchor_init),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    init_tx.t_id = get_hash(
        to_canonical_json(&init_tx).expect("canonicalize init tx"),
    );
    let layer2_voucher_id =
        calculate_layer2_voucher_id(&init_tx).expect("l2 voucher id derivation failed");
    let signed_init = resign_transaction_ext(init_tx, &creator_key, &layer2_voucher_id, Some(&genesis_key));

    // --- overlapping-anchor split transaction ---
    // prev_hash of the split = hash of the signed init transaction.
    let split_prev_hash =
        get_hash(to_canonical_json(&signed_init).expect("canonicalize signed init"));
    // DS-tag must match the deterministic derivation checked by the validator:
    // H(prev_hash_bytes || revealed_ephemeral_pub_bytes).
    let ds_tag = get_hash_from_slices(&[
        &bs58::decode(&split_prev_hash).into_vec().expect("decode prev_hash")[..],
        &bs58::decode(&split_pub).into_vec().expect("decode split pub")[..],
    ]);

    let mut split_tx = Transaction {
        t_id: String::new(),
        prev_hash: split_prev_hash,
        t_type: "split".to_string(),
        t_time: T1.to_string(),
        sender_id: None, // stealth-style anonymous spend
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "60".to_string(),
        sender_remaining_amount: Some("40".to_string()),
        sender_ephemeral_pub: Some(split_pub),
        receiver_ephemeral_pub_hash: Some(overlapping_anchor.clone()),
        change_ephemeral_pub_hash: Some(overlapping_anchor),
        privacy_guard: None,
        trap_data: Some(TrapData {
            ds_tag,
            ..Default::default()
        }),
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    split_tx.t_id = get_hash(
        to_canonical_json(&split_tx).expect("canonicalize split tx"),
    );
    // The split input is held by split_input_key (revealed via sender_ephemeral_pub),
    // so its L2 signature must be produced by that key; challenge = trap ds_tag.
    let signed_split = resign_transaction_ext(split_tx, &creator_key, &layer2_voucher_id, Some(&split_input_key));

    Voucher {
        voucher_standard: Default::default(),
        voucher_id,
        voucher_nonce,
        creation_date: T0.to_string(),
        valid_until: "2031-01-01T00:00:00.000000Z".to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "Minuto".to_string(),
            amount: "100".to_string(),
            abbreviation: None,
            description: None,
        },
        collateral: None,
        creator_profile: Default::default(),
        transactions: vec![signed_init, signed_split],
        signatures: vec![],
    }
}

// =============================================================================
// FINDING HMSEC-SA04-06
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-06
// Severity:      Critical (mutation-gap regression coverage for a
//                security-bypass mutant)
// CWE:           CWE-347 (Improper Verification of Cryptographic Signature)
// Target:        src/services/bundle_processor.rs :: open_and_verify_bundle ->
//                verify_container_signature (~172-185) and
//                verify_bundle_signature (~188-201)
// Threat Model:  Per temp/uncovered_code.md, body-to-`Ok(())` mutants of both
//                private verification helpers SURVIVE the whole suite: unit
//                tests call them directly with obviously invalid input, but no
//                test pushes a forged artifact through the public path
//                `open_and_verify_bundle`. Because `bundle_id` excludes
//                `sender_signature` (HMC-SEC-06-01), an attacker can replace
//                the signature with random bytes AND recompute a fully
//                self-consistent bundle_id, so the ID-binding check passes and
//                the inner Ed25519 verification is then the ONLY defense.
//                Likewise an empty envelope `signature` is a legitimate
//                privacy-mode shape that skips container verification entirely,
//                making verify_bundle_signature the last line of defense; and
//                a present-but-foreign envelope signature must be rejected
//                against the claimed bundle sender.
// Impact:        If either guard regresses (refactoring, "simplification"),
//                anyone holding a valid (container.i, bundle) snapshot can
//                arbitrarily recombine financial content attributed to the
//                original signer - undetectable by the current suite.
// Root Cause:    Missing end-to-end mutant-killing regression coverage; the
//                production code itself is correct.
// Remediation:   Kill-tests through the PUBLIC path asserting typed rejection:
//                (a) self-consistent bundle with FORGED sender_signature in a
//                    signature-less (privacy-shape) container MUST fail with
//                    InvalidBundleSignature;
//                (b) authentic sender payload re-wrapped in a foreign attacker
//                    container (attacker-signed envelope) MUST fail with
//                    InvalidContainerSignature.
// Test Semantics: PASSES on clean code (documents + guards real behavior).
//                 With either guard mutated to Ok(()), the corresponding part
//                 returns Ok / a different variant and this test FAILS.
// =============================================================================
#[test]
fn sa04_06_forged_bundle_and_foreign_container_signatures_must_fail_end_to_end() {
    use human_money_core::error::ValidationError;
    use human_money_core::models::profile::TransactionBundle;
    use human_money_core::models::secure_container::{
        ContainerConfig, PayloadType, PrivacyMode, SecureContainer,
    };
    use human_money_core::services::bundle_processor::open_and_verify_bundle;
    use human_money_core::services::secure_container_manager::{
        create_secure_container, open_secure_container,
    };

    let alice = &human_money_core::test_utils::ACTORS.alice.identity;
    let bob = &human_money_core::test_utils::ACTORS.bob.identity;

    // Attacker key material (independent of sender and receiver).
    let mallory_keys =
        human_money_core::services::crypto_utils::generate_ed25519_keypair_for_tests(
            Some("sa04-06-mallory-seed"),
        );
    let mallory = human_money_core::models::profile::UserIdentity {
        user_id: create_user_id(&mallory_keys.0, Some("sa04-06-mallory"))
            .expect("mallory DID creation failed"),
        signing_key: mallory_keys.1,
        public_key: mallory_keys.0,
    };

    // Step 1: Alice legitimately transfers to Bob (public/flexible flow),
    // producing an authentic, correctly signed bundle container.
    let (freetaler, _freetaler_hash) = &*FREETALER_STANDARD;
    let mut alice_defs = HashMap::new();
    alice_defs.insert(
        freetaler.immutable.identity.uuid.clone(),
        freetaler.clone(),
    );

    let mut alice_wallet = human_money_core::test_utils::setup_in_memory_wallet(alice);
    let source_id = add_voucher_to_wallet(&mut alice_wallet, alice, "100", freetaler, true)
        .expect("voucher setup failed");
    let bundle_bytes = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &alice_defs,
            MultiTransferRequest {
                recipient_id: bob.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "50".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("legitimate transfer must succeed")
        .bundle_bytes;

    // The attacker (e.g. malicious/compromised receiver Bob or a snapshot
    // thief) decrypts the payload addressed to Bob.
    let original_container: SecureContainer =
        serde_json::from_slice(&bundle_bytes).expect("parse alice's container");
    let authentic_payload = open_secure_container(&original_container, bob, None)
        .expect("recipient-shaped payload must decrypt");
    let mut bundle: TransactionBundle =
        serde_json::from_slice(&authentic_payload).expect("parse alice's bundle");

    // --- PART A: forged INNER bundle signature (kills the
    //     verify_bundle_signature -> Ok(()) survivor mutant). ---
    // Manipulate content, replace the signature with garbage, then recompute
    // bundle_id over the canonical empty-id/empty-sig form so the ID-binding
    // check (HMC-SEC-06-01) passes. Wrap it in a container WITHOUT an
    // envelope signature - the legitimate privacy-mode shape - so the inner
    // bundle signature is the ONLY remaining defense line.
    bundle.notes = Some("forged content".to_string());
    bundle.sender_signature = bs58::encode([0xA7u8; 64]).into_string();
    bundle.bundle_id = String::new();
    bundle.bundle_id =
        get_hash(to_canonical_json(&bundle).expect("canonicalize forged bundle"));

    let forged_bytes = {
        let forged_payload = serde_json::to_vec(&bundle).expect("serialize forged bundle");
        let mut c = create_secure_container(
            &mallory,
            ContainerConfig::TargetDid(bob.user_id.clone(), PrivacyMode::TrialDecryption),
            &forged_payload,
            PayloadType::TransactionBundle,
        )
        .expect("attacker can create encrypted containers");
        // Strip the envelope signature (privacy shape) and recompute `i`
        // over the canonical empty-signature form, exactly like honest
        // privacy-mode creation does.
        c.signature = String::new();
        c.i = String::new();
        c.i = get_hash(to_canonical_json(&c).expect("canonicalize container"));
        serde_json::to_vec(&c).expect("serialize container")
    };

    let outcome_a = open_and_verify_bundle(bob, &forged_bytes);
    match outcome_a {
        Err(VoucherCoreError::Validation(ValidationError::InvalidBundleSignature)) => {}
        other => panic!(
            "HMSEC-SA04-06 VIOLATION (part A): a bundle whose sender_signature \
             was replaced with garbage - even with a fully self-consistent \
             recomputed bundle_id - must be rejected with \
             InvalidBundleSignature by open_and_verify_bundle. Got: {:?}",
            other.map(|_| "Ok(bundle)")
        ),
    }

    // --- PART B: foreign ENVELOPE signature over authentic content (kills
    //     the verify_container_signature -> Ok(()) survivor mutant). ---
    // Mallory re-wraps Alice's AUTHENTIC bundle payload in her own freshly
    // encrypted container. Integrity ID and decryption hold; only the
    // envelope signature check (verified against the CLAIMED sender from the
    // decrypted bundle, i.e. Alice) can reject the foreign wrapper.
    let attack_bytes = {
        let attack_container = create_secure_container(
            &mallory,
            ContainerConfig::TargetDid(bob.user_id.clone(), PrivacyMode::TrialDecryption),
            &authentic_payload,
            PayloadType::TransactionBundle,
        )
        .expect("attacker container creation failed");
        serde_json::to_vec(&attack_container).expect("serialize container")
    };

    let outcome_b = open_and_verify_bundle(bob, &attack_bytes);
    match outcome_b {
        Err(VoucherCoreError::Validation(ValidationError::InvalidContainerSignature)) => {}
        other => panic!(
            "HMSEC-SA04-06 VIOLATION (part B): a container whose envelope \
             signature was produced by a THIRD PARTY (mallory) but whose \
             decrypted bundle claims alice as sender must be rejected with \
             InvalidContainerSignature. Got: {:?}",
            other.map(|_| "Ok(bundle)")
        ),
    }
}

// =============================================================================
// FINDING HMSEC-SA04-07
// -----------------------------------------------------------------------------
// Finding-ID:    HMSEC-SA04-07
// Severity:      Medium (downgraded after triage - see below)
// CWE:           CWE-1339 (Implicit Conversion / Silent Rounding), target of
//                a potential Conservation-of-Value breach (CWE-682)
// Target:        src/services/decimal_utils.rs :: format_for_storage (~46-48);
//                consumers: services/voucher_manager/creation.rs:243,
//                services/voucher_manager/transaction.rs:90+197
// Threat Model:  `format_for_storage` uses `format!("{:.places}")`, which
//                SILENTLY ROUNDS (including rounding UP, e.g. remainder
//                0.006 -> "0.01" at places=2). If any route ever fed it an
//                amount whose scale exceeds the standard's decimal places,
//                Sigma(outputs) could exceed Sigma(inputs) by rounding dust
//                (value inflation out of formatting alone).
// Triage Result: [FALSE POSITIVE for exploitability] - all production routes
//                are structurally protected TODAY:
//                (a) transfer/split: create_transaction enforces
//                    validate_precision(amount, places) BEFORE formatting, and
//                    the subtraction producing the remainder cannot exceed the
//                    operand scales;
//                (b) issuance: create_voucher formats the initial amount
//                    without a prior precision check, but verify_transaction_
//                    basics requires init amount == nominal_value.amount on
//                    EVERY subsequent validation, so a silently rounded
//                    issuance fails closed downstream.
//                Defense-in-depth recommendation (NOT applied to avoid an API
//                break): harden format_for_storage to fail-on-rounding in a
//                future major version.
// Test Semantics: CONTROL / REGRESSION GUARD (passes by design):
//                (1) within the production-guaranteed domain (scale <= places)
//                    storage formatting must round-trip EXACTLY;
//                (2) end-to-end tripwire: a partial transfer must store
//                    strings whose parsed sum equals the source balance
//                    exactly - this FAILS if anyone ever removes the upstream
//                    precision guards and silent rounding becomes reachable.
// =============================================================================
#[test]
fn sa04_07_storage_formatting_is_exact_within_validated_precision_domain() {
    use human_money_core::services::decimal_utils::format_for_storage;
    use rust_decimal::Decimal;
    use std::str::FromStr;

    // --- INVARIANT 1: exactness inside the production domain ---
    // For every (value, places) pair reachable through validated inputs
    // (value.scale() <= places) the canonical storage string must parse back
    // to the identical Decimal - no rounding, no truncation.
    let exact_cases = [
        ("100", 0u32),
        ("7", 0),
        ("33", 2),
        ("0.01", 2),
        ("66.67", 2),
        ("1234.5678", 4),
    ];
    for (value_str, places) in exact_cases {
        let value = Decimal::from_str(value_str).expect("parse test decimal");
        let stored = format_for_storage(&value, places);
        assert_eq!(
            Decimal::from_str(&stored).expect("storage string must re-parse"),
            value,
            "HMSEC-SA04-07 VIOLATION: format_for_storage silently altered the \
             value {} at places={} into '{}' - canonical storage formatting \
             must be exact within the validated precision domain.",
            value_str,
            places,
            stored
        );
    }

    // --- INVARIANT 2: end-to-end split conservation tripwire ---
    // FreeTaler uses amount_decimal_places = 2. A partial transfer of 33.33
    // from a 100.00 voucher must store machine-readable strings that sum up
    // EXACTLY to the source balance. If the upstream validate_precision gate
    // were removed and silent rounding became reachable (e.g. sending
    // 33.335), this assertion would expose resulting value inflation.
    let (freetaler, _hash) = &*FREETALER_STANDARD;
    let alice = &human_money_core::test_utils::ACTORS.alice.identity;
    let bob_did = create_user_id(
        &SigningKey::from_bytes(&[0x37u8; 32]).verifying_key(),
        None,
    )
    .expect("recipient DID creation failed");

    let mut defs = HashMap::new();
    defs.insert(freetaler.immutable.identity.uuid.clone(), freetaler.clone());

    let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(alice);
    let source_id = add_voucher_to_wallet(&mut wallet, alice, "100.00", freetaler, true)
        .expect("voucher setup failed");

    let _bundle = wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &defs,
            MultiTransferRequest {
                recipient_id: bob_did,
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "33.33".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("partial transfer must succeed");

    // After the split, exactly one active instance remains (the change).
    assert_eq!(
        wallet.voucher_store.vouchers.len(),
        1,
        "test setup violated: expected exactly the change instance after split"
    );
    let last_tx = wallet
        .voucher_store
        .vouchers
        .values()
        .next()
        .expect("change instance present")
        .voucher
        .transactions
        .last()
        .expect("split instance carries transactions")
        .clone();

    let sent = Decimal::from_str(&last_tx.amount).expect("stored amount must parse");
    let remaining = Decimal::from_str(
        last_tx
            .sender_remaining_amount
            .as_deref()
            .expect("split must carry sender_remaining_amount"),
    )
    .expect("stored remainder must parse");
    let balance = Decimal::from_str("100").expect("constant");

    assert_eq!(
        sent + remaining,
        balance.normalize(),
        "HMSEC-SA04-07 VIOLATION: stored split outputs ({sent} + {remaining}) \
         no longer conserve the source balance - silent rounding leaked value."
    );
}

// =============================================================================
// FINDING HMSEC-SA04-08 (Wave-3 hypothesis WH3-04-401)
// -----------------------------------------------------------------------------
// Finding-ID:      HMSEC-SA04-08
// Severity:        Critical
// CWE:             CWE-347 (Improper Verification of Cryptographic Signature -
//                  a security-critical field is excluded from every
//                  authenticated digest)
// Target Location: src/services/voucher_validation/chain.rs:599-605 (canonical
//                  t_id preimage EXCLUDES `privacy_guard`) and chain.rs:664-694
//                  (HMC_TX_AUTH_V3 layer2 digest excludes the guard);
//                  src/services/conflict_manager.rs:25-116 (fingerprint builder
//                  ignores the guard) and conflict_manager.rs:282-304 (HashSet
//                  dedup collapses identical entries; `unique_t_ids > 1` gate
//                  never fires); src/services/trap_manager.rs (identical-shard /
//                  identical-tau guards discard the degenerate "pair" as a
//                  replay, not a fork).
// Threat Model:    A malicious issuer creates ONE flexible/stealth spend T of a
//                  real input and hands the byte-identical transaction (same
//                  t_id, same SST shards, same layer2_signature, same identity
//                  signature) to TWO victims under two DIFFERENT privacy guards,
//                  each an individually valid AEAD payload addressed to its
//                  victim. Because neither the t_id preimage nor the V3 L2
//                  digest nor the fingerprint builder covers the guard, BOTH
//                  handovers are individually chain-valid and produce
//                  BYTE-IDENTICAL fraud fingerprints. When both victims later
//                  spend their branches, their child chains diverge only
//                  guard-dependently via prev_hash, so their ds_tags differ and
//                  no collision bucket ever forms.
// Impact:          Regresses the core paradigm "Fraud Detection, Not
//                  Prevention" for the most important attacker class (the
//                  issuer/holder himself): a coin can be sold twice while ZERO
//                  cryptographic fraud evidence survives anywhere - no
//                  attribution, no quarantine, ever.
// Root Cause:      V3 (HMC_TX_AUTH_V3) moved `trap_data` AND `privacy_guard`
//                  out of all authenticated preimages. The guard is bound to
//                  nothing, so guard equivocation is invisible to creation,
//                  validation, fingerprinting and collision detection alike.
// Remediation:     Bind a hash of `privacy_guard` into EITHER the canonical
//                  t_id preimage OR the V3 layer2 digest (both variants then
//                  carry distinct t_ids / signatures and form a genuine,
//                  attributable fork pair under the existing machinery), OR
//                  treat duplicate t_ids with diverging canonical JSON as an
//                  explicit equivocation conflict class inside
//                  check_for_double_spend.
// Test Semantics:  Fail-first. Produces one production-created flexible spend
//                  plus a twin whose guard was swapped for a REAL production
//                  guard addressed to a different recipient. Asserts (a) both
//                  twins individually validate (documenting the binding gap),
//                  (b) their fraud fingerprints are DISTINGUISHABLE evidence,
//                  and (c) feeding the pair into check_for_double_spend
//                  SURFACES a verifiable conflict (the prerequisite for
//                  attribution/quarantine). FAILS on unpatched code at (b)/(c):
//                  fingerprints dedup byte-identically and the detector reports
//                  nothing (`unique_t_ids == 1`).
//
// REMEDIATED (protocol V3 hardening): the canonical privacy-guard commitment
// is now bound into the HMC_TX_AUTH_V3 digest; equivocation twins fail chain
// validation and produce distinguishable evidence.
// =============================================================================
#[test]
fn sa04_08_guard_equivocation_must_produce_attributable_evidence() {
    let alice = &human_money_core::test_utils::ACTORS.alice.identity;
    let charlie_did = human_money_core::test_utils::ACTORS.charlie.identity.user_id.clone();
    let bob_did = human_money_core::test_utils::ACTORS.bob.identity.user_id.clone();

    let (freetaler, _hash) = &*FREETALER_STANDARD;
    let mut definitions = HashMap::new();
    definitions.insert(
        freetaler.immutable.identity.uuid.clone(),
        freetaler.clone(),
    );

    let mut wallet = setup_in_memory_wallet(alice);

    // Two independent vouchers of the same standard; FreeTaler runs in
    // 'flexible' privacy mode, so full spends attach a REAL AEAD privacy
    // guard addressed to the respective recipient.
    let id_a = add_voucher_to_wallet(&mut wallet, alice, "100", freetaler, true)
        .expect("voucher A setup failed");
    let id_b = add_voucher_to_wallet(&mut wallet, alice, "100", freetaler, true)
        .expect("voucher B setup failed");

    // A FULL spend removes the instance under its old local ID and re-adds
    // the archived sender copy under a NEW derived ID, so we track the
    // immutable voucher identity instead of the ephemeral local key.
    let vid_a = wallet.voucher_store.vouchers[&id_a].voucher.voucher_id.clone();
    let vid_b = wallet.voucher_store.vouchers[&id_b].voucher.voucher_id.clone();

    // Spend voucher A fully to Charlie -> archived sender copy holds T_A
    // (chain init -> transfer with guard_A for Charlie).
    let _ = wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &definitions,
            MultiTransferRequest {
                recipient_id: charlie_did,
                sources: vec![SourceTransfer {
                    local_instance_id: id_a.clone(),
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("transfer A must succeed");

    // Spend voucher B fully to Bob -> T_B carries guard_B for Bob.
    let _ = wallet
        .execute_multi_transfer_and_bundle(
            alice,
            &definitions,
            MultiTransferRequest {
                recipient_id: bob_did,
                sources: vec![SourceTransfer {
                    local_instance_id: id_b.clone(),
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("transfer B must succeed");

    // Harvest both production-created spend tips plus the shared init tx.
    let voucher_a_full = wallet
        .voucher_store
        .vouchers
        .values()
        .find(|inst| inst.voucher.voucher_id == vid_a)
        .expect("archived copy of spend A missing")
        .voucher
        .clone();
    let init_tx = voucher_a_full.transactions[0].clone();
    let t_a = voucher_a_full.transactions.last().unwrap().clone();
    let t_b = wallet
        .voucher_store
        .vouchers
        .values()
        .find(|inst| inst.voucher.voucher_id == vid_b)
        .expect("archived copy of spend B missing")
        .voucher
        .transactions
        .last()
        .unwrap()
        .clone();

    // Preconditions: both spends carry genuine, distinct guards.
    assert!(
        t_a.privacy_guard.is_some() && t_b.privacy_guard.is_some(),
        "test precondition violated: production flexible spends must attach privacy guards"
    );
    assert_ne!(
        t_a.privacy_guard, t_b.privacy_guard,
        "test precondition violated: the two guards must be different recipients' payloads"
    );

    // THE ATTACK (guard equivocation): one input, two handovers. The twin is
    // byte-identical to T_A except that the guard now addresses BOB - and it
    // is Bob's REAL guard, so Bob can genuinely decrypt his copy.
    let mut t_ab = t_a.clone();
    t_ab.privacy_guard = t_b.privacy_guard.clone();

    // Documented V3 property: swapping the guard leaves the canonical
    // transaction identity untouched - the guard binding lives in the V3
    // signature digest, not in the t_id preimage.
    assert_eq!(
        t_ab.t_id, t_a.t_id,
        "documented V3 property: the t_id preimage excludes privacy_guard; \
         the guard is bound by the HMC_TX_AUTH_V3 layer2_signature instead"
    );

    // Wrap both tips over the SAME chain prefix and verify each chain.
    let mut va = voucher_a_full.clone();
    va.transactions = vec![init_tx.clone(), t_a.clone()];
    let mut vb = voucher_a_full;
    vb.transactions = vec![init_tx, t_ab.clone()];

    // (a) Variant A passes full chain validation; the guard-swapped twin is
    //     REJECTED: its layer2_signature was computed over a different
    //     privacy-guard commitment than the one carried by the transaction.
    assert!(
        verify_transactions(&va, freetaler).is_ok(),
        "variant A must validate (precondition)"
    );
    assert!(
        verify_transactions(&vb, freetaler).is_err(),
        "HMSEC-SA04-08 REGRESSION: the guard-equivocation twin still validates \
         although its layer2_signature was computed over a DIFFERENT privacy \
         guard than the one carried by the transaction"
    );

    // (b) SOLL: the two handovers must yield DISTINGUISHABLE fraud evidence.
    let fp_a = create_fingerprint_for_transaction(&t_a, &va).expect("fingerprint A");
    let fp_ab = create_fingerprint_for_transaction(&t_ab, &vb).expect("fingerprint AB");
    assert_ne!(
        fp_a, fp_ab,
        "HMSEC-SA04-08 VIOLATION: two handovers of ONE input under two \
         different privacy guards produce BYTE-IDENTICAL fraud fingerprints. \
         The guard participates in no authenticated digest, so equivocation is \
         invisible to the fingerprint layer and downstream dedup."
    );

    // (c) SOLL: the detector must surface verifiable conflict evidence for the
    //     equivocation pair (the basis for attribution and quarantine).
    let own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();
    known
        .local_history
        .insert(fp_a.ds_tag.clone(), vec![fp_a.clone()]);
    known
        .foreign_fingerprints
        .insert(fp_ab.ds_tag.clone(), vec![fp_ab]);
    let result = check_for_double_spend(&own, &known);
    assert!(
        result.verifiable_conflicts.contains_key(&fp_a.ds_tag),
        "HMSEC-SA04-08 VIOLATION: check_for_double_spend reports NO conflict \
         for a double-handed input. Byte-identical fingerprints collapse in \
         the HashSet dedup (unique_t_ids == 1), so a double-sold coin stays \
         permanently unattributable and unquarantinable."
    );
}

// =============================================================================
// FINDING HMSEC-SA04-09 (Wave-3 hypothesis WH3-04-402)
// -----------------------------------------------------------------------------
// Finding-ID:      HMSEC-SA04-09
// Severity:        High
// CWE:             CWE-20 (Improper Input Validation - missing structural
//                  validation of cryptographic material before acceptance)
// Target Location: src/services/voucher_validation/chain.rs:310-353 (trap_data
//                  block: only DID-marker characters ':'/'@' and the
//                  ds_tag == H(prev_hash || sender_ephemeral_pub) binding are
//                  checked; trap_r/trap_s are NEVER decoded, so neither curve-
//                  point validity of R_i nor canonical-scalar validity of s_i
//                  is enforced). Contrast: generation contract
//                  src/services/trap_manager.rs :: generate_sst_trap always
//                  emits a decompressable point + canonical scalar.
// Threat Model:    A malicious payer bypasses generate_sst_trap (raw bundle
//                  crafting or a patched client) and signs ARBITRARY byte
//                  strings as SST shards with the legitimately held input key
//                  - the HMC_TX_AUTH_V3 digest binds the shard STRINGS verba-
//                  tim, so garbage signs perfectly. In PUBLIC mode there is no
//                  Layer-0 guard requirement and no handover witness check
//                  (R5 lives exclusively inside the guard-present branch),
//                  leaving the chain validator as the last line of defense -
//                  which accepts anything. Such shards are not affine images
//                  of any SST relation: every later collision of this input
//                  fails in parse_shard/reconstruct_identity, so attribution
//                  is impossible although every signature validated.
// Impact:          Double-spend detection evasion switchable per payment: the
//                  offender unilaterally blinds the SST exactly where the
//                  documented fail-closed guarantee ("recipients reject garbage
//                  traps") does not reach, permanently immunizing the coin
//                  against DS attribution.
// Root Cause:      Structural shard sanity (base58 decodability, 32-byte
//                  length, Edwards-point decompressability of trap_r,
//                  canonical scalar range of trap_s) is enforced nowhere on
//                  the validator level.
// Remediation:     Enforce structural shard validation in the chain validator's
//                  trap_data block: decode_base58 + length 32 +
//                  CompressedEdwardsY decompress for trap_r and strict
//                  canonical scalar parsing for trap_s, rejecting with
//                  ValidationError::TrapDataInvalid otherwise. (Generation
//                  contract guarantees these properties for honest sends.)
// Test Semantics:  Fail-first. Builds cryptographically self-consistent
//                  init(100) -> transfer(100) chains whose tip carries the
//                  CORRECT ds_tag but structurally invalid shards:
//                  (1) trap_r encodes 32 bytes that are NOT a valid compressed
//                      Edwards point ([0xFF;32], y >= p guaranteed invalid);
//                  (2) trap_s contains characters outside the Base58 alphabet.
//                  All signatures are recomputed honestly over the poisoned
//                  strings. verify_transactions MUST reject both chains with a
//                  structural error. FAILS on unpatched code (returns Ok).
//                  Scope note: unlike AUDIT-01-F12 / audit_02_09 (wallet-level
//                  witness enforcement at handover, ignored test), this test
//                  targets the MISSING VALIDATOR-SIDE structure check itself.
// =============================================================================
/// Builds a self-consistent init(100) -> transfer(100) chain whose tip carries
/// the given (possibly poisoned) SST shard strings under the CORRECT ds_tag.
/// Every hash and signature mirrors the production creation path
/// (`resign_transaction_ext`), so ONLY a validator-side structure check can
/// reject the chain.
fn craft_public_mode_chain_with_shards(trap_r: String, trap_s: String) -> Voucher {
    let creator_key = SigningKey::from_bytes(&[0x41u8; 32]);
    let genesis_key = SigningKey::from_bytes(&[0x42u8; 32]); // ephemeral key of init tx
    let input_key = SigningKey::from_bytes(&[0x43u8; 32]); // holds the value after init

    let creator_did = create_user_id(&creator_key.verifying_key(), None)
        .expect("creator DID creation failed");

    // Decodable identifiers (16-byte nonce, 32-byte id).
    let nonce_bytes: [u8; 16] = core::array::from_fn(|i| (i as u8) ^ 0x7C);
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let id_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xC7);
    let voucher_id = get_hash(get_hash_from_slices(&[
        &bs58::encode(id_bytes).into_vec()[..],
        &nonce_bytes[..],
    ]));

    let receiver_anchor_init = get_hash(input_key.verifying_key().to_bytes());
    let next_anchor = get_hash(SigningKey::from_bytes(&[0x44u8; 32]).verifying_key().to_bytes());

    const T0: &str = "2026-01-01T00:00:00.000000Z";
    const T1: &str = "2026-01-02T00:00:00.000000Z";

    let genesis_pub = bs58::encode(genesis_key.verifying_key().to_bytes()).into_string();
    let input_pub = bs58::encode(input_key.verifying_key().to_bytes()).into_string();

    // --- init transaction ---
    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: get_hash_from_slices(&[
            &bs58::decode(&voucher_id).into_vec().expect("decode voucher_id")[..],
            &bs58::decode(&voucher_nonce).into_vec().expect("decode nonce")[..],
        ]),
        t_type: "init".to_string(),
        t_time: T0.to_string(),
        sender_id: Some(creator_did.clone()),
        recipient_id: creator_did,
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(genesis_pub),
        receiver_ephemeral_pub_hash: Some(receiver_anchor_init),
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
    let signed_init =
        resign_transaction_ext(init_tx, &creator_key, &layer2_voucher_id, Some(&genesis_key));

    // --- poisoned transfer transaction ---
    let prev_hash = get_hash(to_canonical_json(&signed_init).expect("canonicalize signed init"));
    // DS-tag MUST match the deterministic derivation checked by the validator:
    // H(prev_hash_bytes || revealed_ephemeral_pub_bytes).
    let ds_tag = get_hash_from_slices(&[
        &bs58::decode(&prev_hash).into_vec().expect("decode prev_hash")[..],
        &bs58::decode(&input_pub).into_vec().expect("decode input pub")[..],
    ]);

    let mut transfer_tx = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: T1.to_string(),
        sender_id: None, // anonymous spend, public-mode compatible
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        sender_ephemeral_pub: Some(input_pub),
        receiver_ephemeral_pub_hash: Some(next_anchor),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: Some(TrapData {
            ds_tag,
            trap_r,
            trap_s,
        }),
        layer2_signature: None,
        deletable_at: None,
        sender_identity_signature: None,
    };
    transfer_tx.t_id = get_hash(
        to_canonical_json(&transfer_tx).expect("canonicalize transfer tx"),
    );
    // The input is held by input_key (revealed via sender_ephemeral_pub); its
    // V3 L2 signature binds the POISONED shard strings verbatim - signing
    // garbage works because the digest treats shards as opaque strings.
    let signed_transfer = resign_transaction_ext(
        transfer_tx,
        &creator_key,
        &layer2_voucher_id,
        Some(&input_key),
    );

    Voucher {
        voucher_standard: Default::default(),
        voucher_id,
        voucher_nonce,
        creation_date: T0.to_string(),
        valid_until: "2031-01-01T00:00:00.000000Z".to_string(),
        non_redeemable_test_voucher: true,
        nominal_value: ValueDefinition {
            unit: "Minuto".to_string(),
            amount: "100".to_string(),
            abbreviation: None,
            description: None,
        },
        collateral: None,
        creator_profile: Default::default(),
        transactions: vec![signed_init, signed_transfer],
        signatures: vec![],
    }
}

#[test]
fn sa04_09_chain_validator_must_reject_structurally_invalid_sst_shards() {
    let cases = [
        (
            "non-curve-point commitment shard",
            bs58::encode([0xFFu8; 32]).into_string(), // y >= p: NEVER decompressable
            bs58::encode([0x01u8; 32]).into_string(), // canonical scalar (not the trigger)
        ),
        (
            "non-base58 response shard",
            bs58::encode([0x2Au8; 32]).into_string(),
            "###invalid-base58-shard###".to_string(), // undecodable scalar encoding
        ),
    ];

    let (standard, _logic_hash) = &*MINUTO_STANDARD;

    for (label, trap_r, trap_s) in cases {
        let voucher = craft_public_mode_chain_with_shards(trap_r, trap_s);

        // SECURE INVARIANT (Soll-Verhalten): the chain validator enforces the
        // SST generation contract (decompressable R_i, canonical scalar s_i)
        // structurally; garbage shards must be rejected BEFORE a coin built on
        // them becomes permanent double-spend detection evasion.
        let result = verify_transactions(&voucher, standard);
        assert!(
            result.is_err(),
            "HMSEC-SA04-09 VIOLATION ({label}): verify_transactions accepted a \
             chain whose tip carries STRUCTURALLY INVALID SST shards. The \
             validator checks only DID-marker characters and the ds_tag \
             binding, so a malicious payer can blind the SST per payment and \
             permanently evade double-spend attribution in public mode."
        );
    }
}

// =============================================================================
// FINDING HMSEC-SA04-10 (Wave-3 hypothesis WH3-04-403)
// -----------------------------------------------------------------------------
// Finding-ID:      HMSEC-SA04-10
// Severity:        Medium
// CWE:             CWE-349 (Acceptance of Extraneous Untrusted Data in Trust
//                  Decision - stored evidence not bound to local input context)
// Target Location: src/wallet/conflict_handler.rs:1015-1022 (V3 ingress gate:
//                  non-init + self-signature only) vs. the tag-binding check
//                  reproduces_local_tag (conflict_handler.rs:1207-1237) that
//                  runs only LATER inside the quarantine race;
//                  persistence into foreign_fingerprints at
//                  conflict_handler.rs:1081-1090; downstream junk-proof
//                  persistence at src/wallet/transaction_handler.rs:591-701;
//                  grouping solely by ds_tag in
//                  src/services/conflict_manager.rs:282-304.
// Threat Model:    The ingress gate admits any forwarded fingerprint that is
//                  (a) not an init entry and (b) self-authenticating - signed
//                  by the ephemeral key NAMED IN THE FINGERPRINT ITSELF. Any
//                  external peer can therefore freely mint such entries and
//                  inject them under a VICTIM'S publicly gossiped input tag
//                  D_H with arbitrary t_ids. The input-binding invariant
//                  (ds_tag == H(prev_hash || sender_ephemeral_pub) against the
//                  locally known fork, i.e. sender_ephemeral_pub must equal the
//                  victim's locally revealed input key) is only evaluated much
//                  later inside resolve_conflict_offline's race - NOT at
//                  storage time. X1/X2 land permanently in
//                  foreign_fingerprints[D_H]; every subsequent honest receive
//                  groups the victim branch with >= 3 unique t_ids ->
//                  persistent verifiable_conflicts and junk soft proofs. The
//                  fallback attribution even names the VICTIM'S OWN ephemeral
//                  key ('ephemeral:E_H') as offender (conflict_handler.rs
//                  :771-784), poisoning the forensic workflow - without any
//                  quarantine (reproduces_local_tag blocks the race win).
// Impact:          Permanent false-alarm channel towards the app layer, proof-
//                  store pollution and unusable forensics for every wallet the
//                  victim receives bundles at; violates the documented attacker
//                  class boundary ("only former key holders",
//                  conflict_handler.rs:1123-1137) since ANY external peer
//                  suffices.
// Root Cause:      Admission decision keyed on message authenticity instead of
//                  LOCAL CONTEXT BINDING; the binding gate exists but sits in
//                  the race, not at ingestion/storage time.
// Remediation:     At ingress/persistence time, drop forwarded fingerprints
//                  whose ds_tag matches a LOCALLY KNOWN input unless
//                  fp.sender_ephemeral_pub equals the locally revealed input
//                  key of that tag (analogon of reproduces_local_tag hoisted
//                  into process_received_fingerprints / import_foreign_
//                  fingerprints); optionally cap foreign bucket size per tag.
// Test Semantics:  Fail-first. A victim holds one active voucher whose input
//                  tag D_H is publicly known. Two THIRD-PARTY-signed (fresh
//                  attacker keys, never holders of the input key) well-formed
//                  gossip fingerprints under D_H are delivered via an ordinary
//                  bundle. SOLL: they must be rejected at ingress or at least
//                  never persist under D_H with foreign keys, and no junk
//                  conflict record may be created. FAILS on unpatched code:
//                  X1/X2 are stored under D_H and a soft proof naming the
//                  victim-side ephemeral key is persisted. Control assertion:
//                  the victim voucher stays Active (race protection intact).
// =============================================================================

/// Builds a self-authenticating (V3) gossip fingerprint signed by `signer`
/// over the canonical HMC_TX_AUTH_V3 digest (mirror of the module-01 helper).
fn sa04_10_make_foreign_fp(
    signer: &SigningKey,
    ds_tag: &str,
    t_id_bytes: &[u8; 32],
    trap_r: &str,
    trap_s: &str,
    encrypted_timestamp: u128,
) -> TransactionFingerprint {
    use human_money_core::services::l2_gateway::{
        calculate_l2_payload_hash_raw, TRAP_NONE_PLACEHOLDER,
    };

    let eph_pub = signer.verifying_key().to_bytes();
    let payload_hash = calculate_l2_payload_hash_raw(
        // Synthetic gossip fingerprint without voucher context: bind the
        // canonical "none" placeholder and an empty privacy-guard commitment,
        // mirroring what ingress verification reproduces.
        TRAP_NONE_PLACEHOLDER,
        ds_tag,
        t_id_bytes,
        &eph_pub,
        trap_r,
        trap_s,
        encrypted_timestamp,
        None,
        "",
    );
    let sig = human_money_core::services::crypto_utils::sign_ed25519(signer, &payload_hash);
    TransactionFingerprint {
        ds_tag: ds_tag.to_string(),
        trap_r: trap_r.to_string(),
        trap_s: trap_s.to_string(),
        t_id: bs58::encode(t_id_bytes).into_string(),
        layer2_signature: bs58::encode(sig.to_bytes()).into_string(),
        sender_ephemeral_pub: bs58::encode(eph_pub).into_string(),
        deletable_at: "2099-01-01T00:00:00Z".to_string(),
        encrypted_timestamp,
        layer2_voucher_id: TRAP_NONE_PLACEHOLDER.to_string(),
        privacy_guard_hash: String::new(),
    }
}

#[test]
fn sa04_10_fingerprint_ingress_must_bind_to_local_input_context() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::voucher_manager::NewVoucherData;

    let dir = tempfile::tempdir().unwrap();
    let password = "audit-password";
    let standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (standard_def, _) = &*FREETALER_STANDARD;
    let mut standards_map = HashMap::new();
    standards_map.insert(
        standard_def.immutable.identity.uuid.clone(),
        standard_toml.clone(),
    );

    let (mut alice, _) =
        setup_service_with_profile(dir.path(), &human_money_core::test_utils::ACTORS.alice, "A16", password);
    let (mut victim, _) =
        setup_service_with_profile(dir.path(), &human_money_core::test_utils::ACTORS.charlie, "V16", password);
    let (mut hacker, _) =
        setup_service_with_profile(dir.path(), &human_money_core::test_utils::ACTORS.hacker, "H16", password);

    let id_alice = alice.get_user_id().unwrap();
    let id_victim = victim.get_user_id().unwrap();

    // Honest baseline: Alice issues a voucher and transfers it fully to the
    // victim, who holds one ACTIVE branch with a publicly visible input tag.
    alice.unlock_session(password, 300).unwrap();
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
            Some(password),
        )
        .expect("voucher creation failed");
    let local_id = alice.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let result = alice
        .create_transfer_bundle(
            MultiTransferRequest {
                recipient_id: id_victim.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: local_id,
                    amount_to_send: "100".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            &standards_map,
            None,
            Some(password),
        )
        .expect("transfer creation failed");
    victim.unlock_session(password, 300).unwrap();
    victim
        .receive_bundle(&result.bundle_bytes, &standards_map, None, Some(password), false)
        .expect("victim must accept the honest transfer");

    // Extract the victim's public fork anchor: input tag D_H, locally
    // revealed input key E_H (both gossip-readable).
    let (ds_tag_victim, e_h, _prev_hash) = {
        let (vw, _) = victim.get_unlocked_mut_for_test();
        let instance = vw.voucher_store.vouchers.values().next().unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();
        (
            last_tx.trap_data.as_ref().unwrap().ds_tag.clone(),
            last_tx.sender_ephemeral_pub.clone().unwrap(),
            last_tx.prev_hash.clone(),
        )
    };

    // ATTACK: two third-party peers (NEVER holders of the input key) mint
    // well-formed, correctly self-signed fingerprints under the victim's
    // input tag D_H with arbitrary sibling t_ids.
    let attack_fps: Vec<TransactionFingerprint> = (0..2)
        .map(|i| {
            let mut seed = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut seed);
            let attacker_key = SigningKey::from_bytes(&seed);
            let mut t_id = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut t_id);
            let fp = sa04_10_make_foreign_fp(
                &attacker_key,
                &ds_tag_victim,
                &t_id,
                &format!("poison_shard_r_{i}"),
                &format!("poison_shard_s_{i}"),
                42, // would win any race if ever admitted to one
            );
            assert!(
                verify_fingerprint_signature(&fp),
                "attack precondition: injected fingerprints must be self-authenticating"
            );
            fp
        })
        .collect();

    // Ship the poison inside an otherwise harmless gossip bundle.
    let depths: HashMap<String, i8> = [(ds_tag_victim.clone(), 1i8)].into_iter().collect();
    hacker.unlock_session(password, 300).unwrap();
    let (attack_bundle, _) = {
        let (hw, hidentity) = hacker.get_unlocked_mut_for_test();
        hw.create_and_encrypt_transaction_bundle(
            hidentity,
            vec![],
            &id_victim,
            None,
            attack_fps,
            depths,
            None,
        )
        .expect("attacker gossip bundle creation failed")
    };
    victim.unlock_session(password, 300).unwrap();
    victim
        .receive_bundle(&attack_bundle, &standards_map, None, Some(password), false)
        .expect("processing a fingerprint-only gossip bundle must succeed");

    // SECURE INVARIANT (Soll-Verhalten): foreign entries colliding with a
    // LOCALLY KNOWN input tag must be bound to the locally revealed input
    // key - third-party junk must be dropped at ingress (or at minimum never
    // persist under D_H), and no junk conflict record may be created.
    let status_after = victim.get_voucher_summaries(None, None, None).unwrap()[0]
        .status
        .clone();
    assert_eq!(
        status_after,
        human_money_core::VoucherStatus::Active,
        "control precondition broken: race protection regressed - third-party \
         gossip quarantined the honest branch"
    );

    {
        let (vw, _) = victim.get_unlocked_mut_for_test();
        let stored = vw
            .known_fingerprints
            .foreign_fingerprints
            .get(&ds_tag_victim)
            .cloned()
            .unwrap_or_default();
        assert!(
            stored.iter().all(|fp| fp.sender_ephemeral_pub == e_h),
            "HMSEC-SA04-10 VIOLATION (ingress binding): fingerprints signed by \
             keys that NEVER held the victim's input were persisted under the \
             locally known input tag D_H ({} foreign entries, keys: {:?}). The \
             ds_tag<->input-key binding check exists only inside the race, not \
             at storage time.",
            stored.len(),
            stored
                .iter()
                .map(|fp| fp.sender_ephemeral_pub.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            vw.proof_store.proofs.len(),
            0,
            "HMSEC-SA04-10 VIOLATION (junk evidence): a persistent soft proof \
             was fabricated from unbound third-party fingerprints - the \
             fallback attribution even names the victim-side ephemeral key as \
             offender, permanently polluting the forensic workflow."
        );
        assert!(
            vw.list_conflicts().is_empty(),
            "HMSEC-SA04-10 VIOLATION: unbound ingress data produced persistent \
             conflict records against the victim."
        );
    }
}
