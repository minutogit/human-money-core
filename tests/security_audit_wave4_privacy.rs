//! # Security Audit Finding: Unsanitized `TransactionBundle.notes` persisted
//! unbounded into the local bundle metadata store
//!
//! - Finding-ID: AUDIT-W4-PRIV-701 (Wave 4, Module 06, hypothesis WH4-06-701)
//! - Severity: MEDIUM
//! - CWE-Classification: CWE-20 (Improper Input Validation) / CWE-770
//!   (Allocation of Resources Without Limits) / CWE-1164 (Irrelevant Code:
//!   unverified metadata propagated into trusted persistent context)
//! - Target Location: src/wallet/transaction_handler.rs:556-559 (receive-side
//!   ingestion into `BundleMetadataStore.history` via
//!   `TransactionBundle::to_header`) and src/models/profile.rs:72,125
//!   (verbatim `notes` clone in `to_header`)
//!
//! ## Threat Model & Exploitation
//! A remote sender controls `TransactionBundle.notes` in full: arbitrary
//! length and arbitrary Unicode, including Cc control characters and
//! invisible/bidi-override format characters (U+202E RLO, U+200D ZWJ,
//! U+0000 NUL). After successful cryptographic verification the receiver
//! clones the field VERBATIM into the persistent `BundleMetadataStore.history`
//! (`to_header` -> `history.insert`, transaction_handler.rs:556-559). This is
//! exactly the ingestion class already remediated by HMSEC-SA06-10 for the
//! sibling attacker-controlled field `sender_profile_name`
//! (`sanitize_display_name`, bounded to 64 chars, control/format stripped):
//! the sanitizer is applied to only ONE of the TWO attacker-controlled
//! string fields on the very same ingestion path.
//!
//! ## Impact Analysis
//! An attacker plants megabytes of poisoned per-bundle metadata into every
//! wallet that receives their bundles (storage exhaustion on offline
//! devices; the history grows permanently) and injects rendering-
//! manipulating characters for any future UI displaying bundle history.
//! Broken invariant: "Every attacker-controlled display/metadata field
//! crossing network ingestion is sanitized and bounded before persistent
//! storage."
//!
//! ## Root Cause
//! Asymmetric sanitization: `sanitize_display_name` is applied to
//! `bundle.sender_profile_name` only (transaction_handler.rs:156);
//! `bundle.notes` reaches `to_header` (profile.rs:125 verbatim clone)
//! and the persistent history unfiltered and unbounded.
//!
//! ## Remediation Strategy
//! Sanitize at network INGESTION only (parity with SA06-10): strip control
//! (Cc) and invisible-format (Cf) characters and bound the length before
//! the received header enters `bundle_meta_store.history`. The LOCAL
//! composition path (a user's own outgoing notes,
//! transaction_handler.rs:96-98) must stay unrestricted — the constraint
//! is asserted as a design guard below.
//!
//! ## Test Semantics (Fail-First)
//! Mallory sends a legitimately signed bundle whose notes carry a
//! ~100k-character bidi/control-poisoned string. Charlie processes it and
//! the test reads `charlie_wallet.bundle_meta_store.history[&bundle_id].notes`
//! (public API surface). SOLL: the stored notes are bounded (<= 64 chars,
//! parity with SA06-10's `MAX_COUNTERPARTY_NAME_CHARS`; a dedicated,
//! consciously chosen NOTES bound may substitute this constant) AND free of
//! control/invisible/bidi characters. On unpatched code the raw 100,004-char
//! poisoned string is persisted -> both invariant assertions FAIL, proving
//! the vulnerability. Fully deterministic (char count / char classes),
//! no wall-clock dependency.

use human_money_core::models::voucher_standard_definition::{
    PrivacyMode, VoucherStandardDefinition,
};
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
use human_money_core::wallet::Wallet;
use std::collections::HashMap;

/// SOLL bound for remotely supplied notes persisted into the local metadata
/// history. Parity with HMSEC-SA06-10 (`MAX_COUNTERPARTY_NAME_CHARS = 64`).
/// If remediation introduces a dedicated NOTES bound instead, this constant
/// must be updated to that documented value (conscious decision point, see
/// docblock "Remediation Strategy").
const MAX_RECEIVED_NOTES_CHARS_SOLL: usize = 64;

/// Configures the FreeTaler standard with a specific privacy mode and returns
/// it together with a standards map ready for transfer calls.
fn setup_standard(
    mode: PrivacyMode,
) -> (
    VoucherStandardDefinition,
    HashMap<String, VoucherStandardDefinition>,
) {
    let mut standard_def = FREETALER_STANDARD.0.clone();
    standard_def.immutable.features.privacy_mode = mode;
    let mut standards_map = HashMap::new();
    standards_map.insert(
        standard_def.immutable.identity.uuid.clone(),
        standard_def.clone(),
    );
    (standard_def, standards_map)
}

/// Creates an in-memory wallet for `identity` holding one fresh voucher of
/// `amount` units under `standard_def` and returns `(wallet, source_instance_id)`.
fn funded_wallet(
    identity: &human_money_core::models::profile::UserIdentity,
    amount: &str,
    standard_def: &VoucherStandardDefinition,
) -> (Wallet, String) {
    let mut wallet = test_utils::setup_in_memory_wallet(identity);
    let local_id =
        test_utils::add_voucher_to_wallet(&mut wallet, identity, amount, standard_def, true)
            .expect("voucher creation failed");
    (wallet, local_id)
}

/// True for Unicode format/invisible characters commonly abused for rendering
/// manipulation (mirrors the SA06-10 classification in
/// src/wallet/transaction_handler.rs::is_invisible_format_char).
fn is_invisible_format_char(c: char) -> bool {
    matches!(c as u32,
        0x200B..=0x200F       // ZWSP..RLM incl. ZWJ
        | 0x202A..=0x202E     // bidi embedding/overrides (incl. U+202E)
        | 0x2060..=0x206F     // word joiner & invisible operators
        | 0xFEFF              // BOM / zero-width no-break space
    )
}

// =============================================================================
// FINDING AUDIT-W4-PRIV-701 (WH4-06-701)
// -----------------------------------------------------------------------------
// Finding-ID:    AUDIT-W4-PRIV-701
// Severity:      Medium
// CWE:           CWE-20 / CWE-770 / CWE-1164
// Target:        src/wallet/transaction_handler.rs:556-559 +
//                src/models/profile.rs:72,125 (to_header notes verbatim clone)
// Test Semantics: Sender Mallory transmits a validly signed bundle with a
//                 bidi/control-poisoned 100,004-char notes payload. After the
//                 victim processes the bundle, the RECEIVED header stored in
//                 `bundle_meta_store.history` must carry notes that are (1)
//                 bounded and (2) free of control/format characters.
//                 Additionally guarded: the sender's OWN history entry keeps
//                 the full locally composed notes (fix belongs to network
//                 ingestion, not local composition), and a legitimate short
//                 clean note passes through unchanged.
//                 FAILS on unpatched code (raw poisoned string persisted).
// =============================================================================
#[test]
fn wh4_06_701_received_notes_must_be_sanitized_and_bounded_in_bundle_history() {
    human_money_core::set_signature_bypass(true);
    let (standard_def, standards_map) = setup_standard(PrivacyMode::Flexible);

    let charlie = &ACTORS.charlie.identity;

    // Attacker Mallory sends a legitimately signed bundle whose ONLY payload
    // of interest is a poisoned free-text notes field.
    let mallory_kp =
        human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(Some(
            "wh4_701_mallory",
        ));
    let mallory = human_money_core::models::profile::UserIdentity {
        user_id: human_money_core::services::crypto::identity::create_user_id(
            &mallory_kp.0,
            Some("mallory"),
        )
        .unwrap(),
        signing_key: mallory_kp.1,
        public_key: mallory_kp.0,
    };
    let (mut mallory_wallet, source_id) = funded_wallet(&mallory, "100", &standard_def);

    // THE ATTACK: bidi override (U+202E), NUL, ZWJ (U+200D) and BEL poisoned
    // onto a 100k filler — arbitrary length + rendering manipulation.
    let poison_prefix: String = ['\u{202E}', '\u{0000}', '\u{200D}', '\u{0007}']
        .iter()
        .collect();
    let attacker_notes = format!("{}{}", poison_prefix, "A".repeat(100_000));

    let attack_bytes = mallory_wallet
        .execute_multi_transfer_and_bundle(
            &mallory,
            &standards_map,
            MultiTransferRequest {
                recipient_id: charlie.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: source_id,
                    amount_to_send: "50".to_string(),
                }],
                notes: Some(attacker_notes.clone()),
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("attack transfer failed")
        .bundle_bytes;

    // DESIGN GUARD (precondition, not the finding): the sender's OWN local
    // composition path is intentionally unrestricted — a remediation must
    // sanitize at network ingestion, not censor the local user's notes.
    let own_header = mallory_wallet
        .bundle_meta_store
        .history
        .values()
        .find(|h| h.direction == human_money_core::models::profile::TransactionDirection::Sent)
        .expect("sent header present");
    assert_eq!(
        own_header.notes.as_deref(),
        Some(attacker_notes.as_str()),
        "AUDIT-W4-PRIV-701 REGRESSION: local note composition must stay \
         unrestricted — sanitization belongs to the RECEIVE path only."
    );

    // Victim processes the bundle (non-cryptographic metadata must not break
    // delivery).
    let mut charlie_wallet = test_utils::setup_in_memory_wallet(charlie);
    let result = charlie_wallet
        .process_encrypted_transaction_bundle(charlie, &attack_bytes, None, &standards_map)
        .expect("attack bundle must process (notes are non-cryptographic metadata)");

    // Read the PERSISTENT metadata entry via the public wallet field.
    let stored_header = charlie_wallet
        .bundle_meta_store
        .history
        .get(&result.header.bundle_id)
        .expect("received bundle must be recorded in bundle_meta_store.history");

    // Precondition sanity: this really is the received entry from Mallory.
    assert_eq!(
        stored_header.sender_id,
        mallory.user_id,
        "Precondition broken: history entry does not belong to the attack bundle"
    );

    let stored_notes = stored_header.notes.as_deref().unwrap_or("");

    // SECURE INVARIANT 1: bounded length — no unbounded remote strings in the
    // persistent per-bundle metadata history (storage-exhaustion vector,
    // CWE-770).
    assert!(
        stored_notes.chars().count() <= MAX_RECEIVED_NOTES_CHARS_SOLL,
        "AUDIT-W4-PRIV-701 VIOLATION: attacker-controlled TransactionBundle.notes \
         entered the persistent bundle metadata history unbounded ({} chars, \
         limit {}).",
        stored_notes.chars().count(),
        MAX_RECEIVED_NOTES_CHARS_SOLL
    );

    // SECURE INVARIANT 2: no control / invisible / direction-manipulating
    // characters survive into persistent display metadata (CWE-20/CWE-1164).
    let has_forbidden_chars = stored_notes.chars().any(|c| {
        c.is_control() || is_invisible_format_char(c)
    });
    assert!(
        !has_forbidden_chars,
        "AUDIT-W4-PRIV-701 VIOLATION: stored bundle notes contain control/\
         invisible/bidi-manipulating characters straight from the wire."
    );

    // -------------------------------------------------------------------
    // REGRESSION GUARD: legitimate short clean notes pass through unchanged.
    // -------------------------------------------------------------------
    let (mut alice_wallet, alice_source) =
        funded_wallet(&ACTORS.alice.identity, "100", &standard_def);
    let legit_bytes = alice_wallet
        .execute_multi_transfer_and_bundle(
            &ACTORS.alice.identity,
            &standards_map,
            MultiTransferRequest {
                recipient_id: charlie.user_id.clone(),
                sources: vec![SourceTransfer {
                    local_instance_id: alice_source,
                    amount_to_send: "50".to_string(),
                }],
                notes: Some("Coffee for Alice".to_string()),
                sender_profile_name: None,
                use_privacy_mode: None,
            },
            None,
        )
        .expect("legit transfer failed")
        .bundle_bytes;
    let mut fresh_charlie = test_utils::setup_in_memory_wallet(charlie);
    let legit_result = fresh_charlie
        .process_encrypted_transaction_bundle(charlie, &legit_bytes, None, &standards_map)
        .expect("legit bundle must process");
    let legit_stored = fresh_charlie
        .bundle_meta_store
        .history
        .get(&legit_result.header.bundle_id)
        .expect("legit received bundle must be recorded");
    assert_eq!(
        legit_stored.notes.as_deref(),
        Some("Coffee for Alice"),
        "AUDIT-W4-PRIV-701 REGRESSION: legitimate short notes must survive \
         ingestion sanitization unchanged."
    );
}
