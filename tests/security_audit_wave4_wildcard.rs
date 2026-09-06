//! # tests/security_audit_wave4_wildcard.rs
//!
//! Security Audit Wave 4 — Module 00 (Wildcard / Cross-Cutting): signing-request
//! ingestion path, load-time rebuild divergence, phantom activation and
//! seal-discipline holdouts.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. Tests turn green only after the
//! corresponding remediation has been implemented.
//!
//! ## Finding Summary
//!
//! | Finding-ID     | Hypothesis  | Severity | Target                                                        |
//! |----------------|-------------|----------|---------------------------------------------------------------|
//! | AUDIT-W4-WC-001| WH4-00-001  | Critical | app_signature_handler.rs (~142-158) + lifecycle.rs (~250) + maintenance.rs (~213) |
//! | AUDIT-W4-WC-002| WH4-00-002  | High     | conflict_manager.rs (~268-276) vs wallet/maintenance.rs (~213-244) |
//! | AUDIT-W4-WC-003| WH4-00-003  | High     | signature_handler.rs (~174-239) + transaction_handler.rs (~801-803) |
//! | AUDIT-W4-WC-004| WH4-00-004  | Medium   | data_encryption.rs (~50-52, ~76-78) + app_signature_handler.rs (swallowed seal updates) |

use std::collections::HashMap;

use human_money_core::app_service::{AppService, ProfileInfo};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::secure_container::{ContainerConfig, PayloadType, PrivacyMode};
use human_money_core::models::signature::DetachedSignature;
use human_money_core::models::voucher::{Transaction, TrapData, ValueDefinition, Voucher, VoucherSignature};
use human_money_core::services::crypto_utils::{
    derive_ephemeral_key_pair, get_hash, get_prefix_from_user_id,
};
use human_money_core::services::mnemonic::MnemonicLanguage;
use human_money_core::services::secure_container_manager::create_secure_container;
use human_money_core::services::signature_manager::complete_and_sign_detached_signature;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::test_utils::{
    create_voucher_for_manipulation, generate_signed_standard_toml, resign_transaction_ext,
    setup_service_with_profile, ACTORS, FREETALER_STANDARD,
};
use human_money_core::wallet::instance::VoucherStatus;
use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
use human_money_core::{UserIdentity, VoucherInstance};
use tempfile::tempdir;

const PASSWORD: &str = "wave4-wildcard-password-123";
const RECOVERY_PASSWORD: &str = "wave4-wildcard-recovery-pw-456";
const INSTANCE_ID: &str = "test-id";
const FREETALER_TOML_PATH: &str = "voucher_standards/freetaler_v1/standard.toml";

/// Attacker-chosen ds_tag for the WH4-00-002 poison transaction.
const ATTACKER_DS_TAG_002: &str = "W4WC002ATTACKERDSTAG0000000000000000000000";

/// Lexicographically-greatest RFC3339-invalid timestamp for WH4-00-003.
/// Chain validation compares t_time ONLY lexicographically (chain.rs), so
/// this value authenticates cleanly everywhere except at spend time, where
/// `DateTime::parse_from_rfc3339(...).unwrap()` panics on it.
const PHANTOM_T_TIME: &str = "zzzz";

// =============================================================================
// Shared helpers
// =============================================================================

/// Mints a fully valid, honestly signed voucher owned by `attacker`
/// (creator signature + init tx; FreeTaler standard allows 0..3 additional
/// signatures, so a creator-only chain validates clean => Active).
fn attacker_minted_voucher(attacker: &UserIdentity) -> Voucher {
    create_voucher_for_manipulation(
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(attacker.user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100.00".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        },
        &FREETALER_STANDARD.0,
        &FREETALER_STANDARD.1,
        &attacker.signing_key,
    )
}

/// Attacker wraps an arbitrary voucher as a VoucherForSigning request
/// addressed to the victim (the exact transport used by the real workflow).
fn wrap_voucher_for_signing(attacker: &UserIdentity, victim_did: &str, voucher: &Voucher) -> Vec<u8> {
    let payload = to_canonical_json(voucher).expect("canonical json of voucher");
    let container = create_secure_container(
        attacker,
        ContainerConfig::TargetDid(victim_did.to_string(), PrivacyMode::TrialDecryption),
        payload.as_bytes(),
        PayloadType::VoucherForSigning,
    )
    .expect("container creation for signing request");
    serde_json::to_vec(&container).expect("serialize container")
}

/// Full remote-ingestion precondition: victim previews the request and then
/// calls `create_detached_signature_response_bundle`, which persists the
/// COMPLETELY UNVALIDATED remote voucher as `Endorsed`.
fn endorse_via_signing_workflow(
    service_victim: &mut AppService,
    victim_did: &str,
    attacker: &UserIdentity,
    voucher: &Voucher,
) {
    let bytes = wrap_voucher_for_signing(attacker, victim_did, voucher);
    let preview = service_victim
        .open_voucher_signing_request(&bytes, None)
        .expect("signing request must open for preview");
    assert_eq!(preview.voucher_id, voucher.voucher_id, "preview mismatch");

    let response = service_victim.create_detached_signature_response_bundle(
        voucher,
        "guarantor",
        false,
        ContainerConfig::TargetDid(attacker.user_id.clone(), PrivacyMode::TrialDecryption),
        Some(PASSWORD),
    );
    // Precondition documenting the unvalidated second ingestion path:
    // nothing rejects the remote voucher before it enters voucher_store.
    assert!(
        response.is_ok(),
        "test precondition violated: signing-response workflow rejected the \
         remote voucher ({:?})",
        response.err()
    );
}

/// Finds the wallet instance carrying the given global voucher id.
fn find_instance_by_voucher_id<'a>(service: &'a AppService, voucher_id: &str) -> &'a VoucherInstance {
    service
        .get_wallet_for_test()
        .expect("wallet must be unlocked for instance lookup")
        .voucher_store
        .vouchers
        .values()
        .find(|i| i.voucher.voucher_id == voucher_id)
        .expect("instance with given voucher_id present in wallet")
}

/// init t_time plus one day (lexicographic-safe ISO timestamps).
fn rfc3339_plus_one_day(ts: &str) -> String {
    let dt = chrono::DateTime::parse_from_rfc3339(ts).expect("parse init t_time");
    (dt.with_timezone(&chrono::Utc) + chrono::Duration::days(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

// =============================================================================
// FINDING AUDIT-W4-WC-001 (Hypothesis WH4-00-001)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-W4-WC-001
// Severity:         CRITICAL
// CWE-Classification: CWE-754 (Improper Check of Exceptional Conditions) /
//                   CWE-20 (Improper Input Validation)
// Target Location:  src/app_service/app_signature_handler.rs:142-158
//                   (unvalidated store of remote voucher),
//                   src/wallet/lifecycle.rs:250 (`rebuild_derived_stores()?`
//                   inside Wallet::load), src/wallet/maintenance.rs:213-218
//                   (iteration over ALL instances incl. Endorsed without
//                   status filter or per-instance error containment)
//
// ## Threat Model & Exploitation
// An attacker sends the victim a VoucherForSigning SecureContainer whose
// embedded voucher carries hostile scalar fields (valid_until = "not-a-date").
// The victim opens the preview (Ok — no field validation) and calls
// `create_detached_signature_response_bundle`. The function signs the metadata
// and persists the completely unvalidated voucher into `voucher_store` with
// status Endorsed. On EVERY subsequent login (and mnemonic recovery, same
// Wallet::load), rebuild_derived_stores iterates all instances and hard-fails
// on the first malformed field (`Failed to parse valid_until`), propagated via
// `?` — one remote interaction permanently bricks the whole wallet through the
// public API surface.
//
// ## Impact Analysis
// Permanent, unrecoverable-through-API login lockout (availability loss of ALL
// funds), contradicting the documented invariant that a single poisoned voucher
// must degrade only that instance, never strand the whole wallet.
//
// ## Root Cause
// The signing workflow is a second ingestion path with zero input validation,
// and `Wallet::load` turns any per-instance rebuild error into a total load
// failure.
//
// ## Remediation Strategy
// (a) Validate remote vouchers (or at least scalar parseability) BEFORE storing
//     them from the signing workflow; (b) contain per-instance rebuild errors:
//     quarantine the offending instance instead of failing the whole load.
//
// ## Test Semantics (Fail-First)
// Asserts the secure invariant: after endorsing a poisoned voucher, both
// password login AND mnemonic recovery MUST still succeed. On unpatched code
// both fail with CryptoError("... Failed to parse valid_until") -> RED proof.
// =============================================================================
#[test]
fn w4_wc_001_poisoned_endorsed_voucher_must_not_brick_login() {
    let dir = tempdir().expect("tempdir");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.bob, "W4-WC001-Victim", PASSWORD);
    // NOTE: containers must address the PERSISTED profile identity
    // (production KDF), not a possibly fast-derived actor identity.
    let victim_did = service.get_user_id().expect("victim user id");

    let mut hostile = attacker_minted_voucher(&ACTORS.alice.identity);
    hostile.valid_until = "not-a-date".to_string();

    endorse_via_signing_workflow(&mut service, &victim_did, &ACTORS.alice.identity, &hostile);

    // Precondition: the poison is stored as Endorsed audit log.
    let inst = find_instance_by_voucher_id(&service, &hostile.voucher_id);
    assert!(
        matches!(inst.status, VoucherStatus::Endorsed { .. }),
        "test precondition violated: remote voucher not stored as Endorsed"
    );

    // Simulate app restart ("drop wallet, fresh AppService").
    drop(service);
    let mut relaunched = AppService::new(dir.path()).expect("fresh AppService");

    // SECURE INVARIANT: a stored Endorsed voucher must never brick login.
    let login = relaunched.login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string());
    assert!(
        login.is_ok(),
        "AUDIT-W4-WC-001 VIOLATION: a single unvalidated Endorsed voucher \
         bricks the whole wallet login. Error was: {:?}. One remote signing \
         request must never strand all funds behind a permanent lockout.",
        login.err()
    );
}

/// Same ingestion vector, recovery leg: `recover_wallet_and_set_new_password`
/// uses the identical `Wallet::load` -> must not be bricked either.
/// Victim is ACTORS.alice because recovery derives keys production-style from
/// the mnemonic (slow derivation), matching the persisted profile identity.
#[test]
fn w4_wc_001_poisoned_endorsed_voucher_must_not_brick_mnemonic_recovery() {
    let dir = tempdir().expect("tempdir");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.alice, "W4-WC001-Recover", PASSWORD);
    let victim_did = service.get_user_id().expect("victim user id");

    let mut hostile = attacker_minted_voucher(&ACTORS.bob.identity);
    hostile.valid_until = "not-a-date".to_string();

    endorse_via_signing_workflow(&mut service, &victim_did, &ACTORS.bob.identity, &hostile);

    drop(service);
    let mut relaunched = AppService::new(dir.path()).expect("fresh AppService");

    // SECURE INVARIANT: mnemonic recovery must survive the poisoned voucher.
    let recovered = relaunched.recover_wallet_and_set_new_password(
        &profile.folder_name,
        &ACTORS.alice.mnemonic,
        ACTORS.alice.passphrase,
        RECOVERY_PASSWORD,
        MnemonicLanguage::English,
        INSTANCE_ID.to_string(),
    );
    assert!(
        recovered.is_ok(),
        "AUDIT-W4-WC-001 VIOLATION: a single unvalidated Endorsed voucher \
         bricks mnemonic recovery. Error was: {:?}",
        recovered.err()
    );

    // Secondary pin: after remediation, login with the new password must work.
    let mut s2 = AppService::new(dir.path()).expect("second AppService");
    let login_after_recovery = s2.login(
        &profile.folder_name,
        RECOVERY_PASSWORD,
        false,
        INSTANCE_ID.to_string(),
    );
    assert!(
        login_after_recovery.is_ok(),
        "wallet must be fully usable after successful recovery ({:?})",
        login_after_recovery.err()
    );
}

// =============================================================================
// FINDING AUDIT-W4-WC-002 (Hypothesis WH4-00-002)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-W4-WC-002
// Severity:         HIGH
// CWE-Classification: CWE-460 (Inconsistent Parsing/Derivation of Same Data)
// Target Location:  src/services/conflict_manager.rs:268-306
//                   (`scan_and_rebuild_fingerprints` SKIPS Endorsed) versus
//                   src/wallet/maintenance.rs:213-244
//                   (`rebuild_derived_stores` iterates ALL instances with NO
//                   Endorsed filter)
//
// ## Threat Model & Exploitation
// Same ingestion vector as AUDIT-W4-WC-001 but with a fully well-formed
// honestly-signed attacker chain whose crafted spend transaction claims
// `sender_id = Some(victim_did)` and carries an attacker-chosen ds_tag. At
// signing time nothing happens (receive-time scan excludes Endorsed: endorsed
// vouchers "must not contribute to double-spend detection"). At the NEXT
// login, the load-time rebuild classifies those fingerprints as OWN
// (`is_own_transaction`) and inserts them into own_fingerprints.history under
// attacker-chosen ds_tags with VIP-negative chain depths.
//
// ## Impact Analysis
// (1) The victim's proactive self-double-spend guard context and forensic
// history contain phantom "own spends"; (2) export_own_fingerprints gossips
// attacker-authored fingerprints under the victim's custody; (3) the next
// save+seal makes the pollution the sealed truth.
//
// ## Root Cause
// Two contradictory derivations over the same store: the documented Endorsed-
// exclusion invariant exists only in scan_and_rebuild_fingerprints, not in
// rebuild_derived_stores (WH3-00-903 bug class on the status dimension).
//
// ## Remediation Strategy
// Apply the identical Endorsed-status filter (and per-instance error
// containment) in rebuild_derived_stores so both derivations agree.
//
// ## Test Semantics (Fail-First)
// Control assertion pins the receive-time behavior (no pollution right after
// endorsing). Secure invariant after re-login: own_fingerprints.history must
// NOT contain the attacker's ds_tag. On unpatched code the entry IS present
// -> RED proof.
// =============================================================================
#[test]
fn w4_wc_002_endorsed_voucher_must_not_pollute_own_fingerprints_at_load_rebuild() {
    let dir = tempdir().expect("tempdir");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.victim, "W4-WC002-Victim", PASSWORD);
    let victim_did = service.get_user_id().expect("victim user id");

    let attacker = &ACTORS.charlie.identity;

    // Well-formed voucher + crafted spend tx claiming VICTIM authorship.
    let mut hostile = attacker_minted_voucher(attacker);
    let next_time = rfc3339_plus_one_day(&hostile.transactions[0].t_time);

    let eph_seed: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    let eph_key = ed25519_dalek::SigningKey::from_bytes(&eph_seed);
    let tx2 = Transaction {
        t_id: String::new(),
        t_type: "transfer".to_string(),
        t_time: next_time,
        prev_hash: get_hash(to_canonical_json(&hostile.transactions[0]).expect("canonical init")),
        sender_id: Some(victim_did.clone()),
        recipient_id: attacker.user_id.clone(),
        amount: "1.00".to_string(),
        sender_remaining_amount: None,
        sender_identity_signature: None,
        receiver_ephemeral_pub_hash: None,
        sender_ephemeral_pub: Some(bs58::encode(eph_key.verifying_key().to_bytes()).into_string()),
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: Some(TrapData {
            ds_tag: ATTACKER_DS_TAG_002.to_string(),
            trap_r: bs58::encode([9u8; 32]).into_string(),
            trap_s: bs58::encode([10u8; 32]).into_string(),
        }),
        layer2_signature: None,
        deletable_at: Some(hostile.valid_until.clone()),
    };
    // Honestly (re-)signed over canonical bytes incl. the hostile claim.
    let signed_tx2 = resign_transaction_ext(tx2, &attacker.signing_key, "", Some(&eph_key));
    hostile.transactions.push(signed_tx2);

    endorse_via_signing_workflow(&mut service, &victim_did, attacker, &hostile);

    // CONTROL (receive-time scan): Endorsed vouchers are excluded pre-reload.
    {
        let wallet = service.get_wallet_for_test().expect("unlocked");
        assert!(
            !wallet.own_fingerprints.history.contains_key(ATTACKER_DS_TAG_002),
            "control violated: Endorsed voucher polluted own history already \
             before reload — isolate divergence to the load-time rebuild"
        );
    }

    // Trigger load-time rebuild via logout/login cycle.
    service.logout();
    service
        .login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string())
        .expect("login itself must succeed for well-formed voucher");

    // SECURE INVARIANT: Endorsed vouchers must not contribute to
    // own_fingerprints at the load-time rebuild either.
    let polluted = service
        .get_wallet_for_test()
        .expect("unlocked after login")
        .own_fingerprints
        .history
        .keys()
        .any(|k| k == ATTACKER_DS_TAG_002);
    assert!(
        !polluted,
        "AUDIT-W4-WC-002 VIOLATION: the load-time rebuild classified \
         attacker-authored transactions of an Endorsed voucher as OWN spends \
         (ds_tag '{ATTACKER_DS_TAG_002}' present in own_fingerprints.history). \
         The two rebuilds diverge on the Endorsed-status dimension."
    );
}

// =============================================================================
// FINDING AUDIT-W4-WC-003 (Hypothesis WH4-00-003) — Stage A: status flip
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-W4-WC-003
// Severity:         HIGH
// CWE-Classification: CWE-284 (Improper Access Control on state transition)
// Target Location:  src/wallet/signature_handler.rs:174-241 (instance matched
//                   by voucher_id across ALL instances incl. Endorsed; no
//                   ownership/recipient gate),
//                   src/app_service/app_signature_handler.rs:288-291
//                   (validation Ok => VoucherStatus::Active)
//
// ## Threat Model & Exploitation
// Stage 1: an arbitrary self-created, FULLY WELL-FORMED voucher E (valid
// self-signed V3 chain, parseable fields) is stored in the victim's wallet as
// Endorsed via the signing-request path (zero validation there). Stage 2: the
// attacker returns an honestly-signed DetachedSignature for E.voucher_id;
// process_and_attach_signature matches E purely by voucher_id string equality
// (it never checks that the local instance was ever transferred to / owned by
// the victim), attaches, and the sibling validation marks E Active.
//
// ## Impact Analysis
// The wallet displays a phantom ACTIVE voucher the victim never received:
// balance aggregation and asset-class listings include attacker-controlled
// value, and downstream state transitions treat the attacker's voucher as the
// victim's own holdings. Broken invariant: "Status transitions to Active
// require ownership evidence (recipient identity or stealth-key match)".
//
// ## Root Cause
// Authorization for the Endorsed -> Active transition is voucher_id equality;
// there is no binding between the local instance and a genuine reception event.
//
// ## Remediation Strategy
// Restrict attach matching / activation to instances that carry ownership
// evidence (received via transaction bundle with recipient identity or
// stealth-key match); treat Endorsed audit copies as non-transitionable.
//
// ## Test Semantics (Fail-First)
// Asserts the secure invariant: after attaching an honestly-signed detached
// signature to a never-received Endorsed voucher, its status MUST NOT be
// Active. On unpatched code validation succeeds and flips it to Active ->
// RED proof.
//
// NOTE ON THE ORIGINAL PANIC LEG (CWE-617, t_time="zzzz"): REFUTED during
// testing. An RFC3339-invalid t_time cannot reach Active on this path:
// attach-time validation calls verify_transaction_integrity_and_signature,
// whose HMC_TX_AUTH_V3 digest requires encrypt_transaction_timestamp, which
// parses t_time strictly (conflict_manager.rs:~907) => fatal error =>
// Quarantined. See w4_wc_003_*_garbage_ttime_* regression guards below.
// =============================================================================
fn stage1_store_phantom_as_endorsed(
    t_time_override: Option<&str>,
) -> (
    AppService,
    ProfileInfo,
    tempfile::TempDir,
    Voucher,
    String,
) {
    let dir = tempdir().expect("tempdir");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.david, "W4-WC003-Victim", PASSWORD);
    let victim_did = service.get_user_id().expect("victim user id");

    // Colluding attackers with DISTINCT identities: bob mints the voucher,
    // alice later supplies the detached signature (identical identities would
    // trip DuplicateIdentityDetected during validation instead of exercising
    // the activation path under test).
    let minter = &ACTORS.bob.identity;

    // Fully honest voucher; optionally poison ONLY the last-tx t_time,
    // re-signed honestly over the canonical bytes containing it.
    let mut phantom = attacker_minted_voucher(minter);
    if let Some(poisoned) = t_time_override {
        let nonce_bytes = bs58::decode(&phantom.voucher_nonce)
            .into_vec()
            .expect("decode voucher_nonce");
        let prefix = get_prefix_from_user_id(&minter.user_id);
        let (genesis_secret, _) =
            derive_ephemeral_key_pair(&minter.signing_key, &nonce_bytes, "genesis", prefix)
                .expect("derive genesis key");
        let mut tx = phantom.transactions[0].clone();
        tx.t_time = poisoned.to_string();
        phantom.transactions[0] =
            resign_transaction_ext(tx, &minter.signing_key, "", Some(&genesis_secret));
    }

    endorse_via_signing_workflow(&mut service, &victim_did, minter, &phantom);

    (service, profile, dir, phantom, victim_did)
}

/// Stage 2: attacker returns an honestly-signed DetachedSignature for the
/// phantom voucher. Returns the raw command result (Ok(local_id) on clean
/// validation, Err with quarantine notice on fatal validation).
fn stage2_attach_attacker_signature_raw(
    service: &mut AppService,
    victim_did: &str,
    phantom: &Voucher,
) -> Result<String, human_money_core::app_service::AppFacadeError> {
    let attacker = &ACTORS.alice.identity;
    let sig_data = DetachedSignature::Signature(VoucherSignature {
        voucher_id: phantom.voucher_id.clone(),
        signer_id: attacker.user_id.clone(),
        role: "guarantor".to_string(),
        ..Default::default()
    });
    let init_t_id = &phantom.transactions[0].t_id;
    let signed_sig = complete_and_sign_detached_signature(
        sig_data,
        attacker,
        None,
        &phantom.voucher_id,
        init_t_id,
    )
    .expect("honest detached signature creation");

    let payload = to_canonical_json(&signed_sig).expect("canonical signature json");
    let container = create_secure_container(
        attacker,
        ContainerConfig::TargetDid(victim_did.to_string(), PrivacyMode::TrialDecryption),
        payload.as_bytes(),
        PayloadType::DetachedSignature,
    )
    .expect("detached signature container");
    let bytes = serde_json::to_vec(&container).expect("serialize container");

    service.process_and_attach_signature(
        &bytes,
        &generate_signed_standard_toml(FREETALER_TOML_PATH),
        None,
        Some(PASSWORD),
    )
}

#[test]
fn w4_wc_003_attach_must_not_activate_never_received_voucher() {
    let (mut service, _profile, _dir, phantom, victim_did) =
        stage1_store_phantom_as_endorsed(None);

    // Precondition: stored copy is Endorsed before the signature arrives.
    let inst = find_instance_by_voucher_id(&service, &phantom.voucher_id);
    assert!(
        matches!(inst.status, VoucherStatus::Endorsed { .. }),
        "test precondition violated: phantom voucher not stored as Endorsed"
    );

    let attach = stage2_attach_attacker_signature_raw(&mut service, &victim_did, &phantom);
    let local_id = attach.expect(
        "attach precondition: well-formed phantom must pass attach-time \
         validation (otherwise the flip-under-test cannot occur)",
    );

    // SECURE INVARIANT: a voucher the victim NEVER RECEIVED (no ownership
    // evidence) must NOT become Active via the attach path.
    let inst = service
        .get_wallet_for_test()
        .expect("unlocked")
        .get_voucher_instance(&local_id)
        .expect("attached instance present");
    assert!(
        !matches!(inst.status, VoucherStatus::Active),
        "AUDIT-W4-WC-003 VIOLATION: attaching an honestly-signed detached \
         signature flipped a never-received Endorsed voucher to Active \
         (status: {:?}). Authorization happened purely on voucher_id string \
         equality, bypassing all ownership gates.",
        inst.status
    );
}

// -----------------------------------------------------------------------------
// AUDIT-W4-WC-003 — Regression guards for the REFUTED panic leg (CWE-617).
//
// Original hypothesis: a signing-request voucher with RFC3339-invalid last-tx
// t_time ("zzzz") flips to Active and a spend attempt then panics on
// `DateTime::parse_from_rfc3339(t_time).unwrap()` inside the future-lock check
// (transaction_handler.rs:~803).
//
// REFUTATION: the flip is impossible — attach-time validation runs
// verify_transaction_integrity_and_signature, whose HMC_TX_AUTH_V3 digest
// requires encrypt_transaction_timestamp, which strictly parses t_time
// (conflict_manager.rs:~907). Fatal error => Quarantined (never Active) => the
// spend aborts with VoucherNotActive BEFORE the future-lock parse. Both guards
// below PIN this existing secure behavior and MUST STAY GREEN.
// -----------------------------------------------------------------------------
#[test]
fn w4_wc_003_garbage_ttime_voucher_must_never_become_active_regression_guard() {
    let (mut service, _profile, _dir, phantom, victim_did) =
        stage1_store_phantom_as_endorsed(Some(PHANTOM_T_TIME));

    let attach = stage2_attach_attacker_signature_raw(&mut service, &victim_did, &phantom);
    assert!(
        attach.is_err(),
        "attach with RFC3339-invalid t_time must report the fatal validation \
         error, got Ok({:?})",
        attach.ok()
    );

    let inst = find_instance_by_voucher_id(&service, &phantom.voucher_id);
    assert!(
        !matches!(inst.status, VoucherStatus::Active),
        "REGRESSION: RFC3339-invalid t_time reached Active status ({:?}); the \
         attach-path t_time parse gate (conflict_manager::\
         encrypt_transaction_timestamp) has been weakened.",
        inst.status
    );
}

#[test]
fn w4_wc_003_spending_garbage_ttime_voucher_must_fail_gracefully_regression_guard() {
    let (mut service, _profile, _dir, phantom, victim_did) =
        stage1_store_phantom_as_endorsed(Some(PHANTOM_T_TIME));
    let _ = stage2_attach_attacker_signature_raw(&mut service, &victim_did, &phantom);

    // Attempt to spend the (non-Active) phantom: must return a GRACEFUL Err,
    // never a panic (the historic unwrap site transaction_handler.rs:~803 must
    // stay unreachable for every status/field combination).
    let request = MultiTransferRequest {
        recipient_id: ACTORS.charlie.identity.user_id.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: service
                .get_wallet_for_test()
                .expect("unlocked")
                .voucher_store
                .vouchers
                .values()
                .find(|i| i.voucher.voucher_id == phantom.voucher_id)
                .expect("phantom present")
                .local_instance_id
                .clone(),
            amount_to_send: "0.01".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        generate_signed_standard_toml(FREETALER_TOML_PATH),
    );

    let outcome = service.create_transfer_bundle(request, &standards_toml, None, Some(PASSWORD));
    assert!(
        outcome.is_err(),
        "REGRESSION: spending a voucher with RFC3339-invalid t_time did not \
         return gracefully; the future-lock unwrap became reachable again."
    );
}

// =============================================================================
// FINDING AUDIT-W4-WC-004 (Hypothesis WH4-00-004)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-W4-WC-004
// Severity:         MEDIUM
// CWE-Classification: CWE-755 (Improper Handling of Exceptional Conditions) /
//                   CWE-667 (Improper Locking discipline: persisting commands
//                   outside the Wave-2 transactional contract)
// Target Location:  src/app_service/data_encryption.rs:50-52 and ~76-78
//                   (`let _ = self.update_seal_after_state_change(...)` after
//                   save_arbitrary_data); same swallowed pattern after
//                   temp_wallet.save in app_signature_handler.rs (~197-200,
//                   ~358-361, ~476-479); contrast hardened orchestrator
//                   src/app_service/mod.rs :: with_transactional_mut
//
// ## Threat Model & Exploitation
// These persisting commands write data files first and advance seal+integrity
// afterwards while IGNORING the seal-phase result — the exact partial-commit
// window AUDIT-00-WILDCARD-01 eliminated for with_transactional_mut. Under a
// transient I/O fault in the seal phase, the command reports Ok while the
// integrity record no longer covers the new file hash (get_all_item_hashes
// covers ALL non-hidden files incl. generic_* data). From then on EVERY
// cleanup_on_login login evaluates integrity as compromised and silently
// disables storage cleanup forever, and check_integrity reports tampering
// where none exists.
//
// ## Impact Analysis
// Persistent availability/false-alarm degradation requiring manual
// repair_integrity; violates the Wave-2 commit contract
// "Ok => data files, seal AND integrity record mutually consistent".
//
// ## Root Cause
// Seal-phase failures are swallowed (`let _ =`) after the data commit instead
// of being surfaced as Err (or compensated) like the hardened orchestrator.
//
// ## Remediation Strategy
// Route these commands through the transactional discipline (or at minimum
// propagate the seal-phase error as Err after compensating/rolling forward the
// integrity record), restoring "Err => zero inconsistent writes".
//
// ## Test Semantics (Fail-First)
// Inject a seal-write failure (directory shadowing `<profile>/seal.enc.tmp`)
// around save_encrypted_data. Secure invariant (disjunctive contract): EITHER
// the command reports Err (honest failure) OR the subsequent integrity check
// stays Valid. On unpatched code the command returns Ok while the stale
// integrity record misses the new generic file -> check_integrity reports
// UnknownItems -> RED proof.
// =============================================================================
#[test]
fn w4_wc_004_swallowed_seal_failure_in_persisting_commands_must_keep_integrity_consistent() {
    let dir = tempdir().expect("tempdir");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.test_user, "W4-WC004", PASSWORD);

    // Baseline cycle: transactional voucher creation established seal +
    // integrity record; a clean login/check must report Valid.
    service.logout();
    service
        .login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string())
        .expect("baseline login");
    let baseline = service.check_integrity(Some(PASSWORD)).expect("baseline check");
    assert!(
        matches!(baseline, human_money_core::models::storage_integrity::IntegrityReport::Valid),
        "test precondition violated: baseline integrity not Valid ({:?})",
        baseline
    );

    // --- FAULT INJECTION: block ONLY the seal temp-file write path ----------
    let seal_tmp_path = dir
        .path()
        .join(&profile.folder_name)
        .join("seal.enc.tmp");
    std::fs::create_dir_all(&seal_tmp_path).expect("shadow seal temp path");

    // Persisting command OUTSIDE the transactional discipline.
    let outcome = service.save_encrypted_data("wave4_audit_settings", b"top-secret", Some(PASSWORD));
    let reported_ok = outcome.is_ok();

    std::fs::remove_dir(&seal_tmp_path).expect("remove seal shadow");

    // Fresh login WITH cleanup-on-login (the degraded path under attack).
    service.logout();
    service
        .login(&profile.folder_name, PASSWORD, true, INSTANCE_ID.to_string())
        .expect("login must remain possible (data files untouched)");

    // SECURE INVARIANT (disjunctive commit contract):
    // Ok => data file, seal AND integrity record mutually consistent.
    let report = service.check_integrity(Some(PASSWORD)).expect("post-fault check");
    assert!(
        matches!(
            report,
            human_money_core::models::storage_integrity::IntegrityReport::Valid
        ) || !reported_ok,
        "AUDIT-W4-WC-004 VIOLATION: persisting command returned Ok while the \
         seal/integrity phase failed silently — integrity record no longer \
         covers the new file ({:?}). Every subsequent cleanup_on_login will be \
         disabled and check_integrity reports tampering where none exists.",
        report
    );
}
