//! # Security Audit — Wave 4, Module 03: Voucher Standards & CEL Policy Engine
//!
//! Fail-First TDD proofs for the Wave-4 hypotheses WH4-03-101 / -102 / -103
//! against `src/services/dynamic_policy_engine.rs`,
//! `src/services/standard_manager.rs` and
//! `src/services/voucher_validation/identity.rs`.
//!
//! ## FAIL-FIRST TDD INVARIANT
//! Every test prefixed with `finding*` asserts the SECURE invariant
//! (**Soll-Verhalten**: fail-closed) and therefore **MUST FAIL on unpatched
//! code**, proving the vulnerability. Tests prefixed with `control*` pin down
//! already-correct behavior and MUST stay green after remediation.
//!
//! ===========================================================================
//! FINDING AUDIT-W4-CEL-101
//! ===========================================================================
//! Finding-ID:  AUDIT-W4-CEL-101 (Wave-4 hypothesis WH4-03-101)
//!             "Uncatchable Process Abort via CEL Message Literals (`T{...}`)
//!             Reaching the Interpreter's `todo!()`"
//! Severity:   CRITICAL
//! CWE-Classification: CWE-248 "Uncaught Exception" (primary);
//!             CWE-636 "Not Failing Securely (Failing Open)" (secondary);
//!             CWE-754 "Improper Check for Unusual or Exceptional Conditions"
//!             (secondary)
//! Target Location: src/services/dynamic_policy_engine.rs:597 (AST pre-check
//!             catch-all `_ => Ok(JsonValue::Null)` — `Expr::Struct` falls
//!             through WITHOUT visiting children); panic source:
//!             cel-interpreter 0.10.0 `src/objects.rs:706`
//!             (`Expr::Struct(_) => todo!("Support structs!")`); parser
//!             production cel-parser 0.10.1 `src/parser.rs:798-826`
//!             (`visit_CreateMessage` -> `Expr::Struct`).
//!
//! ## Threat Model & Exploitation
//! CEL rules originate from signed `[immutable]` zones but remain
//! attacker-influencable content (compromised issuer, socially engineered
//! `.standard`). The expression `Foo{a: 'x'} == Foo{a: 'x'}` is legal CEL
//! message-literal syntax: it passes the static budget scan (`{}` counts as
//! depth 1), passes `Program::compile` (parses only), and passes the own AST
//! pre-check because BOTH struct literals hit the catch-all arm at L597 which
//! returns `Ok(Null)` without inspecting children; `Null == Null` folds to
//! `Bool(true)`. Only `program.execute()` resolves `Expr::Struct` and hits the
//! unfinished `todo!()` inside the third-party interpreter.
//!
//! ## Impact Analysis
//! The panic is not convertible into a controlled `Err` on the validation
//! path (`rules.rs::get_failing_custom_rules` installs no catch_unwind): the
//! whole wallet process dies during routine voucher validation. Violates audit
//! invariant #2 (Fail-Closed) and #1 (controlled, deterministic errors).
//!
//! ## Root Cause
//! The pre-check's catch-all treats every unmodeled expression kind as vacuously
//! evaluable although cel-interpreter explicitly does NOT support message
//! literals and aborts via `todo!()`. Wave-3 AUDIT-M03-007/-008 fixed only the
//! Comprehension family; `Expr::Struct` remained an explicit residual.
//!
//! ## Remediation Strategy
//! Add an explicit `Expr::Struct` arm to `eval_and_check_ast` returning
//! `Err(PolicyEngineError::EvaluationError("struct/message literals are not
//! supported"))` BEFORE the interpreter runs (mirror of M03-007). Same class,
//! defense-in-depth: `Expr::Unspecified => panic!("Can't evaluate Unspecified
//! Expr")` in objects.rs:707.
//!
//! ## Test Semantics (Fail-First)
//! RED on unpatched code. VERIFIED EMPIRICAL SIGNAL (single-run, unpatched):
//! the `todo!()` fires inside `program.execute` at cel-interpreter
//! objects.rs:706:32 ("not yet implemented: Support structs!") and is caught
//! by this test's `catch_unwind` harness (panic=unwind), so nextest reports a
//! deterministic FAIL for exactly this test — no SIGABRT occurs because the
//! abort-class only materializes for stack overflows (wave-3 finding05) or
//! without an unwinding harness. The red proof is the panic payload itself:
//! the signed rule reached the interpreter's unfinished branch instead of
//! yielding `Err`. GREEN after remediation (`Err(PolicyEngineError::_)`).
//!
//! ===========================================================================
//! FINDING AUDIT-W4-CEL-102
//! ===========================================================================
//! Finding-ID:  AUDIT-W4-CEL-102 (Wave-4 hypothesis WH4-03-102)
//!             "No Issuer Pinning: Attacker-Re-Signed Mutable Zone Passes the
//!             Usage-Time Gate and Loosens Consensus via round_up_validity_to"
//! Severity:   HIGH
//! CWE-Classification: CWE-347 "Improper Verification of Cryptographic
//!             Signature" (self-consistent key extracted from the same file);
//!             CWE-345 "Insufficient Verification of Data Authenticity"
//! Target Location: src/services/standard_manager.rs:133 +
//!             standard_manager.rs:107-156 (`verify_standard_signature`: the
//!             public key is taken FROM THE FILE via
//!             `get_pubkey_from_user_id(&signature_block.issuer_id)`, so any
//!             re-sign under ANY key is self-consistently valid);
//!             src/services/voucher_validation/identity.rs:11-25 (uuid/hash
//!             anchors are equally self-consistent against the swapped file)
//!             and identity.rs:167-169 (`round_up_validity_to` from the
//!             nominally UI-only `[mutable]` zone feeds
//!             `verify_validity_duration` and rounds the MAX validity bound
//!             UP).
//! Threat Model & Exploitation:
//! A local attacker with filesystem write access (malware, cloud-sync folder
//! swap — in-scope per AUDIT-M03-010) replaces
//! `voucher_standards/<uuid>/standard.toml` wholesale: IDENTICAL `[immutable]`
//! zone (same uuid -> identity check passes; same canonical bytes -> same
//! logic_hash -> hash check passes), rewritten `[mutable]` zone (phishing
//! metadata + `app_config.round_up_validity_to = "P1Y"`) and a FRESH Ed25519
//! signature under the ATTACKER's own did:key. Both verifiers extract the
//! public key from the file itself, so the swap is accepted everywhere. There
//! is no trust-on-first-use pin of the original issuer anywhere.
//! Impact Analysis:
//! (1) Phishing: issuer_name/homepage/i18n contract texts can be rewritten for
//!     the lifetime of the installation while every cryptographic check stays
//!     green.
//! (2) Consensus loosening (severe): a voucher whose validity massively
//!     exceeds the issuer-intended maximum ("P1M") PASSES usage-time
//!     validation once the re-signed file rounds the max bound up to year end
//!     ("P1Y"). Note: the hypothesis sketch used "P100Y", but
//!     `round_up_date` rejects unsupported units fail-closed (only
//!     P1D/P1M/P3M/P6M/P1Y are accepted), so the realistic attacker choice is
//!     the supported maximal granularity "P1Y".
//! Root Cause:
//! Trust anchor placed only at import time against keys declared INSIDE the
//! file; no persistent pin of the importing-time issuer identity (or canonical
//! hash) exists, and the standards folder is the only plaintext store outside
//! WalletSeal/Integrity coverage.
//! Remediation Strategy:
//! Trust-on-first-use pinning: at import, anchor `issuer_id` (or canonical
//! hash) in a protected sidecar/integrity record and make
//! `verify_standard_signature` compare against that pin (pattern:
//! `store_binding_hash`, SA05-07); alternatively bring voucher_standards into
//! storage integrity coverage.
//! Test Semantics (Fail-First):
//! RED on unpatched code: after the FS-level swap, both usage-time gates
//! return Ok where the secure invariant demands Err. GREEN after pinning.

// ===========================================================================
// FINDING AUDIT-W4-CEL-103
// ===========================================================================
// Finding-ID:  AUDIT-W4-CEL-103 (Wave-4 hypothesis WH4-03-103)
//             "String-Index Byte/Char Divergence: Interpreter Coalesces
//             Misaligned/OOB Byte Indices to Null While the Pre-Check
//             Fabricates Characters"
// Severity:   MEDIUM
// CWE-Classification: CWE-176 "Incorrect Handling of Unicode Encoding" /
//             CWE-178 "Improper Handling of Case Sensitivity or Encoding
//             Divergence"; CWE-636 "Not Failing Securely (Failing Open)"
// Target Location: src/services/dynamic_policy_engine.rs:293-328 (String arm
//             of `_[_]`: byte bounds check `idx < s.len()` at :319, CHAR
//             access `chars().nth(idx).unwrap_or('\0')` at :320) vs.
//             cel-interpreter 0.10.0 `src/objects.rs:545-548` (BYTE-SLICE
//             semantics: `str.get(idx..idx+1)` -> `None => Value::Null` for
//             OOB AND non-char-boundary indices).
// Threat Model & Exploitation:
// Positional rules over string fields (e.g. `Voucher.unit[1] != 'E'`) are
// signed standard content evaluated against attacker-controlled voucher
// state. Because the interpreter indexes BYTES while the pre-check models
// CHARACTERS, a single multibyte prefix shifts the two evaluators apart: for
// state "\u{00C4}EX" ('Ä' = 2 UTF-8 bytes) byte index 1 is a CONTINUATION
// byte -> `str.get(1..2)` -> None -> Value::Null, so the negated rule becomes
// `Null != 'E'` -> true and the signed positional restriction evaporates even
// though character #1 genuinely IS 'E'. Additionally, for indices inside the
// byte length but outside the char count the pre-check fabricates a synthetic
// NUL character ('\0') that never existed in the field.
// Impact Analysis:
// Vacuous bypass of signed positional rules (fail-open) plus evaluator-
// dependent semantics for equality rules against '\u{0000}' — violating
// determinism (#1) and fail-closed (#2) invariants. M03-001 closed the NULL-
// coalescing gap only for map/list bracket access; the string arm was never
// aligned with actual interpreter semantics.
// Remediation Strategy:
// Model BYTE-slice semantics exactly in the pre-check string arm AND turn
// every `None` outcome (OOB and non-char-boundary) into
// `Err(EvaluationError)` instead of coalescing/fabricating — fail-closed like
// the map/list arms; alternatively reject non-ASCII indexing outright.
// Test Semantics (Fail-First):
// RED on unpatched code: negated multibyte rule yields Ok(true) (bypass) and
// misaligned-index rules yield Ok(_) instead of Err. GREEN after remediation.

use human_money_core::app_service::AppService;
use human_money_core::models::profile::UserIdentity;
use human_money_core::models::voucher_standard_definition::{
    SignatureBlock, VoucherStandardDefinition,
};
use human_money_core::services::crypto::{get_hash, sign_ed25519};
use human_money_core::services::dynamic_policy_engine::{DynamicPolicyEngine, PolicyEngineError};
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_validation::{
    verify_standard_identity, verify_validity_duration,
};
use human_money_core::test_utils::actors::user_from_mnemonic_fast;
use serde_json::json;
use std::fs;

// ===========================================================================
// Shared deterministic identities (public test_utils actors — genuine Ed25519
// keys, no signature bypass involved).
// ===========================================================================

/// Legitimate issuer identity (deterministic test actor).
fn audit_issuer() -> UserIdentity {
    user_from_mnemonic_fast(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
        Some("test"),
    )
    .identity
}

/// Attacker identity with a DIFFERENT deterministic key — models a fresh
/// attacker-controlled Ed25519 key used to re-sign the stolen definition.
fn audit_attacker() -> UserIdentity {
    user_from_mnemonic_fast(
        "legal winner thank year wave sausage worth useful legal winner \
         thank yellow",
        Some("attacker"),
    )
    .identity
}

/// Builds the unsigned standard body (no `[signature]`, no `[mutable.app_config]`)
/// with a deliberately TIGHT validity window [P1M, P1M].
fn standard_body(uuid: &str, name: &str) -> String {
    format!(
        r#"
[immutable.identity]
uuid = "{uuid}"
name = "{name}"
abbreviation = "W4T"

[immutable.blueprint]
unit = "AuditUnit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init", "transfer"]

[immutable.issuance]
validity_duration_range = ["P1M", "P1M"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["issuer"]

[immutable.custom_rules]

[mutable.metadata]
issuer_name = "Legit Community Issuer"
"#
    )
}

/// Signs a definition GENUINELY with the given identity over the canonical
/// representation (replicating `verify_and_parse_standard` step 2-5) and
/// serializes the signed definition back to TOML.
fn sign_and_serialize(
    mut definition: VoucherStandardDefinition,
    signer: &UserIdentity,
) -> String {
    definition.signature = None;
    let canonical_json =
        to_canonical_json(&definition).expect("canonicalization failed");
    let signature_hash = get_hash(canonical_json.as_bytes());
    let signature = sign_ed25519(&signer.signing_key, signature_hash.as_bytes());
    definition.signature = Some(SignatureBlock {
        issuer_id: signer.user_id.clone(),
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });
    toml::to_string(&definition).expect("TOML serialization of definition failed")
}

/// Voucher bound to the audited standard whose validity MASSIVELY exceeds the
/// issuer window: created 2026-01-01, valid until 2026-12-15 (>11 months vs.
/// max "P1M").
fn overlong_voucher(standard_uuid: &str, definition_hash: &str) -> human_money_core::models::voucher::Voucher {
    let mut voucher = human_money_core::models::voucher::Voucher::default();
    voucher.voucher_standard.uuid = standard_uuid.to_string();
    voucher.voucher_standard.standard_definition_hash = definition_hash.to_string();
    voucher.nominal_value.unit = "AuditUnit".to_string();
    voucher.creation_date = "2026-01-01T00:00:00Z".to_string();
    voucher.valid_until = "2026-12-15T00:00:00Z".to_string();
    voucher.non_redeemable_test_voucher = true;
    voucher
}

/// Short-lived voucher INSIDE the issuer window [P1M, P1M] (used by controls):
/// min == max == creation + P1M, so only the exact boundary satisfies both.
fn compliant_voucher(standard_uuid: &str, definition_hash: &str) -> human_money_core::models::voucher::Voucher {
    let mut voucher = human_money_core::models::voucher::Voucher::default();
    voucher.voucher_standard.uuid = standard_uuid.to_string();
    voucher.voucher_standard.standard_definition_hash = definition_hash.to_string();
    voucher.nominal_value.unit = "AuditUnit".to_string();
    voucher.creation_date = "2026-01-01T00:00:00Z".to_string();
    voucher.valid_until = "2026-02-01T00:00:00Z".to_string();
    voucher.non_redeemable_test_voucher = true;
    voucher
}

const SWAP_UUID: &str = "w4-m03-0102-uuid";

/// Installs the LEGIT standard via the production import path, then performs
/// the attacker's FILESYSTEM-LEVEL swap: identical immutable zone, phishing
/// mutable zone, `round_up_validity_to = "P1Y"`, signature under the
/// ATTACKER's fresh key. Returns the pristine and the re-signed definitions.
fn install_then_resign_on_disk() -> (
    tempfile::TempDir,
    VoucherStandardDefinition,
    VoucherStandardDefinition,
    String,
) {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let standards_dir = dir.path().join("voucher_standards");
    let app = AppService::new(dir.path()).expect("AppService::new failed");
    let issuer = audit_issuer();

    // 1. Legitimate installation via AppService import.
    let legit_toml = sign_and_serialize(
        toml::from_str(&standard_body(SWAP_UUID, "Wave4 Integrity Probe"))
            .expect("body parses"),
        &issuer,
    );
    let imported_uuid = app
        .import_voucher_standard(legit_toml.as_bytes(), None, &standards_dir)
        .expect("legitimate import failed");
    assert_eq!(imported_uuid, SWAP_UUID);

    let installed_file = standards_dir.join(SWAP_UUID).join("standard.toml");
    assert_eq!(
        fs::read_to_string(&installed_file).expect("installed file readable"),
        legit_toml,
        "precondition: installed bytes are the legitimate standard"
    );

    let (pristine, pristine_hash) =
        VoucherStandardDefinition::from_toml(&legit_toml).expect("pristine standard verifies");

    // 2. Attacker re-signs: immutable zone UNTOUCHED, mutable zone rewritten.
    let mut resigned = pristine.clone();
    resigned.mutable.metadata.issuer_name = "Phish Community".to_string();
    resigned.mutable.app_config.round_up_validity_to = Some("P1Y".to_string());
    let swapped_toml = sign_and_serialize(resigned, &audit_attacker());

    // Enabling precondition: the re-signed file is SELF-CONSISTENTLY valid
    // because both verifiers take the public key from the file itself.
    let (reloaded, reloaded_hash) = VoucherStandardDefinition::from_toml(&swapped_toml)
        .expect("precondition: attacker-re-signed standard must pass verify_and_parse_standard");
    assert_eq!(
        pristine_hash, reloaded_hash,
        "precondition: identical immutable zone -> identical logic_hash"
    );

    // 3. Filesystem-level swap (malware / cloud-sync folder swap threat).
    fs::write(&installed_file, &swapped_toml).expect("attacker swap write failed");
    assert_ne!(
        fs::read_to_string(&installed_file).expect("swapped file readable"),
        legit_toml,
        "precondition: installation was actually replaced on disk"
    );

    (dir, pristine, reloaded, reloaded_hash)
}

// ===========================================================================
// AUDIT-W4-CEL-101 — exploit proof (RED on unpatched code)
// VERIFIED SIGNAL: catchable todo!() panic at cel-interpreter objects.rs:706:32
// ("not yet implemented: Support structs!") -> nextest FAIL via catch_unwind
// (no SIGABRT under panic=unwind; see docblock above).
// ===========================================================================

/// Message literals must be rejected with a controlled error BEFORE reaching
/// the interpreter. SECURE INVARIANT: evaluation of a (possibly hostile)
/// signed rule must yield `Err(PolicyEngineError::_)`, never kill the process
/// via the interpreter's `todo!("Support structs!")`.
#[test]
fn finding101_message_literal_must_err_not_abort_process() {
    // Two message literals compared directly: both fold to Null in the
    // pre-check catch-all (Null == Null -> Bool(true)), so NOTHING intercepts
    // before program.execute() resolves Expr::Struct -> todo!().
    // NOTE: selecting a field instead (`.a`) would accidentally fail closed in
    // the pre-check (NoSuchKey over the Null-folded operand) and would NOT
    // reach the interpreter — the literal-vs-literal form is the real path.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        DynamicPolicyEngine::evaluate_rule(
            "human_money_core{a: 'x'} == human_money_core{a: 'x'}",
            &json!({}),
            None,
        )
    }));

    match result {
        Err(payload) => panic!(
            "AUDIT-W4-CEL-101 PROCESS ABORT/PANIC: evaluating the message literal \
             \"human_money_core{{a: 'x'}} == human_money_core{{a: 'x'}}\" PANICKED or \
             aborted instead of returning a graceful error (payload: {:?}). On unpatched \
             code this test ABORTS the whole test process with SIGABRT (todo!() in \
             cel-interpreter objects.rs:706) during routine rule evaluation — an \
             uncatchable remote process kill via signed standards. Expected: \
             Err(PolicyEngineError::_) (fail-closed).",
            payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<opaque panic payload / process aborted before unwinding>")
        ),
        Ok(Ok(_)) => panic!(
            "AUDIT-W4-CEL-101 FAIL-OPEN: message literal evaluated to Ok(_) although \
             structs are unsupported — must be Err(...) (fail-closed)."
        ),
        Ok(Err(_)) => {} // secure fail-closed behavior (post-remediation)
    }
}

/// CONTROL: ordinary expressions over present fields must keep evaluating
/// after the Expr::Struct rejection arm is added (remediation must stay
/// narrowly scoped to unsupported syntax).
#[test]
fn control101_ordinary_rules_remain_evaluable() {
    let voucher = json!({ "unit": "Minuto" });
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule("Voucher.unit == 'Minuto'", &voucher, None),
        Ok(true),
        "Ordinary rule evaluation broke while adding the struct guard"
    );
    assert!(
        matches!(
            DynamicPolicyEngine::evaluate_rule("Voucher.missing == 'x'", &voucher, None),
            Err(PolicyEngineError::EvaluationError(_))
        ),
        "Fail-closed NoSuchKey behavior must be preserved"
    );
}

// ===========================================================================
// AUDIT-W4-CEL-102 — exploit proofs (RED on unpatched code)
// ===========================================================================

/// After the attacker's re-sign swap, the usage-time identity gate still
/// accepts the foreign-key definition. SECURE INVARIANT: a definition signed
/// under a key OTHER than the pinned/importing issuer must be rejected at use
/// time (trust-on-first-use pinning).
///
/// STATUS: CONFIRMED, remediation PLANNED (host-level TOFU pin store).
/// Proof retained below; ignored until remediation lands because the fix
/// requires a product decision on WHERE the host persists issuer pins
/// (standards dir is attacker-writable by threat model; any in-file anchor is
/// self-consistently re-signable and immutable-zone changes would shift
/// `standard_definition_hash` and strand every issued voucher). The core
/// primitive `standard_manager::verify_and_parse_standard_with_issuer_pin`
/// already ships; hosts pass their stored pin at every usage of an installed
/// file. Mirrors the documented-PENDING pattern of SA04-08/audit_02_11.
#[test]
#[ignore = "AUDIT-W4-CEL-102: awaiting host-level TOFU pin store (plan in reports/wave4 report); core pin primitive shipped"]
fn finding102_usage_time_gate_must_reject_attacker_resigned_definition() {
    let (_dir, pristine, resigned, hash) = install_then_resign_on_disk();

    // Bound to the swapped installation: uuid matches AND immutable-zone hash
    // matches (attacker kept [immutable] untouched) — ONLY the issuer pin is
    // violated, isolating the finding to the missing re-sign detection.
    let voucher = overlong_voucher(SWAP_UUID, &hash);

    // Baseline control: the PRISTINE definition passes the gate.
    assert!(
        verify_standard_identity(&voucher, &pristine).is_ok(),
        "precondition: pristine definition must pass verify_standard_identity"
    );

    // Documentation: phishing metadata rode through verification untouched.
    assert_ne!(
        resigned.mutable.metadata.issuer_name, pristine.mutable.metadata.issuer_name,
        "precondition: issuer_name was rewritten to phishing value"
    );
    assert_eq!(
        resigned.mutable.app_config.round_up_validity_to.as_deref(),
        Some("P1Y"),
        "precondition: consensus-relevant rounding hint was injected"
    );

    // RED ASSERTION: uuid matches + immutable hash matches + self-consistent
    // attacker signature => currently Ok(()).
    let result = verify_standard_identity(&voucher, &resigned);
    assert!(
        result.is_err(),
        "AUDIT-W4-CEL-102 NO ISSUER PINNING: verify_standard_identity accepted a \
         definition whose [mutable] zone was rewritten and whose signature was replaced \
         by an ATTACKER-controlled Ed25519 key (issuer_id taken from the file itself, \
         standard_manager.rs:133). Uuid and immutable-zone hash match because the \
         attacker kept [immutable] untouched. The usage-time gate must enforce \
         trust-on-first-use pinning of the ORIGINAL issuer identity. Expected: \
         Err(...). Got Ok(())."
    );
}

/// Consensus loosening: the overlong voucher that FAILS against the pristine
/// definition PASSES against the attacker-re-signed one because
/// `round_up_validity_to` from the mutable zone rounds the max bound up to
/// year end. SECURE INVARIANT: a re-signed (unpinned) definition must never
/// loosen validation outcomes — verify_validity_duration must stay Err.
///
/// STATUS: CONFIRMED, remediation PLANNED (same host-level TOFU pin store as
/// finding102_usage_time_gate; see that test's docblock).
#[test]
#[ignore = "AUDIT-W4-CEL-102: awaiting host-level TOFU pin store (plan in reports/wave4 report); core pin primitive shipped"]
fn finding102_round_up_loosening_must_not_admit_overlong_validity() {
    let (_dir, pristine, resigned, _hash) = install_then_resign_on_disk();

    let hash_pristine = get_hash(to_canonical_json(&pristine.immutable).unwrap().as_bytes());
    let voucher = overlong_voucher(SWAP_UUID, &hash_pristine);

    // Baseline control (GREEN): against the ISSUER-intended definition the
    // voucher genuinely violates the maximum validity ("P1M").
    let baseline = verify_validity_duration(&voucher, &pristine);
    assert!(
        baseline.is_err(),
        "precondition: voucher validity (11+ months) must violate the P1M maximum \
         against the pristine definition, got {:?}",
        baseline
    );

    // RED ASSERTION: same voucher, swapped definition — the injected
    // "P1Y" rounding pushes the max bound to 2026-12-31T23:59:59.999999999
    // and the violation evaporates => currently Ok(()).
    let result = verify_validity_duration(&voucher, &resigned);
    assert!(
        result.is_err(),
        "AUDIT-W4-CEL-102 CONSENSUS LOOSENING: verify_validity_duration accepted an \
         overlong voucher (valid_until 2026-12-15 vs. issuer maximum P1M) because the \
         ATTACKER-re-signed mutable zone set app_config.round_up_validity_to = 'P1Y' \
         (identity.rs:167-169 rounds the max bound up to year end). A definition \
         re-signed under an unpinned attacker key must not loosen consensus-relevant \
         validation. Expected: Err(...). Got Ok(())."
    );
}

/// CONTROL: compliant vouchers keep passing and pristine gates stay green —
/// remediation (pinning) must not break legitimate usage.
#[test]
fn control102_pristine_gates_remain_functional() {
    let (_dir, pristine, _resigned, _hash) = install_then_resign_on_disk();
    let hash = get_hash(to_canonical_json(&pristine.immutable).unwrap().as_bytes());

    let compliant = compliant_voucher(SWAP_UUID, &hash);
    assert!(
        verify_validity_duration(&compliant, &pristine).is_ok(),
        "A compliant voucher must pass validity checks against the pristine definition"
    );
    let bound = overlong_voucher(SWAP_UUID, &hash);
    assert!(
        verify_standard_identity(&bound, &pristine).is_ok(),
        "The pristine definition must keep passing the identity gate"
    );
}

// ===========================================================================
// AUDIT-W4-CEL-103 — exploit proofs (RED on unpatched code) + controls
// ===========================================================================

/// Negated positional rule bypassed by a multibyte prefix: char #1 IS 'E',
/// but the interpreter slices BYTE 1 (continuation byte) -> str.get -> None ->
/// Value::Null -> `Null != 'E'` -> true. SECURE INVARIANT: undefined/
/// encoding-divergent indexing must never satisfy a signed restriction —
/// engine must return Err (fail-closed) or the char-exact verdict (Ok(false)).
#[test]
fn finding103_multibyte_prefix_bypasses_negated_position_rule() {
    // 'Ä' (U+00C4, 2 UTF-8 bytes) + "EX": chars ['Ä','E','X'], bytes 4.
    let state = json!({ "unit": "\u{00C4}EX" });

    let result =
        DynamicPolicyEngine::evaluate_rule("Voucher.unit[1] != 'E'", &state, None);

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-W4-CEL-103 BYTE/CHAR DIVERGENCE: rule \"Voucher.unit[1] != 'E'\" evaluated \
         to Ok(true) although character #1 of the field genuinely IS 'E'. The interpreter \
         indexes BYTES (objects.rs:545-548): byte 1 is a UTF-8 continuation byte -> \
         str.get(1..2) -> None -> Value::Null; `Null != 'E'` -> true vacuously bypasses \
         the signed positional restriction. Expected: Err(...) (fail-closed) or \
         Ok(false) (char-exact modeling). Got: {:?}",
        result
    );
}

/// Index inside BYTE length but outside CHAR count: the pre-check fabricates
/// '\0' (engine.rs:320 `chars().nth(idx).unwrap_or('\0')`) while the
/// interpreter yields Null — both evaluators invent values that do not exist
/// in the field. SECURE INVARIANT: such access must fail closed (Err), never
/// produce an Ok(_) verdict based on fabricated data.
#[test]
fn finding103_misaligned_index_must_fail_closed_not_invent_values() {
    // "AÄ": chars ['A','Ä'] (count 2), bytes 3. Index 2 is byte-in-range but
    // char-out-of-range AND non-char-boundary.
    let state = json!({ "unit": "A\u{00C4}" });
    // Raw NUL character embedded via char literal (the fabricated value the
    // pre-check's `unwrap_or('\0')` invents at dynamic_policy_engine.rs:320).
    let rule_neq = format!("Voucher.unit[2] != {}", format!("'{}'", '\u{0000}'));
    let rule_eq = format!("Voucher.unit[2] == {}", format!("'{}'", '\u{0000}'));

    let neq = DynamicPolicyEngine::evaluate_rule(&rule_neq, &state, None);
    assert!(
        neq.is_err(),
        "AUDIT-W4-CEL-103 FAIL-OPEN: misaligned index produced an invented value and \
         \"Voucher.unit[2] != '\\u{{0000}}'\" returned {:?} instead of Err. The \
         interpreter yields Null (byte slice fails) making the inequality vacuously \
         true; the pre-check even fabricates '\\0'. Undefined string indexing must \
         fail closed.",
        neq
    );

    let eq = DynamicPolicyEngine::evaluate_rule(&rule_eq, &state, None);
    assert!(
        eq.is_err(),
        "AUDIT-W4-CEL-103 EVALUATOR DIVERGENCE: equality against a fabricated NUL \
         returned {:?} instead of Err. The two evaluators disagree (pre-check: \
         synthetic '\\\\0'; interpreter: Null), so the verdict depends on which one \
         wins rather than on a defined contract. Misaligned/OOB-char string indexing \
         must fail closed.",
        eq
    );
}

/// CONTROL: ASCII strings behave identically under byte- and char-semantics —
/// positional rules over ASCII fields must keep working after remediation.
#[test]
fn control103_ascii_position_rules_remain_exact() {
    let state = json!({ "unit": "TEX" });

    assert_eq!(
        DynamicPolicyEngine::evaluate_rule("Voucher.unit[0] == 'T'", &state, None),
        Ok(true),
        "ASCII positional equality broke"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule("Voucher.unit[2] == 'X'", &state, None),
        Ok(true),
        "ASCII positional equality (last char) broke"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule("Voucher.unit[1] != 'E'", &state, None),
        Ok(false),
        "Negated ASCII positional rule must correctly fail for matching char"
    );
}
