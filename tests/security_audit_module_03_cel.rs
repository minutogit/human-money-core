//! # Security Audit — Module 03: Voucher Standards & Dynamic Policy Engine (CEL)
//!
//! Autonomous security audit of the CEL-based dynamic policy pipeline:
//! `src/services/dynamic_policy_engine.rs` -> consumed by
//! `src/services/voucher_validation/rules.rs::get_failing_custom_rules`
//! (`Ok(true) => {}` forwards a passing rule to successful validation;
//! `Err(e)` is converted into a failing entry -> rejection).
//!
//! ## FAIL-FIRST TDD INVARIANT
//! Every test prefixed with `finding*` asserts the SECURE invariant
//! (**Soll-Verhalten**: fail-closed) and therefore **MUST FAIL on unpatched
//! code**, proving the vulnerability. Tests prefixed with `control*` pin down
//! already-correct behavior and MUST stay green after remediation.
//!
//! ===========================================================================
//! FINDING AUDIT-M03-001
//! ===========================================================================
//! Finding-ID:  AUDIT-M03-001
//!             "Fail-Open via NULL-Coalescing Bracket Indexing in CEL Rule
//!             Evaluation"
//! Severity:   HIGH
//! CWE:        CWE-636 "Not Failing Securely (Failing Open)" (primary);
//!             CWE-754 "Improper Check for Unusual or Exceptional Conditions"
//!             (secondary)
//! Target:     `DynamicPolicyEngine::evaluate_rule`
//!             (`src/services/dynamic_policy_engine.rs`) in combination with
//!             `cel-interpreter 0.10.0`. In the interpreter's INDEX resolution
//!             (`src/objects.rs`), map/list/string indexing resolves absent or
//!             out-of-bounds keys via `.cloned().unwrap_or(Value::Null)` — i.e.
//!             bracket access COALESCES to `Value::Null` instead of raising an
//!             error, whereas dot attribute access correctly raises
//!             `NoSuchKey(...)` (verified empirically; see controls below).
//! Threat
//! Model:      The voucher/transaction JSON handed to CEL evaluation is derived
//!             from attacker-controlled bundle content. Issuer standards
//!             restrict optional fields (`valid_until`, `collateral`,
//!             `Transaction.sender_id`, ...) using NEGATED predicates such as
//!             `Transaction['sender_id'] != '...'`. An attacker OMITS the
//!             optional field in the voucher they hand over (all `Option`
//!             fields are serialized as absent, never as explicit `null`).
//!             Bracket syntax is fully legal CEL and routinely appears in
//!             ported/generated rules.
//! Impact:     `Null != <string>` evaluates to `true` (`PartialEq::ne` on
//!             mismatched types returns `ne == true` without error), and
//!             `!(Null == <x>)` likewise evaluates to `true`. The restriction
//!             evaporates: the hostile voucher PASSES the dynamic rule
//!             (`Ok(true)`) instead of failing closed. This directly violates
//!             system invariant #2 ("Fail-Closed Principle") of the audit
//!             threat model and enables acceptance of policy-violating vouchers
//!             (e.g. undisclosed senders in public-mode standards, forbidden
//!             collateral, vouchers stripped of their expiry date). Out-of-
//!             bounds string/list indexing propagates the same `Null`
//!             (`expr[999] != ''` -> `true`).
//! Root Cause: Two layers compound: (1) cel-interpreter 0.10.0 treats bracket
//!             indexing on missing keys / out-of-range indices as `Value::Null`
//!             (deviating from strict CEL selection semantics and
//!             inconsistently with its own dot-access `NoSuchKey` behavior);
//!             (2) `evaluate_rule` accepts any `Ok(bool)` result without
//!             verifying that all data paths referenced by the expression
//!             actually exist, so absence is silently conflated with a
//!             satisfied predicate.
//! Remediation: Layered fix, preferred order: (a) make map indexing strict —
//!             return an evaluation error for missing keys (vendor/fork patch
//!             aligning bracket with dot semantics, matching the CEL
//!             specification where selection on absent fields is an error);
//!             (b) engine-level guard: statically extract all global attribute/
//!             index paths from the parsed AST (`cel_parser::Expr` is public),
//!             resolve them against the state documents, and return
//!             `Err(PolicyEngineError::EvaluationError("missing field"))`
//!             before trusting any `Ok(_)` result; (c) short-term authoring
//!             guidance: forbid negated predicates over optional fields unless
//!             guarded by explicit existence checks, and reject `custom_rules`
//!             expressions containing bracket indexing at standard-import time.
//! Test
//! Semantics:  RED on unpatched code (assertion of secure outcome fails because
//!             the engine currently yields `Ok(true)`); GREEN after remediation.
//!             Controls document that dot syntax already fails closed
//!             (`NoSuchKey`) and that legitimate rules over PRESENT fields keep
//!             working.
//!
//! ===========================================================================
//! FINDING AUDIT-M03-002
//! ===========================================================================
//! Finding-ID:  AUDIT-M03-002
//!             "Signed-to-Unsigned Wraparound in `check_decimals`"
//! Severity:   LOW
//! CWE:        CWE-195 "Signed to Unsigned Conversion Error"
//! Target:     `DynamicPolicyEngine::register_custom_functions`
//!             (`src/services/dynamic_policy_engine.rs`, closure body
//!             `dec.scale() <= max_places as u32`).
//! Threat
//! Model:      A standard author writes a nonsensical/negative scale limit
//!             (e.g. `-1`), or a hostile-but-signed standard slips through
//!             review; a decimal-place restriction must never be loosened by
//!             numeric conversion artifacts.
//! Impact:     `(-1 i64) as u32` wraps to `4_294_967_295`, so
//!             `check_decimals(<any amount>, -1)` always returns `true` — the
//!             decimal restriction silently disappears (fail-open direction).
//! Root Cause: Unguarded `as u32` cast of the signed `max_places` parameter.
//! Remediation: Reject `max_places < 0 || max_places > 18` inside the closure
//!             (return `false`), replacing `as` with a range-checked
//!             conversion.
//! Test
//! Semantics:  RED on unpatched code; GREEN after remediation.
//!
//! ===========================================================================
//! FINDING AUDIT-M03-003
//! ===========================================================================
//! Finding-ID:  AUDIT-M03-003
//!             "Lexicographic String Ordering of Decimal Amounts Silently
//!             Satisfies Magnitude Limits (Fail-Open)"
//! Severity:   CRITICAL
//! CWE:        CWE-178 "Improper Handling of Case Sensitivity / Lexical
//!             Comparison of Numeric-Like Values" (primary);
//!             CWE-636 "Not Failing Securely (Failing Open)" (secondary)
//! Target:     `DynamicPolicyEngine::evaluate_rule`
//!             (`src/services/dynamic_policy_engine.rs`) AST pre-check
//!             catch-all branch (`eval_and_check_ast`) in combination with
//!             `cel-interpreter 0.10.0` `PartialOrd for Value`
//!             (`(Value::String(a), Value::String(b)) => Some(a.cmp(b))`).
//! Threat
//! Model:      Voucher amounts are deliberately serialized as decimal
//!             STRINGS (cryptographic serialization stability, AGENTS.md).
//!             A standard author naturally writes a magnitude limit as an
//!             ordering predicate over such a field
//!             (`Transaction.amount <= '100'`). Both operands are
//!             `Value::String`, so cel-interpreter compares them BYTE-WISE:
//!             `"15" < "9"` is true because `'1' < '9'`. The engine's own
//!             AST pre-check does not implement `<`/`<=`/`>`/`>=` at all
//!             (generic catch-all -> Null) and therefore never intervenes;
//!             the interpreter verdict becomes the final `Ok(bool)`.
//! Impact:     A magnitude limit is SATISFIED by values that violate it
//!             whenever the textual prefix sorts favorably: a maximum limit
//!             `'9'` passes for `"15"`, `"20"`, `"100000"`; a minimum limit
//!             `'15'` passes for `"9"`. Policy-violating vouchers/transfers
//!             pass validation (`get_failing_custom_rules` forwards
//!             `Ok(true)`). Direct violation of audit invariant #2
//!             (Fail-Closed Principle) and of business-rule determinism (#1):
//!             the same rule is consistently wrong on every platform.
//! Root Cause: Domain drift between the storage representation of amounts
//!             (String, kept intentionally stable for hashing/signatures)
//!             and comparison semantics: no engine-level guard forces
//!             ordering predicates onto numeric domains, and the AST
//!             pre-check delegates ordering operators blindly.
//! Remediation: Engine-level, fail-closed guard inside `eval_and_check_ast`:
//!             handle `_<_`, `_<=_`, `_>_`, `_>=_` explicitly and reject
//!             (EvaluationError) every ordering comparison whose operands
//!             are not BOTH JSON numbers. Numeric ordering remains fully
//!             functional via the interpreter. String-typed magnitudes must
//!             be constrained with domain-aware helpers
//!             (`check_decimals`) or exact membership (`in [...]`), never
//!             with raw ordering. This does NOT touch serialization formats
//!             or serde attributes.
//! Test
//! Semantics:  RED on unpatched code (engine yields Ok(true) for violating
//!             values due to lexicographic comparison); GREEN after the
//!             guard (both violating cases yield Err -> fail-closed).
//!             A control pins that legitimate NUMERIC ordering keeps
//!             working after remediation.
//!
//! ===========================================================================
//! FINDING AUDIT-M03-004
//! ===========================================================================
//! Finding-ID:  AUDIT-M03-004
//!             "Silent Overwrite / Missing Conflict Detection on Voucher
//!             Standard Import (UUID Swap & Brick)"
//! Severity:   HIGH
//! CWE:        CWE-284 "Improper Access Control" (primary);
//!             CWE-400 "Uncontrolled Resource Consumption" (secondary,
//!             brick/DoS direction)
//! Target:     `AppService::import_voucher_standard`
//!             (`src/app_service/standard_container_handler.rs`, unconditional
//!             `fs::write` onto `target_dir/<uuid>/standard.toml`).
//! Threat
//! Model:      An attacker distributes a `.standard` bundle whose
//!             `immutable.identity.uuid` equals the UUID of an already
//!             installed standard but whose immutable zone content differs
//!             (weakened `custom_rules`, relaxed
//!             `additional_signatures_range`, changed decimal places).
//!             Any signature inside the file is self-consistent by design:
//!             `verify_and_parse_standard` only checks that the file was
//!             signed by the issuer_id DECLARED IN THE SAME FILE. The victim
//!             is socially engineered into importing the divergent file.
//! Impact:     (a) Brick/DoS: silently replacing an installed standard
//!             invalidates every existing voucher whose
//!             `standard_definition_hash` binds to the previous immutable
//!             content — they fail validation forever. (b) Rule downgrade:
//!             vouchers created after the swap bind to the weakened hash and
//!             bypass the original issuer restrictions. In both cases the
//!             installation integrity under a given UUID is broken without
//!             any conflict signal — a violation of audit invariant #3
//!             (Immutability & Integrity). Additionally `fs::write` is not
//!             atomic, so a crash mid-write corrupts `standard.toml`.
//! Root Cause: The import path performs no existence/conflict check for the
//!             target UUID directory and no old-vs-new content comparison;
//!             unlike `delete_voucher_standard` it has no safeguards at all.
//! Remediation: Before writing, resolve the target file; if it already
//!             exists: byte-identical content -> idempotent success without
//!             touching disk; divergent content -> refuse with a validation
//!             error (fail-closed). Recovery from a genuinely intended
//!             upgrade is an explicit delete-then-import flow via the
//!             guarded `delete_voucher_standard`. Write via temp-file +
//!             rename to make installation atomic.
//! Test
//! Semantics:  RED on unpatched code (second import returns Ok and the file
//!             content flips to the attacker variant); GREEN after
//!             remediation (divergent import errs, installed bytes remain
//!             those of the first standard). Both standards are GENUINELY
//!             Ed25519-signed in-test against the canonical hash, proving
//!             signature validity alone cannot prevent the swap. A control
//!             pins that re-importing IDENTICAL content stays allowed.

use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::crypto::{get_hash, sign_ed25519};
use human_money_core::services::dynamic_policy_engine::{DynamicPolicyEngine, PolicyEngineError};
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::actors::user_from_mnemonic_fast;
use human_money_core::app_service::AppService;
use human_money_core::models::profile::UserIdentity;
use serde_json::json;
use std::fs;

/// Deterministic test issuer with a genuinely usable Ed25519 signing key
/// (public `test_utils` actor; no signature bypass involved).
fn test_issuer() -> human_money_core::models::profile::UserIdentity {
    user_from_mnemonic_fast(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon about",
        Some("test"),
    )
    .identity
}

/// Builds a syntactically valid standard body WITHOUT the `[signature]` block.
fn standard_body(uuid: &str, name: &str, amount_decimal_places: u32) -> String {
    format!(
        r#"
[immutable.identity]
uuid = "{uuid}"
name = "{name}"
abbreviation = "TST"

[immutable.blueprint]
unit = "TestUnit"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"

[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = {amount_decimal_places}
privacy_mode = "public"
allowed_t_types = ["init", "transfer"]

[immutable.issuance]
validity_duration_range = ["P1M", "P1Y"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 1]
allowed_signature_roles = ["issuer"]

[immutable.custom_rules]

[mutable.metadata]
issuer_name = "Test Issuer"
"#
    )
}

/// Produces a GENUINELY Ed25519-signed `standard.toml`: replicates the
/// canonicalization of `verify_and_parse_standard` (struct without signature
/// block -> canonical JSON -> SHA3 hash) and signs it with the issuer's
/// signing key. No `test-utils` bypass involved.
fn signed_standard_toml(
    uuid: &str,
    name: &str,
    amount_decimal_places: u32,
    issuer: &UserIdentity,
) -> String {
    let body = standard_body(uuid, name, amount_decimal_places);
    let mut definition: human_money_core::VoucherStandardDefinition =
        toml::from_str(&body).expect("standard body must parse");
    definition.signature = None;
    let canonical_json =
        to_canonical_json(&definition).expect("canonicalization failed");
    let signature_hash = get_hash(canonical_json.as_bytes());
    let signature = sign_ed25519(&issuer.signing_key, signature_hash.as_bytes());
    format!(
        "{body}\n[signature]\nissuer_id = \"{}\"\nsignature = \"{}\"\n",
        issuer.user_id,
        bs58::encode(signature.to_bytes()).into_string()
    )
}

/// Voucher state WITHOUT `collateral` and WITHOUT `valid_until`: exactly the
/// shape an attacker submits when omitting restricted optional data (serde
/// serializes `Option::None` fields as absent — never as explicit `null`).
fn voucher_state_minimal() -> serde_json::Value {
    json!({
        "voucher_id": "v-123",
        "nominal_value": {
            "amount": "50.000",
            "unit": "Minuto"
        },
        "signatures": [
            { "role": "creator" }
        ]
    })
}

/// Transaction state WITHOUT the optional `sender_id` (mandatory disclosure in
/// public privacy mode would be enforced by a rule like J below).
fn tx_state_without_sender() -> serde_json::Value {
    json!({
        "t_type": "transfer",
        "amount": "25",
        "recipient_id": "did:key:victim"
    })
}

// ===========================================================================
// FINDING AUDIT-M03-001 — exploit proofs (RED on unpatched code)
// ===========================================================================

/// Bracket-indexed inequality over an ABSENT top-level voucher field evaluates
/// to `Ok(true)`: `Null != ""` -> `true`. SECURE INVARIANT: absence of
/// attacker-restrictable data is an exceptional condition -> engine MUST fail
/// closed (return Err) so `get_failing_custom_rules` rejects the voucher.
#[test]
fn finding01_bracket_inequality_over_absent_voucher_field_must_fail_closed() {
    let voucher = voucher_state_minimal();

    let result =
        DynamicPolicyEngine::evaluate_rule("Voucher['valid_until'] != ''", &voucher, None);

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-001 FAIL-OPEN: rule \"Voucher['valid_until'] != ''\" evaluated to \
         Ok(true) although 'valid_until' does not exist in the state (bracket index \
         coalesced to Null; Null != String -> true). An attacker can bypass issuer \
         restrictions by omitting the optional field. Expected: Err(...) \
         (fail-closed). Got: {:?}",
        result
    );
}

/// Sender-disclosure enforcement via bracket syntax passes although the
/// attacker omitted `sender_id` entirely.
#[test]
fn finding01_bracket_sender_disclosure_rule_bypass_by_omission() {
    let voucher = voucher_state_minimal();
    let tx = tx_state_without_sender();

    let result = DynamicPolicyEngine::evaluate_rule(
        "Transaction['sender_id'] != 'did:key:EVIL'",
        &voucher,
        Some(&tx),
    );

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-001 FAIL-OPEN: disclosure rule \
         \"Transaction['sender_id'] != 'did:key:EVIL'\" passed although 'sender_id' \
         is absent (Null vs String inequality -> true). Expected: Err(...) \
         (fail-closed). Got: {:?}",
        result
    );
}

/// Same class via logical NOT: `!(Null == x)` -> `true`.
#[test]
fn finding01_logical_not_over_bracket_accessed_absent_field_must_fail_closed() {
    let voucher = voucher_state_minimal();

    let result = DynamicPolicyEngine::evaluate_rule(
        "!(Voucher['collateral'] == 'forbidden_collateral_object')",
        &voucher,
        None,
    );

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-001 FAIL-OPEN: negated rule over absent bracket-indexed field \
         evaluated to Ok(true). Expected: Err(...) (fail-closed). Got: {:?}",
        result
    );
}

/// Out-of-bounds string indexing propagates `Null` identically:
/// `expr[999] != ''` -> `Null != ''` -> `true`.
#[test]
fn finding01_out_of_bounds_index_null_propagation_must_fail_closed() {
    let voucher = voucher_state_minimal();

    let result = DynamicPolicyEngine::evaluate_rule(
        "Voucher.nominal_value.unit[999] != ''",
        &voucher,
        None,
    );

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-001 FAIL-OPEN: out-of-bounds index produced Null and the \
         inequality rule passed. Expected: Err(...) (fail-closed). Got: {:?}",
        result
    );
}

// ===========================================================================
// FINDING AUDIT-M03-002 — exploit proof (RED on unpatched code)
// ===========================================================================

/// Negative scale limit wraps around to u32::MAX and lets ANY amount pass.
/// SECURE INVARIANT: a nonsensical scale limit must not loosen the restriction
/// -> result must be Ok(false) or Err, never Ok(true).
#[test]
fn finding02_check_decimals_negative_scale_limit_must_not_pass() {
    let voucher = voucher_state_minimal(); // amount "50.000" has 3 decimals

    let result = DynamicPolicyEngine::evaluate_rule(
        "check_decimals(Voucher.nominal_value.amount, -1)",
        &voucher,
        None,
    );

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-002 TYPE-JUGGLING: check_decimals(amount, -1) returned Ok(true) \
         because (-1 i64) as u32 wrapped to 4294967295. The decimal restriction is \
         silently disabled. Expected: Ok(false) or Err(...). Got: {:?}",
        result
    );
}

// ===========================================================================
// FINDING AUDIT-M03-003 — exploit proofs (RED on unpatched code)
// ===========================================================================

/// Transaction state with a decimal-string amount that VIOLATES the tested
/// limits numerically but sorts favorably lexicographically.
fn tx_state_with_amount(amount: &str) -> serde_json::Value {
    json!({
        "t_type": "transfer",
        "amount": amount,
        "recipient_id": "did:key:victim"
    })
}

/// Maximum-limit form: `Transaction.amount < '9'` with amount "15".
/// Lexicographically "15" < "9" (byte '1' < '9') -> interpreter returns
/// `Ok(true)` although 15 violates the maximum 9.
/// SECURE INVARIANT: an ordering predicate over string-typed decimal amounts
/// must NEVER yield Ok(true) for a numerically violating value -> the engine
/// must fail closed (Err) instead of trusting byte-wise ordering.
#[test]
fn finding03_max_limit_over_string_amount_must_not_pass_for_violating_value() {
    let voucher = voucher_state_minimal();
    let tx = tx_state_with_amount("15");

    let result =
        DynamicPolicyEngine::evaluate_rule("Transaction.amount < '9'", &voucher, Some(&tx));

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-003 FAIL-OPEN: magnitude limit \"Transaction.amount < '9'\" was \
         satisfied by amount \"15\" because cel-interpreter compares two strings \
         LEXICOGRAPHICALLY ('1' < '9'). A transfer exceeding the limit passes \
         validation. Expected: Err(...) (fail-closed). Got: {:?}",
        result
    );
}

/// Minimum-limit form: `Transaction.amount >= '15'` with amount "9".
/// Lexicographically "9" > "15" -> Ok(true) although 9 is below the minimum.
#[test]
fn finding03_min_limit_over_string_amount_must_not_pass_for_violating_value() {
    let voucher = voucher_state_minimal();
    let tx = tx_state_with_amount("9");

    let result = DynamicPolicyEngine::evaluate_rule(
        "Transaction.amount >= '15'",
        &voucher,
        Some(&tx),
    );

    assert!(
        !matches!(result, Ok(true)),
        "AUDIT-M03-003 FAIL-OPEN: minimum limit \"Transaction.amount >= '15'\" was \
         satisfied by amount \"9\" due to lexicographic string comparison \
         ('9' > '1'). Expected: Err(...) (fail-closed). Got: {:?}",
        result
    );
}

// ===========================================================================
// FINDING AUDIT-M03-004 — exploit proof (RED on unpatched code)
// ===========================================================================

/// Importing a second, divergent-but-validly-signed standard under an
/// ALREADY-INSTALLED UUID must be refused; the installed file must remain
/// byte-identical. SECURE INVARIANT: installation integrity under a UUID —
/// no silent overwrite, no brick of existing vouchers, no rule downgrade.
#[test]
fn finding04_import_same_uuid_divergent_content_must_not_overwrite_installed_standard() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let standards_dir = dir.path().join("voucher_standards");
    let app = AppService::new(dir.path()).expect("AppService::new failed");
    let issuer = test_issuer();

    // Two genuinely self-consistent (correctly signed) standards sharing ONE
    // UUID but differing in the immutable zone (2 vs 5 decimal places).
    let toml_original = signed_standard_toml("audit-m03-0004-uuid", "Original Standard", 2, &issuer);
    let toml_weakened =
        signed_standard_toml("audit-m03-0004-uuid", "Weakened Clone", 5, &issuer);

    // Sanity: both verify WITHOUT any test-utils bypass -> signature validity
    // alone cannot distinguish them; the conflict guard is required.
    assert!(VoucherStandardDefinition::from_toml(&toml_original).is_ok());
    assert!(VoucherStandardDefinition::from_toml(&toml_weakened).is_ok());
    assert_ne!(toml_original, toml_weakened);

    // First import installs the original standard.
    let uuid = app
        .import_voucher_standard(toml_original.as_bytes(), None, &standards_dir)
        .expect("initial import of the original standard failed");
    assert_eq!(uuid, "audit-m03-0004-uuid");

    let installed_file = standards_dir.join("audit-m03-0004-uuid").join("standard.toml");
    assert_eq!(
        fs::read_to_string(&installed_file).expect("installed standard readable"),
        toml_original,
        "precondition: installed content is the original standard"
    );

    // Second import with the same UUID but weakened immutable zone.
    let result = app.import_voucher_standard(toml_weakened.as_bytes(), None, &standards_dir);

    assert!(
        result.is_err(),
        "AUDIT-M03-004 SILENT OVERWRITE: importing a divergent standard under an \
         already-installed UUID returned Ok({:?}) and silently replaced the \
         installation. Existing vouchers bound to the previous hash are bricked \
         and newly created ones escape the original rules. Expected: Err(...) \
         (conflict detection, fail-closed).",
        result
    );
    assert_eq!(
        fs::read_to_string(&installed_file).expect("installed standard still readable"),
        toml_original,
        "AUDIT-M03-004 SILENT OVERWRITE: the installed standard.toml was replaced by \
         the divergent clone. The bytes of the originally installed standard must \
         remain untouched."
    );
}

/// CONTROL: re-importing BYTE-IDENTICAL content for an already-installed UUID
/// remains a legitimate idempotent operation (must stay Ok after remediation).
#[test]
fn control_reimport_of_identical_standard_content_stays_allowed() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let standards_dir = dir.path().join("voucher_standards");
    let app = AppService::new(dir.path()).expect("AppService::new failed");
    let issuer = test_issuer();

    let toml_a = signed_standard_toml("audit-m03-0004-ctrl-uuid", "Standard A", 2, &issuer);

    app.import_voucher_standard(toml_a.as_bytes(), None, &standards_dir)
        .expect("initial import failed");

    let second = app.import_voucher_standard(toml_a.as_bytes(), None, &standards_dir);
    assert_eq!(
        second.as_deref(),
        Ok("audit-m03-0004-ctrl-uuid"),
        "Idempotent re-import of identical standard content must remain allowed"
    );
}

// ===========================================================================
// FINDING AUDIT-M03-006 — numeric domain drift in json_to_cel
// (triaged FALSE POSITIVE / PROTECTED — regression controls)
// ===========================================================================
//             Finding-ID:  AUDIT-M03-006
//                         "Int/UInt/f64 Coercion with Precision Loss in json_to_cel"
//             Severity:   MEDIUM (hypothesis) -> triaged NOT VULNERABLE
//             CWE:        CWE-681 "Incorrect Conversion between Numeric Types"
//                         (candidate)
//             Target:     `DynamicPolicyEngine::json_to_cel`
//                         (`src/services/dynamic_policy_engine.rs`)
//             Triage
//             Rationale:  Manual verification of cel-interpreter 0.10.0 and cel-parser
//                         0.10 shows the suspected silent degradation does NOT occur:
//                         (1) `json_to_cel` maps i64 -> Int, then u64 -> UInt (EXACT,
//                         no f64 detour; the f64 branch is only reachable for JSON
//                         numbers that are genuinely fractional/exponent — serde_json's
//                         as_i64/as_u64 reject those first). (2) cel-interpreter's
//                         `PartialEq`/`PartialOrd` for Int<->UInt are implemented via
//                         exact `try_into` conversions, NOT f64 casts; only Float
//                         pairings cast. (3) Plain integer literals parse strictly as
//                         i64 — a magnitude beyond i64::MAX requires an explicit `u`
//                         suffix, so accidental cross-domain literal comparisons fail
//                         loudly at compile time instead of silently coercing.
//                         The remaining theoretical divergence (pre-check serde_json
//                         Number equality vs interpreter cross-type equality) can only
//                         activate if genuinely FLOAT-typed fields ever enter voucher
//                         state; all model fields are Strings or small integers today.
//                         Domain pinning against float ingress is covered by the
//                         canonicalization/serialization guarantees (AGENTS.md) and
//                         module-level determinism requirements.
//             Test
//             Semantics:  CONTROL/REGRESSION tests (green before and after): pin down
//                         the EXACT numeric preservation guarantees so any future
//                         regression inside `json_to_cel` or an upgraded cel-interpreter
//                         is caught immediately.

/// u64::MAX in voucher state must map to Value::UInt EXACTLY and compare
/// exactly against a matching `u`-suffixed CEL literal (no f64 rounding,
/// although u64::MAX > 2^53 cannot be represented by an f64 mantissa).
#[test]
fn control_u64_max_value_preserved_exactly_without_float_detour() {
    let voucher = json!({ "big": 18_446_744_073_709_551_615u64 });

    let result =
        DynamicPolicyEngine::evaluate_rule("Voucher.big == 18446744073709551615u", &voucher, None);

    assert_eq!(
        result,
        Ok(true),
        "AUDIT-M03-006 REGRESSION: u64::MAX lost exactness while crossing \
         json_to_cel or literal parsing — a float detour would corrupt the \
         comparison (f64 cannot represent 2^64-1)."
    );

    // Off-by-one must be distinguished: exactness, not approximate equality.
    let result_off_by_one = DynamicPolicyEngine::evaluate_rule(
        "Voucher.big == 18446744073709551614u",
        &voucher,
        None,
    );
    assert_eq!(
        result_off_by_one,
        Ok(false),
        "AUDIT-M03-006 REGRESSION: adjacent u64 values compared equal — the \
         mapping degraded to a lossy representation."
    );
}

/// Cross-type comparisons between UInt state values and i64 literals must use
/// exact conversions (cel-interpreter `try_into` semantics), staying correct
/// at the i64::MAX boundary.
#[test]
fn control_cross_type_uint_vs_int_comparison_is_exact() {
    let voucher = json!({ "big": 18_446_744_073_709_551_615u64 });

    // u64::MAX > i64::MAX must hold exactly (no f64 collapse, which would
    // render both sides equal).
    let greater = DynamicPolicyEngine::evaluate_rule(
        "Voucher.big > 9223372036854775807",
        &voucher,
        None,
    );
    assert_eq!(greater, Ok(true), "UInt-vs-Int boundary comparison broke");

    let equal_wrongly = DynamicPolicyEngine::evaluate_rule(
        "Voucher.big == 9223372036854775807",
        &voucher,
        None,
    );
    assert_eq!(
        equal_wrongly,
        Ok(false),
        "UInt(i64::MAX+..) must never equal i64::MAX under exact conversion"
    );
}

/// Genuinely fractional JSON numbers take the documented f64 path and stay
/// deterministic; this documents (does not weaken) the intended mapping.
#[test]
fn control_fractional_json_numbers_map_to_cel_float_deterministically() {
    let voucher = json!({ "ratio": 2.5 });

    let result = DynamicPolicyEngine::evaluate_rule("Voucher.ratio == 2.5", &voucher, None);
    assert_eq!(result, Ok(true), "Fractional mapping to CEL Float broke");
}

// ===========================================================================
// CONTROL TESTS — correct behavior that MUST be preserved by remediation.
// All green on unpatched code.
// ===========================================================================

/// Dot attribute access over MISSING fields already raises `NoSuchKey`
/// evaluation errors -> fail-closed today. This documents the dangerous
/// ASYMMETRY between dot and bracket resolution that Finding 01 exploits.
#[test]
fn control_dot_access_over_missing_fields_already_fails_closed() {
    let voucher = voucher_state_minimal();
    let tx = tx_state_without_sender();

    for expr in [
        "Voucher.valid_until != ''",
        "Voucher.collateral.type != 'unbacked'",
        "Transaction.sender_id != 'did:key:EVIL'",
    ] {
        let tx_ref = if expr.starts_with("Transaction") { Some(&tx) } else { None };
        let result = DynamicPolicyEngine::evaluate_rule(expr, &voucher, tx_ref);
        assert!(
            matches!(result, Err(PolicyEngineError::EvaluationError(_))),
            "Dot access over a missing field unexpectedly did NOT fail closed: \
             '{expr}' => {:?}",
            result
        );
    }
}

/// Legitimate rules over PRESENT fields (dot and bracket syntax) must continue
/// to work after remediation.
#[test]
fn control_positive_rules_over_present_fields_remain_passable() {
    let voucher = voucher_state_minimal();

    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "Voucher.nominal_value.unit == 'Minuto'",
            &voucher,
            None
        ),
        Ok(true),
        "Legitimate dot rule over a present field broke"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "Voucher['nominal_value']['unit'] == 'Minuto'",
            &voucher,
            None
        ),
        Ok(true),
        "Legitimate bracket rule over a present field broke"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule("Voucher.nominal_value.amount != ''", &voucher, None),
        Ok(true),
        "Negated rule over a PRESENT field must still legitimately pass"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "check_decimals(Voucher.nominal_value.amount, 3)",
            &voucher,
            None
        ),
        Ok(true),
        "Valid check_decimals usage broke"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "check_decimals(Voucher.nominal_value.amount, 2)",
            &voucher,
            None
        ),
        Ok(false),
        "check_decimals must keep rejecting excessive decimals"
    );
}

/// Ordering comparisons against a MISSING field already fail closed today
/// (`ValuesNotComparable`), unlike the equality family exploited above.
#[test]
fn control_ordering_comparison_over_missing_field_already_fails_closed() {
    let voucher = voucher_state_minimal();

    let result =
        DynamicPolicyEngine::evaluate_rule("Voucher['valid_until'] > '2020-01-01'", &voucher, None);

    assert!(
        matches!(result, Err(PolicyEngineError::EvaluationError(_))),
        "Ordering over missing field unexpectedly did not error: {:?}",
        result
    );
}

/// A rule referencing a COMPLETELY UNBOUND context variable (`Transaction` not
/// registered because transaction_state was None) already fails closed today.
#[test]
fn control_unbound_context_variable_still_fails_closed() {
    let voucher = voucher_state_minimal();

    let result = DynamicPolicyEngine::evaluate_rule(
        "Transaction.amount <= '100'",
        &voucher,
        None, // Transaction intentionally not provided
    );

    assert!(
        matches!(result, Err(PolicyEngineError::EvaluationError(_))),
        "Rule referencing unbound 'Transaction' variable must error, got: {:?}",
        result
    );
}

/// AUDIT-M03-003 remediation control: legitimate NUMERIC ordering predicates
/// (both operands JSON numbers, e.g. computed via `size()`) must remain fully
/// functional after the fail-closed guard is introduced. Only ordering over
/// non-numeric operands may be rejected.
#[test]
fn control_numeric_ordering_predicates_remain_functional() {
    let voucher_one_sig = voucher_state_minimal(); // signatures.len() == 1

    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "size(Voucher.signatures) < 2",
            &voucher_one_sig,
            None
        ),
        Ok(true),
        "Numeric `<` over sizes must keep evaluating normally"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "size(Voucher.signatures) <= 0",
            &voucher_one_sig,
            None
        ),
        Ok(false),
        "Numeric `<=` must keep correctly rejecting"
    );
}

// ===========================================================================
// FINDING AUDIT-M03-005 — exploit proofs (RED on unpatched code)
// ===========================================================================

/// Deeply nested rule expressions must be rejected with a normal `Err`, never
/// abort the process. SECURE INVARIANT: evaluating a (possibly hostile)
/// signed standard's CEL rule must not kill the whole wallet via stack
/// overflow — cel-parser/cel-interpreter recursion overflows the thread stack
/// at surprisingly small nesting depths (measured: depth 12 survives, depth
/// 16 SIGABRTs), and a stack overflow is an uncatchable process abort.
#[test]
fn finding05_deeply_nested_expression_must_err_not_abort() {
    let voucher = voucher_state_minimal();
    // Comfortably inside the measured crash zone (> 16).
    let expression = format!("{}1{}", "(".repeat(64), ")".repeat(64));

    let result =
        DynamicPolicyEngine::evaluate_rule(&expression, &voucher, None);

    assert!(
        matches!(result, Err(PolicyEngineError::CompilationError(_))),
        "AUDIT-M03-005 RESOURCE EXHAUSTION: deeply nested expression did not \
         return a graceful CompilationError; got {:?}. On unpatched code this \
         test ABORTS the process with a stack overflow instead of failing.",
        result
    );
}

/// Comprehensions over attacker-influenced arrays must respect a strict
/// iteration budget. The engine clones the ENTIRE environment per iteration
/// (`loop_env = env.clone()`), so cost is O(n²) in the array size — CPU and
/// memory exhaustion for large lists. SECURE INVARIANT: evaluation must
/// terminate with Err when the deterministic iteration budget is exceeded.
///
/// NOTE: The original wall-clock assertion (`elapsed < 5s`) was removed as
/// redundant and inherently flaky: since AUDIT-M03-005 remediation the budget
/// is enforced by a deterministic per-evaluation iteration counter, so the
/// `Err(EvaluationError)` assertion below fully proves the invariant without
/// depending on scheduler load.
#[test]
fn finding05_comprehension_over_large_array_must_respect_iteration_budget() {
    let big_items: Vec<serde_json::Value> =
        std::iter::repeat_n(json!({ "x": 1 }), 5_000).collect();
    let voucher = json!({ "items": big_items });

    let result = DynamicPolicyEngine::evaluate_rule(
        "Voucher.items.all(i, i.x == 1)",
        &voucher,
        None,
    );

    assert!(
        matches!(result, Err(PolicyEngineError::EvaluationError(_))),
        "AUDIT-M03-005 RESOURCE EXHAUSTION: comprehension over a 5_000-element \
         array returned {:?} instead of a budget error. Environment cloning per \
         iteration makes this O(n²) in attacker-influenced list size.",
        result
    );
}

// ===========================================================================
// WAVE 3 ADDITIONS (Security Audit Wave 3, Phase B)
// ===========================================================================

use human_money_core::services::voucher_validation::verify_standard_identity;

// ===========================================================================
// FINDING AUDIT-M03-007 — exploit proof (RED on unpatched code)
// Wave-3 hypothesis: WH3-03-301
// ===========================================================================

/// WH3-03-301 / AUDIT-M03-007 — CRITICAL.
///
/// Finding-ID:  AUDIT-M03-007
///             "Uncatchable `todo!()` Process Abort Instead of Fail-Closed
///             Error for CEL Comprehensions over Non-Array Ranges"
/// Severity:   CRITICAL
/// CWE:        CWE-248 "Uncaught Exception" (primary);
///             CWE-636 "Not Failing Securely (Failing Open)" (secondary);
///             CWE-754 "Improper Check for Unusual or Exceptional Conditions"
///             (secondary)
/// Target:     `DynamicPolicyEngine::eval_and_check_ast`, arm
///             `Expr::Comprehension`, ELSE-branch
///             (`src/services/dynamic_policy_engine.rs`, ~L559-561: every
///             non-array range silently yields `Ok(JsonValue::Null)` WITHOUT
///             visiting accu_init/loop_cond/loop_step/result children);
///             panic source: cel-interpreter 0.10.0 `src/objects.rs`
///             (~L702, `t => todo!("Support ...")` for any range that is
///             neither List nor Map).
/// Threat
/// Model:      `all`/`exists`/`map`/`filter` are syntactic macros that desugar
///             for ANY target expression (cel-parser macros accept every
///             target). A signed standard rule such as `'abc'.all(x, x=='a')`
///             — or realistically `Voucher.nominal_value.unit.all(c, c=='M')`
///             over the plain String field `unit` carried by essentially every
///             Minuto-style standard — passes the engine's AST pre-check
///             untouched (non-array range -> Ok(Null) skip) and then reaches
///             the real interpreter, whose unfinished comprehension branch
///             panics during `program.execute`.
/// Impact:     The panic is not convertible into `Err`: it tears down the
///             validating call stack and kills the whole wallet process while
///             validating create/receive/transfer against such a standard
///             (the rules.rs consumer path installs no catch_unwind). Tiny
///             expressions suffice — the M03-005 length/depth budgets cannot
///             intercept them. Direct violation of audit invariant #2
///             (Fail-Closed Principle) and of the project-wide
///             no-panic-on-untrusted-input principle.
/// Root Cause: The pre-check's Comprehension arm treats every non-array range
///             as vacuously evaluable (Ok(Null), children skipped) although
///             cel-interpreter supports ONLY List and Map ranges and panics
///             via `todo!()` on everything else — a library TODO surfaced as
///             a remote process-abort primitive through signed standards.
/// Remediation: Fail closed in the engine: in the Comprehension arm, return
///             `Err(PolicyEngineError::EvaluationError("unsupported
///             comprehension range type"))` for ranges that are neither
///             `JsonValue::Array` nor `JsonValue::Object` (and validate
///             children for map ranges). No legitimate business rule
///             comprehends over scalars.
/// Test
/// Semantics:  RED on unpatched code: evaluation PANICS inside
///             `program.execute`; `std::panic::catch_unwind` converts the
///             panic into a failing assertion so this test FAILS (proving
///             the vulnerability) instead of killing the test process.
///             GREEN after remediation (graceful
///             `Err(PolicyEngineError::_)` returned).
#[test]
fn finding07_comprehension_over_non_array_range_must_err_not_panic() {
    // Trigger A: pure literal range — no voucher state required at all.
    let literal_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        DynamicPolicyEngine::evaluate_rule("'abc'.all(x, x == 'a')", &json!({}), None)
    }));

    match literal_result {
        Err(payload) => panic!(
            "AUDIT-M03-007 PROCESS ABORT: evaluating \"'abc'.all(x, x == 'a')\" PANICKED \
             instead of returning a graceful error (panic payload: {:?}). The interpreter's \
             unfinished todo!() comprehension branch turns a signed standard rule into an \
             uncatchable process kill during voucher validation. Expected: \
             Err(PolicyEngineError::_) (fail-closed).",
            payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<opaque panic payload>")
        ),
        Ok(Ok(_)) => panic!(
            "AUDIT-M03-007 FAIL-OPEN: \"'abc'.all(x, x == 'a')\" evaluated to Ok(_) although \
             comprehending over a string range is unsupported — must be Err(...) \
             (fail-closed)."
        ),
        Ok(Err(_)) => {} // secure fail-closed behavior
    }

    // Trigger B: realistic Minuto-shaped state — `nominal_value.unit` is a
    // plain String field present in essentially every real-world standard.
    let voucher = voucher_state_minimal();
    let state_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        DynamicPolicyEngine::evaluate_rule(
            "Voucher.nominal_value.unit.all(c, c == 'M')",
            &voucher,
            None,
        )
    }));

    match state_result {
        Err(payload) => panic!(
            "AUDIT-M03-007 PROCESS ABORT: comprehension over the plain String field 'unit' \
             PANICKED (panic payload: {:?}) instead of failing closed. Every voucher carrying \
             a string-typed unit would crash the whole wallet during routine validation. \
             Expected: Err(PolicyEngineError::_) (fail-closed).",
            payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("<opaque panic payload>")
        ),
        Ok(Ok(_)) => panic!(
            "AUDIT-M03-007 FAIL-OPEN: comprehension over a string-typed field evaluated to \
             Ok(_) — must be Err(...) (fail-closed)."
        ),
        Ok(Err(_)) => {} // secure fail-closed behavior
    }
}

// ===========================================================================
// FINDING AUDIT-M03-008 — exploit proof (RED on unpatched code)
// Wave-3 hypothesis: WH3-03-302
// ===========================================================================

/// WH3-03-302 / AUDIT-M03-008 — HIGH.
///
/// Finding-ID:  AUDIT-M03-008
///             "Non-Deterministic Policy Verdicts via Map-Literal Comprehension
///             over RandomState HashMap Iteration (plus Pre-Check Budget Bypass)"
/// Severity:   HIGH
/// CWE:        CWE-758 "Reliance on Undefined, Unspecified, or
///             Implementation-Defined Behavior" (primary);
///             CWE-636 "Not Failing Securely (Failing Open)" (secondary)
/// Target:     cel-interpreter 0.10.0 `src/objects.rs` (~L692-701): the
///             `Value::Map` comprehension branch iterates
///             `map.map.deref().keys()` over a raw `HashMap<Key, Value>`
///             built with the default `RandomState`, so key order rotates per
///             map instance; combined with the engine pre-check skip for
///             non-array ranges (see AUDIT-M03-007), the interpreter verdict
///             became final and order-dependent.
/// Threat
/// Model:      Map LITERALS inside rule expressions are legitimate, signed
///             CEL syntax (`{'a':1,'b':2}.map(k, k)`). Every evaluation
///             instantiates a fresh HashMap whose key iteration order differs
///             per instance (std rotates the SipHash keys per RandomState),
///             so order-sensitive verdicts flip between retries, processes
///             and platforms.
/// Impact:     Violates audit invariant #1 (100% deterministic evaluation):
///             the SAME signed rule yields different Ok(bool) verdicts across
///             repeated validations of identical state — a transfer rejected
///             once can PASS on retry (fail-open direction).
/// Test
/// Design      WAVE-3 FIX-PHASE CORRECTION: the original Phase-B design
/// Rationale:  compared ONE map instance against ONE fixed expected order
///             (`{'a':1,...,'f':6}.map(k,k) == ['a',..,'f']`). That probe has
///             detection probability 1/6! (~0.14%) per evaluation — measured
///             2/256 hits — so 64 repetitions almost always observed uniform
///             Ok(false) and the test passed on VULNERABLE code (false-
///             negative test design, not a false-positive vulnerability).
///             SHARPENED probe: TWO INDEPENDENT map literals inside one
///             expression are two independent HashMap instances; their list
///             equality is true iff both iterate in the same order (~50% for
///             2 keys, measured 34/64 mixed outcomes on unpatched code).
/// Semantics:  RED on unpatched code: repeating the identical rule mixes
///             Ok(true)/Ok(false) -> the uniformity assertion FAILS and
///             proves non-determinism. GREEN after remediation: results are
///             uniformly one bool OR uniformly Err (fail-closed is an
///             accepted outcome; AUDIT-M03-007 remediation rejects map ranges
///             outright because HashMap ordering cannot be made deterministic
///             at engine level without vendoring the interpreter).
#[test]
fn finding08_map_literal_comprehension_must_be_deterministic_or_fail_closed() {
    // Two separate map literals -> two independent RandomState-seeded HashMap
    // instances per evaluation; equality holds only when both happen to
    // iterate identically (~coin flip for 2 keys).
    const RULE: &str = "{'a':1,'b':2}.map(k, k) == {'a':1,'b':2}.map(k, k)";
    let empty_state = json!({});

    let mut saw_true = false;
    let mut saw_false = false;

    for _ in 0..64 {
        match DynamicPolicyEngine::evaluate_rule(RULE, &empty_state, None) {
            // Uniform fail-closed rejection is an ACCEPTABLE remediated outcome;
            // only MIXED boolean verdicts prove non-determinism.
            Err(_) => {}
            Ok(true) => saw_true = true,
            Ok(false) => saw_false = true,
        }
    }

    assert!(
        !(saw_true && saw_false),
        "AUDIT-M03-008 NONDETERMINISM: the identical signed rule {:?} produced BOTH \
         Ok(true) and Ok(false) across repeated evaluations against the same empty \
         state. Map-literal comprehensions iterate a RandomState HashMap whose order \
         rotates per instance, so policy verdicts flip between retries — a \
         once-rejected transfer can pass on re-validation (fail-open). Expected: \
         uniform result across all repetitions, or uniform Err (fail-closed).",
        RULE
    );
}

/// CONTROL for AUDIT-M03-007/-008 remediation: legitimate comprehensions over
/// ARRAY ranges (the only supported range domain) must remain fully
/// functional after non-array ranges are rejected fail-closed.
#[test]
fn control_array_comprehensions_remain_functional() {
    let voucher = voucher_state_minimal(); // signatures: [{role:"creator"}]

    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "Voucher.signatures.all(s, s.role == 'creator')",
            &voucher,
            None
        ),
        Ok(true),
        "Legitimate all() over an array range broke after M03-007/-008 remediation"
    );
    assert_eq!(
        DynamicPolicyEngine::evaluate_rule(
            "Voucher.signatures.exists(s, s.role == 'guarantor')",
            &voucher,
            None
        ),
        Ok(false),
        "Legitimate exists() over an array range broke after M03-007/-008 remediation"
    );
}

// ===========================================================================
// FINDING AUDIT-M03-009 — exploit proof (RED on unpatched code)
// Wave-3 hypothesis: WH3-03-303
// ===========================================================================

/// WH3-03-303 / AUDIT-M03-009 — HIGH.
///
/// Finding-ID:  AUDIT-M03-009
///             "Path Traversal / Absolute Path Injection via Unsanitized
///             `immutable.identity.uuid` During Standard Import"
/// Severity:   HIGH
/// CWE:        CWE-22 "Improper Limitation of a Pathname to a Restricted
///             Directory ('Path Traversal')" (primary);
///             CWE-36 "Absolute Path Traversal" (secondary)
/// Target:     `AppService::import_voucher_standard`
///             (`src/app_service/standard_container_handler.rs`, ~L142-148:
///             `target_dir.join(&standard_uuid)` + `fs::create_dir_all` +
///             atomic write, with NO validation of `standard_uuid`); contrast:
///             `delete_voucher_standard` of the SAME file explicitly guards
///             `'/'`, `'\\'`, `".."` (~L201-210). Source of the unsanitized
///             value: `ImmutableIdentity.uuid: String`
///             (`src/models/voucher_standard_definition.rs`, free-form String,
///             no UUIDv4/format check in model or in
///             `verify_and_parse_standard`).
/// Threat
/// Model:      `.standard` bundles are untrusted distributed files (same
///             threat model as AUDIT-M03-004): any key can self-sign a valid
///             standard, so signature validity provides ZERO assurance about
///             the uuid string. An attacker ships a bundle with
///             `uuid = "../probe"` (relative escape) or an absolute path
///             (`Path::join` semantics REPLACE the base directory entirely).
/// Impact:     Arbitrary directory creation + `standard.toml` placement at
///             attacker-chosen locations within the process's write
///             permissions: filesystem integrity violation, standards-tree
///             pollution, planting files into host-app-scanned import folders.
///             The M03-004 conflict guard protects only EXISTING targets —
///             newly created paths outside the configured root are entirely
///             unprotected. Installation must stay confined to the configured
///             voucher_standards root (audit invariant #3 beyond the hash
///             chain).
/// Root Cause: Asymmetric input validation: the delete path treats standard
///             IDs as untrusted path components while the import path trusts
///             the uuid from the parsed file blindly.
/// Remediation: Validate the uuid at import time with the SAME guard class as
///             deletion (reject empty, `/`, `\\`, `..`; ideally enforce a
///             strict UUIDv4 format) before any filesystem operation,
///             fail-closed.
/// Test
/// Semantics:  RED on unpatched code: import returns Ok and creates directories
///             OUTSIDE the standards tree (relative escape) / at the
///             attacker-chosen absolute location -> both rejection assertions
///             FAIL. GREEN after remediation (import errs, no stray paths). A
///             benign-import precondition control proves the machinery works;
///             signature self-consistency of hostile-uuid bundles is proven
///             via `verify_and_parse_standard` to show signatures cannot be
///             the mitigating factor.
#[test]
fn finding09_import_must_reject_path_traversal_and_absolute_uuid() {
    let dir = tempfile::tempdir().expect("tempdir failed");
    // Nested one level below the wallet root so the "../" escape demonstrably
    // leaves the voucher_standards tree while staying inside the tempdir.
    let standards_dir = dir.path().join("data").join("voucher_standards");
    let app = AppService::new(dir.path()).expect("AppService::new failed");
    let issuer = test_issuer();

    // PRECONDITION CONTROL: benign uuid installs normally (import machinery
    // functional in this environment).
    let benign = signed_standard_toml("audit-m03-0009-benign", "Benign Probe", 2, &issuer);
    app.import_voucher_standard(benign.as_bytes(), None, &standards_dir)
        .expect("precondition: benign import must succeed");

    // --- Variant A: RELATIVE traversal escaping the standards tree ---------
    let toml_traversal =
        signed_standard_toml("../m03_w3_escape_probe", "Escape Probe", 2, &issuer);
    assert!(
        VoucherStandardDefinition::from_toml(&toml_traversal).is_ok(),
        "precondition: traversal-uuid standard must be self-consistently signed — \
         signature validity alone cannot reject hostile uuids"
    );
    let res_traversal =
        app.import_voucher_standard(toml_traversal.as_bytes(), None, &standards_dir);
    assert!(
        res_traversal.is_err(),
        "AUDIT-M03-009 PATH TRAVERSAL: import accepted uuid '../m03_w3_escape_probe' \
         and returned Ok({res_traversal:?}). The import path joins the unsanitized \
         immutable.identity.uuid into the filesystem while delete_voucher_standard \
         explicitly rejects '/', backslash and '..' — asymmetric protection. \
         Expected: Err(...) (fail-closed)."
    );
    assert!(
        !standards_dir.parent().unwrap().join("m03_w3_escape_probe").exists(),
        "AUDIT-M03-009 PATH TRAVERSAL: directory '{}' was created OUTSIDE the \
         voucher_standards tree. Installation must stay confined to the configured root.",
        standards_dir.parent().unwrap().join("m03_w3_escape_probe").display()
    );

    // --- Variant B: ABSOLUTE path injection (join replaces the base) --------
    let abs_probe = dir.path().join("m03_w3_abs_probe");
    let toml_absolute = signed_standard_toml(
        abs_probe.to_str().expect("utf-8 temp path"),
        "Absolute Probe",
        2,
        &issuer,
    );
    assert!(
        VoucherStandardDefinition::from_toml(&toml_absolute).is_ok(),
        "precondition: absolute-path-uuid standard must be self-consistently signed"
    );
    let res_absolute =
        app.import_voucher_standard(toml_absolute.as_bytes(), None, &standards_dir);
    assert!(
        res_absolute.is_err(),
        "AUDIT-M03-009 ABSOLUTE PATH INJECTION: import accepted absolute uuid '{}' \
         (Path::join semantics replace the base directory entirely). Expected: \
         Err(...) (fail-closed).",
        abs_probe.display()
    );
    assert!(
        !abs_probe.exists(),
        "AUDIT-M03-009 ABSOLUTE PATH INJECTION: attacker-chosen absolute location '{}' \
         was created and populated with standard.toml.",
        abs_probe.display()
    );
}

// ===========================================================================
// FINDING AUDIT-M03-010 — exploit proof (RED on unpatched code)
// Wave-3 hypothesis: WH3-03-304
// ===========================================================================

/// WH3-03-304 / AUDIT-M03-010 — MEDIUM.
///
/// Finding-ID:  AUDIT-M03-010
///             "No Usage-Time Re-Verification of Installed Standards: Mutable
///             Zone Rewrite & Signature Strip Stay Invisible"
/// Severity:   MEDIUM
/// CWE:        CWE-347 "Improper Verification of Cryptographic Signature"
///             (primary — signature is verified exactly once, at import, and
///             never again in the entire usage path);
///             CWE-345 "Insufficient Verification of Data Authenticity"
///             (secondary)
/// Target:     `verify_standard_identity`
///             (`src/services/voucher_validation/identity.rs`, L7-27: checks
///             ONLY uuid equality + `H(canonical [immutable])` against the
///             voucher's `standard_definition_hash`; no signature presence or
///             validity check at use time). Sole verification point remains
///             `verify_and_parse_standard` (standard_manager.rs) during
///             import (`standard_container_handler.rs`).
/// Threat
/// Model:      After installation, the file content under
///             `voucher_standards/<uuid>/standard.toml` can be modified by
///             local malware, cloud-sync folder swaps or accidental editing,
///             WITHOUT any invariant reacting: (a) the `[mutable]` zone
///             (issuer_name, homepage_url, i18n contract texts, app_config)
///             is NOT bound by the immutable-zone hash, so displayed issuer
///             identity/contract terms/links can be rewritten for phishing;
///             (b) even the `[signature]` block itself can be stripped or
///             garbage-replaced — no load/use-time check enforces signature
///             presence or validity.
/// Impact:     Display/phishing integrity attack over the whole lifetime of
///             an installed standard; the cryptographic trust anchor silently
///             degrades to "verified once, never again". Violates audit
///             invariant #3 (Immutability & Integrity) across the lifecycle:
///             integrity holds only at import time, not in operation.
///             (Immutable-ZONE swaps, by contrast, ARE caught accidentally by
///             the hash comparison — the gap is mutable zone + signature.)
/// Root Cause: Trust anchor placed exclusively at import time;
///             `verify_standard_identity` was never designed as a
///             defense-in-depth gate for signature/mutable authenticity and
///             there is no other verifying load path.
/// Remediation: At minimum, defense-in-depth at the identity gate: reject
///             definitions lacking a present-and-valid issuer signature
///             (re-check Ed25519 over canonical content) whenever a standard
///             definition enters validation. If mutable-zone flexibility is
///             intentional design, pin it via explicit trust-boundary docs
///             AND still enforce signature presence/validity at every load.
/// Test
/// Semantics:  RED on unpatched code: after rewriting `[mutable.metadata]`
///             (issuer_name/homepage_url -> phishing values) and setting
///             `signature = None`, usage-time verification returns Ok(())
///             -> the rejection assertion FAILS, proving the gap. GREEN after
///             remediation (Err returned). Baseline control inside the test
///             pins that the PRISTINE definition passes, isolating the fault
///             to the missing re-verification rather than setup errors.
#[test]
fn finding10_usage_time_identity_check_must_reject_tampered_mutable_zone_and_stripped_signature()
{
    let issuer = test_issuer();
    let toml = signed_standard_toml("audit-m03-0010-uuid", "Integrity Probe", 2, &issuer);

    let (mut def, logic_hash) =
        VoucherStandardDefinition::from_toml(&toml).expect("precondition: pristine standard verifies");

    // Voucher bound to THIS installation (uuid + immutable-zone hash match).
    let mut voucher = human_money_core::models::voucher::Voucher::default();
    voucher.voucher_standard.uuid = def.immutable.identity.uuid.clone();
    voucher.voucher_standard.standard_definition_hash = logic_hash;

    // Baseline control: pristine definition must pass usage-time identity.
    assert!(
        verify_standard_identity(&voucher, &def).is_ok(),
        "precondition: pristine definition must pass verify_standard_identity"
    );

    // Post-import tampering (local malware / cloud-sync folder swap): rewrite
    // displayed contract metadata into phishing values AND strip the issuer
    // signature block entirely.
    def.mutable.metadata.issuer_name = "EVIL Phishing Issuer".to_string();
    def.mutable.metadata.homepage_url = Some("https://evil.example/clone".to_string());
    def.signature = None;

    let result = verify_standard_identity(&voucher, &def);

    assert!(
        result.is_err(),
        "AUDIT-M03-010 USAGE-TIME INTEGRITY GAP: verify_standard_identity accepted a \
         definition whose [mutable] zone was rewritten (issuer_name/homepage_url set to \
         phishing values) and whose issuer signature was stripped AFTER import. The \
         Ed25519 signature is checked exactly once (import); the usage-time identity \
         gate re-checks only uuid + immutable hash, so mutable-zone phishing content \
         and signature removal remain invisible for the lifetime of the installation. \
         Expected: Err(...) (defense-in-depth enforcement at usage time). Got Ok(())."
    );
}
