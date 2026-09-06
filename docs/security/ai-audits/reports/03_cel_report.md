# Security Audit Report — Module 03: Voucher Standards & CEL Policy Engine

> **Agent:** A-03 · **Phase B (Wave 2, sequential)** · Stand: 2026-08-24
> **Test file:** `tests/security_audit_module_03_cel.rs`
> **Hypotheses:** `temp/security-hypotheses/module-03.md`
> **Finding-ID scheme:** `AUDIT-M03-0XX` (continues pre-existing numbering 001–002)

---

## 1. Pre-existing coverage (before Wave 2)

| Finding | Title | Outcome |
| :--- | :--- | :--- |
| AUDIT-M03-001 | Fail-open via NULL-coalescing bracket indexing (`Null != x` -> `true`) | Remediated + controls (dot access, OOB indices, unbound variables) |
| AUDIT-M03-002 | Signed-to-unsigned wraparound in `check_decimals` (`-1 as u32`) | Remediated |

## 2. Phase B results (this wave)

Baseline at start: full suite green (537 passed / 3 skipped). Modules 01+02 fixes
(`trap_manager.rs`, `conflict_manager.rs`, `wallet/conflict_handler.rs`,
`voucher_validation/signatures.rs`, `crypto_identity.rs`) and their by-design
`#[ignore]`d tests were untouched. Module suite re-verified green after each
hypothesis; shared-path engine fixes additionally re-verified with the full lib +
integration binaries (498 tests, 3 skipped = other modules' pending ignores).

### AUDIT-M03-003 — Lexicographic string ordering of decimal amounts (fail-open)

- **Hypothesis:** H-03-1 (CRITICAL)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) Rule expressions come from signed `[immutable]` zones but are evaluated against attacker-controlled voucher/transaction state; compromised or socially engineered issuers are in scope — exposed. (2) No offline-forensics capability depends on string ordering. (3) AGENTS.md mandates stable String SERIALIZATION of amounts, but nowhere is lexicographic comparison of those strings documented as intended semantics. (4) Rejecting non-numeric ordering breaks no shipped rule (minuto/template/freetaler use only `filter/size/==/!=/has/in`; numeric ordering stays fully functional).
- **Evidence:** cel-interpreter 0.10.0 `PartialOrd for Value`: `(Value::String(a), Value::String(b)) => Some(a.cmp(b))`. The project's AST pre-check did not implement `<`/`<=`/`>`/`>=` at all (generic catch-all -> Null), so the interpreter verdict became final.
- **Fail-first proof:** `finding03_max_limit_over_string_amount_must_not_pass_for_violating_value` and `finding03_min_limit_over_string_amount_must_not_pass_for_violating_value` FAILED on unpatched code — `Transaction.amount < '9'` passed for `"15"` and `Transaction.amount >= '15'` passed for `"9"` (`Ok(true)`).
- **Fix:** `src/services/dynamic_policy_engine.rs::eval_and_check_ast` — explicit handling of `_<_`, `_<=_`, `_>_`, `_>=_`: delegated to the interpreter ONLY when both operands are JSON numbers; every other combination (notably decimal strings) returns `Err(EvaluationError)` — fail-closed. Serialization formats and serde attributes untouched; authors keep `check_decimals` and exact membership (`in [...]`) for amount domains.
- **Control added:** `control_numeric_ordering_predicates_remain_functional` pins that numeric ordering keeps working after remediation.
- **Status:** CONFIRMED+FIXED.

### AUDIT-M03-004 — Silent overwrite / missing conflict detection on standard import

- **Hypothesis:** H-03-2 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) `.standard` bundles are untrusted distributed files; signature verification is self-consistent by design (issuer_id declared INSIDE the file), so validity alone cannot prevent a swap — exposed. (2) Refusing divergent re-import removes nothing from offline dispute resolution; recovery remains an explicit delete-then-import via the guarded `delete_voucher_standard`. (3) No ADR/design decision documents "silent update on import"; the docstring only describes writing the file. (4) Idempotent re-import of byte-identical content stays allowed; intended upgrades keep an explicit, user-visible path.
- **Fail-first proof:** `finding04_import_same_uuid_divergent_content_must_not_overwrite_installed_standard` FAILED on unpatched code — a second, divergent-but-genuinely-signed standard under the same UUID returned `Ok(uuid)` and replaced the installed file. Both standards were signed IN-TEST against the canonical hash (no `test-utils` bypass), proving signature validity cannot distinguish them.
- **Fix:** `src/app_service/standard_container_handler.rs::import_voucher_standard` — conflict detection before writing: existing byte-identical content -> idempotent success without touching disk; divergent content -> `ValidationError` (fail-closed). Installation is now atomic (temp-file + rename) so a crash can never leave a truncated `standard.toml`.
- **Controls added:** `control_reimport_of_identical_standard_content_stays_allowed` pins the legitimate idempotent flow. All 10 pre-existing handler tests re-verified green.
- **Status:** CONFIRMED+FIXED.

### AUDIT-M03-005 — Missing evaluation budgets (stack overflow & CPU/memory exhaustion)

- **Hypothesis:** H-03-3 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) Expressions originate in signed standards, but malicious/compromised issuers and social-engineered `.standard` files are explicitly in the threat model; evaluation runs on attacker-influenced voucher state — exposed. (2) Budgets remove no forensic capability. (3) "Third-party library without limits" is a known limitation, not a documented design requirement; the project-owned AST pre-check is the natural guard location. (4) Real-world rules nest ~4 deep and iterate over tiny lists; caps far above any legitimate use.
- **Empirical cliff measurement (temporary probes, removed afterwards):** paren nesting depth 12 evaluates fine, depth 16 already SIGABRTs the process with an uncatchable stack overflow inside the third-party parser; unary chains survive to 4096 (see false-positive note below); comprehension over a 10_000-element array took ~31 s and returned `Ok(true)` due to per-iteration environment cloning (`loop_env = env.clone()`, O(n²)).
- **Fail-first proofs:** `finding05_deeply_nested_expression_must_err_not_abort` (hard process ABORT on unpatched code — nextest reported SIGABRT), `finding05_comprehension_over_large_array_must_respect_iteration_budget` (30+ s runtime then `Ok(true)` on unpatched code).
- **Fix:** `src/services/dynamic_policy_engine.rs`:
  - static quote-aware pre-scan `check_expression_budget` BEFORE `Program::compile`: expression length ≤ 4096 chars, structural bracket nesting depth ≤ 8 (safely below the measured parser crash cliff >12, comfortably above realistic rules, wasm32-stack-safe);
  - defense-in-depth recursion cap (512) in the project-owned `eval_and_check_ast`;
  - hard total comprehension-iteration budget (1000) enforced during the strict pre-check, so budget-violating programs never reach the interpreter's second, unbounded pass.
- **False-positive sub-vector:** long unary operator chains do NOT recurse — cel-parser 0.10 collapses consecutive `!` into a single call node (verified via AST dump: `!!true` parses as one `Call("!_", [true])`). The initially planned unary-chain test was removed; no depth risk exists on this parser version.
- **Status:** CONFIRMED+FIXED.

### AUDIT-M03-006 — Int/UInt/f64 coercion precision loss in json_to_cel

- **Hypothesis:** H-03-4 (MEDIUM)
- **Triage outcome:** `[FALSE POSITIVE]` — proven secure, converted to regression controls.
- **Rationale (verified against cel-interpreter 0.10.0 / cel-parser 0.10 sources):**
  1. `json_to_cel` maps i64 -> Int first, u64 -> UInt second (EXACT — no f64 detour). The f64 branch is reachable only for genuinely fractional/exponent JSON numbers, because serde_json's `as_i64`/`as_u64` reject those beforehand.
  2. Cross-type Int<->UInt equality AND ordering in cel-interpreter use exact `try_into` conversions, not f64 casts; only Float pairings cast.
  3. Plain integer literals parse strictly as i64 (`visit_Int`); magnitudes beyond i64::MAX require an explicit `u` suffix — accidental cross-domain literal comparisons fail loudly at compile time instead of silently coercing.
  4. Residual theoretical divergence (pre-check serde_json Number equality vs interpreter cross-type equality) can only activate if FLOAT-typed fields ever enter voucher state; all model fields are Strings or small integers today, and float-free canonicalization is pinned elsewhere (AGENTS.md serialization stability).
- **Tests (controls, expected green):** `control_u64_max_value_preserved_exactly_without_float_detour` (u64::MAX exactness incl. off-by-one discrimination), `control_cross_type_uint_vs_int_comparison_is_exact` (i64::MAX boundary), `control_fractional_json_numbers_map_to_cel_float_deterministically`.
- **Status:** FALSE-POSITIVE (+3 regression-control tests).

## 3. Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-M03-003 | CWE-178 / CWE-636 | `[CONFIRMED VULNERABILITY]` | Lexicographic String-Ordering ließ Betrags-Limits fail-open ("15" < "9" -> true). Keine dokumentierte Designabsicht; Serialisierung bleibt unangetastet. | Engine-Guard: Ordering nur für numerische Operanden; Fail-first Tests + numerischer Control. |
| AUDIT-M03-004 | CWE-284 / CWE-400 | `[CONFIRMED VULNERABILITY]` | Import überschrieb installierte Standards still unter gleicher UUID (Brick/Downgrade); Selbstkonsistenz der Signatur schützt nicht gegen Swap. Idempotenter Re-Import blieb legitimes Bedürfnis. | Konflikt-Detection (byte-identisch = Ok, divergent = Err) + atomarer tmp+rename-Write; Kontrolltest für Re-Import. |
| AUDIT-M03-005 | CWE-400 / CWE-674 | `[CONFIRMED VULNERABILITY]` | Parser-Stack-Overflow bereits ab Klammer-Tiefe ~16 als uncatchable SIGABRT; O(n²)-Comprehension-Kosten ohne Limit. Kein Design-Requirement; projekt-eigene Pre-Check-Schicht als Guard-Ort. Unary-Chains: FALSE POSITIVE (Parser kollabiert zu einem Knoten). | Statischer Pre-Scan (Länge/Tiefe) vor Parse + Rekursions-/Iterations-Budgets im AST-Walk. |
| AUDIT-M03-006 | CWE-681 | `[FALSE POSITIVE]` | u64 bleibt exakt UInt; Int↔UInt-Vergleiche exakt via try_into; Literale >i64::MAX scheitern laut am Compile; f64-Pfad nur für echt gebrochene Zahlen. | 3 Regression-Kontrollen verankern die Exaktheit dauerhaft. |

## 4. Verification

- `cargo nextest run --test security_audit_module_03_cel --status-level fail` → **19 passed / 0 failed** (final state; RED phases documented per finding above).
- Shared-path regression check after engine fixes: `cargo nextest run --lib --test integration_tests --status-level fail` → **498 passed / 3 skipped** (skips are other modules' by-design ignores).

---

# Wave 3 (Security Audit Wave 3, FIX phase — Agent A-03)

> Scope: the four Wave-3 findings WH3-03-301..304 (AUDIT-M03-007..010).
> Baseline at fix start (HEAD b006cfb + A-01/A-02 fixes): 20/23 passed;
> finding07 (panic), finding09 (traversal), finding10 (usage-time gap) RED;
> finding08 unexpectedly GREEN — investigated below.

## AUDIT-M03-007 / WH3-03-301 — `todo!()` process abort for comprehensions over non-array ranges

- **Hypothesis:** WH3-03-301 (CRITICAL)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) CEL rules reach validation from signed-but-attacker-influencable standards against attacker-controlled voucher state — exposed. (2) No offline-forensics capability depends on scalar comprehension. (3) `todo!()` is unfinished third-party library code; no ADR documents a panic surface here. (4) Legitimate rules comprehend over arrays only; failing closed breaks nothing.
- **Evidence:** engine pre-check skipped every non-array range with `Ok(JsonValue::Null)` without visiting comprehension children, so `'abc'.all(x, x == 'a')` and the realistic `Voucher.nominal_value.unit.all(c, c == 'M')` reached cel-interpreter 0.10.0 `objects.rs` (~L702), where any range that is neither List nor Map hits `t => todo!("Support {t:?}")` — an uncatchable process abort during routine voucher validation.
- **Fail-first proof:** `finding07_comprehension_over_non_array_range_must_err_not_panic` FAILED on unpatched code (panic caught via `catch_unwind`, both triggers: pure literal + realistic Minuto string field).
- **Fix:** `src/services/dynamic_policy_engine.rs::eval_and_check_ast`, arm `Expr::Comprehension` (~L537-569): every non-array range now returns `Err(PolicyEngineError::EvaluationError("cannot iterate non-array comprehension range ..."))` BEFORE the interpreter runs — fail-closed instead of panic. Array-range handling (accumulator loop, M03-005 budget) unchanged.
- **Status:** CONFIRMED+FIXED.

## AUDIT-M03-008 / WH3-03-302 — non-deterministic map-literal comprehension verdicts

- **Hypothesis:** WH3-03-302 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — the Phase-B test was a FALSE-NEGATIVE TEST DESIGN, not a false-positive vulnerability.
- **Investigation of the unexpected PASS (mandated):**
  - Root cause of the green result: the original rule compared ONE map instance against ONE fixed expected order (`{'a':1,...,'f':6}.map(k,k) == ['a',...,'f']`). A random permutation matches that one order with probability 1/6! ≈ 0.14 % (standalone probe: 2/256 hits), so 64 repetitions almost always observed uniform `Ok(false)` and the uniformity assertion could never fire.
  - Vulnerability re-proven empirically with a sharpened probe: TWO independent map literals inside one expression are two independently RandomState-seeded `HashMap<Key, Value>` instances; their list equality flips ~50/50 across evaluations (measured 34/64 mixed outcomes on unpatched code). Confirmed against cel-interpreter 0.10.0 `objects.rs` L692-701 (`for key in map.map.deref().keys()` over default-hasher HashMap).
- **Test sharpened:** `finding08_map_literal_comprehension_must_be_deterministic_or_fail_closed` now uses `{'a':1,'b':2}.map(k, k) == {'a':1,'b':2}.map(k, k)` (coin-flip detector, 64 repetitions). RED on unpatched code by construction (mixed Ok(true)/Ok(false)); GREEN after remediation (uniform Err). Docblock documents the design correction.
- **Design decision (important):** sorted-key iteration inside the interpreter would require vendoring/forking cel-interpreter; at ENGINE level map ordering cannot be made deterministic. Therefore the AUDIT-M03-007 fail-closed guard intentionally rejects MAP ranges as well ("map ranges are unsupported because key iteration order is non-deterministic"), which simultaneously closes the zero-budget bypass noted in the hypothesis. Fail-closed is an explicitly accepted outcome of the test invariant.
- **Residual risk documented (out of wave scope):** `Expr::Struct` literals fall into the pre-check's generic catch-all and would panic via `todo!("Support structs!")` inside the INTERPRETER (objects.rs ~L706) — same class as M03-007, candidate for a future wave.
- **Control added:** `control_array_comprehensions_remain_functional` pins that legitimate `all()`/`exists()` over ARRAY ranges keep working after remediation.
- **Status:** CONFIRMED+FIXED (test sharpened, then fixed).

## AUDIT-M03-009 / WH3-03-303 — path traversal / absolute-path injection via import uuid

- **Hypothesis:** WH3-03-303 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) The uuid originates from an untrusted distributed `.standard` file; signature validity says nothing about the string — writes landed OUTSIDE the configured standards root. (2) No offline capability requires traversal uuids. (3) The delete path's own guard (`standard_container_handler.rs`) proves rejecting `/`, `\`, `..` is the project standard; the import-side asymmetry is an oversight. (4) Legitimate uuids never contain separators/traversal tokens or resolve absolutely.
- **Fail-first proof:** `finding09_import_must_reject_path_traversal_and_absolute_uuid` FAILED on unpatched code — relative escape (`../m03_w3_escape_probe`) AND absolute injection both returned `Ok(uuid)` and created directories outside the tree; hostile bundles were proven self-consistently signed beforehand.
- **Fix:** `src/app_service/standard_container_handler.rs::import_voucher_standard` (~L144-160): symmetric sanitizing directly after uuid extraction, BEFORE any filesystem operation — rejects empty ids and any occurrence of `/`, `\`, `..` (absolute paths contain a separator and are rejected implicitly) with `ValidationError`. Mirrors the existing delete-path guard class; conflict detection and atomic write from M03-004 stay unchanged downstream.
- **Status:** CONFIRMED+FIXED.

## AUDIT-M03-010 / WH3-03-304 — no usage-time re-verification of installed standards

- **Hypothesis:** WH3-03-304 (MEDIUM)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) Post-import tampering (local malware, cloud-sync folder swap, accidental edit) is a real lifecycle threat: the mutable zone (issuer_name/homepage_url/i18n contract texts/app_config) was not bound by any use-time check and even the signature block could be stripped invisibly. (2) Re-verification removes no offline capability. (3) Import-time-only anchoring is documented nowhere as intentional; notably the issuer signature covers canonical(immutable+mutable), so re-verifying it binds BOTH zones without touching serialization. (4) Cost is one extra canonicalize+SHA3+Ed25519 per validation — negligible next to the voucher-hash and transaction-signature verifications already in the pipeline.
- **Fail-first proof:** `finding10_usage_time_identity_check_must_reject_tampered_mutable_zone_and_stripped_signature` FAILED on unpatched code — after rewriting `[mutable.metadata]` to phishing values and stripping the signature, `verify_standard_identity` still returned `Ok(())`; pristine-definition baseline control passed.
- **Fix (defense-in-depth at the identity gate):**
  - New `pub fn verify_standard_signature(&VoucherStandardDefinition)` in `src/services/standard_manager.rs` (~L95-150): recomputes the canonical representation WITHOUT signature, decodes/parses the signature block, extracts the issuer key and re-verifies Ed25519 — honoring the `test-utils` bypass exactly like the import-time path.
  - `src/services/voucher_validation/identity.rs::verify_standard_identity` (~L27-35) calls it AFTER uuid + immutable-hash checks (existing error precedence preserved), so every definition entering validation must still carry a present-and-valid signature over its full signed representation. Stripped blocks -> `MissingSignatureBlock`; mutable-zone rewrites (with or without retained stale signature) -> `InvalidSignature`.
- **Regression impact & repair (18 legacy tests):** suites that cloned a signed standard, mutated `[immutable]` and validated WITHOUT re-signing previously relied on the very gap this fix closes (all production entry points — `create_new_voucher`, bundle receive, import — verify signatures before validation, so production flows are unaffected). The affected construction sites were repaired with the purpose-built re-signing helper `test_utils::create_custom_standard` (returns def + logic hash identical to what those sites computed manually): `tests/core_logic/lifecycle.rs` (5 sites), `tests/core_logic/math.rs` (2), `tests/core_logic/privacy_traceability.rs` (1), `tests/core_logic/security/privacy_mode_compliance.rs` (3), `tests/core_logic/security/state_and_collaboration.rs` (3), `tests/core_logic/security/standard_validation.rs::load_required_sig_standard` (1). No assertion semantics were weakened; transaction-signature enforcement untouched (re-signing preferred over bypass flags for exactly that reason).
- **Residual gap documented (out of wave scope):** `amount_decimal_places` (u8) is still not range-checked at import (N3 restgap part c); runtime clamping in the engine keeps it non-exploitable beyond self-inflicted DoS.
- **Status:** CONFIRMED+FIXED.

## Wave-3 Triage Summary

| Finding ID | Wave ID | Suspected CWE | Triage Outcome | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-M03-007 | WH3-03-301 | CWE-248 / CWE-636 | `[CONFIRMED VULNERABILITY]` | Comprehension pre-check rejects non-array ranges fail-closed before the interpreter's `todo!()`. |
| AUDIT-M03-008 | WH3-03-302 | CWE-758 / CWE-636 | `[CONFIRMED VULNERABILITY]` (Phase-B test was false-negative design) | Test sharpened to two-instance coin-flip probe; map ranges rejected fail-closed (engine-level determinism impossible without vendoring). |
| AUDIT-M03-009 | WH3-03-303 | CWE-22 / CWE-36 | `[CONFIRMED VULNERABILITY]` | Import-time uuid guard symmetrical to delete path, before any fs operation. |
| AUDIT-M03-010 | WH3-03-304 | CWE-347 / CWE-345 | `[CONFIRMED VULNERABILITY]` | Usage-time Ed25519 re-verification at identity gate (bypass-aware); 18 legacy test sites re-sign mutated clones via `create_custom_standard`. |

## Wave-3 Verification

- `cargo nextest run --test security_audit_module_03_cel --status-level fail` → **24 passed / 0 failed** (23 baseline tests + 1 new array-comprehension control; finding08 sharpened).
- Mandated regression: `cargo nextest run --test security_audit_module_02_crypto --status-level fail` → **9 passed / 0 failed** (4 skipped by design).
- Full suite isolation run (`cargo nextest run --no-fail-fast`): all failures remaining after my fixes (sa04_*/sa05_*/wildcard_*) reproduce IDENTICALLY in a clean HEAD+A-01/A-02 worktree WITHOUT my src changes — they belong to modules 04/05/wildcard agents' in-flight Wave-3 work. Zero failures attributable to module-03 fixes; core_logic/validation/wallet_api/lib fully green; `cargo check --all-targets` warning-free.
