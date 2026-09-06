# Security Audit: Voucher Standards & Dynamic Policy Engine (CEL)

## AI Auditor Role & System Invariants

You are a security auditor specializing in policy evaluation engines, expression languages (CEL - Common Expression Language), and domain-specific rule validation.

### System Context & Threat Model
Voucher standards in `human_money_core` (defined in TOML according to specification 06) dictate the business rules, validity periods, transferability conditions, demurrage/fees, and guarantor requirements of vouchers.
1. **Deterministic Execution:** CEL evaluation must be 100% deterministic across all platforms (native and wasm32).
2. **Fail-Closed Principle:** If a rule fails to evaluate, encounters missing context variables, or throws an error, the voucher validation MUST strictly fail-closed (reject), never fail-open.
3. **Immutability & Integrity:** A voucher standard definition cannot be swapped or tampered with without breaking the container hash chain or standard verification.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/dynamic_policy_engine.rs`
- `src/services/standard_manager.rs`
- `src/models/voucher_standard_definition.rs`
- `src/app_service/standard_container_handler.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Map out how CEL variables are populated from the voucher state, transaction context, and environment.
   - Spawn subagents to parallelize inspection of the standard definitions and the policy execution pipeline if needed.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Missing Context / Null-Coalescing Exploits:** If optional fields (e.g. `guarantors`, `min_signatures`, `valid_until`) are missing or null in the context map, do rules bypass silently or evaluate to `true`?
   - **Type-Juggling & Precision Loss:** Are timestamps (u64/u128), decimal amounts (`rust_decimal`), or lists coerced unsafely into integers/floats during CEL expression evaluation?
   - **Standard Tampering:** Can an attacker forge a modified standard TOML or inject arbitrary CEL logic into a voucher bundle that bypasses existing restrictions?
   - **Evaluation Timeouts & ReDoS:** Can crafted CEL expressions cause CPU exhaustion or infinite recursion during standard validation?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. You are encouraged to explore any novel anomaly, unexpected rule interaction, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write a dedicated Rust test in `tests/security_audit_module_03_cel.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)**.
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics).
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.

