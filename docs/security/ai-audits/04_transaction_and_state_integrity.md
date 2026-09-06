# Security Audit: Transaction Logic, State Integrity & Rust Robustness

## AI Auditor Role & System Invariants

You are a senior Rust systems engineer and financial ledger security auditor.

### System Context & Threat Model
`human_money_core` manages value transfers, splitting, and merging of vouchers.
1. **Conservation of Value:** $\sum \text{Inputs} = \sum \text{Outputs} + \text{Fees}$. Value can NEVER be created out of thin air. Negative amounts, precision underflows, and arithmetic overflows must be mathematically impossible.
2. **Split Anchor Separation:** In split transactions, the transfer branch and the change branch MUST have cryptographically independent ephemeral keys and anchor commitments ($Key_{\text{Receiver}} \neq Key_{\text{Change}}$).
3. **Panic-Freedom on Untrusted Inputs:** The library processes untrusted binary/TOML bundles from external networks and peers. The core engine MUST NEVER panic (`unwrap()`, `expect()`, out-of-bounds indexing) on malformed or malicious inputs.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/bundle_processor.rs`
- `src/services/secure_container_manager.rs`
- `src/services/integrity_manager.rs`
- `src/services/decimal_utils.rs`
- `src/models/voucher.rs`
- `src/models/secure_container.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Trace the transaction lifecycle from raw bundle ingestion down to state commitment and split execution.
   - Leverage subagents if broad analysis across container serialization and bundle processing is needed.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Conservation & Rounding Exploits:** Can fractional precision handling or integer conversion in `decimal_utils` allow rounding tricks where total output value exceeds input value?
   - **Split & Change Anchor Overlap:** Is it possible for a malformed split operation to reuse the same seed for both the change anchor and the transfer anchor?
   - **Panic Hazards on Untrusted Data:** Audit all instances of `.unwrap()`, `.expect()`, slice indexing `[i]`, and unchecked conversions in bundle/container decoders.
   - **State Desynchronization:** If bundle processing fails midway through a multi-step operation, can it leave internal stores or archives in an inconsistent state?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. You are encouraged to explore any novel anomaly, unexpected transaction sequence, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write a dedicated Rust test in `tests/security_audit_module_04_integrity.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(result.is_ok())` or `assert!(matches!(res, Err(...)))` without panic).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL / panic), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics).
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.

