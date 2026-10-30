# Security Audit: Transaction Logic, State Integrity & Rust Robustness

## AI Auditor Role & System Invariants

You are a senior Rust systems engineer and financial ledger security auditor.

### System Context & Threat Model
`human_money_core` manages value transfers, splitting, and merging of vouchers.
1. **Conservation of Value:** $\sum \text{Inputs} = \sum \text{Outputs} + \text{Fees}$. Value can NEVER be created out of thin air. Negative amounts, precision underflows, and arithmetic overflows must be mathematically impossible. `rust_decimal` arithmetic bounds must be checked before operations to eliminate panic hazards.
2. **Split Anchor Separation:** In split transactions, the transfer branch and the change branch MUST have cryptographically independent ephemeral keys and anchor commitments ($Key_{\text{Receiver}} \neq Key_{\text{Change}}$).
3. **Panic-Freedom on Untrusted Inputs:** The library processes untrusted binary/TOML bundles from external networks and peers. The core engine MUST NEVER panic (`unwrap()`, `expect()`, out-of-bounds slice indexing) on malformed or malicious inputs.

---

## Target Codebase Scope

Inspect the following files:
- `src/wallet/transactions.rs`
- `src/wallet/coin_selection.rs`
- `src/app_service/transactions.rs`
- `src/services/bundle_processor.rs`
- `src/services/voucher_validation/pipeline.rs`
- `src/services/voucher_validation/chain.rs`
- `src/services/voucher_validation/rules.rs`
- `src/models/voucher.rs`
- `src/models/secure_container.rs`
- `src/storage/integrity.rs`
- `src/services/utils.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Trace the transaction lifecycle from raw bundle ingestion down to state commitment, coin selection, validation pipeline, and split execution.
   - Leverage subagents if broad analysis across container serialization and bundle processing is needed.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Conservation & Rounding Exploits:** Can fractional precision handling, decimal conversion, or rounding quirks allow total output value to exceed input value?
   - **Split & Change Anchor Overlap:** Is it possible for a malformed split operation to reuse the same seed for both the change anchor and the transfer anchor?
   - **Panic Hazards on Untrusted Data:** Audit all instances of `.unwrap()`, `.expect()`, slice indexing `[i]`, and unchecked conversions in bundle/container decoders, validation rules, and transaction staging.
   - **State Desynchronization:** If transaction processing fails midway through a multi-step operation, can it leave internal stores or archives in an inconsistent state?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. Explore any novel anomaly, unexpected transaction sequence, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write a dedicated Rust test in `tests/security_audit_module_04_integrity.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(result.is_ok())` or `assert!(matches!(res, Err(...)))` without panic).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL / panic), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock:
     - `Finding-ID: AUDIT-04-INTEGRITY-[INDEX]`
     - `Severity: CRITICAL | HIGH | MEDIUM | LOW`
     - `CWE-Classification`
     - `Target Location`
     - `Threat Model & Exploitation`
     - `Impact Analysis`
     - `Root Cause`
     - `Remediation Strategy`
     - `Test Semantics (Fail-First)`
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.
