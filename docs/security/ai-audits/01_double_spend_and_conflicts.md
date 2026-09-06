# Security Audit: Double-Spend Trap, DS-Tags & Conflict Detection

## AI Auditor Role & System Invariants

You are a senior cryptographic security auditor specializing in decentralized, offline-first digital cash systems.

### System Context & Threat Model
`human_money_core` implements a file-based voucher system without a global consensus blockchain. Offline double-spends cannot be prevented in real-time at the moment of physical/file hand-off. Instead, the protocol enforces deterministic post-facto identity unmasking and instant Layer-2 quarantine:
1. **Mathematical Trap (`TrapData` / Slope Calculation):** If the same voucher input state is spent twice with different outputs, the two resulting transaction fingerprints allow anyone to mathematically compute the perpetrator's `did:key` identity ($V = u \cdot m + ID$).
2. **DS-Tag Invariant:** The Double-Spend Tag ($u = \text{Hash}(\text{prev\_hash} + \text{sender\_ephemeral\_pub})$ using SHA3-256) MUST depend **strictly and exclusively on input data**. It MUST NEVER incorporate amounts, recipients, or output parameters.
3. **Deterministic Derivation:** The slope scalar $m$ must be deterministically bound via HKDF ($m = \text{HKDF}(\text{SenderPrivateKey}, \text{prev\_hash}, \text{info}=\text{prefix})$). A non-interactive zero-knowledge proof (Schnorr NIZK) proves knowledge of $m$ without revealing it.
4. **Layer-2 Quarantining & Dispute Proofs:** L2 nodes identify duplicate DS-Tags in $O(1)$, quarantine the affected voucher, and generate signed dispute proofs.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/trap_manager.rs`
- `src/services/conflict_manager.rs`
- `src/app_service/conflict_handler.rs`
- `src/models/conflict.rs`
- `src/services/l2_gateway.rs`
- `src/models/layer2_api.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - If complex sub-tasks or cross-file traces are needed, invoke specialized subagents (e.g. `research` subagents) to map out the exact NIZK verification and DS-tag derivation flow.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Trap Evasion & Framing:** Can a sender modify or omit parameters such that validation passes without valid identity binding or frames an innocent party?
   - **DS-Tag Collision / Manipulation:** Can an attacker spend the same input anchor twice under different identities or prefixes to yield distinct DS-tags and avoid collision?
   - **False Dispute Injection:** Can an attacker forge conflict reports or fake L2 envelopes to trigger an illegitimate voucher quarantine?
   - **Identity Reconstruction Flaws:** Can edge-case scalar values (e.g. division by zero, non-canonical encodings, identical U parameters) cause identity reconstruction to fail or attribute wrong keys?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. You are encouraged to explore any novel anomaly, unexpected transaction state, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - For every suspected bug or bypass, construct an isolated Rust test in `tests/security_audit_module_01_traps.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(validate_voucher(...).is_err())` or `assert!(import_proof(...).is_err())`).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Every reproduction test file must include the standardized metadata docblock (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics).
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.

