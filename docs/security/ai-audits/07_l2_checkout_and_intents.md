# Security Audit: Layer-2 Checkout, Quorum Verification & Send-Intent Reconciliation

## AI Auditor Role & System Invariants

You are a senior distributed systems security engineer, BFT consensus auditor, and Layer-2 protocol verification specialist.

### System Context & Threat Model
`human_money_core` implements an offline-first payment architecture where Layer 1 operates as a self-contained, sovereign voucher deed (`ProofChain`), and Layer 2 serves as an auxiliary, blind collision lock registry. Point-of-Sale (PoS) checkout and asynchronous outbound send intents must maintain rigorous security boundaries against double-releases, replay attacks, and consensus desynchronization:

1. **Z01 Fail-Closed Checkout Release & Capability Boundary (DEC-072 / DEC-084):**
   - **Observation vs. Authorization:** A `Confirmed` live-proof verification (`L2ProcessingOutcome::Confirmed`) is purely a **mathematical observation** confirming that 14/20 BFT quorum signatures authenticate the recipient challenge.
   - **Capability Token Boundary:** A `Confirmed` outcome CANNOT authorize automatic goods release on its own. Automatic goods release strictly requires the unforgeable crate-internal `DurablePurchaseBinding` capability token. This struct has no public constructor, cannot be constructed from caller-supplied data, and omits `Serialize`/`Deserialize` to prevent forgery.
   - **No Auto-Release from Write Receipts:** Raw write receipts (`Found`, `Provisional`) never authorize automatic goods release and require explicit merchant approval.
2. **Z08 Offline Purchase Replay Idempotency:**
   - Evaluating a previously completed purchase (`AppService::replay_checkout_purchase`) must be strictly idempotent and execute with zero network dependency.
   - Returns `CheckoutCompletion` with `newly_committed = false` and a valid release capability if and only if the purchase is already marked completed for the exact matching bundle hash.
   - Re-submitting an existing purchase ID with a different bundle hash must fail closed.
3. **Z10 Terminal Retained-Choice Send-Intent Reconciliation:**
   - Pending outbound transactions are staged as durable `L2SendIntent` records, preventing replacement while the network outcome is uncertain.
   - **30-Second Hold Window:** Intent reconciliation (`retained_choice_target`, `begin_intent_reconciliation`) is strictly blocked until at least 30 seconds have elapsed since creation (`now_ms >= created_at_ms + 30_000`).
   - **Stored Fresh Challenge:** `begin_intent_reconciliation` installs an unpredictable 32-byte recipient challenge in the wallet profile.
   - **IA02 Committee Refresh:** On challenge generation, the regional committee is dynamically derived via `humoco_proto::mesh::regional_committee` using the wallet's regional mesh policy and active mesh views.
   - **14/20-BFT Quorum Proofs:** `complete_intent_reconciliation` verifies the `LiveStateProof` against the exact stored challenge, context, and 14/20 BFT committee signatures.
   - **Terminal Resolution:** An intent finalizes into `Confirmed`, `Conflicted` (with the observed conflicting child lock), or `Expired`.
4. **Layer-2 Idempotent Conflict Resolution:**
   - When an L2 node returns a Conflict verdict, if the existing transaction ID matches the locally submitted transaction ID (`existing_lock.t_id == local_t_id`), the system MUST treat it as an idempotent retry (Success), NOT as a double-spend attempt requiring quarantine.
5. **Layer-1 Sovereignty (L1 Bedrock):**
   - Layer 1 is the sovereign cryptographic foundation. Layer 2 is strictly an auxiliary collision lock registry. Core never alters L1 transaction schemas, cryptographic hashes, or fraud-trap commitments to accommodate Layer 2. Core performs zero network calls.

---

## Target Codebase Scope

Inspect the following files:
- `src/app_service/checkout.rs`
- `src/app_service/l2_intents.rs`
- `src/services/l2_gateway.rs`
- `src/services/l2_causality.rs`
- `src/wallet/l2_intents.rs`
- `src/models/layer2_api.rs`
- `src/models/l2_intent.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Trace the checkout lifecycle from `begin_checkout_purchase` through `verify_live_checkout_proof` to `complete_checkout_purchase`.
   - Trace the intent lifecycle from `prepare_l2_send_intent` through 30s hold and `begin_intent_reconciliation` to `complete_intent_reconciliation`.
   - Use subagents if concurrent analysis of BFT quorum verification or causal output proofs is needed.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Capability Token Bypass / Forgery:** Can an external caller or malicious PoS client bypass `DurablePurchaseBinding` to mint `can_release_goods_automatically = true` without a durably committed backend purchase?
   - **Uncommitted Goods Release:** Can a failed or rolled-back L1 import still produce a `CheckoutCompletion` that authorizes goods release?
   - **Purchase Replay Desynchronization:** Can an attacker replay a completed purchase with modified voucher contents, altered amounts, or a swapped bundle hash to induce double-release?
   - **30-Second Hold Evasion:** Can a client bypass the 30-second hold in `retained_choice_target` or `begin_intent_reconciliation` to force premature intent finalization?
   - **Challenge Spoofing & Committee Manipulation:** Can an attacker forge a `LiveStateProof` with a recycled or mismatched recipient challenge, or manipulate `RegionalMeshView` to evaluate an unauthorized committee?
   - **Idempotent Retry vs. False Quarantine:** Does an L2 conflict verdict with matching `existing_lock.t_id == local_t_id` properly resolve as an idempotent success, or does it trigger an unwarranted voucher quarantine or DoS?
   - **Causal Output Proof Tampering:** Can an attacker manipulate `humoco_proto::causal::CausalOutputProof` in `L2LockRequest` to anchor an invalid causal branch?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. Explore any novel anomaly, state race, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write an isolated Rust test in `tests/security_audit_module_07_l2_checkout.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(!verdict.can_release_goods_automatically)` or `assert!(complete_intent_reconciliation(...).is_err())`).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Every reproduction test file must include the standardized metadata docblock:
     - `Finding-ID: AUDIT-07-L2CHECKOUT-[INDEX]`
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
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]` (e.g. `Confirmed` observation not auto-releasing without `DurablePurchaseBinding`, L2 same-tx_id conflict as idempotent retry, core performing zero network calls), do not alter the logic; instead document the rationale in the code and protect it with an invariant test.
