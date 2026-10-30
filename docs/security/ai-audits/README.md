# AI Security Audit Suite for human-money-core

Welcome to the **AI Security Audit Suite** of `human-money-core` (v0.5.1).

If you want to contribute to the security, correctness, and resilience of this project, you can use these tailored AI prompts to independently audit different layers of the codebase using any modern AI coding assistant (e.g. Antigravity, Claude, ChatGPT, Cursor).

---

## 🎯 Background & Philosophy (Crucial Context)

`human_money_core` implements decentralized, file-based digital cash (vouchers) without requiring a global consensus blockchain. Because users can hand over vouchers offline (file-to-file), **double-spending cannot be prevented in real-time at the exact moment of offline transfer.**

Instead, the system relies on fundamental cryptographic invariants:
1. **Shared-Signature Trap (SST V4):** Double-spending the same input anchor mathematically forces identity unmasking via SST V4: honest spends share one Schnorr signature line $\mu = H(\text{HMC\_TRAP\_SIG\_V4}, ds\_tag, E)$ with secret nonce derivation ($r = H(\text{HMC\_TRAP\_NONCE\_V4}, x, \mu)$), VRF + Chaum-Pedersen DLEQ line derivation, self-verifying signature masks ($M_R, m_s$), 64-byte compact public shards ($R_i, s_i$), and identity-bound output keys ($E = X + hG$).
2. **Authenticated Victim Witness Disclosure:** Historical junk shards cannot be publicly validated in isolation without witness data. A direct victim holding the matching encrypted receipt discloses its input opening and trap witness upon detecting a signed collision under the same $ds\_tag$. Gossip-only nodes identify ephemeral offenders (`ephemeral:E`) without leaking private stealth history.
3. **DS-Tag Input Dependency:** The Double-Spend Tag ($u = \text{Hash}(prev\_hash + sender\_ephemeral\_pub)$) depends **strictly on input data**, never on outputs (amount or recipient).
4. **Post-Quantum Forward Secrecy & Key Firewall:** Unspent vouchers are anchored via SHA3-256 hashes of ephemeral keys; owner public keys remain secret until spending. Binary 32-byte public keys are enforced to prevent role obfuscation (e.g., creator vs. guarantor).
5. **Layer-1 Sovereignty & Blind L2 Registry:** Layer 1 (`ProofChain`) is the sovereign cryptographic bedrock; Layer 2 is an auxiliary blind collision lock registry. Layer 2 never alters L1 transaction schemas or trap commitments.
6. **L2 Idempotent Conflict Resolution:** If an L2 conflict transaction ID matches the local transaction ID (`existing_lock.t_id == local_t_id`), it is treated as an idempotent retry (Success), not as a double-spend attempt requiring quarantine.
7. **Z01 Fail-Closed Checkout Release:** `Confirmed` live-proof verification is purely a mathematical observation (14/20 BFT quorum + recipient challenge); automatic goods release strictly requires the unforgeable crate-internal `DurablePurchaseBinding` capability token.
8. **Crash-Atomic Wallet Transactions & Storage Integrity:** Multi-file wallet mutations are guarded by an encrypted undo journal and commit marker. Differential cloud backups strip local password slots and use HMAC-derived opaque blob names.
9. **Strict Privacy Boundaries & Offline Forensics (HMSEC-SA06-05):** In Private/Stealth Mode, sender identifiers and signatures are omitted from interchange bundles. Direct counterparty DIDs are intentionally retained in the local encrypted wallet ledger to enable vital hop-by-hop double-spend forensics in offline decentralized networks.

---

## 📂 The Complete Audit Suite (Targeted Modules + Open Wildcard)

The audit suite combines 7 domain-specific vertical modules with 1 open-ended adversarial wildcard prompt:

| File | Area | Scope & Key Attack Vectors |
| :--- | :--- | :--- |
| [`00_general_adversarial_wildcard.md`](./00_general_adversarial_wildcard.md) | **Open-Ended Threat Modeling (Wildcard)** | Cross-cutting state desyncs, novel zero-days, architectural paradoxes, assumption-busting |
| [`01_double_spend_and_conflicts.md`](./01_double_spend_and_conflicts.md) | **Double-Spend Trap (SST V4) & Conflict Detection** | SST V4 line derivation, secret nonces, identity-bound outputs, victim witness disclosure, same-ID guards |
| [`02_cryptography_and_identity.md`](./02_cryptography_and_identity.md) | **Cryptography & Identity Integrity** | Signature malleability, incomplete signing payloads, role obfuscation, key leakage |
| [`03_standards_and_cel_engine.md`](./03_standards_and_cel_engine.md) | **Voucher Standards & Dynamic CEL Rules** | Missing context bypasses, CEL type-juggling, arithmetic precision, standard tampering |
| [`04_transaction_and_state_integrity.md`](./04_transaction_and_state_integrity.md) | **Transaction Logic & Rust Robustness** | Split/Change anchor collisions, conservation of value, unwrap/expect panics on untrusted input |
| [`05_storage_and_key_persistence.md`](./05_storage_and_key_persistence.md) | **Storage, Key Management & Crash-Atomic Persistence** | Crash-atomic transactions, undo journal, differential cloud backups, staged restore, HMAC blobs |
| [`06_privacy_and_protocol_bundles.md`](./06_privacy_and_protocol_bundles.md) | **Privacy Mode & Protocol Interchange** | De-anonymization in Private Mode, bundle spoofing, JWS tampering, `wallet-cli` JSON boundaries |
| [`07_l2_checkout_and_intents.md`](./07_l2_checkout_and_intents.md) | **Layer-2 Checkout, Quorum Verification & Send-Intent Reconciliation** | Fail-closed checkout release, `DurablePurchaseBinding`, purchase replay idempotency, 30s retained-choice reconciliation, 14/20-BFT quorum proofs |

---

## ⚖️ Standard Severity Rating Matrix

Auditors must classify all findings using standard CVSS / CWE severity tiers:

| Severity | Criteria & Impact on `human-money-core` |
| :--- | :--- |
| **CRITICAL** | Direct loss of funds, unauthorized minting/spending of vouchers, arbitrary identity framing in double-spends, complete privacy deanonymization in Stealth Mode. |
| **HIGH** | Unauthenticated remote voucher quarantine (DoS), undetectable double-spends, bypassing mandatory guarantor requirements, persistent wallet state corruption. |
| **MEDIUM** | Misattribution/silent fallback to dummy keys, unhandled panic/crash on untrusted network input, cryptographic malleability without immediate fund loss. |
| **LOW** | Inconsistent error reporting, non-critical parameter validation gaps, misleading diagnostic metadata. |

---

## 🛡️ Mandatory Second-Pass: Post-Audit Design-Intent Triage

Before fixing any finding or opening a pull request, auditors **MUST** run all candidate vulnerabilities through the mandatory triage filter:

👉 **[`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) (Design-Intent & False-Positive Triage Guide)**

### Why Triage is Essential:
Generic security scanners often flag intentional offline cash design decisions (e.g. retaining direct counterparty DIDs in the local encrypted wallet ledger for offline hop-by-hop double-spend investigations) as "Information Disclosure" bugs. Triage ensures:
1. **True Vulnerabilities** are fixed via Fail-First TDD.
2. **Intentional Design Decisions** are NOT broken, but instead documented in code with regression invariant tests.
3. **False Positives** are discarded before causing architectural regressions.

---

## 🧪 Testing Methodology: Fail-First Invariant Testing (TDD)

Every confirmed vulnerability **MUST** be backed by an automated Rust test in `tests/`:

1. **Assert the Safe Invariant (Soll-Verhalten):**
   * Write the test asserting the *secure, required system behavior* (e.g. `assert!(validate_voucher(&tampered, &std).is_err())` or `assert!(import_proof(forged).is_err())`).
2. **Fail on Vulnerable Code:**
   * On unpatched code, the test **MUST FAIL** (`cargo test` -> FAIL / panic). This proves the existence of the vulnerability without false positives.
3. **Turn Green on Fix (Regression Shield):**
   * Once the fix is implemented, the test passes (`cargo test` -> PASS) and permanently stays in the test suite to prevent regressions.

---

## 📝 Required Header & Report Structure

Every finding test file (e.g. `tests/security_audit_module_01_traps.rs`) must begin with a standardized metadata docblock:

```rust
//! # Security Audit Finding: [Concise Title]
//!
//! - Finding-ID: AUDIT-[MODULE]-[INDEX] (e.g. AUDIT-01-TRAP-01)
//! - Severity: CRITICAL | HIGH | MEDIUM | LOW
//! - CWE-Classification: CWE-[ID] (e.g. CWE-347: Improper Verification of Cryptographic Signature)
//! - Target Location: src/[path/to/file.rs]:[start_line]-[end_line]
//!
//! ## Threat Model & Exploitation
//! [Step-by-step description of what the attacker crafts and how they bypass checks]
//!
//! ## Impact Analysis
//! [Broken invariant, affected actors, and financial/cryptographic consequences]
//!
//! ## Root Cause
//! [Exact technical flaw in the code (e.g. fail-open branch, missing parameter in hash)]
//!
//! ## Remediation Strategy
//! [Concrete architectural and code changes to permanently fix the issue]
//!
//! ## Test Semantics (Fail-First)
//! [Explains the assertion logic and why it fails against unpatched code]
```

---

## 🚀 How to Run an Audit (2-Phase Workflow)

1. **Phase 1 (Adversarial Exploration):**
   * Pick one prompt file at a time from modules `00` through `07`.
   * Copy the prompt content into your AI coding assistant.
2. **Phase 2 (Design-Intent Triage):**
   * Run all candidate findings through **[`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md)**.
   * If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do NOT modify the operational logic; instead add explanatory comments and an invariant test.
   * If a finding is a `[CONFIRMED VULNERABILITY]`, implement the fix using the Fail-First TDD methodology.
3. **Submitting Results:**
   * Open a PR containing the test file, code comments / remediation, and the completed Triage Summary table.
