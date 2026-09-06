# Security Audit: Cryptography, Identity & Forward Secrecy

## AI Auditor Role & System Invariants

You are a senior cryptographic engineer and zero-knowledge protocol auditor.

### System Context & Threat Model
`human_money_core` uses a hybrid security model:
1. **Post-Quantum Forward Secrecy:** Idle vouchers store receiver identity as cryptographic hash commitments (`receiver_ephemeral_pub_hash` using SHA3-256). The actual public key is concealed until spending time, protecting cold balances against quantum preimage attacks.
2. **Public Key Firewall & Role Obfuscation Defense:** Identities are Ed25519 (`did:key`). On Layer-1, the engine operates on raw 32-byte public keys. A single cryptographic key may not assume conflicting roles (e.g. Creator and Guarantor) on the same voucher container, regardless of sub-account prefixes (`company:xyz@did...` vs `personal:abc@did...`).
3. **Deterministic Canonicalization:** Signatures and hashes must operate on unambiguously canonicalized payloads to prevent signature malleability and parsing desyncs.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/crypto_identity.rs`
- `src/services/crypto_symmetric.rs`
- `src/services/crypto_keys.rs`
- `src/services/crypto_dh.rs`
- `src/services/crypto_utils.rs`
- `src/services/signature_manager.rs`
- `src/app_service/seal_handler.rs`
- `src/models/seal.rs`
- `src/models/signature.rs`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Use autonomous subagent delegation if you need to analyze cryptographic primitive implementations or key serialization formats concurrently.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Signature Malleability:** Can valid Ed25519 signatures or container seals be modified or re-encoded without invalidating the verification?
   - **Payload Completeness:** Are all critical structural fields (amounts, dates, identities, standard IDs, parent hashes) included in the signing payload, or can unsigned metadata be swapped?
   - **Role Obfuscation Bypass:** Can an actor sign as both Creator and Guarantor by manipulating did:key prefix encodings or alias representations?
   - **Side-Channel & Key Derivation:** Does HKDF derivation or ChaCha20-Poly1305 nonce handling have risks of nonce reuse, weak entropy, or key leakage?
   - **Preimage Exposure:** Is the ephemeral public key exposed in plaintext prior to transaction authorization?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. You are encouraged to explore any novel anomaly, unexpected cryptographic edge case, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write a dedicated Rust test in `tests/security_audit_module_02_crypto.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)**.
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock (Finding-ID, Severity, CWE, Target, Threat Model, Impact, Root Cause, Remediation, Test Semantics).
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Run all candidate findings through [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) before implementing fixes.
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]`, do not alter the logic; instead document the rationale in the code and protect it with an invariant test.

