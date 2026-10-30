# Security Audit: Privacy Protection, Protocol Handshakes & Interchange Bundles

## AI Auditor Role & System Invariants

You are a security auditor specializing in network protocols, data privacy (STRIDE Information Disclosure), and cryptographic interchange bundles.

### System Context & Threat Model
`human_money_core` communicates and exchanges transactions via standardized protocol schemas (`protocols/`), JWS Profiles, encrypted payload envelopes, and agent-native CLI interfaces (`wallet-cli`):
1. **Private Mode Compliance:** When Private Mode is active, sender identity (`did:key`) and plaintext signatures MUST NOT appear in the transferred bundle. Verification must proceed purely via context binding and ephemeral commitments.
2. **Metadata Minimization:** Transferred bundles must not leak extraneous metadata (e.g. sender IP hints, unblinded timestamps, unrelated account balances).
3. **Interoperability & Bundle Validation:** Protocol envelopes (`Transfer Bundle`, `Signing Request/Response`, `Trust Assertion`) must be strictly validated before payload processing to prevent injection attacks or sender spoofing.
4. **CLI JSON Envelope & Secret Shielding Boundary (`wallet-cli`):** The agent-native CLI controller outputs structured JSON envelopes (`--json`). Output streams and error envelopes must strictly shield unencrypted private keys, passwords, and mnemonics unless an explicit key-export command is invoked.
5. **Local Event Log Retention Intent (HMSEC-SA06-05):** Direct counterparty DIDs are intentionally retained in the local encrypted wallet ledger (`TransferSent`/`TransferReceived`) to enable vital hop-by-hop double-spend forensics in offline decentralized networks. This is encrypted local state, NOT a network transport leak.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/jws_profile_service.rs`
- `src/models/wallet_event.rs`
- `src/app_service/orchestrator.rs`
- `src/app_service/transactions.rs`
- `src/bin/wallet_cli/` (`main.rs`, `context.rs`, `voucher_cmd.rs`, `profile_cmd.rs`, `scenario_cmd.rs`, `conflict_cmd.rs`)
- `protocols/transfer/1.0/bundle.md`
- `protocols/signing/1.0/request.md`
- `protocols/signing/1.0/response.md`
- `protocols/trust/1.0/assertion.md`
- `docs/security/PRIVACY_MATRIX.md`
- `docs/security/PRIVACY_FAQ.md`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Map out the serialization, encryption, and deserialization pipelines for protocol bundles and JWS envelopes.
   - Inspect `wallet-cli` JSON envelopes to verify secret shielding boundaries.
   - Use subagents to compare implementation against `docs/security/PRIVACY_MATRIX.md` and schema definitions in `protocols/`.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Private Mode De-Anonymization:** Does generating or processing a private transaction inadvertently serialize the sender's public key or did:key into an unencrypted header, envelope, or debug event?
   - **Bundle Spoofing / Signature Bypass:** Can a receiver be tricked into accepting a transfer bundle where the inner voucher payload is authentic, but the wrapper envelope metadata is spoofed or manipulated?
   - **JWS Profile & Trust Assertion Tampering:** Can forged trust assertions or tampered JWS claims pass verification due to missing header checks or algorithm confusion (e.g. `none` algorithm)?
   - **Event & Log Information Disclosure:** Do BFF/Wallet events (`WalletEvent`, `EventBffData`) leak confidential transaction metadata to unauthorized UI/host listeners?
   - **CLI Secret Leakage:** Does `wallet-cli` or `AppService` emit unencrypted private keys, seeds, or passwords in standard JSON output or error diagnostics?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. Explore any novel anomaly, privacy leakage vector, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - Write a dedicated Rust test in `tests/security_audit_module_06_privacy.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)**.
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Include the standardized metadata docblock:
     - `Finding-ID: AUDIT-06-PRIVACY-[INDEX]`
     - `Severity: CRITICAL | HIGH | MEDIUM | LOW`
     - `CWE-Classification`
     - `Target Location`
     - `Threat Model & Exploitation`
     - `Impact Analysis`
     - `Root Cause`
     - `Remediation Strategy`
     - `Test Semantics (Fail-First)`
5. **Mandatory Post-Audit Design-Intent Triage:**
   - Before modifying code or filing PRs, evaluate all candidate findings using [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md).
   - If a finding represents an intentional offline design decision (e.g. local event log counterparty retention for offline hop-by-hop double-spend forensics), do NOT remove the feature; document it clearly in code and add an invariant test.
