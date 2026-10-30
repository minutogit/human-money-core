# Post-Audit Design-Intent & False-Positive Triage

> **Mandatory Second-Pass Filter:** This triage step MUST be executed at the end of every AI audit run, *after* candidate vulnerabilities are identified and *before* any code modifications or PR submissions are made.

---

## 🎯 Purpose & Threat-Model Realities

Automated AI security auditors often evaluate code using generic web, cloud, or centralized ledger security heuristics (e.g., OWASP, CWE-359 *"Information Disclosure in Logs"*). In conventional systems, any identity retained in a log or memory struct is flagged as a privacy defect.

In **`human-money-core`**, this assumption is frequently false:
* **Decentralized Offline Cash:** The system operates without central mempools or real-time global consensus.
* **Hop-by-Hop Offline Forensics:** Offline double-spends and fraud can **only** be investigated post-hoc by following the chain of custody hop-by-hop ($A \to B \to C$).
* **Encrypted Sealed Storage:** The local wallet event ledger is encrypted at rest (PBKDF2 + ChaCha20-Poly1305) and protected by `WalletSeal`. It is **never** transmitted across the network.
* **Intentional Retention:** Retaining the immediate counterparty DID in local event logs (`TransferSent`/`TransferReceived`) is a **critical functional requirement** for offline dispute resolution, not a transport leak.

Blindly "fixing" such findings destroys vital offline resilience and breaks core system architecture.

---

## 📚 Required Reference Materials

Before triaging findings, the auditor MUST inspect:
1. [`docs/security/PRIVACY_FAQ.md`](../PRIVACY_FAQ.md) — Comprehensive FAQ on Stealth Mode, sender verification, and offline forensics.
2. [`docs/security/sst_v4_regression_hardening.md`](../sst_v4_regression_hardening.md) — SST V4 authorization domain, line derivation, and victim disclosure contracts.
3. [`docs/usage/wallet-backups.md`](../../usage/wallet-backups.md) — Transport-independent differential backup and staged recovery contracts.
4. [`.agents/skills/design-decisions/SKILL.md`](../../../.agents/skills/design-decisions/SKILL.md) — Architectural decisions and trade-offs.
5. [`docs/security/THREAT_MODEL.md`](../THREAT_MODEL.md) — Security boundaries and attacker capabilities.

---

## 🏛️ Key Intentional Architectural Invariants (v0.5.1)

Auditors must evaluate findings against these non-negotiable architectural invariants:

### 1. Layer-1 Sovereignty vs. Blind L2 Lock Registry (Non-Negotiable)
- **Invariant:** The Layer-1 Voucher Deed (`ProofChain`) is the sovereign cryptographic bedrock. Layer 2 is strictly an auxiliary, blind collision lock registry.
- **Rule:** NEVER alter L1 transaction schemas, cryptographic hashes, or fraud-trap commitments to accommodate Layer 2 or external specifications. Layer 2 must always adapt to Core via DTO adapters, never vice versa. Findings demanding changes to L1 schemas for L2 convenience are `[FALSE POSITIVE / MISINTERPRETATION]`.

### 2. L2 Idempotent Conflict Retries (`existing_lock.t_id == local_t_id`)
- **Invariant:** When handling an L2 Conflict verdict, if the conflict transaction ID matches the local transaction ID, it represents an idempotent retry (Success), NOT a double-spend attempt.
- **Rule:** A matching transaction ID means the local wallet's own prior transmission succeeded and was registered. Flagging this as an unquarantined conflict is an `[INTENTIONAL DESIGN REQUIREMENT]` (idempotent retry).

### 3. Local Counterparty Retention in Stealth Mode (HMSEC-SA06-05)
- **Invariant:** Direct counterparty DIDs are intentionally retained in local encrypted wallet events (`TransferSent`/`TransferReceived`) even in Stealth Mode to support vital hop-by-hop double-spend forensics in offline decentralized networks.
- **Rule:** This data is stored strictly in local encrypted files (`wallet.events`) and is NEVER serialized into transit bundles or voucher chains. Flagging this as CWE-359 or information leakage is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 4. Z01 Fail-Closed Checkout Observation vs. Automatic Goods Release
- **Invariant:** A `Confirmed` live-proof verification (`L2ProcessingOutcome::Confirmed`) is purely a mathematical observation (14/20 BFT quorum + recipient challenge).
- **Rule:** Automatic goods release strictly requires the unforgeable crate-internal `DurablePurchaseBinding` capability token (Z08 durable purchase state). Caller-supplied context or proof verification alone can never authorize goods release. Flagging the denial of automatic release on caller-supplied `Confirmed` outcomes as a bug is a `[FALSE POSITIVE / MISINTERPRETATION]`.

### 5. SST V4 Computational Single-Shard Anonymity & Victim Disclosure
- **Invariant:** Public shards remain exactly 64 bytes (32-byte point $R_i$ + 32-byte scalar $s_i$). Self-verifying masks provide computational hiding. General ZK proofs and historical validity certificates are deliberately excluded from Layer 1.
- **Rule:** Prior senders in multi-hop stealth history remain private; only direct victims holding matching encrypted handover receipts can disclose spent input openings upon detecting signed collisions. Flagging the absence of on-chain ZK validity proofs on historical shards as a defect is an `[INTENTIONAL DESIGN REQUIREMENT]`.

### 6. Zero-Network Decoupled Core & Backup Transport Independence
- **Invariant:** Core functions perform zero network I/O. Differential backup operations (`create_differential_backup`, `inspect_backup`, `restore_backup`) are transport-independent.
- **Rule:** Applications provide external storage and network transport. Restored wallets bind fresh device recovery epochs and generate L2 reconciliation queries for the application layer to execute out-of-band. Flagging core for not performing automatic cloud sync or network lookups is a `[FALSE POSITIVE / MISINTERPRETATION]`.

---

## 🔍 The 4-Step Triage Questionnaire

For **every** candidate finding produced by an audit module, answer the following four questions:

### 1. Threat-Actor Boundary Analysis
* **Question:** Is the alleged "leak" exposed to an untrusted third party (network eavesdropper, gossip peer, downstream voucher recipient), or does it remain strictly inside the local wallet owner's encrypted storage?
* **Rule:** If the data is only stored in local encrypted files (`WalletEvent`, sealed state) and never serialized into outgoing transit envelopes or voucher transaction chains, it is **local state**, NOT a network privacy vulnerability.

### 2. Offline Resilience & Dispute Resolution
* **Question:** Would removing or modifying this data make it impossible for users to manually prove or reconstruct who transacted with them in an offline double-spend investigation?
* **Rule:** In an offline P2P system, direct transacting peers must have cryptographic proof of their immediate 1-hop exchange. Features that enable offline fraud attribution are intentional and indispensable.

### 3. Established Architectural Decision Check
* **Question:** Is this behavior explicitly documented in `design-decisions`, `PRIVACY_FAQ.md`, `sst_v4_regression_hardening.md`, `wallet-backups.md`, or an ADR?
* **Rule:** If the behavior was deliberately designed to satisfy a documented system requirement, it is **INTENTIONAL**.

### 4. Functional Trade-Off Evaluation
* **Question:** What functional capability would be permanently broken or degraded if this code were altered?
* **Rule:** If the "fix" eliminates a core offline or cryptographic feature to satisfy an overly generic CWE classification, the finding is a **false positive**.

---

## 🏷️ Triage Classification Outcomes

Classify every candidate finding into one of the following three outcomes:

### Outcome A: `[CONFIRMED VULNERABILITY]`
* **Definition:** A genuine security flaw that breaks mathematical invariants, allows remote code execution / DoS panics, permits unauthorized minting/spending, or leaks plaintext identity keys across the public network transport layer.
* **Action:** Implement a Fail-First TDD test (reproduction), apply the minimal robust fix, and verify that the full test suite passes.

### Outcome B: `[INTENTIONAL DESIGN REQUIREMENT]`
* **Definition:** Behavior flagged by standard CWE/OWASP rules that is actually a necessary architectural feature for offline decentralized cash, local forensics, or cryptographic integrity.
* **Action:** 
  1. **DO NOT MODIFY** the operational logic.
  2. **Improve Code Documentation:** Add clear architectural comments in the source code explaining *why* this behavior is intentional and why it is not a security vulnerability.
  3. **Add Invariant Test:** Write an automated test asserting that this required behavior remains intact (with clear failure messages if anyone tries to remove it in the future).
  4. **Document in FAQ/ADR:** Reference the finding in `docs/security/PRIVACY_FAQ.md` or an Architecture Decision Record.

### Outcome C: `[FALSE POSITIVE / MISINTERPRETATION]`
* **Definition:** The finding is based on an incorrect reading of the code, a mistaken assumption about cryptography, or a scenario that is already structurally impossible.
* **Action:** Discard the finding with a concise rationale.

---

## 📋 Triage Report Template

Include this summary at the conclusion of every audit report:

```markdown
### Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-01-01 | CWE-347 | `[INTENTIONAL DESIGN REQUIREMENT]` | L2 conflict matching local tx_id is an idempotent retry (Success), not double-spend quarantine. | Documented in code + invariant test preserved. |
| AUDIT-06-05 | CWE-359 | `[INTENTIONAL DESIGN REQUIREMENT]` | Direct counterparty retention in local event log required for offline hop-by-hop double-spend forensics. | Documented in code + invariant test added. |
| AUDIT-07-01 | CWE-285 | `[INTENTIONAL DESIGN REQUIREMENT]` | `Confirmed` L2 observation requires `DurablePurchaseBinding` token to release goods (Z01 fail-closed). | Invariant test verifies token requirement. |
| AUDIT-05-02 | CWE-200 | `[FALSE POSITIVE / MISINTERPRETATION]` | Cloud backup blobs use HMAC-SHA3-256 opaque naming, revealing no storage paths or voucher IDs. | Discarded as false positive. |
```
