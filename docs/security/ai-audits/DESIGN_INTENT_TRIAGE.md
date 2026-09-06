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
2. [`.agents/skills/design-decisions/SKILL.md`](../../../.agents/skills/design-decisions/SKILL.md) — Architectural decisions and trade-offs.
3. [`docs/security/THREAT_MODEL.md`](../THREAT_MODEL.md) — Security boundaries and attacker capabilities.

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
* **Question:** Is this behavior explicitly documented in `design-decisions`, `PRIVACY_FAQ.md`, or an ADR?
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
| AUDIT-06-01 | CWE-347 | `[CONFIRMED VULNERABILITY]` | Recomputed bundle_id from canonical bytes before signature check. | Remediated with Fail-First TDD test. |
| AUDIT-06-05 | CWE-359 | `[INTENTIONAL DESIGN REQUIREMENT]` | Direct counterparty retention in local event log required for offline hop-by-hop double-spend forensics. | Documented in code + invariant test added. |
```
