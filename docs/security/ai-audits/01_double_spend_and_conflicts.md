# Security Audit: Double-Spend Trap (SST V4), DS-Tags & Conflict Detection

## AI Auditor Role & System Invariants

You are a senior cryptographic security auditor specializing in decentralized, offline-first digital cash systems, zero-knowledge proofs, and elliptic-curve cryptography.

### System Context & Threat Model
`human_money_core` implements a file-based voucher system without a global consensus blockchain. Offline double-spends cannot be prevented in real-time at the moment of physical/file hand-off. Instead, the protocol enforces deterministic post-facto identity unmasking via **Shared-Signature Traps (SST V4)** and instant Layer-2 quarantine:

1. **SST V4 Shared-Signature Architecture:**
   - **Shared Base Signature:** Honest spends share one Schnorr signature line $(R_{\text{sig}}, s_{\text{sig}})$ over $\mu = H(\text{HMC\_TRAP\_SIG\_V4}, ds\_tag, E)$.
   - **Secret Nonce Derivation:** The private Schnorr nonce $r = H(\text{HMC\_TRAP\_NONCE\_V4}, x, \mu)$ is derived deterministically from the private scalar $x$ and message hash $\mu$. It MUST NEVER be derived from the disclosed VRF point $K_{\text{trap}}$, preventing permanent private key recovery ($(s_{\text{sig}} - r) / c$).
   - **VRF + Chaum-Pedersen DLEQ Line Derivation:** Line derivation is deterministically constrained via verifiable random function (VRF) and Chaum-Pedersen DLEQ zero-knowledge proofs, eliminating sender-chosen rogue scalars.
   - **Identity-Bound Output Keys:** Genesis holders, received outputs, and split change all bind $E = X + hG$, where $h = H(\text{HMC\_STEALTH\_BLIND\_V4}, seed, X)$ and the owner scalar is $x + h$. The encrypted `RecipientPayload` carries `input_key_seed`, the opening of the spent input. `verify_sst_witness` enforces that this opening derives exactly `sender_ephemeral_pub` from the declared sender DID. Legacy raw seed fallbacks (`SigningKey::from_bytes`) are strictly eliminated.
   - **Asymmetric Stealth-Key Derivation:** Prevents senders from reusing recipient blinding seeds to forge downstream signatures.
   - **Canonical Genesis Binding:** Spends bind hex `layer2_voucher_id`, while genesis fingerprints bind the canonical `"none"` placeholder, eliminating signature-malleable `ds_tag` evasion.
   - **Self-Verifying Signature Masks:** Point and scalar masks $(M_R, m_s)$ derive from $(R_{\text{sig}}, s_{\text{sig}}, \mu)$ via `SST_DOMAIN_MASK_R` and `SST_DOMAIN_MASK_S`. Reconstruction recomputes both masks; steered junk shards fail verification without attributing an innocent identity.
   - **Computational Single-Shard Anonymity:** Public shards remain compact at 64 bytes (32-byte point $R_i$ + 32-byte scalar $s_i$). No historical validity certificates or general ZK proofs are added to Layer 1.
2. **Same-ID Guard Evaluation:**
   - Shard evaluation point $\tau = H(\text{HMC\_TAU\_V4}, ds\_tag, t\_id, privacy\_guard\_hash)$ incorporates the authenticated privacy guard commitment. Handovers with identical transaction IDs but different guards evaluate to distinct points $\tau_i$, preventing hash cycles and surviving proof import.
3. **Authenticated Victim Witness Disclosure:**
   - A historical junk shard cannot be publicly validated in isolation without private witness data. When two distinct spends signed by $E$ collide under the same $ds\_tag$, a direct victim holding the original encrypted handover receipt decrypts it and publishes `VictimWitnessDisclosure` (input key opening, checked trap witness, guard commitment, honest shard).
   - Permanent DID attribution is only accepted after victim witness disclosure verifies. Pure gossip proofs attribute only an ephemeral offender (`ephemeral:E`) or an advisory signature candidate. Proof evidence is bounded by the fingerprint bucket limit.
4. **DS-Tag Input Dependency:**
   - The Double-Spend Tag ($u = \text{Hash}(prev\_hash + sender\_ephemeral\_pub)$) MUST depend **strictly and exclusively on input data**. It MUST NEVER incorporate amounts, recipients, or output parameters.
5. **Layer-2 Quarantining & Idempotent Retries:**
   - L2 nodes detect duplicate DS-Tags in $O(1)$, quarantine the affected voucher, and generate signed dispute proofs.
   - **Idempotent Retry Invariant:** When handling an L2 Conflict verdict, if the conflict transaction ID matches the local transaction ID (`existing_lock.t_id == local_t_id`), it MUST be treated as an idempotent retry (Success), NOT as a double-spend attempt requiring quarantine.

---

## Target Codebase Scope

Inspect the following files:
- `src/services/trap_manager.rs`
- `src/services/conflict_manager.rs`
- `src/app_service/conflicts.rs`
- `src/wallet/conflicts/` (`mod.rs`, `gossip.rs`, `ingress.rs`, `maintenance.rs`, `proofs.rs`)
- `src/models/conflict.rs`
- `src/services/l2_gateway.rs`
- `src/models/layer2_api.rs`
- `docs/security/sst_v4_regression_hardening.md`

---

## Autonomous Execution Instructions

1. **Research & Codebase Exploration:**
   - Trace the SST V4 lifecycle: line derivation in `trap_manager.rs`, conflict detection in `conflict_manager.rs`, fingerprint indexing in `wallet/conflicts/`, and L2 lock requests in `l2_gateway.rs`.
   - If complex sub-tasks or cross-file traces are needed, invoke specialized subagents (e.g. `research` subagents) to map out DLEQ proofs, mask derivations, and victim disclosures.
2. **Hypothesis Generation & Vulnerability Scan:**
   - **Trap Evasion & Junk Shard Steering:** Can an attacker craft a malicious or malformed historical shard $(R_i, s_i)$ that bypasses self-verifying mask checks or causes false identity attribution to an innocent DID?
   - **Secret Nonce & Permanent Key Disclosure:** Does any code path expose secret Schnorr nonce $r$ or derive nonces from disclosed VRF points ($K_{\text{trap}}$), enabling permanent private scalar recovery via $(s_{\text{sig}} - r) / c$?
   - **Output Key Binding & Identity Swaps:** Can an attacker spend outputs without proving ownership opening $E = X + hG$, or swap sender identities between spent inputs and revealed ephemeral keys? Are legacy seed fallbacks completely rejected?
   - **Same-ID Equivocation & Guard Conflicts:** Can an attacker execute same-ID equivocations with altered privacy guards without triggering distinct $\tau_i$ evaluations or detection?
   - **Victim Witness Disclosure & Proof Poisoning:** Can a malicious actor forge a `VictimWitnessDisclosure`, inject fabricated second spends, exceed the fingerprint bucket limit, or poison tag buckets with unrelated keys?
   - **DS-Tag Input Dependency:** Does `ds_tag` remain strictly bound to input parameters ($prev\_hash + sender\_ephemeral\_pub$), free from output influence?
   - **L2 Quarantine vs. Idempotent Retry:** Does an L2 conflict verdict where `existing_lock.t_id == local_t_id` correctly resolve as an idempotent retry (Success) rather than erroneously triggering double-spend quarantine?
   - **Open Exploration & Assumption-Busting:** The vectors above are non-exhaustive seeds. Explore any novel anomaly, unexpected transaction state, or unstated assumption you encounter in this domain.
3. **Verification & Proof (Fail-First TDD Invariant):**
   - For every suspected bug or bypass, construct an isolated Rust test in `tests/security_audit_module_01_traps.rs`.
   - **The test MUST assert the secure invariant (Soll-Verhalten)** (e.g. `assert!(validate_voucher(...).is_err())` or `assert!(import_proof(...).is_err())`).
   - The test **MUST fail on unpatched code** (`cargo test` -> FAIL), proving the vulnerability.
4. **Standardized Header Requirement:**
   - Every reproduction test file must include the standardized metadata docblock:
     - `Finding-ID: AUDIT-01-TRAP-[INDEX]`
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
   - If a finding is an `[INTENTIONAL DESIGN REQUIREMENT]` (e.g. L2 same-tx_id conflict as idempotent retry, computational single-shard hiding without L1 ZK bloat, local counterparty retention in encrypted events), do not alter the logic; instead document the rationale in the code and protect it with an invariant test.
