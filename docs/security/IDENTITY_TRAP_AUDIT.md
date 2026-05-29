# Identity Trap — Security Audit Report

**Date:** 2026-05-29  
**Scope:** Cryptographic soundness of the Double-Spend Identity Trap (`trap_manager.rs`, `conflict_manager.rs`, `conflict_handler.rs`)  
**Method:** Targeted adversarial testing against 7 attack vectors  
**Test file:** `tests/core_logic/security/identity_trap_audit.rs`

---

## 1. System Under Test

The Identity Trap is the core fraud-detection primitive of `human_money_core`. It forces every sender to embed a blinded identity commitment $V = u \cdot m \cdot G + ID$ into each transaction, where:

- $m$ is derived deterministically via HKDF-SHA256 from the previous transaction hash and the sender's secret key
- $u$ is derived deterministically from the transaction-specific data (amount, recipient anchor, ds_tag)
- $ID$ is the sender's permanent Ed25519 public key (as a curve point)

A double-spend (same input spent twice) forces reuse of $m$, enabling algebraic recovery of $ID$ from the two divergent transactions.

## 2. Attack Vectors Tested

### 2.1 Random Slope Attack (Vector 1)

**Threat:** A modified client derives random $m_1, m_2$ instead of the deterministic HKDF output.

**Finding:** The ds_tag collision is still detected (ds_tag depends only on `prev_hash` and `sender_ephemeral_pub`, not on $m$). However, the identity extraction via the solver formula yields a mathematically meaningless point — the offender's real $ID$ is **not** revealed to the public network. 
*Update:* By embedding a Chaum-Pedersen DLEQ proof into the encrypted `RecipientPayload`, the *direct recipient* can mathematically verify that $m$ was deterministically derived. If the proof is invalid or missing, the recipient's wallet (Point-of-Sale) immediately rejects the transaction.

**Risk assessment:** **Mitigated (Client-Side / Point-of-Sale).** The DLEQ proof acts as a local firewall. While the global network still cannot extract the identity if an attacker uses a random slope, the attacker is now forced to send the fraudulent transaction to themselves (Sybil identity) or a colluding accomplice who explicitly bypasses the DLEQ verification. This isolates the fraud and drastically narrows the social tracing graph.

**Test:** `test_random_slope_attack_identity_not_recoverable`, `test_random_slope_attack_detection`

### 2.2 Honest Double-Spend Recovery (Positive Control)

**Threat:** None — this is a correctness proof.

**Finding:** When $m$ is derived honestly (deterministically via HKDF), the solver formula `ID = V₁ - u₁ · (V₁ - V₂) · (u₁ - u₂)⁻¹` recovers the exact `EdwardsPoint` matching the sender's `VerifyingKey`. The reconstructed DID matches the original.

**Test:** `test_honest_double_spend_identity_always_recovered`

### 2.3 Trap Replay Attack (Vector 2)

**Threat:** Attacker copies valid TrapData from transaction A into a different transaction B with different amounts/recipients.

**Finding:** The verifier independently computes `u_expected = hash_to_scalar(ds_tag || amount || receiver_hash)` and compares it against the `u` in the TrapData. Since transaction B has different data, `u_expected ≠ u_submitted`, and verification fails with "Varying Input Mismatch".

**Risk assessment:** **Fully mitigated.** The challenge scalar $u$ is bound to the transaction content.

**Test:** `test_trap_replay_rejected_by_u_mismatch`

### 2.4 Forged ZKP Without Knowledge of $m$ (Vector 3)

**Threat:** Attacker does not know $m$ but attempts to forge the Schnorr proof $(R, s)$.

**Finding:** Over 1,000 randomized forgery attempts, every single one was rejected. The Schnorr proof requires solving $s \cdot X = R + c \cdot Y$ where $c = \text{Hash}(X, Y, R, \text{prefix})$. Since $c$ depends on $R$, the attacker faces a circular dependency and cannot construct a valid proof without knowing $m$.

**Risk assessment:** **Fully mitigated.** Standard Schnorr soundness applies. The challenge is computed via a hash function modeled as a random oracle.

**Test:** `test_forged_zkp_without_m_knowledge_rejected`

### 2.5 Prefix-Evasion (Historical Vulnerability A)

**Threat:** Attacker uses different account prefixes (e.g., `pc:Alice` vs `mobil:Alice`) to produce different ds_tags, evading collision detection.

**Finding:** The current implementation computes `ds_tag = hash(prev_hash_bytes || sender_ephemeral_pub_bytes)` without any prefix input. Two transactions from the same key but different prefixes produce identical ds_tags.

**Risk assessment:** **Fully mitigated.** This was a historical vulnerability that has been fixed. The test confirms the fix is in place.

**Test:** `test_ds_tag_prefix_independent`

### 2.6 Scalar Malleability (New Vector)

**Threat:** Attacker submits $u + \ell$ (where $\ell$ is the curve order) instead of $u$, hoping to bypass the `u_expected` check via modular reduction differences.

**Finding:** `Scalar::from_bytes_mod_order()` deterministically reduces any 32-byte input modulo $\ell$. Therefore $u$ and $u + \ell$ decode to the same scalar — no bypass is possible. Additionally, inputs exceeding 32 bytes are rejected during parsing ("Invalid Scalar U length").

**Risk assessment:** **No vulnerability.** The `curve25519-dalek` library handles modular reduction correctly.

**Test:** `test_scalar_malleability_no_bypass`

### 2.7 Extracted Point Validity (New Vector)

**Threat:** The solver returns an `EdwardsPoint` that is not a valid Ed25519 public key (e.g., a low-order point or non-canonical encoding), potentially causing the wallet to assign a garbage DID to the offender.

**Finding:** The wallet logic (`verify_and_create_proof`, line ~455) gates the DID reconstruction behind `VerifyingKey::from_bytes()`, which rejects invalid key representations. If this check fails, the offender_id remains `"anonymous"` — no garbage DID is assigned.

**Risk assessment:** **Fully mitigated.** The safety fuse is correctly placed.

**Test:** `test_extracted_point_validity_check`

## 3. Summary

| # | Attack Vector | Detection | ID Recovery | Status |
|---|---|---|---|---|
| 1 | Random Slope ($m$ randomized) | ✅ ds_tag collision | ❌ Garbage point | **Mitigated (PoS Firewall)** |
| 2 | Honest double-spend | ✅ ds_tag collision | ✅ Exact DID | **Correct** |
| 3 | Trap Replay | ✅ U-mismatch rejection | N/A | **Mitigated** |
| 4 | Forged ZKP | ✅ Schnorr rejection | N/A | **Mitigated** |
| 5 | Prefix Evasion | ✅ Prefix-independent tag | N/A | **Mitigated** |
| 6 | Scalar Malleability | ✅ Deterministic reduction | N/A | **No vulnerability** |
| 7 | Invalid Point Extraction | N/A | ✅ Safety fuse | **Mitigated** |

## 4. Open Considerations

### 4.1 Random Slope and the Sybil/Accomplice Trap

The Random Slope Attack (2.1) highlights a fascinating architectural trade-off between privacy and verification. An attacker **can** avoid identity revelation on the public network by using non-deterministic $m$ values, but the system relies on a powerful hybrid mitigation strategy:

- **Without global consensus**, the system cannot force honest $m$ derivation at the public protocol level without compromising sender privacy. 
- **The Point-of-Sale Firewall:** Honest wallets will reject any transaction with an invalid DLEQ derivation proof.
- **The Sybil/Accomplice Trap:** The DLEQ proof is not a global protection against the Random Slope, but a client-side integrity check that forces the attacker into the Sybil/accomplice trap. To succeed, the attacker *must* collude with an altered recipient client. When the voucher is quarantined, social tracing directly exposes this specific ring of accomplices.

A future enhancement could explore **ZK-SNARK/STARK proofs** of correct derivation for the global layer, but the current DLEQ-based localized firewall provides an exceptionally strong socio-economic deterrent without the massive overhead of full zero-knowledge circuits.

### 4.2 Test Coverage Gaps

The following vectors are **not** covered by this audit and may warrant future work:

- **Timing attacks** on `derive_m` or `calculate_challenge` (constant-time properties of the underlying libraries are assumed but not verified)
- **Multi-party collusion** where two attackers cooperate to construct complementary traps
- **Quantum resistance** of the Ed25519 curve points used in the trap (the P2PKH layer provides hash-based quantum resistance for resting funds, but the trap itself relies on ECDLP hardness)
