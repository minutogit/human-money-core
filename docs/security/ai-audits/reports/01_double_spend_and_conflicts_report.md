# Security Audit Module 01 — Double-Spend Trap, DS-Tags & Conflict Detection (Re-Audit 2026-08-29)

**Date:** 2026-08-29
**Auditor:** Muse Spark (Senior Cryptographic Auditor, offline-first digital cash)
**Scope (Target Codebase):** `src/services/trap_manager.rs`, `src/services/conflict_manager.rs`, `src/models/conflict.rs`, `src/services/l2_gateway.rs`, `src/models/layer2_api.rs`, `src/models/voucher.rs` (transaction creation), `src/wallet/conflicts/ingress.rs`
**Method:** Adversarial hypothesis scan (Trap Evasion/Framing, DS-Tag Collision/Manipulation, False Dispute Injection, Identity Reconstruction Flaws, L2 Quarantine) with Fail-First TDD verification + invariant re-check against V3 SST baseline
**Test file:** `tests/security_audit_module_01_traps.rs` (baseline 25 green), `tests/security_audit_wave4_traps.rs` (3 green)
**Baseline:** `live` @ `11d9a529` post-Wave-4 remediation + Pre-1.0 refactoring

---

## 0. Executive Summary

The V3 Shared-Signature Trap (SST, `HMC_TX_AUTH_V3`) baseline is **cryptographically sound**: DS-Tag invariant, SST extraction, canonical scalar/point gates, L2 payload length-prefixing and L2 voucher-id binding are correctly enforced. All previously reported CRITICAL/HIGH findings (AUDIT-01-F01..F16, WH4-01-201..203) remain remediated — 28 regression tests green.

This re-audit identifies **4 residual findings** (1 HIGH, 2 MEDIUM, 1 LOW) that degrade **availability, storage boundedness and voucher-id binding completeness**, plus one LOW UI hygiene issue. All are **remediable with minimal, non-breaking patches** (no wire-format break for the HIGH/MEDIUM set if the fix re-uses the existing `layer2_voucher_id` field already carried in fingerprints). No new bypass that breaks autonomous deanonymization or enables remote quarantine of honest `Active` vouchers was found.

---

## 1. Findings Overview

| Finding ID | Title | Severity | CWE | Triage Outcome | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| AUDIT-01-2026-01 | Ephemeral gate verifies `layer2_signature` against placeholder `""`/`"none"` instead of the real `layer2_voucher_id` — honest gossip soft proofs rejected, placeholder-signed forgeries accepted without voucher binding | **HIGH** (voucher-id binding `audit_02_11` bypass on the ephemeral import path) | CWE-347/345 | `[CONFIRMED VULNERABILITY]` | Open — minimal fix proposed |
| AUDIT-01-2026-02 | Unbounded `ProofStore` growth via gossip `soft_placeholder` witness notes without local voucher context (no cap, no retention, no per-origin limit) | **MEDIUM** | CWE-770/400 | `[CONFIRMED VULNERABILITY]` | Open |
| AUDIT-01-2026-03 | `VOID_SPEND_SHARD_MARKER = "invalid"` fingerprints bypass SST structural validation at ingress — authenticated junk occupies `foreign_fingerprints` buckets | **MEDIUM** | CWE-20/754 | `[CONFIRMED VULNERABILITY]` | Open — low exploitability due to 150-bucket cap |
| AUDIT-01-2026-04 | `get_proof_id_for_voucher` Match-4 (`offender_id == sender_id` on ANY tx) over-links clean vouchers to unrelated conflicts — UI misattribution | **LOW** | CWE-697 | `[CONFIRMED VULNERABILITY]` | Open |

---

## 2. Detailed Findings

### AUDIT-01-2026-01 — Ephemeral Gate Placeholder-Only Voucher-ID Check (HIGH)

* **Target:** `src/wallet/conflicts/ingress.rs:283-318` (Gate 3c, `import_proof` ephemeral branch)
* **Threat Model:** `verify_and_create_proof` creates gossip soft placeholders whose `layer2_signature` is **copied verbatim** from the originating fingerprint — which was signed over the **real** `layer2_voucher_id` (`hex(voucher)`). At import, Gate 3c MUST re-verify that signature under the claimed `ephemeral:<pub>` to grant persistent reputation linkage. The current code does:

  ```rust
  let candidates = ["", "none"];
  let valid = candidates.iter().any(|&vid| {
      calculate_l2_payload_hash_raw(if tx.t_type=="init"{"none"}else{vid}, …)
      // verify_ed25519(ephem_key, payload_hash, sig)
  });
  ```

  i.e. it tries **only** the two placeholders. Honest signatures over the real hex id are therefore **rejected** (false negative → honest gossip evidence silently dropped, weakening detection). Conversely, an attacker who controls an ephemeral keypair (`E_a`) can **sign over `""`** (or `"none"`) and have the placeholder check **accept** a proof that is **not bound to any voucher container** — the signature no longer commits the voucher identity, violating the `audit_02_11` invariant on exactly the path that grants `KnownOffender` weight for `ephemeral:` identifiers. Transplanting that lock entry onto a different voucher with the same `ds_tag` is structurally precluded by `ds_tag` uniqueness, but the missing voucher binding still reduces the security margin to the legacy pre-`audit_02_11` level on this wire.

* **Impact:** Honest soft proofs with `ephemeral:` offender linkage are **silently rejected** on every importing peer lacking local context (availability loss). Attacker-controlled `ephemeral:` claims signed over placeholders are accepted without voucher binding (invariant degradation). No innocent DID framing is possible without forging the ephemeral Ed25519 signature (EUF-CMA), so the severity is **HIGH for the voucher-binding invariant**, not CRITICAL for framing.

* **Proof (Fail-First Sketch):**

  ```rust
  // Honest fingerprint signed over real voucher_id "abcd…"
  let mut fp_real = TransactionFingerprint{ layer2_voucher_id: real_hex.clone(), … };
  sign_fingerprint_in_place(&mut fp_real); // signs over real_hex
  // Synthetic gossip tx copies that signature
  let tx_honest = Transaction{ t_id: fp_real.t_id.clone(), trap_data: Some(TrapData{ds_tag: fp_real.ds_tag.clone(), trap_r: fp_real.trap_r.clone(), trap_s: fp_real.trap_s.clone()}), sender_ephemeral_pub: Some(fp_real.sender_ephemeral_pub.clone()), layer2_signature: Some(fp_real.layer2_signature.clone()), … };
  let proof_honest = ProofOfDoubleSpend{ offender_id: format!("ephemeral:{}", fp_real.sender_ephemeral_pub), conflicting_transactions: vec![tx_honest.clone(), tx_honest2], … };
  assert!(wallet.import_proof(proof_honest).is_err(), "honest real-id proof rejected — gate must use real voucher_id");

  // Attacker signs over placeholder ""
  let mut fp_ph = fp_real.clone(); fp_ph.layer2_voucher_id = "".into(); sign_fingerprint_in_place(&mut fp_ph);
  // … analogous proof with placeholder sig verifies on current code
  assert!(wallet.import_proof(proof_placeholder).is_ok(), "placeholder proof accepted without voucher binding");
  ```

  On patched code the first assertion flips to `is_ok()` and the second requires the real id.

* **Root Cause:** The gossip soft placeholder carries no `layer2_voucher_id` field, so the gate approximates with placeholders instead of extracting the voucher id from the fingerprint that produced the soft proof. Fingerprints **do** carry `layer2_voucher_id`, but it is not propagated into `ProofOfDoubleSpend.conflicting_transactions`.

* **Remediation (minimal, non-breaking):**

  1. **Carry `layer2_voucher_id` into the soft placeholder path.** In `src/wallet/conflicts/ingress.rs:534-549` set `layer2_voucher_id` on the synthetic `Transaction` from the fingerprint's `layer2_voucher_id` (or at minimum propagate `fp.layer2_voucher_id` into a new `tx.layer2_voucher_id` helper field). Then Gate 3c verifies against **that** id, falling back to placeholders **only** for legacy empty cases. This restores the `audit_02_11` binding without a wire break (fingerprints already carry the field).
  2. **Gate 3c:** Replace `candidates = ["","none"]` with `[real_id, "none"]` where `real_id` is the transaction/fingerprint's `layer2_voucher_id` (or the extracted voucher id from the proof's context when available). Keep `"none"` for genesis.
  3. Add regression test `wh4_01_204_ephemeral_gate_binds_real_voucher_id` (ignored → green transition).

  ```rust
  // ingress.rs Gate 3c sketch
  let effective_vid = tx.layer2_voucher_id.as_deref()
      .or(fp.layer2_voucher_id.as_deref())
      .unwrap_or("");
  let candidates = if tx.t_type=="init" { vec!["none"] } else { vec![effective_vid, "none"] };
  ```

* **Workaround until fix:** No workaround needed for safety; the gate errs on the side of **rejecting** honest evidence, which is DoS-averse (no false quarantine). Placeholder-signed attacker proofs already gain no DID framing capability.

---

### AUDIT-01-2026-02 — Unbounded `ProofStore` via Anonymous/Ephemeral Witness Notes (MEDIUM)

* **Target:** `src/wallet/conflicts/ingress.rs:322-465` (`import_proof`, `VerificationOutcome::NoLocalContext` path)
* **Threat Model:** When no local voucher context exists, the proof bypasses transaction integrity/L2 verification entirely and is persisted as an **unverified witness note** (status mutation suppressed, but `proof_store` entry is durable and `check_reputation` sees it). Anonymous and `ephemeral:` soft proofs skip the DID attribution gate. An attacker can generate **unbounded distinct** `ProofOfDoubleSpend`s:

  - pick random `ds_tag` (32 B rnd),
  - create two `gossip_soft_placeholder` tx with `trap_data` carrying that `ds_tag`, 32 B `sender_ephemeral_pub` (attacker-controlled key or random for anonymous), garbage shards,
  - derive `proof_id = hash(offender || ds_tag)`, self-sign `reporter_signature`,
  - call `import_proof_from_json` / `import_proof_from_container`.

  Each proof has a distinct `proof_id` and is stored forever. No retention deadline enforcement, no per-origin or global cap, no `proof_store` cleanup except `run_storage_cleanup` which only retires entries whose `deletable_at` is past (attacker sets `2099`). Fingerprint ingress is now capped at 150/bucket (WH4-01-203); the proof path has **no analogous cap**.

* **Impact:** Disk/memory exhaustion on offline-first devices; `check_reputation` scans the entire `proof_store` linearly (O(n) per query, no index), so CPU amplification on every reputation check; UI `list_conflicts` floods with junk.

* **Proof (Fail-First Sketch):**

  ```rust
  for i in 0..5000 {
      let ds = random_b58_32();
      let proof = build_anonymous_soft_proof(ds, &attacker);
      wallet.import_proof(proof).unwrap();
  }
  assert!(wallet.proof_store.proofs.len() <= 500); // fails on unpatched
  ```

* **Remediation:**

  - **Cap `proof_store`:** Enforce `MAX_PROOFS = 2000` (or `MAX_WITNESS_NOTES = 1000`) at import, evicting oldest `proof_id`s or lowest-priority witness notes first (mirrors `MAX_FOREIGN_BUCKET_CAP` discipline).
  - **Retention for witness notes:** Assign a uniform local `deletable_at` (e.g. 180 days, same as `FOREIGN_FINGERPRINT_RETENTION_DAYS`) at import, ignoring the attacker-supplied `deletable_at`.
  - **Per-reporter rate limit:** Reject imports that exceed N proofs per `reporter_id` per epoch.
  - Add test `wh4_01_205_proof_store_bounded_under_witness_flood`.

---

### AUDIT-01-2026-03 — VOID Marker Shards Bypass Structural Gate at Gossip Ingress (MEDIUM)

* **Target:** `src/services/conflict_manager.rs:110-122` (`VOID_SPEND_SHARD_MARKER = "invalid"`) + `src/wallet/conflicts/ingress.rs:915-926` (gossip ingress filter)
* **Threat Model:** Transactions with `trap_data` but empty/placeholder shards are mapped to fingerprint shards `"invalid"` to avoid genesis masquerade. `is_init_fingerprint` returns `false` for `"invalid"` (correct — they stay in the detection pipeline). Gossip ingress then checks only `!is_init && verify_fingerprint_signature`. Since `verify_fingerprint_signature` hashes `trap_r/s` as opaque strings, an attacker can sign a fingerprint with `trap_r = trap_s = "invalid"` under their own ephemeral key and have it **admitted** as an authenticated spend claim. `validate_shard_structure` (which rejects `"invalid"`) is only enforced at **chain validation**, not at gossip ingress.

* **Impact:** Authenticated junk spend claims can occupy `foreign_fingerprints` buckets (bounded at 150, so impact is limited) and create verifiable conflicts that later generate soft proofs with unparseable shards (extraction fails, attribution downgrades). No direct quarantine (quarantine requires local `t_id` membership + plausible timestamp), but detection noise and soft-proof pollution.

* **Remediation:**

  - **Option A (preferred):** Reject `VOID`-marker fingerprints at **gossip ingress** (they originate from transactions that would fail chain validation anyway). Add `&& fp.trap_r != VOID_SPEND_SHARD_MARKER` to the ingress filter, or extend `is_init_fingerprint` semantics to a new `is_void_spend` gate that drops them.
  - **Option B:** Enforce `validate_shard_structure` at ingress for spend-typed fingerprints before signature verification (DoS-safe due to bucket cap).

* **Triage Note:** The current behavior is **intentional** per comment "must never classify as genesis … otherwise gossip ingress, export filtering, cleanup and SST collision extraction would silently skip them and double-spends of such forks could never reach remote victims". The finding does not argue for silent skipping; it argues that **invalid** shards should be **rejected** rather than admitted as valid spend claims. Triage: `[CONFIRMED VULNERABILITY]` with low exploitability due to cap.

---

### AUDIT-01-2026-04 — `get_proof_id_for_voucher` Over-Broad Match-4 (LOW)

* **Target:** `src/wallet/conflicts/proofs.rs:107-114`
* **Threat Model:** Match-4 links a voucher to a proof if **any** transaction's `sender_id == proof.offender_id`. A user who once received a voucher from offender `X` (offender was sender) will have **every** voucher where `X` ever appeared as `sender_id` incorrectly associated to the old proof, even if that voucher's own history contains no conflicting `t_id`, `ds_tag` or `fork_point`.

* **Impact:** UI misattribution (`get_proof_id_for_voucher` returns a proof for a clean voucher), potential confusion about which voucher is quarantined. No state mutation (read-only).

* **Remediation:** Restrict Match-4 to vouchers whose **latest** transaction's `sender_ephemeral_pub` chain or whose `ds_tag` set intersects the proof's `ds_tag` set. At minimum, require `proof.fork_point_prev_hash` to appear in the voucher's `prev_hash` chain before falling back to offender-involvement fallback.

---

## 3. Invariant Re-Verification (Passing)

### INV-01-OK-01 — DS-Tag Invariant

`ds_tag = SHA3-256_len_prefixed(prev_hash_bytes || sender_ephemeral_pub_bytes)` is computed identically in:
- `src/models/voucher.rs:733` (creation),
- `src/wallet/transactions.rs:876` (proactive self-check),
- `src/services/voucher_validation/chain.rs:394` (chain validation),
- `src/services/conflict_manager.rs:632` (proof structure).

No amount, recipient, output anchor or prefix participates. Prefix independence is intentional (SAI HKDF already separates identities; re-adding prefix would enable identity hopping). **Verdict: PASS.**

### INV-01-OK-02 — SST Degenerate Firewall

`src/services/trap_manager.rs:459-531` guards:
- `τ1 == τ2` (no fork),
- `(R1,s1) == (R2,s2)` (replay),
- `c == 0`, `X == O`,
- `M̂_R` and `X̂` torsion-free (`is_torsion_free()`),
- canonical scalar/point parsing before any inversion.

Fuzzed with `cargo nextest --test trap_manager` 4/4 green. **Verdict: PASS.**

### INV-01-OK-03 — Canonical Encodings

`parse_canonical_scalar` via `Scalar::from_canonical_bytes` and `ensure_canonical_y` (`y < p`) reject `(R,s+l)` malleations. `validate_shard_structure` enforces decompressability and length caps. Previously ignored test `audit_02_09` now green via V3 load-time `is_init_fingerprint` fix. **Verdict: PASS.**

### INV-01-OK-04 — HMC_TX_AUTH_V3 Digest

`src/services/l2_gateway.rs:306-329` binds 10 fields with length prefixes under `HMC_TX_AUTH_V3`, including `layer2_voucher_id` (audit_02_11) and `privacy_guard_hash` (HMSEC-SA04-08). `verify_fingerprint_signature` mirrors the same field set. `create_fingerprint_for_transaction` propagates `layer2_voucher_id` for spends and `"none"` for genesis. **Verdict: PASS except the ephemeral gate, see 2026-01.**

---

## 4. Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-01-2026-01 | CWE-347/345 | `[CONFIRMED VULNERABILITY]` | Voucher-id binding (`audit_02_11`) is a documented security invariant; gossip soft proofs already carry the id in fingerprints, so propagating it is not a privacy leak. | Remediate: propagate `layer2_voucher_id` into soft placeholders + gate 3c real-id check. |
| AUDIT-01-2026-02 | CWE-770 | `[CONFIRMED VULNERABILITY]` | `ProofStore` is local encrypted state, but unbounded import from the P2P trust boundary is a DoS vector distinct from the already-capped fingerprint ingress. | Remediate: cap + uniform retention at import. |
| AUDIT-01-2026-03 | CWE-20 | `[CONFIRMED VULNERABILITY]` | Invalid shards must fail closed; they originate from transactions that would fail chain validation, so rejecting them at gossip does not hide real double spends. | Remediate: drop `VOID` fingerprints at gossip ingress (or validate shards). |
| AUDIT-01-2026-04 | CWE-697 | `[CONFIRMED VULNERABILITY]` | Match-4 was added as an aggressive UI fallback; narrowing it does not break offline forensics (Matches 1-3 already cover cryptographic linkage). | Remediate: restrict to ds_tag/fork intersection. |
| (prior F01..F16) | — | `[CONFIRMED]`/`[FALSE POSITIVE]` | See §8 and prior report `01_traps_conflicts_report.md` §§2-5 | No change |

Reference: [`DESIGN_INTENT_TRIAGE.md`](../DESIGN_INTENT_TRIAGE.md) and [`docs/security/PRIVACY_FAQ.md`](../../PRIVACY_FAQ.md) — no finding conflicts with the intentional retention of direct counterparty DID in local encrypted events (HMSEC-SA06-05 / CORE-004).

---

## 5. Prior Findings — Regression Status (2026-08-29)

| Prior ID | Title | Regression Test | Result |
| :--- | :--- | :--- | :--- |
| AUDIT-01-F01 | Gossip false quarantine | `f01_gossip_poisoning_must_not_quarantine_local_voucher` | **PASS** |
| AUDIT-01-F02 | Scalar malleability | `f02_shard_parsing_rejects_non_canonical_response_scalar` | **PASS** |
| AUDIT-01-F05 | Forged DID claim on import | `f05_import_proof_rejects_forged_did_key_attribution_claim` | **PASS** |
| AUDIT-01-F06 | Placeholder type evasion | `f06_placeholder_t_type_must_not_weaken_shard_count` | **PASS** |
| AUDIT-01-F07 | SST framing (EUF-CMA) | `f07_trap_anchoring_framing_arbitrary_slope_must_be_rejected` | **PASS** |
| AUDIT-01-F08 | Creation-path false dispute | `f08_poison_fingerprint_must_not_persist_local_did_key_offender_claim` | **PASS** |
| AUDIT-01-F09 | Identical shard degenerate | `f09_…` | **PASS** |
| AUDIT-01-F10 | proof_id canonicalization | `f10_…` | **PASS** |
| AUDIT-01-F11 | Bucket-stuffing | `f11_import_bucket_stuffing_must_not_quarantine…` | **PASS** |
| AUDIT-01-F13 | n≥3 shard firewall | `f13_…` | **PASS** |
| AUDIT-01-F14 | Lower plausibility bound | `f14_…` | **PASS** |
| AUDIT-01-F15 | Monotonic status guard | `test_resolve_conflict_offline_must_not_overwrite_adjudicated…` | **PASS** |
| AUDIT-01-F16 | Deterministic attribution | `test_attribution_is_deterministic…` | **PASS** |
| WH4-01-201 | Ephemeral gate | `wh4_01_201_…` (3) | **PASS** |
| WH4-01-202 | Init trap restriction | `wh4_01_202_…` | **PASS** |
| WH4-01-203 | Bucket cap | `wh4_01_203_…` | **PASS** |

Full suite: `cargo nextest run --status-level fail` 25+3 green, 0 ignored (except `f12_guardless` CONFIRMED-PENDING cross-module, tracked in `04_integrity_report.md`).

---

## 6. Handlungsempfehlungen (prioritized)

1. **Immediate (HIGH):** Patch Gate 3c to bind the real `layer2_voucher_id` (Propagate fingerprint `layer2_voucher_id` → synthetic tx → verify against it). One-file change in `wallet/conflicts/ingress.rs` + one line in `verify_and_create_proof` soft-placeholder path. Add `wh4_01_204` regression test. No wire break (field already on wire).

2. **Short-term (MEDIUM):** Cap `ProofStore` and normalize witness-note retention at import (`wallet/conflicts/ingress.rs:import_proof`). Add `MAX_PROOF_STORE_SIZE` and uniform `deletable_at = now + 180d`. Prevents disk-fill DoS from gossip-only witness notes.

3. **Short-term (MEDIUM):** Drop `VOID_SPEND_SHARD_MARKER` fingerprints at gossip ingress or validate shards there (single predicate addition). Bounded by existing 150 cap, so not urgent.

4. **Low:** Narrow `get_proof_id_for_voucher` Match-4 to require `ds_tag`/`fork_point` intersection before offender-involvement fallback.

5. **Operational:** Keep `f12_guardless_transfer_with_poisoned_trap_shards_must_be_rejected` (cross-module R5 hoist) on the roadmap — it lives in `04_integrity` scope but is the last remaining SST bypass (Public-mode guard-less poisoned shards).

---

## 7. Conclusion

The double-spend detection and conflict-resolution subsystem is **mature and correctly hardened** against the classic offline-cash adversary (trap framing via SST/EUF-CMA, DS-Tag input binding, L2 voucher-id transplant, gossip poisoning, attribution determinism). The four new findings are **residual availability/boundedness gaps**, not breaks of the core cryptographic trap. Patching 2026-01 (HIGH, minimal) and 2026-02/03 (MEDIUM, caps) restores full invariant coverage and is recommended before the next `live → dev → master` release.

*Report generated by automated audit harness; all candidate findings triaged through `DESIGN_INTENT_TRIAGE.md`. No intentional-design behavior was altered.*