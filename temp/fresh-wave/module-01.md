# Module 01 — Fresh Hypotheses (Double-Spend & Conflicts)

Auditor: fresh-eyes pass, 2026-08-26. Research only; no source modified.
Scope read in full: `docs/security/ai-audits/01_double_spend_and_conflicts.md`, `src/services/trap_manager.rs`, `src/services/conflict_manager.rs`, `src/services/l2_gateway.rs`, `src/app_service/conflict_handler.rs`, `src/wallet/conflict_handler.rs`, `src/models/conflict.rs`, `src/models/layer2_api.rs`, plus supporting paths: `src/services/voucher_manager/transaction.rs`, `src/services/voucher_validation/{chain,signatures}.rs` (chain validation), `src/services/crypto_utils.rs`, `src/services/crypto_identity.rs`, `src/wallet/{transaction_handler,maintenance,queries}.rs`, `src/app_service/l2_facade.rs`.

Note on protocol version drift: the audit prompt describes the V2 math (`V = u·m + ID`, `m = HKDF(sk, prev_hash)`). The codebase has evolved to **V3 / Shared-Signature Trap (SST)**: shards $(R_i, s_i) = (R_{sig} + \tau_i M_R,\; s_{sig} + \tau_i m_s)$ with $\mu = H(\text{"HMC\_TRAP\_SIG\_V1"} \| ds\_tag \| E)$ and $ds\_tag = H(prev\_hash \| E)$. The V2 invariant "DS-tag depends strictly on input data" maps to `ds_tag` and is preserved. Analysis below is against the actual V3 code.

## Coverage Matrix

| # | Audit instruction / checkpoint | Status | Note |
|---|---|---|---|
| 1 | Inspect `trap_manager.rs` | FINDING | Reconstruction accepts off-line fabricated shard pairs as attribution evidence → HYP-01-1 |
| 2 | Inspect `conflict_manager.rs` | CLEAN* | Fingerprint creation/signature gates solid; t_id-only dedupe suppresses equivocation evidence → HYP-01-2 (LOW) |
| 3 | Inspect conflict handlers (`app_service/` + `wallet/`) | FINDING | First-success pair extraction + any-pair import gate amplify HYP-01-1; proof_id immunity pre-occupation → HYP-01-3 (LOW) |
| 4 | Inspect `models/conflict.rs` | CLEAN | Fingerprint struct fields all signature-bound or locally assigned; no unauthenticated trust decision on a field |
| 5 | Inspect `l2_gateway.rs` + `models/layer2_api.rs` | UNCERTAIN | Digest is length-prefixed & domain-separated; verdict path requires trusted server key. Residual dependency on serde_json field-order stability for cross-language server sig verification (interop assumption, not exploitable client-side) |
| 6 | Trap evasion: modify/omit parameters so validation passes without identity binding | CLEAN | Spends without trap_data rejected via L2-sig challenge tag (chain.rs:700-712); placeholder/"empty" shards rejected by `validate_shard_structure` (trap_manager.rs:194-213, chain.rs:360-363); trap-without-witness rejected at handover (transaction_handler.rs:327-430); ds_tag recomputed & enforced (chain.rs:365-385) |
| 7 | Framing an innocent party | PARTIAL | Third-party framing requires Schnorr forgery (sound). But the perpetrator can substitute ANY identity whose secret they control → HYP-01-1 (HIGH) |
| 8 | DS-tag collision/manipulation: same input under different identities/prefixes | CLEAN | `ds_tag = SHA3-256_lenprefixed(prev_hash ‖ sender_eph)` strictly input-only (voucher_manager/transaction.rs:195), recomputed at chain validation (chain.rs:378-385), proof structure (conflict_manager.rs:606-621), race admission (`reproduces_local_tag`, conflict_handler.rs:1380-1410) and gossip ingress for known tags (HMSEC-SA04-10, conflict_handler.rs:1147-1187). Prefix-independent since F16-era rework; no output data enters the tag |
| 9 | False dispute injection / fake L2 envelopes | CLEAN | Reporter signature over proof_id (conflict_manager.rs:493-516); proof_id re-derivation (:416-425); did:key claims require shard verification (conflict_handler.rs:438-473); imported layer2_verdicts stripped (Gate 0, :374-391); suspected_identity neutralized (Gate 0b, :393-411); L2 quarantine needs server signature over digest with locally-derived challenge/voucher id (l2_facade.rs:282-317) |
| 10 | Identity reconstruction edge cases (÷0, non-canonical encodings, identical U/tau) | CLEAN | Guards: identical tau (trap_manager.rs:458-462), identical shards (:465-469), c=0 (:497-501), identity point (:505-510), torsion-free M_R/X (:483-489, :516-522), canonical scalars (:156-166), canonical Edwards y (:222-240). Invert-of-zero cannot occur (tau guard precedes :471) |
| 11 | Core invariant: DS-tag strictly input data, never outputs | CLEAN at generation | Generation uses only (x, eph_pub, ds_tag) — trap_manager.rs:294-318; amount/recipient/t_time never enter mu, masking, nonce or tau. t_id excludes trap/guard (chain.rs:653-666) preventing circularity abuse |
| 12 | Deterministic derivation bound to sender key (V2: HKDF; V3 equivalent) | CLEAN | Nonce/masking derived from secret scalar + mu/ds_tag via domain-separated hashes (trap_manager.rs:300-318); deterministic across forks of one input (same witness covers both shards — unit-tested :784-860) |
| 13 | L2 O(1) duplicate-tag detection + signed dispute proofs | CLEAN | Bucketed by ds_tag everywhere (content-addressed after AUDIT-01-F11, conflict_manager.rs:848-892); dispute proofs signed by reporter; authoritative verdicts only via trusted-key gateway |
| 14 | Open exploration / assumption-busting | FINDING | HYP-01-1 (fabricated-shard attribution substitution), HYP-01-2 (equivocation dedupe suppression), HYP-01-3 (proof_id pre-occupation), HYP-01-4 (unbounded local-branch timestamps in Earliest-Wins) |
| 15 | Fail-first TDD tests in `tests/security_audit_module_01_traps.rs` | N/A | Research-only run; per-hypothesis testable flags + fail-first sketches provided below |
| 16 | Standardized metadata docblock | N/A | No test files written (research constraint) |
| 17 | Design-intent triage against DESIGN_INTENT_TRIAGE.md / PRIVACY_FAQ.md | FLAGGED | Per-finding triage notes included; HYP-01-4 likely partially design-intent |

## Hypotheses

### HYP-01-1: Fabricated sibling shard substitutes the extracted offender identity (trap laundering)
- Severity: HIGH
- CWE: CWE-347 (Improper Verification of Cryptographic Signature — off-line constructible evidence accepted as signer-bound attribution); secondary CWE-345
- Target: src/services/trap_manager.rs:452-569 (`reconstruct_identity`, `extract_sst_identity` — reconstruction defines X identically for ANY input, no signer-membership check); src/wallet/conflict_handler.rs:824-898 (first-success extraction sets definitive `offender_id`), :659-743 (`verify_stored_trap_shards_against_identity` any-pair gate, AUDIT-01-F13)
- Attack:
  1. Spender S legitimately owns input anchor `(prev_hash P, ephemeral key E)`; `ds_tag D = H(P‖E)` is public once fork A gossips/handover occurs.
  2. S double-spends creating genuine fork A (shard `(R_A, s_A)`, τ_A).
  3. S picks a burner keypair w. Choose k∈ℝ_q, set R̂ = k·G, c = H_chal(μ(D,E), R̂), ŝ = k + c·w. Solve Lagrange-consistent sibling shard for a fresh t_id_B (τ_B): `R_B = (R̂·(τ_A−τ_B) + τ_B·R_A)/τ_A`, `s_B = (ŝ·(τ_A−τ_B) + τ_B·s_A)/τ_A`. Both are well-formed curve point / canonical scalar, so all HMSEC-SA04-09 structural gates and every degenerate-case guard in `reconstruct_identity` pass.
  4. S signs the fingerprint `(D, t_id_B, E, R_B, s_B, …)` with E's private key — it passes `verify_fingerprint_signature` AND the HMSEC-SA04-10 local-context gate (E IS the locally revealed input key). Attach it to the payment bundle or gossip it.
  5. Victim/bystander bucket D = {genuine A, fabricated B} → collision detected → `verify_and_create_proof` tries pairs; `extract_sst_identity` reconstructs X̂ = (ŝ·G − R̂)·c⁻¹ = w·G = burner pubkey → `offender_id = did:key(burner)`, `suspected_identity` mirrors it.
  6. Imported proofs pass Gate 3b (the fabricated pair verifies against the burner by construction), including via the AUDIT-01-F13 any-pair rule when mixed with genuine shards. Network-wide attribution lands on the burner; the true holder key x·G never appears.
- Root cause: `X̂ := (ŝ·G − R̂)/c` holds *identically* for arbitrary shard inputs — extraction proves only that both shards lie on one common line, NOT that the line was produced by `generate_sst_trap`. The EUF-CMA argument bounds what an attacker can *target* (a third-party key needs its discrete log) but does not bind the output to the true signer when even one off-line shard joins the collision set. The torsion/canonical guards (added for HMC-SEC-02-08 junk-line DoS) do not distinguish "fabricated line through attacker's own key" from a genuine signer line. First-match pair order (canonical t_id sort, conflict_handler.rs:826-837) makes the substituted identity deterministic and attacker-selectable via t_id choice; the comment "Genuine multi-fork collisions yield the same identity for every pair" (conflict_handler.rs:833-835) is false under injection.
- Confidence: HIGH (algebra verified step-by-step against guard order in reconstruct_identity; all guards shown satisfiable)
- Testable: YES — fail-first integration test: generate honest sk_S, ds_tag, eph, two-fork baseline and assert `extract_sst_identity == ed25519_pk_to_curve_point(sk_S.vk())`; then add the crafted third fingerprint built per step 3 (needs only public trap_manager constants + curve25519 scalar/point ops mirroring `sst_scalar`/`sst_challenge`) into the bucket, call `verify_and_create_proof`, and assert the resulting `proof.offender_id == did:key(S)` (Soll behavior). On current code the assertion FAILS (offender becomes the burner DID).

### HYP-01-2: Gossip ingress dedupe on t_id silently drops equivocation evidence
- Severity: LOW
- CWE: CWE-697 (Incorrect Comparison / insufficient discrimination criterion)
- Target: src/wallet/conflict_handler.rs:1254-1263 (`process_received_fingerprints`: `!entry.iter().any(|existing| existing.t_id == fp.t_id)`); src/services/conflict_manager.rs:872-881 (`import_foreign_fingerprints`, same t_id-only dedupe)
- Attack: A signer equivocating on ONE handover produces two validly-signed fingerprints with the SAME t_id but diverging signature-bound fields (e.g. two different `trap_r/trap_s` or privacy-guard commitments under one input — exactly the HMSEC-SA04-08 scenario). Whichever copy arrives first is admitted; the second is dropped as a "duplicate" before storage. `check_for_double_spend`'s `has_equivocation` detector (conflict_manager.rs:405-427) therefore can never observe signer equivocation arriving via gossip — only distinct-t_id forks trigger.
- Root cause: Deduplication key (t_id) is narrower than the evidence identity; divergence within one t_id is precisely the fraud signal, yet it is discarded at ingress instead of stored for the equivocation gate.
- Confidence: HIGH (code paths confirmed)
- Testable: YES — craft two fingerprints, identical ds_tag/t_id/eph, different trap_r, both individually passing `verify_fingerprint_signature`; ingest both via `import_foreign_fingerprints`; assert the stored bucket contains 2 entries and `check_for_double_spend` reports a conflict for that hash. Currently only 1 entry is stored → assertion fails.

### HYP-01-3: Proof-ID immunity lets a first-arriving witness-note occupy a proof_id and downgrade later verified imports
- Severity: LOW
- CWE: CWE-400 (Resource Exhaustion / state-slot pre-occupation)
- Target: src/wallet/conflict_handler.rs:368-372 (`import_proof` immunity check precedes all gates and ignores content quality)
- Attack: An attacker who can compute `(offender_id, fork_point_prev_hash)` of a future honest proof (public once conflicts gossip; for gossip soft proofs these are derivable from the ds_tag + linkage) pre-imports a garbage-content proof with the same proof_id at a target peer. It passes gates only when no local voucher context exists (stored as "unverified witness note"). When the victim's fully verified proof arrives later, immunity discards it — skipping Gate-4 status mutation ("Lost race in imported proof" quarantines), role assignment, and verified-evidence marking at that peer.
- Root cause: Immunity is keyed solely on proof_id without distinguishing an unverified witness note from a cryptographically verified proof; a lower-trust record permanently blocks a higher-trust record for the same conflict.
- Confidence: MEDIUM (mechanism confirmed; practical gain limited because real-time quarantine also runs via `resolve_conflict_offline` independent of proof import)
- Testable: YES — two-wallet test: wallet B first imports an attacker-built proof P (valid structure/reporter-sig, anonymous offender, no local context → witness note), then imports the victim's honest verified proof with identical proof_id; assert B's store entry reflects the verified variant (e.g. conflicting transactions match the honest txs / status mutation applied). Currently the second import returns Ok(()) with no effect → fails.

### HYP-01-4: Earliest-Wins plausibility window exempts locally ingested branches entirely
- Severity: LOW (design-intent adjacent — run through DESIGN_INTENT_TRIAGE)
- CWE: CWE-20 (Improper Input Validation — timestamp trust boundary applied asymmetrically)
- Target: src/wallet/conflict_handler.rs:1429-1440 (`resolve_conflict_offline`: `is_local` candidates bypass min/max plausibility window); interaction with transaction_handler.rs:180-227 (bundle ingestion enforces only far-future rejection; past-dated txs accepted if chain-monotonic)
- Attack: A previous holder delivers a genuinely signed sibling branch dated far in the past (chain-valid: only strict monotonicity along its own chain applies). At victim ingestion it becomes a LOCAL instance; in the subsequent race its decrypted timestamp participates unbounded and always defeats the honest recent branch → victim's voucher quarantined deterministically. The AUDIT-01-F14 floor protects only foreign-fingerprint candidates.
- Root cause: Trust boundary drawn on possession locality rather than timestamp plausibility; local ingestion grants chain-backed trust to attacker-chosen timestamps.
- Confidence: HIGH (mechanics certain; classification as vulnerability vs. accepted offline-cash residual risk uncertain)
- Testable: YES — build voucher with fork branch t_time ≈ now−2y (passes `validate_voucher_against_standard`), deliver to victim wallet holding the honest recent sibling, process bundle, assert honest branch remains Active. Current code quarantines it → fails. [INTENT-CHECK]: may be covered by the documented "Fraud Detection, Not Prevention" paradigm.

## Gaps

**Instructions that produced NO finding (clean):**
- DS-tag derivation & enforcement: strictly input-bound at every producer/consumer (generation, chain validation, proof structure, race admission, ingress gating). No amount/recipient/prefix influence found anywhere.
- Trap parameter omission/evasion: all four evasion routes (missing trap_data, placeholder shards, unsigned garbage shards, missing private witness) are fail-closed (HMSEC-SA04-09, HMSEC-SA06-11, AUDIT-01-F12/R5).
- Degenerate-case identity reconstruction: complete guard firewall; no division-by-zero, malleability (canonical scalar + canonical y policies), replay (identical tau/shards/t_id), or neutral-element attribution path remains.
- False dispute injection by third parties: reporter-signature, proof-id consistency, attribution gate 3b, Gate 0/Gate 0b neutralizations, and trusted-key L2 gateway close the classic forgery routes.
- L2 quarantine flow: challenge tag/voucher id/ephemeral expectation are all locally derived (l2_facade.rs:282-317); server signature mandatory; imported verdicts stripped.

**Uncertain items:**
- `process_l2_verdict` signs `serde_json::to_vec(&envelope.verdict)` — relies on serde field-order determinism matching the server's serializer (cross-language interop assumption). Not client-exploitable; flagged as hardening/interop risk only.
- `scan_and_rebuild_fingerprints` skips `Endorsed` instances entirely (conflict_manager.rs:298-306): escrowed vouchers contribute nothing to local_history; an issuer double-spending an endorsed voucher's input is invisible to the guarantor's detector. Possibly intentional (escrowed funds are not spendable) — needs design-intent triage; not classified as a finding.
- `get_proof_id_for_voucher` matches 4/5 (sender-involvement, recipient-match) can associate an unrelated proof with a voucher for UI purposes — display-layer imprecision, no status impact.
- Earliest-wins itself (attacker dating own fork earliest) is inherent offline-cash residual risk per the documented threat model; only the *local-branch asymmetry* (HYP-01-4) was reported.

**Spec-drift note:** audit prompt's V2 equations (HKDF slope `m`, `V = u·m + ID`, SHA3 u) are superseded by SST V3; checkpoint rows above were evaluated against V3 semantics. Any fix for HYP-01-1 must preserve kryptographische Stabilität of the serialization formats (AGENTS.md domain/view separation).

---

**Finding count:** CRITICAL: 0 · HIGH: 1 · MEDIUM: 0 · LOW: 3
