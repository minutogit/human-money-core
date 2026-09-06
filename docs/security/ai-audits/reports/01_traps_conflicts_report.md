# Security Audit Module 01 — Double-Spend Trap, DS-Tags & Conflict Detection

**Date:** 2026-08-24
**Scope:** `trap_manager.rs`, `conflict_manager.rs`, `app_service/conflict_handler.rs`, `models/conflict.rs`, `l2_gateway.rs`, `models/layer2_api.rs` plus the consuming wallet flows (`wallet/conflict_handler.rs`, `wallet/transaction_handler.rs`)
**Method:** Adversarial hypothesis scan (trap evasion/framing, DS-tag manipulation, false dispute injection, identity-reconstruction edge cases) with Fail-First TDD verification
**Test file:** `tests/security_audit_module_01_traps.rs`

---

## 1. Findings Overview

| Finding ID | Title | Severity | Triage Outcome |
| :--- | :--- | :--- | :--- |
| AUDIT-01-F01 | Gossip-poisoning false quarantine via `resolve_conflict_offline` | High | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F02 | Schnorr response scalar malleability in `verify_trap` | Medium | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F03 | Unprefixed string concatenation in `calculate_l2_payload_hash_raw` | Low | `[FALSE POSITIVE / ACCEPTED RISK]` |
| AUDIT-01-F04 | Debug `println!` in production conflict analysis | Info (hygiene) | `[CONFIRMED]` (removed) |
| AUDIT-01-F05 | Unverified did:key attribution claim at proof-import boundary | High | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F06 | Placeholder substring skip weakens >=2-trap attribution threshold | Low | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F07 | Trap-anchoring framing via arbitrary-slope Schnorr proofs | Critical | `[CONFIRMED VULNERABILITY]` — PENDING architectural fix |
| AUDIT-01-F08 | False dispute injection on the local creation path (`verify_and_create_proof`) | High | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F09 | Degenerate fork data (identical blinded IDs) yields attacker-chosen "identity" | Medium | `[CONFIRMED VULNERABILITY]` |
| AUDIT-01-F10 | proof_id canonicalization desync bypasses import immunity/dedup | Medium | `[CONFIRMED VULNERABILITY]` |

## 2. Confirmed Vulnerabilities (remediated)

### AUDIT-01-F01 — Gossip-Poisoning False Quarantine (High)

* **Vector:** Gossip fingerprints are unauthenticated. The XOR key of
  `encrypted_timestamp` is publicly derivable (`prev_hash + t_id`), so an
  attacker can craft a sibling fingerprint for a victim's real ds_tag whose
  decrypted timestamp is `0`. Receiving any bundle containing this poison
  let the forged branch win the offline "Earliest Wins" race and quarantined
  the victim's legitimate voucher (`reason: "Lost offline race"`).
* **Proof:** Fail-first test `f01_gossip_poisoning_must_not_quarantine_local_voucher`
  reproduced the quarantine on unpatched code.
* **Remediation:** `resolve_conflict_offline` now restricts race candidates to
  fingerprints whose `t_id` corresponds to a locally-held transaction.
  Path-reunion detection (both forks local) is unaffected; remote-only
  branches are handled exclusively by the gated `import_proof` path.

### AUDIT-01-F02 — Schnorr Response Malleability (Medium)

* **Vector:** `verify_trap` parsed the response scalar with
  `Scalar::from_bytes_mod_order`, accepting non-canonical encodings.
  A valid proof `(R, s)` malleates to `(R, s + l)` (group order).
* **Proof:** Fail-first test `f02_verify_trap_rejects_non_canonical_schnorr_response`.
* **Remediation:** `s` is parsed via the strict canonical parser already used
  for U; encodings `>= l` are rejected.

### AUDIT-01-F05 — Forged Attribution Claims on Import (High)

* **Vector:** The anti-framing invariant on `ProofOfDoubleSpend.offender_id`
  ("did:key only if BOTH stored trap proofs verify") was enforced at creation
  time only. A real double-spender owning both genuine forks could sign a
  report naming an innocent did:key identity; every existing gate passes
  because the transactions are cryptographically authentic. Combined with a
  backdated fork timestamp this quarantines the framed party's local branch
  and links their other vouchers to the conflict (`get_proof_id_for_voucher`,
  Match 4).
* **Proof:** Fail-first test `f05_import_proof_rejects_forged_did_key_attribution_claim`.
* **Remediation:** New import gate 4: if `offender_id` parses to a did:key
  public key, `verify_stored_proofs_against_identity` must succeed against it
  (root-account format first, then the prefix derived from the claim itself,
  so prefixed accounts are attributable as well). Anonymous and
  `ephemeral:` identifiers carry no claim and skip the gate.
* **Fixture hardening:** `tests/wallet_api/role_integration.rs` fixtures were
  upgraded to attach cryptographically valid traps bound to the claimed
  offender — matching production reality where every spend carries `TrapData`.

### AUDIT-01-F06 — Placeholder-Type Evasion (Low)

* **Vector:** `verify_stored_proofs_against_identity` skipped transactions
  whose `t_type.contains("placeholder")`. Genuine synthetic placeholders are
  already excluded structurally (no `trap_data`); the substring check only
  allowed an offender to type one REAL fork so that fewer than two traps
  verify, degrading attribution to the anonymous fallback.
* **Proof:** Fail-first test `f06_placeholder_t_type_must_not_weaken_trap_count`.
* **Remediation:** Skip logic relies solely on `trap_data` presence.

## 2a. Wave-2 Findings (Phase B, 2026-08-24)

### AUDIT-01-F07 — Trap-Anchoring Framing via Arbitrary-Slope Proofs (Critical, PENDING)

* **Vector:** `verify_trap` proves knowledge of ONE arbitrary scalar `m`
  with respect to base `X = u*G`. Nothing binds `m` to
  `derive_m(sk_sender, prev_hash)` of the CLAIMED sender. An attacker who
  knows any slope `m'` (e.g. their own) anchors both forks of a synthetic
  double spend at an innocent identity
  (`blinded_id = (u*m')*G + ID_victim`) and produces cryptographically
  GENUINE Schnorr proofs for the victim's point. The F05 import gate
  (`>=2 verified traps` against the claimed identity) therefore PASSES and
  `import_proof` persists a witness note with
  `offender_id = did:key:victim`, driving `check_reputation` to
  `TrustStatus::KnownOffender`. No local voucher context is required.
* **Proof:** Fail-first test
  `f07_trap_anchoring_framing_arbitrary_slope_must_be_rejected` reproduced
  acceptance on unpatched code (positive control with honestly bound traps
  imports fine, so the future fix cannot break honest attribution).
* **Why not patched in place:** A sound fix requires verifying the DLEQ
  equality `log_P(k) == log_G(ID)` with `P = hash_to_curve(prev_hash)` and
  `m = hash_to_scalar(k)`, i.e. the `trap_k_point`/DLEQ components must be
  carried on the wire inside `TrapData`/`ProofOfDoubleSpend`. That is a
  protocol/wire-format change (serialization stability rule; existing stored
  vouchers and cross-client compatibility). Rejecting all unbound did:key
  claims instead would break every legitimate attribution (import gate 3b
  consumers, victim-role fixtures).
* **Status:** Test kept as
  `#[ignore = "pending architectural fix - see report AUDIT-01-F07"]`;
  remediation requires the DLEQ wire extension plus verification at BOTH
  attribution gates (creation + import).

### AUDIT-01-F08 — False Dispute Injection on the Creation Path (High, remediated)

* **Vector:** In `verify_and_create_proof`, the >=2-verified-traps guard was
  only consulted when `offender_id == "anonymous"`. If a collision contained
  one real local transaction, its `sender_id` (a did:key) became the
  authoritative offender claim WITHOUT verification. An attacker gossips a
  poison fingerprint reusing a publicly derivable ds_tag of the victim's own
  spend/init anchor under a fabricated `t_id`; the wallet then created and
  PERSISTED a proof naming the victim (or any third party owning the local
  transaction) as offender — built from [real tx + synthetic placeholder].
* **Proof:** Fail-first test
  `f08_poison_fingerprint_must_not_persist_local_did_key_offender_claim`
  showed the persisted conflict naming the victim's did:key.
* **Remediation:** Any did:key candidate taken from
  `conflicting_transactions[0].sender_id` must now pass
  `verify_stored_proofs_against_identity` against the claimed point (root
  prefix first, then claim-derived prefix, mirroring import gate 3b);
  otherwise it is downgraded to ANONYMOUS and the conservative extraction/
  ephemeral fallbacks proceed unchanged. Non-did:key identifiers are
  untouched. Genuine both-forks-local evidence (two verifying traps) keeps
  full did:key attribution.

### AUDIT-01-F09 — Degenerate Fork Data: identical blinded IDs (Medium, remediated)

* **Vector:** `extract_id_point_from_raw_data` guarded `delta_u == 0` twice
  but never `delta_v == 0`. For two trap entries with byte-identical blinded
  IDs and distinct canonical U scalars, the reconstruction degenerates to
  `ID = V1 - (0 * delta_u^-1) = V1`: Ok(attacker-chosen point) instead of a
  hard error. The result fed `suspected_identity` (advisory sanctions).
* **Proof:** Fail-first test `f09_extract_id_rejects_identical_blinded_ids`
  (with full 32-byte canonical U scalars) returned Ok on unpatched code.
* **Remediation:** New guard rejecting `delta_v.is_identity()` before
  inversion; genuine forks always differ in V.
* **Regression reconciliation:** The pre-existing
  `identity_trap_audit::test_extracted_point_validity_check` used V1==V2
  incidentally as a convenience source for a returned point; it now asserts
  the new rejection contract explicitly and runs its downstream validity
  checks on distinct points (test intent unchanged).
* **Observation:** The older guard test
  `guard_extract_id_rejects_identical_u` passed for a weaker reason than its
  name suggests (4-byte U encodings are rejected by the scalar length check,
  not by the identical-U guard). Its assertion (rejection) remains correct;
  noted here so future readers do not over-trust its coverage.

### AUDIT-01-F10 — proof_id Canonicalization Desync (Medium, remediated)

* **Vector:** `derive_proof_id` hashed the RAW offender_id bytes (first
  `"@did:key:z"` occurrence, no sanitization), while
  `get_pubkey_from_user_id` strips whitespace and splits at the LAST `@`.
  Render variants of the same logical offender identity (`"anonymous "` vs
  `"anonymous"`) derived different proof_ids, bypassing the import immunity
  rule ("already known -> ignore", keyed on proof_id): the same logical
  conflict could be imported repeatedly as new conflicts (duplicate entries,
  resolution splitting, UI/event spam).
* **Proof:** Fail-first test
  `f10_proof_id_must_be_canonical_across_offender_render_variants`
  (unit-level variant collapse + integration-level dedup assertion).
* **Remediation:** `derive_proof_id` canonicalizes offender_id identically
  to `get_pubkey_from_user_id` (whitespace strip + `rfind("@did:key:z")`).
  Canonical inputs derive byte-for-byte identical proof_ids as before, so
  no stored data or signature is invalidated.

## 2b. Wave-3 Findings (Phase B adversarial re-audit of the SST state layer, 2026-08-25)

**Scope:** Protocol/state layer around the V3 SST cryptography (`fdfeb80`/`d31bd89`/`b006cfb`).
The EUF-CMA framing resistance of two-shard reconstruction was algebraically re-checked and
held; all confirmed findings target the surrounding protocol and state machine.

| Finding ID | Hypothesis | Title | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| AUDIT-01-F11 | WH3-01-101 (+ folds WH3-01-107) | Cross-voucher false quarantine via import bucket-stuffing | Critical | `[CONFIRMED VULNERABILITY]` — FIXED | `f11_import_bucket_stuffing_must_not_quarantine_cross_voucher_instances` | `conflict_manager.rs::import_foreign_fingerprints` |
| AUDIT-01-F12 | WH3-01-103 (cross-ref WH3-02-201) | Guard-less transfers accept poisoned trap shards (R5 gap) | High | `[CONFIRMED VULNERABILITY]` — PENDING (cross-module) | `f12_guardless_transfer_with_poisoned_trap_shards_must_be_rejected` (`#[ignore]`) | `transaction_handler.rs` (outside module scope) |
| AUDIT-01-F13 | WH3-01-102 | n>=3 shard firewall weaponized against real proofs | High | `[CONFIRMED VULNERABILITY]` — FIXED | `f13_offline_extra_shard_must_not_block_import_of_authentic_proof` | `trap_manager.rs::verify_stored_trap_shards_against_identity` |
| AUDIT-01-F14 | WH3-01-104 | Epoch-near candidates win the Earliest-Wins race | Medium | `[CONFIRMED VULNERABILITY]` — FIXED | `f14_epoch_near_sibling_timestamp_must_not_win_offline_race` | `conflict_handler.rs::resolve_conflict_offline` (plausibility gate) |
| AUDIT-01-F15 | WH3-01-105 | Offline race reactivates L2-adjudicated/Endorsed instances | Medium | `[CONFIRMED VULNERABILITY]` — FIXED | `test_resolve_conflict_offline_must_not_overwrite_adjudicated_statuses` (internal) | `conflict_handler.rs::resolve_conflict_offline` (write phase) |
| AUDIT-01-F16 | WH3-01-106 | Nondeterministic attribution via HashSet pair choice | Medium | `[CONFIRMED VULNERABILITY]` — FIXED | `test_attribution_is_deterministic_for_three_member_buckets` (internal) | `conflict_manager.rs::check_for_double_spend` + `conflict_handler.rs::verify_and_create_proof` |

### AUDIT-01-F11 — Import Bucket-Stuffing (Critical, remediated)

* **Vector:** `import_foreign_fingerprints` trusted the ATTACKER-controlled JSON map
  key as the bucket identity instead of re-keying by content (`fp.ds_tag`). Two genuine,
  individually well-signed gossip fingerprints from DIFFERENT vouchers stuffed under one
  foreign key formed a fabricated "collision"; in `resolve_conflict_offline` BOTH members
  matched locally-held transactions and entered the Earliest-Wins race unconditionally.
  The member decoded against the wrong fork prev_hash yields a uniform-garbage timestamp,
  loses with probability ~1 and its innocent instance was quarantined
  (`"Lost offline race"`). Additionally a junk soft-proof persisted that linked unrelated
  vouchers to the fabricated conflict (WH3-01-107).
* **Proof:** Fail-first test reproduced the quarantine on unpatched code.
* **Remediation:** Imported entries are re-keyed by their CONTENT (`fp.ds_tag`),
  matching every other ingress path. Legitimate exports already use ds_tag keys;
  coherent buckets collapse to single-member entries so cross-voucher conflicts become
  structurally impossible.

### AUDIT-01-F12 — R5 Witness Enforcement Gap (High, PENDING cross-module)

* **Vector:** The only cryptographic coercion forcing a spender to publish shards that
  reconstruct to THEIR identity is `verify_sst_witness` at L1 handover — executed solely
  nested under `if let Some(guard) = &last_tx.privacy_guard`. A public-mode transaction
  whose recipient is a plain did:key passes Layer-0 without any guard-decryption
  requirement; combined with poisoned shards (garbage under the genuine ds_tag,
  correctly re-signed per HMC_TX_AUTH_V3 with the held input key) the payment is accepted
  and activated with identity-unbound traps. When that branch later double-spends, SST
  extraction deterministically fails -> attribution downgrades: the offender unilaterally
  blinds the autonomous deanonymization chain. Flexible/Stealth flows remain protected by
  the Layer-0 anonymous guard-decryption requirement, so the gap is Public-mode specific.
* **Proof:** Fail-first test (custom signed Public-mode standard via
  `create_custom_standard`) proved acceptance on unpatched code; an honest control
  transfer stays green.
* **Why not patched here:** The minimal fix (reject any incoming last transaction
  carrying `trap_data` without a verifying private witness, regardless of guard presence)
  lives in `src/wallet/transaction_handler.rs::process_encrypted_transaction_bundle_inner`
  — outside module 01's exclusive file scope (transaction/state-integrity owner).
* **Status:** Test kept as `#[ignore = "CONFIRMED-PENDING ..."]`; remediation is a small,
  well-defined hoist of the R5 enforcement out of the guard-presence condition.

### AUDIT-01-F13 — Shard-Line Firewall Weaponized (High, remediated)

* **Vector:** Asymmetric attribution contract: creation wrote a did:key claim when the
  FIRST two bucket members reconstructed it, while import gate 3b demanded full-set line
  consistency for ALL n >= 3 shards. A double-spender broadcasting one structurally valid
  but off-line third shard made every subsequent import of honestly attributed reports
  fail hard — trivial evasion/propagation DoS without breaking EUF-CMA.
* **Proof:** Fail-first test showed the authentic report rejected at import.
* **Remediation:** `verify_stored_trap_shards_against_identity` now evaluates every
  colliding PAIR and succeeds when any pair reconstructs a valid Schnorr signature for
  exactly the claimed key; extra shards neither contribute to nor veto the claim.
  Fabricating a verifying pair for an innocent key remains an EUF-CMA forgery, so
  anti-framing is untouched; the strict full-set firewall
  (`verify_sst_shards_consistency`) stays unchanged for its direct callers/regression
  guards.

### AUDIT-01-F14 — Missing Lower Plausibility Bound (Medium, remediated)

* **Vector:** The timestamp window rejected only `0` and far-future values. Any holder
  of the input one-time key (documented residual-risk class) dated siblings to the Unix
  epoch (`decrypted_nanos = 3600`), passed the gate and beat every genuine wall-clock-era
  branch — contradicting the code's own "near-wall-clock" rationale.
* **Proof:** Fail-first test quarantined the honest branch on unpatched code.
* **Remediation:** Symmetric lower bound `now - 365d` (aligned with the shortest standard
  validity range P1Y); blind grinding success shrinks to ~window/2^128. Collisions older
  than the lookback remain adjudicable via the gated proof-import path.

### AUDIT-01-F15 — Write Phase Without Status Guard (Medium, remediated)

* **Vector:** The write phase of `resolve_conflict_offline` overwrote ANY prior status
  with the race outcome: instances quarantined by a signed L2 verdict or held as
  `Endorsed` escrow were reactivated to `Active` whenever a later conflict run (executed
  on EVERY bundle receipt) declared their t_id winner — letting offenders circumvent
  adjudication with a verdict-less proof variant.
* **Proof:** Internal fail-first test flipped both Endorsed and L2-verdict-quarantined
  winners to Active on unpatched code.
* **Remediation:** Monotonic status protection: `Active` may only degrade
  (Active->Quarantined); an existing Quarantined can only be confirmed, never
  reactivated; adjudicated/terminal states (Endorsed, Archived, Expired, Incomplete) are
  never mutated by heuristic races. Reactivation requires new cryptographic evidence via
  the gated paths. Observation: the `import_proof` FullyVerified path also writes status
  without a prior-status guard, but only after full cryptographic verification of the
  conflicting transactions (strictly stronger evidence class); left as-is and noted for
  future hardening.

### AUDIT-01-F16 — Nondeterministic Attribution Pair Choice (Medium, remediated)

* **Vector:** `check_for_double_spend` materialized bucket members from a `HashSet`, and
  `verify_and_create_proof` extracted identities from positional members `[0]/[1]` only.
  For buckets with >= 3 members (two genuine forks + one structurally valid off-line
  shard) the offender identity differed between runs — measured: 19 distinct outcomes in
  40 iterations, alternating between the true did:key attribution and the ephemeral
  fallback — breaking proof_id-keyed dedup/immunity, UI consistency and forensics.
* **Proof:** Internal fail-first test asserted one stable outcome across repeated fresh
  HashMap seeds; unpatched code produced 19 variants.
* **Remediation:** Canonical bucket ordering by t_id (total order, unique per bucket)
  plus evaluation of ALL colliding pairs in canonical order (first successful extraction
  wins). Genuine multi-fork collisions put every shard on one line, so every pair yields
  the same identity; the outcome is now a deterministic function of the evidence set.

## 3. Hygiene

* **AUDIT-01-F04:** Removed debug `println!` from
  `conflict_manager::check_for_double_spend`.

## 4. Accepted Risk / False Positive

### AUDIT-01-F03 — L2 Payload Hash Concatenation

`calculate_l2_payload_hash_raw` concatenates the two leading string fields
without length prefixes. Within the client threat boundary this is not
exploitable: `layer2_voucher_id` is exact-string-compared against the expected
value and both fields have fixed canonical formats (64-char hex / Base58
hash). Changing the serialization would invalidate every existing
`layer2_signature` and is therefore out of scope for a patch release. The
canonical-format assumption is now documented on the function; a wire-format
migration MUST use length-prefixed hashing if the formats are ever relaxed.

## 5. Invariant Verification (guards, passing before AND after)

* `guard_extract_id_rejects_identical_u`: identical reduced scalars U error
  before inversion (`delta_u == 0` guard intact).
* `guard_extract_id_rejects_non_canonical_u`: non-canonical `(u, u+l)`
  encodings rejected by the strict canonical parser.
* DS-Tag invariant re-verified during review: `ds_tag` is computed exclusively
  from `hash(prev_hash || sender_ephemeral_pub)` (`transaction_handler.rs`),
  never from amounts/recipients/output parameters.

---

## Post-Audit Design-Intent Triage Summary

Reference: [`DESIGN_INTENT_TRIAGE.md`](./DESIGN_INTENT_TRIAGE.md)

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-01-F01 | CWE-349 | `[CONFIRMED VULNERABILITY]` | Quarantine races must never consume unauthenticated gossip-only candidates; contradicts the documented principle that unverified data must not mutate voucher states. | Remediated with Fail-First TDD test. |
| AUDIT-01-F02 | CWE-347 | `[CONFIRMED VULNERABILITY]` | Violates the codebase-wide canonical-scalar invariant established for U; no offline feature depends on lenient parsing. | Remediated with Fail-First TDD test. |
| AUDIT-01-F03 | CWE-20 | `[FALSE POSITIVE / MISINTERPRETATION]` | Not exploitable client-side under current canonical field formats; fix would break all existing L2 signatures (protocol wire change). | Documented canonical-format assumption on `calculate_l2_payload_hash_raw`. |
| AUDIT-01-F04 | CWE-532 | `[CONFIRMED]` | Leftover debug output in production path. | Print statement removed. |
| AUDIT-01-F05 | CWE-345 | `[CONFIRMED VULNERABILITY]` | Import boundary must re-enforce the anti-framing invariant documented on `offender_id`; honest reports always satisfy it. | Remediated (import gate 4) with Fail-First TDD test + fixture hardening. |
| AUDIT-01-F06 | CWE-354 | `[CONFIRMED VULNERABILITY]` | Attacker-influenced string fields must not gate security-relevant counting; synthetics are structurally distinct. | Remediated with Fail-First TDD test. |
| AUDIT-01-F07 | CWE-347/345 | `[CONFIRMED VULNERABILITY]` (pending) | The Schnorr statement ("knowledge of some slope") is weaker than the attribution claim made from it. Sound fix = DLEQ wire extension (`trap_k_point` in `TrapData`) + verification at both attribution gates; a hard reject of unbound claims would break all legitimate attribution. Wire-format changes violate the serialization stability rule for a patch release. | Fail-First exploit test added, kept `#[ignore]`d; remediation plan documented. |
| AUDIT-01-F08 | CWE-349/345 | `[CONFIRMED VULNERABILITY]` | The >=2-trap anti-framing invariant applies to EVERY did:key claim, also on the creation path; unverified gossip must not select an attribution target. Conservative fallbacks keep offline forensics fully functional. | Remediated (claim verification + ANONYMOUS downgrade) with Fail-First TDD test. |
| AUDIT-01-F09 | CWE-20/754 | `[CONFIRMED VULNERABILITY]` | Degenerate fork data must fail closed; the existing `delta_u` guard documents exactly this design intent. No feature depends on bogus identity points. | Remediated (`delta_v.is_identity()` guard) with Fail-First TDD test. |
| AUDIT-01-F10 | CWE-172 | `[CONFIRMED VULNERABILITY]` | Deterministic proof_id derivation requires canonical identifier parsing shared by ALL consumers; dedup/immunity keyed on non-canonical data is bypassable. Canonical inputs remain byte-compatible. | Remediated (canonicalization parity) with Fail-First TDD test. |
| AUDIT-01-F11 | CWE-349/20 | `[CONFIRMED VULNERABILITY]` | Bucket identity must be content-addressed; attacker-controlled transport map keys enable fabricated collisions that quarantine innocent active vouchers with genuine signatures. No offline feature depends on foreign key trust. | Remediated (content re-keying in `import_foreign_fingerprints`) with Fail-First TDD test. |
| AUDIT-01-F12 | CWE-354/20 | `[CONFIRMED VULNERABILITY]` (pending) | R5 fail-closed handover must key on trap presence, not guard-envelope presence; documented SST guarantee contradicted by conditional enforcement. Fix is a small hoist in the receive path (`transaction_handler.rs`), owned by the transaction/state-integrity module. | Exploit reproduced, test `#[ignore]`d as CONFIRMED-PENDING with remediation plan. |
| AUDIT-01-F13 | CWE-628/757 | `[CONFIRMED VULNERABILITY]` | Attribution contract must be identical at creation and import; a single attacker-broadcast off-line shard must not veto authentic evidence. Anti-framing unaffected: any claimed pair must still reconstruct a valid signature under the claim (EUF-CMA). | Remediated (pair evaluation in `verify_stored_trap_shards_against_identity`) with Fail-First TDD test. |
| AUDIT-01-F14 | CWE-20 | `[CONFIRMED VULNERABILITY]` | Plausibility gates must enforce their own documented rationale symmetrically; epoch-near candidates otherwise win every race within the holder class. Rejection direction is fail-safe (status quo preserved). | Remediated (lower bound 365d) with Fail-First TDD test. |
| AUDIT-01-F15 | CWE-285 | `[CONFIRMED VULNERABILITY]` | Status transitions are monotonic by design intent: cryptographic verdicts/endorsements outweigh heuristic races; reactivation requires new cryptographic evidence. | Remediated (monotonic status guard in write phase) with internal Fail-First TDD test. |
| AUDIT-01-F16 | CWE-703/20 | `[CONFIRMED VULNERABILITY]` | Attribution must be a deterministic function of the evidence set (core determinism principle); HashSet iteration order must never decide offender identities. Canonical ordering + full pair iteration preserve all honest outcomes. | Remediated (canonical sort + pair iteration) with internal Fail-First TDD test (19 variants -> 1). |

Wave-3 verification: `security_audit_module_01` filter 24/24 green
(1 additionally `#[ignore]`d: F12 CONFIRMED-PENDING), older
`security_audit_conflict_and_traps` suite 6/6, neighboring attribution suites
(trap_manager unit 4/4, identity_trap_audit 8/8, reputation 10/10,
wallet_api::role_integration 3/3) green. clippy clean for touched code paths
(no new warnings).

All remediations verified: no git commits created (per Phase-B protocol).
