# Module 04 Audit Report — Transaction Logic & State Integrity (Agent A-04)

> Wave 2, Phase B. Scope: `src/services/bundle_processor.rs`, `secure_container_manager.rs`,
> `integrity_manager.rs`, `decimal_utils.rs`, `models/voucher.rs`, `models/secure_container.rs`
> plus downstream lifecycle (`src/wallet/transaction_handler.rs`,
> `src/services/voucher_validation/chain.rs`).
> Test file: `tests/security_audit_module_04_integrity.rs`.
> Pre-existing findings SA04-01..03 were already remediated in earlier waves.

## Summary Table

| Finding-ID | Hypothesis | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA04-04 | H-04-01 Partial-commit desync on multi-voucher receive | Critical | CONFIRMED + FIXED | `sa04_04_failed_multi_voucher_receive_must_not_partially_commit` | `src/wallet/transaction_handler.rs` (snapshot-and-rollback wrapper) |
| HMSEC-SA04-05 | H-04-03 Split/change anchor overlap accepted by validator | High | CONFIRMED + FIXED | `sa04_05_split_validator_must_reject_identical_output_anchors` | `src/services/voucher_validation/chain.rs` (split branch anchor-separation check) |
| HMSEC-SA04-06 | H-04-04 Mutation gap: bundle/container signature verification | Critical (coverage) | MUTANT-KILL REGRESSION GUARD (code correct, no src change) | `sa04_06_forged_bundle_and_foreign_container_signatures_must_fail_end_to_end` | none (test-only) |
| HMSEC-SA04-07 | H-04-07 `format_for_storage` silent rounding | Medium | FALSE POSITIVE for exploitability + control test / defense-in-depth recommendation | `sa04_07_storage_formatting_is_exact_within_validated_precision_domain` | none (test-only guard) |

## Finding Details

### HMSEC-SA04-04 — Partial-Commit Desync on Receive (H-04-01)

- **CWE:** CWE-662 (Improper Synchronization / partial transaction commit)
- **Verified failure:** A 2-voucher bundle whose second member carries an unknown
  standard UUID returned `Err`, but the first voucher remained committed in
  `voucher_store` while `bundle_meta_store.history` (Layer-1 replay gate),
  `TransferReceived` events and fingerprint rebuilds never executed.
- **Triage:** `[CONFIRMED VULNERABILITY]`. Not local-only data; actively harms
  replay protection and offline forensics; no documented best-effort receive
  semantics; rollback degrades no functionality.
- **Fix:** `process_encrypted_transaction_bundle` now snapshots the wallet
  (`self.clone()`) before any mutation and restores it on any `Err`,
  mirroring the send path's temp-wallet transactional pattern in
  `execute_multi_transfer_and_bundle`. Serialization formats untouched.

### HMSEC-SA04-05 — Split Anchor Overlap Accepted (H-04-03)

- **CWE:** CWE-347 (missing output-key separation check)
- **Verified failure:** A fully self-consistent `init(100)` -> `split(60/40)`
  chain with `receiver_ephemeral_pub_hash == change_ephemeral_pub_hash`
  passed `verify_transactions` with `Ok(())`: a single key controlled both
  output branches, enabling double-spend framing of recipients and
  transfer/change fingerprint correlation.
- **Triage:** `[CONFIRMED VULNERABILITY]`. No legitimate creation path can
  produce identical anchors (recipient seed is random, change seed is HKDF-
  derived); not a documented design decision.
- **Fix:** The split branch of `verify_transactions` now rejects splits whose
  receiver and change anchors are identical
  (`ValidationError::InvalidTransaction`).

### HMSEC-SA04-06 — Signature Verification Mutation Gap Closed (H-04-04)

- **CWE:** CWE-347
- **Status:** Production code verified correct by manual review; the surviving
  mutants from `temp/uncovered_code.md` are killed by two end-to-end vectors
  through the public path `open_and_verify_bundle`:
  - **Part A** (kills `verify_bundle_signature -> Ok(())`): forged
    `sender_signature` with garbage bytes plus recomputed self-consistent
    `bundle_id` (the ID binding excludes the signature), wrapped in an
    envelope WITHOUT signature (legitimate privacy shape). Must fail with
    `InvalidBundleSignature`; with the mutant it would be ACCEPTED.
  - **Part B** (kills `verify_container_signature -> Ok(())`): authentic
    sender payload re-wrapped in an attacker-signed container. Must fail with
    `InvalidContainerSignature`; with the mutant the attack would be ACCEPTED
    end-to-end (inner authentic signature remains valid).
- **Action:** Test-only regression coverage; no src modification.

### HMSEC-SA04-07 — Silent Rounding in `format_for_storage` (H-04-07)

- **CWE:** CWE-1339 / CWE-682 (potential conservation breach)
- **Triage:** `[FALSE POSITIVE for exploitability]`. All production routes are
  structurally protected today:
  - transfer/split: `create_transaction` enforces `validate_precision`
    BEFORE both `format_for_storage` call sites;
  - issuance: `create_voucher` formats without prior precision check, but
    `verify_transaction_basics` requires init amount == nominal_value.amount,
    so a rounded issuance fails closed downstream.
- **Action:** Control/regression guard test asserting (1) exact round-trip
  formatting within the validated precision domain and (2) an end-to-end split
  conservation tripwire that fails if upstream precision guards are ever
  removed. Defense-in-depth recommendation: harden `format_for_storage` to
  fail-on-rounding in a future major version (not applied to avoid an API break).

## Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA04-04 | CWE-662 | `[CONFIRMED VULNERABILITY]` | Receive path mutated state incrementally without rollback; phantom vouchers unregistered in replay gate. | Fail-first test + snapshot-and-rollback fix. |
| HMSEC-SA04-05 | CWE-347 | `[CONFIRMED VULNERABILITY]` | Validator never compared split output anchors; single-key control over both branches. | Fail-first test + anchor separation check. |
| HMSEC-SA04-06 | CWE-347 | Coverage gap (code correct) | Surviving bypass mutants lacked end-to-end kill tests. | Two mutant-killing regression tests via public path. |
| HMSEC-SA04-07 | CWE-1339 | `[FALSE POSITIVE]` (exploitability) | All reachable routes enforce scale <= places before formatting or fail closed. | Control/invariant tests + defense-in-depth note. |

## Verification

- Module suite: `cargo nextest run --test security_audit_module_04_integrity --status-level fail`
  → 7 passed, 0 failed.
- Full-suite verify after src fixes: `cargo nextest run --status-level fail`
  → 558 passed, 0 failed, 5 skipped (skips = pre-existing by-design ignores).

---

# Wave 3 (Adversarial Re-Audit at HEAD b006cfb, Fix Phase)

> Agent A-04, exclusive files: `tests/security_audit_module_04_integrity.rs`,
> `src/services/voucher_validation/chain.rs`, `src/services/trap_manager.rs`,
> `src/wallet/conflict_handler.rs`, `src/wallet/transaction_handler.rs`
> (+ un-ignore of `f12` in module-01 tests per coordinator routing).

## Summary Table (Wave 3)

| Finding-ID | Hypothesis | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA04-08 | WH3-04-401 Guard equivocation invisible to fraud evidence | Critical | **CONFIRMED-PENDING** (requires protocol break V4) | `sa04_08_guard_equivocation_must_produce_attributable_evidence` (`#[ignore]`d, rationale inline) | none (remediation design below) |
| HMSEC-SA04-09 | WH3-04-402 Structurally invalid SST shards accepted by validator | High | **CONFIRMED + FIXED** | `sa04_09_chain_validator_must_reject_structurally_invalid_sst_shards` | `chain.rs` + new `trap_manager::validate_shard_structure` |
| HMSEC-SA04-10 | WH3-04-403 Fingerprint ingress without input-context binding | Medium | **CONFIRMED + FIXED** | `sa04_10_fingerprint_ingress_must_bind_to_local_input_context` | `conflict_handler.rs::process_received_fingerprints` |
| AUDIT-01-F12 | WH3-01-103 Guard-less transfer accepts poisoned shards | High | **CONFIRMED + FIXED** (coordinator-routed) | `f12_guardless_transfer_with_poisoned_trap_shards_must_be_rejected` (un-ignored) | `transaction_handler.rs` (R5 keyed on trap presence) |
| HMC-SEC-02-09 | audit_02_09 Shard striping / init masquerade | Medium | **PARTIALLY UNBLOCKED** (SOLL-A green via SA04-09 fix; SOLL-B outside scope) | `audit_02_09_...` (stays `#[ignore]`d, see below) | conflict_manager.rs ownership |

## Finding Details (Wave 3)

### HMSEC-SA04-08 — Guard Equivocation Without Attributable Evidence (WH3-04-401)

- **CWE:** CWE-347 (security-critical field excluded from every authenticated digest)
- **Test repair:** The original run failed on a SETUP precondition
  ("archived copy of spend A missing"): a FULL spend re-keys the sender's
  archived copy under a NEW local instance ID, so the harvest-by-old-ID lookup
  could never succeed. The test now tracks the immutable `voucher_id` before
  both production spends and resolves the archived instances by identity.
- **Verified failure after repair:** The test reaches its vulnerability
  assertions and fails exactly as predicted — both guard variants validate,
  and `create_fingerprint_for_transaction` yields BYTE-IDENTICAL fingerprints
  for T_A (guard→Charlie) and T_AB (guard→Bob); `check_for_double_spend`
  reports nothing (`unique_t_ids == 1` collapses under HashSet dedup).
- **Triage (4-question check applied):** `[CONFIRMED VULNERABILITY]`, but NOT
  remediable without a wire-level protocol break:
  - *Option A rejected (detector/wallet-side fix):* cryptographically
    impossible. The two handovers differ ONLY in the AEAD guard blob, which is
    committed by NO authenticated structure (t_id preimage excludes it since
    V3, HMC_TX_AUTH_V3 digest excludes it, timestamp XOR-key is guard-
    independent). Any detector signal derived from unauthenticated data (e.g.
    an optional guard-hash field on `TransactionFingerprint`) is controlled by
    the attacker himself — he IS the legitimate signer of both variants and
    can strip/forge such a field via raw bundle crafting, which is precisely
    this threat model's attacker class. Grouping additionally keys on
    `unique_t_ids > 1`, an axiom equivocation violates by construction
    (one input, ONE t_id, two handovers). Honest gossip forwarding also makes
    byte-equality dedup mandatory, so "count duplicates" detectors would
    false-positive network-wide.
  - *Option B selected:* bind a hash of `privacy_guard` into the canonical
    t_id preimage OR into a future **HMC_TX_AUTH_V4** digest. Both invalidate
    every existing chain/signature and must ship as a versioned migration.
- **Remediation design (pending):**
  1. Add `guard_hash = H(privacy_guard || t_id)` to the L2 digest only
     (preferred over the t_id preimage: keeps SST tau-circularity intact and
     leaves L1 anchors untouched).
  2. Version-gated dual verification during transition: wallets verify
     layer2_signature under V3 OR V4 rules keyed on an epoch marker;
     creation emits V4 exclusively after the cutoff height.
  3. Under V4, equivocating twins carry different signatures over different
     digests while sharing (ds_tag, t_id) — the existing collision machinery
     then treats them as a genuine fork pair and `extract_sst_identity`
     attributes via the shard relation.
  4. Migration risk to document: chains created between cutoff versions are
     unverifiable under strict-V4 wallets; the epoch marker MUST be part of
     sealed profile state, not bundle data.
  Test stays `#[ignore]`d until the V4 migration lands; it fails at assertion
  (b)/(c) on current code by design (fail-first documentation).

### HMSEC-SA04-09 — Structural SST Shard Validation in Chain Validator (WH3-04-402)

- **CWE:** CWE-20 (missing structural validation of cryptographic material)
- **Verified failure:** Self-consistent public-mode chains whose tip carried
  garbage shards under the CORRECT ds_tag passed `verify_transactions` with
  `Ok(())`.
- **Fix:** New `pub(crate) trap_manager::validate_shard_structure(trap_r, trap_s)`
  enforcing the generation contract at the validator level, called from the
  `trap_data` block of `verify_transactions` for every non-init transaction:
  - Base58 decodability + exact 32-byte length for BOTH shards;
  - `trap_r`: STRICT CANONICAL compressed-Edwards encoding (masked y < p,
    rejecting non-canonical encodings that dalek's decompress would silently
    reduce mod p — e.g. `[0xFF;32]` ≡ y=18 IS decompressable and would
    otherwise slip through) followed by point decompression;
  - `trap_s`: canonical (fully reduced) scalar encoding.
  Honest sends always satisfy these gates (`generate_sst_trap` emits
  compress()/canonical scalars), so no legitimate path regresses. The genesis
  placeholder pair `"none"/"none"` fails the length gates by design — this is
  the shared remediation ground with HMSEC-SA06-11 (SOLL-A) and
  audit_02_09 SOLL-A (empty-string shards likewise rejected).
- **Canonicality note:** the initial test premise "[0xFF;32] is guaranteed
  non-decompressable" was mathematically wrong under dalek semantics; the
  strict canonical-y gate was added so the documented malleability concern is
  also closed (mirrors `parse_canonical_scalar` policy).

### HMSEC-SA04-10 — Input-Context Binding at Fingerprint Ingress (WH3-04-403)

- **CWE:** CWE-349 (extraneous untrusted data in trust decision)
- **Verified failure:** Two third-party-signed fingerprints under the victim's
  public input tag D_H were persisted into
  `known_fingerprints.foreign_fingerprints[D_H]` and fabricated a persistent
  junk soft proof naming the victim-side ephemeral key as offender.
- **Fix:** `process_received_fingerprints` now builds the LOCAL input context
  (tag → set of legitimately revealed `sender_ephemeral_pub` values, sourced
  from all held voucher chains, own active/history fingerprints and local
  history) BEFORE admission. A forwarded fingerprint whose ds_tag collides
  with a locally known input is admitted ONLY if its `sender_ephemeral_pub`
  equals one of the locally revealed input keys — the storage-time analogue
  of the race-level `reproduces_local_tag`. Tags WITHOUT local context remain
  unaffected, so ordinary gossip forwarding of evidence about unknown inputs
  keeps working (F11 ingress gate untouched). Honest forwarding never breaks:
  real spend fingerprints always name the spender key that equals the local
  chain's revealed key.
- **Effect:** X1/X2-style poison is dropped before metadata updates, store
  persistence, grouping, junk-proof fabrication and conflict records; no
  quarantine regression (victim branch stays Active).

### AUDIT-01-F12 — R5 Witness Enforcement Keyed on Trap Presence (coordinator-routed)

- **Fix:** `process_encrypted_transaction_bundle_inner` now rejects any
  incoming tip transaction carrying `trap_data` WITHOUT a `privacy_guard`
  fail-closed before state mutation. Every production spend attaches trap AND
  guard (guard encryption triggers for any did:key recipient across all
  privacy modes), so legitimate receives are unaffected; the previously
  accepted shape (trap present, guard stripped) can never present its private
  witness and is now rejected up front, in addition to the existing witness
  check inside the guard branch.
- **Test:** `f12_guardless_transfer_with_poisoned_trap_shards_must_be_rejected`
  un-ignored; module-01 filter green (25/25).

### HMC-SEC-02-09 (audit_02_09) — Status After SA04-09 Fix

- **SOLL-A (stripped spend must fail chain validation): GREEN** via the
  SA04-09 structural gate (empty/"none" shards rejected).
- **SOLL-B (stripped-spend fingerprint must not classify as init): still RED**
  — requires changing `is_init_fingerprint` in `src/services/conflict_manager.rs`,
  which is OUTSIDE A-04's exclusive file scope. Test therefore STAYS
  `#[ignore]`d ("pending cross-module fix"); owner: coordinator to route
  conflict_manager.rs (same root cause keeps `wildcard_05` red).

## Verification (Wave 3)

- Module filter: `--test security_audit_module_04_integrity` → **9 passed, 1 skipped**
  (skip = sa04_08 documented CONFIRMED-PENDING ignore).
- Regressions: `--test security_audit_module_01_traps` → **25 passed, 0 failed**;
  `--test security_audit_conflict_and_traps` → **6 passed, 0 failed**;
  `identity_trap_audit` → **8 passed**; `core_logic::security::trap_verification`
  → **6 passed** (combined core_logic filter: 99 passed).
- Modules 02+03+06 filters green (34 passed / 24 passed / respective skips =
  documented pending ignores incl. audit_02_09, sa06_11..14).
- Full suite (`--no-fail-fast`): 601 passed / 9 failed / 14 skipped. All 9
  residual failures are OTHER modules' NEW fail-first tests pending their
  owners' fixes, none coupled to A-04 files: sa05_07..11 (storage serde/
  generation gates), wildcard_05 (is_init_fingerprint gap, cf. above),
  wildcard_06 (V2-legacy load classification), wildcard_07 (stealth container
  creation parses ANONYMOUS recipient as DID — pre-existing since the JWE
  refactor), plus `test_attack_fuzzing_random_mutations` which passes in
  isolation (parallel-run flake).

## Post-Audit Design-Intent Triage Summary (Wave 3)

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA04-08 | CWE-347 | `[CONFIRMED VULNERABILITY — PENDING PROTOCOL BREAK]` | Guard bound to no authenticated commitment; non-breaking detector fix information-theoretically impossible against the issuing-wallet attacker class. | Fail-first proof + `#[ignore]` with rationale; V4 migration design above. |
| HMSEC-SA04-09 | CWE-20 | `[CONFIRMED VULNERABILITY]` | Validator skipped shard structure entirely; generation contract enforceable at zero legit cost. | Canonical-point/scalar gate in chain validator. |
| HMSEC-SA04-10 | CWE-349 | `[CONFIRMED VULNERABILITY]` | Storage-time admission keyed on message authenticity only; binding hoisted from race to ingress without breaking unknown-tag gossip. | Local-input binding gate in `process_received_fingerprints`. |
| AUDIT-01-F12 | CWE-20/347 | `[CONFIRMED VULNERABILITY]` | Witness enforcement gated on guard presence instead of trap presence. | Trap-presence keyed rejection in receive path; f12 un-ignored. |
