# Module 00 Audit Report — Adversarial Wildcard / Cross-Cutting Vectors (Agent A-00)

> Wave 2, Phase B (sequential, last station). Scope: cross-cutting vectors spanning
> AppService ↔ Wallet ↔ FileStorage ↔ Seal that no single functional module owns.
> Test file: `tests/security_audit_wildcard.rs` (new).
> Hypotheses: `temp/security-hypotheses/module-00-wildcard.md`.
> Baseline at wave start: full suite green (~561 passed, several by-design
> `#[ignore]`d tests from modules 01/02/06 untouched).

## Summary Table

| Finding-ID | Hypothesis | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| AUDIT-00-WILDCARD-01 | H-00-1 Seal-update failure after commit → Err although persisted + permanent login brick | Critical | CONFIRMED + FIXED | `wildcard_01_seal_update_failure_after_commit_must_not_brick_login` | `src/app_service/mod.rs::with_transactional_mut` (+ new `compensate_failed_seal_phase`); `src/app_service/seal_handler.rs` (new state-less helper `persist_seal_for_wallet_state`) |
| AUDIT-00-WILDCARD-02 | H-00-2 Post-commit archive failure → ghost entries despite wallet rollback | High | CONFIRMED + FIXED (re-verified: NOT covered by A-04's fix) | `wildcard_02_post_commit_archive_failure_must_not_desync_wallet_and_archive` | `src/wallet/transaction_handler.rs::execute_multi_transfer_and_bundle` (post-commit loop is best-effort) |
| AUDIT-00-WILDCARD-03 | H-00-3 Generation blind spot + seal-less mid-session reload → voucher resurrection/framing | Critical | CONFIRMED + FIXED (residual gap; partial-rollback half already covered by A-05's generation bound) | `wildcard_03_external_state_rollback_mid_session_must_be_rejected_before_mutation` | `src/app_service/seal_handler.rs` (new `verify_state_matches_seal`) called from the reload branch of `with_transactional_mut` (`src/app_service/mod.rs`) |
| AUDIT-00-WILDCARD-04 | H-00-4 Lock ownership broken (foreign-lock deletion); session Instant overflow panic | Medium | CONFIRMED + FIXED (parts 1+3); part 2 DOCUMENTED LIMITATION | `wildcard_04a_unlock_must_not_remove_foreign_live_lock`, `wildcard_04b_session_timeout_arithmetic_must_be_panic_free` | `src/storage/file_storage.rs::unlock`; `src/app_service/mod.rs` (`resolve_auth_method`, `get_session_key`, `is_session_active`) |

Not processed in this wave (remains open for coordinator triage):
H-00-5 (profiles.json non-atomic write → collective login DoS / zombie profiles,
MEDIUM). It was outside this station's assigned hypothesis set; the fail-first test
sketch in the hypothesis file is ready to use. The four untracked side notes
(L2-facade without seal update, login-writes-before-lock, derive_folder_name
concatenation, epoch-zone double parse) remain documented cross-references to
modules 01/05/06.

## Finding Details

### AUDIT-00-WILDCARD-01 — Seal-Update Failure After Commit Bricks Login (H-00-1)

- **CWE:** CWE-755 (improper handling of exceptional conditions) → partial commit
  (CWE-662 class) and permanent availability loss.
- **Verified failure:** With only `<profile>/seal.enc.tmp` shadowed by a directory
  (blocks `save_seal`'s tmp-write while every `Wallet::save` target stays writable),
  a mutating command persisted vouchers/own_fingerprints/generation and THEN failed
  in `update_seal_after_state_change`. The command returned `Err`, but a fresh login
  died with `StateRollbackDetected` ("Recovery required") because disk contained the
  NEW own_fingerprints next to the OLD seal. One transient I/O fault = permanent
  lockout (normal login path; only mnemonic-level recovery remained).
- **Triage:** `[CONFIRMED VULNERABILITY]`. 4-question check: the state-hash gate in
  `verify_seal_on_login` itself is `[INTENTIONAL DESIGN REQUIREMENT]` (rollback
  protection) and was NOT weakened; the missing fault compensation contradicts the
  orchestrator's own documented contract ("If persistence fails … safely rolls back").
- **Fix:** The seal/integrity persistence core was factored into the state-less
  `AppService::persist_seal_for_wallet_state` (old public behavior of
  `update_seal_after_state_change` preserved via delegation; all existing callers
  unaffected). In both commit branches of `with_transactional_mut`, the seal is now
  advanced BEFORE publishing the new RAM state; if that fails after the data files
  were durably written, `compensate_failed_seal_phase` re-persists the PRE-transaction
  wallet (generation counter aligned with the value the aborted commit wrote) so disk
  matches the untouched seal again — `save_seal` is tmp+rename atomic, so a failed
  seal update always leaves the previous intact seal behind. Result: honest `Err`
  reporting AND a loginable wallet. Best-effort limitation documented in-code: if the
  compensating write itself fails under active I/O breakdown, recovery stays manual.

### AUDIT-00-WILDCARD-02 — Ghost Archive Entries After Post-Commit Failure (H-00-2)

- **CWE:** CWE-662 (partial commit across authoritative store and forensic archive).
- **Re-verification result:** NOT fixed by A-04. Their remediation moved PRE-commit
  archiving behind the commit point (SA04-03) — which CREATED this window: the
  post-commit loop still propagated `?`. A spy archive succeeding on element 1 and
  failing on element 2 produced `Err` + one archived record; the AppService mapped the
  `Err` to full wallet rollback, leaving forensic evidence of transfers the rolled-back
  (authoritative) wallet says never happened — plus the Err-after-commit lie (same
  class as Wildcard-01: lost bundle bytes, unsafe retries).
- **Triage:** `[CONFIRMED VULNERABILITY]`. The in-code comment claimed the opposite of
  actual behavior (spec violation, not intent). Journaling/compensation WOULD be
  architectural (VoucherArchive has no delete API), but eliminating the false error
  report is not: after the commit point, failures are reported truthfully.
- **Fix:** Post-commit archiving is best-effort: individual failures are logged
  (`eprintln`) and skipped; the operation stays successful. This makes the documented
  invariant true in BOTH directions — `Err` ⇒ zero archive writes (pre-commit aborts),
  `Ok` ⇒ records correspond to a genuinely committed transfer (forensic gaps possible
  only under active I/O failure, logged loudly). ⚠️ Cross-review flag for coordinator:
  fix touches A-04's file territory; revert is trivial if the coordinator prefers the
  old semantics, with the test serving as an explicit tripwire either way.

### AUDIT-00-WILDCARD-03 — Mid-Session Reload Resurrects Rolled-Back State (H-00-3)

- **CWE:** CWE-354 / CWE-708 (reload path validates only a manipulable counter, not
  the cryptographic anchor).
- **Verified failure (two-stage):**
  1. Partial data-side rollback (vouchers.enc + own_fingerprints.enc +
     `.wallet.generation`, seal left ahead) is ALREADY rejected mid-command — by
     A-05's vouchers.enc↔profile.enc generation-bound check surfacing as
     `ValidationError("Failed to reload wallet: … does not match the store generation
     bound …")`. Layered defense works; no code change needed for this half.
  2. Residual gap CONFIRMED fail-first: a COHERENT snapshot rollback (adding
     profile.enc, satisfying all internal consistency checks) with only seal.enc left
     ahead passed the silent reload and ACCEPTED a mutation on the resurrected state
     (`Ok(voucher)`): previously spent voucher Active again, ds_tag guard blind.
- **Triage:** `[CONFIRMED VULNERABILITY]` for the residual gap. The dotfile skip in
  `get_all_item_hashes` for `.wallet.lock` remains `[INTENTIONAL DESIGN REQUIREMENT]`
  (lock file must stay out of integrity reports); no design intent covers accepting
  unverified external state on the reload path.
- **Fix:** New `AppService::verify_state_matches_seal` (same state-hash discipline as
  `verify_seal_on_login`: SHA3(canonical(own_fingerprints)) vs
  `seal.payload.state_hash`) enforced in the Reload-Before-Write branch of
  `with_transactional_mut`; mismatch → `StateRollbackDetected` before any mutation.
  Seal-less legacy wallets remain exempt, mirroring login behavior. The gate itself is
  intentional design and was strengthened, not weakened.

### AUDIT-00-WILDCARD-04 — Lock Ownership & Session Overflow (H-00-4)

- **CWE:** CWE-667/CWE-459 (unlock deletes foreign locks); CWE-248/CWE-190 (panicking
  Instant arithmetic on host input).
- **Part 1 — verified failure:** `FileStorage::unlock` deleted `.wallet.lock`
  unconditionally (comment admitted the missing ownership check); reachable via
  `AppService::logout`, so one process could destroy another LIVE process's lock and
  let a third writer in. **Fix:** unlock performs the same sysinfo liveness check as
  `lock()`: foreign live PID → `Err(LockFailed)` (logout ignores it harmlessly);
  stale/dead-PID and unparseable locks are still cleaned up, preserving crash recovery.
- **Part 2 — DOCUMENTED LIMITATION (not fixed):** PID recycling can keep a dead
  wallet's lock "alive" forever (`LockFailed` brick, no TTL/token). Deterministic
  testing is not feasible; proper resolution needs a lock token/TTL redesign — left
  for coordinator/architecture backlog.
- **Part 3 — verified failure:** `unlock_session(password, u64::MAX)` followed by ANY
  session check panicked deterministically ("overflow when adding duration to
  instant") in three mod.rs sites, wedging the whole command surface until restart.
  **Fix:** deadline math switched to the panic-free `last_activity.elapsed()` pattern
  already used by `seal_handler::get_read_auth` and `refresh_session_activity`;
  identical semantics, no overflow possible.

## Regression Verification

All runs via filtered `cargo nextest run --test …` commands (never plain `cargo test`):

- Own filter: `security_audit_wildcard` → 5/5 passed (after per-hypothesis fixes).
- Adjacent audit suites: modules 01–06 + conflict_and_traps → 63 passed, 3 skipped
  (by-design ignores from earlier waves untouched).
- Main AppService consumer suite (`integration_tests` binding app_service,
  architecture, core_logic, persistence, services, validation, wallet_api):
  423 passed, 3 skipped — run twice (after mod.rs/seal_handler changes and again
  after transaction_handler/storage changes).
- No serialization formats or serde attributes touched anywhere.

---

# Wave 3 Addendum — V3/SST Cross-Cutting Findings (Final Fix Phase)

> Scope: WH3-00-901…905 against the V3/SST protocol rework (`HMC_TX_AUTH_V3`,
> Shared-Signature Trap). Test file: `tests/security_audit_wildcard.rs`
> (tests wildcard_05…09). All five findings CONFIRMED fail-first; all five
> remediated in this final wave.

## Summary Table (Wave 3)

| Finding-ID | Hypothesis | Severity | Outcome | Test | Fix Location |
| :--- | :--- | :--- | :--- | :--- | :--- |
| AUDIT-00-WILDCARD-05 | WH3-00-902 Empty-shard spend fork classified genesis → network-wide double-spend detection evasion | Critical | CONFIRMED + FIXED | `wildcard_05_empty_shard_spend_fork_must_stay_visible_at_gossip_ingress` | `src/services/conflict_manager.rs::is_init_fingerprint` |
| AUDIT-00-WILDCARD-06 | WH3-00-901 V2-legacy chain displayed Active after load → silent stranding | Critical | CONFIRMED + FIXED | `wildcard_06_v2_legacy_voucher_must_not_be_displayed_active_after_load` | `src/wallet/lifecycle.rs::load` (protocol-epoch sweep) |
| AUDIT-00-WILDCARD-07 | WH3-00-903 Rebuild wipes own stealth-spend history (inconsistent is_sender definitions) | High | CONFIRMED + FIXED | `wildcard_07_stealth_spend_history_must_survive_bundle_receive_rebuild` | `src/services/conflict_manager.rs` (new `is_own_transaction`) applied in `scan_and_rebuild_fingerprints` + `src/wallet/maintenance.rs::rebuild_derived_stores` |
| AUDIT-00-WILDCARD-08 | WH3-00-904 Instant overflow panic in L2 quarantine auth fallback (+ 2 fresh copies in app_service/conflict_handler.rs) | Medium | CONFIRMED + FIXED (all 3 sites) | `wildcard_08_l2_quarantine_session_arithmetic_must_be_panic_free` | `src/app_service/l2_facade.rs::process_l2_response`; `src/app_service/conflict_handler.rs::set_conflict_local_override` + `::import_proof` |
| AUDIT-00-WILDCARD-09 | WH3-00-905 L2 quarantine write outside the Wave-2 transactional discipline | Medium | CONFIRMED + FIXED | `wildcard_09_l2_quarantine_write_must_respect_rollback_discipline` | `src/app_service/l2_facade.rs::process_l2_response` (full discipline rewrite) |

## Finding Details (Wave 3)

### AUDIT-00-WILDCARD-05 — Empty-Shard Laundering via Genesis Classification (WH3-00-902)

- **Verified failure:** A hand-crafted SPEND fingerprint with
  `trap_r = trap_s = ""` and a layer2_signature binding exactly those empty
  strings was classified as genesis by `is_init_fingerprint` (empty ⇔ init)
  and silently dropped at gossip ingress (`import_foreign_fingerprints`),
  load purge and cleanup: `imported == 1`, no conflict. One honest fork plus
  one laundered fork therefore produced NO detectable collision anywhere in
  the network.
- **Triage:** `[CONFIRMED VULNERABILITY]`. Dropping GENESIS fingerprints is
  intentional ("no detection value"); equating attacker-controlled empty
  shards with genesis for entries that are L1-validatable spends is not.
- **Fix (new classification rule):** `is_init_fingerprint` now returns true
  ONLY when BOTH shards carry the canonical `"none"` placeholder — exactly
  what `create_fingerprint_for_transaction` emits for genuine genesis
  transactions. Empty-shard entries are treated as spend-typed: they stay in
  the detection pipeline and survive all gates only when their embedded V3
  signature authenticates them. Consequences audited across all consumers
  (ingress, load purge, cleanup, export filter, offline race admission, SST
  extraction, challenge-tag selection): laundered forks become visible;
  extraction naturally skips them (empty shards fail point/scalar parsing,
  no panic path); legacy local genesis entries were already dropped by the
  signature gates and are unaffected semantically.
- **Synergy:** together with A-04's `validate_shard_structure` (L1 rejects
  shard-less spends) and A-06's `VOID_SPEND_SHARD_MARKER`, this closes both
  assertions of HMC-SEC-02-09 → test UN-IGNORED (see Stretch below).

### AUDIT-00-WILDCARD-06 — Protocol-Epoch Stranding at Load (WH3-00-901)

- **Verified failure:** A persisted store containing a pre-V3 transaction
  loaded cleanly through the real login path and remained status `Active`;
  every later spend failed with generic validation noise.
- **Fixture realism upgrade (per coordination round):** the injected legacy
  transaction now models an honest upgrader precisely — t_id self-consistent
  under the CURRENT canonical preimage, genuine ephemeral keypair, production
  SST shards on the correct input anchor (`H(prev_hash ‖ eph)`), but its
  `layer2_signature` authenticates a V2-style digest payload (old preimage
  shape including trap_data). Under V3 rules exactly ONE property fails: the
  authentication epoch — isolating the stranding gap from garbage input and
  staying fully clear of A-05's serde-coercion territory (no legacy field
  names involved).
- **Design decision (documented explicitly; offline-cash sensitivity):**
  Option (b) "mark distinctly non-spendable" over option (a) "hard-fail the
  whole store". Rationale: bricking the ENTIRE wallet login because ONE
  voucher was written by a legacy client would strand ALL other funds — the
  worst outcome for offline-first cash. Leaving them `Active` is equally
  forbidden (silent stranding). New protocol-epoch sweep in `Wallet::load`
  (sibling of the expiration sweep) marks affected Active instances
  `Incomplete { reasons: [BusinessRule { message }] }` with an explicit
  "protocol epoch mismatch" message. The serde-stable `BusinessRule` variant
  is reused deliberately — NO schema change to the persisted status enum.
  Funds are not destroyed and remain forensic-addressable; a migration API
  (option c) stays on the coordinator backlog.
- **Note:** the sweep reuses `verify_transaction_integrity_and_signature`,
  which short-circuits Ok under the test-utils signature bypass — mirroring
  production semantics for test setups.

### AUDIT-00-WILDCARD-07 — Stealth History Wiped by Rebuild (WH3-00-903)

- **Fixture repair first (per coordination):** the harness failed at SETUP
  (`Invalid user ID format`) because it passed `ANONYMOUS_ID` as the REQUEST
  recipient; that field must be a real DID (bundle encryption and
  fingerprint selection run before the Flexible standard anonymizes the
  chain itself). After the fixture fix the test reaches the real gap —
  fail-first re-verified by temporarily reverting the scan filter: the own
  stealth-spend fingerprint vanished from `own_fingerprints.history` after
  ONE unrelated bundle receive.
- **Root cause:** two contradictory "was I the sender" definitions. The
  transfer path counts anonymous spends as own
  (`transaction_handler::_execute_single_transfer`), while BOTH rebuilds
  filtered strictly on `sender_id == Some(user_id)`:
  `conflict_manager::scan_and_rebuild_fingerprints` (receive-time) AND its
  load-time twin `maintenance::rebuild_derived_stores` (same bug pattern —
  fixed in the same stroke so logins cannot wipe what receives preserved).
- **Fix:** new canonical predicate
  `conflict_manager::is_own_transaction(tx, user_id)`
  (`sender == user || (sender.is_none() && recipient == ANONYMOUS_ID)`)
  used by both rebuilds. Received stealth vouchers are counted own as well:
  authorship is intentionally not derivable from anonymous chain data, so
  erring toward more protective guard context and richer evidence custody
  was chosen; distinct per-input ds_tags make spurious proactive-guard trips
  cryptographically impossible. Full-replace commit semantics kept (entries
  re-derive from the local chain).

### AUDIT-00-WILDCARD-08 — Instant Overflow Residue ×3 (WH3-00-904)

- **Verified failure:** `unlock_session(PASSWORD, u64::MAX)` followed by the
  first L2 quarantine verdict panicked deterministically
  (`cache.last_activity + cache.session_duration`, l2_facade.rs). The
  batch-run pass observed during coordination was environmental flake; solo
  runs reproduce the panic every time.
- **Two additional copies found** in freshly written code:
  `app_service/conflict_handler.rs::set_conflict_local_override` (~L93) and
  `::import_proof` (~L144) — identical panicking deadline materialization.
- **Fix:** all three sites use the panic-free
  `cache.last_activity.elapsed() > cache.session_duration` comparison
  (identical semantics to the Wave-2 mod.rs fix). In l2_facade the ad-hoc
  auth fallback was replaced wholesale by `resolve_auth_method`; its generic
  timeout error surfaces as `SessionExpired` at this call site (behavioral
  delta vs. the old placeholder-key dance documented here; observable
  contract "no panic, structured Err" unchanged).

### AUDIT-00-WILDCARD-09 — Quarantine Write Outside Transactional Discipline (WH3-00-905)

- **Verified failure:** coherent external rollback of the data side (state N)
  while seal.enc stayed ahead at state G, plus forging the plaintext
  `.wallet.generation` marker to G (defeating the CAS anchor alone), let
  `process_l2_response` durably anchor a quarantine onto the resurrected
  state and return `Ok(())` with a bumped generation — the only persisting
  path still bypassing every Wave-2 gate.
- **Triage:** `[CONFIRMED VULNERABILITY]`. Wave 2 established the discipline
  for all other writes; this residue contradicts it.
- **Fix:** `process_l2_response` rewritten onto the full discipline:
  fork-lock check → state isolation → file lock → panic-free session
  resolution → UNCONDITIONAL Reload-Before-Write with
  `verify_state_matches_seal` (the marker alone is forgeable, so the fresh
  disk state itself must match the cryptographic seal before any quarantine
  is anchored) → verdict re-derived against the SEAL-VERIFIED fresh wallet →
  sealed commit (`save` + `persist_seal_for_wallet_state`) with the same
  compensation contract as `with_transactional_mut`. Verified rejection
  reason in the test scenario: `StateRollbackDetected`.
- **Session-anchor note:** the live-session `l2_server_pubkey`
  (host-app runtime configuration, RAM-only by convention) is re-applied to
  the reloaded wallet so verdict evaluation keeps working across the
  mandatory reload; it is owner-controlled configuration, NOT rolled-back
  disk content, and every persisted-content integrity gate remains enforced
  BEFORE any write.

## Stretch Goals

- **audit_02_09 (HMC-SEC-02-09) UN-IGNORED and GREEN:** SOLL-A (chain
  rejects stripped spends) passes via A-04's `validate_shard_structure`,
  SOLL-B (stripped-spend fingerprint not genesis) via A-06's void marker +
  the new `is_init_fingerprint` rule. Ignore rationale removed with
  documentation of the landed remediation sites.
- **audit_02_08 / audit_02_11 remain `#[ignore]`d (documented, NOT free):**
  audit_02_08 (Schnorr-valid off-line line poisons attribution) requires a
  protocol-level corroboration policy (n>=3 consistency or documented
  downgrade semantics); audit_02_11 requires binding `layer2_voucher_id`
  into the L2 digest — an atomic cross-module migration already routed to
  module-01 ownership. Neither is addressed by this wave's fix path.

## Regression Verification (Wave 3 finalization)

All runs via filtered `cargo nextest run …`:

- Own filter `security_audit_wildcard`: **10 passed / 0 failed** (incl.
  wildcard_01–04 Wave-2 tripwires).
- Mandated regressions: `security_audit_module_01_traps`,
  `security_audit_module_02_crypto`, `security_audit_module_06_privacy`,
  `security_audit_conflict_and_traps` → 54 passed / 5 skipped;
  `integration_tests architecture::resilience_and_gossip` → 11 passed;
  unit filter `reputation_tests` → 10 passed; `core_logic::security` →
  64 passed.
- FULL suite after all changes incl. un-ignore: **616 passed / 0 failed /
  8 skipped** (baseline at wave start: 585 passed / 5 skipped; growth =
  Wave-3 tests of modules 01–06 plus wildcard_05–09 and audit_02_09).
- No serde attributes or serialization formats touched; status marking
  reuses the existing serde-stable `ValidationFailureReason::BusinessRule`
  variant.
