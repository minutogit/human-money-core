# Wave 4 — Module 04 Hypotheses: Transaction Logic & State Integrity

> Auditor: A-04 (Wave 4 research pass, branch `live`).
> Scope: `src/wallet/transaction_handler.rs`, `src/services/voucher_validation/*`,
> `src/services/bundle_processor.rs`, `src/services/voucher_manager/{transaction,balance,creation}.rs`,
> `src/services/conflict_manager.rs` (ingress/fingerprint), Conservation-of-Value,
> Split/Change anchors, panic-freedom, voucher status transitions.
> Dedupe base: `reports/04_integrity_report.md` (SA04-04..10), `STATUS.md`,
> `temp/security-triage-report.md` (K1–K4, W1–W6, N1–N11). Scope-excluded per assignment:
> SA04-08 / HMC_TX_AUTH_V4 design (PENDING), audit_02_11 V3.x digest migration, seal history, sa06_07.

---

## WH4-04-501: Init without attributed creator bypasses issuance attribution entirely
- Severity: HIGH | CWE: CWE-347 (missing issuer-binding enforcement)
- Target: `src/services/voucher_validation/chain.rs:511-520` (`verify_transaction_basics`, init party gate) in interaction with `src/services/voucher_validation/signatures.rs:26-42,69-89` (creator signature optional) and `src/services/voucher_manager/balance.rs:33-39` (firewall skipped when `creator_profile.id == None`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: An attacker hand-crafts a voucher whose header is byte-faithful to a genuine,
  loaded standard (correct `voucher_standard.uuid` + `standard_definition_hash`, correct unit,
  valid validity window) but sets `creator_profile.id = None`. Every issuance-attribution gate is
  conditional on that field being present: the init-party check in `verify_transaction_basics`
  only runs when `creator_profile.id.is_some()` (both disjuncts re-require `is_some()`);
  `verify_signatures` binds the "creator" role only IF such a signature exists, and
  `additional_signatures_range` minima are satisfiable with attacker-owned keys under any allowed
  non-creator role; the issuance firewall skips when creator id is absent. The attacker then signs
  init as themselves (`sender_identity_signature` + HMC_TX_AUTH_V3 `layer2_signature` under their
  genesis/ephemeral key), producing a chain that passes `validate_voucher_against_standard`
  end-to-end and ingests via `process_encrypted_transaction_bundle` into victims' wallets.
  Result: unlimited self-issuance of vouchers under trusted standard UUIDs with zero issuer
  accountability — Outcome A territory ("unauthorized minting") of the triage matrix.
- Broken Invariant: "Every init transaction commits to an attributed creator: init sender and
  recipient MUST equal `voucher.creator_profile.id`, and a creator-role signature bound to that
  id MUST be present and verify" — currently enforced only when `creator_profile.id` happens to
  be `Some`, while all honest creation paths (`create_voucher`) guarantee `Some`.
- Fail-First-Test-Skizze: In `tests/security_audit_module_04_integrity.rs`:
  (1) Load fixture standard (e.g. minuto_v1 via `load_and_verify_standard`); (2) clone header
  fields from a legitimately issued voucher (uuid, `standard_definition_hash`, unit, amount 100);
  (3) set `voucher.creator_profile.id = None`; craft init tx with attacker did:key as sender AND
  recipient, `prev_hash = H(voucher_id ‖ nonce)`, genesis `sender_ephemeral_pub` from attacker
  key+nonce, `layer2_signature` computed exactly like `creation.rs:296-320`
  (`calculate_l2_payload_hash_raw(t_id, …)` placeholders "none"/"none"), identity sig over t_id;
  (4) assert `validate_voucher_against_standard(&v, &std)` is `Err(...)` — on unpatched code it
  returns `Ok(())`, so the test FAILS and proves the gap. Optional end-to-end hardening: wallet B
  accepts the bundle from wallet A (`process_encrypted_transaction_bundle` → `Ok`, instance Active).
- Dedupe-Check: SA04-06/audit_02 series covered bundle/container signature verification;
  HMC-SEC-02-04 fixed creator-attribution *binding* for signatures that ARE present (raw-pubkey
  dedup) — neither requires presence of creator attribution. SA05/SA06 storage/privacy findings
  unrelated. STATUS.md has no entry on mandatory `creator_profile.id`. Triage caveat for the fix
  phase: confirm no intentional anonymous-issuance use case exists (none documented in
  design-decisions / PRIVACY_FAQ); queries surface blank creator (`unwrap_or_default`,
  `wallet/queries.rs:130`), so this reads as a validation gap, not design.

---

## WH4-04-502: Chain time-ordering enforced by raw RFC3339 string comparison (offset confusion)
- Severity: LOW | CWE: CWE-20 (improper input validation of timestamp encoding)
- Target: `src/services/voucher_validation/chain.rs:177` (`tx.t_time <= last_tx_time`),
  `chain.rs:530` (`tx.t_time < voucher.creation_date`), `signatures.rs:98`
  (`signature_time < voucher.creation_date`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE (defense-in-depth class; limited standalone impact)
- Threat Model: Ordering invariants of the transaction chain are enforced lexicographically on
  RFC3339 strings, but timestamps are free-form RFC3339 accepted with arbitrary UTC offsets.
  A crafted chain can contain interior transactions whose *parsed instants* violate chronological
  order while the string comparison passes (e.g. interior `"2026-01-01T23:59:59-14:00"` is
  lexically below tip `"2026-01-02T00:00:00Z"` yet instant-wise ~14 h AFTER it). Interior
  `t_time`s are never parsed as instants during ingress — `verify_not_far_in_future`
  (`transaction_handler.rs:197-238`) parses only the MAX tip plus signature times — so
  future-shifted instants inside the chain evade the future-grace check and flow into
  fingerprint timestamps (`encrypt_transaction_timestamp` parses at scan time, succeeds for
  valid offset forms) that feed the offline earliest-wins race inputs. Race-level windows
  (AUDIT-01-F14 floor/ceiling on decrypted nanos) bound the residual abuse, hence LOW.
- Broken Invariant: For every consecutive pair `(tx[i-1], tx[i])`:
  `parse_instant(tx[i].t_time) > parse_instant(tx[i-1].t_time)` and
  `parse_instant(init.t_time) >= parse_instant(voucher.creation_date)` — string ordering does not
  imply instant ordering under mixed offsets.
- Fail-First-Test-Skizze: Build a self-consistent 2-tx public-mode chain (init +
  transfer) where `init.t_time = "2026-01-02T00:00:00Z"` and
  `transfer.t_time = "2026-01-01T23:59:59-14:00"` (instant ≈ 2026-01-02T13:59:59Z, i.e. after the
  init instant; all hashes/t_ids/L2 sigs recomputed with existing test helpers). Assert
  `verify_transactions(&v, &std)` is `Err(InvalidTimeOrder{..})` — on unpatched code the string
  comparison accepts the chain (`Ok(())`) and the test FAILS.
- Dedupe-Check: SA01-02/F03 fixed scalar canonicality, not timestamp parsing; AUDIT-01-F14 added
  the race-window bounds, not chain-level ordering semantics; STATUS.md lists generic
  "ISO 8601 edge-case tests" as an ongoing focus area (no concrete finding) — flagged as possible
  overlap with that backlog item, otherwise new.

---

## WH4-04-K4: Post-commit best-effort archiving still permits PARTIAL forensic archives (multi-source sends)
- Severity: MEDIUM | CWE: CWE-662 (inconsistent side-effect commit)
- Target: `src/wallet/transaction_handler.rs:1057-1097` (`execute_multi_transfer_and_bundle`,
  post-commit archive loop, per-voucher `continue`/skip on error)
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (explicit follow-up of K4 in `temp/security-triage-report.md`)
- Threat Model: The original K4 defect ("archive error after commit → AppService rollback → ghost
  entries") is remediated at HEAD: the phase is now best-effort, failures are logged
  (`eprintln!`) and never propagate (AUDIT-00-WILDCARD-02 rationale inline). Residual gap: for
  N-source transfers the loop archives voucher-by-voucher and continues on individual failure,
  so a mid-loop persistent failure (e.g. one source's standard missing from the provided map,
  line 1078-1085, or repeated AEAD/KDF errors) yields a PARTIALLY populated forensic archive for
  an atomically committed send. Offline double-spend forensics relying on
  `find_transaction_in_stores` archive fallback sees a truncated custody chain for exactly the
  fraud-relevant cases. No value-integrity impact; evidence-completeness invariant broken.
- Broken Invariant: "After a committed multi-source transfer, the forensic archive contains ALL
  transferred pre-states or none" — relaxed to "some subset, silently".
- Fail-First-Test-Skizze: Wallet with two Active sources S1/S2; call
  `execute_multi_transfer_and_bundle` with `archive = Some(broken_archive)` where the test
  archive backend fails specifically for S2's `archive_voucher` call; assert afterwards that
  EITHER both states are archived OR the operation reports the forensic incompleteness to the
  caller (result flag/error channel). Current code: returns `Ok(CreateBundleResult{..})` with
  zero signal, archive holds only S1 → test FAILS on unpatched code.
- Dedupe-Check: HMC-SEC-04-03 moved archiving after commit; AUDIT-00-WILDCARD-02 made the phase
  best-effort (documented "forensic gap"). Neither closed nor tracked the partial-archive subset
  case; K4 named it, no finding ID exists. Deepdive should decide between warn-event/journal vs.
  result-metadata and add the invariant test.

---

## WH4-04-N4: Overflow rejection path remains type-erased and undocumented for direct core consumers
- Severity: LOW | CWE: CWE-703 (improper check or handling of exceptional conditions)
- Target: `src/wallet/transaction_handler.rs:493-497` (`VoucherCoreError::Generic("Amount overflow …")`)
  and `chain.rs:200-215` (overflow mapped to `InsufficientFundsInChain` with "overflow (…)" string)
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (explicit follow-up of N4 in `temp/security-triage-report.md`)
- Threat Model: Both overflow guards introduced by HMC-SEC-04-01/02 are functionally correct
  (no panics, fail-closed), but machine-unreadable: hosts cannot distinguish
  "attacker-scale amounts rejected" from other errors, and the `InsufficientFundsInChain`
  variant is semantically overloaded for what is really an input-validation rejection. Per the
  triage report there is also an AppService/core asymmetry: direct core users of
  `process_encrypted_transaction_bundle` get the snapshot rollback (safe), but clients see only
  a generic message; behavior "bundles summing beyond `Decimal::MAX` are rejected as a whole"
  is nowhere documented for client authors.
- Broken Invariant: Error-taxonomy invariant: security-relevant input rejections must be
  programmatically distinguishable (cf. dedicated variants pattern used elsewhere, e.g.
  `BundleAlreadyProcessed`).
- Fail-First-Test-Skizze: Send a 2-voucher bundle with near-MAX amounts to a test wallet;
  assert `matches!(err, VoucherCoreError::AmountOverflow(_))` (proposed variant) — FAILS today
  because the variant does not exist and `Generic` is returned (test doubles as the API contract
  once implemented). Companion doc assertion: FAQ/ADR section exists describing whole-bundle
  rejection semantics.
- Dedupe-Check: HMC-SEC-04-01 fixed the panic, not the error taxonomy; N4 explicitly left open;
  no other wave touched error typing for amounts.

---

### Explicitly investigated and discarded (dedupe/noise control)
- DetachedSignature early-return in `process_encrypted_transaction_bundle_inner`
  (`transaction_handler.rs:574-581`): dead code — `open_and_verify_bundle` enforces
  `PayloadType::TransactionBundle` before this point; not reachable.
- Replay/resurrection of stale chain states via fresh bundles: L2 gate
  (`check_bundle_fingerprints_against_history`) covers held tips because
  `scan_and_rebuild_fingerprints` places EVERY tx of every non-Endorsed held instance into
  `known.local_history` persistently (Archived instances included until grace-period purge);
  Endorsed instances are skipped, but Layer-0 recipient fuse structurally blocks bundles
  containing vouchers the wallet has no ownership stake in.
- Quarantined→Active reset via identical-content replay: blocked by the same local_history
  replay gate (CASE A, same ds_tag+t_id).
- Fork-extension ingestion of locally quarantined lineages arriving back as new tips: same-call
  conflict processing + AUDIT-01-F15 monotonic status guard handle this by design
  ("Fraud Detection, Not Prevention").
- `get_spendable_balance` swallowing `Validation` errors (`balance.rs:99-104`): reachable only
  for already-validated stored instances (Active-gated spend); downstream
  `create_transaction` re-validates the extended chain and fails closed. Defense-in-depth note
  only; no exploit path found in Wave 4 scope.
- `.unwrap()` sweep: `transaction_handler.rs:802-803` operate on tips already parse-hardened at
  ingress (line 199-203); `:915` guarded by prior `last()` checks; `transaction.rs:106` guarded
  by `_execute_single_transfer`. No remotely triggerable panic found in module scope.
