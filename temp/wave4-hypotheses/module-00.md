# Wave 4 — Module 00 (Wildcard / Cross-Cutting) Hypotheses

> Auditor: AI Security Auditor (Wave 4, wildcard station).
> Basis: `docs/security/ai-audits/00_general_adversarial_wildcard.md`,
> triaged against `DESIGN_INTENT_TRIAGE.md`.
> Dedupe sources: `reports/00_wildcard_report.md` (Waves 2+3), `STATUS.md`,
> `temp/security-triage-report.md` (W1–W6, N1–N11).
> Scope exclusions honored: audit_02_11 digest migration, SA04-08 V4 design,
> HMC-SEC-02-05 seal history, sa06_07 spec flaw — none re-reported.
>
## WH4-00-001: Remote signing request bricks login AND mnemonic recovery via unvalidated Endorsed voucher + unconditional rebuild error propagation

- Severity: CRITICAL | CWE: CWE-754 (improper check of exceptional conditions) / CWE-20
- Target: src/app_service/app_signature_handler.rs:~142-158 (stores remote voucher unvalidated); src/wallet/lifecycle.rs:~250 (`wallet.rebuild_derived_stores()?` in `Wallet::load`); src/wallet/maintenance.rs:~213-218 (`for instance in self.voucher_store.vouchers.values()` without status filter + `create_fingerprint_for_transaction(tx, &instance.voucher)?`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: An attacker sends the victim a `VoucherForSigning` SecureContainer whose embedded `Voucher` carries a single syntactically-minimal transaction but hostile scalar fields (e.g. `valid_until = "not-a-date"`, or a no-trap transaction with non-Base58 `prev_hash`, or `t_time = "zzzz"`). The victim calls the public API `AppService::create_detached_signature_response_bundle(...)` ("please guarantee my community voucher"). The function signs the metadata and then persists the **completely unvalidated** remote voucher into `voucher_store` with status `Endorsed` (`add_voucher_instance`, line ~152-158) and saves. On every subsequent `login` (and even `recover_wallet_and_set_new_password`, which uses the same `Wallet::load`), `Wallet::load` runs `rebuild_derived_stores()?`; the rebuild iterates ALL instances including Endorsed ones and fails hard on the first malformed field (`valid_until` RFC3339 parse at conflict_manager.rs:~43, Base58 decode at ~106, t_time parse at ~845). The `?` turns one remote interaction into a **permanent, unrecoverable-through-API wallet brick** — contradicting the explicit Wave-3 design decision (AUDIT-00-WILDCARD-06) that a single poisoned voucher must never strand the whole wallet.
- Broken Invariant: "One malformed/poisoned voucher instance must degrade that instance only (Incomplete/Quarantined), never fail the whole load/login" (established by WH3-00-901 remediation rationale in `Wallet::load`). Also breaks the receive-path contract that only vouchers which passed `process_encrypted_transaction_bundle`'s input validation ever enter `voucher_store` — the signing workflow is a second ingestion path with zero validation.
- Fail-First-Test-Sketch:
  1. Setup A (requester/attacker) and B (victim/signer) AppServices in temp dirs.
  2. Attacker crafts `Voucher { valid_until: "not-a-date", transactions: vec![one init-like tx], ..Default::default() }` (any non-empty chain so the `transactions.first()` guard passes), serializes into `SecureContainer` with `PayloadType::VoucherForSigning` addressed to B.
  3. B: `open_voucher_signing_request` → Ok; B: `create_detached_signature_response_bundle(&voucher, "guarantor", false, config, None)` → currently Ok + persisted.
  4. Drop B's AppService; re-login with correct password.
  5. Secure invariant assertion: `assert!(app.login(folder_b, PASSWORD, true, instance_id).is_ok(), "a stored Endorsed voucher must never brick login")` — on unpatched code this FAILS (`CryptoError("Login failed ... Failed to parse valid_until")`), same for `recover_wallet_and_set_new_password`.
- Dedupe-Check: Wave 2/3 wildcard report covers seal/rollback/lock/L2-discipline/genesis-classification/rebuild-predicate — never the signing-request ingestion path. STATUS.md SA06-04 fixed only the `transactions[0]` index panic in this workflow, not state pollution. Triage W1–W6/N1–N11 do not mention it. The protocol-epoch sweep (wildcard_06) explicitly skips non-Active statuses and cannot neutralize this (status Endorsed, and the failure is a parse error inside rebuild, not chain authentication).

## WH4-00-002: Endorsed-exclusion divergence between the two rebuilds poisons own_fingerprints and gossip at every login

- Severity: HIGH | CWE: CWE-460 (inconsistent parsing/derivation of same data) / CWE-708
- Target: src/services/conflict_manager.rs:~268-276 (`scan_and_rebuild_fingerprints` skips `VoucherStatus::Endorsed`); src/wallet/maintenance.rs:~213-244 (`rebuild_derived_stores` iterates ALL instances with NO Endorsed filter)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: Same ingestion vector as WH4-00-001, but with a fully well-formed attacker chain (all fields parseable, valid V3 layer2_signature — the attacker honestly signs their own shards). The crafted transactions claim `sender_id = Some(victim_did)` (or `sender_id: None` + `recipient_id = "anonymous"`). At signing time nothing happens (receive-scan excludes Endorsed: "must not contribute to double-spend detection"), but at the NEXT LOGIN the load-time rebuild classifies those fingerprints as OWN (`is_own_transaction`) and inserts them into `own_fingerprints.history` with attacker-chosen ds_tags/t_ids, plus VIP-negative depths (chain position). Consequences: (1) victim's proactive self-double-spend guard context and forensic history now contain phantom "own spends"; (2) `export_own_fingerprints` gossips attacker-authored fingerprints under the victim's custody with best-priority depth — free VIP relay for attacker evidence; (3) after the next save+seal update the poisoned store becomes the sealed truth, making the pollution persistent and seal-consistent.
- Broken Invariant: Documented invariant at conflict_manager.rs:~269-271 — endorsed vouchers "do not belong to the user and must not contribute to double-spend detection". This is exactly the WH3-00-903 bug class (two contradictory derivations over the same store), but on the status dimension instead of the sender predicate; the Wave-3 fix did not touch it.
- Fail-First-Test-Sketch:
  1. Victim wallet V owns a normal Active voucher (any test-utils setup). Victim DID known.
  2. Attacker crafts well-formed voucher: 2-tx chain, tx2 `{sender_id: Some(victim_did), recipient_id: "attacker", trap_data: Some(valid SST shards signed by attacker eph key), prev_hash: <valid b58>, sender_ephemeral_pub: Some(attacker eph pub), t_time increasing, amount "1.00"}`; sends as signing request; victim calls `create_detached_signature_response_bundle`.
  3. Re-login victim (triggers `rebuild_derived_stores`).
  4. Secure invariant: `assert!(wallet.own_fingerprints.history.keys().all(|k| !attacker_ds_tags.contains(k)), "Endorsed vouchers must not contribute to own_fingerprints at load-time rebuild")` — FAILS on unpatched code (entry present). Control: same assertion right after step 2 passes (receive-scan correctly skips), isolating the divergence to maintenance.rs.
- Dedupe-Check: AUDIT-00-WILDCARD-07/WH3-00-903 fixed the `is_own_transaction` predicate divergence only; both functions now agree on sender semantics but disagree on the Endorsed-status filter. No report/triage/STATUS entry covers Endorsed handling in `rebuild_derived_stores`.

## WH4-00-003: Detached-signature attach flips a never-received Endorsed copy to Active, bypassing all receive-path gates → deterministic panic on spend attempt

- Severity: HIGH | CWE: CWE-617 (reachable panic) / CWE-284 (missing ownership authorization on state transition)
- Target: src/wallet/signature_handler.rs:~174-239 (target instance matched by `voucher_id` across ALL instances incl. Endorsed; no ownership/recipient gate); src/app_service/app_signature_handler.rs:~288-291 (validation Ok ⇒ `VoucherStatus::Active`); src/wallet/transaction_handler.rs:~801-803 (`parse_from_rfc3339(&last_tx.t_time).unwrap()` behind lexicographic guard)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: Two-stage exploit. Stage 1: attacker gets an arbitrary self-created voucher E stored in the victim's wallet as Endorsed (signing request, cf. WH4-00-001) — E contains a fully valid, self-signed V3 chain whose last tx has `t_time = "zzzz"` (lexicographically greater than any timestamp, RFC3339-invalid; chain validation compares t_time ONLY lexicographically, chain.rs:~177/~530, so E validates clean) and plausible `valid_until`. Stage 2: attacker returns an honestly-signed `DetachedSignature` for `E.voucher_id`; victim's `process_and_attach_signature` matches E by voucher_id (it never checks that the local instance was actually transferred to/owned by the victim), attaches, and `create_detached_signature_response_bundle`'s sibling validation path marks E **Active**. The victim's UI now shows a phantom Active voucher; any spend attempt (public API `create_transfer_bundle`) reaches `_execute_single_transfer`, whose future-lock check parses `t_time` AFTER the lexicographic pre-filter and BEFORE any ownership/balance check → deterministic `unwrap()` panic → command surface wedged (state left Locked) until restart. Chain-validation format-blindness plus the missing receive-gate on this path make the previously-defended unwrap reachable again.
- Broken Invariant: (1) "Every Active instance in `voucher_store` passed full receive-path input validation including t_time parseability" (transaction_handler.rs:~199-203 enforces this for bundles; the signature path does not); (2) "Status transitions to Active require ownership evidence (recipient identity or stealth-key match)" — the attach path authorizes purely on `voucher_id` string equality.
- Fail-First-Test-Sketch:
  1. Stage 1 as in WH4-00-001 but with well-formed `valid_until`, garbage `t_time: "zzzz"`, valid self-signed chain (use test-utils voucher_setup helpers, mutate only t_time post-signing? No — sign honestly over the canonical bytes containing "zzzz").
  2. Attacker creates `DetachedSignature::Signature(VoucherSignature { voucher_id: E.voucher_id, signer_id: attacker_did, role: "guarantor", ..})`, signs per `complete_and_sign_detached_signature`, wraps in SecureContainer; victim: `process_and_attach_signature(container, freetaler_toml, ...)`.
  3. Assert secure invariant A: instance status must NOT be Active for a voucher the victim never received (`assert!(!matches!(instance.status, VoucherStatus::Active)))` — fails on unpatched code.
  4. Spend attempt: `app.create_transfer_bundle(local_id_e, attacker_or_any_recipient, "0.01", None, None)` → secure invariant: graceful Err; on unpatched code the test process panics at transaction_handler.rs:803 ("Failed to parse ..." unwrap on DateTime) — fail-first demonstrated.
- Dedupe-Check: SA06-04 covered only empty-chain index panics in this workflow. The t_time unwrap itself appears nowhere in Waves 1–3 reports nor triage (the receive-path parse gate made it look defended; this is a new bypass route for it). Status-flip-without-ownership is not reported anywhere.

## WH4-00-004: Persisting commands outside the Wave-2 transactional discipline swallow seal-phase failures → permanently stale integrity record disables cleanup-on-login

- Severity: MEDIUM | CWE: CWE-755 / CWE-667
- Target: src/app_service/data_encryption.rs:~50-52 and ~76-78 (`let _ = self.update_seal_after_state_change(...)` after `save_arbitrary_data`); src/app_service/app_signature_handler.rs:~197-200, ~358-361, ~476-479 (same swallowed pattern after `temp_wallet.save` in all three signature commands); contrast hardened orchestrator src/app_service/mod.rs `with_transactional_mut`
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: These five persisting commands write data files first and advance seal+integrity afterwards, ignoring the seal-phase result — the exact partial-commit window AUDIT-00-WILDCARD-01 eliminated for `with_transactional_mut`. Under a transient I/O fault in the seal phase (shadowed file, full disk, AV lock), the command reports Ok while `integrity.json` no longer covers the new file hash (`get_all_item_hashes` covers ALL non-hidden files incl. generic_* arbitrary data, file_storage.rs:~1165-1203). From then on EVERY `cleanup_on_login=true` login evaluates integrity as compromised (lifecycle.rs:~241-250) and silently disables storage cleanup forever, and `check_integrity` reports tampering where none exists — a persistent availability/false-alarm degradation needing manual `repair_integrity`. Additionally these commands skip the exclusive `WalletLockGuard` and Reload-Before-Write discipline entirely (generation CAS is their only defense).
- Broken Invariant: "`Err` ⇒ zero writes beyond the aborted point; `Ok` ⇒ data files, seal AND integrity record are mutually consistent" (Wave-2 commit contract established for all persisting commands).
- Fail-First-Test-Sketch: Integration test with spy FileStorage (or shadow `generic_<name>` target as directory like wildcard_01's fixture): create profile, unlock, call `save_encrypted_data("settings", b"x", Some(pwd))` with the seal-write sabotaged → assert returned Ok is accompanied by a subsequent `check_integrity() == Valid` (secure invariant). Unpatched behavior: Ok returned, then fresh login with `check_integrity` yields manipulated-item report and `run_storage_cleanup` is skipped (eprintln path) → assertion fails.
- Dedupe-Check: Wildcard-01/-09 remediated `with_transactional_mut` and `process_l2_response` only; the Wave-2 side note "login-writes-before-lock" is a different site. No prior finding names app_signature_handler/data_encryption as discipline holdouts.

---
### Post-Audit Design-Intent Triage Preview (pre-coordination)

| Finding ID | Suspected CWE | Tentative Outcome | Rationale |
| :--- | :--- | :--- | :--- |
| WH4-00-001 | CWE-754/20 | A [CONFIRMED] | No design intent covers accepting unvalidated remote state into the authoritative store; contradicts documented single-voucher-must-not-strand decision. |
| WH4-00-002 | CWE-460 | A [CONFIRMED] | Violates the in-code documented Endorsed-exclusion invariant; not a privacy/offline-forensics trade-off. |
| WH4-00-003 | CWE-617/284 | A [CONFIRMED] | Panic + unauthorized status transition; no forensic benefit argument applies. |
| WH4-00-004 | CWE-755/667 | A [CONFIRMED, severity debate] | Same fault class already classified A in Wave 2; residual inconsistency, not new design intent. |

No candidate touches intentional designs from DESIGN_INTENT_TRIAGE (local counterparty retention CORE-004, seal rollback gates, dotfile skip, fraud-detection-not-prevention).
