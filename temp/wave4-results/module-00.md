# Wave 4 — Module 00 (Wildcard) Results

> Auditor: AI Security Auditor (Wave 4, wildcard station).
> Test file: `tests/security_audit_wave4_wildcard.rs` (7 tests).
> Run: `CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_wildcard`
> Final matrix: 5 FAILED (fail-first proofs), 2 PASSED (regression guards for a refuted leg).

---

## WH4-00-001 — Remote signing request bricks login AND mnemonic recovery
- **ID:** AUDIT-W4-WC-001 | **STATUS: PROVEN** (CRITICAL, CWE-754/20)
- **Tests:** `w4_wc_001_poisoned_endorsed_voucher_must_not_brick_login`, `w4_wc_001_poisoned_endorsed_voucher_must_not_brick_mnemonic_recovery`
- **Failure evidence:**
  - Login: `AUDIT-W4-WC-001 VIOLATION: ... bricks the whole wallet login. Error was: Some(CryptoError("Login failed (check password): Generic error: Failed to parse valid_until: premature end of input"))`
  - Recovery: `... bricks mnemonic recovery. Error was: Some(CryptoError("Recovery failed ... Generic error: Failed to parse valid_until: premature end of input"))`
- **Fix note:** Validate remote vouchers (at minimum scalar parseability) before `add_voucher_instance` in the signing workflow AND/OR contain per-instance rebuild errors in `Wallet::load` (quarantine instead of `rebuild_derived_stores()?` hard-fail).

## WH4-00-002 — Endorsed-exclusion divergence poisons own_fingerprints at every login
- **ID:** AUDIT-W4-WC-002 | **STATUS: PROVEN** (HIGH, CWE-460)
- **Test:** `w4_wc_002_endorsed_voucher_must_not_pollute_own_fingerprints_at_load_rebuild` (+ passing control assertion pre-reload isolating the divergence to maintenance.rs)
- **Failure evidence:** `... classified attacker-authored transactions of an Endorsed voucher as OWN spends (ds_tag 'W4WC002ATTACKERDSTAG0000000000000000000000' present in own_fingerprints.history)`
- **Fix note:** Apply the same `VoucherStatus::Endorsed` skip that `conflict_manager::scan_and_rebuild_fingerprints` documents to `wallet/maintenance.rs::rebuild_derived_stores`.

## WH4-00-003 — Detached-signature attach flips never-received voucher to Active / panic on spend
- **ID:** AUDIT-W4-WC-003 | **STATUS: PARTIAL** —
  - Status-flip leg (CWE-284): **PROVEN**
    - Test: `w4_wc_003_attach_must_not_activate_never_received_voucher`
    - Evidence: `... flipped a never-received Endorsed voucher to Active (status: Active). Authorization happened purely on voucher_id string equality`
    - Fix note: authorize the Endorsed→Active transition on ownership evidence (bundle reception / recipient or stealth-key match), not `voucher_id` equality.
  - Panic leg (CWE-617, t_time="zzzz"): **REFUTED**
    - Reason: an RFC3339-invalid `t_time` can NEVER reach Active on this path — attach-time validation runs `verify_transaction_integrity_and_signature`, whose HMC_TX_AUTH_V3 digest calls `encrypt_transaction_timestamp`, which strictly RFC3339-parses `t_time` (`src/services/conflict_manager.rs:~907`) → fatal error → Quarantined → spend aborts with `VoucherNotActive` BEFORE the future-lock unwrap (`transaction_handler.rs:~803`). The lexicographic-only premise of the hypothesis does not hold end-to-end.
    - Rewritten as GREEN regression guards pinning the existing defense:
      - `w4_wc_003_garbage_ttime_voucher_must_never_become_active_regression_guard` (PASS)
      - `w4_wc_003_spending_garbage_ttime_voucher_must_fail_gracefully_regression_guard` (PASS; graceful Err, no panic/SIGABRT observed — panic signal therefore not applicable)

## WH4-00-004 — Persisting commands outside transactional discipline swallow seal-phase failures
- **ID:** AUDIT-W4-WC-004 | **STATUS: PROVEN** (MEDIUM, CWE-755/667)
- **Test:** `w4_wc_004_swallowed_seal_failure_in_persisting_commands_must_keep_integrity_consistent` (seal-write fault injected by directory-shadowing `<profile>/seal.enc.tmp`)
- **Failure evidence:** `persisting command returned Ok while the seal/integrity phase failed silently — integrity record no longer covers the new file (UnknownItems(["generic_wave4_audit_settings.enc"]))`; login stderr additionally showed `Skipping storage cleanup during login because integrity is compromised.` (cleanup permanently disabled)
- **Fix note:** Route `save_encrypted_data` and the three signature commands through the Wave-2 transactional discipline (or propagate/compensate the seal-phase error instead of `let _ = self.update_seal_after_state_change(...)`).

---

### Notes for coordinators
- No src/ changes made; only `tests/security_audit_wave4_wildcard.rs` and this file were created.
- Transient build interference from concurrent agents editing `src/` occurred mid-run (unrelated bin `l2_client_simulator`); final run compiles and is reproducible.
