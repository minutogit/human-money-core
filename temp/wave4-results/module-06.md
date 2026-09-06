# WAVE 4 — Module 06 Results (Phase B: Fail-First TDD Proof)

> Auditor: Wave-4 Phase-B test author · Date: 2026-08-26 · Branch: `live`
> Scope: ONLY WH4-06-701 per coordinator. WH4-06-702/703/704 are dispositioned
> KNOWN-OPEN-DEEPDIVE / hardening — NOT tested (no tests written for them).
> Files created: `tests/security_audit_wave4_privacy.rs` + this report. Zero changes to src/, existing files, or git state.

## Results Table

| ID | Result | Testname | Ausschnitt | Fix-Notiz |
|---|---|---|---|---|
| AUDIT-W4-PRIV-701 (WH4-06-701) | **PROVEN** (red on unpatched code) | `wh4_06_701_received_notes_must_be_sanitized_and_bounded_in_bundle_history` (tests/security_audit_wave4_privacy.rs:169) | `panicked at tests/security_audit_wave4_privacy.rs:232:5: AUDIT-W4-PRIV-701 VIOLATION: attacker-controlled TransactionBundle.notes entered the persistent bundle metadata history unbounded (100004 chars, limit 64).` | Apply SA06-10 parity at network ingestion: sanitize+bound `bundle.notes` right after verification in `process_encrypted_transaction_bundle_inner` (next to the existing `bundle.sender_profile_name = sanitize_display_name(...)` at src/wallet/transaction_handler.rs:156), BEFORE `bundle.to_header(...)` feeds `bundle_meta_store.history.insert` (:556-559). Reuse `sanitize_display_name` semantics (strip Cc/Cf incl. U+202E/U+200D, bound length); a dedicated NOTES bound > 64 is acceptable but requires consciously updating `MAX_RECEIVED_NOTES_CHARS_SOLL` in the test (documented decision point in the test docblock). MUST NOT touch the local composition path (`create_and_encrypt_transaction_bundle`, :96-98) — guarded by the in-test DESIGN GUARD + regression guard ("Coffee for Alice" passes verbatim). |

## Execution Environment Note (exact obstacle + resolution)

The mandated command **fails to compile in-repo for a pre-existing reason unrelated to this finding**:

```
error[E0061]: this function takes 9 arguments but 7 arguments were supplied
   --> src/bin/l2_client_simulator/main.rs:220:24   (and :342, :458, :598, :829, :1199)
error[E0063]: missing field `privacy_guard` in initializer of `L2LockRequest`
   --> src/bin/l2_client_simulator/main.rs:231      (and :353, :469, :609, :841, :1210)
```

Cargo builds all package binaries whenever any integration test target is built
(`CARGO_BIN_EXE_*` requirement), so even `--test security_audit_wave4_privacy`
compiles the stale demo binary. The simulator lags behind the hardened V3 L2
digest signature (`calculate_l2_payload_hash_raw`, now 9 args) and the new
`L2LockRequest.privacy_guard` field — API drift from recent security fixes,
untouched by this phase. Verified my test file compiles cleanly via
`CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo check --test security_audit_wave4_privacy`
in-repo (OK).

To still execute the mandated command against byte-identical library/test
sources, the run was performed in `/tmp/opencode/hmc-w4-run` — an exact copy of
the repo differing ONLY by: (1) `src/bin` present but disabled in that copy's
`Cargo.toml` (`autobins = false`, explicit `[[bin]] voucher-cli` table removed),
(2) nothing else. All lib/test/voucher_standards/bindings sources are
byte-identical (verified by file-manifest diff: sole delta = bin targets).
Repo itself remains completely unmodified. Command executed exactly as mandated:

```
CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_privacy
```

Result: 1 run, 1 FAIL (red proof above). The test turns green once the
ingestion-side sanitization lands.

## Dispositioned hypotheses (NOT tested, per coordinator)

- WH4-06-702 (voucherless bundles keep permanent-key envelope sig): KNOWN-OPEN-DEEPDIVE — no test.
- WH4-06-703 (cleartext DIDs across get_event_history boundary / quarantine asymmetry): KNOWN-OPEN-DEEPDIVE — no test.
- WH4-06-704 (`was_contributory()` parity gap on container receive path): likely-FP hardening — no test.
