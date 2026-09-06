# WAVE 4 — Module 03 Results (Phase B: Fail-First TDD Proof)

> Auditor: Wave-4 Phase-B test author · Date: 2026-08-26 · Branch: `live`
> Scope: WH4-03-101 / -102 / -103. Files created: `tests/security_audit_wave4_cel.rs` + this report.
> Zero changes to src/, existing files, or git state (only artifact: new untracked test file).

## Results Table

| ID | Result | Testname | Ausschnitt/Signal | Fix-Notiz |
|---|---|---|---|---|
| AUDIT-W4-CEL-101 (WH4-03-101) | **PROVEN** (red on unpatched code) | `finding101_message_literal_must_err_not_abort_process` (tests/security_audit_wave4_cel.rs:383) | `panicked at .../cel-interpreter-0.10.0/src/objects.rs:706:32: not yet implemented: Support structs!` — payload `"not yet implemented: Support structs!"` captured by the in-test `catch_unwind` harness (assertion fires at tests/security_audit_wave4_cel.rs:391). nextest reports **FAIL** for exactly this one test; **no SIGABRT observed**: under `panic=unwind` the `todo!()` is a catchable panic (abort-class applies to stack overflow, wave-3 finding05). Empirically verifiziert per Einzellauf `cargo nextest run --test security_audit_wave4_cel finding101`. Trigger rule: `human_money_core{a: 'x'} == human_money_core{a: 'x'}` (two message LITERALS — a `.a` field select would accidentally fail closed in the pre-check via NoSuchKey over the Null-folded catch-all operand BEFORE execute; see docblock). | Add explicit `Expr::Struct` arm in `DynamicPolicyEngine::eval_and_check_ast` returning `Err(PolicyEngineError::EvaluationError("struct/message literals are not supported"))` before `program.execute()` (mirror of M03-007 Comprehension fix; closes dynamic_policy_engine.rs:597 catch-all gap). Defense-in-depth, same class: `Expr::Unspecified => panic!("Can't evaluate Unspecified Expr")` (objects.rs:707). |
| AUDIT-W4-CEL-102a (WH4-03-102) | **PROVEN** (red on unpatched code) | `finding102_usage_time_gate_must_reject_attacker_resigned_definition` (tests/security_audit_wave4_cel.rs:447) | After legit install via `AppService::import_voucher_standard` and FILESYSTEM swap of `voucher_standards/<uuid>/standard.toml` (immutable UNVERÄNDERT, mutable phishing + eigener Ed25519 Key): `verify_and_parse_standard(swapped)` = Ok (self-consistent), uuid+logic_hash match, then `verify_standard_identity` accepted it — `Expected: Err(...). Got Ok(()).` (tests/security_audit_wave4_cel.rs:470). | Trust-on-first-use Issuer-Pinning: bei Import `issuer_id` (oder Hash der Canonical-Bytes) in geschützten Sidecar/Integrity-Record verankern und `verify_standard_signature` (standard_manager.rs:107-156, Key-aus-Datei via `get_pubkey_from_user_id` Z.133/Z.60) gegen den Pin prüfen — Pattern `store_binding_hash` (SA05-07); alternativ voucher_standards-Ordner in Storage Integrity aufnehmen. |
| AUDIT-W4-CEL-102b (WH4-03-102, Konsenslockerung) | **PROVEN** (red on unpatched code) | `finding102_round_up_loosening_must_not_admit_overlong_validity` (tests/security_audit_wave4_cel.rs:489) | Baseline (grün): überlanger Voucher (valid_until 2026-12-15, Max "P1M") failed gegen PRISTINE def mit `ValidityDurationTooLong`. Nach Re-Sign mit `app_config.round_up_validity_to = "P1Y"`: `verify_validity_duration` akzeptiert ihn — `Expected: Err(...). Got Ok(()).` (tests/security_audit_wave4_cel.rs:508). identity.rs:167-169 rundet Max-Bound auf Jahresende (2026-12-31T23:59:59.999999999). SKIZZEN-ANPASSUNG dokumentiert: Hypothese-"P100Y" → unterstützte Einheit "P1Y", da `round_up_date` (date_utils.rs:108-169) nur P1D/P1M/P3M/P6M/P1Y akzeptiert und Unsupported fail-closed Err wirft (= kein Beweis). Zusatzassert Metadaten-Phishing enthalten (issuer_name "Phish Community" ritt durch Verifikation). | Gleicher Pinning-Fix wie 102a; zusätzlich prüfen, ob `round_up_validity_to` als konsensrelevant aus der nominell UI-only Mutable-Zone herausgenommen oder an den Pin gebunden werden soll (Design-Entscheidung, Phase C). |
| AUDIT-W4-CEL-103 (WH4-03-103) | **PROVEN** (red on unpatched code, 2 Tests) | `finding103_multibyte_prefix_bypasses_negated_position_rule` (tests/security_audit_wave4_cel.rs:550); `finding103_misaligned_index_must_fail_closed_not_invent_values` (tests/security_audit_wave4_cel.rs:568) | (a) State `"ÄEX"` (U+00C4 = 2 Bytes): Regel `Voucher.unit[1] != 'E'` → `Ok(true)`, obwohl Char #1 genuinely 'E' ist — Interpreter slicet BYTE 1 (Continuation) → `str.get(1..2)` → None → `Value::Null` → `Null != 'E'` → true (cel-interpreter objects.rs:545-548). Signierte Positionsregel vacuously bypassed. (b) State `"AÄ"`, Index 2 (byte-in-range, char-OOB, non-char-boundary): `!= '\u{0000}'` → `Ok(true)` (fail-open), `== '\u{0000}'` → `Ok(false)` — Pre-Check fabriziert `'\0'` (dynamic_policy_engine.rs:320 `chars().nth(idx).unwrap_or('\0')`, Bounds-Check in BYTES Z.319), Interpreter liefert Null → Evaluator-Divergenz statt definiertem Vertrag. Beide SOLL: `Err(...)`. | String-Arm (dynamic_policy_engine.rs:293-328) an Byte-Slice-Semantik des Interpreters angleichen UND jeden `None`-Fall (OOB UND non-char-boundary) zu `Err(EvaluationError)` machen statt Null/NUL zu koaleszieren/fabrizieren — fail-closed wie Map/List-Arm (M03-001-Geist); alternativ non-ASCII-Indexierung generell ablehnen. |

## Controls (GREEN on unpatched code, müssen nach Fix grün bleiben)

- `control101_ordinary_rules_remain_evaluable` — normale Regeln + dot-access NoSuchKey unverändert.
- `control102_pristine_gates_remain_functional` — compliant Voucher (exakter P1M-Boundary 2026-02-01, Window [P1M,P1M]) passiert `verify_validity_duration`, pristine def passiert Identity-Gate.
- `control103_ascii_position_rules_remain_exact` — ASCII-Positionalregeln (`TEX`: `[0]=='T'`, `[2]=='X'`, `[1]!='E'`=false) byte-/char-identisch.

## Final Run (mandated command, shared target dir)

```
CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_cel
Summary: 8 tests run: 3 passed, 5 failed, 0 skipped
FAIL finding101_message_literal_must_err_not_abort_process        (objects.rs:706:32 todo!)
FAIL finding102_usage_time_gate_must_reject_attacker_resigned_definition
FAIL finding102_round_up_loosening_must_not_admit_overlong_validity
FAIL finding103_multibyte_prefix_bypasses_negated_position_rule
FAIL finding103_misaligned_index_must_fail_closed_not_invent_values
PASS control101_ordinary_rules_remain_evaluable
PASS control102_pristine_gates_remain_functional
PASS control103_ascii_position_rules_remain_exact
```

## Execution Environment Note (identisches Hindernis wie Module 06)

Die mandatierte Command kompiliert im Repo NICHT aus **vorbestehendem, unbezogenem Grund**:
`cargo nextest run` baut beim Test-Target-Build alle Package-Binaries (CARGO_BIN_EXE-Anforderung);
das verwaiste Demo-Binary `src/bin/l2_client_simulator/main.rs` hinter der gehärteten V3-L2-API zurück
(`calculate_l2_payload_hash_raw` jetzt 9 Args, Errors in main.rs:220/:342/:458/:598/:829/:1199;
fehlendes Feld `L2LockRequest.privacy_guard` in :231/:353/:469/:609/:841/:1210) — API-Drift durch
frühere Security-Fixes, von dieser Phase unberührt und von mir NICHT fixiert (Verbot).

Ausführung daher in `/tmp/opencode/hmc-w4-run` — exakte Kopie des Repos, einziger Delta in
`Cargo.toml` der Kopie: `autobins = false` + entfernte `[[bin] voucher-cli]`-Tabelle; alle
lib/test/bindings-Quellen byte-identisch (verifiziert per `diff -r`, einziger Diff = Manifest).
Repo selbst komplett unmodified. Mandated command dort exakt wie vorgegeben ausgeführt.

## Disposition

- WH4-03-101: CONFIRMED-VULNERABILITY (**PROVEN**) — CRITICAL.
- WH4-03-102: CONFIRMED-VULNERABILITY (**PROVEN**, 2 Beweise: Gate-Akzeptanz + Konsenslockerung) — HIGH.
- WH4-03-103: CONFIRMED-VULNERABILITY (**PROVEN**, 2 Beweise: Bypass + Evaluator-Divergenz) — MEDIUM.
