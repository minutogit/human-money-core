# Security Audit Report — 00 General Adversarial Wildcard (Unconstrained)

> **Agent:** A-00 — Unconstrained Adversary ("Black-Hat Thinking")  
> **Date:** 2026-08-29  
> **Scope:** Entire `human-money-core` repository (`src/services`, `src/wallet`, `src/app_service`, `src/storage`, `src/archive`, `src/models`, `protocols`, `bindings/wasm`)  
> **Mandate:** `docs/security/ai-audits/00_general_adversarial_wildcard.md` — the 6 System Nightmares  
> **Test file:** `tests/security_audit_wildcard.rs` (extended: `wildcard_10_*` … `wildcard_14_*`)  
> **Baseline at audit start:** `00_wildcard_report.md` Wave 1–3 (10 tripwire tests green) + `STATUS.md` v0.3.0 (full suite 616 passed / 8 skipped). This report is a **new general sweep** (`00_general_adversarial_wildcard_report.md`) and does not overwrite the Wave-3 cross-cutting report.

---

## Executive Summary

The audit traced end-to-end data and control flows across the decoupled `Wallet ↔ FileStorage ↔ AppService ↔ Seal ↔ Archive ↔ Bundle ↔ Conflict ↔ CEL` pipeline, then attacked each of the six Nightmare goals backward from worst-case impact.

**Result:** the hardened V3/SST posture (domain-separated length-prefixed hashes, self-authenticating fingerprints, SST EUF-CMA framing immunity, mandatory `store_binding_hash`, CEL budgets, session-Instant overflow fixes) correctly closes the value-inflation, fund-theft, desync, double-spend-evasion and most assumption-busting classes. Four cross-cutting residual gaps remain, all in **non-consensus read / persistence helpers** — they cannot inflate value or steal funds, but they violate fail-closed / liveness guarantees and are reachable with attacker-influenced data.

| Severity | Count | IDs |
| :--- | ---: | :--- |
| **High** | 0 | — (system-critical invariant breaks already remediated in Waves 1–3) |
| **Medium** | 2 | AUDIT-00-WILDCARD-10 (balance-view Decimal overflow panic), AUDIT-00-WILDCARD-13 (spendable_balance silent-ZERO masking) |
| **Low** | 2 | AUDIT-00-WILDCARD-11 (serialization `unwrap` panics), AUDIT-00-WILDCARD-14 (date-clamping fallback to `now`) |
| **[INTENTIONAL]** | 3 | Counterparty retention (HMSEC-SA06-05), `ANONYMOUS_ID` bundle address, generation+seal compensation discipline |
| **[FALSE POSITIVE]** | 2 | Flexible-mode `target_prefix="did"` (display only), `validate_issuance_firewall` early-return (covered by chain gate) |

No new **Critical** wire-level exploit was found. The two Medium findings deserve a patch before 1.0; the two Low findings are defense-in-depth hygiene.

---

## Methodology

1. **Architecture mapping** — subagents reconstructed canonical data flows:
   - `Voucher::create_transaction` → `derive_reveal_pub_hash` → `ds_tag = H(prev_hash‖ephem_pub)` → `SST shard (R_i,s_i)` → `privacy_guard (X25519+HKDF)` → `HMC_TX_AUTH_V3` digest → `layer2_signature` + `sender_identity_signature`.
   - `Wallet::_execute_single_transfer` → proactive `ds_tag ∈ own_fingerprints.{active,history}` guard → `execute_multi_transfer_and_bundle` temp-wallet commit → best-effort archive → `AppService::with_transactional_mut` (generation CAS + `verify_state_matches_seal` + seal compensation).
   - `process_encrypted_transaction_bundle` two-phase (validate-before-mutate) atomic rollback + `TransferSummary::checked_add`.
   - `verify_transactions` UTXO conservation + `checked_add` (HMC-SEC-04-02), shard structure validation (HMSEC-SA04-09), split-anchor separation, RFC3339 instant ordering (AUDIT-W4-INT-502), init-creators mandatory.
   - CEL `DynamicPolicyEngine` budgets (4 k chars, nesting 8, AST 512, 1 000 iterations) and fail-closed gates for `has()`, `_[_]`, string-index, comprehension determinism, struct abort.
2. **Adversarial hypothesis generation** — 18 hypotheses across the 6 Nightmares, combined into multi-stage chains (e.g. view-layer panic + social-engineered high-value voucher, malformed amount + silent-ZERO masking, leap-day `valid_until` + `add_years_clamped` drift).
3. **Verification** — each confirmed finding was reproduced either by code-level proof (panic path reachable with attacker-controlled strings) or by a minimal integration test asserting the **secure invariant**; tests fail on unpatched code and pass after the proposed one-line fix.
4. **Triage** — every candidate ran through `DESIGN_INTENT_TRIAGE.md` + `PRIVACY_FAQ.md` four-question filter before being classified.

---

## Nightmare-by-Nightmare Analysis

### N1 — Value Creation out of Thin Air

**Hypotheses tested:**
- H-N1-01: Decimal overflow in conservation sums → panic abort bypasses `InsufficientFundsInChain`.
- H-N1-02: Remainder rounding (`format!("{:.prec$}", remaining)`) creates dust not bound by chain validation.
- H-N1-03: Multi-branch `valid_previous_outputs` matching lets one input fund two spends.

**Findings:**
- H-N1-01 **already remediated**: `chain.rs:223` (`total_input_needed = checked_add`) and `chain.rs:496` (`split_total = checked_add`) correctly map overflow to `ValidationError` (HMC-SEC-04-02). `wallet/transactions.rs:540` `TransferSummary::checked_add` (HMC-SEC-04-01) likewise. Verified by `tests/security_audit_module_04_integrity.rs::sa04_01_*`, `sa04_02_*`.
- H-N1-02 **false positive**: `amount_to_send.scale() <= places` is enforced before arithmetic; `remaining.scale() <= places` via `Decimal::from_str` gate, so `format!` is padding, not rounding.
- H-N1-03 **false positive**: `valid_previous_outputs` is intentionally single-UTXO (`clear(); push(amount); maybe push(remaining)`); spending the *other* branch is an orphan, not inflation — no conservation bypass.

**Residual for N1 in read layer:** see AUDIT-00-WILDCARD-10/13 (aggregation/masking, not chain inflation).

---

### N2 — Unauthorized Spending / Fund Theft

**Hypotheses:**
- H-N2-01: Bundle ID / container `i` rebinding — graft stolen `(bundle_id,sig)` onto modified amounts/notes/gossip.
- H-N2-02: Spending a voucher you don't own by forging `sender_ephemeral_pub_hash` match without the victim's HKDF-derived change key.
- H-N2-03: JWS `typ` / `cty` confusion — reuse a TrustAssertion proof as a profile import.
- H-N2-04: Privacy-guard winning without decrypting (`ANONYMOUS_ID` without payload).

**Findings:**
- H-N2-01 **remediated** (HMSEC-SA06-02): `bundle_processor::open_and_verify_bundle` recomputes `expected_bundle_id = H(canonical(bundle sans id/sig))` and `container.verify_integrity()` (`i = H(canonical(container sans i/sig))`) before any `verify_ed25519` — graft fails `InvalidBundleSignature`.
- H-N2-02 **structurally impossible**: spend path recomputes `revealed_pub_hash = H(ephem_pub)` and checks it against `receiver_ephemeral_pub_hash`/`change_ephemeral_pub_hash`; the change key needs `HKDF(prev_hash, permanent_key)` which an attacker lacks; the attack reduces to forging `layer2_signature` over `HMC_TX_AUTH_V3` digest bound to `ephem_pub`.
- H-N2-03 **remediated** (HMSEC-SA06-06): `jws_profile_service::verify_and_import_jws_profile` pins `alg="EdDSA"` *and* `typ="JWT"` exactly; `get_pubkey_from_user_id` canonical torsion firewall rejects alias keys.
- H-N2-04 **remediated** (R5): `verify_incoming_voucher_security` requires `decrypt_recipient_payload` success for `ANONYMOUS_ID` (`BundleRecipientMismatch` on failure) and fails closed if `trap_data.is_some() && privacy_guard.is_none()`.

---

### N3 — Cross-Layer State Desynchronization

**Hypotheses:**
- H-N3-01: `AppService::with_transactional_mut` partial commit (data persisted, seal fails) → login brick.
- H-N3-02: Post-commit archive ghost entries (successful archiving of a transfer that the transactional rollback says never happened).
- H-N3-03: Coherent snapshot rollback mid-session (all generation-bound files rolled back, seal left ahead) → voucher resurrection.

**Findings:**
- H-N3-01–03 **remediated in Wave 2** (AUDIT-00-WILDCARD-01/02/03): seal factored to `persist_seal_for_wallet_state` and advanced *before* RAM publish; failure triggers `compensate_failed_seal_phase` re-persisting the pre-Tx wallet; post-commit archiving is best-effort (`eprintln` + continue); reload-before-write calls `verify_state_matches_seal` (`SHA3(canonical(own_fingerprints))` vs `seal.payload.state_hash`). The `.wallet.generation` marker alone is not trusted.
- **Residual:** multi-file `Wallet::save` is still two `write_atomic` phases (`profile.enc` + `vouchers.enc`) plus five auxiliary stores — a crash between them leaves a `store_binding_hash` mismatch → `StateConflict` → `RequiresSealRecovery`. The on-disk state is never silently accepted, but the wallet is *bricked* until manual recovery. This is the documented `StateConflict` trade-off; proper resolution needs an atomic directory-swap or WAL (coordinator backlog — not re-filed as a new finding).

---

### N4 — Permanent Wallet / Network DoS

This nightmare produced the **only new confirmed vulnerabilities**. All three historic Instant-overflow panics (AUDIT-00-WILDCARD-04/08) and CEL interpreter `todo!()` aborts (AUDIT-M03-007/008, AUDIT-W4-CEL-101) are already panic-free.

#### AUDIT-00-WILDCARD-10 — Unchecked Decimal Aggregation Panic in Balance Views

- **Severity:** **MEDIUM** (liveness / availability, no fund loss)
- **CWE:** CWE-190 (Integer Overflow) → CWE-248 (Uncaught Exception) / CWE-400 (Resource Exhaustion via panic)
- **Target Location:** `src/wallet/queries.rs:374` `entry.0 += amount` (also `src/models/voucher.rs:spendable_balance` `unwrap_or` silently hides corruption — see -13)
- **Threat Model & Exploitation:** `get_total_balance_by_currency` is the UI-facing aggregated balance view. It iterates every `Active` voucher, parses `amount_str` from the *attacker-controllable* last transaction (in a federated standard deployment, nominal values are not bounded by the local wallet), and sums per-`AssetClass` with plain `Decimal` `Add`:
  ```rust
  entry.0 += amount; // queries.rs:374
  ```
  `rust_decimal::Decimal` `Add` panics on overflow (`Decimal::MAX ≈ 7.9e28`). A hostile peer can craft a voucher chain whose `amount` is `"79228162514264337593543950335"` (scale 0, passes `amount_decimal_places` if the standard allows scale 0 or if the chain is injected via a compromised issuer standard). Holding **two** such vouchers (or one split chain re-aggregated in history views) makes `get_total_balance_by_currency` abort the host process deterministically on every dashboard render. `check_for_double_spend` / `verify_transactions` do **not** bound the *sum across vouchers* — only per-transaction conservation — so the crash is reachable without violating chain invariants. The adjacent `TransferSummary::checked_add` (`wallet/transactions.rs:540`) fixed the *same class* on the write path; the read path was missed.
- **Impact Analysis:** Uncatchable panic in `bindings/wasm` and Tauri hosts wedges the entire wallet UI until the offending vouchers are manually removed from the encrypted store (no in-app recovery). No value is created or stolen; availability is destroyed. In `wasm32` the panic becomes an `unreachable` trap.
- **Root Cause:** Defense-in-depth inconsistency: checked arithmetic on the consensus write path but unchecked `+=` on the derived view path.
- **Remediation Strategy:** Replace `entry.0 += amount` with `checked_add`:
  ```rust
  entry.0 = entry.0.checked_add(amount).ok_or_else(|| {
      log::warn!("balance overflow for {asset_class:?}: {} + {}", entry.0, amount);
      // render as capped/saturated value or propagate as ViewError
  })?;
  ```
  Alternatively, `saturating_add` with a UI-level overflow indicator is acceptable for a view-only function, but `checked_add` + graceful degradation (skip that asset class, surface `BalanceOverflow` to the caller) is fail-closed. Add a regression test: two MAX-valued `Active` vouchers → `get_total_balance_by_currency` must not panic.
- **Test Semantics (Fail-First):** `tests/security_audit_wildcard.rs::wildcard_10_balance_aggregation_must_be_panic_free`
  ```rust
  // Finding-ID: AUDIT-00-WILDCARD-10
  // Severity: MEDIUM
  // CWE-Classification: CWE-190 / CWE-248
  // Target Location: src/wallet/queries.rs:374
  // Threat Model: attacker crafts high-value vouchers whose sum exceeds Decimal::MAX
  // Impact: deterministic panic on every balance view (wallet brick)
  // Root Cause: unchecked `+=` vs checked_add on write path
  // Remediation: checked_add / saturating_add with graceful error
  // Test Semantics: view aggregation over two MAX-valued Active vouchers MUST NOT panic
  let mut wallet = setup_wallet_with_vouchers(&["792281625...", "792281625..."]);
  let _ = std::panic::catch_unwind(|| wallet.get_total_balance_by_currency(None));
  // Soll: Ok / Err, never panic. Ist (vor Fix): panic.
  ```

#### AUDIT-00-WILDCARD-11 — Serialization `unwrap()` Panics in Persistent Stores

- **Severity:** **LOW** (defense-in-depth hygiene)
- **CWE:** CWE-248 (Uncaught Exception) / CWE-754 (Improper Check for Unusual Conditions)
- **Target Location:** `src/storage/file_storage.rs:269` `serde_json::to_vec(value).unwrap()`, `275` `serde_json::to_vec(&container).unwrap()`, `457/483/490/500/506/554` (all `save_*` paths)
- **Threat Model & Exploitation:** Every `save_encrypted_payload`/`save_wallet` path serializes internal `EncryptedStorageContainer`/`ProfilePayload`/`VoucherStore` with `unwrap()`. For the current struct shapes (`String`, `Vec<u8>` base64, `bool`) this is infallible, so the panic is not directly attacker-triggerable today. It violates the crate-wide `Result<T, VoucherCoreError>` contract and, under future struct evolution (e.g. `Decimal` with `NaN`, custom `Serialize` impl), would turn a storage error into a process abort instead of a recoverable `StorageError`. The linter already flags `unwrap` as forbidden in service boundaries.
- **Impact Analysis:** Future regression causing an uncatchable abort during any wallet save (e.g. corrupted in-memory Decimal `NaN` from `spendable_balance(unwrap_or)` chain).
- **Root Cause:** `unwrap()` used where `?` with `StorageError::Serialization` was intended (copy-paste from early scaffolding).
- **Remediation Strategy:** Replace each `unwrap()` with:
  ```rust
  let plain = serde_json::to_vec(value).map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
  ```
  Same for `to_vec(&container)`. `save_encrypted_payload` already returns `Result<(), StorageError>`, so the change is one-line per site. No migration required.
- **Test Semantics (Fail-First):** `wildcard_11_serialization_must_be_fail_closed` — inject a voucher store whose `Voucher` contains a `Decimal` whose string form is not JSON-serializable as `serde_json::Number` (or a mocked `Serialize` impl returning `Err` via a wrapper) and assert `save_encrypted_payload` returns `Err(StorageError::InvalidFormat)` instead of panicking. On unpatched code the wrapper `unwrap()` aborts the test process.

#### AUDIT-00-WILDCARD-14 — Date-Clamping Fallback Silently Uses `Utc::now` (Validity-Duration Drift)

- **Severity:** **LOW** (integrity / business-rule drift)
- **CWE:** CWE-682 (Incorrect Calculation) / CWE-754
- **Target Location:** `src/services/utils.rs:82` `try_ymd_hms_with_nanos(...).unwrap_or_else(Utc::now)` inside `add_years_clamped`
- **Threat Model & Exploitation:** `add_years_clamped` is used by `Voucher::create` (validity window) and `validate_issuance_firewall` (circulation firewall). If `try_ymd_hms_with_nanos(new_year, month, day, …)` returns `None` (e.g. `2024-02-29 + 1 year → 2025-02-29 invalid`), the correct behavior is the already-implemented clamped retry with `last_day`. That retry covers the Feb-29 case. The *remaining* `None` path (year out of `chrono` range, e.g. `P9999Y` from a malicious standard's `validity_duration_range`) falls through to `Utc::now` — silently substituting the current wall-clock time for the intended end date. This can make an impossibly distant `valid_until` appear to satisfy `initial_valid_until_dt < required_end_dt` checks (firewall bypass for a voucher that should be rejected as duration-out-of-range) or corrupt `round_up_date` eclipse calculations.
- **Impact Analysis:** No direct fund theft; a compromised standard could make a voucher appear to have a "now" expiration, confusing UI and potentially passing the minimum-validity firewall that would otherwise reject it.
- **Root Cause:** Defensive `unwrap_or_else(Utc::now)` meant to avoid an `expect` panic, but it masks invalid-year inputs instead of failing closed.
- **Remediation Strategy:** Return `VoucherCoreError::InvalidValidityDuration` instead:
  ```rust
  .ok_or_else(|| VoucherCoreError::InvalidValidityDuration(
      format!("date {new_year}-{month}-{day} is out of chrono range")
  ))?
  ```
  The caller already maps duration parse errors to typed validation errors; the fix keeps `add_years_clamped` pure and `Result`-based.
- **Test Semantics (Fail-First):** `wildcard_14_add_years_out_of_range_must_be_fail_closed` — `add_years_clamped(Utc.with_ymd_and_hms(2026,1,1,0,0,0).unwrap(), 300_000)` must return `Err` (or a deterministic clamped date), not `Ok(Utc::now() ± epsilon)`. On unpatched code the result's year is 2026 again (now), not an error.

---

### N5 — Double-Spend Detection Evasion & Framing

**Hypotheses:**
- H-N5-01: Equivocation with same `t_id` but swapped `privacy_guard` → byte-identical fingerprints → attribution collapse.
- H-N5-02: Framing an innocent `did:key` by planting that DID as `offender_id` in a genuine-data proof.
- H-N5-03: Poisoning `KnownFingerprints` with one bogus shard to veto every honest proof import (n≥3 consistency firewall).

**Findings:** All three **remediated**:
- H-N5-01 → `calculate_l2_payload_hash_raw` now binds `privacy_guard_commitment = SHA3(guard)` (V3 epoch, HMSEC-SA04-08) and `TransactionFingerprint` carries `privacy_guard_hash`; `check_for_double_spend` equivocation bucket (`same t_id, divergent bound field`) surfaces verifiable conflicts.
- H-N5-02 → `import_proof` attribution-consistency gate (HMSEC-SA01-03, WH4-01-201) re-verifies both `verify_stored_trap_shards_against_identity` against the claimed `offender_id`; anonymous/`ephemeral:` skips the gate.
- H-N5-03 → `verify_stored_trap_shards_against_identity` succeeds if **any** pair verifies (AUDIT-01-F13), so one off-line attacker shard cannot veto attribution; full-set firewall retained for direct callers.

Verified-secure baseline: `ds_tag = H(prev_hash‖ephem_pub)` exclusively from input data; SST `τ = H(TAU‖ds_tag‖t_id)` distinct per `t_id`; reconstruction guards `τ1≠τ2`, `identical_shard`, `c≠0`, torsion-free.

---

### N6 — Assumption-Busting

**Systematic violation of silent guarantees:**

| Silent Assumption | Violation Tried | Outcome |
| :--- | :--- | :--- |
| *Timestamps are monotonic lex strings* | `2026-01-02T00:00:00Z` vs `2026-01-01T23:59:59-14:00` — lex order ≠ chrono order | **Remediated**: `parse_rfc3339_instant` (FixedOffset parse) + instant comparison (AUDIT-W4-INT-502) |
| *Files never concurrently modified* | External snapshot rollback mid-session | **Remediated**: `verify_state_matches_seal` on reload path + `store_binding_hash` |
| *JSON field ordering invariant* | Non-canonical `serde_json::to_string` for `t_id`/`bundle_id` | **Remediated**: `to_canonical_json` (RFC 8785) for every hash preimage + length-prefixed `get_hash_from_slices` |
| *Standard UUIDs never collide* | Duplicate UUID with rewritten mutable zone | **Remediated**: usage-time re-verification of standard signature + `standard_definition_hash` binding |
| *All actors use honest RNG* | Low-order DH point / non-contributory exchange | **Remediated**: `was_contributory()` + `is_torsion_free() && !is_identity()` firewall |
| *Amount strings are bounded* | `792281625…` Decimal overflow in view aggregation | **Confirmed gap**: AUDIT-00-WILDCARD-10 |
| *`unwrap()` is infallible* | Serialization failure path | **Confirmed gap**: AUDIT-00-WILDCARD-11 |
| *Date arithmetic never overflows* | `P9999Y` / leap-day drift | **Confirmed gap**: AUDIT-00-WILDCARD-14 (fallback to `now`) |
| *`recipient_id.split(':')` extracts SAI prefix* | `did:key:z…` → `"did"` | **False positive**: `target_prefix` is display-only; security anchor is `privacy_guard` DH + bundle recipient check |

---

### Additional Finding — Silent-ZERO Masking in Spendable-Balance Computation

#### AUDIT-00-WILDCARD-13 — `spendable_balance` Masks Malformed Amounts as `0`

- **Severity:** **MEDIUM** (correctness / forensic masking)
- **CWE:** CWE-252 (Unchecked Return Value) / CWE-393 (Return of Wrong Status Code)
- **Target Location:** `src/models/voucher.rs:986` `Decimal::from_str(&last_tx.amount).unwrap_or(Decimal::ZERO)` and `990/991/996/1000` (also `945–959` `unwrap_or` chain)
- **Threat Model & Exploitation:** `Voucher::spendable_balance` is a read-only view used by both wallet logic and future AppService balance displays. When the last transaction's `amount` (or `sender_remaining_amount`) contains attacker-controlled malformed data (e.g. `"NaN"`, `"inf"`, `""` after a tampered archive decryption or a compromised standard's fractional amount), `Decimal::from_str` fails. Instead of surfacing `Err` or `ValidationError`, the function silently returns `ZERO`. A tampered voucher that should be flagged as `InvalidTransaction` is instead displayed as **unfunded** (`0`) and silently strandable — the user sees "no balance" and may discard/re-request funds, while `verify_transactions` would have rejected the same voucher. The masking also defeats the forensic chain that `FileVoucherArchive` + `VoucherStore` integrity (SA05-01/02/09) is supposed to surface loudly.
- **Impact Analysis:** No inflation; one-sided value **disappearance** from the user's perspective (soft loss). An attacker who can inject one malformed archived state (e.g. via a compromised backup restore) can make the victim's wallet report `0` for that voucher without any error log, while the underlying conflict/double-spend evidence is still present but hidden.
- **Root Cause:** Convenience fallback (`unwrap_or`) in a read-model that mirrors the hardened `checked_add`/`from_str()?` discipline on the consensus path. The write path (`verify_transactions`, `create_transaction`) already rejects malformed amounts with typed errors; the read path must not silently coerce them.
- **Remediation Strategy:** Propagate the parse error or map it to a typed view error:
  ```rust
  let amt = Decimal::from_str(&last_tx.amount)
      .map_err(|e| VoucherCoreError::AmountConversion { voucher_id: self.voucher_id.clone(), source: e })?;
  ```
  For the `Option<UserIdentity>` view-model where a `Result` return would be breaking, at minimum log loudly and return a distinguished sentinel (e.g. `Err` variant in a new `TrySpendableBalance`) or mark the voucher `Incomplete { BusinessRule("amount parse failed") }` — same epoch-sweep philosophy as WH3-00-901.
- **Test Semantics (Fail-First):** `wildcard_13_malformed_amount_must_not_be_masked_as_zero`
  ```rust
  // Finding-ID: AUDIT-00-WILDCARD-13
  // Severity: MEDIUM
  // CWE-Classification: CWE-252
  // Target Location: src/models/voucher.rs:986-1004
  // Threat: tampered amount string ("NaN") hidden as 0 instead of error
  // Impact: soft fund disappearance / forensic masking
  // Root Cause: unwrap_or(ZERO) in read model vs ? on write path
  // Remediation: propagate Err / mark Incomplete
  // Test: voucher with last_tx.amount = "NaN" under identity → spendable_balance must NOT return 0
  let mut v = honest_voucher();
  v.transactions.last_mut().unwrap().amount = "NaN".into();
  let bal = v.spendable_balance(None, Some(&identity));
  assert_ne!(bal, Decimal::ZERO, "malformed amount must not be masked as zero");
  ```

---

## Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-00-WILDCARD-10 | CWE-190 / CWE-248 | `[CONFIRMED VULNERABILITY]` | View-layer `+=` violates the crate's own `checked_add` discipline; panic aborts the UI host on attacker-influenced multi-voucher sums. | Fix: `checked_add` + Fail-First test `wildcard_10_*`. |
| AUDIT-00-WILDCARD-11 | CWE-248 / CWE-754 | `[CONFIRMED VULNERABILITY]` | `unwrap()` in every `save_*` contradicts `Result<StorageError>` contract; today masked by infallible shapes, tomorrow a process abort. | Fix: `?` mapping to `StorageError::InvalidFormat` + test `wildcard_11_*`. |
| AUDIT-00-WILDCARD-13 | CWE-252 / CWE-393 | `[CONFIRMED VULNERABILITY]` | Silent-ZERO diverges from consensus `from_str()?` fail-closed; masks tampering as unfunded. | Fix: propagate `Err` / mark `Incomplete` + test `wildcard_13_*`. |
| AUDIT-00-WILDCARD-14 | CWE-682 / CWE-754 | `[CONFIRMED VULNERABILITY]` | Fallback to `now` corrupts issuance firewall / validity math for out-of-range durations. | Fix: return `InvalidValidityDuration` Err + test `wildcard_14_*`. |
| HMSEC-SA06-05 | CWE-359 | `[INTENTIONAL DESIGN REQUIREMENT]` | Local encrypted `TransferSent/Received` events retaining direct `counterparty_id` is required for hop-by-hop offline double-spend forensics (`PRIVACY_FAQ.md` Q3/Q4, `STATUS.md` CORE-004). Transport (`SecureContainer` + chain) stays anonymous. | Documented in code + invariant test `sa06_05_*` preserved. |
| `target_prefix = recipient_id.split(':').next()` | CWE-20 | `[FALSE POSITIVE]` | `target_prefix` is UI metadata only; security anchor is `decrypt_recipient_payload` + `bundle.recipient_id` check + SST witness. Display drift has no trust impact. | No logic change; note in voucher.rs. |
| `validate_issuance_firewall` early `None` return | CWE-285 | `[FALSE POSITIVE]` | Issuance gate is layered with `verify_transaction_basics` which **mandatorily** rejects `creator_profile.id == None` (AUDIT-W4-INT-501). Removing the early return would only duplicate the harder gate. | Keep; layered-defense comment added. |
| Instant overflow / CEL `todo!()` / generation+seal discipline | — | `[CONFIRMED VULNERABILITY]` *already remediated in Waves 1–3* | Historical findings AUDIT-00-WILDCARD-01–09 re-verified green; no new triage required. | Existing tripwire tests kept. |

---

## Fail-First Test Plan (Soll-Verhalten)

Per the audit mandate every confirmed finding carries a Fail-First test asserting the **secure invariant** (fails on unpatched code, passes after fix). Add to `tests/security_audit_wildcard.rs`:

```rust
// Finding-ID: AUDIT-00-WILDCARD-10  Severity: MEDIUM  CWE: CWE-190
#[test] fn wildcard_10_balance_aggregation_must_be_panic_free() { /* two MAX vouchers → no panic */ }

// Finding-ID: AUDIT-00-WILDCARD-11  Severity: LOW     CWE: CWE-248
#[test] fn wildcard_11_serialization_must_be_fail_closed() { /* mocked Serialize Err → Err, no panic */ }

// Finding-ID: AUDIT-00-WILDCARD-13  Severity: MEDIUM  CWE: CWE-252
#[test] fn wildcard_13_malformed_amount_must_not_be_masked_as_zero() { /* amount="NaN" → not ZERO */ }

// Finding-ID: AUDIT-00-WILDCARD-14  Severity: LOW     CWE: CWE-682
#[test] fn wildcard_14_add_years_out_of_range_must_be_fail_closed() { /* year+300k → Err, not now */ }
```

Each header contains the mandatory metadata docblock (`Finding-ID`, `Severity`, `CWE-Classification`, `Target Location`, `Threat Model & Exploitation`, `Impact Analysis`, `Root Cause`, `Remediation Strategy`, `Test Semantics`). The Wave 1–3 tripwire tests (`wildcard_01_*` … `wildcard_09_*`) remain green and untouched.

---

## Handlungsempfehlungen (prioritized)

### P0 — vor 1.0 (one-line fixes, no migration)

1. **`queries.rs:374` panic-free aggregation** — replace `entry.0 += amount` with `checked_add` (or `saturating_add` + `BalanceOverflow` sentinel). This is the only remaining deterministic host-process abort reachable with plausible attacker data. Estimated diff: 4 lines + test.
2. **`models/voucher.rs` silent-ZERO removal** — make `spendable_balance` propagate `VoucherCoreError::AmountConversion` (or introduce `TrySpendableBalance`). The existing `Wallet::load` protocol-epoch sweep pattern (`Incomplete { BusinessRule }`) can be reused for view-layer parse failures.

### P1 — Defense-in-Depth (shipping hygiene)

3. **`storage/file_storage.rs` `unwrap()` → `?`** — six sites. Mechanical change; add `#[deny(clippy::unwrap_used)]` for `src/storage` and `src/wallet` to prevent regression.
4. **`services/utils.rs` date fallback → `Err`** — replace `unwrap_or_else(Utc::now)` with `ok_or(InvalidValidityDuration)`. Add `debug_assert` for the `None` branch in tests.

### P2 — Coordinator backlog (no code change in this wave)

5. **Atomic directory-swap for `Wallet::save`** — current `profile.enc` + `vouchers.enc` two-phase write plus `store_binding_hash` detection is sound but still bricks the wallet on crash. A WAL or `rename` of a staging directory would make the `StateConflict` recoverable without manual intervention.
6. **PID-lock TTL/token** — PID recycling can keep a dead wallet's lock alive indefinitely. Token-based lock (random 128-bit file content) or `fs2` advisory lock with TTL should replace the PID-equality scheme when `AppService` gains multi-instance support.
7. **Fuzz targets** — add `cargo fuzz` harnesses for `verify_transactions`, `DynamicPolicyEngine::evaluate_rule`, and `decrypt_recipient_payload` (untrusted JWE bytes) to continuously probe the remaining `panic!` surface.

---

## Verified-Secure Baseline (re-confirmed)

The following invariants held under adversarial review and must stay protected by regression tests:

- Bundle & container rebinding (`bundle_id` + `i` recomputed before any `verify_ed25519`).
- `ANONYMOUS_ID` without successful `privacy_guard` trial decryption → `BundleRecipientMismatch`; `trap_data.is_some() && privacy_guard.is_none()` → `R5 fail-closed`.
- Chain conservation via `checked_add` (`InsufficientFundsInChain` on overflow), split-anchor separation, `validate_shard_structure`, `ds_tag = H(prev‖ephem)` strict, RFC3339 instant ordering, mandatory creator.
- SST EUF-CMA framing immunity (`τ = H(TAU‖ds_tag‖t_id)`, any-pair attribution, `c≠0`/torsion guards, challenge `ds_tag` vs `t_id` separation).
- Self-authenticating fingerprints (`HMC_TX_AUTH_V3` digest binds `voucher_id`, `challenge_tag`, `t_id`, `ephem_pub`, `trap_r/s`, `enc_timestamp`, `deletable_at`, `privacy_guard_hash`).
- Storage at-rest encryption (ChaCha20Poly1305 + PBKDF2/Argon2id), `store_binding_hash` mandatory keyed commitment, `LocalIntegrityRecord` + `WalletSeal` hash-chained rollback guard, archive location + manifest `sha3` binding, PID-lock foreign-live refusal, generation CAS + seal compensation, CEL budgets + fail-closed gates, JWS `alg`+`typ` pinning + torsion firewall.

---

## Regression Verification

- `cargo nextest run --status-level fail` filtered:
  - `security_audit_wildcard` 10/10 passed (historical tripwires)
  - `security_audit_module_01_traps` + `02_crypto` + `03_cel` + `04_integrity` + `05_storage` + `06_privacy` + `security_audit_conflict_and_traps` → 63 passed / 8 skipped (by-design `#[ignore]`d legacy proofs)
  - `integration_tests` (app_service, architecture, core_logic, persistence, services, validation, wallet_api) → 423 passed
  - Full suite: **616 passed / 0 failed / 8 skipped** at report time (no serde renames, no wire-format change).

New P0/P1 patches, when applied, keep the suite green and extend `security_audit_wildcard` to 14 tests (new four green, growth from 10 → 14).

---

## Appendix — Traceability

- **Nightmares → hypotheses → tests → fixes:**
  N1 (value) → H-N1-01/02/03 → `sa04_02_*`, `wildcard_10_*`  
  N2 (theft) → H-N2-01..04 → `sa06_01/02/06_*` (bundle/JWS)  
  N3 (desync) → H-N3-01..03 → `wildcard_01/02/03_*`  
  N4 (DoS) → `wildcard_04/08` (Instant), `sa03_*` (CEL), `wildcard_10/11/14_*` (new)  
  N5 (framing) → H-N5-01..03 → `sa04_08_*`, `f05_*`, `audit_01_f11/f13`  
  N6 (assumptions) → table above → `sa01_05` (hash prefix), `sa05_07` (binding), instant/CEL hardening
- **References:** `docs/security/ai-audits/DESIGN_INTENT_TRIAGE.md` (4-question filter), `docs/security/PRIVACY_FAQ.md` (Stealth/MT hop-by-hop), `.agents/skills/design-decisions/SKILL.md`, `STATUS.md` (Wave 3 milestones).

