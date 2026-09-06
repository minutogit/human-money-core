# Module 04 — Fresh Hypotheses (Transaction & State Integrity)

Auditor: fresh-eyes pass, 2026-08-26. Research only — no source code modified.
Scope walked end-to-end: bundle ingestion (`bundle_processor`, `secure_container_manager`) →
chain validation (`voucher_validation/*`) → split/change creation (`voucher_manager/transaction.rs`,
`balance.rs`, `creation.rs`) → wallet state transitions (`wallet/transaction_handler.rs`,
`conflict_handler.rs`, `maintenance.rs`, `queries.rs`, `lifecycle.rs`, `maintenance.rs`) →
supporting services (`decimal_utils`, `integrity_manager`, `conflict_manager`, `l2_gateway`,
`trap_manager`, `date_utils`).

## Coverage Matrix

| # | Instruction / Checkpoint (audit prompt) | Status | Note |
|---|---|---|---|
| 1 | Conservation of value: ΣInputs = ΣOutputs + Fees; negative/zero amounts impossible | CLEAN | `chain.rs:213-267,395-497`: exact-equality matching against single unspent output, `checked_add` for attacker sums (HMC-SEC-04-02), `NegativeOrZeroAmount` gate at `chain.rs:622-636`; creation path re-validates whole voucher after append (`transaction.rs:339`). |
| 2 | Rounding / precision tricks in `decimal_utils` letting outputs exceed inputs | CLEAN | `validate_precision` is scale-only but every consumer gates by equality: init amount must `.normalize()`-equal nominal (`chain.rs:559-567`), split total must exactly equal prior balance (`chain.rs:480-496`). `format_for_storage` rounds silently, but any rounded-vs-nominal mismatch is rejected — no path converts rounding into value. |
| 3 | Integer overflow/underflow in amount arithmetic | FINDING (HYP-04-1) | Per-tx arithmetic hardened with `checked_add`; the aggregate balance view `queries.rs:389` still uses plain `+=` on `Decimal` (panics ≥ rust_decimal MAX) — same class as the already-fixed HMC-SEC-04-01. |
| 4 | Split/change anchor overlap: same seed reused for transfer + change branch | CLEAN | Construction is independent (recipient seed = CSPRNG `transaction.rs:149-153`; change seed = HKDF(permanent key, salt=prev_hash) `transaction.rs:156-185`) and a validator gate rejects equal anchors (`chain.rs:445-465`, HMSEC-SA04-05). Re-derivation (`transaction_handler.rs:1136-1152`) matches creation salt/info exactly. |
| 5 | Anchor-calculation consistency between create and rederive paths | CLEAN | HKDF salt (`prev_hash.as_bytes()`), IKM (permanent key), info string (`[prefix]change_seed`) identical in `transaction.rs:159-174` vs `transaction_handler.rs:1133-1149`; hash-match verification before acceptance prevents drift. |
| 6 | Panic-freedom on untrusted binary/TOML bundles: unwrap/expect/indexing/conversions in decoders | FINDINGS (HYP-04-2, HYP-04-4) | Most decoder hazards are mapped to `Err` (base58, try_into, slice guards in `l2_gateway.rs:347-352`, len-checked expects behind guards in `conflict_manager.rs:199-228`). Remaining panics live outside the strict decoders: date arithmetic on standard/app-supplied durations (`date_utils.rs`) and i8 truncation of chain depth. `transaction.rs:106` / `balance.rs:106` `last().unwrap()` are provably unreachable (InsufficientFunds fires first for empty chains). |
| 7 | State desynchronization if bundle processing fails midway | CLEAN | Receive path wraps everything in clone-snapshot rollback (`transaction_handler.rs:121-135`, HMSEC-SA04-04); send path commits via temp-wallet swap (`transaction_handler.rs:969-1055`); forensic archive writes strictly post-commit, failures surfaced via `forensic_archive_incomplete` (AUDIT-W4-INT-503); `Wallet::load` self-heals derived stores via `rebuild_derived_stores`. |
| 8 | Race conditions in wallet state | CLEAN (residual note) | No interior mutability outside test-only `MOCK_TIME`; all mutations through `&mut self`; optimistic generation counter in `save()` (`lifecycle.rs:267-274`). Concurrent savers via separate wallet clones would be an app-layer misuse; core itself has no shared mutable state. |
| 9 | Open exploration / assumption busting | FINDINGS (HYP-04-3 + notes) | Ingestion proves guard decryptability but never binds the delivered `next_key_seed` to `receiver_ephemeral_pub_hash` — balance views then fall back to displaying the raw transaction amount (HYP-04-3). Also noted: unbounded recipient-array trial decryption (resource DoS), i8 depth truncation. |

## Hypotheses

### HYP-04-1: Unchecked Decimal aggregation panics on near-MAX voucher amounts
- Severity: MEDIUM (process crash on untrusted input)
- CWE: CWE-190 (integer overflow) / CWE-690 (unhandled panic path)
- Target: src/wallet/queries.rs:389 (`entry.0 += amount;`)
- Attack:
  1. Attacker creates two vouchers under any standard imported by the victim (amount magnitude is not bounded by standards — only scale is checked, `chain.rs:148-169`; init amount only has to equal nominal, `chain.rs:559-567`).
  2. Nominal values e.g. `"79228162514264337593543950335"` (Decimal::MAX) and `"1"`; chains are internally consistent and pass `validate_voucher_against_standard` on receive (`transaction_handler.rs:304`).
  3. Victim's wallet stores both as `Active` in the same AssetClass (same standard uuid/unit/test-flag), which the code itself groups and sums.
  4. Any call to `Wallet::get_total_balance_by_currency` (exposed via AppService/Tauri balance view) executes `entry.0 += amount`. rust_decimal 1.x `Add` panics unconditionally on overflow ("Addition overflowed") in debug AND release.
- Root cause: The HMC-SEC-04-01 hardening (`checked_add`) was applied to the TransferSummary aggregation (`transaction_handler.rs:489-498`) but not to the identical aggregation in the balance view. Amounts summed here originate from peer-supplied voucher chains with no upper magnitude bound.
- Confidence: HIGH
- Testable: YES — Integration test: build a `Wallet`, `add_voucher_instance` two minimal `Active` vouchers whose last transaction `amount`s are Decimal::MAX and "1" (plain structs; no signatures needed for this read path), then call `get_total_balance_by_currency(Some(&identity))`. Secure invariant: function returns gracefully (skips or errors per bucket). Current code panics → test FAILS (abort) on unpatched code.

### HYP-04-2: Panic in ISO-8601 duration arithmetic on extreme standard/app durations
- Severity: MEDIUM (crash of validation/receive/create paths on untrusted TOML or app input)
- CWE: CWE-690 (unchecked unwrap on date computation), CWE-20 (insufficient input range validation)
- Target: src/services/voucher_manager/date_utils.rs:38-49 ("Y" fallback unwrap), :53-90 ("M" branch unwraps; u32 add at :54 debug-overflow), :92 ("D" chrono Add overflow)
- Attack:
  1. Vector A (network TOML): attacker publishes a self-signed `standard.toml` with `issuance_minimum_validity_duration = "P300000Y"` (or `"P4294967295D"`, `"P4294967284M"`). Import verifies only the issuer signature over the file (`standard_manager.rs:75-136`); duration strings are never range-checked, and issuer pinning is optional (`verify_and_parse_standard_with_issuer_pin` legacy mode).
  2. Victim imports the standard. Anyone sends the victim ANY voucher under that standard.
  3. Receive-path validation calls `verify_validity_duration` (`voucher_validation/mod.rs:47` → `identity.rs:102-165`) → `add_iso8601_duration`.
  4. `"Y"`: year+300000 exceeds chrono's ±262143 range → `with_year` None → fallback `Utc.with_ymd_and_hms(...)` returns `LocalResult::None` → `.unwrap()` panics (date_utils.rs:48). `"D"`: `DateTime + Duration::days(...)` overflows chrono range → unconditional `expect` panic inside chrono. `"M"`: extreme month counts reach the same `LocalResult::None.unwrap()` sites (release-mode panic via lines 71-74/78-89; debug builds additionally panic on the u32 add at line 54).
  5. Every subsequent validate/spend/receive touching that standard panics the calling thread — permanent DoS for that asset (and bundle processing aborts mid-flight; state rollback cannot catch a panic).
  - Direct variant without hostile standards: `Wallet::create_new_voucher` forwards app/user-supplied `data.validity_duration` into `add_iso8601_duration` first thing (`creation.rs:96`), so a frontend-supplied `"P999999999999D"` panics the create command.
- Root cause: Duration parser bounds the numeric part to `u32` but never bounds the resulting date arithmetic; all failure signals (`LocalResult::None`, chrono overflow) are met with `unwrap()` instead of `Err`.
- Confidence: HIGH (panic mechanics certain; full remote chain requires importing an attacker-signed standard, which is explicitly within module 04's stated threat model of untrusted TOML bundles from peers)
- Testable: YES — Unit-level: `assert!(add_iso8601_duration(Utc::now(), "P300000Y").is_err())` (function is publicly exported, `voucher_manager/mod.rs:18`). Must return Err after fix; currently panics → test fails. Integration variant: import signed standard with hostile duration, process a conforming voucher through `validate_voucher_against_standard`, assert `Err` without panic.

### HYP-04-3: Ingestion never binds privacy-guard seed / receiver anchor to the victim — phantom spendable-looking balances
- Severity: HIGH (local balance integrity violation enabling exchange fraud; NOT global value creation — the affected output is controlled by the attacker or nobody, ledger conservation stays intact)
- CWE: CWE-603 (use of client-supplied authorization without server-side verification analogue: acceptance on claimed plaintext recipient instead of cryptographic ownership proof)
- Target:
  - src/wallet/transaction_handler.rs:240-281 (receive gate accepts on `recipient_id` match and, for anonymous, mere guard *decryptability* — no `hash(next_key_seed) == receiver_ephemeral_pub_hash` check),
  - src/wallet/queries.rs:100-124 and :335-364 (when `rederive_secret_seed` fails, both views fall back to displaying/counting the raw `tx.amount`),
  - contrast src/wallet/transaction_handler.rs:1163-1170 where spending DOES verify the binding.
- Attack (two variants):
  1. Public-mode variant: under a `PrivacyMode::Public` standard, attacker sends a validly-signed transaction naming the victim's DID as `recipient_id`, with `receiver_ephemeral_pub_hash` = anchor of a key the attacker keeps (or garbage). No privacy_guard is required (guard check at `transaction_handler.rs:254` applies only to ANONYMOUS recipients).
  2. Stealth variant: `recipient_id = "anonymous"` with a privacy_guard encrypted to the victim whose `next_key_seed` deliberately does NOT hash to `receiver_ephemeral_pub_hash` — decryption succeeds, so the `owns_voucher` gate passes (`transaction_handler.rs:253-272`).
  3. Chain passes full validation (anchors internally consistent; conservation exact); instance stored `Active`.
  4. On load/view, `rederive_secret_seed` correctly refuses (hash mismatch, `transaction_handler.rs:1168`) → `holder_pub_hash = None` → display heuristic in `list_vouchers` shows `tx.amount` as the victim's current_amount (`queries.rs:116-123`) and `get_total_balance_by_currency` counts it into the aggregated total (`queries.rs:352-362`).
  5. Victim sees real-looking incoming funds (UI, event feed, totals); any spend attempt fails in `rederive_secret_seed`. If the attacker retained the receiver seed they retain unilateral control of that output while the victim believes they were paid — classic fake-payment for physical goods/services in this offline cash model.
- Root cause: Asymmetric enforcement of the P2PKH ownership invariant: spending requires cryptographic anchor proof, ingestion/display accept a plaintext `recipient_id` claim plus (anonymous case) guard decryptability. The cheap missing check is `H(pub(next_key_seed)) == receiver_ephemeral_pub_hash` at ingestion (fail-closed), and/or balance views must render 0/Incomplete when cryptographic matching was attempted and failed with an identity present.
- Confidence: HIGH (mechanism fully traced; severity bounded to victim-local illusion, hence HIGH not CRITICAL)
- Testable: YES — Integration test (test-utils signature bypass): craft voucher with last tx `recipient_id = ANONYMOUS`, `receiver_ephemeral_pub_hash = H(key_random_not_delivered)`, guard encrypted to the victim containing `next_key_seed = bs58(random32')`. Assert secure invariant: after `process_encrypted_transaction_bundle` → `Ok`, `get_total_balance_by_currency(Some(&victim_identity))` contributes 0 (or instance status != Active). On current code the amount IS counted → assertion FAILS (fail-first).

### HYP-04-4: `as i8` truncation of chain depth allows VIP-metadata poisoning via long chains
- Severity: LOW (gossip-priority/metadata manipulation only; no quarantine or value impact)
- CWE: CWE-681 (incorrect conversion between numeric types), CWE-190
- Target: src/wallet/conflict_handler.rs:1273 (`let depth_in_chain = (tx_count - 1 - i) as i8;`), same pattern src/wallet/maintenance.rs:261
- Attack:
  1. Attacker builds a legitimately valid chain with ≥ 130 transactions (strictly increasing timestamps; only the last tx is bound to the 2 h future grace check, `transaction_handler.rs:191-227`).
  2. Victim receives a voucher from that chain. Phase-2 fingerprint processing computes `depth_in_chain` for EVERY historical tx; genesis depth 129..255 wraps modulo 256 into negative i8 territory (129 → -127).
  3. Negative depth classifies the tag as "VIP/toxic" in `fingerprint_metadata` (`conflict_handler.rs:1223-1247` interplay), distorting cleanup priority (`maintenance.rs:126` sorts highest-depth-out), gossip export selection, and VIP symmetry normalization — an attacker-influenced prioritization/poisoning channel, not a safety control bypass.
- Root cause: Unchecked narrowing cast instead of `i8::try_from(...).unwrap_or(i8::MAX)` / clamp; chain length is attacker-influenced and unbounded above 128.
- Confidence: HIGH (cast semantics certain), impact LOW
- Testable: YES — Build a 130-tx voucher instance, run `rebuild_derived_stores` / receive processing, assert genesis-tag `fingerprint_metadata.depth >= 0`. Currently -127 → FAIL-first.

## Gaps

**Instructions that produced NO finding (audited clean):**
- Conservation/rounding (matrix #1, #2): the exact-equality UTXO model plus `checked_add` gates and post-mutation full re-validation leave no rounding or overflow slack in the ledger paths themselves.
- Split/change anchor separation (#4, #5): independently seeded by construction AND validator-enforced; create/rederive HKDF parameters match byte-for-byte.
- Mid-bundle state desynchronization (#7): dual transactional patterns (receive rollback snapshot; send temp-wallet commit) plus best-effort-but-flagged archiving close the classic partial-commit holes.
- Race conditions (#8): core is single-writer by design (`&mut self`, no shared interior mutability); the save-time generation counter is adequate for the intended host integration.

**Uncertain items (documented, not raised as findings):**
- `transaction_handler.rs:802-803` `parse_from_rfc3339(...).unwrap()`: inputs are provably RFC3339-clean for anything that passed ingestion (`parse_rfc3339_instant` validates every t_time) and storage is assumed sealed; only reachable via out-of-band storage tampering. Hardening candidate, not exploitable per threat model.
- `open_secure_container` trial decryption iterates an attacker-sized `recipients` array doing X25519+HKDF+AEAD per entry, and several ingress points deserialize unbounded JSON (`import_foreign_fingerprints`, container parsing): generic resource-exhaustion surface without size caps. Reported as a gap because it is a systemic hardening topic rather than a module-04 logic defect.
- String-comparison time lock `_execute_single_transfer` (`last_tx.t_time > now_str`, line 801) compares RFC3339 strings with potential offset confusion; consequence is limited to lock UX (spend attempt either errors or proceeds into full validation which enforces instant ordering) — no value risk found.
- Concurrent `save()` from two wallet clones can theoretically race the generation check; deemed host-integration misuse, flagged for documentation rather than a code finding.

**Design-intent triage reminder:** All four hypotheses should pass through DESIGN_INTENT_TRIAGE.md before remediation. HYP-04-3 in particular touches the documented "offline forensics keeps counterparty DID locally" design space but concerns a different axis (ownership proof, not metadata retention) — triage should confirm the fallback heuristics in queries.rs are legacy-compat rather than protected behavior.
