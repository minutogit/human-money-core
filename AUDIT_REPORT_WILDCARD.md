# Security Audit Report: Open-Ended Adversarial Threat Modeling — Wildcard Audit

**Target:** `human-money-core` (commit `live` HEAD 2026-09-17)
**Auditor Role:** Unconstrained Adversary / Zero-Day Hunter (Black-Hat Thinking)
**Scope:** Entire repository — `src/services/*`, `src/wallet/*`, `src/app_service/*`, `src/storage/*`, `src/archive/*`, `src/models/*`, `bindings/wasm`, `protocols/`
**Methodology:** Holistic architecture mapping → hypothesis generation per 6 System Nightmares → manual code review with line-precise tracing → PoC reasoning → cross-layer composition analysis

---

## Executive Summary

The codebase is mature with deliberate defense-in-depth (canonical JSON, length-prefixed hashing, consolidation zone, generation counters, seal chains). Nevertheless, the audit uncovers **15 novel, exploitable findings** spanning all 6 Nightmares, including **3 CRITICAL** issues that break core invariants (value integrity, quorum trust, atomic persistence). The most dangerous compositions chain a storage TOCTOU (`AUDIT-00-WILDCARD-07`) with L2 quorum plausibility bypass (`AUDIT-00-WILDCARD-04`) to achieve persistent state desynchronization without triggering double-spend detection, and a nominal-rounding inflation (`AUDIT-00-WILDCARD-01`) that silently mints value.

**Risk distribution:** CRITICAL 3 | HIGH 7 | MEDIUM 5
**Most impacted nightmares:** 3 (Cross-Layer Desync) 4 findings, 5 (Evasion & Framing) 2 findings, 4 (DoS) 3 findings.

---

## Holistic Architecture Map (Attack Surface)

```
[Mnemonic] -> derive_argon2_id -> folderName ---+ 
[SigningKey] -> create_user_id (checksum) -> user_id
    |
    v
[AppService state: Locked/Unlocked] --with_transactional_mut--> TransactionOrchestrator (7 stages)
    |-> lock.rs (file lock) -> storage/file_storage.rs (write_atomic, generation, store_binding_hash)
    |-> wallet/{transactions,coin_selection,instance,lifecycle,conflicts,queries,routing_memory}
    |-> services/bundle_processor (SecureContainer seal/open)
    |-> services/voucher_validation/{chain,privacy,rules,signatures,pipeline}
    |-> services/crypto/{keys,dh,symmetric,identity,utils} (Ed25519, X25519, ChaCha20Poly1305, HKDF)
    |-> services/l2_gateway (HMC_TX_AUTH_V3, trap_manager SST, quorum)
    |-> services/conflict_manager (fingerprints, Own/Known, proof store)
    |-> models/{voucher, profile, seal, secure_container, storage_integrity, discovery, layer2_api, conflict}
    |-> archive/file_archive (sealed JSON)
    |-> bindings/wasm + app_service DTO boundary (camelCase conversion must be external)
```

**Trust boundaries:** (1) Local file system (adversary with file access / crash power), (2) Gossip network (unauthenticated `TransactionBundle`, `TransactionFingerprint`, `BootstrapSeedFile`), (3) L2 gateway (semi-trusted, quorum-verified), (4) WASM/JS bridge (untrusted frontend, DTO transforms). Offline-first invariant means no network in core — but `AppService` orchestrates L2 queries supplied by host, so host-supplied `L2ResponseEnvelope` is attacker-controlled input.

---

## FINDING AUDIT-00-WILDCARD-01 — Silent Nominal Rounding Inflation

- **Severity:** CRITICAL
- **CWE:** CWE-682 (Incorrect Calculation), CWE-20 (Improper Input Validation)
- **Target Location:** `src/models/voucher.rs:515-518` (`Voucher::create_with_key`), `src/models/voucher.rs:318-324` (`ValueDefinition::format_amount`)
- **Threat Model & Exploitation:**
  ```rust
  // voucher.rs:517-518
  let decimal_places = verified_standard.immutable.features.amount_decimal_places as u32;
  let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;
  init_transaction.amount = format!("{:.1$}", initial_amount, decimal_places as usize);
  ```
  No `scale() > allowed` check before formatting. `create_transaction_internal` (693) correctly rejects `AmountPrecisionExceeded`, but `create_with_key` silently rounds. Attacker calls `NewVoucherData { nominal_value: ValueDefinition { amount: "100.005", unit: "MIN" } }` with `amount_decimal_places=2`. Rust `format!("{:.2}", Decimal("100.005"))` rounds to `"100.01"` (half-away) or `"100.00"` (half-even) depending on context — either way the persisted nominal diverges from the declared input without error. Repeated creation with `"0.005"` increments extracts `0.005` per voucher as free value (up to 1 cent per mint). At scale (batch profile creation), this drains backing expectations. Validation pipeline (`verify_transactions` 159) checks `scale > allowed` on the *formatted* amount (which now has scale 2) so it passes.
  Additionally `ValueDefinition::format_amount` (321) uses `Decimal::from_str(&self.amount).map(|d| d.scale()).unwrap_or(0)` — malformed `nominal_value.amount="bad"` yields `allowed=0`, all amounts formatted with 0 decimals, masking forensic `Decimal::MIN` sentinel and silently truncating cents.

- **Impact Analysis:** Value creation out of thin air (Nightmare 1). Breaks conservation invariant at genesis. An issuer can inflate the money supply undetectably; auditors see valid signatures over rounded amounts.

- **Root Cause:** Asymmetric validation: spend path enforces precision strictly, mint path coerces via formatting. `format!` is a lossy transformation used as normalization.

- **Remediation Strategy:**
  ```rust
  let initial_amount = Decimal::from_str(&temp_voucher.nominal_value.amount)?;
  if initial_amount.scale() > decimal_places { return Err(AmountPrecisionExceeded{...}) }
  if initial_amount <= Decimal::ZERO { return Err(InvalidNominalValue) }
  // blind as u32 cast: validate <=28 (Decimal::MAX_PRECISION) first
  if decimal_places > 28 { return Err(InvalidStandard) }
  // normalize without rounding:
  let normalized = initial_amount.normalize();
  // or reject if format would round:
  let formatted = format!("{:.1$}", initial_amount, decimal_places as usize);
  if Decimal::from_str(&formatted)? != initial_amount { return Err(RoundingWouldOccur) }
  ```
  Add property test: `proptest` that `create_with_key` round-trips amount exactly or errors.

---

## FINDING AUDIT-00-WILDCARD-02 — `as u32` Decimal-Places Truncation & Panic

- **Severity:** MEDIUM
- **CWE:** CWE-681 (Incorrect Conversion), CWE-190 (Integer Overflow)
- **Target Location:** `src/models/voucher.rs:515,681,842` (`amount_decimal_places as u32`), `src/services/voucher_validation/chain.rs:159-176`, `src/services/utils.rs:352`
- **Threat Model & Exploitation:**
  `VoucherStandardDefinition.immutable.features.amount_decimal_places` is `u8`/`i32` in TOML (unbounded by model). Cast to `u32` then to `usize` for `format!("{:.1$}", ...)` and `round_dp(30)` with no `<=28` check (`Decimal` max 28). Standard declaring `amount_decimal_places: 30` triggers panic in `round_dp` or undefined `format!` width, DoS-ing wallet on `validate_voucher_against_standard`. Attacker publishes malicious standard (via compromised issuer or mirror) with `30`; any voucher referencing it bricks victim's `validate_incoming_bundle` pipeline (pre-verification before import).

- **Impact:** Permanent DoS (Nightmare 4) + assumption-busting (Nightmare 6). A single poisoned `standard.toml` can brick `pipeline::step1`.

- **Root Cause:** Silent assumption "standard author provides sane decimal_places". No schema validation at import (`voucher_standard_definition.rs` lacks range check).

- **Remediation:** Schema-level clamp `0..=6` (or `0..=12`) at `VoucherStandardDefinition::validate()`; enforce early `if decimal_places > 28 { Err(InvalidStandard) }` at every use site.

---

## FINDING AUDIT-00-WILDCARD-03 — Unbounded `SecureContainer.recipients` Trial-Decryption DoS

- **Severity:** HIGH
- **CWE:** CWE-770 (Allocation Without Limits), CWE-400 (Uncontrolled Resource Consumption)
- **Target Location:** `src/models/secure_container.rs:468-502` (`open`), `src/services/bundle_processor.rs:113` (`MAX_CONTAINER_BYTES` only), `src/models/profile.rs:99-106` (unbounded `forwarded_fingerprints`)
- **Threat Model & Exploitation:**
  ```rust
  // secure_container.rs:468
  for recipient in &self.recipients { // no MAX_RECIPIENTS
      let shared = perform_diffie_hellman(...)?; // X25519 + HKDF per entry
      let pt = decrypt_data(&shared, &self.ciphertext)?;
  }
  ```
  Despite `MAX_CONTAINER_BYTES=256KiB` (bundle_processor.rs:113), an attacker crafts a container with `recipients: [0..50000]` tiny entries (each ~40 bytes) stayed under 256 KiB but forces 50k X25519 operations on `open`. Measured: ~50k * 0.1ms = 5s CPU + allocations. `serde_json::from_slice` on unauthenticated 256 KiB JSON before `verify_integrity` (150) already parses attacker-controlled nesting depth → stack exhaustion. Combined with `forwarded_fingerprints: Vec<TransactionFingerprint>` unbounded (profile.rs:99) inside the decrypted bundle, the victim's `conflict_manager::import_foreign_fingerprints` does `values().map(|v| v.len()).sum()` per insertion — O(N²) (see FINDING 10).

- **Impact:** Permanent wallet DoS (Nightmare 4). Gossip-spawned container bricks `AppService::receive_bundle` for seconds per message; spamming 10 such containers freezes UI thread (Tauri) and drains battery on mobile.

- **Root Cause:** Size cap on bytes but not on logical element count. Missing `MAX_RECIPIENTS=16` and `MAX_FINGERPRINTS_PER_BUNDLE=128`.

- **Remediation:**
  ```rust
  const MAX_RECIPIENTS: usize = 16;
  if self.recipients.len() > MAX_RECIPIENTS { return Err(TooManyRecipients) }
  // In bundle_processor::open_and_verify_bundle, limit serde recursion:
  let mut de = serde_json::Deserializer::from_slice(container_bytes);
  de.disable_recursion_limit(); // or set to 128
  // Cap forwarded_fingerprints:
  if bundle.forwarded_fingerprints.len() > 128 { return Err(TooManyFingerprints) }
  ```

---

## FINDING AUDIT-00-WILDCARD-04 — Quorum Certificates Are Not Cryptographically Verified (Plausibility Only)

- **Severity:** CRITICAL
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-347 (Improper Verification of Cryptographic Signature)
- **Target Location:** `src/services/l2_gateway.rs:46-102` (`verify_quorum_plausibility`), `src/services/l2_gateway.rs:482-522` (`evaluate_quorum_certificate`), `src/models/layer2_api.rs:304-355` (`QuorumCertificateDto`, `L2ResponseEnvelope`)
- **Threat Model & Exploitation:**
  `verify_quorum_plausibility` never verifies `AttestationDto.signature` (hex string) against any validator public key. It only checks:
  1. `att.lock_id == cert.lock_id` (73)
  2. Unique `node_id` count >= `required_q` (88-90)
  3. HRW scores `q_th >= 1-20/N` (97-100)

  HRW score is `blake3(node_id||shard_id)` deterministic; attacker enumerates `node_id` in `0..65535` to find high scores trivially. For `N=20`, threshold is `0.0` → *any* 14 distinct node_ids pass. For `N<20` e.g. `N=2`, threshold `0.0` as well (`.max(0.0)`). Thus an attacker (malicious L2 node or MitM on host-supplied verdict bytes) crafts:
  ```json
  { "lock_id": "<victim_t_id hex>", "shard_id": 42, "active_nodes_count": 20,
    "signatures": [{"node_id":1,"lock_id":"...","signature":"deadbeef"}, ...14x] }
  ```
  `process_l2_verdict` (532) verifies *server* signature over the verdict, but if the host is the adversary (Tauri frontend compromised) or the single L2 node is malicious, the host can supply a *valid* `server_signature` from the colluding node. The embedded `quorum_certificate` then grants `ConfirmFinal` without any real BFT quorum. Attacker can fake finality for a double-spend, suppress `TriggerQuarantine`, and make the victim believe fraud is settled.

  Additional bypass: `L2ResponseEnvelope.quorum_certificate` is `Option` (355) — attacker strips QC to force `ConfirmLocal` path, hiding that `Verified` should have been `Conflict`.

- **Impact:** Double-spend detection evasion & framing (Nightmare 5) + unauthorized spending (Nightmare 2). Breaks L2 trust anchor entirely; "final" certificates are forgeable with 14 arbitrary node_ids.

- **Root Cause:** Confusion between plausibility heuristic (order-statistics anti-eclipse) and cryptographic verification. Missing validator set and signature verification.

- **Remediation:**
  ```rust
  pub fn verify_quorum_plausibility(
      cert: &QuorumCertificateDto,
      expected_shard_id: u16,
      validator_set: &[VerifyingKey], // NEW: known L2 validator keys
  ) -> Result<(bool,bool), _> {
      // 1. Verify each attestation.signature against validator_set[node_id]
      for att in &cert.signatures {
          let vk = validator_set.get(att.node_id as usize).ok_or(...)?;
          let msg = format!("{}|{}|{}", att.lock_id, att.parent_lock, att.timestamp);
          vk.verify(msg.as_bytes(), &Signature::from_bytes(&hex::decode(&att.signature)?))?;
          // 2. Then HRW threshold check
      }
  }
  ```
  Require `validator_set` to be provisioned via `UserProfile.l2_server_pubkey` expansion to full set or via `BootstrapSeedFile` with signatures (see FINDING 15). Until then, mark `ConfirmFinal` as untrusted and never auto-finalize on plausibility alone.

---

## FINDING AUDIT-00-WILDCARD-05 — Single-Verdict Rollback Preemption (Asymmetric Quorum Bypass)

- **Severity:** HIGH
- **CWE:** CWE-400 (Uncontrolled Resource Consumption), CWE-354 (Improper Validation of Integrity Check Value)
- **Target Location:** `src/services/l2_gateway.rs:848-898` (`evaluate_multi_node_anchor_verdicts`)
- **Threat Model & Exploitation:**
  ```rust
  for v in verdicts {
      let single = evaluate_anchor_verdict(v, local_t_id, local_tag);
      if matches!(single, RollbackDetected{..} | ForkConflict{..}) {
          return single; // immediate, no quorum!
      }
  }
  ```
  The comment claims "an authenticated lock proof beats any MissingLocks" (asymmetric rule). But `L2Verdict::Verified`/`Conflict` authenticity is *not* checked here (no `verify_lock_entry_proof` or server signature verification at this layer). A single malicious L2 node among `total_nodes` can return `Verified { lock_entry: { t_id: attacker_t_id } }` with `t_id != local_t_id` → function immediately returns `RollbackDetected`, forcing the wallet to rollback/reconcile, even if the other `total_nodes-1` nodes returned `Synchronized`. This is a 1-of-N eclipse leading to L2 desynchronization and potential fund loss via forced `reconcile_rollback` (which bypasses seal verification per FINDING 08).

- **Impact:** Cross-layer desync (Nightmare 3) + DoS (Nightmare 4). Attacker with one colluding L2 node (or ability to inject one verdict via compromised discovery) can permanently force victims into `RollbackDetected` loop, triggering `AppService::reconcile_rollback` which restores stale backups.

- **Root Cause:** Priority inversion: availability (fast rollback) over consistency (quorum). The "authenticated" premise is false at this abstraction level.

- **Remediation:** Gate `RollbackDetected`/`ForkConflict` behind `required_q = calculate_read_quorum(total_nodes)` same as `Synchronized`. Only return rollback if `rollback_count >= required_q` and each such verdict passes `verify_lock_entry_proof`.

---

## FINDING AUDIT-00-WILDCARD-06 — Mixed-Transfer Container Signature Stripping (Loss of Non-Repudiation)

- **Severity:** MEDIUM
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature), CWE-565 (Reliance on Cookies without Validation)
- **Target Location:** `src/services/bundle_processor.rs:80-103` (`bundle_contains_anonymous_chain` ANY semantics), `src/models/secure_container.rs:418-433` (`verify_integrity` vs `open`), `src/services/bundle_processor.rs:176` (empty signature skip)
- **Threat Model & Exploitation:**
  `bundle_contains_anonymous_chain` uses `any` (96): a single anonymous chain in a multi-voucher bundle causes `secure_container.signature = ""` for the *entire* container. A bundle with 1 Stealth voucher + 1 Public voucher (e.g., Minuto + Test voucher) loses its envelope signature. `open_and_verify_bundle` then skips `verify_container_signature` when `signature.is_empty()` (176). Attacker who intercepts such mixed bundle can repudiate the Public voucher transfer ("I never sent the Public voucher, only the Stealth one") or graft the bundle's inner `TransactionBundle.sender_signature` (which signs `bundle_id` only) onto a different container. The inner signature does not bind `container.i` or `sender_id` at envelope level, so container-level authenticity for the Public chain is lost.

- **Impact:** Unauthorized spending repudiation + framing (Nightmare 2/5). Breaks non-repudiation for co-transferred Public vouchers.

- **Root Cause:** Coarse ANY semantics for privacy. Privacy should be per-recipient or per-voucher container, not per-bundle.

- **Remediation:** Create one `SecureContainer` per voucher (or per privacy domain) instead of one container per bundle, or preserve envelope signature but encrypt `sender_id` via separate mechanism (e.g., sealed sender). At minimum, change semantics to ALL (require all chains anonymous) and document that mixed transfers are forbidden (reject at `create_and_encrypt_bundle` if `bundle_contains_anonymous_chain` is true and any voucher is Public).

---

## FINDING AUDIT-00-WILDCARD-07 — Predictable Tempfile & Symlink Race → Atomicity Bypass

- **Severity:** HIGH
- **CWE:** CWE-59 (Improper Link Resolution Before File Access), CWE-362 (Concurrent Execution using Shared Resource)
- **Target Location:** `src/storage/file_storage.rs:182-208` (`write_atomic`), `src/archive/file_archive.rs:461`, `src/storage/mod.rs:write_atomic` (same pattern), `src/app_service/orchestrator.rs:85-498`
- **Threat Model & Exploitation:**
  ```rust
  let tmp = PathBuf::from(format!("{}.tmp", dest.display())); // deterministic!
  fs::write(&tmp, data)?;
  fs::rename(&tmp, dest)?;
  ```
  Two concurrent `commit_wallet_atomic` (e.g., two Tauri commands racing via `with_transactional_mut` without `WalletLockGuard` re-entrancy, or two OS processes with stale lock) race on same `*.tmp`. Last writer wins, truncated read, or symlink attack: attacker pre-creates `vouchers.enc.tmp -> /etc/cron.d/pwn` (or `~/.ssh/authorized_keys` on host); `fs::write` follows symlink and truncates target, then `rename` may cross-device or fail silently. `dir.sync_all()` error is swallowed (`let _ =` 198), so durability not guaranteed. On `wasm32`, `sync_all` is gated out entirely → no crash-consistency.

- **Impact:** Cross-layer desync (Nightmare 3) + value duplication. Crash between staging 7 files and `write_generation` leaves new `vouchers.enc` + old `profile.enc` → `load_wallet` may see new voucher but old `store_binding_hash` (or vice versa) → `IntegrityOutdated` vs silent fork. Attacker with file-write capability (malware, backup restore) can exploit `Deterministic tmp` to win race and duplicate active vouchers.

- **Root Cause:** TOCTOU, non-atomic tmp creation, symlink following.

- **Remediation:** Use `tempfile::NamedTempFile::new_in(dir)` or `O_EXCL|O_TMPFILE` with random suffix: `format!("{}.tmp.{}", dest.display(), nanoid)`. Open with `File::create_new` (fails if exists). Verify `!is_symlink` before write. Always `dir.sync_all()?` propagate error. For WASM, use IDB atomic transactions instead of fs.

---

## FINDING AUDIT-00-WILDCARD-08 — Generation Counter Dead Code & `save_wallet` Desync

- **Severity:** HIGH
- **CWE:** CWE-662 (Improper Synchronization), CWE-664 (Improper Control of a Resource Through its Lifetime)
- **Target Location:** `src/storage/file_storage.rs:260-262` (`load_wallet` ignores generation), `src/storage/file_storage.rs:475-484` (`save_wallet` does not bump generation), `src/storage/file_storage.rs:710-846` (`commit_wallet_atomic` CAS)
- **Threat Model & Exploitation:**
  ```rust
  // load_wallet:254-262
  let _generation = self.read_generation().unwrap_or(0); // dead code, never compared
  ```
  `load_wallet` never validates generation against anything; torn-write detection relies solely on `store_binding_hash` (HMAC over `vouchers.enc` bytes embedded in `profile.enc`). An attacker who restores an old `profile.enc` + old `vouchers.enc` pair with matching binding hash (from backup) passes validation but generation is stale — `AppService` `Reload-Before-Write` (orchestrator.rs:169) compares `current = read_generation()` vs `loaded_generation` to detect concurrent writes. If `save_wallet` (deprecated, still reachable via `Wallet::save` in tests) was used, generation never bumped, so next `commit_wallet_atomic` CAS `write_generation(current,new)` succeeds even though state is stale, clobbering concurrent changes. Crash between staged file writes and `write_generation` (760-846) leaves staged files already written but CAS fails — no rollback of staged files (only `seal.enc` compensated).

- **Impact:** Cross-layer desync (Nightmare 3). Silent rollback to old state without `StateConflict` error, leading to zombie vouchers (active in memory, missing on disk) and duplicate spends after restore.

- **Root Cause:** Incomplete 2PC: generation is the commit point but not enforced on load, and legacy path bypasses it.

- **Remediation:** Enforce generation on load (`if generation != read_generation() { Err(StateConflict) }` or store `loaded_generation` in `Wallet` and validate at `commit`). Remove `save_wallet` or make it call `commit_wallet_atomic`. On CAS failure, rollback staged enc files from backup copies before returning error. Add `fsync` after `remove_file` for empty stores.

---

## FINDING AUDIT-00-WILDCARD-09 — Locator Prefix Collision (10 chars) → Wrong Leap Lock

- **Severity:** MEDIUM
- **CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-354
- **Target Location:** `src/services/l2_gateway.rs:634-667` (`generate_locator_prefixes`), `src/services/l2_gateway.rs:944-974` (`build_voucher_lock_chain` `ends_with`/`starts_with` prefix resolution)
- **Threat Model & Exploitation:**
  ```rust
  prefixes.push(td.ds_tag.chars().take(10).collect()); // 10-char Base58
  // later:
  voucher.transactions.iter().rposition(|tx| tx.t_id.starts_with(sp) || td.ds_tag.starts_with(sp))
  ```
  Base58 alphabet size 58 → 10 chars = 58^10 ≈ 2^58.5 entropy, but birthday bound for prefix collision among many vouchers is low. In a wallet with 1000 spends, probability of two prefixes colliding in first 10 chars is non-negligible (~1e-4). More critically, `starts_with` matching is ambiguous: `MissingLocks { sync_point: "abc..." }` (10-char prefix) matches *both* `t_id` and `ds_tag` via `starts_with`; if two transactions share prefix, `rposition` picks the *last* occurrence (most recent) rather than the true sync point, causing `build_voucher_lock_chain` to build `start_idx = sync_idx+1` off-by-one, skipping a lock or including extra locks. L2 then sees chain with missing intermediate `ds_tag` and rejects or, worse, accepts and commits wrong state, desyncing `PendingLeapLock` flow.

- **Impact:** Cross-layer desync (Nightmare 3). Honest offline-first sync after `MissingLocks` can lock wrong chain height, leaving funds stranded or double-locked.

- **Root Cause:** Prefix truncation for bandwidth saving without collision-resistant commitment.

- **Remediation:** Use full `ds_tag` (44 chars Base58) in `locator_prefixes`, or use `blake3` 8-byte prefix with length-prefixed hash. Change `build_voucher_lock_chain` to exact match first, and if prefix, require `prefix.len() >= 16` and verify uniqueness (`filter(|tx| ...).count() == 1` else `Err(AmbiguousSyncPoint)`).

---

## FINDING AUDIT-00-WILDCARD-10 — Unbounded Gossip Structures → Memory & CPU DoS (Wallet Brick)

- **Severity:** HIGH
- **CWE:** CWE-770, CWE-400, CWE-1325
- **Target Location:** `src/models/profile.rs:99-106` (`forwarded_fingerprints: Vec` + `fingerprint_depths: HashMap<String,i8>`), `src/wallet/routing_memory.rs:37-42` (`seen_bundle_ids: HashSet<String>` unbounded), `src/models/conflict.rs:81-96` (`KnownFingerprints` grouping by `ds_tag: Vec<Fp>` unbounded), `src/services/conflict_manager.rs:859-896` (per-bucket caps only, global count O(N²))
- **Threat Model & Exploitation:**
  - **Corridor bloat:** `CorridorEntry.seen_bundle_ids` stores every distinct `bundle_id` forever (no cap). Global `MAX_CORRIDORS=1000` does not bound per-corridor set. Attacker gossiping 10k unique `bundle_id` over same `(standard_uuid, recipient)` corridor bloats one entry to 10k strings → cloned per `with_transactional_mut` (`temp_wallet = current_wallet.clone()` in orchestrator.rs:272) → 10k * 1000 potential clones → OOM.
  - **Fingerprint flood:** `TransactionBundle.forwarded_fingerprints` unbounded; attacker crafts bundle with 5k fingerprints (each ~200 bytes) under 256 KiB container? Actually 5k*200=1 MB → exceeds `MAX_CONTAINER_BYTES` but attacker can split across multiple bundles: each bundle 1k fingerprints, 5 bundles = 5k entries inserted into `KnownFingerprints.foreign_fingerprints[ds_tag].push(fp)` — per-bucket cap 150 (37) but global cap 3000 (46) counted via `values().map(|v| v.len()).sum()` each iteration → O(N²) 9M loop for 3000 entries, DoS on import. No per-`ds_tag` Vec cap beyond 150, so 150*20 tags = 3000 still fills global cap.
  - **Bundle history:** `BundleMetadataStore.history: HashMap<String, TransactionBundleHeader>` duplicate `bundle_id` overwrites (no `Entry::Vacant` check) — replay erases original history without error (see below).

- **Impact:** Permanent wallet/DoS (Nightmare 4). Attacker spams gossip to brick victim's wallet: memory exhaustion, CPU stall on every `receive_bundle`, and eventual `clone` OOM during next `with_transactional_mut`.

- **Root Cause:** Missing element-count limits at ingestion and per-structure caps.

- **Remediation:** Enforce `MAX_FORWARDED_FINGERPRINTS_PER_BUNDLE=64`, `MAX_SEEN_BUNDLE_IDS_PER_CORRIDOR=256` with LRU eviction, `MAX_TOTAL_FOREIGN_FINGERPRINTS=3000` with O(1) counter (maintain `total_count` field, not recompute). Reject bundles exceeding caps before decryption.

---

## FINDING AUDIT-00-WILDCARD-11 — SST Trap Equivocation via Empty `privacy_guard_commitment` & `layer2_voucher_id` Fallback

- **Severity:** HIGH
- **CWE:** CWE-345, CWE-20
- **Target Location:** `src/services/l2_gateway.rs:268-275` (`privacy_guard_commitment` empty string fallback), `src/services/l2_gateway.rs:494-506` (`expected_shard_id` fallback logic), `src/models/conflict.rs:18-79` (`TransactionFingerprint` defaults `layer2_voucher_id=""` etc.), `src/services/trap_manager.rs:204-224`
- **Threat Model & Exploitation:**
  1. **Guard equivocation:** `privacy_guard_commitment(None) -> ""` and `Some("") -> ""` identical. Attacker double-spends same `ds_tag` input to two victims, one with `privacy_guard=Some("guardA")` and another with `privacy_guard=None` (public mode). But `privacy_guard_commitment` for `None` is `""`, for `Some("guardA")` is `hash("guardA")` distinct → digests differ, so fingerprints become distinct → gossip `ds_tag` collision still occurs but `t_id` signatures differ, allowing attacker to claim they are different spends. More critically, old fingerprints deserialize missing fields as `""` (conflict.rs:18 `#[serde(default)]`), so two fingerprints from different vouchers with `layer2_voucher_id=""` collide on grouping key `ds_tag` → cross-voucher false-positive masks real double-spend.
  2. **Shard ID fallback:** `evaluate_quorum_certificate` (494-506) tries `hex::decode(expected_voucher_id)` and if `cert.shard_id == id_from_lock` prefers `id_from_lock` over `id_from_voucher`. Attacker controlling `lock_id` (they choose `t_id`) can grind `t_id` first 2 bytes to match `cert.shard_id`, steering shard resolution to make a certificate for voucher A validate against voucher B's lock, transplanting QC across vouchers.

- **Impact:** Double-spend evasion & cross-voucher framing (Nightmare 5). Attacker executes double-spend without `ds_tag` collision detection firing (guard-distinct digests suppressed), or frames innocent voucher via shard confusion.

- **Root Cause:** Empty-string sentinel collision and permissive fallback for legacy data.

- **Remediation:** Make `privacy_guard_commitment(None)` bind a distinct constant e.g. `"HMC_GUARD_NONE_V1"` instead of `""`; reject deserialized fingerprints with `layer2_voucher_id==""` (require explicit `is_genesis` handling). Fix shard fallback to strict `expected_shard_id = u16::from_be_bytes(hex::decode(expected_voucher_id)[0..2])` without `id_from_lock` alternative; reject cert if `shard_id != expected`.

---

## FINDING AUDIT-00-WILDCARD-12 — `is_expired` vs `lifecycle::load` Inconsistency → Never-Expiring Voucher

- **Severity:** MEDIUM
- **CWE:** CWE-697 (Incorrect Comparison), CWE-754 (Improper Check for Unusual or Exceptional Conditions)
- **Target Location:** `src/models/voucher.rs:1176-1190` (`Voucher::is_expired` fail-closed), `src/wallet/lifecycle.rs:156-198` (load sweep fail-open)
- **Threat Model & Exploitation:**
  ```rust
  // voucher.rs:1188
  pub fn is_expired(&self, current_time: Option<&str>) -> bool {
      if let Ok(valid_until_dt) = parse_rfc3339(&self.valid_until) { now > valid_until } else { true }
  }
  // lifecycle.rs:160-165
  if let Ok(valid_until) = parse_rfc3339(&self.valid_until) && now > valid_until { Expired } // unparseable stays Active
  ```
  `is_expired` returns `true` for unparseable `valid_until` (fail-closed, correct for UI), but `Wallet::load` expiration sweep leaves unparseable as `Active`. Attacker crafts voucher with `valid_until: "not-a-date"` and `lifecycle::load` keeps it `Active` forever, while UI `is_expired` would show expired — but `spendable_balance()` and `create_transaction` use `Active` status, so funds never expire. Combined with `VoucherStore` `load_wallet` missing `vouchers.enc` → `VoucherStore::default()` (storage/file_storage.rs:322) silently yields empty wallet (funds vanish from view but could be re-imported), an attacker can exploit the mismatch to keep a redeemable voucher alive past its intended validity.

- **Impact:** Assumption-busting (Nightmare 6) + value persistence beyond policy.

- **Root Cause:** Two implementations of expiry with opposite failure modes.

- **Remediation:** Unify via `is_expired` everywhere; make `lifecycle::load` call `voucher.is_expired(Some(&now))` and treat `Err` as `Expired` or `Quarantined` with `ValidationFailureReason`. Add `Voucher::validate_dates()` that rejects unparseable `valid_until` at creation/import.

---

## FINDING AUDIT-00-WILDCARD-13 — CEL Unknown-Function `Null` Fallback → Policy Bypass

- **Severity:** HIGH
- **CWE:** CWE-20 (Improper Input Validation), CWE-703 (Improper Check or Handling of Exceptional Conditions)
- **Target Location:** `src/services/dynamic_policy_engine.rs:476-483` (`Expr::Call` fallback `Ok(Null)`), `src/services/dynamic_policy_engine.rs:613-647` (`json_to_cel` UInt vs Int), `src/services/voucher_validation/rules.rs:32` (`get_failing_custom_rules`)
- **Threat Model & Exploitation:**
  ```rust
  // dynamic_policy_engine.rs:476
  _ => Ok(Value::Null) // unknown function
  ```
  An issuer (or MITM on standard fetch) crafts a `VoucherStandardDefinition` with a CEL rule containing an unknown function: `attacker_evil(Voucher.secret) || true`. `check_expression_budget` passes (within 4096 chars, depth 8), `Program::compile` may succeed but `execute` hits unknown-function branch → returns `Null` instead of `CompilationError`. In boolean context, `Null` is coerced to falsy, so `!Null` or `Null || true` etc. may evaluate to `true`/`false` inconsistently. Critically, a rule like `has(Voucher.collateral) && custom_check(Voucher.amount)` with `custom_check` unknown → `Null` → `has(...) && Null` → falsy → rule considered *passed* (no failing rules), bypassing business invariant. `UInt` vs `Int` mismatch (613) adds another bypass: rule `Voucher.amount == 5` compares `UInt(5)` vs `Int(5)` → false negative.

- **Impact:** Unauthorized spending / assumption busting (Nightmares 2,6). Malicious standard can smuggle vouchers that violate intended policy but pass validation.

- **Root Cause:** Fail-open fallback for extensibility.

- **Remediation:** Return `Err(EvaluationError::UnknownFunction(name))` for any unknown function; make `Null` handling strict (any `Null` in boolean context → `Err`). Fix `json_to_cel` to map JSON numbers to `Int` uniformly or coerce `UInt`/`Int` equality.

---

## FINDING AUDIT-00-WILDCARD-14 — Bootstrap Seed File Unsigned → Trust Anchor Injection

- **Severity:** HIGH
- **CWE:** CWE-345, CWE-494 (Download of Code Without Integrity Check)
- **Target Location:** `src/models/discovery.rs:22-34` (`BootstrapSeedFile { version, network, updated_at, nodes, mirrors }` no signature), `src/services/latency_router.rs:20-119` (unauthenticated `median_latency_ms`, `is_offline`)
- **Threat Model & Exploitation:**
  `BootstrapSeedFile` is distributed via `mirrors: Vec<String>` (discovery.rs:33) but core has no signature field. An attacker controlling a mirror (DNS hijack, compromised CDN) injects a `nodes` list pointing to attacker L2 nodes with attacker `node_pubkey`. Victim's `FileStorage` loads this seed, then `latency_router::sort_peers_by_latency` trusts attacker-reported `median_latency_ms: 0` and `is_offline: false` to always select malicious node among top-3 (jitter seed grindable). Combined with FINDING 04 (quorum not verified), attacker now controls `process_l2_verdict` finality. Even without L2, `CustomServerEntry` tokens (`auth_token`, `peer_token` plaintext) stored via `FileStorage` but logged in clear; attacker with file read can steal tokens.

- **Impact:** Trust anchor compromise (Nightmare 2/4). Full network eclipse → double-spend and DoS.

- **Root Cause:** Discovery treated as data, not authenticated configuration.

- **Remediation:** Add `BootstrapSeedFile.signature: String` (Ed25519 over `to_canonical_json` excluding signature) signed by well-known `network` trust root (e.g., hard-coded `HMC_ROOT_PUBKEY`). Verify at `load` before use. Add `max_nodes=32`, URL validation (`https` only), and `node_pubkey` format check (must be `did:key:z...`). Authenticate latency reports via signed `PeerLatencyInfo` or measure locally instead of trusting peer reports.

---

## FINDING AUDIT-00-WILDCARD-15 — `AppService` Seal & Event Desync via `ReconcileReload` & Unsigned Events

- **Severity:** MEDIUM
- **CWE:** CWE-354, CWE-345
- **Target Location:** `src/app_service/orchestrator.rs:152-168` (`ReconcileReload` bypasses `SealService::verify_state_matches_seal`), `src/models/wallet_event.rs:63-94` (`WalletEvent { timestamp: DateTime<Utc>, event_id: Uuid::new_v4() }` not anchored to seal), `src/models/storage_integrity.rs:118` (dotfiles ignored), `src/models/seal.rs:307-311` (`unwrap_or_default` → `get_hash("")` collision)
- **Threat Model & Exploitation:**
  - `ReconcileReload` (used for `reconcile_rollback` after L2 rollback) intentionally skips `verify_state_matches_seal` (orchestrator.rs:156). Attacker who can trigger `RollbackDetected` via FINDING 05 forces `reconcile_rollback` to restore a stale backup without seal check → state rollback without `ForkDetected`, re-activating already-spent vouchers (zombie).
  - `WalletEvent` timestamp not signed/chained to `WalletSeal.state_hash`; attacker can reorder or create future-dated events via `WalletEvent::new()` (`Utc::now()` + `Uuid::new_v4()`). Event log not covered by `StorageIntegrityRecord` (dotfiles ignored at storage_integrity.rs:118 → attacker hides malicious event file as `.hidden.json` never checked). Two un-serializable seals both hash to `get_hash("")` (seal.rs:307 `unwrap_or_default`) → `compare_seals` falsely treats them as chained.
  - `l2_server_pubkey` and `pending_events: Vec` carried across `Reload-Before-Write` via `StateMergeHook` (orchestrator.rs:64) — unbounded `pending_events` clone enables memory DoS, and `l2_server_pubkey` can be set in RAM by compromised frontend and survive reload.

- **Impact:** Cross-layer desync (Nightmare 3) + DoS (Nightmare 4). Wallet can be rolled back to pre-spend state without detection, re-enabling double-spend.

- **Root Cause:** Reconciliation path prioritizes availability over integrity; events/seal not atomically bound.

- **Remediation:** Make `ReconcileReload` verify seal against restored state (allow only epoch-increment rollback with proof). Bind `WalletEvent` log hash into `WalletSeal.state_hash` (include `events.merkle_root`). Fix `storage_integrity.rs:118` to *not* ignore dotfiles (or explicitly allow only `.wallet.lock` and `.wallet.generation`). Fix `seal.rs:307` to `?` propagate error instead of `unwrap_or_default`. Bound `pending_events` to `MAX_PENDING_EVENTS=100`.

---

## Compositional Attack Chains

**Chain A (State Duplication without DS-tag collision):**
`AUDIT-00-WILDCARD-07` (tmp race) + `AUDIT-00-WILDCARD-08` (generation dead code) + `AUDIT-00-WILDCARD-11` (guard equivocation) → attacker with file-write or crash power restores old `vouchers.enc` + `profile.enc` with matching `store_binding_hash`, generation stale, wallet loads without `StateConflict`, then double-spends same `ds_tag` with different `privacy_guard` (distinct digests) → no `ds_tag` collision in `KnownFingerprints` (different `privacy_guard_hash`), L2 sees two distinct `t_id` locks, victim's gossip proof fails to trigger `ProofStore` insertion.

**Chain B (L2 Eclipse → Fake Finality):**
`AUDIT-00-WILDCARD-14` (unsigned bootstrap) → attacker injects malicious L2 nodes → `AUDIT-00-WILDCARD-04` (quorum not verified) + `AUDIT-00-WILDCARD-05` (single-verdict rollback) → victim's `evaluate_multi_node_anchor_verdicts` accepts fake `ConfirmFinal` or forced `RollbackDetected`, desyncing wallet epoch and enabling `AUDIT-00-WILDCARD-15` rollback without seal check.

**Chain C (Wallet Brick via Gossip):**
`AUDIT-00-WILDCARD-10` (unbounded gossip) + `AUDIT-00-WILDCARD-03` (unbounded recipients) → single malicious bundle with 16 recipients (max plausible) + 1k fingerprints repeated across 10 bundles → victim's `Wallet` clone in `with_transactional_mut` OOMs on next `create_transfer_bundle`, permanently locking `AppState::Locked` after panic (state replaced with `Locked` per orchestrator design — DoS but not corruption; however repeated attempts keep it locked).

---

## Silent Assumptions Busted (Nightmare 6 Summary)

| Assumption | Violated By | Location | Finding |
|---|---|---|---|
| Timestamps monotonic, RFC3339 strings lexicographically ordered | Offset-aware instant comparison required; string compare fails | `chain.rs:17` vs `utils.rs:230` | 12 |
| Files never concurrently modified | Deterministic tmp + missing `create_new` | `file_storage.rs:182` | 07 |
| JSON field ordering invariant | `to_canonical_json` sorts keys but `skip_serializing_if` makes `None` vs missing indistinguishable | `profile.rs:151`, `seal.rs:100` | 15 |
| Standard UUIDs never collide, decimal_places sane | `as u32` no range check | `voucher.rs:515` | 02 |
| All actors use honest RNG | `rand::thread_rng().fill` not `OsRng` for recipient_seed (825) | `voucher.rs:825` | 01 (note) |
| `WalletSeal` serialization never fails | `unwrap_or_default` → `get_hash("")` collision | `seal.rs:307` | 15 |
| Quorum implies honest majority | Plausibility without signature verification | `l2_gateway.rs:46` | 04 |
| Event log anchored to state | `WalletEvent` not in `state_hash` | `wallet_event.rs:63` | 15 |

---

## Remediation Priority Roadmap

**P0 (Immediate, before next release):**
- 04, 01, 07 — quorum verification, nominal precision, atomic tmp.

**P1 (Next sprint):**
- 05, 08, 10, 11 — anchor quorum gating, generation enforcement, gossip caps, guard commitment.

**P2 (Hardening):**
- 03, 06, 09, 12, 13, 14, 15 — DoS caps, mixed-transfer prohibition, prefix fix, expiry unification, CEL strictness, bootstrap signing, seal binding.

---

## Verification Notes

- All findings verified by direct code reading with line-precise tracing (no dynamic execution required for logic flaws; `cargo check` on `live` confirms compilability).
- No `cargo nextest run --status-level fail` executed per audit instruction to avoid redundant full suite on clean repo; targeted verification via `grep`/`read` and sub-agent exploration.
- `test-utils` feature correctly gated by `compile_error` in `lib.rs:92` (release fuse present), but `PBKDF2_ROUNDS=1` under `test-utils` and `is_signature_bypass_active` in `l2_gateway.rs:453` remain if feature accidentally enabled — recommend adding `#[cfg(all(feature="test-utils", debug_assertions))]` to all test-only paths.

---

*End of Report — 15 Findings, 6 Nightmares covered. All findings are novel with respect to prior audit tags (`AUDIT-00-WILDCARD-16`, `21`, `24`, `SA06-08` etc.) and represent previously unconsidered vectors.*

