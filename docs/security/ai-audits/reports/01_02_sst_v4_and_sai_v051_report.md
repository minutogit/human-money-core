# Adversarial Cryptographic & Security Audit Report — Modules 01 & 02 (v0.5.1)

**Scope Audited:** `src/services/trap_manager.rs`, `src/services/conflict_manager.rs`, `src/wallet/conflicts/{mod,ingress,proofs,gossip,maintenance}.rs`, `src/app_service/conflicts.rs`, `src/models/{conflict,voucher,signature,secure_container,voucher_standard_definition}.rs`, `src/services/crypto/{mod,constants,keys,identity,utils,dh,symmetric}.rs`, `src/services/voucher_validation/{mod,pipeline,chain,signatures,identity,rules}.rs`, `src/services/{bundle_processor,l2_gateway}.rs`, `src/wallet/{transactions,queries}.rs`, and regression suites (`tests/poc_sst_trap_evasion_v2.rs`, `tests/security_audit_module_01_traps.rs`, `tests/security_audit_module_06_privacy.rs`).

---

## Executive Verification: What Holds Rock-Solid in SST V4 & Core Crypto

1. **SST V4 Algebra, Secret Nonce Isolation & Key-Extraction Immunity (`src/services/trap_manager.rs:285-545`, `src/services/crypto/keys.rs:249-260`) — ROCK-SOLID**
   - **Zero Private Key Leakage from Witness Disclosure:** Schnorr signature $(R_{sig}, s_{sig})$ derives its secret nonce $r = \text{sst\_scalar}(\text{SST\_DOMAIN\_NONCE}, [x, \mu])$ directly from permanent secret scalar $x$ (`trap_manager.rs:304`), completely decoupled from the disclosed VRF output $K_{trap} = x \cdot H_{vrf}(\text{ds\_tag})$. Disclosing `TrapWitness` (`r_sig, s_sig, m_r, m_s, k_trap, dleq_c, dleq_s, input_seed`) in `RecipientPayload` or `VictimWitnessDisclosure` leaks zero information about $r$ or $x$.
   - **Stealth Key Nonce Safety:** `EphemeralKey::Stealth` signs `layer2_signature` with secret deterministic nonce $r_{L2} = \text{sst\_scalar}(\text{SST\_DOMAIN\_STEALTH\_NONCE}, [x_{eph}, m])$ (`src/services/crypto/utils.rs:175`). Disclosing `input_seed` (hence $h$, where $x_{eph} = x + h \pmod \ell$) alongside multiple distinct `layer2_signature`s never creates nonce reuse or a solvable system in $x$.
2. **Subgroup, Torsion, Canonical Encoding & Panic Safety (`src/services/trap_manager.rs:148-246, 482, 528`) — ROCK-SOLID**
   - `parse_point_bs58` enforces `len <= 44`, exact 32-byte Base58 decode, canonical field element $y < 2^{255}-19$, canonical sign bit (`point.compress().to_bytes() == bytes`, rejecting negative zero `-0`), and prime-order Ristretto/Ed25519 subgroup membership (`point.is_torsion_free()`). `k_trap_point.is_identity()` is explicitly rejected (`trap_manager.rs:366`).
   - `parse_scalar_bs58` enforces canonical scalar reduction ($s < \ell$) via `Scalar::from_canonical_bytes`.
   - `sst_encoded_parts` prefixes every variable/fixed component with a 64-bit little-endian length (`trap_manager.rs:67-76`), eliminating transcript concatenation collisions across VRF, DLEQ, slope $\tau$, and mask derivations.
   - **Self-Verifying Masks & Anti-Framing:** `reconstruct_identity` (`trap_manager.rs:519-538`) re-derives $(M_R, m_s)$ from recovered $(R_{sig}, s_{sig}, \mu)$ and verifies `s_hat * G == r_hat + c * x_hat`, deterministically rejecting steered/garbage shards so an honest user or arbitrary third party cannot be framed.
   - **Victim Witness Disclosure Ordering & Input Ownership Binding (`trap_manager.rs:647-740`, `ingress.rs:761-786`):** `verify_victim_witness_disclosure` authenticates victim output ownership (`receiver_ephemeral_pub_hash` / `change_ephemeral_pub_hash` or Public-mode `victim_did` signature), verifies `verify_sst_witness` ($E == X + hG$, Chaum-Pedersen DLEQ, Schnorr, masks) on `victim_fp`, and verifies `other_fp`'s `layer2_signature` under `E` — defeating both garbage-shard evasion and Same-ID Equivocation (`t_id_1 == t_id_2`, `privacy_guard_hash_1 != privacy_guard_hash_2`).
   - **Zero Untrusted Panic / Division-by-Zero Vectors:** `sh1.tau == sh2.tau` (`trap_manager.rs:482`) and `c == Scalar::ZERO` (`trap_manager.rs:528`) are guarded prior to `.invert()`, and `curve25519-dalek` `Scalar::ZERO.invert()` returns `Scalar::ZERO` without panicking. All production slice conversions (`[..32]`, `[..16]`) operate on fixed-width SHA-512/SHA-256/BLAKE3 outputs.
3. **Detached Signature & Role Firewall (`src/services/voucher_validation/signatures.rs:144-224`, `src/wallet/transactions.rs:1404-1499`) — SOLID (except SAI string equality in `remove_signature`, see Finding 1)**
   - Creator vs. Guarantor role separation, `init_t_id` binding, `signature_id` canonical content hashing, and `Incomplete > Active > Endorsed` attachment ordering (`AUDIT-00-WILDCARD-21`) hold properly.

---

## Confirmed Vulnerabilities (Post-Triage)

### [CONFIRMED VULNERABILITY 1] — SAI Prefix / Root DID Desynchronization Breaks `KnownOffender` Blocking, `derive_proof_id` Deduplication, and Creator Role Checks
- **Severity:** `HIGH`
- **CWE:** CWE-172 (Encoding / Canonicalization Error) / CWE-287 (Improper Authentication via Identifier Alias)
- **Locations:**
  1. `src/wallet/queries.rs:472-489` (`Wallet::check_reputation_with_provider`)
  2. `src/wallet/conflicts/ingress.rs:769-770` (`Wallet::verify_and_create_proof`) & `src/wallet/transactions.rs:321, 330`
  3. `src/services/conflict_manager.rs:542-565` (`derive_proof_id`) & `src/wallet/conflicts/ingress.rs:190-217` (`Wallet::import_proof` Gate 3b)
  4. Secondary SAI raw-string sites: `src/wallet/transactions.rs:1555` (`Wallet::remove_signature`) and `src/models/voucher.rs:1253-1256` (`Voucher::spendable_balance_for_user`)
- **Vulnerability & Step-by-Step Exploit Construction:**
  Per the project's **SAI Public-Key Invariant** (`.agents/skills/design-decisions/SKILL.md:33-36`), a user's permanent Ed25519 key $X$ has one canonical root DID (`did:key:z6Mk...`) and arbitrarily many valid Self-Addressing Identifier (SAI) prefixes (`<prefix>:<checksum>@did:key:z6Mk...`). Three interacting bugs break this invariant across the fraud-reputation boundary:
  1. **Default `KnownOffender` Gate Bypass (`queries.rs:473` + `ingress.rs:769`):**
     - Standard Humoco wallets use prefixed SAIs (e.g., `mallory:8f2a@did:key:z6MkMallory...`).
     - When Mallory double-spends, SST V4 recovers Mallory's permanent public key `pk` in `verify_and_create_proof` (`src/wallet/conflicts/ingress.rs:769`) and calls `create_user_id(&pk, None)?`, which ALWAYS records `proof.offender_id = "did:key:z6MkMallory..."` (bare root DID, no `@`).
     - Mallory subsequently sends a new `TransactionBundle` (or circulates a voucher she minted) using her normal prefixed SAI `mallory:8f2a@did:key:z6MkMallory...` (or rotates to `mallory2:1b9c@did:key:z6MkMallory...`).
     - `process_bundle_with_registry_inner` (`src/wallet/transactions.rs:321, 330`) calls `self.check_reputation(&bundle.sender_id)` and `self.check_reputation(creator_id)`.
     - `check_reputation_with_provider` (`src/wallet/queries.rs:473`) checks `if entry.proof.offender_id == offender_id` using **raw string equality** (`"did:key:z6MkMallory..." == "mallory:8f2a@did:key:z6MkMallory..."` -> `false`), returning `TrustStatus::Clean`! Every SST-deanonymized offender with a prefixed SAI bypasses `KnownOffenderTransactionBlocked` out of the box.
  2. **Incomplete `AUDIT-01-F10` Canonicalization in `derive_proof_id` (`conflict_manager.rs:550-561`):**
     - `derive_proof_id` attempts to canonicalize DIDs via `if let Some(pos) = sanitized.rfind("@did:key:z") { bs58::decode(&sanitized[pos + 10..]) } else { sanitized.into_bytes() }`.
     - A bare root DID `"did:key:z6Mk..."` does **not** contain `'@'`! Thus `rfind("@did:key:z")` returns `None`, hashing the **ASCII string** `b"did:key:z6Mk..."`, whereas `"anyprefix@did:key:z6Mk..."` hashes the **decoded 34-byte multicodec public key**!
     - Meanwhile, `import_proof` Gate 3b (`src/wallet/conflicts/ingress.rs:190-217`) validates `proof.offender_id` via `get_pubkey_from_user_id` (which accepts both root DIDs and arbitrary prefixes, even without `validate_user_id` checksum verification).
     - Consequently, an attacker can take a resolved/overridden root-DID proof (`"did:key:z6Mk..."`), rewrite `offender_id` to `"alias@did:key:z6Mk..."`, re-sign `reporter_signature`, and import it under a **second distinct `proof_id`**, bypassing `import_proof` immunity (`ingress.rs:180`).
  3. **Secondary SAI String Comparisons:** `Wallet::remove_signature` (`src/wallet/transactions.rs:1555`: `if &identity.user_id != creator_id`) and `Voucher::spendable_balance_for_user` (`src/models/voucher.rs:1253-1256` on non-init public transactions) also use raw string equality instead of `get_pubkey_from_user_id`.
- **Recommended Fix:**
  1. In `derive_proof_id` (`src/services/conflict_manager.rs:549-562`), extract canonical identity bytes via `crate::services::crypto::get_pubkey_from_user_id(&sanitized).map(|pk| pk.to_bytes().to_vec()).unwrap_or_else(|_| sanitized.into_bytes())` so `"did:key:z..."` and `"prefix:chk@did:key:z..."` always produce the exact same 32-byte Ed25519 public key input to `HMC_PROOF_ID_V1`.
  2. In `Wallet::check_reputation_with_provider` (`src/wallet/queries.rs:470-490`), compare permanent identities by underlying `VerifyingKey` (`get_pubkey_from_user_id(a) == get_pubkey_from_user_id(b)`) when both parse as DIDs, falling back to trimmed string equality for `"ephemeral:<pub>"` / `"anonymous"`.
  3. Canonicalize `proof.offender_id` to bare root `create_user_id(&pk, None)` (or validate via `validate_user_id`) in `import_proof` Gate 3b, and replace raw `==`/`!=` with `get_pubkey_from_user_id` comparison in `transactions.rs:1555` and `voucher.rs:1253-1256`.
- **Fail-First Test Blueprint:**
  ```rust
  #[test]
  fn test_sst_deanonymized_offender_cannot_evade_reputation_via_sai_prefix() {
      // 1. Create permanent keypair for Mallory with SAI "mallory:xxxx@did:key:z6Mk..."
      // 2. Assert derive_proof_id("did:key:z6Mk...", fork) == derive_proof_id("mallory:xxxx@did:key:z6Mk...", fork)
      // 3. Insert SST-derived ProofOfDoubleSpend (offender_id = root "did:key:z6Mk...") into Bob's wallet
      // 4. Assert bob_wallet.check_reputation("mallory:xxxx@did:key:z6Mk...") returns TrustStatus::KnownOffender(_)
      // 5. Attempt process_bundle_with_registry_inner from Mallory's prefixed SAI with force_accept = false
      //    -> MUST fail with Err(VoucherCoreError::KnownOffenderTransactionBlocked { .. })
  }
  ```

---

### [CONFIRMED VULNERABILITY 2] — Missing Victim Authorization in `add_resolution_endorsement` Allows Offender / Sybil Self-Forgiveness
- **Severity:** `HIGH`
- **CWE:** CWE-285 (Improper Authorization) / CWE-345 (Insufficient Verification of Data Authenticity)
- **Locations:**
  - `src/wallet/conflicts/proofs.rs:212-294` (`Wallet::add_resolution_endorsement`)
  - `src/app_service/transactions.rs:141-152` (`AppService::import_resolution_endorsement`)
  - `src/wallet/queries.rs:474-484` (`Wallet::check_reputation_with_provider`)
  - `src/models/conflict.rs:291-292` (`ResolutionEndorsement::victim_id` contract)
- **Vulnerability & Step-by-Step Exploit Construction:**
  `ResolutionEndorsement::victim_id` (`src/models/conflict.rs:291-292`) and prior audit remediation `HMSEC-SA06-12` (`tests/security_audit_module_06_privacy.rs:1678-1680`) specify that `add_resolution_endorsement` must both verify `victim_signature` against `victim_id` **and** bind `victim_id` to an actual victim recipient of `proof.conflicting_transactions`. Currently, `add_resolution_endorsement` (`src/wallet/conflicts/proofs.rs:235-274`) verifies only self-consistency of `endorsement_id` and `verify_ed25519(&get_pubkey_from_user_id(&endorsement.victim_id), ...)`, **never checking who `victim_id` is relative to the conflict proof**:
  1. Offender `M` double-spends and is recorded as `TrustStatus::KnownOffender(proof_id)` in victim and witness wallets.
  2. Offender `M` generates any fresh Sybil identity `S` (`did:key:z6MkSybil...`) — or even uses `M`'s own offender identity — and calls `create_and_sign_resolution_endorsement(&proof_id, &S, Some("Settled"))`.
  3. `M` distributes this `ResolutionEndorsement` to `import_resolution_endorsement` (`src/app_service/transactions.rs:141`).
  4. `add_resolution_endorsement` verifies `S`'s valid signature under `S`'s own `victim_id` and pushes it into `entry.proof.resolutions`.
  5. `check_reputation_with_provider` (`src/wallet/queries.rs:474`) evaluates `entry.proof.resolutions.as_ref().is_some_and(|r| !r.is_empty())` as `true`, flipping `M` from `KnownOffender` to `TrustStatus::Resolved` across every importing wallet without any victim participation.
- **Recommended Fix:**
  1. In `add_resolution_endorsement` (`src/wallet/conflicts/proofs.rs:250`), extract `victim_pk = get_pubkey_from_user_id(&endorsement.victim_id)?` and explicitly:
     - Reject if `get_pubkey_from_user_id(&entry.proof.offender_id).ok().as_ref() == Some(&victim_pk)` (an offender can never endorse their own conflict).
     - Require `entry.proof.conflicting_transactions.iter().any(|tx| get_pubkey_from_user_id(&tx.recipient_id).ok().as_ref() == Some(&victim_pk))` (matching one of the conflicting branches' recipient public keys).
     - Note on Stealth/Private mode (`tx.recipient_id == "anonymous"`): When recipients are anonymous on-chain, an unbound `did:key` cannot cryptographically prove victimhood unless accompanied by an output-key ownership signature matching `tx.receiver_ephemeral_pub_hash` (analogous to `VictimWitnessDisclosure::victim_ephemeral_pub` + signature in `trap_manager.rs:703-717`); until optional stealth-victim proof fields are present, unbound endorsements on anonymous-recipient conflicts must be rejected (users can always apply local forgiveness via `set_conflict_local_override`). *(Note: update `create_mock_proof` in `tests/wallet_api/conflict_management.rs:25` to populate `tx1.recipient_id = ACTORS.victim.user_id.clone()` when adding this gate.)*
- **Fail-First Test Blueprint:**
  ```rust
  #[test]
  fn test_offender_or_unrelated_sybil_cannot_self_resolve_double_spend_proof() {
      // 1. Import unresolved ProofOfDoubleSpend for offender M where victims are Alice and Bob
      // 2. Mint ResolutionEndorsement signed by Sybil S (and a second one signed by M himself)
      // 3. Assert wallet.add_resolution_endorsement(sybil_endorsement).is_err()
      // 4. Assert wallet.add_resolution_endorsement(self_endorsement).is_err()
      // 5. Assert wallet.check_reputation(&M.user_id) remains TrustStatus::KnownOffender(_)
  }
  ```

---

### [CONFIRMED VULNERABILITY 3] — `import_proof` Bypasses Monotonic Status Guard (`AUDIT-01-F15`), Plausibility Floor (`AUDIT-01-F14`), and Possession Priority
- **Severity:** `HIGH`
- **CWE:** CWE-367 / CWE-754 (Improper Enforcement of State-Transition & Timestamp Plausibility Invariants)
- **Location:** `src/wallet/conflicts/ingress.rs:349-447` (`Wallet::import_proof` Gate 4), contrasted with `src/wallet/conflicts/ingress.rs:1160-1228, 1330-1350` (`resolve_conflict_offline`)
- **Vulnerability & Step-by-Step Exploit Construction:**
  `resolve_conflict_offline` was hardened with three critical invariants: (a) `AUDIT-01-F15` monotonic status protection (never reactivate `Quarantined`, `Endorsed`, `Archived`, or `Expired` instances to `Active`), (b) `AUDIT-01-F14` timestamp plausibility floor (rejecting `1970-01-01` epoch-backdated siblings earlier than the fork predecessor), and (c) Possession Priority (`reputation_tests.rs:720`: a single locally `Active` voucher is not quarantined by an unverified foreign offline timestamp). **`Wallet::import_proof` (`src/wallet/conflicts/ingress.rs:376-446`) implements its own parallel Earliest-Wins race that omits all three guards:**
  1. **Exploit Prong A — Reactivation of L2-Quarantined / `Archived` / `Endorsed` Vouchers (`ingress.rs:439-441`):**
     - Line 439 unconditionally assigns: `instance.status = if tx.t_id == winner_id { VoucherStatus::Active } else { VoucherStatus::Quarantined { .. } };`.
     - If an attacker gives Victim `tx_early` (`10:00:00`), locks `tx_late` (`10:00:05`) on Layer 2 first (causing Victim's wallet to quarantine `tx_early` via authoritative signed L2 Conflict verdict), and later sends `ProofOfDoubleSpend([tx_early, tx_late])` to `import_proof`, `tx_early == winner_id` **overwrites `VoucherStatus::Quarantined` back to `VoucherStatus::Active`**, defeating Layer-2 adjudication! Equally, an already-spent `Archived` voucher, `Endorsed` escrow voucher, or `Expired` voucher matching `winner_id` is resurrected to `Active`.
  2. **Exploit Prong B — Post-Hoc Epoch-Backdated Quarantine of Any Active Voucher by a Historical Hop (`ingress.rs:378, 408-420`):**
     - `verify_transaction_integrity_and_signature` (`chain.rs:755-915`) verifies only `t_id` hash and `layer2_signature` — it does **not** check `tx.t_time >= prev_tx.t_time`, `tx.t_time >= voucher.creation_date`, or `amount` validity.
     - Any former holder of any historical hop `E_k` in a victim's `Active` voucher chain (since `find_voucher_for_transaction` and `instance.voucher.transactions.iter().find(...)` match historical hops `1..len`, not just the tip) can post-hoc sign a dummy `Transaction` spending the historical `prev_hash` with `t_time = "1970-01-01T00:00:01Z"`, wrap `[tx_k, tx_1970]` in a `ProofOfDoubleSpend`, and import it — **unconditionally winning `winner_tx_id` and quarantining the current holder's `Active` voucher**.
- **Recommended Fix:**
  1. Enforce `AUDIT-01-F15` monotonicity in `import_proof` (`src/wallet/conflicts/ingress.rs:439-446`): never transition any non-`Active` status (`Quarantined`, `Archived`, `Endorsed`, `Expired`, `Incomplete`) into `VoucherStatus::Active` (`if matches!(instance.status, VoucherStatus::Active) && tx.t_id != winner_id { ... }`).
  2. Enforce `AUDIT-01-F14` predecessor timestamp floor (using the local voucher's `prev_tx.t_time` / `creation_date`) and Possession Priority (do not quarantine a locally `Active` branch solely because an unheld foreign sibling transaction in an offline proof claims an earlier self-attested `t_time`, unless `proof.layer2_verdict` is cryptographically verified or both conflicting branches are held locally).
- **Fail-First Test Blueprint:**
  ```rust
  #[test]
  fn test_import_proof_enforces_monotonic_status_and_timestamp_plausibility() {
      // Prong A: Local voucher has VoucherStatus::Quarantined { reason: "L2 verdict" } (or Archived / Endorsed)
      // with tx_early (10:00). Import valid ProofOfDoubleSpend([tx_early, tx_late(11:00)]).
      // -> Assert status MUST NOT flip back to VoucherStatus::Active.
      // Prong B: Alice holds Active voucher created in 2026. Former hop signs sibling tx_fake with
      // t_time = "1970-01-01T00:00:01Z" and imports ProofOfDoubleSpend([tx_honest, tx_fake]).
      // -> Assert Alice's Active voucher is NOT quarantined by epoch-backdated sibling.
  }
  ```

---

### [CONFIRMED VULNERABILITY 4] — `ProofStore` Eviction Poisoning via Unsigned `report_timestamp` Wipes All `KnownOffender` Records
- **Severity:** `MEDIUM`
- **CWE:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-400 (Resource Exhaustion / Eviction Manipulation)
- **Locations:**
  - `src/wallet/conflicts/ingress.rs:527-541` (`Wallet::import_proof` `MAX_PROOFS` eviction)
  - `src/services/conflict_manager.rs:568-595` (`verify_proof_signature`)
- **Vulnerability & Step-by-Step Exploit Construction:**
  `ProofOfDoubleSpend::reporter_signature` signs only `proof_id` (`H("HMC_PROOF_ID_V1" || offender_pk || fork_point_prev_hash)`), leaving `report_timestamp` completely unauthenticated, and `import_proof` never parses or bounds `report_timestamp`. When `self.proof_store.proofs.len() >= MAX_PROOFS` (1,000), lines 528–538 evict:
  `.min_by_key(|(_, e)| e.proof.report_timestamp.as_str())`.
  1. An attacker generates 1,000 zero-cost soft proofs on random throwaway keys `E_i` (`offender_id = "ephemeral:<E_i>"`, two minimal `gossip_soft_placeholder` transactions signed by `E_i` -> passes Gates 1–4 via `NoLocalContext` without needing any real voucher or standard).
  2. Attacker sets `report_timestamp = "9999-12-31T23:59:59Z"` (or `"~~~~"`, which sorts after `"2026-..."` in ASCII).
  3. Importing these 1,000 proofs evicts **100% of legitimate `KnownOffender` and `ConflictRole::Victim` proofs** (`"2026-..." < "9999-..."`) from `ProofStore`, laundering every real offender back to `TrustStatus::Clean` and permanently pinning all 1,000 slots so any subsequent legitimate proof (`"2026-..."`) is evicted on the next import.
- **Recommended Fix:**
  1. In `import_proof`, overwrite `proof.report_timestamp` with local `get_current_timestamp()` (or validate RFC 3339 and clamp to `<= Utc::now()`).
  2. Tier `MAX_PROOFS` eviction priority so `ConflictRole::Witness` + `"ephemeral:..."` / `"anonymous"` (`NoLocalContext`) entries are always evicted before permanent-DID (`did:key:z...`) `KnownOffender` proofs, and never evict `ConflictRole::Victim` proofs in favor of `Witness` proofs.
- **Fail-First Test Blueprint:**
  ```rust
  #[test]
  fn test_proof_store_eviction_resists_future_timestamp_ephemeral_flood() {
      // 1. Insert legitimate KnownOffender proof for permanent DID Mallory (report_timestamp = now)
      // 2. Import 1,005 valid ephemeral soft proofs with report_timestamp = "9999-12-31T23:59:59Z"
      // 3. Assert wallet.check_reputation(&mallory_did) is STILL TrustStatus::KnownOffender(_)
  }
  ```

---

### [CONFIRMED VULNERABILITY 5] — `quarantine_pairs` Ingress Bypasses `foreign_fingerprints` Caps and Fails Deduplication Due to Fresh Microsecond `deletable_at`
- **Severity:** `MEDIUM`
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **Location:** `src/wallet/conflicts/ingress.rs:1052-1053, 1077-1086` (`Wallet::process_received_fingerprints` Phase 3)
- **Vulnerability & Step-by-Step Exploit Construction:**
  In `process_received_fingerprints` Phase 3 (`quarantine_pairs` ingress):
  1. Lines 1052–1053 call `assign_local_retention_to_wire_entry(&mut p0)` and `(&mut p1)`, stamping each incoming fingerprint's `deletable_at` with `Utc::now() + 180 days` at **microsecond precision**.
  2. Lines 1077–1086 insert `p0` and `p1` into `self.known_fingerprints.foreign_fingerprints` using `if !entry.iter().any(|e| e == p)`. Because `TransactionFingerprint` derives `PartialEq` across **all** fields including `deletable_at` (`src/models/conflict.rs:60`), `e == p` evaluates to `false` across any two bundles separated by $\ge 1\,\mu\text{s}$ — appending duplicate copies of the exact same fingerprint on every bundle!
  3. Unlike Phase 2 (`ingress.rs:999-1005`) and `import_foreign_fingerprints` (`conflict_manager.rs:1014-1025`), Phase 3 enforces neither `MAX_FOREIGN_BUCKET_CAP` (150) nor `MAX_TOTAL_FOREIGN_FINGERPRINTS` (50,000), allowing unbounded growth of single `ds_tag` buckets and degrading $O(k^2)$ pairwise loops in `check_for_double_spend` / `verify_and_create_proof`.
- **Recommended Fix:**
  Replace `if !entry.iter().any(|e| e == p)` at `src/wallet/conflicts/ingress.rs:1083` with the same logical deduplication predicate and capacity bounds used in Phase 2 (`!entry.iter().any(|e| e.t_id == p.t_id && e.privacy_guard_hash == p.privacy_guard_hash)` + `entry.len() < MAX_FOREIGN_BUCKET_CAP` + `total_foreign_count < MAX_TOTAL_FOREIGN_FINGERPRINTS`).
- **Fail-First Test Blueprint:**
  ```rust
  #[test]
  fn test_quarantine_pairs_ingress_deduplicates_across_time_and_respects_bucket_cap() {
      // Deliver the same quarantine_pair in 3 consecutive bundles separated by 1ms sleep.
      // Assert foreign_fingerprints[&ds_tag].len() == 2 (not 6), and never exceeds MAX_FOREIGN_BUCKET_CAP.
  }
  ```

---

### [CONFIRMED VULNERABILITY 6] — Non-Strict Ed25519 Verification in `l2_gateway.rs` & Same-`t_id` Equivocation Dedup Loss in `scan_and_rebuild_fingerprints`
- **Severity:** `LOW`
- **CWE:** CWE-347 (Improper Verification of Cryptographic Signature — Cofactor/Small-Order Malleability)
- **Locations:**
  1. `src/services/l2_gateway.rs:557-559` (`verify_lock_entry_proof`) & `src/services/l2_gateway.rs:742-745` (`process_l2_verdict_internal`)
  2. `src/wallet/conflicts/ingress.rs:49` (`Wallet::scan_and_rebuild_fingerprints`)
- **Details & Recommended Fix:**
  1. While L1 consistently uses `crypto::verify_ed25519` (`public_key.verify_strict(...)`, rejecting small-order 8-torsion `R`/public-key components and non-canonical encodings per RFC 8032), `l2_gateway.rs` calls `ephem_key.verify(...)` (lines 557, 559) and `server_key.verify(...)` (lines 742, 745) using `ed25519_dalek::Verifier::verify` (non-strict). Replace both with `crate::services::crypto::verify_ed25519(...)`.
  2. In `scan_and_rebuild_fingerprints` (`src/wallet/conflicts/ingress.rs:49`), `old_local_history` deduplicates via `e.t_id == fp.t_id` instead of `e.t_id == fp.t_id && e.privacy_guard_hash == fp.privacy_guard_hash`, dropping local Same-ID Equivocation evidence across rebuilds when one voucher was archived. Update the predicate to match `(t_id, privacy_guard_hash)`.

---

## Post-Audit Design-Intent Triage Summary

| Candidate Issue | Triage Decision | Architectural / Threat-Model Justification (`AGENTS.md` & `DESIGN_INTENT_TRIAGE.md`) |
| :--- | :--- | :--- |
| **Offline sender ordering two post-predecessor spends (`t0+1s` vs `t0+2s`) before delivery** | **DISCARDED** (Step 2 & Step 4: Offline-Cash Trade-Off) | Offline P2P Layer 1 has no global clock; SST V4 still deterministically deanonymizes the sender's `did:key`, and Possession Priority protects a single local `Active` holder against foreign gossip timestamps. (Contrast with Finding 3, where `import_proof` violated `AUDIT-01-F14`/`F15` against L2 verdicts and pre-predecessor `1970` timestamps.) |
| **`sender_identity_signature` signs raw 32-byte `t_id` without ASCII domain tag (`voucher.rs:603, 1020`)** | **DISCARDED** (Step 3: L1 Sovereignty + Verified Non-Overlap) | Audited all 11 permanent-key `sign_ed25519` call sites across `src/`: every other signature signs $\ge 43$-byte ASCII Base58 hashes or Base64URL JWS inputs (`eyJ...`). Strict message-length separation prevents cross-protocol replay without altering L1 serialization. |
| **`check_bundle_fingerprints_against_history` rejects second Same-`t_id` Equivocation bundle with `TransactionFingerprintAlreadyKnown` (`ingress.rs:856`)** | **DISCARDED** (Step 4: Safe Fail-Closed Behavior) | If Victim B already received Victim A's fingerprint via gossip, rejecting the incoming bundle before state commit prevents Victim B from accepting double-spent funds (`0` loss), while Victim A can still generate the `ProofOfDoubleSpend` via `VictimWitnessDisclosure`. |
| **`parse_point_bs58` permits `EdwardsPoint::identity()` on `r_sig_point` (`trap_manager.rs:376`)** | **DISCARDED** (Step 1: Algebraically Non-Exploitable) | `Identity.is_torsion_free()` is `true`, corresponding to $r = 0$, which forces $s_{sig} G = c X \implies s_{sig} = c \cdot x \pmod \ell$. Forging $s_{sig}$ still requires knowing secret scalar $x$, and $x = s_{sig} \cdot c^{-1}$ still extracts the offender's exact permanent key $X$. |
| **Findings 1–6 above** | **CONFIRMED** | All 6 violate explicit codebase security contracts (SAI Public-Key Invariant, `HMSEC-SA06-12` victim binding, `AUDIT-01-F14`/`F15` monotonic/plausibility guards, `ProofStore` fraud retention, `foreign_fingerprints` bucket caps, and strict Ed25519 verification) and are fixable purely offline without altering L1 wire serialization. |
