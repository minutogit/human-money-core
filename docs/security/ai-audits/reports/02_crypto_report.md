# Security Audit Report — Module 02: Cryptography, Identity & Forward Secrecy

> **Agent:** A-02 · **Phase B (Wave 2, sequential)** · Stand: 2026-08-24
> **Test file:** `tests/security_audit_module_02_crypto.rs`
> **Hypotheses:** `temp/security-hypotheses/module-02.md`
> **Finding-ID scheme:** `HMC-SEC-02-0X` (continues pre-existing numbering 01–03)

---

## 1. Pre-existing coverage (before Wave 2)

| Finding | Title | Outcome |
| :--- | :--- | :--- |
| HMC-SEC-02-01 | Low-order ephemeral key in `decrypt_recipient_payload` (non-contributory DH) | Remediated (`audit_02_01_…`) |
| HMC-SEC-02-02 | Non-canonical signer IDs accepted by signature validation (double-`@` alias) | Remediated (`audit_02_02_…`) |
| HMC-SEC-02-03 | Ed25519 scalar malleability rejected by `verify_ed25519` | Verified-secure regression guard (`audit_02_03_…`) |

## 2. Phase B results (this wave)

Baseline at start: full suite green (537 passed / 3 skipped). Module 01 fixes landed in parallel were untouched; their suite re-verified green after my shared-path fixes.

### HMC-SEC-02-04 — Creator attribution not cryptographically bound to creator-role signature

- **Hypothesis:** H-02-1 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** (1) Voucher containers circulate between untrusted peers — exposed. (2) Binding the creator signature to `creator_profile.id` removes no offline-forensics capability. (3) The dead error variant `ValidationError::CreatorAsAdditionalSigner` proves the binding was intended but never wired. (4) Honest flows always sign with the profile's own key; raw-key comparison keeps root/prefixed SAI equivalence intact.
- **Fail-first proof:** `audit_02_04_forged_creator_attribution_must_be_rejected_in_signature_validation` FAILED on unpatched code — a voucher attributing creation to the victim's did:key with a valid attacker-key creator signature returned `Ok(())`.
- **Fix:** `src/services/voucher_validation/signatures.rs::verify_signatures` — every `role == "creator"` signature must resolve to the same raw 32-byte public key as `voucher.creator_profile.id`; missing profile id fails closed.
- **Status:** CONFIRMED+FIXED.

### HMC-SEC-02-05 — Seal fork swallowed at unverifiable nonce distance (> +1)

- **Hypothesis:** H-02-3 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — but remediation requires architectural redesign → **PENDING**.
- **Rationale:** Fail-first proven: divergent chains at nonce distance > +1 resolve to `RemoteIsNewer`/`LocalIsNewer`, bypassing the documented ForkDetected hard-lock invariant (`models/seal.rs`). However, the sync architecture compares exactly ONE remote seal (`seal_handler.rs::compare_remote_seal`); a fail-closed change would hard-lock honest multi-step catch-up. A correct fix needs Layer-2 seal-history fetch + chain walk (cross-module redesign). Note: exploitation requires a valid signature by the wallet's own identity key upstream (clone/restore scenario).
- **Tests:** `audit_02_05_divergent_chain_at_unverifiable_nonce_distance_must_be_fork` (`#[ignore = "pending architectural fix - see report"]`, fail-first verified via explicit run) + control `audit_02_05_control_direct_successor_divergence_must_be_fork` pinning the strict nonce+1 branch.
- **Recommendation for coordinator:** schedule seal-chain-history sync as a dedicated work item; do not silently delete the ignored test.
- **Status:** CONFIRMED-PENDING.

### HMC-SEC-02-06 — Empty-prefix / separator-less identity aliases bypass canonical grammar

- **Hypothesis:** H-02-5 (HIGH)
- **Triage outcome:** `[CONFIRMED VULNERABILITY]`
- **4-question check:** Same vulnerability class as the already-remediated double-`@` parser desync (HMC-SEC-02-02), reached via a different parser path; `create_user_id` cannot produce either form; no documented design accepts them; honest flows unaffected.
- **Fail-first proof:** `audit_02_06_empty_prefix_and_separator_less_aliases_must_be_rejected` FAILED on unpatched code — `:<checksum>@did:key:z…` validated as TRUE and aliases to the root identity (`get_prefix_from_user_id` → `None`), while `<checksum>@did:key:z…` claims an arbitrary prefix name under an empty-prefix checksum.
- **Fix:** `src/services/crypto_identity.rs::validate_user_id` — prefixed forms now require both a `:` separator and a non-empty prefix, matching the exact grammar producible by `create_user_id`.
- **Status:** CONFIRMED+FIXED.

### HMC-SEC-02-07 — Mutation gaps: identity grammar, HKDF SAI-binding, short-hash index logic

- **Hypothesis:** H-02-7 (MEDIUM)
- **Triage outcome:** `[FALSE POSITIVE]` as a code defect → converted to regression guards (mutant killers).
- **Rationale:** All secure invariants already hold on unpatched code; tampered-checksum rejection was additionally already covered by `tests/services/crypto_properties.rs`. What was missing is behavioral pinning so surviving mutants die:
  - (a) uppercase-prefix rejection + did/checksum-swap rejection in `validate_user_id`,
  - (b) `build_hkdf_info` argument symmetry, recipient_id (SAI) sensitivity, end-to-end wrong-id decryption fails closed,
  - (c) `get_short_hash_from_user_id` pinned against a reference SHA3→Base58→last-4-bytes derivation.
- **Test:** `audit_02_07_identity_hkdf_and_short_hash_invariants_are_pinned` (expected PASS; failure = regression).
- **Status:** FALSE-POSITIVE (+1 regression-guard test).

## 3. Post-Audit Design-Intent Triage Summary

| Finding ID | Hypothesis | Suspected CWE | Triage Outcome | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMC-SEC-02-04 | H-02-1 | CWE-347/CWE-345 | `[CONFIRMED VULNERABILITY]` | Creator-attribution binding added in `verify_signatures`; fail-first test green. |
| HMC-SEC-02-05 | H-02-3 | CWE-345 | `[CONFIRMED VULNERABILITY]` — pending fix | Ignored invariant test + strict-branch control; architectural chain-walk fix required (L2 seal history). |
| HMC-SEC-02-06 | H-02-5 | CWE-20/CWE-172 | `[CONFIRMED VULNERABILITY]` | Canonical grammar tightened in `validate_user_id`; fail-first test green. |
| HMC-SEC-02-07 | H-02-7 | CWE-345 (test gap) | `[FALSE POSITIVE]` | Regression guards added pinning grammar/HKDF/short-hash behavior. |

## 4. Verification status

- Module filter (`binary(security_audit_module_02_crypto)`): 7 passed / 1 skipped (intentional ignore) — GREEN.
- Shared crypto paths touched (`verify_signatures`, `validate_user_id`) → `cargo nextest run crypto`: 38 passed — GREEN.
- Cross-checks after shared-path fixes: module 01 suite 9 passed / 1 skipped (their by-design ignore) — GREEN; `integration_tests` binary re-run — GREEN (see final section).

*(No serialization formats or serde attributes were modified. No git operations performed.)*

---

# Wave 3 — SST / HMC_TX_AUTH_V3 Crypto Primitives (HEAD `b006cfb`)

> **Agent:** A-02 · **Phase B (Wave 3, sequential)** · Stand: 2026-08-25
> **Scope:** Crypto-primitive review of the NEW SST code paths (`b006cfb`, `d31bd89`, `fdfeb80`); hypotheses WH3-02-201 … -206.
> **Baseline:** Working copy contained A-01's Wave-3 fixes in `conflict_manager.rs`, `trap_manager.rs`, `conflict_handler.rs`; `security_audit_module_01` green (24 tests + 1 documented ignore) before my changes and re-verified green after them.
> **Finding-ID scheme:** continues at HMC-SEC-02-08 (file numbering ended at 02-07).

### HMC-SEC-02-08 — Off-line fabricated shards evade EUF-CMA attribution (junk extraction as definitive did:key)

- **Hypothesis:** WH3-02-202 (HIGH) · **CWE:** CWE-347/CWE-345
- **Target:** `src/services/trap_manager.rs::reconstruct_identity` (~389–437); consumer `conflict_handler.rs::verify_and_create_proof` (~749–767).
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — partially remediated at primitive level, remainder CONFIRMED-PENDING (protocol decision).
- **Fail-first proof:** `audit_02_08_offline_fabricated_junk_collision_must_not_yield_usable_offender_identity` FAILED on unpatched code — a collision between an honest fork and a naive off-line junk fork produced a parseable Ed25519 identity point, which `conflict_handler.rs` promotes to the DEFINITIVE offender did:key of a signed ProofOfDoubleSpend. Chosen-victim framing remains impossible (that invariant holds); the attack class is un-attributable evasion + reputation poisoning with meaningless identities.
- **Fix (module-local, crypto-primitive):** torsion-free guards on the reconstructed masking point `m_hat_r` AND the extracted identity `x_hat` in `reconstruct_identity`. Honest shards always satisfy this (`hash_to_curve` outputs are prime-order; real keys are clamped scalars × basepoint); naive garbage fabrication is rejected fail-closed. Honest-collision unit tests (incl. module 01 suite) stay green.
- **PENDING (architectural):** a Schnorr-VALID off-line line signed under the spender's own payer key is publicly indistinguishable from honest generation (M_R/m_s determinism binds to the private key x; `verify_sst_witness` checks signature validity + internal shard consistency only). Test `audit_02_08_schnorr_valid_offline_line_passes_l1_witness_and_poisons_attribution` documents this bypass and stays `#[ignore = "pending architectural/protocol decision"]`. Resolution options for the owner of `conflict_handler.rs`: n≥3 full-set corroboration before DEFINITIVE offender status, or documented downgrade semantics (suspected vs. definitive). Must be reconciled with AUDIT-01-F13 pair-evaluation semantics (availability side).
- **Status:** CONFIRMED+FIXED (primitive level) / CONFIRMED-PENDING (protocol level).

### HMC-SEC-02-09 — Shard striping via serde defaults (empty trap_r/trap_s pass L1, masquerade as init)

- **Hypothesis:** WH3-02-203 (MEDIUM) · **CWE:** CWE-20/CWE-436
- **Target:** `models/voucher.rs::TrapData` serde defaults (~94–98); `chain.rs::verify_transactions` (~310–353); `conflict_manager.rs::is_init_fingerprint` (~184–189).
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — cross-module fix required → **PENDING**.
- **Fail-first proof (wallet-based end-to-end):** `audit_02_09_stripped_shard_spend_passes_chain_validation_and_masquerades_as_init` FAILED twice on unpatched code: (A) `validate_voucher_against_standard` accepted a spend whose shards were stripped to `""` with a validly RE-SIGNED V3 digest over `""`/`""` (input anchor key reproduced via `rederive_secret_seed` Case C "holder" derivation); (B) `is_init_fingerprint` classified the stripped SPEND fingerprint as genesis — disabling gossip export, ingress gate, cleanup and extraction participation by pure omission.
- **Remediation sites live outside module-02 file ownership** (chain.rs / models/voucher.rs / conflict_manager.rs = module-01 territory): reject non-init transactions whose shards are empty or `"none"`; reserve init classification for genuine genesis entries. Two representations for "no trap" ("none" placeholder vs. empty string) constitute the same grammar-desync class as HMC-SEC-02-06.
- **Status:** CONFIRMED-PENDING (`#[ignore = "pending cross-module fix"]`; do not silently delete).

### HMC-SEC-02-10 — Small-order did:key identities & JWE DH without contributory check

- **Hypothesis:** WH3-02-204 (MEDIUM) · **CWE:** CWE-325/CWE-20
- **Target (root cause):** `crypto_identity.rs::get_pubkey_from_user_id` (~216–255); affected consumer `secure_container_manager.rs` (:105/:124/:315 raw DH → `derive_kek`).
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — root cause fixed module-locally; defense-in-depth hardening remains open.
- **Fail-first proof:** `audit_02_10_small_order_did_key_identities_must_be_rejected_by_key_resolution` FAILED on unpatched code: order-2 AND order-1 did:keys resolved successfully; the resulting X25519 u-coordinate collapsed to `[0u8;32]`; end-to-end demonstrated that a third party recomputes `kek = HKDF(b"secure-container-kek", zeros)` WITHOUT secrets, unwraps the CEK from the JWE recipient entry and decrypts the financial bundle payload.
- **Fix (module-local):** new `GetPubkeyError::NonPrimeOrderKey`; `get_pubkey_from_user_id` now enforces prime-order subgroup membership (torsion-free, neutral element explicitly rejected — its Montgomery image is the zero u-coordinate despite being "torsion-free" in Edwards terms). Honestly generated keys always pass; every consumer including `create_secure_container(TargetDid)` now fails closed against small-order payment addresses.
- **PENDING hardening:** the three raw `diffie_hellman` calls without `was_contributory()` in `secure_container_manager.rs` remain inconsistent with the hardened privacy-guard path (SA02-01). Exploitation now requires an identity point that no longer resolves through the firewall, but the contributory check should be applied systematically (file ownership outside module-02).
- **Status:** CONFIRMED+FIXED (root cause) / hardening backlog noted.

### HMC-SEC-02-11 — layer2_voucher_id unbound in HMC_TX_AUTH_V3 digest (cross-voucher lock transplant)

- **Hypothesis:** WH3-02-205 (MEDIUM) · **CWE:** CWE-347/CWE-345
- **Target:** `l2_gateway.rs::calculate_l2_payload_hash_raw` (~280–299) + `process_l2_verdict` (~371–433).
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — cross-module fix required → **PENDING**.
- **Fail-first proof:** `audit_02_11_lock_entry_signature_without_voucher_binding_must_not_quarantine_foreign_voucher` FAILED on unpatched code: an authentic lock entry (valid signature under the spender's ephemeral key) relabeled onto a foreign `layer2_voucher_id` was processed as a Verified verdict WITH full ephemeral-key pinning (`expected_ephemeral_pub=Some`) and returned `Ok(TriggerQuarantine(foreign_t_id))`. The voucher reference exists ONLY in the caller-side string comparison (check 0); cryptographically the digest authorizes transactions context-free — payload-completeness violation of the same class as the remediated HMC-SEC-06-01 bundle-id rebinding.
- **Remediation site outside module-02 scope** (`l2_gateway.rs` = module-01/L2 ownership): bind `layer2_voucher_id` into the digest; external L2 servers migrate anyway due to the V3 breaking change. The deliberate API-stability exclusion (comment chain.rs ~583) was a compatibility, not a security decision.
- **Status:** CONFIRMED-PENDING (`#[ignore = "pending cross-module fix"]`; do not silently delete).

### Cross-references (not tested by this module, per coordination instruction)

| Hypothesis | Disposition |
| :--- | :--- |
| WH3-02-201 (R5-SST witness gate dead for Anonymous recipients) | ≙ **A-01-F12** — CONFIRMED-PENDING, owned by module 01. |
| WH3-02-206 (fingerprint trusts `trap.ds_tag`; import trusts JSON group key) | ≙ **A-01-F11** — FIXED by module 01. |

## 5. Wave-3 Post-Audit Design-Intent Triage Summary

| Finding ID | Hypothesis | Suspected CWE | Triage Outcome | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMC-SEC-02-08 | WH3-02-202 | CWE-347/CWE-345 | `[CONFIRMED VULNERABILITY]` (partial) | Torsion-free guards in `reconstruct_identity` (naive junk class killed); Schnorr-valid off-line lines remain CONFIRMED-PENDING (protocol corroboration policy, ignored test). |
| HMC-SEC-02-09 | WH3-02-203 | CWE-20/CWE-436 | `[CONFIRMED VULNERABILITY]` — pending fix | Fail-first proven wallet-based; shard-presence validation in `chain.rs` + init-classification fix owned by module 01; ignored invariant test. |
| HMC-SEC-02-10 | WH3-02-204 | CWE-325/CWE-20 | `[CONFIRMED VULNERABILITY]` (root cause) | `NonPrimeOrderKey` firewall in `get_pubkey_from_user_id` (small-order/torsion/identity rejected); raw-JWE-DH contributory check remains hardening backlog. |
| HMC-SEC-02-11 | WH3-02-205 | CWE-347/CWE-345 | `[CONFIRMED VULNERABILITY]` — pending fix | Fail-first proven; voucher-id binding in L2 digest requested from l2_gateway owner; ignored invariant test. |

## 6. Verification status (end of Wave 3)

- `cargo nextest run security_audit_module_02 --status-level fail`: **9 passed / 0 failed**, 4 intentional ignores (02-05 divergent-seal [Wave 2], 02-08 schnorr-line, 02-09 stripped shards, 02-11 voucher binding) — **GREEN**.
- Regression sanity (shared crypto paths touched: `trap_manager.rs`, `crypto_identity.rs`) → `cargo nextest run security_audit_module_01 --status-level fail`: **24 passed / 0 failed** — **GREEN**.
- No serialization/serde attributes modified; no git commits performed.
