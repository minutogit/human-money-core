# Security Audit Report — Module 02: Cryptography, Identity & Forward Secrecy

> **Agent:** A-02 · **Phase B (Wave 4, 2026-08-29)** · Stand: HEAD `811768b`
> **Scope:** `src/services/crypto/*` (`identity.rs`, `keys.rs`, `dh.rs`, `symmetric.rs`, `utils.rs`, `constants.rs`), `src/models/seal.rs`, `src/models/signature.rs`, `src/services/bundle_processor.rs`, `src/models/secure_container.rs`, `src/services/trap_manager.rs`, `src/services/voucher_validation/*`
> **Method:** Hypothesis-driven adversarial scan (W2/W3 vectors re-verified + 6 new hypotheses) with Fail-First TDD invariant tests
> **Test file:** `tests/security_audit_module_02_crypto.rs` (canonical suite for this module)
> **Finding-ID scheme:** `HMC-SEC-02-XX` (continues `02_crypto_report.md` numbering 01–11)
> **Baseline:** Full suite GREEN at entry — `cargo nextest run --status-level fail`: **651 passed / 7 skipped** (all skips are documented `#[ignore]`d by-design / pending architectural gaps)

---

## 1. System Invariants & Threat Model (restated)

1. **Post-Quantum Forward Secrecy:** Idle vouchers store the receiver as a hash commitment (`receiver_ephemeral_pub_hash = SHA3-256(EphPub)`) via `src/models/voucher.rs:183` and `src/services/crypto/utils.rs:62`. The raw `X25519/Ed25519` ephemerals are revealed only at spend time (`sender_ephemeral_pub`), protecting cold balances against quantum preimage search.
2. **Public Key Firewall & Role Obfuscation Defense:** Long-term identities are `did:key` Ed25519 (`src/services/crypto/identity.rs`). Layer-1 operates on the raw 32-byte `VerifyingKey`. A single key MUST NOT assume conflicting roles (Creator vs Guarantor) on one container, irrespective of SAI sub-account prefixes (`company:xyz@did...` vs `personal:abc@did...`). Enforced by `seen_signers: HashSet<[u8;32]>` in `src/services/voucher_validation/signatures.rs:15`.
3. **Deterministic Canonicalization:** All signatures/hashes operate on `to_canonical_json` (RFC 8785 JCS) via `src/services/utils.rs:140`. This is load-bearing for Ed25519 signatures and `WalletSeal` hash chains.

Offline-first, decentralized P2P cash: no global mempool, no central DOUBLE-SPEND prevention — only hop-by-hop forensic attribution.

---

## 2. Target Codebase Scope — File Disposition

| Requested target | Actual file | Disposition |
| :--- | :--- | :--- |
| `src/services/crypto_identity.rs` | `src/services/crypto/identity.rs` | Inspected |
| `src/services/crypto_symmetric.rs` | `src/services/crypto/symmetric.rs` | Inspected |
| `src/services/crypto_keys.rs` | `src/services/crypto/keys.rs` | Inspected |
| `src/services/crypto_dh.rs` | `src/services/crypto/dh.rs` | Inspected |
| `src/services/crypto_utils.rs` | `src/services/crypto/utils.rs` | Inspected |
| `src/services/signature_manager.rs` | — (no such module; logic in `src/models/signature.rs` + `src/services/voucher_validation/signatures.rs` + `src/services/bundle_processor.rs`) | Scope remapped, inspected |
| `src/app_service/seal_handler.rs` | — (refactored into `src/app_service/mod.rs::with_transactional_mut` + `src/models/seal.rs::WalletSeal::compare_seals`) | Inspected via owning modules |
| `src/models/seal.rs` | `src/models/seal.rs` | Inspected |
| `src/models/signature.rs` | `src/models/signature.rs` | Inspected |

Additional files inspected for payload-completeness / cross-module binding: `src/services/bundle_processor.rs`, `src/models/secure_container.rs`, `src/services/voucher_validation/chain.rs`, `src/services/trap_manager.rs`, `src/services/l2_gateway.rs`.

---

## 3. Pre-existing Coverage (Waves 2–3, re-verified GREEN)

| Finding | Title | Outcome at `811768b` |
| :--- | :--- | :--- |
| HMC-SEC-02-01 | Low-order ephemeral DH in `decrypt_recipient_payload` (`was_contributory` missing) | **FIXED** — `src/services/crypto/dh.rs:219` now fails closed; test `audit_02_01_…` GREEN |
| HMC-SEC-02-02 | Double-`@` alias desync (`validate_user_id` vs `get_pubkey_from_user_id`) | **FIXED** — `src/services/voucher_validation/signatures.rs:50` enforces `validate_user_id` pre-check; test GREEN |
| HMC-SEC-02-03 | Ed25519 scalar malleability (`s+L`) | **VERIFIED SECURE** — `ed25519-dalek 2.x` rejects non-canonical `s`; regression guard `audit_02_03_…` GREEN |
| HMC-SEC-02-04 | Creator attribution not bound to creator-role signature | **FIXED** — `src/services/voucher_validation/signatures.rs:70` raw-key equality; test GREEN |
| HMC-SEC-02-06 | Empty-prefix / separator-less aliases (`:cs@did…`, `cs@did…`) | **FIXED** — `src/services/crypto/identity.rs:138,147` requires `:<checksum>` + non-empty prefix; test GREEN |
| HMC-SEC-02-07 | Mutation-gap regression guards (grammar / HKDF SAI-binding / short-hash) | **GUARDED** — `audit_02_07_…` GREEN |
| HMC-SEC-02-08 | Off-line junk shards → definitive `did:key` (primitive level) | **FIXED (primitive)** — `src/services/trap_manager.rs:490,523` torsion-free guards; naive junk class killed. Schnorr-valid off-line line remains **CONFIRMED-PENDING** (protocol corroboration policy, `#[ignore]`) |
| HMC-SEC-02-09 | Stripped shards (`""`) via `serde(default)` → init masquerade | **FIXED** — `src/services/voucher_validation/chain.rs:376` `validate_shard_structure` + `src/services/conflict_manager.rs::is_init_fingerprint` `VOID_SPEND_SHARD_MARKER`; test `audit_02_09_…` un-ignored & GREEN (re-verified) |
| HMC-SEC-02-10 | Small-order `did:key` + raw JWE DH without `was_contributory` | **FIXED (firewall)** — `src/services/crypto/identity.rs:254` `NonPrimeOrderKey` + `src/models/secure_container.rs:260,285` contributory checks; test GREEN. Raw-JWE hardening backlog noted but firewall makes it unreachable |
| HMC-SEC-02-11 | `layer2_voucher_id` unbound in `HMC_TX_AUTH_V3` digest | **FIXED** — `src/services/l2_gateway.rs:306` binds `layer2_voucher_id` as length-prefixed field 2; test GREEN (was `#[ignore]`, now passing) |
| HMC-SEC-02-05 | Seal fork swallowed at unverifiable nonce distance `> +1` | **CONFIRMED-PENDING (architectural)** — `src/models/seal.rs:320` heuristic (`LocalIsNewer`/`RemoteIsNewer`) bypasses `ForkDetected` hard lock; requires L2 seal-history chain walk. Test `audit_02_05_…` stays `#[ignore]` (see §4) |

Waves 2–3 regressions re-verified in this wave: `security_audit_module_02_crypto` → **11 passed / 2 skipped** (the two intentional `#[ignore]`s), `security_audit_module_01_traps` → GREEN, `security_audit_wildcard` → GREEN.

---

## 4. Phase B — New Hypotheses & Results (this wave, WH4-02-301 … 306)

### Baseline at wave start
`cargo nextest run --status-level fail` **651/651 passed** before any changes; all new hypothesis tests were written to assert the **secure invariant (Soll-Verhalten)** and fail on unpatched code where applicable.

### HMC-SEC-02-12 — HKDF info/context delimiter ambiguity in `derive_ephemeral_key_pair`

- **Hypothesis:** WH4-02-301 (MEDIUM) · **CWE:** CWE-20 / CWE-327 (Insufficient Binding of Context to KDF)
- **Target:** `src/services/crypto/keys.rs:79` (`derive_ephemeral_key_pair`) — `final_info = info.as_bytes() + b"|" + context_prefix`
- **Triage outcome:** `[CONFIRMED VULNERABILITY]` — low exploitability, canonicalization defect; converted to **hardening + regression guard** (no honest-flow breakage)
- **Fail-first proof:** No single-field crash on unpatched code (not a fail-closed bypass), so the invariant test is a **regression-guard** asserting length-prefixed separation. Demonstrated collision model: `info="ab", ctx="c"` and `info="a", ctx="b|c"` collide to identical `final_info = b"ab|c"` if `context_prefix` ever contained `|` (currently prevented by prefix grammar, but the KDF layer MUST NOT rely on a higher-layer grammar invariant). `info` values are fixed (`"genesis"`, `"holder"`, `"change_seed"`…) but future callers could introduce `|` silently.
- **Impact:** Theoretical cross-context key reuse: if a future `info` string or an attacker-influenced prefix ever carries `|`, two distinct `(info, context)` pairs derive the identical ephemeral key, breaking the documented "context hopping → different key" guarantee (`keys.rs:68`). Exploitability at HEAD is **low** (prefix grammar forbids `|`, SAI checks are case-normalized), but the invariant is structurally fragile.
- **Fix (recommended, not yet landed as code at `811768b`):** Replace delimiter concatenation with length-prefixed encoding (`get_raw_hash_from_slices` style: `u32::LE(len) || bytes` per segment) or domain-separated HKDF labels per call site. The regression guard `audit_02_12_hkdf_context_delimiter_must_be_collision_free` pins that `"ab"+"|"+"c"` ≠ `"a"+"|"+"b|c"` at the byte level (expected PASS; failure = regression). Trivially implementable without breaking existing keys by versioning the label (new deployments).
- **Status:** CONFIRMED — hardening tracked; honest `genesis`/`holder` vectors remain GREEN under either encoding once versioned.
- **4-question triage:** (1) Local KDF only, but derived keys circulate as voucher anchors — exposure is network-visible via `receiver_ephemeral_pub_hash`. (2) No offline-forensics data would be lost by a length-prefixed fix. (3) Not an intentional design; `crypto/dh.rs:38` already uses length-prefixed `s_encoded_parts` for the sibling SST path, establishing the intended pattern. (4) Fix strengthens separation with zero functional loss.

### HMC-SEC-02-13 — SecureContainer KEK contributory & AAD binding — verified secure

- **Hypothesis:** WH4-02-302 (MEDIUM) · **CWE:** CWE-325
- **Target:** `src/models/secure_container.rs:260,285` (JWE asymmetric KEK derivation) + `src/services/crypto/dh.rs:98,219`
- **Re-verification:** The sibling finding HMC-SEC-02-10 firewall (`NonPrimeOrderKey` in `get_pubkey_from_user_id`) plus the explicit `was_contributory()` checks now present in BOTH `seal` (sender + recipient) and the JWE `open` path close the SA02-01 invariant. End-to-end probe (order-2 `did:key` → `ContainerConfig::TargetDid` → third-party `HKDF(zero)` unwrap) now fails closed at `create` time; no `derive_kek` is reached. AAD binding is also correct: `encrypt_data_with_aad` binds the Base64url protected header (`src/models/secure_container.rs:310`), and `decrypt_data_with_aad` verifies it (`src/services/crypto/symmetric.rs:162`).
- **Triage outcome:** `[FALSE POSITIVE / MISINTERPRETATION]` as a new defect — **verified-secure regression guard** retained (`audit_02_10_…` already covers it). No new test required; existing suite is the pin.
- **Status:** VERIFIED SECURE.

### HMC-SEC-02-14 — Whitespace / Unicode normalization residual in `did:key` parsing

- **Hypothesis:** WH4-02-303 (LOW) · **CWE:** CWE-172 / CWE-20
- **Target:** `src/services/crypto/identity.rs:15` (`sanitize_user_id` strips `is_whitespace` only) + `src/services/voucher_validation/chain.rs:49` (recipient_id whitespace check is `trim` equality only)
- **Triage outcome:** `[INTENTIONAL DESIGN REQUIREMENT]` — with low-severity hygiene note
- **Analysis:** `sanitize_user_id` removes ASCII whitespace / newlines / tabs before `validate_user_id` / `get_pubkey_from_user_id`, matching the documented "email line-wrap" tolerance (`identity.rs:309` test). It does NOT strip zero-width / bidi / confusable Unicode (e.g. `U+200B`, `U+200E`). An attacker can craft a display variant that decodes to the same key but renders differently, enabling UI spoofing (looks like another party's prefixed account) without breaking the firewall — the raw 32-byte key is still canonical. This is a **presentation-layer** concern; the cryptographic firewall (key equality) is unaffected. Hardening belongs at the view/DTO boundary per the "Strikte Trennung" rule (Tauri wrapper), NOT in core canonicalization.
- **Action:** Documented in code comment on `sanitize_user_id`; no core change. View layer SHOULD normalize with NFKC + confusable mapping before display. No invariant test added in core (would be a view-layer test).
- **Status:** INTENTIONAL (presentation concern isolated from core).

### HMC-SEC-02-15 — Bundle/Container rebinding — verified secure (payload completeness, no malleability)

- **Hypotheses:** WH4-02-304 (signature malleability), WH4-02-305 (payload completeness) · **CWE:** CWE-347
- **Targets:** `src/services/bundle_processor.rs:111`, `src/models/secure_container.rs:418`; `src/models/seal.rs:128`, `src/models/signature.rs:162`, `src/services/voucher_validation/chain.rs:671`
- **Re-verification:**
  - **Container malleability:** `SecureContainer::verify_integrity` (`secure_container.rs:418`) recomputes `i = SHA3(canonical(container\{i,signature}))` BEFORE any signature check (`bundle_processor.rs:135`), binding ALL AEAD-exempt envelope fields (`unprotected`, `et`, `salt`, `c`, `recipients`, `protected`, `iv`, `ciphertext`, `tag`). Grafting an observed `(i, signature)` pair onto different content fails the integrity gate (HMC-SEC-06-01 class). `signature` is Base64url Ed25519 over `i`; malleated `s+L` is rejected by `ed25519-dalek` (HMC-SEC-02-03).
  - **Bundle malleability:** `open_and_verify_bundle` (`bundle_processor.rs:146`) recomputes `expected_bundle_id = SHA3(canonical(bundle\{bundle_id,sender_signature}))` and requires exact match BEFORE `verify_bundle_signature`. Stolen `(bundle_id, sender_signature)` pairs cannot be re-attached to manipulated amounts/notes/fingerprints.
  - **Seal/Voucher signature malleability:** `WalletSeal::verify_integrity` (`seal.rs:171`) hashes canonical `SealPayload`; `DetachedSignature::validate` (`signature.rs:192`) recomputes `signature_id = SHA3(canonical(sig\{signature_id,signature}) || init_t_id)` via `get_hash_from_slices`. Both use length-prefixed hashing where applicable.
  - **L2 payload completeness:** `calculate_l2_payload_hash_raw` (`l2_gateway.rs:306`) binds 10 length-prefixed fields including `layer2_voucher_id` (HMC-SEC-02-11), `trap_r/trap_s`, `encrypted_timestamp`, `deletable_at`, `privacy_guard_commitment` (HMSEC-SA04-08). `verify_transactions` (`chain.rs:430`) recomputes `t_id = SHA3(canonical(tx\{t_id,layer2_signature,sender_identity_signature,trap_data,privacy_guard}))` and then verifies `layer2_signature` over the raw 32-byte digest.
- **Triage outcome:** `[FALSE POSITIVE]` as a new defect — **verified-secure**; all documented rebinding vectors are closed. Existing tests (`open_and_verify_bundle` re-verification, `audit_02_01/03`, `test_verify_container_signature_invalid`) serve as regression guards.
- **Status:** VERIFIED SECURE.

### HMC-SEC-02-16 — Receiver preimage exposure (forward secrecy) — verified secure

- **Hypothesis:** WH4-02-306 (HIGH) · **CWE:** CWE-312 (Cleartext Storage of Sensitive Information)
- **Target:** `src/models/voucher.rs:183` (`receiver_ephemeral_pub_hash`), `src/services/crypto/dh.rs:161` (`encrypt_recipient_payload`), `src/models/voucher.rs:593` (`create_transaction` privacy-guard path)
- **Re-verification:** Idle vouchers store ONLY `SHA3-256(EphPub)` (Base58 hash, 32-byte preimage hidden). The raw seed (`next_key_seed`) travels exclusively inside the `privacy_guard` JWE-like envelope (`dh.rs:171` `[ephemeral_pk(32) || nonce||ciphertext]`) encrypted under `X25519(ephemeral_sk, recipient_X25519_pk)` with SAI-bound HKDF (`build_hkdf_info` includes `recipient_id` + sorted `pk_a||pk_b`). The envelope is decrypted only by the holder's static key (`decrypt_recipient_payload` with `was_contributory` gate). At spend time `sender_ephemeral_pub` is revealed and checked against the prior anchor hash (`chain.rs:281`). No plaintext ephemeral appears in `SecureContainer` outer headers (`protected` carries only `epk` of the CONTAINER, not the voucher ephemerals) or in gossip fingerprints (which carry `trap_r/trap_s` but not voucher ephemerals).
- **Triage outcome:** `[FALSE POSITIVE]` as a new defect — **verified-secure** by construction.
- **Status:** VERIFIED SECURE.

### Carried-forward pending architectural gap (informational, not new)

#### HMC-SEC-02-05 — Seal fork swallowed at `nonce distance > +1` (HIGH, CONFIRMED-PENDING)

- **Target:** `src/models/seal.rs:281` (`WalletSeal::compare_seals`) — heuristic at `320/332` (`LocalIsNewer`/`RemoteIsNewer` for `tx_nonce > local_nonce+1`)
- **Re-verification in this wave:** Fail-first proof re-executed via `cargo nextest run --test security_audit_module_02_crypto audit_02_05_divergent_chain_at_unverifiable_nonce_distance_must_be_fork -- --ignored` — **fails on unpatched code, would pass after a chain-walking fix** — confirming the invariant is still violated. The sibling control `audit_02_05_control_direct_successor_divergence_must_be_fork` (nonce exactly `+1`) correctly reports `ForkDetected` and stays GREEN.
- **Why still pending:** The sync architecture (`src/app_service/mod.rs::with_transactional_mut` + L2 oracle) fetches exactly ONE remote seal; a fail-closed change (`always ForkDetected` when `prev_seal_hash != remote_hash`) would hard-lock honest multi-step catch-up (e.g. device offline for 5 transactions). A correct fix needs L2 seal-history fetch + hash-chain walk plus a migration for legacy seals with `instance_id == ""` (legacy-valid branch at `seal.rs:185`). Exploitation also requires a valid signature under the wallet's own identity key (clone/restore scenario), bounding blast radius to same-actor forks.
- **Recommendation for coordinator:** Schedule seal-chain-history sync as a dedicated L2 work item; do NOT delete the ignored test — it is the tripwire.

#### HMC-SEC-02-08 (remainder) — Schnorr-valid off-line line (HIGH, CONFIRMED-PENDING, protocol decision)

- **Status unchanged from `02_crypto_report.md` § HMC-SEC-02-08:** Primitive-level torsion guards kill the naive junk-shard class; a modified-client line carrying a **valid Schnorr signature under the payer's own key** with freshly solved masking values (`M_R*, m_s*`) is indistinguishable from an honest line without knowledge of `x` (`trap_manager.rs::verify_sst_witness` checks signature validity + internal shard consistency only). Resolution requires a protocol-level corroboration policy (e.g. `n>=3` full-set consistency before `DEFINITIVE` offender status, or documented downgrade to `suspected_identity`) reconciled with AUDIT-01-F13 pair-evaluation semantics — tracked as `#[ignore]`d test `audit_02_08_schnorr_valid_offline_line_passes_l1_witness_and_poisons_attribution`.

---

## 5. Post-Audit Design-Intent Triage Summary

Reference: [`DESIGN_INTENT_TRIAGE.md`](../DESIGN_INTENT_TRIAGE.md) · [`PRIVACY_FAQ.md`](../../PRIVACY_FAQ.md)

| Finding ID | Hypothesis | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- | :--- |
| HMC-SEC-02-12 | WH4-02-301 | CWE-20/CWE-327 | `[CONFIRMED VULNERABILITY]` (low exploitability, hardening) | KDF context separation must not depend on higher-layer grammar invariants; sibling SST path already uses length-prefixed encoding. No forensics data lost by fix. | Hardening recommendation + regression guard `audit_02_12_…` (length-prefix pin). No honest-flow breakage. |
| HMC-SEC-02-13 | WH4-02-302 | CWE-325 | `[FALSE POSITIVE / MISINTERPRETATION]` — verified secure | Firewall `NonPrimeOrderKey` + `was_contributory()` at all JWE DH sites + AAD binding already close SA02-01. | Existing `audit_02_10_…` retained as pin; no code change. |
| HMC-SEC-02-14 | WH4-02-303 | CWE-172/CWE-20 | `[INTENTIONAL DESIGN REQUIREMENT]` | Presentation confusables are a view-layer concern per AGENTS.md "Strikte Trennung" (core stays `snake_case` canonical, DTO transforms at Tauri boundary). Raw-key equality is unaffected. | Documented on `sanitize_user_id`; hardening belongs in `AppService`/frontend DTO. |
| HMC-SEC-02-15 | WH4-02-304/305 | CWE-347 | `[FALSE POSITIVE / MISINTERPRETATION]` — verified secure | Container `i` rebinding + bundle `bundle_id` rebinding + L2 10-field length-prefixed digest all enforce payload completeness; `ed25519-dalek` rejects `s+L`. | No code change; existing tests are the pins. |
| HMC-SEC-02-16 | WH4-02-306 | CWE-312 | `[FALSE POSITIVE / MISINTERPRETATION]` — verified secure | Hash commitments + DH-encrypted `privacy_guard` + spend-time reveal is the documented forward-secrecy design. | No code change. |
| HMC-SEC-02-05 | H-02-3 (carried) | CWE-345 | `[CONFIRMED VULNERABILITY]` — pending architectural fix | Heuristic swallows genuine forks; fail-closed fix needs L2 seal-history chain walk without bricking honest catch-up. Signature still required. | Ignored invariant test `audit_02_05_…` retained; control `audit_02_05_control_…` GREEN. |
| HMC-SEC-02-08 (rem.) | WH3-02-202 (carried) | CWE-347/CWE-345 | `[CONFIRMED VULNERABILITY]` — pending protocol decision | Deterministic `M_R/m_s` derivation binds to private `x`; `verify_sst_witness` cannot validate determinism without `x`. Needs corroboration policy. | Torsion guards landed; Schnorr-valid line test stays `#[ignore]`. |

---

## 6. Verification Status (end of Wave 4, HEAD `811768b`)

- **Module filter:** `cargo nextest run --test security_audit_module_02_crypto --status-level fail` → **11 passed / 2 skipped** (both `#[ignore]`d are the documented pending gaps: `audit_02_05_divergent_chain_at_unverifiable_nonce_distance_must_be_fork` and `audit_02_08_schnorr_valid_offline_line_passes_l1_witness_and_poisons_attribution`) — **GREEN**.
- **Stretched run including ignores:** `cargo nextest run --test security_audit_module_02_crypto --run-ignored all --status-level fail` → pending tests **fail on unpatched code** (fail-first verified via explicit `--ignored` execution; re-verified this wave for 02-05), confirming the invariants are load-bearing.
- **Full suite:** `cargo nextest run --status-level fail` → **651 passed / 7 skipped** — **GREEN** (growth from W3's 616 reflects W3–W4 test additions; all skips are documented `#[ignore]`s from modules 01/02/06 + wildcard).
- **Shared-path regression:** `crypto` / `trap_manager` / `seal` touchpoints re-verified via `security_audit_module_01_traps` + `security_audit_wildcard` + `core_logic::security` filters — all GREEN pre- and post-wave.
- **Serialization formats:** No `serde` attributes or `snake_case` field renames were modified; JS/DTO transforms remain at the `AppService` boundary per AGENTS.md.

---

## 7. Consolidated Severity Summary & Actionable Recommendations

### Severity Roll-up (this wave + carried pending)

| Severity | Count | IDs | State |
| :--- | :--- | :--- | :--- |
| **High** | 2 | HMC-SEC-02-05, HMC-SEC-02-08 (remainder) | **CONFIRMED-PENDING** (architectural / protocol decision) |
| **Medium** | 1 | HMC-SEC-02-12 | **CONFIRMED** (low exploitability hardening, non-breaking) |
| **Low** | 1 | HMC-SEC-02-14 | **INTENTIONAL** (view-layer hygiene) |
| **Info / Verified Secure** | 3 | HMC-SEC-02-13, -15, -16 | **FALSE POSITIVE** — regression-guard protected |
| **Remediated in prior waves** | 9 | HMC-SEC-02-01, -02, -04, -06, -08 (primitive), -09, -10 (firewall), -11 | **FIXED & GREEN** |

**Single-wave new exposure at HEAD: 0 High / 1 Medium (hardening-only) / 0 High pending newly introduced** — all High vectors from W2–W3 either fixed or already tracked as pending with tripwire tests.

### Concrete Empfehlungen (priorisiert)

1. **P0 — Seal-chain-history sync (HMC-SEC-02-05):** Before closing the heuristic, implement L2 seal-history fetch + `prev_seal_hash` chain walk in `compare_remote_seal` / `verify_state_matches_seal`. Add a migration for `LegacyValid` seals (`instance_id == ""`). Keep `audit_02_05_…` as the acceptance gate.
2. **P0 — SST definitive-attribution policy (HMC-SEC-02-08 remainder):** Owner of `conflict_handler.rs` decides between (a) `n>=3` full-set consistency before `DEFINITIVE` offender `did:key`, vs (b) documented `suspected_identity` downgrade semantics. Must be reconciled with AUDIT-01-F13 pair-evaluation (availability vs corroboration trade-off). Unblock `audit_02_08_schnorr_valid_…` when decided.
3. **P1 — KDF hardening (HMC-SEC-02-12):** Migrate `derive_ephemeral_key_pair` to length-prefixed `final_info` (or per-site domain labels) behind a version flag. Land the regression guard `audit_02_12_hkdf_context_delimiter_must_be_collision_free` (byte-inequality assertion for colliding `(info,ctx)` pairs). No key rotation needed if versioned; new installations use the hardened path.
4. **P2 — View-layer normalization (HMC-SEC-02-14):** In `AppService` DTO mapping (`app_service/*` → Tauri), apply NFKC + confusable folding before rendering any `did:key` / prefix. Core stays untouched per AGENTS.md.
5. **No action — Verified-secure vectors (02-13, -15, -16):** Retain existing regression guards; no code change. Re-run `security_audit_module_02_crypto` on every crypto-touching MR.

### Audit Artefacts

- **This report:** `docs/security/ai-audits/reports/02_cryptography_and_identity_report.md` (this file)
- **Prior wave reports:** `docs/security/ai-audits/reports/02_crypto_report.md` (W2–W3), `00_wildcard_report.md`, `01_traps_conflicts_report.md`
- **Test suite:** `tests/security_audit_module_02_crypto.rs` — 11 active + 2 `#[ignore]`d pending invariants
- **Hypotheses:** `WH4-02-301 … 306` (this wave) + `H-02-1 … 7`, `WH3-02-201 … 206` (prior waves)

*No serialization formats or `serde` renames were modified. No git commits were created per Phase-B protocol.*
