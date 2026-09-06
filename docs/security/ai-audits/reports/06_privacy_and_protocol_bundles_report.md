# Module 06 Audit Report — Privacy & Protocol Bundles (Wave 2, Phase B)

> **Agent:** A-06 · **Date:** 2026-08-24 · **Scope:** `services/jws_profile_service.rs`, `app_service/data_encryption.rs` / `app_signature_handler.rs`, `models/wallet_event.rs`, `wallet/{signature_handler,transaction_handler}.rs`, `protocols/{transfer,signing,trust}/1.0/*.md`
>
> **Baseline:** Wave-2 start green (537 passed). After modules 01–05: 558 passed / skipped by design.
> **Method:** One hypothesis at a time (`temp/security-hypotheses/module-06.md`): read cited code → manual verification → fail-first invariant test → filtered run (`cargo nextest run -E 'test(sa06)' --status-level fail`) → DESIGN_INTENT_TRIAGE 4-question check → minimal fix if `[CONFIRMED VULNERABILITY]`.
>
> **Pre-existing coverage (not re-challenged):** SA06-01 … SA06-04, SA06-06 (tests) and SA06-05 (**protected intentional design** — counterparty DID retention for offline hop-by-hop forensics; explicitly preserved and regression-guarded in HMSEC-SA06-10).

---

## Findings

### HMSEC-SA06-07 — Trust assertion signature does not bind semantic fields
| | |
|---|---|
| **Status Phase B** | `CONFIRMED-PENDING` (spec-level; no code target exists yet) |
| Severity | High |
| CWE | CWE-347 (Improper Verification of Cryptographic Signature) |
| Target | `protocols/trust/1.0/assertion.md` (schema lines 13–19); routable via `PayloadType::TrustAssertion` (`src/models/secure_container.rs:23`) |
| Affected Lines | `src/models/secure_container.rs:23` (TrustAssertion variant), `protocols/trust/1.0/assertion.md:13–19` (schema definition) |
| Test | `sa06_07_trust_assertion_signature_must_bind_all_semantic_fields` — `#[ignore = "HMSEC-SA06-07 pending architectural fix"]` |

**Verified suspicion:** The planned schema defines `assertion_id = hash(issuer_id + subject_id + timestamp)` and `issuer_signature` as a signature over `assertion_id` **alone**. `trust_level` and `context` are therefore cryptographically unprotected: anyone who observes one legitimate assertion can rewrite its semantics undetectably by any future spec-conformant verifier. No verifier exists in src/ today.

**Root Cause:** Trust assertion signature only binds to `assertion_id`, excluding all other semantic fields (`trust_level`, `context`). This creates a forgery vulnerability where semantics can be rewritten without detection.

**Triage:** `[CONFIRMED VULNERABILITY]` (spec-level) — Applying DESIGN_INTENT_TRIAGE.md 4-questions:
1. **Threat-Actor Boundary:** The gap exists at the protocol schema level; no verifier code exists in src/ to exploit it remotely, but the incomplete spec leaves assertions forgeable.
2. **Offline Resilience:** N/A — this is a schema-level design gap, not a data retention issue.
3. **Architectural Decision:** No documented design decision — the spec simply omits binding, leaving it as a future implementation risk.
4. **Functional Trade-off:** Fixing this would require a protocol version bump and invalidation of all existing assertions — breaking change out of audit scope.

**Action:** Conformance harness committed as ignored test `sa06_07_*` documenting (a) a working spec-conformant verifier, (b) the concrete forgery, and (c) the secure invariant the future implementation MUST satisfy (bind issuer signature to canonical form of all semantic fields, excluding only `issuer_signature`). **The protocol document must be fixed BEFORE any verifier is implemented**, or every issued assertion becomes invalid upon remediation.

---

### HMSEC-SA06-08 — Mixed-visibility bundles reactivate the SA06-01 de-anonymization oracle
| | |
|---|---|
| **Status Phase B** | `CONFIRMED+FIXED` |
| Severity | High |
| CWE | CWE-359 / CWE-202 |
| Target | `src/services/bundle_processor.rs::is_anonymous_bundle` (all-or-nothing gate) + call site in `create_and_encrypt_bundle` |
| Affected Lines | `src/services/bundle_processor.rs:96-103` (`bundle_contains_anonymous_chain` function), `:80-82` (signature suppression gate) |
| Fix | `all()` → `any()` semantics, renamed to `bundle_contains_anonymous_chain`; fully-public bundles keep their envelope signature |
| Test | `sa06_08_mixed_visibility_bundle_must_not_carry_permanent_key_envelope_signature` (FAIL on unpatched, green after fix) |

**Exploit detail:** With per-voucher privacy resolution (`use_privacy_mode = None`), one `MultiTransferRequest` combining a **Public**-standard voucher (plaintext DIDs on-chain) with a **Stealth**-standard voucher produces a container whose envelope keeps the sender's permanent-key Ed25519 signature over `i` — publicly verifiable against any candidate key pool, thereby linking the co-transferred stealth chain to the sender's identity at transport level.

**Note:** A Flexible-standard "public" leg does NOT trigger the gate (its recipient stays anonymous and satisfies the second disjunct); the exploitable combination requires a Public-standard leg with real-DID recipient plus a Stealth/Flexible-private leg.

**Root Cause:** `bundle_contains_anonymous_chain` used `all()` semantics — requiring ALL vouchers to be anonymous before suppressing the envelope signature. A single public-chain voucher in a multi-standard bundle kept the permanent-key signature active, creating a de-anonymization oracle for co-transferred stealth chains.

**Triage:** `[CONFIRMED VULNERABILITY]` — Applying DESIGN_INTENT_TRIAGE.md 4-questions:
1. **Threat-Actor Boundary:** The oracle is on the public envelope (network-visible). An eavesdropper or gossip peer can link stealth chains to the sender's permanent identity.
2. **Offline Resilience:** Offline forensics unaffected — SA06-05 event logs carry counterparty attribution, which is preserved intact.
3. **Architectural Decision:** SA06-01 remediation (unsigned envelopes as legitimate) was already established; the fix is consistent with the documented architecture.
4. **Functional Trade-off:** `any()` semantics accept that a single anonymous chain suppresses the envelope signature, but receive path tolerates empty signatures (no breakage). Minimal risk.

**Fix:** Changed `all()` → `any()` in `bundle_contains_anonymous_chain` at `src/services/bundle_processor.rs:96-103`, renamed function, and applied at the call site in `create_and_encrypt_bundle` (line 80-82).

---

### HMSEC-SA06-09 — Wrapper-spoofing fix asymmetry: signing paths lack `i` rebinding
| | |
|---|---|
| **Status Phase B** | `CONFIRMED+FIXED` |
| Severity | High |
| CWE | CWE-347 |
| Target | `src/services/jws_profile_service.rs::open_voucher_signing_request` (preview path); `src/wallet/transactions.rs::process_and_attach_signature` (attach path) |
| Affected Lines | `src/models/secure_container.rs:418-427` (`verify_integrity` method), `src/app_service/transactions.rs:243-244` (integrity check in `open_voucher_signing_request`), `:334-338` (integrity check in `process_and_attach_signature`) |
| Fix | New shared helper `secure_container_manager::verify_container_integrity_binding` (recompute `i = hash(canonical(container − i − signature))`), called from both paths — pre-decrypt in the request preview path, post-decrypt in the attach path (preserving the established AEAD-error precedence exercised by `api_wallet_signature_fail_tampered_container`) |
| Test | `sa06_09_signing_paths_must_rebind_container_integrity_id` (both parts FAIL on unpatched; green after fix; honest-flow regression guards included) |

**Exploit detail:** Stolen-but-genuinely-signed `(i, signature)` pairs remount onto freshly crafted `VoucherForSigning` / `DetachedSignature` containers, and arbitrary AEAD-exempt metadata (`unprotected`, `salt`, `et`, `c`) can be mutated undetected — the same attack class remediated at bundle level as HMSEC-SA06-02.

**Deliberate scope limit:** Envelope *signature enforcement* was NOT added. Integrity is fully restored by rebinding (it covers every non-cryptographic envelope field); enforcing attribution would require product decisions (which key, empty-signature tolerance) beyond a minimal safe fix. Cleartext preview semantics remain intentional design: content review is the signer's decision and the resulting detached signature cryptographically binds the reviewed content.

**Root Cause:** Both the signing-request preview path (`open_voucher_signing_request`) and the signature-attach path (`process_and_attach_signature`) acted on decrypted container payloads without first rebinding the integrity ID `i` to the received bytes. This allowed stolen `(i, signature)` pairs to be remounted onto freshly crafted containers with mutated AEAD-exempt fields (`unprotected`, `salt`, `et`, `c`) going undetected.

**Triage:** `[CONFIRMED VULNERABILITY]` — Applying DESIGN_INTENT_TRIAGE.md 4-questions:
1. **Threat-Actor Boundary:** The attack is on the container integrity (network-visible envelope). An attacker who steals a legitimate `(i, signature)` pair can remount it onto manipulated content.
2. **Offline Resilience:** The fix preserves offline forensics — the rebinding is a local integrity check, not a data retention change.
3. **Architectural Decision:** The shared helper `verify_container_integrity_binding` was deliberately wired into both paths to ensure consistent behavior, consistent with the AEAD-error precedence already established in the codebase.
4. **Functional Trade-off:** Rebinding adds a minimal computational cost (one canonical JSON hash) and preserves all existing functionality. Honest-flow regression guards (6 `api_wallet_signature` tests) pass green.

**Fix:** Wired shared integrity rebinding helper into both `open_voucher_signing_request` (preview path, line 243-244) and `process_and_attach_signature` (attach path, line 334-338). The `verify_integrity` method in `src/models/secure_container.rs:418-427` recomputes `i` excluding `i` and `signature` fields.

---

### HMSEC-SA06-10 — Attacker-controlled display-name injection into event feed
| | |
|---|---|
| **Status Phase B** | `CONFIRMED+FIXED` |
| Severity | Medium |
| CWE | CWE-74 / CWE-1164 |
| Target | `src/wallet/transactions.rs::process_encrypted_transaction_bundle_inner` (`counterparty_name ← bundle.sender_profile_name` → `EventBffData`, `BundleMetadataStore.history`) |
| Affected Lines | `src/wallet/transactions.rs:32-65` (`sanitize_display_name` function), `:412` (sanitization call site in `process_encrypted_transaction_bundle_inner`) |
| Fix | Single ingestion-point sanitizer `sanitize_display_name`: strips control (Cc) and invisible/format (Cf: ZWJ/ZWNJ/bidi-override/BOM-class) characters, bounds length to 64 chars; applied immediately AFTER all cryptographic verification (local storage/display transformation only) |
| Test | `sa06_10_received_display_name_must_be_sanitized_and_bounded` (FAIL on unpatched with 10,005-char poisoned name; green after fix; legit-name passthrough + SA06-05 DID-retention guards included) |

**Root Cause:** The `counterparty_name` field from `bundle.sender_profile_name` was stored directly into `EventBffData.counterparty_name` and `BundleMetadataStore.history` without sanitization, allowing attacker-supplied control characters and invisible Unicode format characters to inject into the event feed and local metadata history.

**Triage:** `[CONFIRMED VULNERABILITY]` — Applying DESIGN_INTENT_TRIAGE.md 4-questions:
1. **Threat-Actor Boundary:** The display name is stored in local encrypted event logs and shown in UI — not directly network-visible, but an attacker controlling the sender profile name can poison the local wallet UI and metadata history.
2. **Offline Resilience:** Sanitizing the display name does not touch the forensic anchor (`counterparty_id`), which remains intact for offline double-spend forensics (HMSEC-SA06-05 protected design).
3. **Architectural Decision:** The `sanitize_display_name` function was already established as the ingestion-point sanitizer; adding it at the bundle processing layer (after crypto verification) is consistent with the documented architecture.
4. **Functional Trade-off:** Stripping control and invisible characters while bounding to 64 chars removes attack vectors without affecting legitimate display names. Legitimate-name passthrough is verified, and SA06-05 DID-retention guards are included in the test.

**Fix:** Added `sanitize_display_name(bundle.sender_profile_name)` call at `src/wallet/transactions.rs:412` in `process_encrypted_transaction_bundle_inner`, immediately after all cryptographic verification. The sanitizer function at lines 32-65 strips control/invisible characters and bounds length to 64 chars.

---

## Not pursued (documented rationale)

- **H-06-1** (JWS `cty` pinning / unknown header members): assigned to backlog by coordinator (WAVE2-STATUS.md) — not in this wave's test set.
- **H-06-3** (unblinded creation timestamp committed into `bundle_id`): backlog per WAVE2-STATUS.md. Preliminary analysis stands: `bundle.timestamp` has no security consumer on the receive path; any future fix must weigh chain-replay implications.
- **SA06-05**: protected intentional design — untouched, additionally guarded by HMSEC-SA06-10.

---

## Post-Audit Design-Intent Triage Summary

| Finding ID | Suspected CWE | Triage Outcome | Rationale / Architectural Requirement | Action Taken |
| :--- | :--- | :--- | :--- | :--- |
| HMSEC-SA06-07 | CWE-347 | `[CONFIRMED VULNERABILITY]` (spec-level) | Signature basis excludes semantic fields; no verifier exists yet — fixing post-implementation would invalidate all assertions | Ignored conformance harness `sa06_07_*`; protocol fix mandated before implementation |
| HMSEC-SA06-08 | CWE-359/202 | `[CONFIRMED VULNERABILITY]` | Any-anonymous-chain context must suppress permanent-key envelope signature | Fixed `all()`→`any()` in `bundle_processor.rs`; TDD test `sa06_08_*` |
| HMSEC-SA06-09 | CWE-347 | `[CONFIRMED VULNERABILITY]` | Wrapper-payload binding must hold on ALL protocol paths | Shared rebinding helper wired into both signing paths; TDD test `sa06_09_*` |
| HMSEC-SA06-10 | CWE-74/1164 | `[CONFIRMED VULNERABILITY]` | Remote display metadata requires bound/sanitized ingestion; forensic DID retention preserved | Ingestion sanitizer in `transaction_handler.rs`; TDD test `sa06_10_*` |
| HMSEC-SA06-05 | CWE-359 | `[INTENTIONAL DESIGN REQUIREMENT]` | Direct counterparty retention in local event log required for offline hop-by-hop double-spend forensics; strictly local, never transmitted | Documented in code + invariant test added; preserved in `PRIVACY_FAQ.md`; no code modification |

## Suite status

`cargo nextest run -E 'test(sa06)' --status-level fail` → **9 passed / 0 failed** (+1 ignored by design: `sa06_07`). Filtered foreign regressions touched by src fixes: `api_wallet_signature*` 6 passed, `*event*` 18 passed. Full-suite verification is the coordinator's final step.

---

# Wave 3 Addendum — Fix Phase (WH3-06-601..605 / HMSEC-SA06-11..15)

Fix agent A-06. All five Wave-3 tests were verified FAIL-first by the coordinator run
(fail-first proof), parked as `#[ignore = "CONFIRMED-PENDING …"]`, and are now
remediated, UN-IGNORED, and green. Design-intent 4-question triage was applied to each
finding; the 🛡️ SA06-05 precedent (local counterparty retention is INTENTIONAL) was
respected — no SA06-05-protected code path was touched.

---

### HMSEC-SA06-11 / WH3-06-601 — Placeholder-shard spends switch SST attribution off (High)
| | |
|---|---|
| **Status FIX** | `CONFIRMED+FIXED` |
| CWE | CWE-347 / CWE-20 |
| Test | `sa06_11_placeholder_shard_spend_must_fail_reception_validation` (UN-IGNORED, green) |

**Outcome — two-part fix:**
1. **Prong A (chain rejection) via A-04 synergy, no new code:** the SA04-09 gate
   `trap_manager::validate_shard_structure` (enforced in `voucher_validation/chain.rs`
   for every non-init transaction) already rejects the canonical `"none"/"none"`
   placeholder pair — Base58-decodes to 3 bytes ≠ 32 → structural rejection. The
   self-consistently re-signed V3 placeholder spend fails reception validation.
   Cross-ref: STATUS.md Wave-3 Module-04 entry explicitly reserved this ground
   ("shared ground with SA06-11").
2. **Prong B (fingerprint classification), this fix:** new constant
   `conflict_manager::VOID_SPEND_SHARD_MARKER` ("invalid"). `create_fingerprint_for_transaction`
   replaces empty/placeholder shards of transactions that CARRY `trap_data` (i.e. claim
   to be spends) with the void marker, so such fingerprints never classify as genesis in
   `is_init_fingerprint` — gossip ingress, export filter, cleanup and SST collision
   extraction no longer silently skip them. Genuine genesis transactions have NO
   trap_data and keep the `"none"` placeholders.

**Design note:** adding an authoritative marker FIELD to `TransactionFingerprint` was
rejected: full struct literals in files outside this wave's ownership
(`wallet/tests.rs`, `test_utils/voucher_setup.rs`, `security_audit_module_01_traps.rs`)
would break compilation. Hostile wire entries with placeholder shards remain rejected at
ingress through the unchanged shard heuristic plus the V3 signature gate (their spend-
style signature cannot validate under the init challenge-tag selection).

**Regression verification:** module_06 filter 14/14; module_01 traps 25/25;
conflict_and_traps 6/6; lib 81/81 (incl. reputation tests).

---

### HMSEC-SA06-12 / WH3-06-603 — Unverified endorsements/verdicts flip reputation to Resolved (High)
| | |
|---|---|
| **Status FIX** | `CONFIRMED+FIXED` |
| CWE | CWE-347 / CWE-345 |
| Target | `wallet/conflict_handler.rs::add_resolution_endorsement`, `::import_proof` |
| Test | `sa06_12_unverified_endorsements_and_verdicts_must_not_flip_reputation` (UN-IGNORED, green) |

**Fix (both gates at ingestion, so presence-based `check_reputation` in `queries.rs`
stays untouched):**
1. `add_resolution_endorsement` now verifies `victim_signature` over `endorsement_id`
   against the permanent key of the CLAIMED `victim_id` (canonical parser
   `get_pubkey_from_user_id`, prefixed SAI IDs supported). Forged/self-signed
   endorsements claiming a real victim are rejected. Deliberately bypass-RESISTANT:
   the audit test runs under signature bypass and must still be rejected.
2. `import_proof` neutralizes any `layer2_verdict` arriving on the import channel to
   `None` (Gate 0). Import proofs carry no trusted-server context, and a self-claimed
   did:key "server" would still be attacker-controlled — honoring such verdicts would
   preserve the laundering vector. Authoritative verdicts enter exclusively via the
   authenticated gateway path (`l2_gateway::process_l2_verdict` with a configured
   trusted server pubkey).

**Companion fixture fix (out-of-scope file, documented):**
`tests/wallet_api/conflict_management.rs::test_wallet_add_resolution_endorsement`
hand-crafted an endorsement with bogus `victim_signature: "sig"` — it enshrined the
vulnerability. Its intent (valid endorsement stored + readable) is preserved by using
the canonical signer `conflict_manager::create_and_sign_resolution_endorsement`.
Suite green after modernization (5/5).

**Regression verification:** integration_tests 423/423 (incl. all wallet_api conflict
suites); lib 81/81.

---

### HMSEC-SA06-13 / WH3-06-602 — Unbound `suspected_identity` advisory survives transit (Medium)
| | |
|---|---|
| **Status FIX** | `CONFIRMED+FIXED` |
| CWE | CWE-347 / CWE-345 |
| Target | `wallet/conflict_handler.rs::import_proof` |
| Test | `sa06_13_suspected_identity_must_be_bound_or_neutralized_on_import` (UN-IGNORED, green) |

**Fix (neutralize variant of the disjunctive remediation):** new Gate 0b in
`import_proof`: if `suspected_identity` is present and differs from `offender_id`, it is
set to `None` before storage. Rationale: the field is not covered by
`reporter_signature` (which signs only `proof_id`) and the did:key attribution gate is
skipped for `ephemeral:`/anonymous offenders — so anything diverging from the offender
linkage in transit is untrustworthy advisory data that must not reach the conflict UI.
Matching values from legitimate reporters who performed a verified extraction are kept.
Local extraction in `verify_and_create_proof` is unaffected.

---

### HMSEC-SA06-14 / WH3-06-604 — L2 lock requests leak output-graph anchors (Medium)
| | |
|---|---|
| **Status FIX** | `CONFIRMED+FIXED` |
| CWE | CWE-359 / CWE-345 |
| Target | `services/l2_gateway.rs::generate_lock_request` |
| Test | `sa06_14_l2_lock_request_anchors_must_be_absent_or_digest_bound` (UN-IGNORED, green) |

**Design decision — METADATA MINIMIZATION variant** (of the disjunctive Soll):
`generate_lock_request` no longer emits `receiver_ephemeral_pub_hash` /
`change_ephemeral_pub_hash` (constant `None`). Entitability is proven by the reference
client (`l2_client_simulator` sends `None` everywhere and passes the compliance
sequence); mock L2 servers in the test suites merely copy the fields. The wire-model
fields remain (serde-defaulted) for deserialization compatibility with legacy peers.
L2-server logic checked: no consumer of these fields exists in src/ or the reference
server mocks' decision paths (only test-mock bookkeeping).

**Protocol impact: NONE.** No digest change was required for this finding — the V3
digest is untouched by SA06-14 (the digest-level protocol impact concerns only
audit_02_11 below, which remains PENDING).

---

### HMSEC-SA06-15 / WH3-06-605 — Gossip wireformat links voucher families via `deletable_at` (Medium)
| | |
|---|---|
| **Status FIX** | `CONFIRMED+FIXED` |
| CWE | CWE-359 / CWE-202 |
| Target | `services/conflict_manager.rs` (egress + ingress), `wallet/conflict_handler.rs` (bundle gossip) |
| Test | `sa06_15_gossip_wireformat_must_not_link_family_spends_via_deletable_at` (UN-IGNORED, green) |

**Design decision — CHANNEL SEPARATION (generalized neutral wire marker + local uniform
retention), applied to BOTH gossip channels:**
- **Egress:** `export_own_fingerprints` serializes a sanitized copy with `deletable_at`
  replaced by `NEUTRAL_WIRE_DEADLINE` ("") on every exported entry;
  `select_fingerprints_for_bundle` applies the same neutralization to the fingerprint
  clones forwarded inside transfer bundles (same leak via `forwarded_fingerprints`).
- **Ingress:** new public helper `assign_local_retention_to_wire_entry` assigns every
  admitted foreign fingerprint a uniform local deadline
  (`FOREIGN_FINGERPRINT_RETENTION_DAYS = 180`, RFC3339/micros/Z — lexicographically
  compatible with the existing string-comparison cleanup), applied in both
  `import_foreign_fingerprints` and `process_received_fingerprints`. Wire deadlines are
  untrusted either way (honest peers send none; attackers could poison retention or
  leak validity months).
- **Local semantics preserved:** the exact month-rounded value stays in LOCAL stores
  for retention cleanup; `create_fingerprint_for_transaction` rounding untouched.
- **Signature gate unaffected:** spend-challenge digests do not bind `deletable_at`
  (only init entries bind it, and those are rejected before rewriting).
- **Dedupe hardening:** foreign-bucket dedupe switched from whole-struct equality to
  evidence identity (`t_id`), since per-session deadlines would otherwise accumulate
  duplicates.

Legitimate uses audited: L2 server logic consumes `Transaction.deletable_at` (genesis
locks), NOT the fingerprint wire field — nothing breaks.

---

## Zusatzaufgabe audit_02_11 (HMC-SEC-02-11, coordinator routing from A-02)

**Outcome: REMAINS `#[ignore]`d — fix NOT implementable within A-06's file scope; test
harness is structurally incapable of passing.** Two independent reasons:

1. **Structural (verified live):** the harness asserts panic on EVERY possible outcome —
   `.expect("verdict processing")` panics on `Err`, and the `match` arms panic on
   `TriggerQuarantine`, `ConfirmLocal` AND `_` (any other action). Re-running the
   ignored test confirms it fails at the SECURITY-VIOLATION panic today; even a perfect
   voucher-id binding that makes `process_l2_verdict` return `Err` would fail the test
   at `.expect`. There is no green state by construction; only a harness rewrite
   (e.g. `assert!(result.is_err())`) could ever pass — and that file is frozen for A-06
   except the ignore line itself.
2. **Scope (compile blast radius):** binding `layer2_voucher_id` into the canonical
   digest requires changing `calculate_l2_payload_hash_raw`'s serialization AND
   migrating every signer/verifier: `voucher_validation/chain.rs` (~693, A-04's file),
   `voucher_manager/creation.rs` + `transaction.rs` (signers), `test_utils/voucher_setup.rs`
   (3 sites), `l2_client_simulator/main.rs` (7 sites) and NINE test files calling the
   raw function directly (`signature_reuse`, `module_01_traps`, `module_02_crypto`,
   `l2_integration`, `module_04_integrity`, `identity_trap_audit`,
   `core_logic/vulnerabilities`, `security_audit_wildcard`, fixtures) — all outside
   A-06's exclusive file set; changing the raw function's signature alone breaks
   compilation of frozen suites.

**Migration plan for a coordinated V3.x run (pre-launch breaking changes accepted):**
add `layer2_voucher_id` as a length-prefixed slice to the digest (position: after
domain tag, before challenge tag), migrate signers (voucher_manager) and verifiers
(chain.rs, process_l2_verdict, verify_fingerprint_signature) plus test fixtures and the
simulator in one atomic commit; rewrite the audit_02_11 harness to assert
`process_l2_verdict(...)` returns `Err(ValidationFailed(...))` for the relabeled entry,
then un-ignore. Until then the transplant gap documented by HMC-SEC-02-11 remains open
and known; caller-side voucher-ID comparison (check 0) remains the only defense.

---

## Wave 3 suite status

`cargo nextest run --test security_audit_module_06_privacy --status-level fail` →
**14 passed / 0 failed / 1 skipped** (`sa06_07`, spec-level protocol fix pending, unchanged).

Mandated regressions: `security_audit_module_02_crypto` 9 passed / 4 pre-existing skips ·
`security_audit_module_01_traps` 25/25 · `security_audit_wildcard` 5 failures —
**proven pre-existing** (identical failure set with A-06 changes stashed; wildcard_05
is the classifier-level sibling of SA06-11-B owned by the Module-00 agent; 06–09 are
legacy-voucher-display / stealth-history / quarantine-arithmetic domains) ·
`architecture::` 27/27 (run because l2_gateway.rs changed).

Additional regression safety: `security_audit_module_03_cel` +
`security_audit_module_04_integrity` + `security_audit_module_05_storage` 44/44 (+1
pre-existing skip) · `security_audit_conflict_and_traps` 6/6 · lib tests 81/81 ·
integration_tests 423/423 · `cargo check --bins --examples` clean.
