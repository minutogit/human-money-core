# Module 06 — Fresh Hypotheses (Privacy & Protocol Bundles)

Auditor: fresh-eyes re-audit, research only. All file:line references verified against working tree at audit time.

## Coverage Matrix

| # | Instruction / Checkpoint (from 06_privacy_and_protocol_bundles.md) | Status | Note |
|---|---|---|---|
| 1 | **Private Mode Compliance:** sender did:key + plaintext signatures MUST NOT appear in transferred bundle; verification via context binding/ephemeral commitments | UNCERTAIN | Envelope is clean (`bundle_processor.rs:84-86` suppresses the permanent-key container signature for anonymous chains). However `TransactionBundle.sender_id` + `sender_signature` (permanent key, over `bundle_id`) are ALWAYS present inside the encrypted payload, even for fully Stealth chains (`bundle_processor.rs:44`, `bundle_processor.rs:58`, model `profile.rs:88-100`); same for `RecipientPayload.sender_permanent_did` (`voucher_manager/transaction.rs:256`). Only the direct recipient can decrypt — hop-by-hop traceability is a documented architectural requirement (`transaction_handler.rs:929-935`). Treated as design-intent, not de-anonymization of third parties. See Gaps. |
| 2 | **Metadata Minimization:** no extraneous metadata in transferred bundles | FINDING | Egress hygiene is strong (`deletable_at` neutralized on gossip export `conflict_manager.rs:820-826`; month-rounded validity `conflict_manager.rs:42-69`; XOR-encrypted timestamp `conflict_manager.rs:905-936`). Residual: HashedRouting `kid` = unkeyed SHA3-256(DID) → dictionary correlation (HYP-06-2). |
| 3 | **Interoperability & Bundle Validation** before payload processing | CLEAN | Receive path recomputes container `i` over all AEAD-exempt fields before anything else (`bundle_processor.rs:139-145`), rejects `EncryptionType::None` for bundles (`bundle_processor.rs:130-132`), enforces payload type (`bundle_processor.rs:121-123`), recomputes `bundle_id` excluding only id+signature (`bundle_processor.rs:156-162`), and binds privacy-guard sender to bundle sender (`transaction_handler.rs:365-370`). |
| 4 | **Private Mode De-Anonymization:** sender pubkey/did:key serialized into unencrypted header/envelope/debug event? | CLEAN | JWE protected header carries only alg/enc/typ/epk (`secure_container_manager.rs:83-88`); TrialDecryption leaves recipient/sender headers `None` (`secure_container_manager.rs:115-119,139-143`); events are local-only (`wallet/lifecycle.rs:285-287` persists into encrypted storage; nothing in core transmits `WalletEvent`). |
| 5 | **Bundle Spoofing / Signature Bypass:** authentic inner payload + spoofed wrapper metadata | CLEAN (transfer) / FINDING (signing) | Transfer bundles: wrapper fully rebound via `i` recompute; signature stripping is harmless (inner bundle signature still verifies, `bundle_processor.rs:171-176`). Signing workflow: guarantor signatures do not commit to voucher-level semantics → HYP-06-1. |
| 6 | **JWS Profile & Trust Assertion Tampering** (algorithm confusion, `none`, missing header checks) | CLEAN | `jws_profile_service.rs:102-119`: `alg` pinned to EdDSA, `typ` pinned to JWT; signing input is the raw received `header.payload` b64 (RFC 7515-correct, `jws_profile_service.rs:144-147`); DID parser is strict-length/canonical (`jws_profile_service.rs:169-172`). TrustAssertion has no verification code yet (protocol doc marks it "reserved") — nothing to bypass today. |
| 7 | **Event & Log Information Disclosure** to unauthorized UI/host listeners | CLEAN (design-intent) | `EventBffData.counterparty_id/name` retained locally by intent for offline forensics (`models/wallet_event.rs:50-54`; explicit design rationale `transaction_handler.rs:521-531` and `929-935`); events persist only into encrypted storage (`lifecycle.rs:285-287`); quarantine events deliberately carry `counterparty_id: None` (`conflict_handler.rs:558-567`). |
| 8 | **Signing Request/Response protocol validation** (`protocols/signing/*.md`) | FINDING | Preview path validates envelope integrity but nothing about voucher authenticity (`app_signature_handler.rs:47-83`); detached signature binds only `(signature metadata, init_t_id)` (`signature_manager.rs:114-128`) → HYP-06-1. |
| 9 | **Open exploration / assumption busting** | FINDING | HYP-06-2 (hashed-routing linkability), HYP-06-3 (unauthenticated L2 lock/status requests with dummy key). Also verified-and-cleared: SST shard malleability (`trap_manager.rs:148-240` canonical gates), trap-less stealth spends are rejected at L1 because non-init txs require trap-bound layer2_signature (`voucher_validation/chain.rs:700-712`), void-shard marker logic (`conflict_manager.rs:77-102`), VIP symmetry/ingress gates (`conflict_handler.rs:1176-1195`), nonce discipline (fresh OsRng nonce per AEAD op, `crypto_symmetric.rs:47-63,115-134`). |
| 10 | **Fail-first test requirement** | ADDRESSED IN REPORT | Per task constraints no test files were written; each hypothesis contains a fail-first integration-test sketch. |

## Hypotheses

### HYP-06-1: Voucher-level semantics are committed by NO signature — signing-request bait-and-switch and undetectable post-issuance mutation
- Severity: MEDIUM
- CWE: CWE-347 (Improper Verification of Cryptographic Signature), CWE-345 (Insufficient Verification of Data Authenticity)
- Target:
  - `src/services/signature_manager.rs:112-128` (detached-signature preimage = signature metadata + `init_t_id` only)
  - `src/services/voucher_validation/signatures.rs:134-187` (same weak preimage enforced on receive)
  - `src/services/voucher_manager/creation.rs:196-199` (`voucher_id = H(initial voucher content)` is derived ONCE at creation and never re-checked anywhere)
  - `src/app_service/app_signature_handler.rs:95-103` (guarantor signs a remote-supplied `Voucher` without any content commitment beyond ids)
- Attack (step-by-step):
  1. Creator builds voucher V_display with attractive terms shown to a guarantor: long `valid_until`, `non_redeemable_test_voucher=false`, flattering `creator_profile` display fields.
  2. Guarantor opens the request (`open_voucher_signing_request`, which for Cleartext/Symmetric containers performs no authenticity check at all) and issues a detached signature.
  3. The signature preimage is `H(canonical_json(VoucherSignature{role, signer_id, voucher_id, signature_time, details}) || init_t_id)` (`signature_manager.rs:114-127`) — it commits to the voucher identity pair only.
  4. Creator mutates local Voucher fields that live OUTSIDE the init transaction — e.g. shortens `valid_until` to the standard minimum, flips `non_redeemable_test_voucher`, swaps `creator_profile.first_name/organization/email`, alters `collateral` — while keeping `voucher_id`, `voucher_nonce` and the init transaction byte-identical.
  5. `process_and_attach_signature` finds the instance by `voucher_id` (`wallet/signature_handler.rs:211-221`), `validate_detached_signature` passes (`signature_manager.rs:185-194`), full standard validation also passes as long as mutated values stay inside the standard's allowed windows (`voucher_validation/identity.rs:98-178`).
  6. The voucher now circulates carrying a genuine guarantor endorsement for terms the guarantor never saw. The same gap lets any intermediate holder mutate these fields before re-transfer: no rule ever recomputes `voucher_id == H(content)` (grep confirms the derivation exists only at `creation.rs:196-199`).
- Root cause: the detached-signature scheme signs `(sig_metadata, init_t_id)`. `init_t_id` transitively commits the init transaction (amount, creator parties, nonce) but NONE of the voucher-envelope fields (`valid_until`, `non_redeemable_test_voucher`, `creator_profile` display data, `collateral`, standard name). The one existing content commitment — `voucher_id` being the hash of the initial voucher JSON — is write-only: it is never re-derived during validation, so the binding silently decays after issuance.
- Confidence: HIGH (mechanics fully code-verified)
- Testable: YES — Rust integration test: create a voucher via `create_voucher`, deep-copy it, change `valid_until` (stay within standard window) and `creator_profile.organization` on the copy, then assert `validate_voucher_against_standard(&copy, std).is_err()` AND `verify_signatures(&copy, std).is_err()` (secure invariant: envelope mutations must invalidate the voucher). On current code both return `Ok(())`, so the assertion FAILS first — proving the vulnerability.

### HYP-06-2: HashedRouting `kid` uses an unkeyed hash — routing metadata is dictionary-linkable
- Severity: LOW
- CWE: CWE-359 (Exposure of Private Personal Information), CWE-202 (Observation of Data Sent to Third Party)
- Target: `src/services/secure_container_manager.rs:114-119` (recipient `kid`), `src/services/secure_container_manager.rs:138-143` (sender `kid`); hash primitive `crypto_utils.rs:68-74` (plain SHA3-256, no key/personalization)
- Attack:
  1. Sender chooses `ContainerConfig::TargetDid(did, PrivacyMode::HashedRouting)` (exposed through the public AppService/container API).
  2. Container carries `recipients[i].header.kid = SHA3-256(recipient_did)` and the sender entry `kid = SHA3-256(sender_did)`.
  3. Any observer of the container bytes (it is meant to travel untrusted channels) enumerates candidate DIDs harvested from public profiles/JWS exports and computes their hashes; exact match links container ↔ participant without ever decrypting.
  4. Because the same deterministic hash is reused across all containers of a participant, an observer can also cluster all HashedRouting traffic per identity (long-term correlator).
- Root cause: "obfuscation" implemented as an unkeyed, unpadded hash of a low-entropy-from-the-adversary's-view identifier (DIDs are public values), giving dictionary-trial anonymity of effectively zero bits against targeted correlation.
- Confidence: HIGH (mechanics), MEDIUM (exploitability — TrialDecryption is the default used by every internal call site, e.g. `bundle_processor.rs:64`)
- Testable: YES — unit test asserting the secure invariant: build two containers with `PrivacyMode::HashedRouting` for known DIDs and assert `!serde_json::to_string(&container).unwrap().contains(&get_hash(did))` (i.e., kid must be salted/keyed or absent). On current code the hash IS embedded verbatim → test fails.

### HYP-06-3: L2 lock/status requests are unauthenticated and use a hard-coded zeroed "ephemeral" key
- Severity: LOW
- CWE: CWE-306 (Missing Authentication for Critical Function), CWE-200 (Information Exposure)
- Target: `src/app_service/l2_facade.rs:32-36` (`let ephemeral_key = [0u8; 32];` + `generate_lock_request(...)`), `src/app_service/l2_facade.rs:66-78` (status query with dummy key + `auth_signature: None`), `src/services/l2_gateway.rs:62-63` (`ephemeral_pubkey: *ephemeral_key, auth_signature: None`)
- Attack:
  1. Wallet generates `L2LockRequest` / `L2StatusQuery` containing `layer2_voucher_id`, `challenge_ds_tag`, `locator_prefixes` and `auth: { ephemeral_pubkey: 0x00…00, auth_signature: None }`.
  2. Anyone (not just the wallet) can mint identical requests — there is no secret bound into them — so the L2 server cannot distinguish legitimate holders from third parties probing voucher state; holder pseudonymity vs the L2 server is impossible (every query links to whatever transport identity is used, with zero cryptographic rotation despite the field existing for exactly that purpose).
  3. Conversely, responses ARE gated server-signature-wise on the receive side (`l2_facade.rs:302-316` requires configured `l2_server_pubkey`), so this does not enable verdict forgery — impact is confined to request authenticity/anonymity.
- Root cause: acknowledged TODO stubs (`// TODO: In the future, derive a proper ephemeral key. For now, use dummy bytes.`) shipping in the request-construction path; the auth fields exist in the schema but are never populated or required.
- Confidence: HIGH (code fact), MEDIUM (real-world impact depends on host/L2 deployment outside this repo)
- Testable: YES — test asserts the secure invariant `L2AuthPayload.auth_signature.is_some()` and `auth.ephemeral_pubkey != [0u8;32]` for `generate_l2_lock_request` output; fails on current code.

## Gaps

**Instructions that produced no finding:**
- Transfer-bundle envelope validation (#3, #5): genuinely hardened — container-id rebinding covers every AEAD-exempt field, plaintext fuse exists on BOTH directions, bundle-id recompute closes stolen-(id, signature)-pair grafts, privacy-guard sender binding prevents guard/payload mismatch.
- JWS profile verification (#6): algorithm and type confusion are explicitly closed; no `none` acceptance; strict DID parsing.
- Event/log disclosure (#7): events never leave encrypted local storage in-core; counterparty retention is documented intentional design (offline forensics) and would be misreported as a vulnerability.
- De-anonymization via envelope headers/debug output (#4): clean; signature suppression gate uses correct ANY-semantics over last transactions (`bundle_processor.rs:100-107`) including mixed public+stealth bundles.
- Trap/fingerprint pipeline (open exploration): SST shard canonicality, collision guards (torsion-freeness, tau inequality), void-shard marker, VIP ingress symmetry, retention-deadline neutralization, timestamp plausibility window — all verified sound.

**Uncertain items and why:**
- Coverage row #1 (sender DID inside encrypted bundle payload): the audit prompt's invariant reads as "MUST NOT appear in the transferred bundle", but the code intentionally includes the permanent DID + permanent-key bundle signature inside the AEAD payload for direct-recipient forensics (`RecipientPayload.sender_permanent_did`, `MismatchedPrivacySenderId` check at `transaction_handler.rs:365-370`; explicit design comments at `transaction_handler.rs:929-935`). I could not decide intent-vs-violation without reading `DESIGN_INTENT_TRIAGE.md`/`PRIVACY_FAQ.md`, which were deliberately excluded to keep this pass independent. Flagged for triage, not scored as CRITICAL: third-party observers learn nothing (payload is AEAD-protected; the public envelope signature is suppressed).
- Trust Assertion tampering: protocol is explicitly "reserved for future versions"; no struct/verification code exists yet, so the checkpoint is vacuously clean today but must be revisited when implemented (the JWS verifier already pins `typ=JWT`, which will need a deliberate extension point).

**Out-of-scope observations noted during review (not scored):**
- Unbounded `recipients[]` array in `SecureContainer` allows cheap trial-decryption CPU amplification on the receive path (`secure_container_manager.rs:315-342`); host-level input size limits mitigate.
- `verify_and_import_jws_profile` ignores `cty` (non-security-critical).
- Symmetric-encryption TransactionBundle containers are unreachable in the core receive path (password is never supplied, `bundle_processor.rs:147`), so the missing creation-side symmetric gate is defense-in-depth only.

**Summary of findings:** 0 CRITICAL · 0 HIGH · 1 MEDIUM (HYP-06-1) · 2 LOW (HYP-06-2, HYP-06-3)
