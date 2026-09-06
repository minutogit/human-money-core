# WAVE 4 — Module 06 Hypotheses: Privacy & Protocol Bundles

> Auditor: Wave-4 research pass · Date: 2026-08-26 · Branch: `live`
> Scope: Bundle creation/verification (`bundle_processor.rs`), SecureContainer/JWE envelope (`secure_container_manager.rs`), Stealth-mode paths (`transaction_handler.rs`), signing workflow (`app_signature_handler.rs`, `wallet/signature_handler.rs`), JWS profiles (`jws_profile_service.rs`), event metadata (`app_queries.rs`, `wallet_event.rs`).
> Excluded per coordinator: sa06_07 spec-flaw (PENDING), audit_02_11, SA04-08, Seal-History.
> Dedupe sources fully read: `reports/06_privacy_report.md` (Wave 2+3), `STATUS.md`, `temp/security-triage-report.md` (K1–K4, W1–W6, N1–N11). SA06-05 counterparty-DID-stripping is a confirmed FALSE POSITIVE (reverted via 382bad8) — NOT re-reported; CORE-004 retention paths treated as protected design throughout.

---

## WH4-06-701: Unsanitized attacker-controlled `TransactionBundle.notes` persisted unbounded into local metadata store
- Severity: MEDIUM | CWE: CWE-20 / CWE-770 / CWE-1164 (sibling class of HMSEC-SA06-10)
- Target: src/wallet/transaction_handler.rs:556–559 (receive-side ingestion into `bundle_meta_store.history`); src/models/profile.rs:72,125 (`TransactionBundleHeader::notes` verbatim clone in `to_header`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: A remote sender controls `TransactionBundle.notes` in full (arbitrary length, arbitrary Unicode incl. Cc/Cf control and bidi-override characters). After successful cryptographic verification the receiver clones it verbatim into the persistent `BundleMetadataStore.history` via `to_header`. This is exactly the ingestion class remediated by SA06-10 for `sender_profile_name` (bounded to 64 chars, control/format chars stripped): an attacker can plant megabytes of poisoned per-bundle metadata into every wallet that receives their bundles (storage-exhaustion on offline devices) and inject rendering-manipulating characters for any future UI that displays bundle history. The send path also stores own notes (transaction_handler.rs:96–98), so a fix must sanitize at network ingestion only, not restrict local composition.
- Broken Invariant: "Every attacker-controlled display/metadata field crossing network ingestion is sanitized and bounded before persistent storage" — established as invariant by SA06-10's `sanitize_display_name`, but applied to only one of the two attacker-controlled string fields on the same ingestion path.
- Fail-First-Test-Sketch: In `tests/security_audit_module_06_privacy.rs`: build wallets A/B via `test_utils::wallet_setup`; craft `notes = Some(format!("{}{}", "\u{202E}\u{0000}", "A".repeat(100_000)))`; call `wallet_a.create_and_encrypt_transaction_bundle(&identity_a, vouchers, &id_b, notes, vec![], HashMap::new(), None)`; feed bytes to `wallet_b.process_encrypted_transaction_bundle(...)`; read `wallet_b.bundle_meta_store.history[&header.bundle_id].notes`. Assert Soll: `notes.chars().count() <= 64` (or dedicated NOTES bound) AND no char is `is_control()` or invisible-format. On unpatched code the raw 100,005-char bidi-poisoned string is stored → FAIL.
- Dedupe-Check: SA06-10 (report + STATUS.md + triage report 4.6) explicitly scopes to `sender_profile_name`/`counterparty_name`; `sanitize_display_name` doc-comment names only that field. Neither the cumulative module-06 report nor `temp/security-triage-report.md` (N1–N11, W1–W6) mentions `notes`. Triage note: Q1 applies (local encrypted store), same as SA06-10 — classified there as CONFIRMED because remote input integrity/degradation, not transport leak; consistent MEDIUM.

---

## WH4-06-702: Voucherless bundles retain permanent-key envelope signature (N8 edge of the SA06-01/SA06-08 oracle gate)
- Severity: HIGH (potential, if voucherless private-context bundles exist in host flows) | CWE: CWE-359 / CWE-202
- Target: src/services/bundle_processor.rs:100–107 (`bundle_contains_anonymous_chain`, first conjunct `!bundle.vouchers.is_empty()`), gate call site :84–86
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (explicitly flagged as N8 in temp/security-triage-report.md)
- Threat Model: The de-anonymization-oracle gate strips the permanent-key Ed25519 envelope signature only when ≥1 voucher chain resolves anonymous. For a container with an EMPTY voucher set the predicate is `false`, so the envelope carries a publicly verifiable permanent-key signature over the public field `i` even when the transfer intent is private (e.g., pure fingerprint-gossip/metadata carriers, future payment-request acks, or host bugs passing empty vecs). Any eavesdropper holding a candidate public key gets the O(1) linkage oracle SA06-01/SA06-08 closed for voucher-carrying bundles.
- Broken Invariant: "A SecureContainer produced under private context must never carry a plaintext Ed25519 signature made with the sender's permanent identity key over a public field." The empty-voucher case silently reverts to all-or-nothing semantics for that input class.
- Fail-First-Test-Sketch: Unit test in bundle_processor tests or module-06 suite: `let (bytes, _) = create_and_encrypt_bundle(&identity_stealth, vec![], &recipient_did, None, vec![], HashMap::new(), None);` deserialize `SecureContainer`; assert Soll: `container.signature.is_empty()` whenever privacy intent holds (disjunctive fix: strip when vouchers empty AND sender standard/intent is private, or document loud why voucherless containers are always public-context). Currently signature is non-empty → FAIL; then demonstrate oracle: third party verifies sig over `i` against candidate pubkey → match.
- Dedupe-Check: N8 in security-triage-report.md ("Randfall is_anonymous_bundle … Guard erweitern oder dokumentieren") — open by name, deepened here with concrete target/test; NOT in 06_privacy_report.md findings, NOT in STATUS.md. Distinct from fixed SA06-08 (mixed non-empty bundles, ANY-semantics already shipped).

---

## WH4-06-703: Cleartext counterparty DIDs cross the Core→Host boundary via `get_event_history`; quarantine/conflict events forensically inconsistent (W6)
- Severity: MEDIUM | CWE: CWE-359 (boundary) + CWE-1164 (inconsistency)
- Target: src/app_service/app_queries.rs:162–186 (`get_event_history` returns raw `Vec<WalletEvent>` incl. `bff_data.counterparty_id/name`); src/wallet/transaction_handler.rs:642,673,739 (quarantine events hardcode `counterparty_id: None`)
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (explicitly flagged as W6 in temp/security-triage-report.md, second half of 382bad8 triage)
- Threat Model: CORE-004 correctly retains counterparty DIDs inside sealed local storage, but the AppService emits them as plaintext structs across the trust boundary to UI/host. Per AGENTS.md, datentransformation for external clients belongs at system edges (DTOs/AppService); without a DTO boundary or guard, Tauri frontends persist events into unencrypted LocalStorage/cloud sync/clipboard — the exact end-state the reverted SA06-05 finding feared, reintroduced through the application layer. Additionally the three quarantine/conflict event sites hardcode `counterparty_id: None`, contradicting the documented forensic rationale of CORE-004 (double-spend quarantine is precisely where counterparty attribution matters) — either both retention classes are intentional or neither; today it is undocumented asymmetry.
- Broken Invariant: (a) "Identity data leaving WalletSeal-protected storage crosses the host boundary only through an explicit, privacy-aware DTO contract" — no such contract exists; (b) CORE-004 consistency: "local forensic anchors are retained uniformly for all forensically relevant events".
- Fail-First-Test-Sketch: AppService integration test: unlocked service, execute a stealth transfer, call `get_event_history(0, 50, None)`; Soll variant A (boundary guard): returned events expose `counterparty_id` only pseudonymized (hash/prefix) unless an explicit `PrivacyBypass::Forensics` flag is set — assert absence of raw `did:key:` substring → currently FAILS (raw DID present, no bypass API exists). Companion invariant test: after a conflict-driven quarantine of a received stealth voucher, assert `VoucherQuarantined` event carries the same counterparty anchor as `TransferReceived` → currently FAILS (`None`).
- Dedupe-Check: W6 named open point (triage report §2 table + §4.7 item 1–2); explicitly requested by coordinator for wave-4 deepening. Original SA06-05 stripping remains reverted/protected — this finding targets ONLY the app-layer boundary and the quarantine-event asymmetry, not the local retention itself.

---

## WH4-06-704: Missing `was_contributory()` on ECDH-ES receive path of SecureContainer (low-order `epk` accepted)
- Severity: LOW | CWE: CWE-325 (parity gap with HMC-SEC-02-01)
- Target: src/services/secure_container_manager.rs:315 (`recipient_x25519_sk.diffie_hellman(&esk_pub)` in `open_secure_container`); contrast hardened sibling path crypto_dh.rs::decrypt_recipient_payload
- Status-Vermutung: LIKELY-FALSE-POSITIVE (real parity gap, marginal impact — hardening recommendation)
- Threat Model: An attacker crafting a container with a low-order/all-zero `epk` forces the DH shared secret to a constant independent of the victim key, letting them derive the KEK and wrap an attacker-chosen payload key that trial decryption accepts. Unlike HMC-SEC-02-01 (privacy_guard ownership proof), no authentication property is broken here: JWE-style ECDH-ES to public did:key recipients grants anyone the ability to craft validly decryptable containers anyway, and payload authenticity rests solely on the inner bundle/signature verification, which the attacker cannot satisfy for third-party identities. Impact reduces to defense-in-depth/algorithm-hygiene.
- Broken Invariant: "Every X25519 DH in the library rejects non-contributory results" — violated on this one call site (encrypt side :105 uses fresh OsRng ephemeral key and is safe).
- Fail-First-Test-Sketch: Craft container where protected-header `epk` = base64([0u8;32]); precompute constant DH output → KEK via `derive_kek`, wrap chosen `payload_key`, fill `encrypted_key`, compute valid `i` binding; call `open_secure_container(&container, &victim_identity, None)`. Soll (parity): reject with error (was_contributory failure) → currently returns decrypted attacker payload → FAIL demonstrates acceptance; classify impact honestly before fixing.
- Dedupe-Check: No mention anywhere in 06_privacy_report.md, STATUS.md (HMC-SEC-02-01 covers crypto_dh.rs only), or triage report K/W/N lists. New observation, expected Outcome C/hardening under the 4-question triage.

---

## Not pursued (documented rationale)

- **Dead DetachedSignature routing** (transaction_handler.rs:574–581): unreachable — `open_and_verify_bundle` rejects `c != TransactionBundle` (:121) before the branch; functional quirk, no exploit path, out of privacy scope.
- **VoucherForSigning cleartext allowance**: `EncryptionType::None` doc comment explicitly sanctions cleartext "only for signing requests"; protocol doc requires guarantor plaintext review (design-intent Outcome B) — would be FP.
- **JWS `cty` pinning / profile replay (no exp)**: H-06-1 coordinator backlog; profile-JWS is a signed business card, freshness not modeled.
- **H-06-3 unblinded bundle.timestamp**: backlog, no security consumer on receive path.
- **HashedRouting unsalted `kid` hash**: inherent candidate-set trade-off, TrialDecryption used on bundle path.
- **Protected-header alg/enc not validated on receive**: algorithms hardcoded in implementation, header values decorative; `i`-rebinding prevents tamper; no confusion selectable.

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 0 |
| HIGH | 0 (WH4-06-702 conditional-high, filed KNOWN-OPEN-DEEPDIVE) |
| MEDIUM | 1 confirmed candidate (701) + 2 KNOWN-OPEN-DEEPDIVE (702, 703) |
| LOW | 1 (704, likely-FP hardening) |
