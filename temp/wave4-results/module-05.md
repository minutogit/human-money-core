# Wave 4 — Results Module 05: Storage, Archive & Key Persistence

> Agent: B-05 (Phase B, Fail-First TDD). Branch `live`. Date: 2026-08-26.
> Test file: `tests/security_audit_wave4_storage.rs` (only file created besides this report).
> Command: `CARGO_TARGET_DIR=/tmp/opencode/hmc-w4-target cargo nextest run --test security_audit_wave4_storage`
> Result: **4 tests run: 0 passed, 4 failed** — every test asserts the secure
> Soll-Verhalten and is RED on unpatched code (= proof). No src/ changes, no git ops.
> Note: during the run an unrelated concurrent agent's WIP temporarily broke
> `bin/l2_client_simulator` (compile error, not caused by this test file); after
> their fix the command above ran cleanly as documented.

| Finding-ID | Wave-ID | Severity | Status | Test |
| :--- | :--- | :--- | :--- | :--- |
| AUDIT-W4-STO-601 | WH4-05-001 | HIGH | **PROVEN** | `wh4_05_001_record_substitution_within_directory_must_be_detected` |
| AUDIT-W4-STO-602 | WH4-05-002a | MEDIUM | **PROVEN** | `wh4_05_002a_manifest_sync_must_refuse_diverged_disk_state` |
| AUDIT-W4-STO-603 | WH4-05-002b | MEDIUM | **PROVEN** | `wh4_05_002b_missing_manifest_must_not_bootstrap_over_deleted_records` |
| — (same wave-ID) | WH4-05-003 | MEDIUM | **PROVEN** | `wh4_05_003_file_storage_must_reject_empty_passwords_at_save_and_reset` |
| AUDIT-W4-STO-605 | WH4-05-004 | LOW | **BLOCKED** | — (no test, rationale below) |

---

## AUDIT-W4-STO-601 / WH4-05-001 — PROVEN (HIGH)

- **Test:** `wh4_05_001_record_substitution_within_directory_must_be_detected`
- **Setup:** three genuinely archived states t1→t2→t3 via
  `FileVoucherArchive::with_key` + `archive_voucher` (strictly growing chain);
  baseline read serves the full newest chain. Attack: `fs::copy(<t2>.json →
  <t3>.json)` — same-directory whole-record content substitution; manifest
  ID-set, AEAD authenticity and location binding all remain satisfied.
- **Ausschnitt (red run):**
  ```
  AUDIT-W4-STO-601 VIOLATION: copying the older genuine record
  <wh4-05-001-state-two-t-id>.json over the newest record
  <wh4-05-001-state-three-t-id>.json went UNDETECTED — get_archived_voucher
  served a ROLLED-BACK history (3 transactions instead of 4) because the
  sealed manifest pins only the record ID SET, never the per-record
  content/generation. Whole-record substitution within one directory must
  yield IntegrityViolation (CWE-354/CWE-345).
  ```
- **Fix-Notiz:** Bind each record's CONTENT to its record ID in the sealed
  per-voucher manifest (keyed per-record hash analogous to
  `derive_store_binding_hash`) and verify in `get_archived_voucher` /
  `find_transaction_by_id` BEFORE deserialization; mismatch ⇒
  `ArchiveError::IntegrityViolation`. The control archive (unmanipulated
  t1→t2→t3 must keep loading Ok) is part of the test — the binding must not
  produce false positives.

## AUDIT-W4-STO-602 / WH4-05-002a — PROVEN (MEDIUM)

- **Test:** `wh4_05_002a_manifest_sync_must_refuse_diverged_disk_state`
- **Setup:** two genuine states archived (intact manifest {t1,t2}); attack:
  delete `<t2>.json` + inject junk `wh4-junk.json` (`{}`) → set no longer
  shrank, so the shrinkage-only guard does not fire; then one LEGITIMATE
  `archive_voucher(t3)`.
- **Ausschnitt (red run):**
  ```
  AUDIT-W4-STO-602 VIOLATION: the manifest sync accepted (laundered) the
  delete+inject divergence by rewriting the manifest without error, and the
  subsequent read only fails with an OPAQUE content error ('… wh4-junk.json
  is not a sealed envelope …') instead of a deterministic divergence report
  naming the manifest/disk mismatch. Once rewritten, the deletion evidence is
  destroyed forever and the junk record bricks every future read (permanent
  IntegrityViolation, self-healing-never) (CWE-354/CWE-345).
  ```
- **Proof semantics:** sync returned `Ok(())` while rewriting the sealed
  manifest over the tampered state (= laundering), and the fallback read-side
  branch shows NO deterministic divergence report exists post-laundering
  (information destroyed; permanent brick). Either secure outcome turns the
  test green: sync refuses arbitrary divergence with IntegrityViolation, OR a
  reader-side deterministic manifest/divergence error naming "manifest"/"record set".
- **Fix-Notiz:** Extend `sync_manifest`'s refusal (:480–489) from
  shrinkage-only to FULL set inequality between intact manifest and disk;
  keep bootstrap only for legitimately empty directories.

## AUDIT-W4-STO-603 / WH4-05-002b — PROVEN (MEDIUM)

- **Test:** `wh4_05_002b_missing_manifest_must_not_bootstrap_over_deleted_records`
- **Setup:** two genuine states archived; attacker deletes the sealed
  `archive_manifest.sealed` AND `<t2>.json`; one legitimate
  `archive_voucher(t3)` follows.
- **Ausschnitt (red run):**
  ```
  AUDIT-W4-STO-603 VIOLATION: after deleting the sealed manifest and the
  genuine record <wh4-05-002b-state-two-t-id>.json, the next legitimate
  archive_voucher BOOTSTRAPPED a fresh manifest from the tampered disk
  contents and returned Ok("Ok(())") — deletion detection was silently reset
  and every future read serves the rolled-back {t1, t3} history as
  consistent. A missing manifest above EXISTING records must refuse the
  rewrite with IntegrityViolation (CWE-354/CWE-345).
  ```
- **Fix-Notiz:** In `sync_manifest`, bootstrap-from-disk (:497) only when the
  voucher directory held no state records before this write; if records exist
  without a manifest, refuse with `IntegrityViolation` (deletion cannot be
  ruled out).

## WH4-05-003 — PROVEN (MEDIUM)

- **Test:** `wh4_05_003_file_storage_must_reject_empty_passwords_at_save_and_reset`
- **Setup:** (a) initial `save_wallet(.., AuthMethod::Password(""))`;
  (b) wallet created under a valid password, then `reset_password(.., "")`.
- **Ausschnitt (red run):**
  ```
  AUDIT-W4-STO-604 VIOLATION (a): FileStorage::save_wallet accepted an EMPTY
  password for the initial wallet save and wrapped the master file key under
  KDF("", salt) — a deterministic credential anyone with profile.enc (cloud
  sync, stolen backup) can reconstruct offline, decrypting the full wallet
  incl. the raw signing key. Zero-entropy credentials must be rejected with
  StorageError::Generic before persistence (CWE-521/CWE-1392); got Ok("Ok(())").
  ```
  (The test additionally fails on aspect (b): reset rewrites profile.enc
  instead of rejecting without rewrite.)
- **KDF cfg-split honored:** the test asserts acceptance behavior only (never
  KDF determinism); SHA256 fast path under `test-utils` vs Argon2id in release
  is documented in the test docblock and irrelevant to the assertions.
- **Fix-Notiz:** Reject empty credentials in `save_wallet` (initial save AND
  update path) and `reset_password` with `StorageError::Generic` BEFORE any
  key derivation/persistence — parity with the HMSEC-SA05-10 archive guard.

## AUDIT-W4-STO-605 / WH4-05-004 — BLOCKED (LOW)

- **No test written.** Rationale: a faithful SA05-06-style heap-canary probe
  through `FileStorage::save_wallet`/`load_wallet` requires capturing interior
  heap pointers of buffers (`file_key`, `password_key`/`mnemonic_key` KDF
  outputs, decrypted `ProfilePayload.signing_key_bytes`) that exist ONLY inside
  library-private scopes. Unlike SA05-06 (which constructed the
  `SecureContainer` directly in the test and could capture pointers before
  drop), these allocations cannot be reached from an integration test without
  modifying src/ (exposing internals or injecting instrumentation) — which is
  forbidden in this phase. A proxy probe (e.g. canaried signing keys passed
  via `setup_voucher_with_one_tx`) cannot prove retention of the specific
  FileStorage working copies and would produce a false-confidence result.
- **Fix-Notiz (for the fixing phase):** mechanical — wrap the sensitive local
  copies in `zeroize::Zeroizing<Vec<u8>>` / call `.zeroize()` before scope exit:
  `file_key`/`password_key`/`mnemonic_key` (file_storage.rs ~372–434),
  decrypted payload bytes (~277–283), `ProfilePayload.signing_key_bytes`
  (~131–134, or make it `Zeroizing`), plaintext store bytes (~325–329).
  Regression shield should then be a unit test INSIDE the crate where pointers
  are capturable.

---

### Koordinator-Notizen

1. 601 und 602 sind unabhängig ausnutzbar (Hypothesen-Dedupe #1 bestätigt):
   601 überlebt ein perfektes Set-Manifest; der 602-Fix allein schließt 601
   nicht. Gemeinsame Fixrichtung: keyed per-record content hash im Manifest.
2. Alle vier roten Tests asserten ausschließlich Soll-Verhalten und dienen
   nach dem Fix als permanente Regression Shields (Fail-First-TDD-Protokoll).
3. Dedupe-Unsicherheit #2 (Host-Layer-Passwort-Policy) bleibt offen — der Test
   pinnt die Core-Garantie analog SA05-10; falls eine dokumentierte
   Host-Verantwortung existiert, ist Reklassifikation zu Outcome-B möglich,
   der Test bleibt dann als dokumentierter Invariantentest bestehen.
