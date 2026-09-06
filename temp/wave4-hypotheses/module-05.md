# Wave 4 — Hypotheses Module 05: Storage, Archive & Key Persistence

> Agent: A-05 (Wave 4). Scope: `src/storage/file_storage.rs`, `src/storage/mod.rs`,
> `src/archive/file_archive.rs`, `src/services/mnemonic.rs`, `src/models/profile.rs`,
> `src/models/secure_container.rs`, key-derivation helpers in
> `src/services/crypto_symmetric.rs`. Research-only; no code edited, no git ops.
> Dedupe basis: cumulative `05_storage_report.md` (SA05-01..11), STATUS.md
> (2026-08-25), `temp/security-triage-report.md` (K1–K4/W1–W6/N1–N11).
>
> Checked and discarded as already-known/open (NOT re-reported): torn two-file
> rename sequence without fsync + post-fix brick (WH3-05-503 carried forward),
> lock TOCTOU / PID reuse (H-05-03 open), raw IDs as archive filenames /
> metadata leak (WH3-05-507 / N6), PBKDF2-per-record O(N·KDF) cost (N7),
> PBKDF2 100k < OWASP 210k rounds policy (H-05-05 open), archive fail-closed
> scan availability trade-off (W5), empty-password guard for the ARCHIVE
> (SA05-10, fixed), mnemonic printlns found in `mnemonic.rs:480/544–554`
> are inside `#[cfg(test)] mod tests` → no production leak.
>
> Scope exclusions honored: HMC-SEC-02-05 seal history, audit_02_11, SA04-08,
> sa06_07 not touched.

---

## WH4-05-001: Same-directory record content substitution silently rolls back archived voucher history

- Severity: HIGH | CWE: CWE-354 (Integrity Check Value Manipulation) / CWE-345
- Target: src/archive/file_archive.rs:~567–590 (`get_archived_voucher` manifest set check), ~349–389 (`read_record` location binding), ~392–461 (`read_manifest`/`collect_record_ids`)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: Local attacker with disk write access (the exact attacker of SA05-04/05/09) overwrites the bytes of record `<t_id_new>.json` with the bytes of an older genuine record from the SAME voucher directory (copy older state over newer filename, or swap two records). The sealed manifest pins only the SET of record IDs — which is unchanged; AEAD verifies content authenticity but not freshness/generation; the location binding only compares `voucher_id` against the parent directory. Every check passes and `get_archived_voucher` serves the rolled-back history (newest state replaced by an older one) with zero detection — precisely the forensic rollback outcome HMSEC-SA05-09 was meant to make impossible ("deleting the newest record silently served the older state"). Deleting the newest spend evidence this way can launder a double-spend dispute.
- Broken Invariant: "Manipulations … in archived vouchers must be detected deterministically before data is deserialized" extends beyond bit-flips to whole-record *substitution within a directory*: the manifest must authenticate not only WHICH record IDs exist but WHICH CONTENT each record ID carries (per-record generation binding).
- Fail-First-Test-Skizze: In `tests/security_audit_module_05_storage.rs`: build `FileVoucherArchive::with_key(dir, k)`; archive three evolving states via `archive_voucher` (chain grows t1→t2→t3, distinct chain lengths); let `dir/t3_id.json` be the newest record. Attack: `fs::copy("<dir>/<t2_id>.json>", "<dir>/<t3_id>.json>")`. SOLL assertion: `get_archived_voucher(voucher_id)` returns `Err(ArchiveError::IntegrityViolation)` (and `find_transaction_by_id(t3)` must not serve the forged pair). IST on unpatched code: returns `Ok(state@t2)` → test FAILS, proving the vulnerability. Control assertion: unmodified archive still loads `Ok` (no false positive from the new binding).
- Dedupe-Check: SA05-02 covered bit-flips (AEAD), SA05-05 whole-file plaintext replacement (downgrade), SA05-09 whole-record delete/relocate ACROSS directories (set equality + location binding). The same-directory content-swap/freshness gap is named nowhere: SA05-09's documented residual covers only foreign-voucher deletion during global scans; WH3-05-503 is crash-torn writes, 507 is filename metadata. New.

---

## WH4-05-002: Manifest re-sync launders delete+inject tampering and permanently enshrines junk records

- Severity: MEDIUM | CWE: CWE-354 / CWE-345
- Target: src/archive/file_archive.rs:~473–498 (`sync_manifest`: shrinkage-only refusal at ~480–489, bootstrap-from-disk at ~497), interplay with ~514–555 (`archive_voucher` bookkeeping)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE
- Threat Model: The SA05-09 bookkeeping refuses rewrite only when the on-disk set SHRANK and is a strict subset of the manifest. Two interleavings defeat it: (a) an attacker deletes the newest record AND adds any extra `.json` file (e.g. a copy of a genuine record under a fresh name or a zero-byte/junk file) — the set no longer shrank, so the next legitimate `archive_voucher` rewrites the manifest over the tampered state, laundering the deletion forever after; with a junk file the victim additionally gets a PERMANENT `IntegrityViolation` on every future `get_archived_voucher` (fail-closed brick amplified from transient W5 bit-rot to persistent, self-healing-never). (b) An attacker who deletes the manifest itself plus records enjoys silent bootstrap from disk contents on the next legit write — deletion detection reset without any error.
- Broken Invariant: "A shrinking record set while the manifest is intact refuses rewrite (no deletion laundering via interleaved writes)" — the guard must hold against arbitrary divergences (grow/substitute/mixed) and manifest deletion, not only pure shrinkage.
- Fail-First-Test-Skizze: Archive two genuine states (manifest intact). Attack: remove `<t2>.json`, add `<junk>.json` containing `{}`. Call `archive_voucher(third_state)` (legitimate write). SOLL: either the sync refuses with `IntegrityViolation`, or subsequent `get_archived_voucher` deterministically reports the divergence. IST on unpatched code: sync rewrites the manifest to `{t1, junk, t3}` (no error) and `get_archived_voucher` now fails permanently with `IntegrityViolation("not valid JSON")` — first assertion FAILS, proving laundering+brick. Second variant: delete manifest + `t2.json`, one legit write, assert `IntegrityViolation` — currently returns `Ok`.
- Dedupe-Check: SA05-09 fixed read-side detection and introduced exactly this narrow shrinkage heuristic; its residual note documents only foreign-record NotFound degradation. The laundering-by-interleaving and manifest-deletion-bootstrap vectors are unreported; WH3-05-503 (crash brick, needs recovery API) is a different mechanism (no attacker action). New.

---

## WH4-05-003: FileStorage accepts zero-entropy passwords at wallet creation and password reset (archive asymmetry)

- Severity: MEDIUM | CWE: CWE-521 (Weak Password Requirements) / CWE-1392
- Target: src/storage/file_storage.rs:~380–417 (`save_wallet` initial save — no password check before `derive_key_from_password`), ~473–509 (`reset_password` — accepts empty `new_password`), ~1610–1633 (`derive_key_from_password`)
- Status-Vermutung: KNOWN-OPEN-DEEPDIVE (N7 deepened)
- Threat Model: `FileStorage` wraps the persistent file key under BOTH a password-derived key and a mnemonic-derived key — but the password wrap ALONE recovers the master file key (`get_file_key`, Password branch). `FileStorage::new`/`save_wallet`/`reset_password` never reject an empty (or trivially weak) credential, so a wallet created/reset with `""` is protected by Argon2id("", salt): deterministic, offline-reconstructable by anyone who obtains `profile.enc` (cloud-synced folder, stolen backup) — the full wallet incl. private signing key decrypts. The SA05-10 triage argued FileStorage was unlike the archive because of a "second factor downstream", but that factor does not protect the password unwrap path at all; the archive got a seal-time guard, the storage layer did not. Possible mitigating argument (why only DEEPDIVE): host apps/Tauri wrapper may enforce password policy before calling core — must be verified/documented, core-level guarantee is absent (same reasoning that justified SA05-10's in-core guard).
- Broken Invariant: At-rest confidentiality invariant #1 must not depend on caller discipline: credentials that produce deterministic, zero-entropy derived keys must be rejected before key material is wrapped/persisted (parity with HMSEC-SA05-10).
- Fail-First-Test-Skizze: SOLL test: `FileStorage::new(tmp)/save_wallet(profile, store, identity, &AuthMethod::Password(""))` must return `Err(StorageError::Generic(_))` and leave no `profile.enc` on disk; likewise `reset_password(identity, "")` must be rejected without rewriting the container. IST on unpatched code: both return `Ok(())` and persist a container whose `password_wrapped_key_with_nonce` decrypts under Argon2id("")/SHA256("") (test-utils fast path) — assertions FAIL, proving the gap. Note: keep the existing release/test KDF cfg-split in mind when asserting determinism.
- Dedupe-Check: SA05-10 + its test cover ONLY `FileVoucherArchive::seal_record`; wave-2 report deferred H-05-05 (KDF policy) and N7 names the archive constructor. No prior finding targets `FileStorage::save_wallet`/`reset_password` credential acceptance. New target, same defect class.

---

## WH4-05-004: Storage-layer key material and decrypted payloads are never zeroized (coverage gap outside SecureContainer)

- Severity: LOW | CWE: CWE-244 / CWE-459 (heap memory not cleared before release → retained secrets in freed memory)
- Target: src/storage/file_storage.rs:~372–434 (`file_key`, `password_key`, `mnemonic_key` as plain locals), ~277–283 (`payload_bytes` = decrypted JSON containing `signing_key_bytes`), ~131–134 (`ProfilePayload.signing_key_bytes: Vec<u8>` — plain copy of the Ed25519 seed), ~325–329 (`store_bytes` plaintext voucher store)
- Status-Vermutung: CONFIRMED-VULN-CANDIDATE (defense-in-depth coverage gap, SA05-06 precedent)
- Threat Model: SA05-06 hardened `SecureContainer::drop` after proving wrapped payload keys survive in freed heap. The same class exists one layer down: every `load_*/save_*` path materializes the master file key, KDF outputs, and — worst — the decrypted `ProfilePayload` holding the RAW SIGNING KEY BYTES as ordinary `Vec<u8>`s that are dropped without zeroization (in contrast, `UserIdentity` in `models/profile.rs:17–28` deliberately uses `ZeroizeOnDrop`). Crash dumps, swap files, or heap scrapers can recover the identity seed from stale allocations; mutant-removal of any future zeroize would again survive the suite untested.
- Broken Invariant: "Sensitive key material and decrypted secrets should not linger unnecessarily in heap memory" (audit instruction #4 / invariant #4) — currently enforced for SecureContainer and UserIdentity but not for the FileStorage working copies of the very same secrets.
- Fail-First-Test-Skizze: Unsafe heap-inspection probe in the style of `sa05_06_*`: construct a `ProfilePayload`-equivalent buffer path through `FileStorage::save_wallet`/`load_wallet` with a canary signing key, force drop of the intermediate buffers (scope exit), inspect freed chunk suffixes (byte ≥32, per SA05-06 allocator-metadata technique). SOLL: all canary bytes cleared (or type carries `ZeroizeOnDrop`). IST: canary survives → FAIL proves retention. Marked LOW because exploitation requires post-mortem memory access; fix is mechanical (`Zeroizing<Vec<u8>>`/explicit `zeroize()` before drop).
- Dedupe-Check: SA05-06 scoped to `SecureContainer` fields (encrypted_key/salt); profile.rs UserIdentity already ZeroizeOnDrop and guarded elsewhere. FileStorage local key/plaintext copies are covered by no test and no finding in waves 1–3. New.

---

## Sortierung & Zählung

| Severity | Count | Findings |
| :--- | :--- | :--- |
| CRITICAL | 0 | — |
| HIGH | 1 | WH4-05-001 |
| MEDIUM | 2 | WH4-05-002, WH4-05-003 |
| LOW | 1 | WH4-05-004 |

### Dedupe-Unsicherheiten (für Koordinator)

1. **WH4-05-001 vs. WH4-05-002**: verwandt (Manifest bindet nur ID-Set), aber unabhängig ausnutzbar — 001 braucht keinen Folgeschreibvorgang und überlebt einen perfekten Set-Manifest; Fix für 002 (Rewrite-Verweigerung bei beliebiger Divergenz) alone schließt 001 nicht. Empfohlen: getrennt bewerten, gemeinsame Fixrichtung (keyed per-Record-Hash im Manifest analog `derive_store_binding_hash`).
2. **WH4-05-003**: falls der Tauri-/AppService-Layer nachweislich eine Passwort-Policy erzwingt UND das dokumentiert ist, wäre Reklassifikation zu Outcome-B (dokumentierte Host-Verantwortung + Invariantentest) vertretbar — mir ist keine solche Doku bekannt (PRIVACY_FAQ/design-decisions schweigen dazu).
3. **Storage Integrity layer**: Ich habe NICHT beansprucht, dass Rollbacks von `own_fingerprints.enc`/`proofs.enc` etc. undetektierbar sind — der signierte `LocalIntegrityRecord` deckt Hauptverzeichnis-Dateien ab; ob er kombinierte Record+Integrity-Datei-Rollbacks (gleiche Epoche) fängt, war ohne Vertiefung von `integrity_manager.rs`/Seal-Epochen nicht sicher zu entscheiden und wurde bewusst nicht als Finding geführt (mögliches Wave-5-Thema).
