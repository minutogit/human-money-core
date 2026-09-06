# Module 05 — Fresh Hypotheses (Storage & Key Persistence)

Fresh-eyes audit of `docs/security/ai-audits/05_storage_and_key_persistence.md`.
Scope read in full: `src/storage/mod.rs`, `src/storage/file_storage.rs`, `src/archive/mod.rs`,
`src/archive/file_archive.rs`, `src/services/mnemonic.rs`, `src/models/profile.rs`,
`src/models/storage_integrity.rs`, `src/services/integrity_manager.rs`, plus the persistence-relevant
callers (`src/wallet/lifecycle.rs`, `src/wallet/maintenance.rs`, `src/app_service/lifecycle.rs`,
`src/app_service/mod.rs`, `src/app_service/seal_handler.rs`, `src/app_service/data_encryption.rs`,
`src/services/crypto_symmetric.rs`, `src/services/crypto_keys.rs`, `src/services/crypto_utils.rs`,
`src/bin/voucher-cli.rs`). All findings verified against actual code; no prior audit reports consulted.

## Coverage Matrix

| # | Audit instruction / checkpoint | Status | Note |
|---|---|---|---|
| 1 | At-Rest Confidentiality: keys/seeds never persisted plaintext | **FINDING** | HYP-05-04: shipped CLI binary writes raw mnemonic + raw signing key unencrypted (voucher-cli.rs:88-104). Wallet core itself encrypts correctly. |
| 2 | Encryption at rest strictly enforced (ChaCha20-Poly1305 / Argon2id) | CLEAN (core) / FINDING (KDF) | Wallet containers and archive envelopes are AEAD-sealed before disk; plaintext-downgrade rejected (file_archive.rs:234-255). KDF weakness: HYP-05-05. |
| 3 | Crash Consistency & Atomic Writes (write-temp-then-rename) | **FINDING** | tmp+rename used per-file, but no fsync anywhere (HYP-05-02); multi-file save has torn-write windows with only partial mitigation (HYP-05-03); generation counter written *before* data; profiles.json non-atomic (HYP-05-08). |
| 4 | Storage Integrity: bit-flips/tampering detected deterministically before deserialize | CLEAN / **FINDING** | AEAD tag verified before serde in all readers; legacy schema gates pre-deserialize (file_storage.rs:1472-1555). Residual: whole-record deletion laundered via manifest bootstrap (HYP-05-10). |
| 5 | Memory Hygiene: no lingering secrets, no debug-log leakage of key material | **FINDING** | Partial: `UserIdentity` is `ZeroizeOnDrop`, but session key cache, decrypted file keys, and archive password String are never zeroized (HYP-05-07). Log/Error disclosure: CLEAN (checked error.rs, StorageError, ArchiveError, model Debug derives; German mnemonic error already hardened at mnemonic.rs:425-436). |
| 6 | Map FileStorage/FileVoucherArchive: KDF, serialization, locking, directory structure | **FINDING** | Mapping complete. File-locking mechanism has TOCTOU race (HYP-05-01); lock acquired too late during login-time writes (HYP-05-09). |
| 7 | Key leakage paths: export / backup / unauthenticated profile save | **FINDING** | Only the dev/issuer CLI leaks plaintext (HYP-05-04). `save_wallet` requires valid auth to unwrap the file key on update; no export path serializes identity secrets (all `export_*` functions emit only public JWS profile, fingerprints, standards). |
| 8 | Weak KDF / static salts / predictable nonces | **FINDING** | Wallet password KDF = Argon2id defaults (m=19MiB,t=2,p=1) -> OK; nonces from OsRng per encryption (crypto_symmetric.rs:50) -> OK; salts random per container -> OK. Findings: PBKDF2-SHA512@100k for archive records (HYP-05-05), static global salt for folder-name derivation (HYP-05-06). Test-only SHA-256 KDF is compile-gated behind `test-utils` (file_storage.rs:1614-1624), documented as release-forbidden. |
| 9 | Partial Write Corruption: voucher removed from active storage before archive commit? | CLEAN (with note) | Archiving is additive; vouchers are not deleted from active storage during archiving. The torn multi-file save window itself is covered by HYP-05-03. |
| 10 | Tampering & integrity bypass on archived vouchers (amount/validity change) | CLEAN | Any content modification breaks the AEAD tag -> `IntegrityViolation` before deserialization (file_archive.rs:308-332); relocated records rejected by location binding (349-388); injection/deletion detected by sealed-manifest set-equality (563-590) -- except the deletion-laundering gap (HYP-05-10). |
| 11 | Log/Error Disclosure in Display/Debug impls | CLEAN | `UserIdentity` deliberately has no Debug/Serialize derive (profile.rs:18-30); StorageError/ArchiveError strings carry IDs/messages only; `Wallet::load` logs user_id only (public DID, lifecycle.rs:119-124); German mnemonic validation errors carry positional info only (mnemonic.rs:425-436). |
| 12 | Open exploration: filesystem races, novel anomalies, unstated assumptions | **FINDING** | Lock-file TOCTOU (HYP-05-01), login-time unlocked writes (HYP-05-09), manifest bootstrap laundering (HYP-05-10), plaintext dev-key persistence (HYP-05-04). |

---

## Hypotheses

### HYP-05-01: Wallet lock acquisition is not atomic (TOCTOU) - two processes can both "hold" the exclusive lock
- Severity: HIGH
- CWE: CWE-367 (Time-of-check Time-of-use Race); related CWE-362
- Target: src/storage/file_storage.rs:944-992 (esp. 950-991)
- Attack:
  1. Process A and process B both start an operation on the same profile directory.
  2. Both run `lock()`: both observe `lock_file_path.exists() == false` (or both read the same stale PID), so neither sees a live holder.
  3. Both call `fs::File::create(&self.lock_file_path)` (line 988); `File::create` opens/truncates without exclusivity, so both succeed.
  4. Both receive `Ok(true)` ("newly locked") and proceed with concurrent read-modify-write cycles (`Wallet::save`, bundle creation), interleaving tmp+rename generations of profile.enc/vouchers.enc.
  5. If profile.enc and vouchers.enc land from different save cycles, every later `load_wallet` hard-fails with `StateConflict` (store_binding_hash mismatch, file_storage.rs:305-320) -> wallet permanently unloadable through standard APIs.
- Root cause: Check (`exists()` -> PID read -> liveness probe) and acquire (`File::create`) are separate syscalls with no atomicity primitive: no `OpenOptions::create_new(true)` (O_EXCL), no flock/fcntl, no rename-based acquire. Verified by grep: zero hits for `create_new|O_EXCL|flock` in src/. Additionally, the second acquirer's RAII guard deletes the lock on drop while the first still believes it holds it, admitting a third writer.
- Confidence: HIGH (code fact; exploitation needs a process-start race, but that window recurs on every launch).
- Testable: YES - integration test spawning two child processes (same test binary, env-selected mode) looping `storage.lock()` against one temp dir; secure invariant: never two simultaneous `Ok(true)`. On current code overlapping `Ok(true)` occurs within the loop -> test fails.

### HYP-05-02: No fsync around atomic renames - power loss can persist renames ahead of file data
- Severity: MEDIUM
- CWE: CWE-459 (Incomplete Cleanup) / crash-consistency violation
- Target: src/storage/file_storage.rs:461-468 (save_wallet), 502-506 (reset_password), 557-564, 615-622, 697-704, 782-789, 848-855, 889-890, 1072-1079, 1136-1144, 1294-1296, 1342-1344; src/archive/file_archive.rs:437-439, 544-546
- Attack:
  1. `Wallet::save` writes profile.enc.tmp and vouchers.enc.tmp, then renames both onto the live files.
  2. Power failure between data write and journal commit of the rename (safe ordering is guaranteed only on e.g. ext4 data=ordered; not on all FS/configurations) leaves the renamed target truncated/garbage.
  3. Next load: AEAD/JSON failure -> `InvalidFormat`; wallet unloadable (or archive record -> `IntegrityViolation`). Detection works, but there is no recovery copy: the previous good version was destroyed by the rename.
- Root cause: All "atomic" writes use `fs::write` + `fs::rename` without `File::sync_all()` on the temp file before rename and without directory fsync afterwards. Verified: `rg 'sync_all|sync_data'` over src/ returns zero hits. Durability is delegated entirely to host-FS defaults.
- Confidence: HIGH (absence is fact; real-world impact depends on host FS).
- Testable: NO - requires fault-injected/power-cut I/O stack (dm-flakey or LD_PRELOAD shim); not expressible as an ordinary Rust integration test.

### HYP-05-03: Multi-file save is not transactional and generation counter advances BEFORE data writes - partial failures strand state
- Severity: HIGH
- CWE: CWE-460 (Improper Cleanup on Handled Exception) / non-atomic multi-resource update
- Target: src/wallet/lifecycle.rs:261-291 (`Wallet::save`, esp. line 274 vs. 277-286); src/storage/file_storage.rs:453-468 (two sequential renames)
- Attack:
  1. `Wallet::save` bumps `.wallet.generation` N->N+1 on disk first (lifecycle.rs:274), then writes seven independent files (profile+vouchers bound pair, bundles.meta.enc, known_fingerprints.enc, own_fingerprints.enc, proofs.enc, fingerprint_metadata.enc, event chunks).
  2a. Crash between the two renames in `save_wallet` (line 467 vs 468): new profile.enc references the binding hash of the NEW store while the old vouchers.enc persists -> mandatory binding check rejects load with `StateConflict` (fail-loud by design) - but there is no recovery path: `load_wallet` always refuses and even `recover_wallet_and_set_new_password` routes through `Wallet::load` (app_service/lifecycle.rs:310-349), so the wallet is bricked for all standard flows although the intact new store still sits in vouchers.enc.tmp.
  2b. I/O error mid-save (e.g. ENOSPC at save_proofs after save_wallet succeeded): disk holds new vouchers + stale proofs/bundle metadata + generation N+1 while the seal still anchors the OLD state. In `AppService::with_transactional_mut` the compensation path (`compensate_failed_seal_phase`, app_service/mod.rs:544-561) covers ONLY seal-phase failures; a failure inside `Wallet::save` propagates without compensation (mod.rs:434-443). Every subsequent mutating command reloads the new state, fails `verify_state_matches_seal` (seal_handler.rs:606-629, `StateRollbackDetected`) -> wallet blocked until full mnemonic recovery.
  2c. Direct `Wallet` users (no AppService): stale proofs.enc/bundles.meta.enc silently persist next to advanced vouchers.enc; recent double-spend proofs can be lost permanently (they existed only in memory pre-crash).
- Root cause: Seven independent tmp+rename units plus a separately persisted counter, counter incremented FIRST, no journal/WAL spanning them. The keyed `store_binding_hash` (good hardening) protects exactly one pair (profile<->vouchers) and nothing else; the seal/state-hash gate converts partial failures into a persistent refusal state rather than a recoverable one.
- Confidence: HIGH for the code paths; MEDIUM for trigger frequency (needs crash/error inside a narrow window).
- Testable: YES - delegate `Storage` to `FileStorage` in a wrapper whose `save_proofs` returns Err(Io). Secure invariant: after failed `Wallet::save`, `read_generation()` unchanged AND `load_wallet` yields pre-save state. Current code: generation already advanced when save_proofs runs -> assertion fails.

### HYP-05-04: Shipped CLI binary writes raw mnemonic and raw private key unencrypted to disk
- Severity: HIGH (literal plaintext seed exposure per rubric would be CRITICAL; downgraded because this is the issuer/dev-tooling path outside the wallet threat model - expect `[INTENTIONAL DESIGN REQUIREMENT]` triage, but permissions/hardening are still missing)
- CWE: CWE-312 (Cleartext Storage of Sensitive Information)
- Target: src/bin/voucher-cli.rs:84-104 (mnemonic at 88-93, raw key bytes at 99-104)
- Attack:
  1. Issuer runs `voucher-cli generate-keys` (documented workflow; binary ships via Cargo.toml `[[bin]]`).
  2. Tool writes target/dev-keys/issuer.mnemonic (full BIP-39 seed phrase) and target/dev-keys/issuer.key (raw 32-byte Ed25519 private key) with default umask (no 0600 restriction).
  3. Any local actor, backup job, CI artifact cache, or cloud-synced target/ folder exfiltrates the issuer identity that signs voucher standards -> silent impersonation of a trust anchor.
- Root cause: `fs::write(&key_path, signing_key.to_bytes())` and plain mnemonic write: no encryption envelope (the crate's own ChaCha20/PBKDF2 helpers are in-repo), no permission restriction, no warning output.
- Confidence: HIGH.
- Testable: YES - run generate flow against temp dir; secure invariant: neither file contains raw key bytes nor the plaintext word sequence (encrypted-envelope format present instead). Current code writes raw bytes -> test fails.

### HYP-05-09: Login performs multiple writes BEFORE acquiring the wallet lock
- Severity: MEDIUM
- CWE: CWE-667 (Improper Locking); related CWE-362
- Target: src/app_service/lifecycle.rs:202-301 (load @224, event-flush save @228-232, cleanup save @252-272, seal migration write @279-281, lock acquisition only @283-286); same pattern in create_profile (writes @133-157 before lock @161-163) and force handover (seal+integrity writes @520-533 before lock @536)
- Attack:
  1. Two app instances call `login()` for the same folder with the correct password.
  2. Both perform full read-modify-write cycles - including `wallet.save()` (event flush) and `migrate_seal_on_login` (`save_seal`) - with no exclusion, since the lock is only acquired after all writes.
  3. Interleaving loses flushed events/pending state (last-writer-wins) and can leave seal.enc from process A against data files from process B -> next login trips the seal state-hash gate (seal_handler.rs:468-476) -> `StateRollbackDetected`, recovery forced.
- Root cause: Lock discipline enforced in `with_transactional_mut` (app_service/mod.rs:359-361) is absent from lifecycle entry points that themselves mutate; the terminal `storage.lock()` provides no protection for preceding writes.
- Confidence: HIGH (ordering explicit in code).
- Testable: YES - two child processes racing login(cleanup_on_login=true) in a loop against one seeded wallet where each emits a distinct pending event; secure invariant: no event ever disappears, no login ends in StateRollbackDetected. Current code loses updates under contention -> test fails.

### HYP-05-10: Archive manifest bootstrap launders whole-record deletions (rollback of forensic history)
- Severity: MEDIUM
- CWE: CWE-693 (Protection Mechanism Failure)
- Target: src/archive/file_archive.rs:473-498 (`sync_manifest` bootstraps a MISSING manifest from current disk contents), invoked unconditionally from `archive_voucher` at lines 533 and 552
- Attack:
  1. A local attacker (or a sync tool restoring an old folder) deletes the newest sealed state `<voucher_id>/<latest_tx>.json` together with `archive_manifest.sealed` - neither operation needs key material.
  2. The next legitimate `archive_voucher()` for that voucher finds no manifest; `sync_manifest` bootstraps a fresh sealed manifest over the shrunken record set. The shrinkage-refusal logic (480-489) is skipped precisely because the manifest is gone.
  3. From then on manifest set-equality passes; `get_archived_voucher` serves the truncated history as complete. The rollback HMSEC-SA05-09 was designed to detect becomes undetectable - removing exactly the evidence double-spend forensics relies on.
- Root cause: Asymmetric handling: shrinkage under an INTACT manifest refuses (correct), but shrinkage under a MISSING manifest silently re-baselines, although a missing manifest is exactly the "deletion cannot be ruled out" condition readers treat as fatal (567-574).
- Confidence: HIGH.
- Testable: YES - archive two states, delete newest record + manifest, then archive_voucher a third state; secure invariant: must fail with IntegrityViolation (or quarantine marker), never silently re-baseline. Current code succeeds -> test fails.

### HYP-05-07: Decrypted key material and cached session keys are never zeroized (partial memory hygiene)
- Severity: MEDIUM
- CWE: CWE-316 (Cleartext Storage of Sensitive Information in Memory)
- Target:
  - src/app_service/mod.rs:96-103 (`SessionCache.session_key: [u8;32]`, no Drop/zeroize, lives for whole unlock session; copied by value at mod.rs:582)
  - src/storage/file_storage.rs:130-134 (`ProfilePayload.signing_key_bytes: Vec<u8>` - decrypted master private key material, no ZeroizeOnDrop), 232-239 + 1570-1601 (`get_master_key_from_auth`/`get_file_key` return buffers never scrubbed), 372-434 (file_key and wrapped-key buffers)
  - src/archive/file_archive.rs:103-109 + 143-148 (`ArchiveKeySource::Password(String)` retains the raw wallet password for the archive object's lifetime)
- Attack: memory-scraper malware or heap core dump post-logout recovers file key / session key / archive password from freed-but-unscrubbed pages, then decrypts profile.enc offline. Contrast: `UserIdentity` is correctly `ZeroizeOnDrop` (models/profile.rs:14-30) - hygiene policy inconsistently applied.
- Root cause: zeroize is a dependency (Cargo.toml) and used for UserIdentity/SecureContainer, but no storage-layer key buffer implements Zeroize/ZeroizeOnDrop; AuthMethod propagates password/session-key copies freely.
- Confidence: HIGH (fact); impact MEDIUM.
- Testable: YES (heuristic) - runtime heap-scan for known key pattern after drop is flaky; better a type-level assertion (static assert that key-holding types implement ZeroizeOnDrop) which currently fails to compile.

### HYP-05-05: Archive password-mode uses PBKDF2-HMAC-SHA512 at 100k iterations (below OWASP guidance; inconsistent with wallet KDF)
- Severity: MEDIUM
- CWE: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- Target: src/services/crypto_symmetric.rs:214-227 (encrypt) and 252-265 (decrypt); consumed by src/archive/file_archive.rs:193-194
- Attack: Attacker with archive files (stolen laptop/cloud-synced folder - the module's stated threat model) runs offline dictionary attacks against pbkdf2-sha512 envelopes at 100k rounds - below OWASP's 210k recommendation for PBKDF2-HMAC-SHA512 and far weaker than the memory-hard Argon2id protecting the same wallet's main container. Weak passwords fall fastest exactly where voucher history (amounts, counterparties) lives.
- Root cause: Hardcoded `PBKDF2_ROUNDS = 100_000`; doc comment (file_archive.rs:21-22) claims parity with the ProfileStorageContainer pattern, but that container migrated to Argon2id - stale claim vs. reality.
- Confidence: HIGH (parameter fact); exploitability depends on password strength.
- Testable: NO cleanly - iteration count not exposed publicly; wall-clock assertions flaky. Recommend exposing a KFD-parameter descriptor or asserting envelope advertises Argon2 once remediated.

### HYP-05-06: Static global salt + delimiter-free concatenation for secret-derived profile folder names
- Severity: LOW
- CWE: CWE-759 (Use of a One-Way Hash with a Predictable Salt); also CWE-760; concatenation ambiguity (no domain separation between mnemonic/passphrase/prefix)
- Target: src/services/crypto_constants.rs:22 (`ARGON2_PROFILE_FOLDER_SALT = b"human-money-profile-folder-v1"`); src/app_service/mod.rs:157-174
- Attack:
  1. Folder name = Argon2id(mnemonic || passphrase || prefix, GLOBAL constant salt).
  2. Because the salt is identical on every installation, an attacker can precompute one dictionary mapping candidate mnemonics -> folder names and reuse it against any stolen profiles.json/directory listing (linkability + faster brute force of weak seeds).
  3. Delimiter-free concatenation additionally allows tuple collisions (passphrase="x", prefix="yz" == passphrase="xy", prefix="z") -> folder-name collisions between distinct identities (creation-time DoS/confusion; low practical impact since identities differ).
- Root cause: Constant salt chosen for deterministic folder naming; no per-wallet random component and no length-prefixed/domain-separated input encoding. Note: determinism appears deliberate (folder-collision detection at create_profile), so triage may mark intentional - the collision ambiguity remains a defect regardless.
- Confidence: HIGH (fact); impact LOW.
- Testable: YES - assert that equal-concatenation tuples ("ab"+"c" vs "a"+"bc") yield different folder names (fails today), and structurally that the salt is not a hardcoded shared constant.

### HYP-05-08: profiles.json index written non-atomically (and delete order risks residue)
- Severity: LOW
- CWE: CWE-460 (Improper Cleanup) / torn metadata update
- Target: src/app_service/lifecycle.rs:170-174 (create_profile index write), 602-606 (delete_profile index rewrite before remove_dir_all at 609)
- Attack:
  1. Crash/power loss during `fs::write(index_path, ...)` truncates or half-writes profiles.json.
  2. Next start: `list_profiles` fails to parse (or silently drops entries, depending on corruption point) -> ALL wallets disappear from the login UI although encrypted data on disk is intact; recovery requires manual JSON surgery.
  3. In delete_profile, crash between index rewrite and remove_dir_all leaves an orphaned encrypted folder still listed nowhere (privacy residue until manual cleanup).
- Root cause: Only direct fs::write for the central index, unlike every wallet payload which uses tmp+rename; no atomic swap and no ordering guarantee between index and directory lifecycle.
- Confidence: HIGH (code fact).
- Testable: PARTIAL - the non-atomicity itself is not triggerable in-process; a structural test can assert index updates go through tmp+rename (would fail today).

---

## Gaps

Instructions/checkpoints that produced NO finding:

- **Nonce/salt handling in the core wallet**: clean - OsRng nonces per encryption (crypto_symmetric.rs:50,123), fresh 16-byte salts per container creation (file_storage.rs:386-401), keyed mandatory store-binding commitment (file_storage.rs:449-451, checked at load 305-320).
- **Content tampering of archived vouchers**: clean - AEAD-before-deserialize invariant holds everywhere; unknown KDF identifiers, stripped envelopes, legacy plaintext downgrade, relocation, and injection are all rejected deterministically.
- **Log/error disclosure**: clean - no Display/Debug path formats signing keys, mnemonics, passwords, or decrypted payloads; UserIdentity intentionally derives no Debug; the German wordlist validator already avoids echoing phrase material.
- **Path traversal in arbitrary data blocks**: clean on both write and read sides (file_storage.rs:868-872, 902-907, validate_item_name 1444-1455).
- **Event-log consistency**: append deduplication by event_id makes legacy migration and re-append idempotent under crashes; events are cleared from memory only after successful persist.
- **Session-key verification**: `test_session_key` correctly validates via AEAD unwrap attempt; wrong keys cannot pass.

Uncertain items and why:

- **Full-snapshot rollback of the entire wallet folder** (attacker restores profile.enc + vouchers.enc + own_fingerprints.enc + seal.enc together from an old backup): undetectable locally by construction (offline-first, no external monotonic anchor); partially mitigated by L2 epoch checks. Treated as accepted threat-model boundary ("Fraud Detection, Not Prevention"), not counted as a finding.
- **Missing vouchers.enc tolerated at load** (file_storage.rs:302-339): explicitly documented as recovery-friendly design, detected separately by the signed integrity layer as MissingItems; flagged for design-intent triage, not counted as a finding.
- **storage_integrity.json stored unencrypted** (signed, not confidential): documented trait contract (storage/mod.rs:249-259); leaks only hashed item names/metadata. Design-intent candidate.
- **Argon2 default parameters for the password KDF** (`Argon2::default()` = m=19MiB, t=2, p=1): meets OWASP baseline for Argon2id; noted as acceptable, though `derive_argon2_id` elsewhere uses t=3 - minor parameter inconsistency, no finding raised.
- **HYP-05-02 testability**: real proving requires power-fault injection hardware/tooling; reported as finding but marked not testable via ordinary integration tests.

Summary of findings (10 total): 0 CRITICAL / 3 HIGH (HYP-05-01 lock TOCTOU, HYP-05-03 non-transactional save, HYP-05-04 plaintext dev keys) / 5 MEDIUM (HYP-05-02 no fsync, HYP-05-05 PBKDF2@100k, HYP-05-07 memory hygiene, HYP-05-09 unlocked login writes, HYP-05-10 manifest laundering) / 2 LOW (HYP-05-06 static folder salt, HYP-05-08 profiles.json atomicity).
