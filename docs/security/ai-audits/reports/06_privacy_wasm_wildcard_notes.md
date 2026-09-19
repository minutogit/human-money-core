# Security Audit — Privacy, WASM/Bindings, Protocols, CLI & Assumption-Busting
**Date:** 2026-09-19  **Auditor:** Muse Spark (opencode)  **Scope:** privacy guard, SecureContainer, WASM FFI, CLI/file-storage, JWS, timestamps, canonicalization

---

## 1. SecureContainer: `sender:true` header de-anonymizes envelope even in `TrialDecryption`? No — but `HashedRouting`/`CleartextRouting` leak sender identity via `kid`+`sender:true`
- **File:line:** `src/models/secure_container.rs:295-300` (sender header construction) and `src/models/secure_container.rs:509-521` (open loop with `kid` match)
- **Severity:** **Medium** (privacy) / **Low** for `TrialDecryption` (not vulnerable)
- **Finding:** `TrialDecryption` intentionally sets `header=None` for both recipient and sender wraps — verified secure. However when caller selects `HashedRouting` or `CleartextRouting`, the sender's wrap is annotated with `{"kid": <hash|cleartext>, "sender": true}` distinct from recipient wraps. An eavesdropper observing the JWE `recipients[]` array (even without decryption) can (a) count participants (`recipients.len()-1` = real recipients), (b) trivially identify which entry belongs to the sender, and (c) in `CleartextRouting` learn `sender.user_id` in cleartext, in `HashedRouting` learn a stable pseudonym `hash(sender_id)` that is linkable across bundles. This defeats the anonymity goal of `TrialDecryption` if the app mistakenly picks a routing mode.
- **Protocol violation:** `PayloadType::TransactionBundle` must always use `TrialDecryption` per privacy matrix, but `SecureContainer::seal` accepts any `PrivacyMode` for any `PayloadType` — no gate enforces `TransactionBundle => TrialDecryption`.
- **PoC:**
  ```rust
  // Attacker passively collects JWE from relay/QR
  let container: SecureContainer = serde_json::from_slice(&intercepted_bytes).unwrap();
  for r in &container.recipients {
      if r.header.as_ref().and_then(|h| h.get("sender")).is_some() {
          println!("sender kid = {}", r.header.as_ref().unwrap()["kid"]); // de-anonymized
      }
  }
  // In CleartextRouting this prints "did:key:z6M..." directly; in HashedRouting it prints stable hash.
  // TrialDecryption: all headers == None → not vulnerable (verify by asserting headers.iter().all(|h| h.is_none())).
  ```
- **Recommendation:** Gate `ContainerConfig` in `app_service/transactions.rs:160` / `bundle_processor.rs:58` to reject `Hashed/CleartextRouting` when `PayloadType::TransactionBundle`. Add `debug_assert!` + `VoucherCoreError::PrivacyModeViolation` for financial payloads. Consider removing `sender:true` flag altogether and rely on trial-decryption for sender (same as recipients).

---

## 2. SecureContainer: Double-Key-Wrapping uses same `epk` for recipient and sender — no fresh contribution check on sender DH and sender wrap leaks plaintext `sender_id` in header
- **File:line:** `src/models/secure_container.rs:284-305` (sender DH `sender_static_sk.diffie_hellman(&esk_pub)` and header `kid: sender.user_id` / `hash(sender_id)`)
- **Severity:** **Low** (design) / **Medium** if `CleartextRouting` used with financial payload
- **Finding:** The ephemeral `esk_pub` is reused for all recipients including the sender's self-wrap. `was_contributory()` is checked, but both derivations share the same `esk` — compromise of `esk_priv_static` (memory disclosure before zeroize) would expose payload key to all. Defense-in-depth would use a second independent ephemeral for the sender wrap or HKDF domain separation (`"recipient-kek"` vs `"sender-kek"`). More importantly, the sender's `kid` header again leaks identity (see Finding 1). Zeroization in `Drop` is best-effort (heap copies from `serde_json` remain) — documented limitation, acceptable.
- **PoC:** Intercept container with `CleartextRouting`, extract `recipients` where `header.sender==true` → `kid` equals sender's `did:key` — no decryption needed. Replay: clone container bytes and re-submit to another recipient — `verify_integrity` passes (signature binds `i` but `i` is hash of ciphertext, not recipients set? Actually `i` covers recipients via `to_canonical_json(&container)` — so replay to different recipient would require re-wrapping, but attacker can replay identical bytes to same victim → envelope signature still valid, bundle signature still valid → duplicate processing unless app deduplicates `bundle_id`.
- **Recommendation:** Enforce `TrialDecryption` for financial payloads; domain-separate KEK HKDF info string (`derive_kek(shared_secret, b"secure-container-kek-v1" + role)`).

---

## 3. WASM FFI: `panic=abort` vs `catch_unwind` — most `#[wasm_bindgen]` exports are not unwind-safe; Rust panic becomes WASM trap (unreachable) and leaks stack
- **File:line:** `bindings/wasm/src/lib.rs:143-452` (all `#[wasm_bindgen]` functions except `safe_validate_cel`) ; `src/services/utils.rs:25`, `94`, `162` (`expect`/`unwrap` on date construction)
- **Severity:** **Medium** (availability, memory safety)
- **Finding:** Only `safe_validate_cel` (`lib.rs:127-139`) uses `catch_unwind`. All other WASM exports (`generate_mnemonic`, `derive_issuer_id`, `parse_and_diagnose_standard`, `sign_standard`, `verify_standard`, `to_toml_preview`) propagate `Result` via `JsError` but internally call `.expect("valid date")`, `.unwrap()`, `toml::to_string_pretty(...).map_err(...)` is safe, but `to_canonical_json` → `serde_json_canonicalizer::to_string` could panic on non-serializable types (not here), and `crypto::derive_ephemeral_key_pair` uses `.expect("HKDF never fails")` (`seal.rs:527`). In WASM, a panic unwinds into JS as `RuntimeError: unreachable` — not caught by JS `try/catch` if `panic=abort` is set, and leaks the WASM memory instance (JsError strings may contain raw key material if `e.to_string()` includes key bytes). `bindings/wasm/Cargo.toml` does not set `panic = "abort"` nor `catch` via `wasm-bindgen` `__wbg_..._catch` attribute.
- **PoC (TypeScript):**
  ```ts
  import * as wasm from "./pkg/human_money_wasm.js";
  // Supply malformed mnemonic that triggers internal .expect inside derive path
  try { wasm.derive_issuer_id("", "0", ""); } catch(e) { console.log(e); }
  // If internal panic occurs (e.g., year 9999 rounding in get_timestamp → expect fails),
  // WASM instance traps: `RuntimeError: unreachable` at wasm+offset, JS catch shows `__wbg` non-Error.
  // Verify with wasm-pack test --node: call with 10MB TOML string containing invalid UTF-16 surrogate.
  ```
- **Recommendation:** Wrap every `#[wasm_bindgen]` body in `std::panic::catch_unwind` → `JsError`, or build with `panic = "abort"` + `wasm-bindgen` `catch` attribute and fuzz inputs. Zeroize `JsError` messages — never return key bytes. Add `#[wasm_bindgen(catch)]` to exports and audit `.expect`/`.unwrap` in called crypto utils (replace with `map_err`).

---

## 4. CLI: `target/dev-keys/issuer.key` written with default umask, and `standard_file`/`key` Path traversal via symlink
- **File:line:** `src/bin/voucher-cli.rs:70-118` (`generate_keys`, `sign_standard`) and `src/storage/file_storage.rs:192-210` (`write_atomic` already hardened with `O_EXCL`+random nonce, but CLI does not)
- **Severity:** **Medium** (confidentiality) / **Low** (path traversal — `clap` PathBuf is intended to be arbitrary)
- **Finding:** `generate_keys` does `fs::write(&key_path, signing_key.to_bytes())` with default umask (022 → world-readable on many Linux). Private key material at 32 bytes should be `0o600`. `sign_standard` does `fs::read(key_path)` following symlinks — attacker who can plant symlink `issuer.key → /etc/hosts` or `standard_file → /proc/self/mem` could exfiltrate or overwrite arbitrary `standard_path` (the tool overwrites `standard_path` in place at line 178 with `fs::write(standard_path, final_toml_content)` without checking it is a regular file inside an expected directory). `update_signature_in_toml` blindly overwrites. No path traversal check like `storage_ops.rs:775` (`contains '/'`, `..`) is applied to CLI args.
- **PoC:**
  ```bash
  ln -s /tmp/evil.toml target/dev-keys/issuer.key  # if attacker can pre-create symlink before generate_keys
  cargo run --bin voucher-cli -- generate-keys --prefix 0 # follows? Actually create_dir_all then fs::write will follow symlink
  # Key bytes written to /tmp/evil.toml world-readable
  # Overwrite attack:
  ln -s /home/victim/.ssh/authorized_keys /tmp/victim_standard.toml
  cargo run --bin voucher-cli -- sign-standard --key target/dev-keys/issuer.key --prefix 0 /tmp/victim_standard.toml
  # fs::write overwrites authorized_keys with TOML
  ```
- **Recommendation:** `fs::write` → `OpenOptions::new().create_new(true).mode(0o600).write(true).open()` for key material, `fs::metadata` check `file_type.is_file()` and `fs::canonicalize` + `starts_with` allowlist before overwrite. Or document CLI as dev-only, not for production paths.

---

## 5. File-Storage & Archive Path Traversal: `generic_*.enc` and `voucher_id/*.json` rely on base58 alphabet for safety — no explicit `..` check on `voucher_id`
- **File:line:** `src/storage/file_storage.rs:682`, `696` (`save_arbitrary_data`/`load_arbitrary_data` correctly reject `/\..`), `src/archive/file_archive.rs:665` (`voucher_dir = archive_directory.join(&voucher.voucher_id)`) and `src/app_service/storage_ops.rs:775-783` (uuid traversal check), `src/storage/file_storage.rs:192` (`write_atomic` takes `relative_path` from constant)
- **Severity:** **Low** (currently safe, defense-in-depth missing)
- **Finding:** `save_arbitrary_data` correctly validates `name` against `/\..`. `FileVoucherArchive::archive_voucher` joins `voucher.voucher_id` (Base58 SHA3-256 hash, alphabet `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` — no `/\..`) so traversal is not possible by construction. However no explicit assertion is kept; if `voucher_id` source changes to user-supplied `funded_standard` or legacy V2 `blinded_id` path, traversal would be silent. `import_voucher_standard` (`storage_ops.rs:775`) correctly rejects `uuid` containing `/\..` or empty, and `delete_voucher_standard` (`821`) does same — good. `Generic(String)` payload type builds `to_didcomm_uri` via `format!(".../generic/1.0/{}.md", s)` without sanitizing `s` — if `s` contains `../`, the `typ` header could carry path-like string, but not written to filesystem.
- **PoC (bust assumption):** Craft voucher with forged `voucher_id = "../../etc/passwd"` (would fail `verify_voucher_hash` because voucher_id is hash of content, but if bypass via `test-utils` signature bypass, archive path would be `base/../../etc/passwd/t_id.json` → directory traversal if voucher validation skipped). With current code `Voucher::create` always hashes, so not exploitable, but `test_utils::create_voucher_for_manipulation` allows manual assignment — test harness could miss.
- **Recommendation:** Add explicit `assert!(!voucher_id.contains('/') && !voucher_id.contains(".."))` in `archive_voucher`/`get_archived_voucher` as defense-in-depth, and sanitize `Generic(String)` typ segment (`s.replace('/', "_")`).

---

## 6. JWS Profile Verification: `cty` and `kid` not pinned, and payload `id` aliases via `get_pubkey_from_user_id` sanitize whitespace — potential malleable ID confusion (mitigated)
- **File:line:** `src/services/jws_profile_service.rs:97-149` (`verify_and_import_jws_profile`) and `src/services/crypto/identity.rs:14-18` (`sanitize_user_id` strips whitespace)
- **Severity:** **Low** (already fixed for `alg`/`typ`; remaining `cty` is informational) / **Informational** on whitespace alias
- **Finding:** Fix `HMC-SEC-06-06` correctly pins `alg == "EdDSA"` and `typ == "JWT"` and delegates `did:key` parsing to `get_pubkey_from_user_id` which rejects trailing-garbage aliases (`did:key:z<key><extra>`). However `JwsHeader.cty` (`application/json`) is not validated — attacker could set `cty: "application/jose+json"` to smuggle JWS through a generic JWS library that dispatches on `cty`. Not exploitable in this crate (only this verifier). More subtle: `sanitize_user_id` strips **all** whitespace before parsing, so `"did:key:z6M... "` and `"did:key:z6M...\n"` map to same key but are different strings — `profile.id` stored verbatim would cause string-equality authorization bypass (e.g., allowlist `user_id == expected` fails to match sanitized form). `validate_user_id` also sanitizes before split, so `"test:abc@did:key:z6M..."` with embedded whitespace inside prefix would be accepted after stripping.
- **PoC:**
  ```rust
  let did_with_ws = format!("{} ", victim_did); // trailing space
  let profile = PublicProfile { id: Some(did_with_ws.clone()), ..Default::default() };
  let jws = export_profile_as_jws(&victim_sk, &profile).unwrap();
  // Verifier strips whitespace, extracts pubkey ok, but stored id retains whitespace
  let (imported, imported_did) = verify_and_import_jws_profile(&jws).unwrap();
  assert_eq!(imported.id.unwrap(), did_with_ws); // retains space
  assert!(get_pubkey_from_user_id(&imported_did).is_ok()); // same key
  // Downstream check `imported_did == expected_did_without_space` fails despite same key — malleable alias.
  ```
- **Recommendation:** Canonicalize `profile.id` on import (`sanitize_user_id` + re-validate) and store sanitized form. Validate `cty == "application/json"` (or ignore but document).

---

## 7. Privacy Guard: `timestamp` not encrypted in SecureContainer, and `privacy_guard_commitment` leaks guard existence / equivocation detection relies on distinct commitments
- **File:line:** `src/models/voucher.rs:131-165` (`RecipientPayload.timestamp: u64` plaintext UTC seconds inside AEAD guard) and `src/services/l2_gateway.rs:273-280` (`privacy_guard_commitment` → `hash(guard_b64)` vs `""` for None), `src/models/conflict.rs:72-79` (`privacy_guard_hash` in fingerprint)
- **Severity:** **Low** (privacy) / **Medium** for equivocation detection (already fixed in V3)
- **Finding:** `RecipientPayload.timestamp` is the `chrono::Utc::now().timestamp() as u64` — coarse seconds, not microsecond JCS timestamp — stored encrypted (X25519+ChaCha) so not leaked on wire. However `Transaction.t_time` (ISO8601 string) is inside `Voucher.transactions` which is inside `TransactionBundle` which is inside `SecureContainer` encrypted with `protected` header as AAD — so encrypted. But gossip `TransactionFingerprint.encrypted_timestamp` is `original_nanos ^ hash(prev_hash||t_id)` — XOR with hash, recoverable only if attacker obtains `prev_hash` (not in fingerprint). For an observer with full voucher chain, `prev_hash` is known (hash of prev transaction canonical JSON) so they can recover timestamp by `decrypted = encrypted ^ hash(prev_hash||t_id)` — timestamp not confidential to anyone with chain history, by design (gossip needs ordering). `privacy_guard_commitment` is `SHA3(guard_b64)` — leaks whether guard was present (`""` vs 44-char hash) and allows linkability: two fingerprints with same `ds_tag` but different `privacy_guard_hash` are distinguishable as guard equivocation (HMSEC-SA04-08 fix) — intentional. But if guard is `Some("")` (empty string) it is treated as `None` (`!guard.is_empty()` check) → `privacy_guard_commitment` returns `""`, collapsing `None` and `Some("")` — equivocation via empty guard not distinguishable. No field carries raw timestamp in cleartext outside AEAD.
- **PoC (timestamp recovery):**
  ```rust
  // Given decrypted transaction chain (victim), recover encrypted timestamp:
  let enc = fingerprint.encrypted_timestamp;
  let h = get_raw_hash_from_slices(&[&bs58::decode(prev_hash).unwrap(), &bs58::decode(t_id).unwrap()]);
  let orig_nanos = enc ^ u128::from_le_bytes(h[0..16].try_into().unwrap()); // simplified; actual hash is SHA3, not raw slice
  // Actual impl in conflict_manager::decrypt_transaction_timestamp uses same derivation — proves timestamp is recoverable with chain.
  ```
- **Recommendation:** Document that `t_time` confidentiality inside bundle relies on SecureContainer encryption, not on fingerprint encryption. Ensure `privacy_guard_commitment` treats `Some("")` distinct from `None` (return constant `"HMC_GUARD_EMPTY_V1"` for empty).

---

## 8. JSON Canonicalization: `serde_json_canonicalizer::to_string` is correctly used for all cryptographic hashes; `HashMap` iteration order is NOT assumed
- **File:line:** `src/services/utils.rs:146-148` (`to_canonical_json` → `serde_json_canonicalizer::to_string`), `src/models/secure_container.rs:396` (`container_json_for_id = to_canonical_json(&container)`), `src/services/bundle_processor.rs:51`, `src/models/seal.rs:101, 244, 312`, `src/models/voucher_standard_definition.rs:251, 264` (all use `to_canonical_json` for hashes/signatures), `bindings/wasm/src/lib.rs:258` (`cel_diagnostics.sort_by(rule_id)`), `src/models/voucher.rs:549` (trap generation uses `sst_encoded_parts` length-prefixed, not JSON)
- **Severity:** **Informational** (assumption bust — **not vulnerable**)
- **Finding:** Audit hypothesis was that `HashMap<String, DynamicRule>` or `fingerprint_depths: HashMap<String,i8>` iteration would produce non-deterministic JSON. Verification: every hash/signature path uses `to_canonical_json` which internally sorts object keys lexicographically per RFC 8785 (JCS). `serde_json_canonicalizer` does not rely on `HashMap` iteration order. Places that use `serde_json::to_string` / `to_vec` are **not** hash-bound: `bundle_processor.rs:56` serializes bundle for transport (not hash), `jws_profile_service.rs:52,57` uses raw `serde_json::to_string` for JWS header/payload — JWS signs the *exact* base64url of that serialization, verifier recomputes over received `header_b64.payload_b64` raw bytes, so canonicalization is not needed. `HashMap` in `TransactionBundle.forwarded_fingerprints: Vec<TransactionFingerprint>` is `Vec`, not map. Where deterministic output matters for UI (WASM `cel_diagnostics`), code explicitly sorts (`lib.rs:258`). No vulnerability.
- **PoC (bust):**
  ```rust
  let mut m = HashMap::new(); m.insert("b".to_string(), 2); m.insert("a".to_string(), 1);
  let j1 = to_canonical_json(&m).unwrap(); // '{"a":1,"b":2}' regardless of insertion order
  let j2 = serde_json::to_string(&m).unwrap(); // might be '{"b":2,"a":1}' non-deterministic, but never hashed
  assert_eq!(j1, r#"{"a":1,"b":2}"#);
  ```
- **Recommendation:** Keep invariant: any new field added to a hashed struct must be covered by `to_canonical_json` (add `#[deny(clippy::disallowed_method)]` for `serde_json::to_string` in `services/crypto`). Already documented in `AGENTS.md` — "Strict Separation of Domain and View Model (Cryptographic Stability)".

---

## 9. DTO / camelCase segregation: Core models remain snake_case, view DTOs at boundary correctly use `rename`
- **File:line:** `src/app_service/mod.rs:81-88` (`ProfileInfo` with `#[serde(rename="profileName")]`), `src/models/profile.rs:170-216` (`PublicProfile` snake_case), `src/models/voucher.rs:1-14` (voucher core snake_case), `src/models/secure_container.rs:79` (`EncryptionType` camelCase is JWE spec, not view leak)
- **Severity:** **Informational** (compliant)
- **Finding:** Core structures (`Voucher`, `Transaction`, `TrapData`, `VoucherStandard`) use idiomatic Rust `snake_case` and `serde` defaults (no `rename_all = "camelCase"`). Only boundary DTOs (`ProfileInfo`, `AppService` JS-facing returns) use `rename` for camelCase — correctly isolated per `AGENTS.md` rule. `SecureContainer.EncryptionType` uses `#[serde(rename_all="camelCase")]` but this maps to JWE `et` field internals (`Asymmetric` vs `Symmetric`) — spec, not view. `VoucherStandardDefinition` uses `rename_all = "snake_case"` — correct. No view-layer camelCase leaks into core serialization.
- **PoC:** `cargo test --features test-utils` shows `test_container_config_serialization` (`secure_container.rs:661`) only asserts `ContainerConfig` tagged enum format (`{"type":"TargetDid","value":[...]}`) — stability test for JS interop, not core hash.

---

## 10. Additional: Protocol markdowns correctly bind signing over `assertion_id` covering all semantic fields (trust/1.0/assertion.md)
- **File:line:** `protocols/trust/1.0/assertion.md:13-19`, `protocols/transfer/1.0/bundle.md:11-18`, `protocols/signing/1.0/*.md`, `protocols/conflict/1.0/proof.md`
- **Severity:** **Informational** (spec-correct)
- **Finding:** `trust/1.0/assertion.md` documents `assertion_id = hash(canonical_json({issuer_id, subject_id, trust_level, context, timestamp}))` including `context=null` — prevents semantic rewriting; signature over `assertion_id` bytes correctly binds all fields. `transfer/1.0/bundle.md` defines `bundle_id = hash(canonical_json(bundle without signature))` — matches `bundle_processor.rs:51-55`. `conflict/1.0/proof.md` defines `proof_id = hash(offender_id + fork_point_prev_hash)` — matches `conflict_manager` logic. No spec mismatch.

---

## Summary Table

| # | Title | File:line | Severity | Status |
|---|-------|-----------|----------|--------|
| 1 | Sender header leaks identity in routing modes | `secure_container.rs:295-300` | Medium | Open — gate TransactionBundle to TrialDecryption |
| 2 | Double wrap reuse & header `sender:true` oracle | `secure_container.rs:284-305` | Low | Open — domain separate KEK |
| 3 | WASM panics not caught → trap | `bindings/wasm/src/lib.rs:143-452`, `utils.rs:25` | Medium | Open — add catch_unwind |
| 4 | CLI key file umask + symlink overwrite | `src/bin/voucher-cli.rs:70-178` | Medium | Open — chmod 0600 + canonicalize |
| 5 | Archive `voucher_id` traversal defense only implicit | `file_archive.rs:665` | Low | Open — explicit validation |
| 6 | JWS `cty` not pinned, whitespace malleable alias | `jws_profile_service.rs:97-149` | Low | Open — store sanitized id |
| 7 | Guard commitment empty vs None collapse, timestamp recoverable with chain | `l2_gateway.rs:273-280` | Low | Open — distinct constants |
| 8 | Canonicalization correctly uses JCS | `utils.rs:146` | Info | ✓ Not vulnerable |
| 9 | DTO camelCase properly isolated | `app_service/mod.rs:81` | Info | ✓ Compliant |
| 10 | Protocol markdowns correctly bind signatures | `protocols/trust/1.0/assertion.md` | Info | ✓ Correct |

**General notes:** Realm/SAI prefix leakage is limited to explicit `Hashed/CleartextRouting` modes; `TrialDecryption` (default for `TransactionBundle` via `bundle_processor.rs:60`) is safe. `FileStorage::save_arbitrary_data` path traversal is already mitigated. `FileVoucherArchive` location binding + manifest (`file_archive.rs:404-456`) correctly prevents whole-record smuggling. `TrapManager` shard structure validation (`validate_shard_structure`) correctly rejects `trap_r="none"` in spend path. No critical RCE found.

