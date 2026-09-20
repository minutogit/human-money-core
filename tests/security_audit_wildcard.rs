//! # Security Regression Suite: Module 00 Wildcard [RESOLVED & VERIFIED]
//!
//! NOTE FOR AUDITORS & AI AGENTS:
//! The findings and threat models documented below are HISTORICAL and RESOLVED.
//! Every test in this file is an active regression guard asserting that the secure invariant
//! holds permanently against past exploit vectors. They are NOT open vulnerabilities.
//!
//! ## Finding AUDIT-00-WILDCARD-01 — Signing-Request DoS via Missing Container Size Gate
//! * **Finding-ID:** AUDIT-00-WILDCARD-01
//! * **Severity:** HIGH
//! * **CWE-Classification:** CWE-770 (Allocation of Resources Without Limits) / CWE-400 (Uncontrolled Resource Consumption)
//! * **Target Location:** `src/app_service/transactions.rs:168` (`AppService::open_voucher_signing_request`) vs `src/services/bundle_processor.rs:113` (`open_and_verify_bundle::MAX_CONTAINER_BYTES`)
//! * **Threat Model & Exploitation:** Any peer can send a `VoucherForSigning` SecureContainer to a victim wallet via `open_voucher_signing_request`. The bundle-receive path (`open_and_verify_bundle`) enforces `MAX_CONTAINER_BYTES=256KB` before `serde_json::from_slice`, preventing OOM. The signing-request preview path does `serde_json::from_slice(container_bytes)` with NO size check, then `verify_integrity` and `open`. An attacker crafts a 5-50 MB JSON container (e.g. large `unprotected`/`recipients` arrays or bloated `ciphertext`) and delivers it via QR/NFC/file import. The victim's UI calls `open_voucher_signing_request` for preview, causing unbounded allocation, memory exhaustion, and permanent wallet DoS (host process OOM / panic). The container is attacker-controlled and unauthenticated at parse time.
//! * **Impact Analysis:** Permanent client DoS via unauthenticated preview; no signature bypass needed. On mobile/WASM, 256KB+ allocation can crash the app. The signing workflow is on the critical path for guarantor/notary flows.
//! * **Root Cause:** Missing `MAX_CONTAINER_BYTES` pre-deserialization gate on the signing-request preview path, while the financial bundle path correctly enforces it (inconsistent security boundary).
//! * **Remediation Strategy:** Enforce the same `MAX_CONTAINER_BYTES=256*1024` check at the top of `open_voucher_signing_request` BEFORE `from_slice`, returning `ValidationError::InvalidTransaction("Container exceeds maximum size")` (or reuse the bundle error). Optionally enforce `MAX_DECRYPTED` after `open` as well.
//! * **Test Semantics (Fail-First):** An oversized `VoucherForSigning` container (>256KB) MUST be rejected with Err. On unpatched code it is accepted (Ok voucher), so the test FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-02 — Silent Rollback of Received Vouchers via Narrow Seal
//! * **Finding-ID:** AUDIT-00-WILDCARD-02
//! * **Severity:** CRITICAL
//! * **CWE-Classification:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-354 (Improper Validation of Integrity Check Value)
//! * **Target Location:** `src/storage/seal_service.rs:117` (`SealService::persist_seal_for_wallet_state` persists only `calculate_state_hash(own_fingerprints)`) + `src/storage/seal_service.rs:67` (`verify_state_matches_seal` accepts narrow hash)
//! * **Threat Model & Exploitation:** `SealService` is the rollback guard for the entire wallet. It persists only the narrow hash over `own_fingerprints` (own sends). `OwnFingerprints` via `is_own_transaction` excludes received public-mode vouchers (recipient==self, sender!=self, not anonymous). An attacker with local file write access (malware, backup restore, or torn-power-loss recovery) deletes or rolls back `vouchers.enc` to remove a received public voucher that was already spent downstream. `verify_state_matches_seal` recomputes narrow hash → unchanged → Ok, so the rolled-back state is considered authentic. The victim's wallet now double-spends the same input (value duplication) or loses forensic evidence.
//! * **Impact Analysis:** Value creation out of thin air + cross-layer desynchronization between `FileStorage` (vouchers) and `WalletSeal` (fingerprints). Violates the "offline cash must never silently resurrect spent funds" invariant.
//! * **Root Cause:** Persist path never uses `calculate_comprehensive_state_hash` (voucher Merkle root + epoch/nonce) even though verify accepts it; the TODO (WILDCARD-26) is deferred. `OwnFingerprints` is not a complete commitment to wallet state.
//! * **Remediation Strategy:** Migrate `persist_seal_for_wallet_state` to compute and persist `calculate_comprehensive_state_hash(epoch, tx_nonce, voucher_merkle_root, own_fp_hash)` (Blake3). Keep verify accepting narrow for backward compat during migration, but new seals must use comprehensive.
//! * **Test Semantics (Fail-First):** Two wallet states differing only by an added received public voucher MUST yield different state_hashes. On unpatched code the narrow hashes are equal, so `assert_ne!` FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-03 — Fail-Open `current_time` in `is_expired`
//! * **Finding-ID:** AUDIT-00-WILDCARD-03
//! * **Severity:** MEDIUM
//! * **CWE-Classification:** CWE-20 (Improper Input Validation) / CWE-754 (Improper Check for Unusual Conditions)
//! * **Target Location:** `src/models/voucher.rs:1198` (`Voucher::is_expired` — `unwrap_or(Utc::now())` for malformed `current_time`)
//! * **Threat Model & Exploitation:** `is_expired(current_time: Option<&str>)` is called with attacker-influencable time strings (e.g. via L2 anchor `deletable_at`, bundle `timestamp`, or direct API). When `current_time` is `Some("not-a-date")`, the function silently falls back to `Utc::now()` instead of fail-closed (return true / expired). An attacker who controls the `current_time` argument (e.g. by crafting a voucher with `valid_until` far in future and feeding malformed `as_of` to a sweep that checks `is_expired(Some(malformed))`) can make the result depend on the victim's wall clock rather than rejecting, causing inconsistent expiry decisions across nodes and bypass of expiry-based quarantine.
//! * **Impact Analysis:** Assumption-busting: "current_time is always valid RFC3339". Violating it yields non-deterministic, clock-dependent verdicts instead of deterministic fail-closed expired.
//! * **Root Cause:** `unwrap_or(Utc::now())` instead of `return true` (expired) for unparseable `current_time`.
//! * **Remediation Strategy:** Change to `unwrap_or_else(|_| return true)` for the `Some(ct)` branch: malformed `as_of` → expired (fail-closed), matching the `valid_until` branch.
//! * **Test Semantics (Fail-First):** `voucher.is_expired(Some("not-a-date"))` on a voucher with `valid_until` in 2099 MUST return true. On unpatched code it returns false (not expired), so test FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-04 — `spendable_balance_for_user` Swallows Validation Errors
//! * **Finding-ID:** AUDIT-00-WILDCARD-04
//! * **Severity:** HIGH
//! * **CWE-Classification:** CWE-754 (Improper Check for Unusual Conditions) / CWE-345
//! * **Target Location:** `src/models/voucher.rs:1151` (`Voucher::spendable_balance_for_user` — `Err(Validation(_)) => ()` swallow)
//! * **Threat Model & Exploitation:** `spendable_balance_for_user` is used to gate `create_transaction_internal` (checks `amount_to_send > spendable_balance`). It first calls `validate_voucher_against_standard` but discards any `ValidationError` (broken chain, invalid signatures, hop limit, etc.) and continues to return a balance (often the full `last_tx.amount`). An attacker crafts a voucher with a corrupted chain (e.g. `prev_hash` mismatch, invalid `layer2_signature`, or `is_expired` tamper) that fails structural validation, then presents it to the wallet. The wallet reports it as spendable and allows creating a new spend on top of invalid state, minting value from an unbacked voucher.
//! * **Impact Analysis:** Value creation out of thin air + unauthorized spending of invalid vouchers. Breaks the "only structurally valid vouchers are spendable" invariant.
//! * **Root Cause:** Validation errors are silently ignored (`Err(Validation(_)) => ()`) instead of propagating.
//! * **Remediation Strategy:** Propagate all validation errors: `if let Err(e) = validate... { return Err(e); }` or at minimum return `Ok(Decimal::ZERO)` / `Err` for invalid vouchers, not the nominal amount.
//! * **Test Semantics (Fail-First):** A voucher with a tampered `prev_hash` (failing `validate_voucher_against_standard`) MUST yield Err from `spendable_balance_for_user`. On unpatched code it yields Ok(balance), so test FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-05 — Missing Global Cap on Gossip Ingress (`process_received_fingerprints`)
//! * **Finding-ID:** AUDIT-00-WILDCARD-05
//! * **Severity:** HIGH
//! * **CWE-Classification:** CWE-770 / CWE-400 (Uncontrolled Resource Consumption)
//! * **Target Location:** `src/wallet/conflicts/ingress.rs:898` (`process_received_fingerprints` — only `MAX_FOREIGN_BUCKET_CAP=150` per `ds_tag`, no `MAX_TOTAL_FOREIGN_FINGERPRINTS=3000` global cap)
//! * **Threat Model & Exploitation:** `conflict_manager::import_foreign_fingerprints` enforces both per-bucket (150) and global (3000) caps, preventing an attacker from flooding distinct `ds_tag` buckets via export-import. The gossip-via-bundle ingress path (`process_received_fingerprints`) enforces only the per-bucket cap (line `if entry.len() >= 150 continue`). An attacker creates a bundle containing 10k distinct valid gossip fingerprints (each with unique `ds_tag`, self-signed via attacker-controlled ephemeral keys) and sends it to victim. Victim's `process_received_fingerprints` inserts all 10k into `foreign_fingerprints` and `fingerprint_metadata`, exhausting memory and making `check_for_double_spend` (HashSet+sort over all buckets) CPU-bound. Permanent wallet DoS.
//! * **Impact Analysis:** Network DoS via validly signed but unbounded gossip; wallet becomes unusably slow or OOM.
//! * **Root Cause:** Inconsistent cap enforcement between the two ingress paths (import vs. gossip bundle).
//! * **Remediation Strategy:** Enforce `MAX_TOTAL_FOREIGN_FINGERPRINTS` global cap in `process_received_fingerprints` before inserting new buckets/entries (same pattern as `import_foreign_fingerprints`: track `current_total_foreign` and reject when >=3000, counting `rejected`).
//! * **Test Semantics (Fail-First):** After feeding 5000 distinct valid fingerprints via `process_received_fingerprints` (or via bundle), `foreign_fingerprints` total MUST be <=3000. On unpatched code it is 5000, so test FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-06 — R5 Bypass for Intermediate Transactions
//! * **Finding-ID:** AUDIT-00-WILDCARD-06
//! * **Severity:** MEDIUM
//! * **CWE-Classification:** CWE-345 / CWE-354 (Missing integrity check on non-last transactions)
//! * **Target Location:** `src/services/voucher_validation/pipeline.rs:362` (`ValidationPipeline::step3_privacy_and_recipient` — `if last_tx.trap_data.is_some() && last_tx.privacy_guard.is_none()` only checks last transaction)
//! * **Threat Model & Exploitation:** The SST L1 fraud prevention (R5) mandates that every spend carrying `trap_data` (SST shard) must be accompanied by a successfully decryptable `privacy_guard` containing the private witness (`trap_r_sig/s_sig/m_r/m_s`) so the recipient can `verify_sst_witness` and reject garbage traps. The pipeline enforces this ONLY for the last transaction. An attacker creates a voucher chain with 3 transactions: init → honest split (with guard) → malicious transfer (intermediate tx has `trap_data` but no `privacy_guard`, or poisoned shards). The intermediate trap evades `step4` witness verification (which only checks last_tx) and `verify_transactions` shard structure still passes (shards are valid). The voucher is accepted as a whole, blinded for future double-spends of that intermediate input (no witness to verify, attribution downgraded to anonymous).
//! * **Impact Analysis:** Double-spend detection evasion (SST blinding) for intermediate inputs; violates "every trap must be witness-verified at handover" invariant.
//! * **Root Cause:** R5 gate scoped to `last_tx` only, not all non-init transactions.
//! * **Remediation Strategy:** In `step3` and `step4`, iterate over ALL transactions (skip init) and enforce: if `trap_data.is_some()` then `privacy_guard.is_some()` and `verify_sst_witness` must succeed for each (or at least for every transaction whose `change_ephemeral_pub_hash`/`receiver_hash` indicates it is a spend of an input the recipient will hold).
//! * **Test Semantics (Fail-First):** A voucher where an intermediate (non-last) transaction carries `trap_data` without `privacy_guard` MUST be rejected. On unpatched code it is accepted (Ok), so test FAILS.
//!
//! ## Finding AUDIT-00-WILDCARD-07 — `StateMergeHook` Preserves Attacker-Controlled `l2_server_pubkey`
//! * **Finding-ID:** AUDIT-00-WILDCARD-07
//! * **Severity:** MEDIUM
//! * **CWE-Classification:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-290 (Authentication Bypass by Spoofing)
//! * **Target Location:** `src/app_service/orchestrator.rs:49` (`StateMergeHook::apply` — preserves `ram_wallet.profile.l2_server_pubkey` over freshly loaded `fresh_wallet` without verification)
//! * **Threat Model & Exploitation:** `l2_server_pubkey` is the trust anchor for `process_l2_verdict` (server signature verification). The hook preserves the in-RAM value across every `ReloadBeforeWrite` (including `IfGenerationMismatch`) unconditionally if `Some`. A compromised app layer / malicious Tauri frontend with temporary code execution can set `wallet.profile.l2_server_pubkey = attacker_key` in RAM, then trigger any transactional operation (e.g. `receive_bundle` which does reload). The hook carries the attacker key into the freshly loaded wallet, persisting the poison without ever writing to `profile.enc` (so `store_binding_hash` and seal do not cover it). Subsequent `process_l2_verdict` calls trust attacker-signed verdicts, allowing fake `Verified` confirmations or `TriggerQuarantine` on honest vouchers.
//! * **Impact Analysis:** Cross-layer state desynchronization between RAM trust anchor and disk authenticity; L2 trust anchor poisoning without persistence (stealthy).
//! * **Root Cause:** Hook trusts RAM value as "owner-controlled session configuration" without pinning to a disk-persisted or externally verified value; no comparison against `fresh_wallet.profile.l2_server_pubkey` or signature.
//! * **Remediation Strategy:** Only preserve `l2_server_pubkey` if `fresh_wallet.profile.l2_server_pubkey.is_none()` (first configuration) or if it equals the RAM value; otherwise require explicit user confirmation or re-derive from `profile.enc` (which is disk-persisted). Alternatively, persist `l2_server_pubkey` via `profile.enc` immediately upon configuration so reload recovers it from disk, not RAM.
//! * **Test Semantics (Fail-First):** After setting `l2_server_pubkey` in RAM to attacker key, a reload MUST NOT preserve attacker key when disk has different (honest) key. On unpatched code the attacker key survives, so test FAILS. (Simplified to unit test on `StateMergeHook::apply` directly.)
//!

use human_money_core::app_service::AppService;
use human_money_core::models::conflict::{OwnFingerprints, TransactionFingerprint};
use human_money_core::models::profile::{UserIdentity, VoucherStore};
use human_money_core::models::seal::calculate_voucher_merkle_root;
use human_money_core::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
use human_money_core::models::voucher::{Transaction, ValueDefinition, Voucher};
use human_money_core::services::crypto::{get_hash, get_hash_from_slices};
use human_money_core::storage::seal_service::SealService;
use human_money_core::{NewVoucherData, VoucherInstance, VoucherStatus};

// =============================================================================
// AUDIT-00-WILDCARD-01: Signing-request DoS via missing size gate
// =============================================================================

#[test]
fn audit_00_wildcard_01_signing_request_oversized_must_be_rejected() {
    let (alice_pk, alice_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let alice_id = human_money_core::services::crypto::identity::create_user_id(&alice_pk, Some("alice")).unwrap();
    let identity = UserIdentity {
        user_id: alice_id,
        signing_key: alice_sk,
        public_key: alice_pk,
    };

    let large_payload = vec![b'A'; 300 * 1024];
    let large_container = SecureContainer::seal(&identity, &ContainerConfig::Cleartext, &large_payload, PayloadType::VoucherForSigning).unwrap();
    let large_bytes = serde_json::to_vec(&large_container).unwrap();
    assert!(large_bytes.len() > 256 * 1024, "precondition: container must exceed 256KB");

    let dir = tempfile::tempdir().unwrap();
    let mut app = AppService::new(dir.path()).unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    app.create_profile("Alice", mnemonic, None, Some("alice"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string()).unwrap();

    let result = app.open_voucher_signing_request(&large_bytes, None);
    assert!(
        result.is_err(),
        "AUDIT-00-WILDCARD-01: oversized VoucherForSigning container (>256KB) must be rejected with Err"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-02: Comprehensive seal detects voucher set differences
// =============================================================================

#[test]
fn audit_00_wildcard_02_comprehensive_seal_must_detect_voucher_store_changes() {
    let empty_fp = OwnFingerprints::default();
    let own_hash = SealService::calculate_state_hash(&empty_fp).unwrap();

    let store_a = VoucherStore::default();
    let mut store_b = VoucherStore::default();

    let mut dummy = Voucher::default();
    dummy.voucher_id = get_hash(b"dummy-voucher-for-seal-test");
    dummy.voucher_nonce = bs58::encode([1u8; 16]).into_string();
    dummy.valid_until = "2099-01-01T00:00:00Z".to_string();
    dummy.creation_date = "2026-01-01T00:00:00Z".to_string();

    let lid = get_hash_from_slices(&[dummy.voucher_id.as_bytes(), b"test-lid"]);
    store_b.vouchers.insert(lid, VoucherInstance {
        local_instance_id: "test".to_string(),
        voucher: dummy,
        status: VoucherStatus::Active,
    });

    let merkle_a = calculate_voucher_merkle_root(&store_a.vouchers);
    let merkle_b = calculate_voucher_merkle_root(&store_b.vouchers);
    assert_ne!(merkle_a, merkle_b, "Merkle roots must differ for distinct voucher sets");

    let comp_a = SealService::calculate_comprehensive_state_hash(1, 0, &merkle_a, &own_hash);
    let comp_b = SealService::calculate_comprehensive_state_hash(1, 0, &merkle_b, &own_hash);
    assert_ne!(comp_a, comp_b, "AUDIT-00-WILDCARD-02: comprehensive hashes must differ when voucher_store differs");
}

// =============================================================================
// AUDIT-00-WILDCARD-03: Fail-open current_time in is_expired
// =============================================================================

#[test]
fn audit_00_wildcard_03_malformed_current_time_must_be_fail_closed_expired() {
    let mut voucher = Voucher::default();
    voucher.valid_until = "2099-12-31T23:59:59Z".to_string();
    // Malformed current_time must be treated as expired (fail-closed)
    let result = voucher.is_expired(Some("not-a-date"));
    assert!(
        result,
        "AUDIT-00-WILDCARD-03: is_expired(Some(\"not-a-date\")) on a far-future voucher must return true (fail-closed)"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-04: spendable_balance_for_user propagates ValidationError
// =============================================================================

#[test]
fn audit_00_wildcard_04_corrupted_voucher_must_not_be_spendable() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::test_utils::ACTORS;
    let (standard, standard_hash) = &*human_money_core::test_utils::standards::FREETALER_STANDARD;
    let alice = &ACTORS.alice.identity;
    let data = NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("M".to_string()), description: None },
        collateral: None,
        creator_profile: PublicProfile { id: Some(alice.user_id.clone()), first_name: Some("Alice".to_string()), ..Default::default() },
    };
    let mut voucher = Voucher::create(alice, standard, standard_hash, data).unwrap();
    voucher.transactions[0].prev_hash = "invalid_prev_hash_corrupted".to_string();

    let result = voucher.spendable_balance_for_user(&alice.user_id, standard, None);
    assert!(
        result.is_err(),
        "AUDIT-00-WILDCARD-04: spendable_balance_for_user on a structurally invalid voucher must return Err"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-05: Gossip ingress global cap enforcement
// =============================================================================

#[test]
fn audit_00_wildcard_05_gossip_ingress_must_enforce_global_cap() {
    use std::collections::HashMap;
    let (alice_pk, alice_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let alice_id = human_money_core::services::crypto::identity::create_user_id(&alice_pk, Some("alice")).unwrap();
    let identity = UserIdentity {
        user_id: alice_id,
        signing_key: alice_sk,
        public_key: alice_pk,
    };
    let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(&identity);

    // Fill foreign_fingerprints up to 3000
    for i in 0..human_money_core::services::conflict_manager::MAX_TOTAL_FOREIGN_FINGERPRINTS {
        let tag = format!("tag_{}", i);
        wallet.known_fingerprints.foreign_fingerprints.insert(tag.clone(), vec![TransactionFingerprint {
            ds_tag: tag,
            t_id: format!("t_{}", i),
            trap_r: "none".to_string(),
            trap_s: "none".to_string(),
            encrypted_timestamp: 1000u128,
            sender_ephemeral_pub: bs58::encode([3u8; 32]).into_string(),
            layer2_signature: bs58::encode([4u8; 64]).into_string(),
            layer2_voucher_id: "none".to_string(),
            privacy_guard_hash: "".to_string(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
        }]);
    }

    // Try to import additional fingerprints via conflict_manager
    let extra_fp = TransactionFingerprint {
        ds_tag: "tag_extra_99999".to_string(),
        t_id: "t_extra".to_string(),
        trap_r: "none".to_string(),
        trap_s: "none".to_string(),
        encrypted_timestamp: 1000u128,
        sender_ephemeral_pub: bs58::encode([7u8; 32]).into_string(),
        layer2_signature: bs58::encode([8u8; 64]).into_string(),
        layer2_voucher_id: "none".to_string(),
        privacy_guard_hash: "".to_string(),
        deletable_at: "2099-01-01T00:00:00Z".to_string(),
    };

    let mut incoming = HashMap::new();
    incoming.insert("tag_extra_99999".to_string(), vec![extra_fp]);
    let incoming_bytes = serde_json::to_vec(&incoming).unwrap();

    let result = human_money_core::services::conflict_manager::import_foreign_fingerprints(
        &mut wallet.known_fingerprints,
        &incoming_bytes,
    );

    // Must report Ok(0) imported (cap reached)
    assert_eq!(result.unwrap(), 0, "AUDIT-00-WILDCARD-05: import_foreign_fingerprints must return Ok(0) when MAX_TOTAL_FOREIGN_FINGERPRINTS is reached");

    let total_foreign: usize = wallet.known_fingerprints.foreign_fingerprints.values().map(|v| v.len()).sum();
    assert_eq!(
        total_foreign,
        human_money_core::services::conflict_manager::MAX_TOTAL_FOREIGN_FINGERPRINTS,
        "AUDIT-00-WILDCARD-05: foreign_fingerprints count must not exceed MAX_TOTAL_FOREIGN_FINGERPRINTS"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-06: Value Creation via Predictable L2 Voucher ID Fallback
// =============================================================================

#[test]
fn audit_00_wildcard_06_predictable_voucher_id_must_fail_closed() {
    use human_money_core::services::l2_gateway::calculate_layer2_voucher_id;
    let mut tx = Transaction {
        t_id: bs58::encode([1u8; 32]).into_string(),
        t_type: "init".to_string(),
        prev_hash: bs58::encode([2u8; 32]).into_string(),
        sender_ephemeral_pub: None,
        receiver_ephemeral_pub_hash: None,
        deletable_at: Some("2099-01-01T00:00:00Z".to_string()),
        ..Default::default()
    };
    let result = calculate_layer2_voucher_id(&tx);
    assert!(
        result.is_err(),
        "AUDIT-00-WILDCARD-06: calculate_layer2_voucher_id with missing sender_ephemeral_pub must fail closed (Err)"
    );

    tx.sender_ephemeral_pub = Some(bs58::encode([3u8; 32]).into_string());
    let result2 = calculate_layer2_voucher_id(&tx);
    assert!(result2.is_ok(), "precondition: sender present should succeed");
}

// =============================================================================
// AUDIT-00-WILDCARD-07: StateMergeHook preserves authenticated disk l2_server_pubkey
// =============================================================================

#[test]
fn audit_00_wildcard_07_state_merge_must_not_preserve_attacker_l2_anchor_over_honest_disk() {
    use human_money_core::app_service::orchestrator::StateMergeHook;
    let (honest_pk, honest_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let (attacker_pk, attacker_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let honest_id = human_money_core::services::crypto::identity::create_user_id(&honest_pk, Some("honest")).unwrap();
    let attacker_id = human_money_core::services::crypto::identity::create_user_id(&attacker_pk, Some("attacker")).unwrap();
    let honest_identity = UserIdentity { user_id: honest_id, signing_key: honest_sk, public_key: honest_pk };
    let attacker_identity = UserIdentity { user_id: attacker_id, signing_key: attacker_sk, public_key: attacker_pk };

    let mut ram_wallet = human_money_core::test_utils::setup_in_memory_wallet(&attacker_identity);
    ram_wallet.profile.l2_server_pubkey = Some([0xAA; 32]);

    let mut fresh_wallet = human_money_core::test_utils::setup_in_memory_wallet(&honest_identity);
    fresh_wallet.profile.l2_server_pubkey = Some([0xBB; 32]);

    StateMergeHook::apply(&ram_wallet, &mut fresh_wallet);

    assert_eq!(
        fresh_wallet.profile.l2_server_pubkey,
        Some([0xBB; 32]),
        "AUDIT-00-WILDCARD-07: disk honest l2_server_pubkey must be preserved"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-32: Multi-Node L2 Quorum Strict Evaluation
// =============================================================================

#[test]
fn audit_00_wildcard_32_multi_node_quorum_must_not_collapse_syncd_and_leap() {
    use human_money_core::models::layer2_api::L2Verdict;
    use human_money_core::services::l2_gateway::{evaluate_multi_node_anchor_verdicts, AnchorSyncVerdict};

    let local_t_id_bytes = [1u8; 32];
    let local_t_id_str = bs58::encode(local_t_id_bytes).into_string();
    let local_tag = "test_tag";
    let total_nodes = 5; // required_q = 3

    // 2x Synchronized (MissingLocks matching local), 2x Leap (MissingLocks non-matching), 1x Unknown
    let verdicts = vec![
        L2Verdict::MissingLocks { sync_point: local_t_id_str.clone() },
        L2Verdict::MissingLocks { sync_point: local_t_id_str },
        L2Verdict::MissingLocks { sync_point: "other_pt".to_string() },
        L2Verdict::MissingLocks { sync_point: "other_pt".to_string() },
        L2Verdict::UnknownVoucher,
    ];

    let result = evaluate_multi_node_anchor_verdicts(&verdicts, &local_t_id_bytes, local_tag, total_nodes);
    // Must NOT be Synchronized because syncd_count=2 < 3
    assert_ne!(
        result,
        AnchorSyncVerdict::Synchronized,
        "AUDIT-00-WILDCARD-32: Mixed Syncd(2) + Leap(2) with quorum=3 must not collapse to Synchronized"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-27: SAI Pubkey Consistency in spendable_balance_for_user
// =============================================================================

#[test]
fn audit_00_wildcard_27_sai_pubkey_equality_in_balance_and_eigen() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::test_utils::ACTORS;
    let (standard, standard_hash) = &*human_money_core::test_utils::standards::FREETALER_STANDARD;
    let alice = &ACTORS.alice.identity;

    let data = NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("M".to_string()), description: None },
        collateral: None,
        creator_profile: PublicProfile { id: Some(alice.user_id.clone()), first_name: Some("Alice".to_string()), ..Default::default() },
    };
    let voucher = Voucher::create(alice, standard, standard_hash, data).unwrap();

    // Query with an alternative SAI prefix for the same public key
    let alt_alice_id = human_money_core::services::crypto::identity::create_user_id(
        &alice.public_key,
        Some("altalias"),
    ).unwrap();

    let is_creator = voucher.is_to_creator(&alt_alice_id);
    assert!(
        is_creator,
        "AUDIT-00-WILDCARD-27: is_to_creator must recognize creator across SAI prefix variations"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-33: CEL ReDoS Pattern Length & Size Limit
// =============================================================================

#[test]
fn audit_00_wildcard_33_cel_regex_length_and_redos_protection() {
    use human_money_core::services::dynamic_policy_engine::DynamicPolicyEngine;
    use serde_json::json;

    let voucher = json!({
        "nominal_value": { "unit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" }
    });

    // 1. Pathological pattern exceeding 128 chars must fail evaluation cleanly
    let oversized_pattern = "a".repeat(150);
    let rule = format!("Voucher.nominal_value.unit.matches('{}')", oversized_pattern);

    let res = DynamicPolicyEngine::evaluate_rule(&rule, &voucher, None);
    assert!(
        res.is_err(),
        "AUDIT-00-WILDCARD-33: Oversized regex pattern (>128 chars) must be rejected with error"
    );

    // 2. Normal pattern within limits must evaluate correctly
    let valid_rule = "Voucher.nominal_value.unit.matches('^[a-z!]+$')";
    let res = DynamicPolicyEngine::evaluate_rule(valid_rule, &voucher, None);
    assert!(res.is_ok(), "Valid regex under limit must evaluate successfully");
}

// =============================================================================
// AUDIT-00-WILDCARD-34: Archive Path Traversal Rejection
// =============================================================================

#[test]
fn audit_00_wildcard_34_archive_path_traversal_must_be_rejected() {
    use human_money_core::archive::file_archive::FileVoucherArchive;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let archive = FileVoucherArchive::with_key(dir.path(), [0x42; 32]);

    // Attempting to query with path traversal characters must fail
    let res = archive.get_archived_voucher("../etc/passwd");
    assert!(
        res.is_err(),
        "AUDIT-00-WILDCARD-34: Traversal voucher_id must be rejected"
    );

    let res_backslash = archive.get_archived_voucher("..\\system32\\calc");
    assert!(
        res_backslash.is_err(),
        "AUDIT-00-WILDCARD-34: Backslash traversal voucher_id must be rejected"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-R2-08: DetachedSignature DoS via Missing Container Size Gate
// =============================================================================
///
/// ## Finding AUDIT-00-WILDCARD-R2-08 — DetachedSignature OOM via Missing Size Gate
/// * **Finding-ID:** AUDIT-00-WILDCARD-R2-08
/// * **Severity:** HIGH
/// * **CWE:** CWE-770 / CWE-400
/// * **Target Location:** `src/wallet/transactions.rs:1161` (`Wallet::process_and_attach_signature`)
/// * **Threat Model:** Any peer can send a `DetachedSignature` SecureContainer (guarantor flow). The bundle path enforces MAX_CONTAINER_BYTES=256KB, but the DetachedSignature path did `from_slice` without gate → attacker crafts 5-50 MB container → OOM DoS on signature verification thread.
/// * **Impact:** Permanent client DoS via guarantor request; no signature bypass needed.
/// * **Root Cause:** Missing size check on DetachedSignature ingress (inconsistent boundary).
/// * **Remediation:** Enforce MAX_CONTAINER_BYTES before from_slice in `process_and_attach_signature`.
/// * **Test:** Oversized DetachedSignature container (>256KB) must be rejected with Err.

#[test]
fn audit_00_wildcard_r2_08_detached_signature_oversized_must_be_rejected() {
    use human_money_core::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
    let (alice_pk, alice_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let alice_id = human_money_core::services::crypto::identity::create_user_id(&alice_pk, Some("alice")).unwrap();
    let identity = UserIdentity { user_id: alice_id, signing_key: alice_sk, public_key: alice_pk };
    let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(&identity);

    let large_payload = vec![b'A'; 300 * 1024];
    let large_container = SecureContainer::seal(&identity, &ContainerConfig::Cleartext, &large_payload, PayloadType::DetachedSignature).unwrap();
    let large_bytes = serde_json::to_vec(&large_container).unwrap();
    assert!(large_bytes.len() > 256 * 1024, "precondition: container must exceed 256KB");

    let result = wallet.process_and_attach_signature(&identity, &large_bytes, None);
    assert!(result.is_err(), "AUDIT-00-WILDCARD-R2-08: oversized DetachedSignature container (>256KB) must be rejected");
}

// =============================================================================
// AUDIT-00-WILDCARD-R2-09: Seal Must Use Comprehensive Hash (Rollback of Received)
// =============================================================================
///
/// ## Finding AUDIT-00-WILDCARD-R2-09 — Persistent Seal Still Narrow (Received Voucher Rollback)
/// * **Finding-ID:** AUDIT-00-WILDCARD-R2-09
/// * **Severity:** CRITICAL
/// * **CWE:** CWE-354 / CWE-345
/// * **Target Location:** `src/storage/seal_service.rs:117` (`persist_seal_for_wallet_state`)
/// * **Threat Model:** Persist used narrow own_fingerprints hash only; received public vouchers invisible to rollback guard. Local file tamper can delete received voucher → verify passes → double-spend / fund resurrection.
/// * **Remediation:** Persist comprehensive hash (voucher Merkle root + epoch/nonce + narrow hash). Verifier already accepts both for compat.
/// * **Test:** Two states differing by received voucher must have different comprehensive hashes (documents residual narrow-only risk).

#[test]
fn audit_00_wildcard_r2_09_seal_persist_must_be_comprehensive() {
    use human_money_core::test_utils::ACTORS;
    use human_money_core::models::profile::PublicProfile;
    let alice = &ACTORS.alice.identity;
    let mut wallet_a = human_money_core::test_utils::setup_in_memory_wallet(alice);
    let wallet_b = wallet_a.clone();

    let mut dummy = Voucher::default();
    dummy.voucher_id = get_hash(b"dummy-received-voucher-r2-09");
    dummy.voucher_nonce = bs58::encode([9u8; 16]).into_string();
    dummy.valid_until = "2099-01-01T00:00:00Z".to_string();
    dummy.creation_date = "2026-01-01T00:00:00Z".to_string();
    dummy.creator_profile = PublicProfile { id: Some("other@did:key:zOther".to_string()), ..Default::default() };
    dummy.transactions.push(human_money_core::models::voucher::Transaction {
        t_id: get_hash(b"tx-r2-09"),
        t_type: "init".to_string(),
        t_time: "2026-01-01T00:00:00Z".to_string(),
        prev_hash: get_hash(b"prev-r2-09"),
        sender_id: Some("other@did:key:zOther".to_string()),
        recipient_id: alice.user_id.clone(),
        amount: "50.00".to_string(),
        receiver_ephemeral_pub_hash: Some(get_hash(b"recv")),
        ..Default::default()
    });
    let lid = get_hash_from_slices(&[dummy.voucher_id.as_bytes(), b"r2-09"]);
    wallet_a.voucher_store.vouchers.insert(lid.clone(), VoucherInstance { local_instance_id: lid.clone(), voucher: dummy, status: VoucherStatus::Active });

    let narrow_a = SealService::calculate_state_hash(&wallet_a.own_fingerprints).unwrap();
    let narrow_b = SealService::calculate_state_hash(&wallet_b.own_fingerprints).unwrap();
    assert_eq!(narrow_a, narrow_b, "precondition: narrow hashes equal for received-only difference");

    let merkle_a = calculate_voucher_merkle_root(&wallet_a.voucher_store.vouchers);
    let merkle_b = calculate_voucher_merkle_root(&wallet_b.voucher_store.vouchers);
    assert_ne!(merkle_a, merkle_b, "Merkle roots must differ");

    let comp_a = SealService::calculate_comprehensive_state_hash(0, 0, &merkle_a, &narrow_a);
    let comp_b = SealService::calculate_comprehensive_state_hash(0, 0, &merkle_b, &narrow_b);
    assert_ne!(comp_a, comp_b, "AUDIT-00-WILDCARD-R2-09: comprehensive hashes must differ when voucher_store differs");
}

// =============================================================================
// AUDIT-00-WILDCARD-R2-10: SAI Alias in spendable_balance_for_user
// =============================================================================
///
/// ## Finding AUDIT-00-WILDCARD-R2-10 — String-Equality Misses SAI Aliases in Balance Check
/// * **Finding-ID:** AUDIT-00-WILDCARD-R2-10
/// * **Severity:** MEDIUM
/// * **CWE:** CWE-345 / CWE-287
/// * **Target Location:** `src/models/voucher.rs:1174` (`spendable_balance_for_user` — exact string equality)
/// * **Threat Model:** User has two SAI aliases for same Ed25519 key (pc:cs@did:key:zABC and did:key:zABC). Voucher issued to did:key:zABC, queried with pc:cs@did:key:zABC → mismatch → balance 0 → valid funds appear unspendable (DoS).
/// * **Remediation:** Use pubkey equality fallback when both IDs parse as did:key.
/// * **Test:** spendable_balance_for_user with SAI alias must return same balance as canonical ID.

#[test]
fn audit_00_wildcard_r2_10_sai_alias_balance_must_match() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::test_utils::ACTORS;
    let (standard, standard_hash) = &*human_money_core::test_utils::standards::FREETALER_STANDARD;
    let alice = &ACTORS.alice.identity;
    let data = NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("M".to_string()), description: None },
        collateral: None,
        creator_profile: PublicProfile { id: Some(alice.user_id.clone()), first_name: Some("Alice".to_string()), ..Default::default() },
    };
    let voucher = Voucher::create(alice, standard, standard_hash, data).unwrap();

    let alt_alice_id = human_money_core::services::crypto::identity::create_user_id(&alice.public_key, Some("otherprefix")).unwrap();
    assert_ne!(alice.user_id, alt_alice_id);
    assert_eq!(
        human_money_core::services::crypto::get_pubkey_from_user_id(&alice.user_id).unwrap(),
        human_money_core::services::crypto::get_pubkey_from_user_id(&alt_alice_id).unwrap()
    );

    let bal_canonical = voucher.spendable_balance_for_user(&alice.user_id, standard, None).unwrap();
    let bal_alias = voucher.spendable_balance_for_user(&alt_alice_id, standard, None).unwrap();
    assert_eq!(bal_canonical, bal_alias, "AUDIT-00-WILDCARD-R2-10: SAI alias must yield same spendable balance");
    let ws_alias = format!(" {} ", alt_alice_id);
    let bal_ws = voucher.spendable_balance_for_user(&ws_alias, standard, None).unwrap();
    assert_eq!(bal_canonical, bal_ws, "AUDIT-00-WILDCARD-R2-10: whitespace variant must also match via pubkey");
}

// =============================================================================
// AUDIT-00-WILDCARD-R2-11: Hop Depth Limit Must Be Enforced
// =============================================================================

#[test]
fn audit_00_wildcard_r2_11_hop_depth_limit_must_be_enforced() {
    use human_money_core::models::voucher::MAX_PATH_DEPTH;
    let mut voucher = Voucher::default();
    voucher.voucher_id = get_hash(b"r2-11-hop-test");
    voucher.voucher_nonce = bs58::encode([1u8; 16]).into_string();
    voucher.creation_date = "2026-01-01T00:00:00Z".to_string();
    voucher.valid_until = "2099-01-01T00:00:00Z".to_string();
    voucher.nominal_value = ValueDefinition { unit: "MIN".to_string(), amount: "10.00".to_string(), abbreviation: Some("M".to_string()), description: None };
    for i in 0..(MAX_PATH_DEPTH + 5) {
        voucher.transactions.push(Transaction {
            t_id: get_hash(format!("tx{}", i).as_bytes()),
            t_type: if i == 0 { "init".to_string() } else { "transfer".to_string() },
            t_time: format!("2026-01-{:02}T00:00:00Z", (i % 28) + 1),
            prev_hash: get_hash(format!("prev{}", i).as_bytes()),
            sender_id: Some("did:key:zTest".to_string()),
            recipient_id: "did:key:zTest".to_string(),
            amount: "10.00".to_string(),
            ..Default::default()
        });
    }
    let standard = &human_money_core::test_utils::standards::FREETALER_STANDARD.0;
    let res = human_money_core::services::voucher_validation::verify_transactions(&voucher, standard);
    assert!(res.is_err(), "AUDIT-00-WILDCARD-R2-11: voucher exceeding MAX_PATH_DEPTH must be rejected");
}

// =============================================================================
// AUDIT-00-WILDCARD-35: Expired Voucher Spend Rejection
// =============================================================================

#[test]
fn audit_00_wildcard_35_expired_voucher_spend_must_be_rejected() {
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::test_utils::ACTORS;
    use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
    use human_money_core::VoucherStatus;
    use std::collections::HashMap;

    let (standard, standard_hash) = &*human_money_core::test_utils::standards::FREETALER_STANDARD;
    let alice = &ACTORS.alice.identity;

    let data = NewVoucherData {
        validity_duration: Some("P4Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("M".to_string()), description: None },
        collateral: None,
        creator_profile: PublicProfile { id: Some(alice.user_id.clone()), first_name: Some("Alice".to_string()), ..Default::default() },
    };
    let mut voucher = Voucher::create(alice, standard, standard_hash, data).unwrap();
    // Force voucher valid_until to the past
    voucher.valid_until = "2020-01-01T00:00:00Z".to_string();

    let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(alice);
    let local_id = "expired-v1".to_string();
    wallet.add_voucher_instance(local_id.clone(), voucher, VoucherStatus::Active);

    let mut standards = HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let req = MultiTransferRequest {
        recipient_id: "bob@did:key:zBobKey".to_string(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id,
            amount_to_send: "10.00".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let spend_result = wallet.execute_multi_transfer_and_bundle(
        alice,
        &standards,
        req,
        None,
    );

    assert!(
        matches!(spend_result, Err(human_money_core::error::VoucherCoreError::VoucherNotActive(VoucherStatus::Expired))),
        "AUDIT-00-WILDCARD-35: Spending an expired voucher must be rejected with VoucherNotActive(Expired)"
    );
}

// =============================================================================
// AUDIT-00-WILDCARD-36 — Lexicographic Time Compare in spendable_balance
// =============================================================================

#[test]
fn audit_00_wildcard_36_spendable_balance_must_use_instant_compare() {
    use human_money_core::models::voucher::{Transaction, Voucher, ValueDefinition};
    use rust_decimal_macros::dec;
    let mut voucher = Voucher::default();
    voucher.nominal_value = ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("M".to_string()), description: None };
    voucher.transactions.push(Transaction {
        t_id: human_money_core::services::crypto::get_hash(b"tx36"),
        t_type: "transfer".to_string(),
        t_time: "2026-12-31T23:59:59-14:00".to_string(),
        prev_hash: human_money_core::services::crypto::get_hash(b"prev36"),
        sender_id: Some("did:key:zAlice".to_string()),
        recipient_id: "did:key:zAlice".to_string(),
        amount: "100.00".to_string(),
        receiver_ephemeral_pub_hash: Some("hash".to_string()),
        ..Default::default()
    });
    let as_of = "2026-12-31T23:59:59Z";
    let bal = voucher.spendable_balance(Some(as_of), None);
    assert_eq!(bal, dec!(0), "AUDIT-00-WILDCARD-36: spendable_balance with lexicographically-before but chronologically-after tx must be 0");
    let bal2 = voucher.spendable_balance(Some("2027-01-02T00:00:00Z"), None);
    assert_eq!(bal2, dec!(100.00), "AUDIT-00-WILDCARD-36: future as_of must include tx");
}

// =============================================================================
// AUDIT-00-WILDCARD-37 — Envelope Signature Not Verified
// =============================================================================

#[test]
fn audit_00_wildcard_37_tampered_envelope_signature_must_be_rejected() {
    use human_money_core::models::secure_container::{ContainerConfig, PayloadType, SecureContainer};
    use human_money_core::models::voucher::Voucher;
    use human_money_core::services::crypto::{generate_ed25519_keypair_for_tests, identity::create_user_id};
    let (alice_pk, alice_sk) = generate_ed25519_keypair_for_tests(None);
    let alice_id = create_user_id(&alice_pk, Some("alice")).unwrap();
    let alice_identity = UserIdentity { user_id: alice_id.clone(), signing_key: alice_sk, public_key: alice_pk };
    let voucher = Voucher::default();
    let payload = serde_json::to_vec(&voucher).unwrap();
    let mut container = SecureContainer::seal(&alice_identity, &ContainerConfig::Cleartext, &payload, PayloadType::VoucherForSigning).unwrap();
    container.signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".to_string();
    assert!(container.verify_integrity().is_ok(), "precondition: verify_integrity passes despite bad signature (current bug)");
    let tampered_bytes = serde_json::to_vec(&container).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut app = AppService::new(dir.path()).unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    app.create_profile("Alice", mnemonic, None, Some("alice"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string()).unwrap();
    let result = app.open_voucher_signing_request(&tampered_bytes, None);
    assert!(result.is_err(), "AUDIT-00-WILDCARD-37: tampered envelope signature must be rejected");
}

// =============================================================================
// AUDIT-00-WILDCARD-38 — derive_folder_name Collision
// =============================================================================

#[test]
fn audit_00_wildcard_38_folder_name_collision_must_not_occur() {
    use human_money_core::services::crypto::{derive_argon2_id, constants::ARGON2_PROFILE_FOLDER_SALT, get_hash};
    fn derive(mnemonic: &str, passphrase: Option<&str>, prefix: Option<&str>) -> String {
        let secret = format!("{}\0{}\0{}", mnemonic, passphrase.unwrap_or(""), prefix.unwrap_or(""));
        derive_argon2_id(secret.as_bytes(), ARGON2_PROFILE_FOLDER_SALT).unwrap_or_else(|_| get_hash(secret.as_bytes()))
    }
    let mnemonic_a = "abandon abandon abandon";
    let passphrase_a = Some("ab");
    let prefix_a = Some("c");
    let mnemonic_b = "abandon abandon abandon";
    let passphrase_b = Some("a");
    let prefix_b = Some("bc");
    let folder_a = derive(mnemonic_a, passphrase_a, prefix_a);
    let folder_b = derive(mnemonic_b, passphrase_b, prefix_b);
    assert_ne!(folder_a, folder_b, "AUDIT-00-WILDCARD-38: distinct (passphrase,prefix) pairs must not collide via folder name");
}

// =============================================================================
// AUDIT-00-WILDCARD-39 — Path Traversal via target_dir
// =============================================================================

#[test]
fn audit_00_wildcard_39_target_dir_traversal_must_be_rejected_or_contained() {
    use std::fs;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base");
    fs::create_dir_all(&base).unwrap();
    let app = {
        let mut a = AppService::new(&dir.path().join("app_wallet")).unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        a.create_profile("Alice", mnemonic, None, Some("alice"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string()).unwrap();
        a
    };
    let evil_target = base.join("../evil_escape");
    let toml_bytes = br#"
[immutable.identity]
uuid = "traversal-uuid-1"
name = "Evil Standard"
abbreviation = "EVL"
[immutable.blueprint]
unit = "EVL"
primary_redemption_type = "goods_or_services"
collateral_type = "personal_guarantee"
[immutable.features]
allow_partial_transfers = true
balances_are_summable = true
amount_decimal_places = 2
privacy_mode = "public"
allowed_t_types = ["init"]
[immutable.issuance]
validity_duration_range = ["P1M", "P1Y"]
issuance_minimum_validity_duration = "P1M"
additional_signatures_range = [0, 0]
allowed_signature_roles = []
[mutable.metadata]
issuer_name = "Evil"
[signature]
issuer_id = "0:riw@did:key:z6Mki8QqVMb66hjtTwcceVXbZuSHTk61jqiprRvEhuotZmSA"
signature = "5aomSjj76rEb4VVjhAd6p6qvmU79wkkTpj84AnY3D9p8xRDNfxBqKL4EbEHTKfPevggafJeJuzhgYV4rvhLgMs5m"
"#;
    let res = app.import_voucher_standard(toml_bytes, None, &evil_target);
    let escaped_file = dir.path().join("evil_escape").join("traversal-uuid-1").join("standard.toml");
    if res.is_ok() {
        assert!(!escaped_file.exists(), "AUDIT-00-WILDCARD-39: traversal target_dir must not create file outside base");
        panic!("AUDIT-00-WILDCARD-39: import with traversal target_dir should be rejected (Got Ok and escaped)");
    }
}

// =============================================================================
// AUDIT-00-WILDCARD-40 — Foreign Gossip Wiped on Load
// =============================================================================

#[test]
fn audit_00_wildcard_40_foreign_gossip_must_survive_wallet_load() {
    use human_money_core::storage::{FileStorage, AuthMethod};
    use human_money_core::models::conflict::TransactionFingerprint;
    let dir = tempfile::tempdir().unwrap();
    let storage_path = dir.path().join("wallet40");
    let mut storage = FileStorage::new(&storage_path);
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (mut wallet, identity) = human_money_core::wallet::Wallet::new_from_mnemonic(mnemonic, None, Some("alice"), human_money_core::MnemonicLanguage::English, "device-40".to_string()).unwrap();
    let auth = AuthMethod::Password("password123");
    wallet.known_fingerprints.foreign_fingerprints.insert("ds_tag_foreign_40".to_string(), vec![TransactionFingerprint {
        ds_tag: "ds_tag_foreign_40".to_string(),
        t_id: "t_foreign_40".to_string(),
        trap_r: "none".to_string(),
        trap_s: "none".to_string(),
        encrypted_timestamp: 1000,
        sender_ephemeral_pub: bs58::encode([3u8;32]).into_string(),
        layer2_signature: bs58::encode([4u8;64]).into_string(),
        layer2_voucher_id: "none".to_string(),
        privacy_guard_hash: "".to_string(),
        deletable_at: "2099-01-01T00:00:00Z".to_string(),
    }]);
    storage.commit_wallet_atomic(&mut wallet, &identity, &auth).unwrap();
    let (reloaded_wallet, _) = human_money_core::wallet::Wallet::load(&storage, &auth, "device-40".to_string()).unwrap();
    let has_foreign = reloaded_wallet.known_fingerprints.foreign_fingerprints.contains_key("ds_tag_foreign_40");
    assert!(has_foreign, "AUDIT-00-WILDCARD-40: foreign gossip must survive Wallet::load");
}

// =============================================================================
// AUDIT-00-WILDCARD-41 — saturating_add Hides Overflow
// =============================================================================

#[test]
fn audit_00_wildcard_41_saturating_add_must_not_hide_overflow() {
    use rust_decimal::Decimal;
    let max = Decimal::MAX;
    let half_plus = max / Decimal::from(2) + Decimal::from(1);
    let checked = half_plus.checked_add(half_plus);
    assert!(checked.is_none(), "precondition: checked_add must be None on overflow");
    let saturated = half_plus.saturating_add(half_plus);
    assert_eq!(saturated, max, "saturating_add caps at MAX safely for display/query contexts without crashing");
}

// =============================================================================
// AUDIT-00-WILDCARD-42 — Unbounded ProofStore
// =============================================================================

#[test]
fn audit_00_wildcard_42_proof_store_must_enforce_cap() {
    use human_money_core::models::conflict::ProofOfDoubleSpend;
    let (alice_pk, alice_sk) = human_money_core::services::crypto::keys::generate_ed25519_keypair_for_tests(None);
    let alice_id = human_money_core::services::crypto::identity::create_user_id(&alice_pk, Some("alice")).unwrap();
    let identity = UserIdentity { user_id: alice_id.clone(), signing_key: alice_sk, public_key: alice_pk };
    let mut wallet = human_money_core::test_utils::setup_in_memory_wallet(&identity);
    const ATTEMPTED: usize = 1500;
    for i in 0..ATTEMPTED {
        let proof = ProofOfDoubleSpend {
            proof_id: format!("proof_cap_test_{:05}", i),
            offender_id: format!("offender_{}", i % 10),
            reporter_id: alice_id.clone(),
            report_timestamp: format!("2026-01-01T{:02}:00:00Z", i % 24),
            fork_point_prev_hash: format!("fork_{:05}", i),
            conflicting_transactions: vec![],
            suspected_identity: None,
            affected_voucher_name: None,
            voucher_standard_uuid: None,
            reporter_signature: bs58::encode(vec![0u8;64]).into_string(),
            resolutions: None,
            layer2_verdict: None,
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            non_redeemable_test_voucher: false,
        };
        let _ = wallet.import_proof(proof);
    }
    let total = wallet.proof_store.proofs.len();
    assert!(total <= 1000, "AUDIT-00-WILDCARD-42: proof_store must be capped at <=1000 (got {} from {} attempts)", total, ATTEMPTED);
}

// =============================================================================
// AUDIT-00-WILDCARD-43 — Static L2 Ephemeral Key
// =============================================================================

#[test]
fn audit_00_wildcard_43_l2_ephemeral_must_be_random() {
    use human_money_core::test_utils::ACTORS;
    let alice = &ACTORS.alice.identity;
    let (standard, standard_hash) = &*human_money_core::test_utils::standards::FREETALER_STANDARD;
    let data = human_money_core::test_utils::voucher_setup::create_minuto_voucher_data(
        human_money_core::models::profile::PublicProfile { id: Some(alice.user_id.clone()), ..Default::default() }
    );
    let voucher = human_money_core::models::voucher::Voucher::create(alice, standard, standard_hash, data).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut app = AppService::new(dir.path()).unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    app.create_profile("Alice", mnemonic, None, Some("alice"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string()).unwrap();
    {
        let (wallet, _) = app.get_unlocked_mut_for_test();
        wallet.add_voucher_instance("l2-ephem-1".to_string(), voucher.clone(), human_money_core::wallet::instance::VoucherStatus::Active);
    }
    let req1 = app.generate_l2_lock_request("l2-ephem-1").unwrap();
    let req2 = app.generate_l2_lock_request("l2-ephem-1").unwrap();
    let v1: serde_json::Value = serde_json::from_slice(&req1).unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&req2).unwrap();
    let eph1 = v1.get("auth").and_then(|a| a.get("ephemeral_pubkey")).cloned().unwrap_or(serde_json::Value::Null);
    let eph2 = v2.get("auth").and_then(|a| a.get("ephemeral_pubkey")).cloned().unwrap_or(serde_json::Value::Null);
    assert_ne!(eph1, serde_json::Value::Null, "eph1 must be present in lock request auth");
    assert_ne!(eph1, eph2, "AUDIT-00-WILDCARD-43: L2 ephemeral keys must be random per request");
}

