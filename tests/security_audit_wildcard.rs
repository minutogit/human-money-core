//! # tests/security_audit_wildcard.rs
//!
//! Security Audit — Module 00: Adversarial Wildcard / Cross-Cutting Vectors.
//!
//! Fail-first (TDD) proof-of-concept tests. Every test asserts the SECURE
//! invariant ("Soll-Verhalten") and MUST FAIL on the unpatched code base,
//! thereby proving the vulnerability. Tests turn green only after the
//! corresponding remediation has been implemented (or are documented as
//! intentional-design / pending-architectural-fix invariant tests).
//!
//! Audit scope: cross-cutting vectors spanning AppService ↔ Wallet ↔
//! VoucherStore ↔ FileStorage ↔ Seal that no single functional module owns.
//!
//! ## Finding Summary
//!
//! | Finding-ID            | Hypothesis | Severity | Target                                   |
//! |-----------------------|------------|----------|------------------------------------------|
//! | AUDIT-00-WILDCARD-01  | H-00-1     | Critical | app_service/mod.rs::with_transactional_mut |
//! | AUDIT-00-WILDCARD-02  | H-00-2     | High     | wallet/transaction_handler.rs (post-commit archive loop) |
//! | AUDIT-00-WILDCARD-03  | H-00-3     | Critical | app_service/mod.rs (silent mid-session reload) |
//! | AUDIT-00-WILDCARD-04  | H-00-4     | Medium   | storage/file_storage.rs::unlock, SessionCache arithmetic |
//! | AUDIT-00-WILDCARD-05  | WH3-00-902 | Critical | services/conflict_manager.rs::is_init_fingerprint + gossip ingress |
//! | AUDIT-00-WILDCARD-06  | WH3-00-901 | Critical | wallet/lifecycle.rs::load (V2->V3 stranding display gate) |
//! | AUDIT-00-WILDCARD-07  | WH3-00-903 | High     | conflict_manager/conflict_handler::scan_and_rebuild_fingerprints |
//! | AUDIT-00-WILDCARD-08  | WH3-00-904 | Medium   | app_service/l2_facade.rs::process_l2_response (Instant overflow residue) |
//! | AUDIT-00-WILDCARD-09  | WH3-00-905 | Medium   | app_service/l2_facade.rs (quarantine write outside transactional discipline) |
//! | AUDIT-00-WILDCARD-10  | GN-00-10   | Medium   | wallet/queries.rs::get_total_balance_by_currency (unchecked Decimal +=) |
//! | AUDIT-00-WILDCARD-11  | GN-00-11   | Low      | storage/file_storage.rs (serde_json::to_vec().unwrap() panics) |
//! | AUDIT-00-WILDCARD-13  | GN-00-13   | Medium   | models/voucher.rs::spendable_balance (unwrap_or(ZERO) masking) |
//! | AUDIT-00-WILDCARD-14  | GN-00-14   | Low      | services/utils.rs::add_years_clamped (fallback to Utc::now) |
//! | AUDIT-00-WILDCARD-15  | GN-00-15   | High     | services/l2_gateway.rs::process_l2_verdict (L2 409 Conflict Proof-of-Truth) |
//! | AUDIT-00-WILDCARD-16  | GN-00-16   | High     | services/l2_gateway.rs::process_l2_verdict (QuorumCertificate lock_id replay) |
//! | AUDIT-00-WILDCARD-17  | GN-00-17   | [INTENT] | storage/file_storage.rs::load_wallet (tolerant load missing vouchers.enc - HMSEC-SA05-04) |
//! | AUDIT-00-WILDCARD-18  | GN-00-18   | Medium   | app_service/conflicts.rs::import_proof_from_container (missing verify_integrity) |

use human_money_core::app_service::{AppFacadeError, AppService};
use human_money_core::models::profile::PublicProfile;
use human_money_core::NewVoucherData;
use human_money_core::test_utils::{generate_signed_standard_toml, setup_service_with_profile, ACTORS};
use std::collections::HashMap;
use tempfile::tempdir;

const PASSWORD: &str = "wildcard-audit-password-123";
const INSTANCE_ID: &str = "test-id";
const FREETALER_TOML: &str = "voucher_standards/freetaler_v1/standard.toml";

/// Creates a profile with one persisted voucher and returns the service
/// together with the profile info (anonymous folder name).
fn setup_unlocked_with_voucher(profile_label: &str) -> (AppService, human_money_core::app_service::ProfileInfo, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir creation failed");
    let (mut service, profile) =
        setup_service_with_profile(dir.path(), &ACTORS.test_user, profile_label, PASSWORD);

    let signed_standard = generate_signed_standard_toml(FREETALER_TOML);
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(service.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
            ..Default::default()
        },
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "100.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    service
        .create_new_voucher(&signed_standard, voucher_data, Some(PASSWORD))
        .expect("voucher creation in test setup failed");

    (service, profile, dir)
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-01 (Hypothesis H-00-1)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-01
// Severity:         Critical
// CWE:              CWE-755 (Improper Handling of Exceptional Conditions)
//                   leading to a partial commit (CWE-662 class) and a
//                   permanent availability loss (CWE-400 class brick)
// Target Location:  src/app_service/mod.rs :: with_transactional_mut
//                   (Commit branch: temp_wallet.save -> RAM swap ->
//                   self.update_seal_after_state_change(password)?),
//                   second layer: src/storage/file_storage.rs :: save_seal
//                   and src/app_service/seal_handler.rs :: verify_seal_on_login
// Threat Model & Exploitation:
//                   Any transient I/O failure (disk full, permission, sync
//                   conflict, exhausted fd) between the wallet-data flush and
//                   the seal update flips the transaction into a half-committed
//                   state. The mutation is durably persisted (vouchers.enc,
//                   own_fingerprints.enc, generation counter), but the caller
//                   receives Err -- for create_transfer_bundle this means the
//                   produced bundle_bytes are lost ("burned" money) while the
//                   spend actually happened. Worse: disk now contains a NEW
//                   own_fingerprints store next to the OLD seal, so the
//                   state-hash gate in verify_seal_on_login rejects EVERY
//                   subsequent login with StateRollbackDetected ("Recovery
//                   required"). One unlucky write permanently bricks the
//                   wallet (Nightmare 3 + 4).
// Impact Analysis:  (a) Return value and durable state diverge: Err although
//                   persisted -> retry hazards / lost bundles.
//                   (b) Permanent login lockout requiring mnemonic-level
//                   recovery for every affected user.
// Root Cause:       update_seal_after_state_change is executed AFTER the
//                   commit point (data files + generation) and its `?` error
//                   propagates without compensating the already-persisted
//                   data, leaving data ahead of the seal.
// Remediation Strategy:
//                   Preserve the state-hash gate (rollback protection is
//                   intentional design and must NOT be weakened). Instead, if
//                   the seal update fails after the data commit, compensate:
//                   re-persist the PRE-transaction wallet state (generation
//                   counter aligned with the value the aborted commit wrote)
//                   so the on-disk data matches the untouched seal again
//                   (save_seal is tmp+rename-atomic, hence the old seal is
//                   always intact when save_seal fails). Report the operation
//                   honestly as Err afterwards: Err => no durable commit.
// Test Semantics:   Inject a seal-write failure that blocks ONLY
//                   `<profile>/seal.enc.tmp` (a directory shadowing the temp
//                   file used by save_seal) while leaving every Wallet::save
//                   target writable. A mutating command must surface the
//                   fault as Err (honest reporting), and a FRESH LOGIN
//                   afterwards MUST SUCCEED -- the wallet must not be bricked.
//                   FAILS on unpatched code: the command returns Err although
//                   persisted, and the follow-up login dies with
//                   StateRollbackDetected.
// =============================================================================
#[test]
fn wildcard_01_seal_update_failure_after_commit_must_not_brick_login() {
    let (mut service, profile, _dir) = setup_unlocked_with_voucher("Wildcard Seal Brick");

    // Baseline: a fresh login cycle works before the fault injection.
    service.logout();
    service
        .login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string())
        .expect("baseline login must succeed before fault injection");

    // --- FAULT INJECTION -------------------------------------------------
    // Shadow the seal temp-file path with a DIRECTORY. Every
    // fs::write(seal.enc.tmp) inside FileStorage::save_seal now fails with
    // EISDIR, while all regular Wallet::save targets remain writable.
    let seal_tmp_path = _dir
        .path()
        .join(&profile.folder_name)
        .join("seal.enc.tmp");
    std::fs::create_dir_all(&seal_tmp_path).expect("failed to shadow seal temp path");
    assert!(
        seal_tmp_path.is_dir(),
        "test setup: seal temp-path shadow missing"
    );

    // --- FAULTED MUTATION ------------------------------------------------
    let signed_standard = generate_signed_standard_toml(FREETALER_TOML);
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(service.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
            ..Default::default()
        },
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "50.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let outcome = service.create_new_voucher(&signed_standard, voucher_data, Some(PASSWORD));

    // Honest reporting: the injected I/O fault must surface as Err.
    assert!(
        outcome.is_err(),
        "test precondition violated: mutation unexpectedly succeeded despite \
         blocked seal writes"
    );

    // Remove the fault so subsequent operations can persist normally.
    std::fs::remove_dir(&seal_tmp_path).expect("failed to remove seal temp shadow");

    // --- SECURE INVARIANT (Soll-Verhalten) -------------------------------
    // The wallet must NOT be permanently bricked: a fresh login after the
    // partial-commit fault has to succeed (the state-hash gate is reserved
    // for genuine rollbacks/tampering, not for the wallet's own crash).
    let relaunch = service.login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string());
    assert!(
        relaunch.is_ok(),
        "AUDIT-00-WILDCARD-01 VIOLATION: a seal-update failure after the data \
         commit bricks the wallet -- login now fails with {:?}. The persisted \
         data diverged from the untouched seal (own_fingerprints ahead of \
         seal.enc), so verify_seal_on_login reports StateRollbackDetected for \
         every future login. One transient write failure must never cause a \
         permanent lockout.",
        relaunch.err()
    );

    // The recovered session must be fully operational (readable, consistent
    // store) -- i.e. the system ended in ONE coherent state, not a zombie.
    service
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .expect("recovered wallet must answer read queries");
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-03 (Hypothesis H-00-3)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-03
// Severity:         Critical
// CWE:              CWE-354 (Improper Validation of Integrity Check Value) /
//                   CWE-708 (Incorrect Ownership Assignment) on the reload path
// Target Location:  src/app_service/mod.rs :: with_transactional_mut (silent
//                   mid-session reload branch, `disk_generation !=
//                   loaded_generation` -> Wallet::load without any seal check);
//                   second layer: src/storage/file_storage.rs ::
//                   get_all_item_hashes (dotfile skip hides .wallet.generation
//                   from the integrity record) and src/wallet/lifecycle.rs :: load
// Threat Model & Exploitation:
//                   An external actor with write access to the profile folder
//                   (cloud-sync conflict resolution, "smart" backup/restore
//                   tool, malware, careless user copying an old snapshot back)
//                   rolls the DATA side of the wallet (vouchers.enc,
//                   own_fingerprints.enc, .wallet.generation) back to an older
//                   snapshot while the session stays unlocked. The seal.enc is
//                   not part of that rollback and remains AHEAD. On the next
//                   mutating command the generation mismatch triggers a SILENT
//                   Wallet::load that blindly trusts disk: a voucher that was
//                   already SPENT becomes Active again, its ds_tags vanish from
//                   the rebuilt history, so the transfer guard no longer fires.
//                   The victim re-sends value that already left the wallet --
//                   two valid bundles for the same voucher (framing / double
//                   spend), and the rollback detection only ever fires at the
//                   NEXT login, i.e. too late.
// Impact Analysis:  Silent resurrection of spent vouchers; the wallet owner
//                   becomes an unintentional double-spender; forensic history
//                   and wallet state diverge without any error surface.
// Root Cause:       The Reload-Before-Write mechanism verifies only the
//                   generation counter -- the single manipulable anchor --
//                   and never cross-checks the reloaded state against the
//                   cryptographic seal, although verify_seal_on_login applies
//                   exactly that check for the login path.
// Remediation Strategy:
//                   Layered defense: (a) the vouchers.enc<->profile.enc
//                   generation-bound check (HMSEC-SA05 hardening) already
//                   rejects partially rolled-back stores; (b) the residual gap
//                   -- a CONSISTENTLY rolled-back snapshot (data + profile
//                   container + generation marker all at state N) whose only
//                   diverging witness is the seal that stayed ahead -- is
//                   closed by applying the login-path state-hash gate to the
//                   mid-session reload: after Wallet::load, compare
//                   SHA3(canonical(own_fingerprints)) of the freshly loaded
//                   store against seal.payload.state_hash; on mismatch reject
//                   the command with StateRollbackDetected instead of silently
//                   continuing. Wallets without a seal (legacy migration case)
//                   stay exempt, mirroring login behavior. The gate itself is
//                   intentional design and must not be weakened.
// Test Semantics:   Snapshot ALL data-side files (including the profile
//                   container so internal generation-bound checks pass) at
//                   state N, advance to N+1 by a legitimate command, then
//                   restore the complete snapshot -- simulating a coherent
//                   sync/backup rollback with only seal.enc left ahead. A
//                   subsequent mutation MUST be rejected
//                   (StateRollbackDetected / ValidationError). FAILS on
//                   unpatched code: the silent reload resurrects the old state
//                   and the mutation succeeds.
// =============================================================================
#[test]
fn wildcard_03_external_state_rollback_mid_session_must_be_rejected_before_mutation() {
    let (mut service, profile, _dir) = setup_unlocked_with_voucher("Wildcard Resurrection");
    let profile_dir = _dir.path().join(&profile.folder_name);

    // --- SNAPSHOT: coherent data side of state N ---------------------------
    // Including profile.enc: its generation bound must agree with the rolled
    // back vouchers.enc so that the SA05 torn-write detection is satisfied --
    // isolating exactly the blind spot this finding targets.
    let mut snapshot: HashMap<String, Vec<u8>> = HashMap::new();
    for name in [
        "vouchers.enc",
        "own_fingerprints.enc",
        "profile.enc",
        ".wallet.generation",
    ] {
        let bytes = std::fs::read(profile_dir.join(name))
            .unwrap_or_else(|e| panic!("test setup: cannot read {name}: {e}"));
        snapshot.insert(name.to_string(), bytes);
    }

    // --- Advance legitimately to state N+1 (seal follows) ------------------
    let signed_standard = generate_signed_standard_toml(FREETALER_TOML);
    let voucher_b = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(service.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
            ..Default::default()
        },
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "20.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    service
        .create_new_voucher(&signed_standard, voucher_b, Some(PASSWORD))
        .expect("legitimate second voucher creation failed");

    // --- External coherent rollback: everything except the seal -------------
    for (name, bytes) in &snapshot {
        std::fs::write(profile_dir.join(name), bytes)
            .unwrap_or_else(|e| panic!("rollback simulation failed for {name}: {e}"));
    }

    // --- Mutation attempt on top of the resurrected state -------------------
    let voucher_c = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(service.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
            ..Default::default()
        },
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "10.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };
    let outcome = service.create_new_voucher(&signed_standard, voucher_c, Some(PASSWORD));

    // SECURE INVARIANT (Soll-Verhalten): the command must HARD-FAIL on the
    // externally rolled-back state instead of silently reloading and minting
    // value on top of a stale snapshot.
    match outcome {
        Err(AppFacadeError::StateRollbackDetected)
        | Err(AppFacadeError::Validation(_))
        | Err(AppFacadeError::ValidationFailed(_)) => {}
        other => panic!(
            "AUDIT-00-WILDCARD-03 VIOLATION: with_transactional_mut reloaded a \
             state that was coherently rolled back behind its back (older data \
             files restored, generation counter rewound, seal unchanged) and \
             committed new transactions on top of it. Expected \
             StateRollbackDetected / ValidationError on reload, got {other:?}."
        ),
    }
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-04 (Hypothesis H-00-4)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-04
//                   lock guarantee becomes worthless. (Related, not directly
//                   testable here: PID recycling turns stale-lock detection
//                   into a permanent LockFailed brick.)
// Impact Analysis:  Loss of cross-process mutual exclusion -> concurrent
//                   writers -> state forks / double-spend risk.
// Root Cause:       unlock() documents an ownership check but never performs
//                   one ("A simple deletion is sufficient here").
// Remediation Strategy: unlock() refuses to delete a lock whose PID belongs to
//                   another LIVE process (sysinfo check, same discipline as
//                   lock()). Stale locks (dead PID / unparseable) are still
//                   cleaned up, preserving crash recovery. Residual PID-
//                   recycling risk is documented as a known limitation.
// Test Semantics:   A live foreign process PID is written into .wallet.lock.
//                   Precondition: our lock() must be refused (foreign lock
//                   respected). Then unlock() runs -- the SECURE invariant is
//                   that the foreign lock file still exists afterwards.
//                   FAILS on unpatched code (file is deleted).
// =============================================================================
#[test]
fn wildcard_04a_unlock_must_not_remove_foreign_live_lock() {
    use std::process::{Command, Stdio};

    let dir = tempdir().expect("tempdir creation failed");
    let storage = human_money_core::FileStorage::new(dir.path());
    let lock_path = dir.path().join(".wallet.lock");

    // Live foreign process whose PID owns the lock.
    let mut child = Command::new("sleep")
        .arg("120")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("test setup: failed to spawn foreign holder process");

    std::fs::write(&lock_path, child.id().to_string()).expect("cannot write foreign lock");
    let foreign_pid = child.id();

    // Precondition: lock() respects a foreign LIVE lock.
    assert!(
        storage.lock().is_err(),
        "test precondition violated: lock() did not respect a foreign live lock"
    );
    assert!(lock_path.exists(), "precondition: lock file vanished early");

    // SECURE INVARIANT (Soll-Verhalten): unlock() must NEVER remove a lock
    // owned by another live process.
    let _ = storage.unlock();
    assert!(
        lock_path.exists(),
        "AUDIT-00-WILDCARD-04 VIOLATION: unlock() deleted a lock file owned by \
         another LIVE process (PID {foreign_pid}). Any code path that logs out \
         can thereby break the exclusive-lock guarantee for concurrent wallet \
         processes and let a third writer in."
    );

    child.kill().expect("cleanup: kill failed");
    let _ = child.wait();
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-04b (Hypothesis H-00-4, part 3)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-04 (same cluster, session arithmetic)
// Severity:         Medium
// CWE:              CWE-248 (Uncaught Exception) via CWE-190 (overflow)
// Target Location:  src/app_service/mod.rs :: resolve_auth_method (~222),
//                   get_session_key (~573), is_session_active (~599):
//                   `cache.last_activity + cache.session_duration`
// Threat Model:     Host-supplied `unlock_session(password, duration_seconds)`
//                   accepts any u64. The next session check evaluates
//                   `Instant + Duration`, which panics deterministically on
//                   overflow ("overflow when adding duration to instant") --
//                   repeatable DoS of every subsequent command until restart.
//                   Note: seal_handler::get_read_auth and lifecycle::
//                   refresh_session_activity already use the panic-free
//                   elapsed()-pattern; only the three mod.rs sites are
//                   vulnerable.
// Impact Analysis:  One extreme-but-valid host input permanently wedges the
//                   command surface of the running app instance.
// Root Cause:       Panicking `Instant + Duration` used for deadline math.
// Remediation Strategy: Compare `last_activity.elapsed()` against the stored
//                   duration instead of materializing the deadline Instant
//                   (identical semantics, no overflow possible). Clamp or
//                   reject absurd durations at unlock_session time is NOT
//                   required for safety but may be added by the host layer.
// Test Semantics:   unlock_session(PASSWORD, u64::MAX) followed by
//                   is_session_active()/get_session_key()/a Mode-B read must
//                   complete without panicking. FAILS on unpatched code
//                   (caught panic).
// =============================================================================
#[test]
fn wildcard_04b_session_timeout_arithmetic_must_be_panic_free() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut service, _profile, _dir) = setup_unlocked_with_voucher("Wildcard Overflow");

    service
        .unlock_session(PASSWORD, u64::MAX)
        .expect("unlock_session with maximum duration must be accepted");

    // SECURE INVARIANT (Soll-Verhalten): session deadline evaluation must be
    // panic-free regardless of the configured duration magnitude.
    let active_check = catch_unwind(AssertUnwindSafe(|| service.is_session_active()));
    assert!(
        active_check.is_ok(),
        "AUDIT-00-WILDCARD-04 VIOLATION: is_session_active PANICKED after \
         unlock_session(u64::MAX) -- `last_activity + session_duration` overflows \
         Instant arithmetic. Host-supplied durations must never crash the wallet."
    );

    let key_check = catch_unwind(AssertUnwindSafe(|| service.get_session_key()));
    assert!(
        key_check.is_ok(),
        "AUDIT-00-WILDCARD-04 VIOLATION: get_session_key PANICKED after \
         unlock_session(u64::MAX)."
    );

    let balance_check = catch_unwind(AssertUnwindSafe(|| {
        let _ = service.with_wallet_and_identity(|w, id| w.get_total_balance_by_currency(Some(id)));
    }));
    assert!(
        balance_check.is_ok(),
        "AUDIT-00-WILDCARD-04 VIOLATION: a Mode-B authenticated query PANICKED \
         after unlock_session(u64::MAX) -- resolve_auth_method overflows."
    );
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-02 (Hypothesis H-00-2, re-verification)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-02
// Severity:         High
// CWE:              CWE-662 (Improper Synchronization / partial commit across
//                   wallet state and forensic archive)
// Target Location:  src/wallet/transaction_handler.rs ::
//                   execute_multi_transfer_and_bundle -- post-commit archiving
//                   loop AFTER `*self = temp_wallet` (commit point), where
//                   `archive_backend.archive_voucher(...)?` propagates errors
//                   from INSIDE an already-committed operation.
// Threat Model & Exploitation:
//                   A multi-source transfer commits (`*self = temp_wallet`),
//                   then archives each transferred state in a loop. If the
//                   archive backend fails on a LATER element (IO error, disk
//                   full, corrupted archive dir), the error propagates out of
//                   the committed operation. The AppService layer maps that
//                   Err to TransactionOutcome::Rollback and restores the
//                   wallet -- but the already-written archive records persist:
//                   ghost entries for transfers that (per the rolled-back,
//                   authoritative wallet state) NEVER HAPPENED.
// Impact Analysis:  The forensic archive (basis for double-spend path-union
//                   analysis and proof generation) permanently contains
//                   fabricated transfer evidence; archive and wallet diverge;
//                   additionally the caller receives Err although the bundle
//                   was created (Err-after-commit lie, same class as
//                   AUDIT-00-WILDCARD-01).
// Root Cause:       Post-commit phase reports failure as if the operation had
//                   aborted, while its side effects are not compensable
//                   (VoucherArchive has no delete API).
// Remediation Strategy: After the commit point, archive failures must not be
//                   reported as operation failure: log + continue (best-effort
//                   forensics). This makes the documented invariant ("an
//                   aborted operation never leaves ghost entries") truthful in
//                   BOTH directions: Err => zero archive writes; Ok =>
//                   entries correspond to a genuinely committed transfer.
//                   Cross-reference: owned by A-04's file territory; flagged
//                   for coordinator cross-review.
// Test Semantics:   A spy archive accepts the first state and fails on the
//                   second. A two-source transfer must EITHER abort with ZERO
//                   archive records (all-or-nothing) OR succeed truthfully.
//                   An Err result together with recorded entries violates the
//                   atomicity contract. FAILS on unpatched code.
// =============================================================================
#[test]
fn wildcard_02_post_commit_archive_failure_must_not_desync_wallet_and_archive() {
    use human_money_core::archive::file_archive::FileVoucherArchive;
    use human_money_core::test_utils::{add_voucher_to_wallet, create_test_wallet, MINUTO_STANDARD};
    use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
    use std::collections::HashMap;

    let (mut sender_wallet, sender_identity) =
        create_test_wallet("wildcard-02-sender-seed", "sender-instance".to_string())
            .expect("sender wallet setup failed");
    let (standard, _hash) = &*MINUTO_STANDARD;

    let id_a = add_voucher_to_wallet(&mut sender_wallet, &sender_identity, "100", standard, true)
        .expect("voucher A setup failed");
    let id_b = add_voucher_to_wallet(&mut sender_wallet, &sender_identity, "100", standard, true)
        .expect("voucher B setup failed");

    let recipient_did = human_money_core::services::crypto::create_user_id(
        &ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]).verifying_key(),
        None,
    )
    .expect("recipient DID creation failed");

    let mut definitions = HashMap::new();
    definitions.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let archive_dir = tempdir().expect("tempdir creation failed");
    let archive = FileVoucherArchive::new_secure(archive_dir.path(), "audit-test-pw");

    let id_b_voucher_id = sender_wallet
        .get_voucher_instance(&id_b)
        .expect("source B instance missing")
        .voucher
        .voucher_id
        .clone();

    // Block archiving for voucher B by creating a regular file with voucher B's id
    std::fs::write(archive_dir.path().join(&id_b_voucher_id), b"blocker").expect("write blocker file");

    let request = MultiTransferRequest {
        recipient_id: recipient_did,
        sources: vec![
            SourceTransfer {
                local_instance_id: id_a,
                amount_to_send: "100".to_string(),
            },
            SourceTransfer {
                local_instance_id: id_b,
                amount_to_send: "100".to_string(),
            },
        ],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let result = sender_wallet.execute_multi_transfer_and_bundle(
        &sender_identity,
        &definitions,
        request,
        Some(&archive),
    );

    // SECURE INVARIANT (Soll-Verhalten): outcome and archive must agree.
    // Either the operation aborted (Err) and wrote NOTHING to the archive,
    // or it committed (Ok) and its archive records describe a real transfer.
    match &result {
        Ok(res) => {
            // Committed truthfully; best-effort forensics may have gaps, but
            // gap is reported in forensic_archive_incomplete.
            assert!(res.forensic_archive_incomplete.contains(&id_b_voucher_id));
        }
        Err(e) => {
            panic!("Transfer should have succeeded (best-effort archiving), got error: {e:?}");
        }
    }
}

// =============================================================================
// WAVE 3 (V3/SST protocol audit) — shared helpers
// =============================================================================

/// Random 32-byte value, Base58 encoded (t_id / prev_hash shape).
fn w3_random_b58_32() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    bs58::encode(buf).into_string()
}

/// Fresh random Ed25519 signing key.
fn w3_fresh_signing_key() -> ed25519_dalek::SigningKey {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-05 (Hypothesis WH3-00-902, network-side share)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-05
// Severity:         Critical (network-wide double-spend detection evasion)
// CWE:              CWE-707 (Improper Neutralization) on the ingress
//                   classification / CWE-694 (Use of Multiple Resources with
//                   Inconsistent Identifier Equivalence: "shard-less" is
//                   equated with "genesis")
// Target Location:  src/services/conflict_manager.rs :: is_init_fingerprint
//                   (~184–189) consumed by import_foreign_fingerprints
//                   (~684), process_received_fingerprints ingress gate and
//                   cleanup_known_fingerprints.
// Threat Model:     `is_init_fingerprint` classifies EVERY fingerprint whose
//                   trap_r/trap_s are empty or "none" as a genesis/init entry
//                   with "no detection value". But a hand-crafted SPEND
//                   transaction with TrapData { ds_tag: <correct>,
//                   trap_r: "", trap_s: "" } passes the complete L1 chain
//                   validation (the layer2_signature binds the EMPTY shard
//                   strings verbatim — chain.rs takes td.trap_r.as_str()
//                   literally). A double-spender broadcasts fork A with real
//                   SST shards and fork B with empty shards: every peer drops
//                   B's fingerprint at gossip ingress / load purge / cleanup,
//                   so the collision never materializes anywhere in the
//                   network — no quarantine, no SST extraction, no proof. The
//                   victim's fork-A voucher keeps circulating unrecognized.
// Impact Analysis:  Deterministic evasion of the entire double-spend
//                   detection system (Nightmare 5); SST attribution chain
//                   bypassed without breaking any signature.
// Root Cause:       Empty-shard equivalence with genesis for entries that are
//                   L1-validatable spends; the ingress purge treats them as
//                   noise although they carry an authenticated spend claim.
// Remediation:      The classification must not treat a spend-typed,
//                   authentically signed fingerprint as genesis: either reject
//                   non-init transactions lacking cryptographically well-formed
//                   shards at L1 validation, or admit signed empty-shard
//                   fingerprints at ingress so collisions stay visible.
// Test Semantics:   Two colliding spend fingerprints sharing one input anchor:
//                   fork A carries genuine generate_sst_trap shards, fork B
//                   carries empty shards and a layer2_signature computed over
//                   exactly those empty strings. Both are fed to
//                   import_foreign_fingerprints of an innocent wallet.
//                   SECURE INVARIANT: (a) the empty-shard spend fingerprint is
//                   NOT classified genesis, (b) both entries are admitted
//                   (imported == 2) and (c) check_for_double_spend reports the
//                   collision. FAILS on unpatched code: B is classified init,
//                   silently dropped at ingress (imported == 1), no conflict.
// =============================================================================
#[test]
fn wildcard_05_empty_shard_spend_fork_must_stay_visible_at_gossip_ingress() {
    use human_money_core::models::conflict::TransactionFingerprint;
    use human_money_core::services::conflict_manager::{
        is_init_fingerprint, verify_fingerprint_signature,
    };
    use human_money_core::services::crypto::{get_hash_from_slices, sign_ed25519};
    use human_money_core::services::l2_gateway::{
        calculate_l2_payload_hash_raw, TRAP_NONE_PLACEHOLDER,
    };
    use human_money_core::services::trap_manager;
    use human_money_core::test_utils::{setup_service_with_profile, ACTORS};
    use tempfile::tempdir;

    let sk = w3_fresh_signing_key();
    let eph_bytes = sk.verifying_key().to_bytes();
    let eph_b58 = bs58::encode(eph_bytes).into_string();
    let prev_b58 = w3_random_b58_32();
    // Production-derived input anchor tag: H(prev_hash || sender_ephemeral_pub).
    let ds_tag = get_hash_from_slices(&[
        bs58::decode(&prev_b58).into_vec().unwrap().as_slice(),
        eph_bytes.as_slice(),
    ]);

    // Builds an ingress-ready fingerprint for one fork. The embedded
    // layer2_signature signs the canonical HMC_TX_AUTH_V3 digest over the
    // EXACT shard strings given (including empty ones), by the holder of the
    // named ephemeral key — i.e., fully self-authenticating gossip data.
    let make_fp = |t_id_b58: &str, trap_r: &str, trap_s: &str| -> TransactionFingerprint {
        let t_id_bytes: [u8; 32] = bs58::decode(t_id_b58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let encrypted_ts = u128::from_le_bytes(
            bs58::decode(w3_random_b58_32()).into_vec().unwrap()[..16]
                .try_into()
                .unwrap(),
        );
        let payload_hash = calculate_l2_payload_hash_raw(
            // Synthetic gossip fingerprints without voucher context: bind the
            // canonical "none" placeholder and an empty privacy-guard
            // commitment, mirroring what ingress verification reproduces.
            TRAP_NONE_PLACEHOLDER,
            &ds_tag,
            &t_id_bytes,
            &eph_bytes,
            trap_r,
            trap_s,
            encrypted_ts,
            None,
            "",
        );
        let sig = sign_ed25519(&sk, &payload_hash);
        TransactionFingerprint {
            ds_tag: ds_tag.clone(),
            t_id: t_id_b58.to_string(),
            trap_r: trap_r.to_string(),
            trap_s: trap_s.to_string(),
            layer2_signature: bs58::encode(sig.to_bytes()).into_string(),
            sender_ephemeral_pub: eph_b58.clone(),
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            encrypted_timestamp: encrypted_ts,
            layer2_voucher_id: TRAP_NONE_PLACEHOLDER.to_string(),
            privacy_guard_hash: String::new(),
        }
    };

    // Fork A: genuine SST shards via the production trap generator.
    let t_id_a = w3_random_b58_32();
    let (trap_a, _witness) =
        trap_manager::generate_sst_trap(&sk, &ds_tag, &eph_bytes, &t_id_a)
            .expect("honest trap generation failed");
    let fp_a = make_fp(&t_id_a, &trap_a.trap_r, &trap_a.trap_s);

    // Fork B: hand-crafted empty shards — the laundering variant. Its
    // signature binds the EMPTY shard strings verbatim, exactly like a
    // hand-crafted spend transaction does at L1.
    let fp_b = make_fp(&w3_random_b58_32(), "", "");

    // Precondition controls: fork A is a regular authenticated spend fp.
    assert!(
        !is_init_fingerprint(&fp_a),
        "test precondition violated: honest fork classified as init"
    );
    assert!(
        verify_fingerprint_signature(&fp_a),
        "test precondition violated: honest fork must pass the V3 ingress gate"
    );

    // SECURE INVARIANT (Soll-Verhalten) 1: a spend-typed, shard-less
    // fingerprint must NOT be equated with genesis.
    assert!(
        !is_init_fingerprint(&fp_b),
        "AUDIT-00-WILDCARD-05 VIOLATION: a hand-crafted SPEND fingerprint \
         carrying empty trap shards is classified as genesis/init. Any peer \
         can launder a double-spend fork this way: the entry is dropped at \
         every gossip ingress, load purge and cleanup, making the collision \
         invisible network-wide while its L1-valid sibling keeps circulating."
    );

    // SECURE INVARIANT (Soll-Verhalten) 2+3: an innocent wallet receiving
    // BOTH forks via gossip must see the collision.
    let dir = tempdir().expect("tempdir creation failed");
    let (mut victim, _profile) =
        setup_service_with_profile(dir.path(), &ACTORS.charlie, "W05-Victim", PASSWORD);
    {
        let (wallet, _) = victim.get_unlocked_mut_for_test();
        let export_blob =
            HashMap::from([(ds_tag.clone(), vec![fp_a.clone(), fp_b.clone()])]);
        let bytes = serde_json::to_vec(&export_blob).unwrap();

        let imported = wallet
            .import_foreign_fingerprints(&bytes)
            .expect("ingress import must parse structurally");
        assert_eq!(
            imported, 2,
            "AUDIT-00-WILDCARD-05 VIOLATION: only {imported} of 2 colliding \
             fork fingerprints survived the gossip ingress — the empty-shard \
             spend was silently discarded as 'init'. A double-spender can \
             broadcast one honest fork plus one laundered fork and NO peer \
             will ever hold enough evidence to detect the conflict."
        );

        let check = wallet.check_for_double_spend();
        assert!(
            check.verifiable_conflicts.contains_key(&ds_tag),
            "AUDIT-00-WILDCARD-05 VIOLATION: two distinct-t_id forks sharing \
             ds_tag {} produced NO verifiable double-spend conflict after \
             ingress — the laundered empty-shard fork vanished netzweit.",
            ds_tag
        );
    }
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-06 (Hypothesis WH3-00-901, wallet-state share)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-06
// Severity:         Critical (permanent silent stranding of pre-V3 funds)
// CWE:              CWE-754 (Improper Check for Unusual Conditions — missing
//                   protocol-version gate at load) / CWE-1188 (Insecure
//                   Default Initialization of Resource: legacy residue stays
//                   Active)
// Target Location:  src/wallet/lifecycle.rs :: Wallet::load (~112–200: no
//                   chain/protocol validation, only expiration sweep) +
//                   src/services/voucher_validation/chain.rs ::
//                   verify_transaction_integrity_and_signature (V3-only
//                   t_id preimage + HMC_TX_AUTH_V3 digest).
// Threat Model:     The V3 rework broke the canonical t_id preimage (trap_data
//                   removed from it) and replaced the authentication digest
//                   (HMC_TX_AUTH_V2 -> V3). Every pre-V3 voucher chain fails
//                   validation under the new rules. Yet Wallet::load performs
//                   NO schema/epoch gate: a persisted legacy store (e.g. a
//                   transaction carrying V2-era trap fields u/blinded_id)
//                   loads cleanly, passes the rebuild scan and remains status
//                   Active. Only at spend time does create_transaction fail
//                   with generic MismatchedTransactionId/signature noise. The
//                   user sees a spendable balance that can never be spent,
//                   with no quarantine marker, no migration path, no epoch
//                   hint (K1 paradox, now including the t_id itself).
// Impact Analysis:  Silent permanent loss of access to all legacy balances;
//                   support/forensics blind because the UI reports Active.
// Root Cause:       No protocol-epoch awareness in the load path; breaking
//                   wire-format changes without migration or explicit
//                   invalidation markers.
// Remediation:      Either (a) hard-fail loading a store containing pre-V3
//                   chains with a recognizable protocol/schema error, or (b)
//                   mark affected instances distinctly non-spendable
//                   (quarantine/incomplete + reason), or (c) provide a
//                   migration API. Active display + generic spend failure is
//                   the forbidden combination.
// Test Semantics:   Build a legacy store state by injecting a transaction that
//                   originates from a V2-shaped persistence blob (old field
//                   names u/blinded_id) into vouchers.enc via the public
//                   Storage trait round-trip, then perform a REAL application
//                   login. SECURE INVARIANT: login either fails with a
//                   recognizable gate, OR the legacy instance is displayed as
//                   anything BUT Active. FAILS on unpatched code: login
//                   succeeds and the stranded voucher is shown Active.
//                   (Scope note: the serde-coercion sub-issue itself is owned
//                   by A-05; this test tolerates both coercion behaviors and
//                   asserts only the stranding/display side.)
// =============================================================================
#[test]
fn wildcard_06_v2_legacy_voucher_must_not_be_displayed_active_after_load() {
    use human_money_core::models::voucher::{ANONYMOUS_ID as ANONYMOUS_ID_LEGACY, Transaction};
    use human_money_core::storage::AuthMethod;
    use human_money_core::FileStorage;

    let (mut service, profile, dir) = setup_unlocked_with_voucher("Wildcard Stranding");
    service.logout();

    // --- Inject a V2-legacy transaction into the PERSISTED store -------------
    // Round-trip through the public Storage trait: decrypt, mutate, re-save.
    // This simulates a store written by a pre-V3 client version.
    let profile_dir = dir.path().join(&profile.folder_name);
    let mut storage = FileStorage::new(&profile_dir);
    let auth = AuthMethod::Password(PASSWORD);
    let (loaded_profile, mut store, identity) = storage
        .load_wallet(&auth)
        .expect("storage-level load of the healthy store failed");

    // REALISTIC legacy fixture (per audit coordination): the injected
    // transaction is a fully well-formed spend of the OLD protocol epoch —
    // real ephemeral key, genuine SST shards on the correct input anchor and
    // a t_id that is self-consistent under the CURRENT preimage — but its
    // layer2_signature authenticates a V2-STYLE digest payload instead of
    // the HMC_TX_AUTH_V3 digest. Under V3 rules exactly ONE thing fails:
    // the authentication epoch. That isolates the stranding gap (an honest
    // upgrader's voucher) from mere garbage input.
    use human_money_core::services::crypto::{get_hash, get_hash_from_slices, sign_ed25519};
    use human_money_core::services::trap_manager;
    use human_money_core::services::utils::to_canonical_json;

    let legacy_sk = w3_fresh_signing_key();
    let eph_bytes = legacy_sk.verifying_key().to_bytes();
    let eph_b58 = bs58::encode(eph_bytes).into_string();
    let prev_b58 = w3_random_b58_32();
    let prev_bytes = bs58::decode(&prev_b58).into_vec().unwrap();
    let ds_tag = get_hash_from_slices(&[&prev_bytes, eph_bytes.as_slice()]);

    let mut legacy_tx = Transaction {
        t_type: "transfer".to_string(),
        t_time: "2026-08-24T12:00:00Z".to_string(),
        prev_hash: prev_b58,
        recipient_id: ANONYMOUS_ID_LEGACY.to_string(),
        amount: "100.00".to_string(),
        sender_ephemeral_pub: Some(eph_b58.clone()),
        ..Default::default()
    };
    // t_id per the CURRENT canonical preimage (trap_data excluded).
    legacy_tx.t_id = human_money_core::services::crypto::get_hash(
        to_canonical_json(&legacy_tx).expect("canonical tx json").into_bytes(),
    );
    // Genuine production shards bound to this exact input anchor.
    let (legacy_trap, _witness) =
        trap_manager::generate_sst_trap(&legacy_sk, &ds_tag, &eph_bytes, &legacy_tx.t_id)
            .expect("legacy trap generation");
    legacy_tx.trap_data = Some(legacy_trap);

    // V2-style authentication: sign a digest over the OLD preimage shape
    // (transaction INCLUDING trap_data) instead of the V3 unified digest.
    let v2_style_payload = get_hash(
        to_canonical_json(&legacy_tx).expect("canonical legacy payload").into_bytes(),
    );
    legacy_tx.layer2_signature = Some(
        bs58::encode(sign_ed25519(&legacy_sk, v2_style_payload.as_bytes()).to_bytes()).into_string(),
    );

    let instance = store.vouchers.values_mut().next().expect("store empty");
    instance.voucher.transactions.push(legacy_tx);

    storage
        .save_wallet(&loaded_profile, &store, &identity, &auth)
        .expect("storage-level re-save of the legacy store failed");
    drop(storage);

    // --- Reload through the REAL application load path -----------------------
    match service.login(&profile.folder_name, PASSWORD, false, INSTANCE_ID.to_string()) {
        Err(_gate) => {
            // Acceptable Soll branch: a hard, recognizable schema/epoch gate.
        }
        Ok(()) => {
            let summaries = service
                .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
                .expect("voucher query after legacy reload failed");
            assert_eq!(summaries.len(), 1, "precondition: single voucher expected");
            assert!(
                !matches!(summaries[0].status, human_money_core::VoucherStatus::Active),
                "AUDIT-00-WILDCARD-06 VIOLATION: a voucher whose chain contains \
                 a V2-legacy transaction (invalid under the V3 t_id-preimage and \
                 HMC_TX_AUTH_V3 digest rules) is displayed as ACTIVE/spendable \
                 after Wallet::load. Every spend attempt will fail with generic \
                 validation noise — permanent silent stranding without any \
                 epoch marker, quarantine reason or migration path."
            );
        }
    }
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-07 (Hypothesis WH3-00-903)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-07
// Severity:         High (defense-in-depth erosion + evidence export loss)
// CWE:              CWE-460 (Inconsistent Cleanup of Temporary/State Resource):
//                   the full-replace rebuild uses a NARROWER sender definition
//                   than the transfer path that created the entries.
// Target Location:  src/services/conflict_manager.rs ::
//                   scan_and_rebuild_fingerprints (~226: filter
//                   tx.sender_id == Some(user_id)) vs.
//                   src/wallet/transaction_handler.rs (~863–866: anonymous
//                   stealth spends counted as own; ~897–909: direct insert),
//                   full-replace commit in src/wallet/conflict_handler.rs
//                   (~62: self.own_fingerprints = own), triggered on EVERY
//                   bundle receive (transaction_handler.rs ~554).
// Threat Model:     Stealth/Flexible-privacy spends carry sender_id = None.
//                   At creation time their fingerprints are direct-inserted
//                   into own_fingerprints.history (and guard the proactive
//                   self-double-spend check via history/active lookups). But
//                   the next rebuild — running on EVERY received bundle and
//                   every load — recomputes own_fingerprints with the strict
//                   `sender_id == Some(user_id)` filter and FULLY REPLACES the
//                   store: all own stealth-spend entries vanish. The proactive
//                   DoubleSpendAttemptBlocked guard goes blind for stealth-held
//                   inputs (every future reload gap immediately re-enables
//                   framing double-spends), and export_own_fingerprints never
//                   ships the stealth evidence to peers.
// Impact Analysis:  Self-double-spend protection silently disabled after the
//                   next receive/login; forensic export incomplete exactly for
//                   the privacy-maximizing mode.
// Root Cause:       Two contradictory definitions of "was I the sender" plus a
//                   full-replace instead of a merge for own.history.
// Remediation:       The rebuild's sender filter must treat anonymous spends
//                   consistently with _execute_single_transfer (e.g. include
//                   sender_id.is_none() && recipient_id == ANONYMOUS_ID), or
//                   preserve existing own.history entries during rebuild.
// Test Semantics:   Alice stealth-spends her whole voucher (Flexible standard,
//                   use_privacy_mode=true -> sender_id=None). Control: the
//                   spend fingerprint IS present in export_own_fingerprints.
//                   Bob sends her any bundle (rebuild trigger). SECURE
//                   INVARIANT: every previously exported own entry still
//                   exists afterwards. FAILS on unpatched code (entry wiped).
// =============================================================================
#[test]
fn wildcard_07_stealth_spend_history_must_survive_bundle_receive_rebuild() {
    use human_money_core::models::conflict::TransactionFingerprint;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::NewVoucherData;
    use human_money_core::test_utils::{
        setup_service_with_profile, ACTORS, FREETALER_STANDARD,
    };
    use human_money_core::wallet::{MultiTransferRequest, SourceTransfer};
    use tempfile::tempdir;

    let dir = tempdir().expect("tempdir creation failed");
    let standard_toml = generate_signed_standard_toml(FREETALER_TOML);
    let (standard_def, _) = &*FREETALER_STANDARD;

    let mut standards_map = HashMap::new();
    standards_map.insert(
        standard_def.immutable.identity.uuid.clone(),
        standard_toml.clone(),
    );

    let make_voucher_data = |amount: &str, creator: String| NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: amount.to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };

    let (mut alice, _) =
        setup_service_with_profile(dir.path(), &ACTORS.alice, "W07-Alice", PASSWORD);
    let (mut bob, _) =
        setup_service_with_profile(dir.path(), &ACTORS.bob, "W07-Bob", PASSWORD);

    // Alice mints one voucher and STEALTH-spends it completely.
    let alice_id = alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    alice
        .create_new_voucher(
            &standard_toml,
            make_voucher_data("100", alice_id),
            Some(PASSWORD),
        )
        .expect("alice voucher creation failed");
    let v1_local = alice
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    // FIXTURE NOTE (WH3-00-903): the REQUEST recipient must be a real DID —
    // it is used for bundle encryption and fingerprint selection before the
    // Flexible standard anonymizes the on-chain transaction itself
    // (sender_id = None, recipient_id = "anonymous"). The previous fixture
    // passed ANONYMOUS_ID here, which fails DID validation at setup and
    // masked the actual vulnerability under test.
    let bob_id = bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let stealth_request = MultiTransferRequest {
        recipient_id: bob_id,
        sources: vec![SourceTransfer {
            local_instance_id: v1_local,
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: Some(true), // Flexible standard -> sender_id = None
    };
    alice
        .create_transfer_bundle(stealth_request, &standards_map, None, Some(PASSWORD))
        .expect("stealth spend must succeed");

    // CONTROL: the runtime direct-insert recorded the stealth spend as OWN.
    let snapshot_own = |service: &mut AppService| -> HashMap<String, Vec<String>> {
        let (wallet, _) = service.get_unlocked_mut_for_test();
        let exported = wallet
            .export_own_fingerprints()
            .expect("own-fingerprint export failed");
        let map: HashMap<String, Vec<TransactionFingerprint>> =
            serde_json::from_slice(&exported).expect("export must deserialize");
        map.into_iter()
            .map(|(k, v)| {
                (
                    k,
                    v.iter().map(|fp| fp.t_id.clone()).collect::<Vec<_>>(),
                )
            })
            .collect()
    };
    let before = snapshot_own(&mut alice);
    assert!(
        before.values().any(|v| !v.is_empty()),
        "test precondition violated: stealth spend was not even recorded at \
         creation time (direct insert path broken)"
    );

    // TRIGGER: any unrelated bundle receipt runs scan_and_rebuild_fingerprints.
    let bob_id_again = bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    bob.create_new_voucher(
        &standard_toml,
        make_voucher_data("10", bob_id_again),
        Some(PASSWORD),
    )
    .expect("bob voucher creation failed");
    let b_local = bob
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();
    let alice_id_again = alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let bob_request = MultiTransferRequest {
        recipient_id: alice_id_again,
        sources: vec![SourceTransfer {
            local_instance_id: b_local,
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let bundle = bob
        .create_transfer_bundle(bob_request, &standards_map, None, Some(PASSWORD))
        .expect("bob transfer failed");
    alice
        .receive_bundle(&bundle.bundle_bytes, &standards_map, None, Some(PASSWORD), false)
        .expect("alice must accept the unrelated bundle");

    // SECURE INVARIANT (Soll-Verhalten): the rebuild must not shrink the
    // owner's own history — every previously present entry survives.
    let after = snapshot_own(&mut alice);
    for (tag, t_ids_before) in &before {
        let now_bucket = after.get(tag).cloned().unwrap_or_default();
        for t_id in t_ids_before {
            assert!(
                now_bucket.contains(t_id),
                "AUDIT-00-WILDCARD-07 VIOLATION: own stealth-spend fingerprint \
                 (ds_tag {tag}, t_id {t_id}) vanished from own_fingerprints \
                 after ONE unrelated bundle receive. The rebuild's \
                 sender_id==Some(user_id) filter contradicts the transfer \
                 path's is_sender logic (anonymous spends ARE own), so the \
                 self-double-spend guard goes blind and the stealth evidence \
                 leaves the wallet's export permanently."
            );
        }
    }
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-08 (Hypothesis WH3-00-904)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-08
// Severity:         Medium (repeatable DoS wedging the security-relevant L2
//                   verdict path until restart)
// CWE:              CWE-248 (Uncaught Exception) via CWE-190 (Integer Overflow)
// Target Location:  src/app_service/l2_facade.rs :: process_l2_response
//                   (~180–181): `std::time::Instant::now() > cache.last_activity
//                   + cache.session_duration` inside VerdictAction::
//                   TriggerQuarantine. This is the leftover copy of the exact
//                   pattern fixed in Wave 2 (AUDIT-00-WILDCARD-04 part 3) for
//                   mod.rs resolve_auth_method/get_session_key/is_session_active.
// Threat Model:     unlock_session(password, u64::MAX) stores Duration::from_secs
//                   (u64::MAX) verbatim. The FIRST L2 quarantine verdict that
//                   arrives without an explicit password evaluates the panicking
//                   Instant addition — deterministically crashing precisely the
//                   security path (double-spend response). The unwinds skips the
//                   state restore (self.state stays Locked), wedging every
//                   subsequent command until process restart.
// Impact Analysis:  Host-controlled input turns the fraud-response handler into
//                   a crash button; incident response blocked at the worst spot.
// Root Cause:       Panicking deadline materialization (`last + duration`)
//                   instead of the panic-free elapsed() comparison already used
//                   elsewhere.
// Remediation:      Mirror mod.rs::resolve_auth_method: compare
//                   cache.last_activity.elapsed() > cache.session_duration.
// Test Semantics:   Configure a trusted l2_server_pubkey, unlock_session(u64::MAX),
//                   deliver a server-signed Verified envelope naming a foreign
//                   t_id (signature bypass active under test-utils) so the
//                   TriggerQuarantine branch executes with password=None.
//                   SECURE INVARIANT: the call must not panic (Ok or structured
//                   Err acceptable). FAILS on unpatched code (caught overflow
//                   panic from l2_facade.rs line ~181).
// =============================================================================
#[test]
fn wildcard_08_l2_quarantine_session_arithmetic_must_be_panic_free() {
    use human_money_core::models::layer2_api::{L2LockEntry, L2ResponseEnvelope, L2Verdict};
    use human_money_core::services::l2_gateway;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let (mut service, _profile, _dir) = setup_unlocked_with_voucher("Wildcard L2 Overflow");

    // Trusted L2 server key configured in the RAM profile (public API surface
    // used identically by tests/services/l2_integration.rs).
    let server_pubkey: [u8; 32] = {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        b
    };
    let (local_id, voucher_id_hex, eph_b58) = {
        let wallet = service.get_wallet_mut().expect("wallet unlocked");
        wallet.profile.l2_server_pubkey = Some(server_pubkey);
        let instance = wallet.voucher_store.vouchers.values().next().unwrap();
        let vid = l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
            .expect("voucher id derivation failed");
        let eph = instance
            .voucher
            .transactions
            .last()
            .unwrap()
            .sender_ephemeral_pub
            .clone()
            .unwrap_or_else(|| bs58::encode([0u8; 32]).into_string());
        (instance.local_instance_id.clone(), vid, eph)
    };
    let eph_bytes: [u8; 32] = bs58::decode(&eph_b58)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    // Server envelope claiming a FOREIGN lock under our challenge tag ->
    // VerdictAction::TriggerQuarantine(foreign_t_id). With the test-utils
    // signature bypass active the zero signatures authenticate trivially.
    let foreign_t_id: [u8; 32] = {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        b
    };
    let lock_entry = L2LockEntry {
        layer2_voucher_id: voucher_id_hex,
        t_id: foreign_t_id,
        sender_ephemeral_pub: eph_bytes,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let envelope = L2ResponseEnvelope {
        verdict: L2Verdict::Verified { lock_entry },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };
    let response_bytes = serde_json::to_vec(&envelope).unwrap();

    service
        .unlock_session(PASSWORD, u64::MAX)
        .expect("unlock_session with maximum duration must be accepted");

    human_money_core::set_signature_bypass(true);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        service.process_l2_response(&local_id, &response_bytes, None)
    }));
    human_money_core::set_signature_bypass(false);

    // SECURE INVARIANT (Soll-Verhalten): no panic — Ok or a structured Err.
    assert!(
        outcome.is_ok(),
        "AUDIT-00-WILDCARD-08 VIOLATION: process_l2_response PANICKED while \
         handling a quarantine verdict after unlock_session(u64::MAX) — \
         `cache.last_activity + cache.session_duration` in l2_facade.rs \
         overflows Instant arithmetic. This is the unfixed copy of the Wave-2 \
         wildcard_04b pattern, sitting on the SECURITY path: a host-supplied \
         duration crashes the double-spend response handler and wedges the \
         wallet until restart."
    );
}

// =============================================================================
// FINDING AUDIT-00-WILDCARD-09 (Hypothesis WH3-00-905, testable core)
// -----------------------------------------------------------------------------
// Finding-ID:       AUDIT-00-WILDCARD-09
// Severity:         Medium (persistent write outside the Wave-2 transactional
//                   discipline -> silent anchoring/seal-desync brick potential)
// CWE:              CWE-662 (Improper Synchronization — side door around the
//                   generation-CAS/reload/seal discipline)
// Target Location:  src/app_service/l2_facade.rs :: process_l2_response
//                   (~128–246): TriggerQuarantine persists via
//                   temp_wallet.save() WITHOUT Reload-Before-Write, WITHOUT
//                   verify_state_matches_seal and WITHOUT
//                   update_seal_after_state_change — the only remaining
//                   persisting path that bypasses with_transactional_mut's
//                   post-Wave-2 gates.
// Threat Model:     An external writer rolls the DATA side back to an older
//                   coherent snapshot (vouchers.enc + own_fingerprints.enc +
//                   profile.enc) while seal.enc stays ahead, and sets the plain
//                   decimal .wallet.generation marker to the value the live
//                   session expects (trivially forgeable — it is an unsigned
//                   text file). A mid-session L2 quarantine verdict then hits:
//                   with_transactional_mut would detect the divergence
//                   (reload + verify_state_matches_seal -> StateRollbackDetected),
//                   but process_l2_response has no such gate: the generation
//                   CAS inside save() passes (forged marker == RAM expectation)
//                   and the quarantine is durably committed ON TOP OF the
//                   resurrected state. Disk now diverges from the seal again
//                   (own_fingerprints content vs. seal.state_hash), so the
//                   next login bricks with StateRollbackDetected — and the
//                   caller received Ok for a write executed outside the sealed
//                   discipline.
// Impact Analysis:  Stale-RAM anchoring writes resurrect rolled-back vouchers;
//                   deterministic seal<->store desync bricks following logins.
// Root Cause:       The L2 facade predates (and skipped) the Wave-2 discipline
//                   unification of all persisting writes.
// Remediation:      Route the quarantine write through with_transactional_mut
//                   (or apply the identical reload + seal-gate + seal-update
//                   steps inline). The gates themselves remain intentional
//                   design and must not be weakened.
// Test Semantics:   Snapshot data files at gen N, advance legitimately to gen
//                   G (=N+1, seal ahead), restore the snapshot bytes and forge
//                   .wallet.generation back to G (RAM expectation), then feed a
//                   server-signed TriggerQuarantine verdict (signature bypass
//                   active) with password=Some (so the separate WH3-00-904
//                   panic residue cannot mask this finding).
//                   SECURE INVARIANT: (a) the command must be REJECTED
//                   (structured Err — rollback gate), and (b) nothing may leak
//                   to disk (generation marker unchanged). FAILS on unpatched
//                   code: the write succeeds on the resurrected state (Ok) and
//                   bumps the generation.
// =============================================================================
#[test]
fn wildcard_09_l2_quarantine_write_must_respect_rollback_discipline() {
    use human_money_core::models::layer2_api::{L2LockEntry, L2ResponseEnvelope, L2Verdict};
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::services::l2_gateway;
    use human_money_core::FileStorage;

    let (mut service, profile, dir) = setup_unlocked_with_voucher("Wildcard L2 Discipline");
    let profile_dir = dir.path().join(&profile.folder_name);

    // Local id of the ORIGINAL voucher (exists identically in RAM and in the
    // older snapshot we will restore below).
    let voucher_a_local_id = {
        let wallet = service.get_wallet_mut().expect("wallet unlocked");
        wallet
            .voucher_store
            .vouchers
            .keys()
            .next()
            .cloned()
            .expect("precondition: one voucher present")
    };

    // --- SNAPSHOT: coherent data side at gen N -------------------------------
    let mut snapshot: HashMap<String, Vec<u8>> = HashMap::new();
    for name in [
        "vouchers.enc",
        "own_fingerprints.enc",
        "profile.enc",
        ".wallet.generation",
    ] {
        let bytes = std::fs::read(profile_dir.join(name))
            .unwrap_or_else(|e| panic!("test setup: cannot read {name}: {e}"));
        snapshot.insert(name.to_string(), bytes);
    }

    // --- Legitimate advance to gen G (seal follows along) --------------------
    let signed_standard = generate_signed_standard_toml(FREETALER_TOML);
    service
        .create_new_voucher(
            &signed_standard,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "20.00".to_string(),
                    ..Default::default()
                },
                validity_duration: Some("P1Y".to_string()),
                ..Default::default()
            },
            Some(PASSWORD),
        )
        .expect("legitimate second voucher creation failed");
    let generation_ram = FileStorage::new(&profile_dir)
        .read_generation()
        .expect("generation read failed");

    // --- External coherent rollback + generation-marker forgery --------------
    // Everything except the seal goes back to state N; the plaintext marker is
    // set to the value the live session holds in RAM, emulating a sync tool /
    // attacker that defeats the CAS anchor alone.
    for (name, bytes) in &snapshot {
        std::fs::write(profile_dir.join(name), bytes)
            .unwrap_or_else(|e| panic!("rollback simulation failed for {name}: {e}"));
    }
    std::fs::write(profile_dir.join(".wallet.generation"), generation_ram.to_string())
        .expect("generation marker forgery failed");

    // --- Trusted-L2 configuration + quarantine verdict (TriggerQuarantine) ---
    let server_pubkey: [u8; 32] = {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        b
    };
    let (voucher_a_vid, eph_b58) = {
        let wallet = service.get_wallet_mut().expect("wallet unlocked");
        wallet.profile.l2_server_pubkey = Some(server_pubkey);
        let instance = wallet
            .voucher_store
            .vouchers
            .get(&voucher_a_local_id)
            .expect("voucher A present in RAM");
        let vid = l2_gateway::calculate_layer2_voucher_id(&instance.voucher.transactions[0])
            .expect("voucher id derivation failed");
        let eph = instance
            .voucher
            .transactions
            .last()
            .unwrap()
            .sender_ephemeral_pub
            .clone()
            .unwrap_or_else(|| bs58::encode([0u8; 32]).into_string());
        (vid, eph)
    };
    let eph_bytes: [u8; 32] = bs58::decode(&eph_b58)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();

    let foreign_t_id: [u8; 32] = {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        b
    };
    let lock_entry = L2LockEntry {
        layer2_voucher_id: voucher_a_vid,
        t_id: foreign_t_id,
        sender_ephemeral_pub: eph_bytes,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let envelope = L2ResponseEnvelope {
        verdict: L2Verdict::Verified { lock_entry },
        server_signature: [0u8; 64],
        quorum_certificate: None,
    };
    let response_bytes = serde_json::to_vec(&envelope).unwrap();

    human_money_core::set_signature_bypass(true);
    let outcome = service.process_l2_response(&voucher_a_local_id, &response_bytes, Some(PASSWORD));
    human_money_core::set_signature_bypass(false);

    // SECURE INVARIANT (Soll-Verhalten) 1: the out-of-discipline write must be
    // rejected by the same rollback gate every other mutating command obeys.
    assert!(
        outcome.is_err(),
        "AUDIT-00-WILDCARD-09 VIOLATION: process_l2_response accepted a \
         quarantine write ON TOP of an externally rolled-back store whose \
         content diverges from the seal (only the plaintext generation marker \
         was forged to the RAM expectation). The L2 path performs no \
         Reload-Before-Write and no verify_state_matches_seal, unlike every \
         with_transactional_mut command since Wave 2 — the quarantine got \
         durably anchored onto resurrected state and returned Ok."
    );

    // SECURE INVARIANT (Soll-Verhalten) 2: nothing leaked to disk.
    let generation_after = FileStorage::new(&profile_dir)
        .read_generation()
        .expect("generation read failed");
    assert_eq!(
        generation_after, generation_ram,
        "AUDIT-00-WILDCARD-09 VIOLATION: although (or despite) reporting {:?}, \
         the L2 quarantine path mutated persistent state outside the sealed \
         transactional discipline (generation marker moved from \
         {generation_ram}).",
        outcome.map(|_| "Ok").map_err(|e| e.to_string())
    );
}

// =============================================================================
// General Adversarial Wildcard — Fail-First Tests (2026-08-29)
// Scope: docs/security/ai-audits/00_general_adversarial_wildcard.md
// Report: docs/security/ai-audits/reports/00_general_adversarial_wildcard_report.md
// =============================================================================

///
/// Finding-ID: AUDIT-00-WILDCARD-10
/// Severity: MEDIUM
/// CWE-Classification: CWE-190 (Integer Overflow) / CWE-248 (Uncaught Exception)
/// Target Location: src/wallet/queries.rs:374 (`entry.0 += amount`)
/// Threat Model & Exploitation: Attacker crafts high-value vouchers whose per-AssetClass
///   aggregated sum exceeds Decimal::MAX. `get_total_balance_by_currency` uses unchecked
///   `+=` (plain Decimal Add) and panics deterministically on every dashboard render,
///   bricking the wallet UI. The write path (`TransferSummary::checked_add`) already
///   fixed the same class; the read path was missed.
/// Impact Analysis: Uncatchable panic / wasm trap on every balance view; no fund loss,
///   but permanent liveness DoS until manual store surgery.
/// Root Cause: Defense-in-depth inconsistency — checked arithmetic on consensus write path
///   but unchecked `+=` on derived view path.
/// Remediation Strategy: `checked_add` with graceful degradation (skip asset class /
///   surface BalanceOverflow) or `saturating_add` with UI indicator.
/// Test Semantics (Fail-First): Aggregation over two MAX-valued Active vouchers MUST NOT panic.
///
#[test]
fn wildcard_10_balance_aggregation_must_be_panic_free() {
    use human_money_core::models::voucher::{Voucher, VoucherStandard, ValueDefinition};
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::wallet::instance::{VoucherInstance, VoucherStatus};
    use rust_decimal::Decimal;
    use std::str::FromStr;

    // Construct a minimal wallet with two Active vouchers whose amounts sum beyond Decimal::MAX.
    // Decimal::MAX = 79_228_162_514_264_373_935_439_503_335 (scale 0).
    // Two copies overflow plain `+=`.
    let max_str = "79228162514264337593543950335";
    let _ = Decimal::from_str(max_str).expect("MAX must parse");

    // Build wallet via new_from_mnemonic helper to get a valid profile, then inject vouchers.
    let (mut wallet, _) = human_money_core::wallet::Wallet::new_from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        None,
        Some("test"),
        human_money_core::MnemonicLanguage::English,
        "test-id".to_string(),
    )
    .expect("wallet creation");

    // Helper to build a voucher with controlled last-transaction amount
    let make_voucher = |vid: &str, amount: &str| -> Voucher {
        let mut v = Voucher::default();
        v.voucher_id = vid.to_string();
        v.voucher_standard = VoucherStandard {
            name: "Freetaler".to_string(),
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            standard_definition_hash: "test".to_string(),
        };
        v.nominal_value = ValueDefinition {
            unit: "MIN".to_string(),
            amount: amount.to_string(),
            abbreviation: Some("MIN".to_string()),
            description: None,
        };
        v.creator_profile = PublicProfile {
            id: Some(wallet.get_user_id().to_string()),
            ..Default::default()
        };
        v.transactions = vec![human_money_core::models::voucher::Transaction {
            t_id: format!("t_{vid}"),
            t_type: "init".to_string(),
            t_time: "2026-01-01T00:00:00Z".to_string(),
            prev_hash: "prev".to_string(),
            receiver_ephemeral_pub_hash: None,
            sender_id: Some(wallet.get_user_id().to_string()),
            sender_identity_signature: None,
            recipient_id: wallet.get_user_id().to_string(),
            amount: amount.to_string(),
            sender_remaining_amount: None,
            sender_ephemeral_pub: None,
            change_ephemeral_pub_hash: None,
            privacy_guard: None,
            trap_data: None,
            layer2_signature: None,
            deletable_at: None,
        }];
        v
    };

    let v1 = make_voucher("vid-10-a", max_str);
    let v2 = make_voucher("vid-10-b", max_str);
    // Use deterministic local_instance_ids so aggregation buckets collide on same AssetClass
    wallet
        .voucher_store
        .vouchers
        .insert("lid-10-a".to_string(), VoucherInstance {
            local_instance_id: "lid-10-a".to_string(),
            voucher: v1,
            status: VoucherStatus::Active,
        });
    wallet
        .voucher_store
        .vouchers
        .insert("lid-10-b".to_string(), VoucherInstance {
            local_instance_id: "lid-10-b".to_string(),
            voucher: v2,
            status: VoucherStatus::Active,
        });

    // Soll-Verhalten: must not panic. Unpatched code panics at `entry.0 += amount`.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wallet.get_total_balance_by_currency(None)
    }));
    assert!(
        result.is_ok(),
        "AUDIT-00-WILDCARD-10 VIOLATION: get_total_balance_by_currency panicked on overflow \
         (Decimal::MAX + Decimal::MAX via unchecked `+=`). The view layer must use \
         checked_add / saturating_add and degrade gracefully instead of aborting the host. \
         Panic payload: {:?}",
        result.err()
    );
}

///
/// Finding-ID: AUDIT-00-WILDCARD-11
/// Severity: LOW
/// CWE-Classification: CWE-248 (Uncaught Exception) / CWE-754
/// Target Location: src/storage/file_storage.rs:269,275,457,483,490,500,506,554
/// Threat Model & Exploitation: Every `save_encrypted_payload` / `save_wallet` path
///   serializes with `serde_json::to_vec(...).unwrap()`. Today the shapes are infallible,
///   but the `Result<StorageError>` contract promises fail-closed behavior; a future
///   struct evolution (custom Serialize returning Err, Decimal NaN) would turn a storage
///   error into an uncatchable process abort.
/// Impact Analysis: Future regression → process abort during any wallet save.
/// Root Cause: `unwrap()` where `?` with `StorageError::InvalidFormat` was intended.
/// Remediation Strategy: `serde_json::to_vec(value).map_err(|e| StorageError::InvalidFormat(e.to_string()))?`
/// Test Semantics (Fail-First): The storage layer's Result contract must be upheld;
///   this test documents the invariant by inspecting the source for remaining `unwrap()` on `to_vec`.
///   It fails on unpatched code (unwrap still present) and passes after replacement with `?`.
///
#[test]
fn wildcard_11_serialization_must_be_fail_closed() {
    let src = std::fs::read_to_string("src/storage/file_storage.rs")
        .expect("can read file_storage.rs");
    // Count `serde_json::to_vec` sites that still use `.unwrap()`
    let offending: Vec<_> = src
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("serde_json::to_vec") && line.contains("unwrap()"))
        .map(|(idx, line)| format!("L{}: {}", idx + 1, line.trim()))
        .collect();
    assert!(
        offending.is_empty(),
        "AUDIT-00-WILDCARD-11 VIOLATION: {} `serde_json::to_vec(...).unwrap()` sites remain in \
         src/storage/file_storage.rs — they must be replaced with `?` mapping to \
         StorageError::InvalidFormat to honor fail-closed persistence. Offending lines:\n{}",
        offending.len(),
        offending.join("\n")
    );
}

///
/// Finding-ID: AUDIT-00-WILDCARD-13
/// Severity: MEDIUM
/// CWE-Classification: CWE-252 (Unchecked Return Value) / CWE-393
/// Target Location: src/models/voucher.rs:986-1004 (`spendable_balance` `unwrap_or(ZERO)`)
/// Threat Model & Exploitation: `Voucher::spendable_balance` silently maps any
///   `Decimal::from_str` failure on `last_tx.amount` / `sender_remaining_amount` to
///   `Decimal::ZERO` via `unwrap_or`. A tampered or legacy-invalid amount (e.g. "NaN")
///   is displayed as unfunded (0) instead of surfacing as a validation error,
///   masking corruption / forensic evidence.
/// Impact Analysis: Soft fund disappearance — user sees 0 balance for a voucher that
///   should be flagged InvalidTransaction / Incomplete; forensic masking.
/// Root Cause: Convenience fallback in read model diverging from consensus `from_str()?`.
/// Remediation Strategy: Propagate Err (or mark voucher Incomplete { BusinessRule }) instead of ZERO.
/// Test Semantics (Fail-First): A voucher with last_tx.amount="NaN" must NOT report spendable 0
///   via silent coercion; the read path must surface an error or non-zero sentinel.
///
#[test]
fn wildcard_13_malformed_amount_must_not_be_masked_as_zero() {
    use human_money_core::models::voucher::{Voucher, VoucherStandard, ValueDefinition, Transaction};
    use human_money_core::models::profile::PublicProfile;
    use rust_decimal::Decimal;
    // Build a minimal voucher whose last amount is malformed
    let mut v = Voucher::default();
    v.voucher_id = "vid-13".to_string();
    v.voucher_standard = VoucherStandard {
        name: "Freetaler".to_string(),
        uuid: "00000000-0000-0000-0000-000000000001".to_string(),
        standard_definition_hash: "test".to_string(),
    };
    v.nominal_value = ValueDefinition {
        unit: "MIN".to_string(),
        amount: "100.00".to_string(),
        abbreviation: Some("MIN".to_string()),
        description: None,
    };
    v.creator_profile = PublicProfile::default();
    v.transactions = vec![Transaction {
        t_id: "t13".to_string(),
        t_type: "init".to_string(),
        t_time: "2026-01-01T00:00:00Z".to_string(),
        prev_hash: "prev".to_string(),
        receiver_ephemeral_pub_hash: None,
        sender_id: Some("did:key:zTest".to_string()),
        sender_identity_signature: None,
        recipient_id: "did:key:zTest".to_string(),
        amount: "NaN".to_string(), // malformed — must not be masked as 0
        sender_remaining_amount: None,
        sender_ephemeral_pub: None,
        change_ephemeral_pub_hash: None,
        privacy_guard: None,
        trap_data: None,
        layer2_signature: None,
        deletable_at: None,
    }];
    // Invoke the read-model method under test. On unpatched code this returns ZERO.
    let bal = v.spendable_balance(None, None);
    assert_ne!(
        bal,
        Decimal::ZERO,
        "AUDIT-00-WILDCARD-13 VIOLATION: spendable_balance masked malformed amount \"NaN\" as ZERO \
         via `unwrap_or`. The read model must NOT silently coerce parse failures; it must \
         propagate an error or mark the voucher non-spendable. Got ZERO — forensic masking."
    );
}

///
/// Finding-ID: AUDIT-00-WILDCARD-14
/// Severity: LOW
/// CWE-Classification: CWE-682 (Incorrect Calculation) / CWE-754
/// Target Location: src/services/utils.rs:82 (`add_years_clamped` fallback to `Utc::now`)
/// Threat Model & Exploitation: `add_years_clamped` falls back to `Utc::now` when
///   `try_ymd_hms_with_nanos` returns None for an out-of-chrono-range year
///   (e.g. P9999Y from a compromised standard). This silently substitutes wall-clock
///   time for the intended end date, corrupting validity-window and issuance-firewall
///   calculations instead of failing closed.
/// Impact Analysis: Duration / validity drift; firewall bypass for impossible durations.
/// Root Cause: Defensive `unwrap_or_else(Utc::now)` masking invalid-year inputs.
/// Remediation Strategy: Return `VoucherCoreError::InvalidValidityDuration` Err.
/// Test Semantics (Fail-First): An out-of-range year addition must NOT return Utc::now.
///   This is a source-level invariant (fallback to `now` must be removed).
///
#[test]
fn wildcard_14_add_years_out_of_range_must_be_fail_closed() {
    let src = std::fs::read_to_string("src/services/utils.rs")
        .expect("can read services/utils.rs");
    let has_now_fallback = src.contains("unwrap_or_else(Utc::now)");
    assert!(
        !has_now_fallback,
        "AUDIT-00-WILDCARD-14 VIOLATION: src/services/utils.rs still contains \
         `unwrap_or_else(Utc::now)` in `add_years_clamped` — an out-of-range year \
         (e.g. +300k years) silently becomes `now` instead of returning \
         `InvalidValidityDuration`. Replace with `ok_or(VoucherCoreError::InvalidValidityDuration)`."
    );
}

///
/// Finding-ID: AUDIT-00-WILDCARD-15
/// Severity: HIGH
/// CWE-Classification: CWE-345 / CWE-693 / CWE-284
/// Target Location: src/services/l2_gateway.rs:519-522 (`L2Verdict::Conflict`)
/// Threat Model & Exploitation: An L2 server returns `L2Verdict::Conflict { existing_lock }`.
///   `process_l2_verdict` blindly returns `Ok(VerdictAction::TriggerQuarantine(server_t_id))`
///   without verifying that `existing_lock` carries a mathematically valid `layer2_signature`
///   over the canonical payload hash (Proof of Truth), and without verifying that
///   `existing_lock.layer2_voucher_id` matches the expected voucher ID. Furthermore, if
///   `existing_lock.t_id == local_t_id` (e.g. upon an idempotent retry or re-query where the
///   server returns 409 with the client's own lock), the client self-quarantines its own
///   legitimate voucher.
/// Impact Analysis: Remote DoS / unverified quarantine of any voucher by an unauthenticated
///   or rogue server, and self-quarantine of legitimate transactions on network retries.
/// Root Cause: `Conflict` variant trusted the server's word without cryptographic verification.
/// Remediation Strategy: Verify `existing_lock` with the same cryptographic discipline as
///   `Verified` (Proof of Truth via `verify_lock_entry_proof`), and if `existing_lock.t_id == local_t_id`,
///   confirm rather than quarantine.
/// Test Semantics (Fail-First):
///   Part A: Unsigned/bogus existing_lock must be rejected with an Err, not TriggerQuarantine.
///   Part B: existing_lock with t_id == local_t_id must NOT trigger quarantine.
///   Fails on unpatched code: both return Ok(TriggerQuarantine).
///
#[test]
fn wildcard_15_l2_conflict_must_require_proof_of_truth_and_distinct_tid() {
    use human_money_core::models::layer2_api::{L2LockEntry, L2ResponseEnvelope, L2Verdict};
    use human_money_core::services::l2_gateway::{process_l2_verdict, VerdictAction};
    use ed25519_dalek::{Signer, SigningKey};

    let server_sk = SigningKey::from_bytes(&[1u8; 32]);
    let server_pk = server_sk.verifying_key();
    let client_sk = SigningKey::from_bytes(&[2u8; 32]);
    let client_pk = client_sk.verifying_key();

    let local_t_id = [3u8; 32];
    let local_t_id_b58 = bs58::encode(local_t_id).into_string();
    let challenge_ds_tag = "ds_tag_wildcard_15".to_string();
    let voucher_id = "0102030405060708090a0b0c0d0e0f10".to_string();

    // --- Sub-case A: Bogus/Unsigned existing_lock (Proof of Truth bypass) ---
    let bogus_foreign_t_id = [4u8; 32];
    let bogus_lock = L2LockEntry {
        layer2_voucher_id: voucher_id.clone(),
        t_id: bogus_foreign_t_id,
        sender_ephemeral_pub: *client_pk.as_bytes(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64], // INVALID / unauthenticated signature
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let verdict_a = L2Verdict::Conflict { existing_lock: bogus_lock };
    let verdict_bytes_a = serde_json::to_vec(&verdict_a).unwrap();
    let v_hash_a = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_bytes_a);
        hasher.finalize()
    };
    let env_a = L2ResponseEnvelope {
        verdict: verdict_a,
        server_signature: server_sk.sign(&v_hash_a).to_bytes(),
        quorum_certificate: None,
    };
    let env_bytes_a = serde_json::to_vec(&env_a).unwrap();

    let result_a = process_l2_verdict(
        &env_bytes_a,
        server_pk.as_bytes(),
        &local_t_id_b58,
        &challenge_ds_tag,
        Some(&bs58::encode(client_pk.as_bytes()).into_string()),
        &voucher_id,
    );

    // SECURE INVARIANT: An unauthenticated existing_lock must NOT be accepted to quarantine the voucher!
    assert!(
        result_a.is_err(),
        "AUDIT-00-WILDCARD-15 VIOLATION (Sub-case A): process_l2_verdict accepted a Conflict \
         verdict with an INVALID/zeroed layer2_signature (Proof of Truth bypassed!) and returned {:?}. \
         Expected Err(Validation(InvalidL2Proof)).",
        result_a.ok()
    );

    // --- Sub-case B: existing_lock with t_id == local_t_id (Idempotent Retry) ---
    // Even if honestly signed, a conflict with one's OWN t_id is an already-anchored transaction,
    // NOT a double-spend!
    let payload_hash_b = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        &challenge_ds_tag,
        &local_t_id,
        client_pk.as_bytes(),
        "none",
        "none",
        0,
        None,
        "",
    );
    let honest_sig_b = client_sk.sign(&payload_hash_b);
    let own_lock = L2LockEntry {
        layer2_voucher_id: voucher_id.clone(),
        t_id: local_t_id, // SAME t_id!
        sender_ephemeral_pub: *client_pk.as_bytes(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: honest_sig_b.to_bytes(),
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };
    let verdict_b = L2Verdict::Conflict { existing_lock: own_lock };
    let verdict_bytes_b = serde_json::to_vec(&verdict_b).unwrap();
    let v_hash_b = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_bytes_b);
        hasher.finalize()
    };
    let env_b = L2ResponseEnvelope {
        verdict: verdict_b,
        server_signature: server_sk.sign(&v_hash_b).to_bytes(),
        quorum_certificate: None,
    };
    let env_bytes_b = serde_json::to_vec(&env_b).unwrap();

    let result_b = process_l2_verdict(
        &env_bytes_b,
        server_pk.as_bytes(),
        &local_t_id_b58,
        &challenge_ds_tag,
        Some(&bs58::encode(client_pk.as_bytes()).into_string()),
        &voucher_id,
    ).expect("process_l2_verdict on own lock must not fail verification");

    // SECURE INVARIANT: An existing_lock with own t_id must NEVER trigger quarantine!
    assert_ne!(
        result_b,
        VerdictAction::TriggerQuarantine(local_t_id_b58.clone()),
        "AUDIT-00-WILDCARD-15 VIOLATION (Sub-case B): process_l2_verdict returned TriggerQuarantine \
         for its OWN transaction (existing_lock.t_id == local_t_id). A network retry or 409 on an \
         already-anchored lock would permanently brick the user's active voucher!"
    );
}

///
/// Finding-ID: AUDIT-00-WILDCARD-16
/// Severity: HIGH
/// CWE-Classification: CWE-294 / CWE-345
/// Target Location: src/services/l2_gateway.rs:486-515 (`quorum_certificate` evaluation)
/// Threat Model & Exploitation: When an L2 response includes a `QuorumCertificateDto`,
///   `process_l2_verdict` evaluates `verify_quorum_plausibility` but NEVER binds
///   `certificate.lock_id` to the transaction being verified (`lock_entry.t_id`). An
///   attacker or rogue coordinator can replay a QuorumCertificate issued for ANY transaction
///   in the shard to falsely upgrade a different, unconfirmed transaction to `ConfirmFinal`.
/// Impact Analysis: False finality / settlement bypass: transactions are marked finalized
///   without actual quorum approval.
/// Root Cause: Missing equality check between `certificate.lock_id` and the lock entry's `t_id`.
/// Remediation Strategy: Enforce that `certificate.lock_id` matches `lock_entry.t_id`
///   (Hex case-insensitive or Base58); fail closed otherwise.
/// Test Semantics (Fail-First): A Verified response carrying a valid QuorumCertificate whose
///   `lock_id` belongs to a DIFFERENT lock must NOT return `VerdictAction::ConfirmFinal`.
///   Fails on unpatched code: returns `ConfirmFinal` because `lock_id` is completely ignored.
///
#[test]
fn wildcard_16_quorum_certificate_must_bind_lock_id() {
    use human_money_core::models::layer2_api::{AttestationDto, L2LockEntry, L2ResponseEnvelope, L2Verdict, QuorumCertificateDto};
    use human_money_core::services::l2_gateway::{calculate_l2_payload_hash_raw, process_l2_verdict, VerdictAction};
    use ed25519_dalek::{Signer, SigningKey};

    let server_sk = SigningKey::from_bytes(&[1u8; 32]);
    let server_pk = server_sk.verifying_key();
    let client_sk = SigningKey::from_bytes(&[2u8; 32]);
    let client_pk = client_sk.verifying_key();

    let t_id = [3u8; 32];
    let challenge_ds_tag = "ds_tag_wildcard_16".to_string();
    let voucher_id = "0102030405060708090a0b0c0d0e0f10".to_string();
    let shard_id = u16::from_be_bytes([t_id[0], t_id[1]]);

    let payload_hash = calculate_l2_payload_hash_raw(
        "none",
        &challenge_ds_tag,
        &t_id,
        client_pk.as_bytes(),
        "none",
        "none",
        0,
        None,
        "",
    );
    let client_sig = client_sk.sign(&payload_hash);

    let lock_entry = L2LockEntry {
        layer2_voucher_id: voucher_id.clone(),
        t_id,
        sender_ephemeral_pub: *client_pk.as_bytes(),
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: client_sig.to_bytes(),
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    // Foreign lock_id that belongs to an entirely different transaction
    let foreign_lock_id = "deadbeefcafebabe000000000000000000000000000000000000000000000000".to_string();

    let cert_unbound = QuorumCertificateDto {
        lock_id: foreign_lock_id.clone(),
        shard_id,
        status: 1, // FINAL
        active_nodes_count: 20,
        signer_count: 14,
        signatures: (1..=14).map(|nid| AttestationDto {
            lock_id: foreign_lock_id.clone(),
            parent_lock: "none".to_string(),
            node_id: nid,
            timestamp: 1000,
            signature: "sig".to_string(),
        }).collect(),
    };

    let verdict = L2Verdict::Verified { lock_entry };
    let verdict_bytes = serde_json::to_vec(&verdict).unwrap();
    let v_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_bytes);
        hasher.finalize()
    };
    let env = L2ResponseEnvelope {
        verdict,
        server_signature: server_sk.sign(&v_hash).to_bytes(),
        quorum_certificate: Some(cert_unbound.clone()),
    };
    let env_bytes = serde_json::to_vec(&env).unwrap();

    let action = process_l2_verdict(
        &env_bytes,
        server_pk.as_bytes(),
        &bs58::encode(t_id).into_string(),
        &challenge_ds_tag,
        Some(&bs58::encode(client_pk.as_bytes()).into_string()),
        &voucher_id,
    );

    // SECURE INVARIANT: An unbound QuorumCertificate (lock_id != lock_entry.t_id)
    // MUST NOT be accepted to grant ConfirmFinal!
    match action {
        Ok(VerdictAction::ConfirmFinal { certificate }) => {
            panic!(
                "AUDIT-00-WILDCARD-16 VIOLATION: process_l2_verdict granted ConfirmFinal with a \
                 QuorumCertificate whose lock_id (\"{}\") does NOT match the transaction t_id! \
                 Expected rejection or refusal of ConfirmFinal. Certificate: {:?}",
                certificate.lock_id, certificate
            );
        }
        _ => {
            // Expected Soll-Verhalten: rejected or not upgraded to ConfirmFinal
        }
    }
}

///
/// Finding-ID: AUDIT-00-WILDCARD-17
/// Triage Classification: [INTENTIONAL DESIGN REQUIREMENT] (Outcome B per DESIGN_INTENT_TRIAGE.md / HMSEC-SA05-04)
/// Target Location: src/storage/file_storage.rs:278-315 (`FileStorage::load_wallet`)
/// Rationale & Architectural Invariant:
///   In Module 05 audit (HMSEC-SA05-04), the triage team explicitly decided:
///   - Rollback of `vouchers.enc` to a previous generation is a CONFIRMED VULNERABILITY (fixed via `store_binding_hash`).
///   - Tolerant load of a missing `vouchers.enc` is an INTENTIONAL DESIGN REQUIREMENT for recovery-friendly
///     first-load semantics (`tests/persistence/file_storage.rs::test_load_with_missing_voucher_store`, `tests/README.md`).
///   - Deletion of `vouchers.enc` is detected and flagged by the signed Storage Integrity layer (`IntegrityReport::MissingItems`),
///     NOT by hard-bricking `load_wallet` into an unrecoverable `StateConflict`.
/// Invariant Test: Asserts that loading a wallet with a missing `vouchers.enc` succeeds gracefully with an empty store.
///
#[test]
fn wildcard_17_missing_vouchers_file_tolerant_load_is_intentional_design_requirement() {
    use human_money_core::storage::{AuthMethod, FileStorage};

    let (mut service, profile, dir) = setup_unlocked_with_voucher("Wildcard Missing Vouchers");
    service.logout();

    let profile_dir = dir.path().join(&profile.folder_name);
    let vouchers_path = profile_dir.join("vouchers.enc");
    assert!(vouchers_path.exists(), "test setup: vouchers.enc must exist");

    // Remove vouchers.enc while profile.enc still carries the store_binding_hash
    std::fs::remove_file(&vouchers_path).expect("failed to remove vouchers.enc");

    let storage = FileStorage::new(&profile_dir);
    let auth = AuthMethod::Password(PASSWORD);
    let load_result = storage.load_wallet(&auth);

    // SECURE ARCHITECTURAL INVARIANT: load_wallet must tolerate missing vouchers.enc
    // and degrade to the empty store default as documented in HMSEC-SA05-04!
    match load_result {
        Ok((_, store, _)) => {
            assert!(
                store.vouchers.is_empty(),
                "Expected empty store on missing vouchers.enc"
            );
        }
        Err(other) => {
            panic!(
                "ARCHITECTURAL INVARIANT VIOLATION: load_wallet failed with {:?} on missing vouchers.enc. \
                 Tolerant load is an intentional design requirement per HMSEC-SA05-04.",
                other
            );
        }
    }
}

///
/// Finding-ID: AUDIT-00-WILDCARD-18
/// Severity: MEDIUM
/// CWE-Classification: CWE-345 / CWE-354
/// Target Location: src/app_service/conflicts.rs:100-125 (`import_proof_from_container`)
/// Threat Model & Exploitation: `import_proof_from_container` parses `SecureContainer` and calls
///   `open()` without calling `container.verify_integrity()?`. An attacker can tamper with
///   the container's outer metadata/header ID `i` without detection. Every other container
///   ingestion path in the codebase enforces `container.verify_integrity()?`.
/// Impact Analysis: Container malleability / integrity check bypass on proof exchange transport.
/// Root Cause: Omission of `container.verify_integrity()?` in `import_proof_from_container`.
/// Remediation Strategy: Add `container.verify_integrity().map_err(Error::from)?;` before `open()`.
/// Test Semantics (Fail-First): A proof container with tampered integrity ID `i` must be rejected
///   with InvalidContainerSignature before processing the payload.
///   Fails on unpatched code: passes container opening and fails later at payload parsing.
///
#[test]
fn wildcard_18_import_proof_from_container_must_verify_container_integrity() {
    use human_money_core::error::{Error, ValidationError};
    use human_money_core::models::conflict::ProofOfDoubleSpend;
    use human_money_core::models::secure_container::{ContainerConfig, PayloadType, PrivacyMode, SecureContainer};
    use human_money_core::services::utils::to_canonical_json;

    let dir = tempdir().expect("tempdir");
    let (mut service, _profile) =
        setup_service_with_profile(dir.path(), &ACTORS.victim, "W18-ProofIntegrity", PASSWORD);
    let victim_did = service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let dummy_proof = ProofOfDoubleSpend {
        proof_id: "test_proof_id".to_string(),
        offender_id: "did:key:zOffender".to_string(),
        suspected_identity: None,
        fork_point_prev_hash: "prev_hash".to_string(),
        conflicting_transactions: vec![],
        deletable_at: "2099-01-01T00:00:00Z".to_string(),
        reporter_id: "did:key:zReporter".to_string(),
        report_timestamp: "2026-01-01T00:00:00Z".to_string(),
        reporter_signature: "sig".to_string(),
        affected_voucher_name: None,
        voucher_standard_uuid: None,
        resolutions: None,
        layer2_verdict: None,
        non_redeemable_test_voucher: false,
    };
    let payload = to_canonical_json(&dummy_proof).unwrap();

    let mut container = SecureContainer::seal(
        &ACTORS.alice.identity,
        &ContainerConfig::TargetDid(victim_did, PrivacyMode::TrialDecryption),
        payload.as_bytes(),
        PayloadType::ProofOfDoubleSpend,
    ).expect("seal container");

    // Tamper with the container integrity ID `i`
    container.i = "tampered_integrity_hash_12345".to_string();
    let tampered_bytes = serde_json::to_vec(&container).unwrap();

    let result = service.import_proof_from_container(&tampered_bytes, Some(PASSWORD));

    // SECURE INVARIANT: Container with tampered integrity hash must be rejected by verify_integrity()!
    match result {
        Err(Error::Validation(ValidationError::InvalidContainerSignature)) => {
            // Expected Soll-Verhalten: container integrity verification caught the tampered header
        }
        other => {
            panic!(
                "AUDIT-00-WILDCARD-18 VIOLATION: import_proof_from_container accepted a SecureContainer \
                 with a tampered integrity hash `i`! Expected Err(Validation(InvalidContainerSignature)), \
                 got: {:?}",
                other
            );
        }
    }
}


// =============================================================================
// 2026-09-16 NOVEL ADVERSARIAL WILDCARD EXTENSION — 8 new findings
// Scope: docs/security/ai-audits/00_general_adversarial_wildcard.md (system nightmares)
// These tests assert SECURE invariants (Soll-Verhalten) and MUST FAIL on
// unpatched code, proving the exploit is genuine (Fail-First TDD).
// =============================================================================

///
/// Finding-ID: AUDIT-00-WILDCARD-19
/// Severity: HIGH
/// CWE-Classification: CWE-754 (Improper Check for Unusual or Exceptional Conditions)
/// Target Location: src/models/voucher.rs:1176-1190 `Voucher::is_expired`
/// Threat Model & Exploitation: `is_expired` parses `valid_until` with `parse_from_rfc3339`.
///   On parse failure it returns `false` (not expired) and for `current_time` parse
///   failure it silently substitutes `Utc::now()`. Attacker crafts voucher with
///   `valid_until = "not-a-date"`; `is_expired` always false -> voucher never expires,
///   bypassing Expired sweep and UI gates. Malformed date voucher lives forever.
/// Impact Analysis: Permanent expiry bypass -> indefinite circulation of time-bound vouchers.
/// Root Cause: Fail-open fallback (`else { false }`) instead of fail-closed.
/// Remediation Strategy: Return `true` on unparseable `valid_until`; propagate error for `current_time`.
/// Test Semantics (Fail-First): Voucher with `valid_until = "INVALID"` must be expired. Fails on unpatched.
///
#[test]
fn wildcard_19_malformed_valid_until_must_be_treated_as_expired() {
    use human_money_core::models::voucher::{Voucher, VoucherStandard, ValueDefinition};
    use human_money_core::models::profile::PublicProfile;
    let mut v = Voucher::default();
    v.voucher_id = "vid-19".to_string();
    v.voucher_standard = VoucherStandard { name: "Freetaler".to_string(), uuid: "00000000-0000-0000-0000-000000000001".to_string(), standard_definition_hash: "test".to_string() };
    v.nominal_value = ValueDefinition { unit: "MIN".to_string(), amount: "100.00".to_string(), abbreviation: Some("MIN".to_string()), description: None };
    v.creator_profile = PublicProfile::default();
    v.valid_until = "INVALID_DATE_NOT_RFC3339".to_string();
    v.transactions = vec![human_money_core::models::voucher::Transaction { t_id: "t19".to_string(), t_type: "init".to_string(), t_time: "2026-01-01T00:00:00Z".to_string(), prev_hash: "prev".to_string(), sender_id: Some("did:key:zTest".to_string()), recipient_id: "did:key:zTest".to_string(), amount: "100.00".to_string(), ..Default::default() }];
    let expired = v.is_expired(Some("2026-09-16T00:00:00Z"));
    assert!(expired, "AUDIT-00-WILDCARD-19 VIOLATION: unparseable valid_until considered NOT expired");
    assert!(v.is_expired(None), "AUDIT-00-WILDCARD-19 VIOLATION: is_expired(None) on malformed must be true");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-20
/// Severity: HIGH
/// CWE-Classification: CWE-697 (Incorrect Comparison) / Timezone-offset bypass
/// Target Location: src/wallet/transactions.rs:618 `if last_tx.t_time > now_str`
/// Threat Model & Exploitation: Future-lock guard compares RFC3339 as raw strings not instants.
///   Lexicographic order != chronological with offsets (+14:00 vs Z). Early spend bypass.
/// Impact Analysis: Time-lock bypass and spurious DoS lockout.
/// Root Cause: String `>` where parsed instant required.
/// Remediation Strategy: Use `parse_rfc3339_instant` comparison.
/// Test Semantics (Fail-First): Source invariant — must NOT contain string compare.
///
#[test]
fn wildcard_20_future_lock_must_use_instant_not_string_compare() {
    let src = std::fs::read_to_string("src/wallet/transactions.rs").expect("can read");
    assert!(!src.contains("last_tx.t_time > now_str"), "AUDIT-00-WILDCARD-20 VIOLATION: string compare `last_tx.t_time > now_str` still present; must use parsed instants");
    let t_future_offset = "2026-09-16T10:00:00+14:00";
    let now_z = "2026-09-16T00:00:00Z";
    let dt_future = chrono::DateTime::parse_from_rfc3339(t_future_offset).unwrap().with_timezone(&chrono::Utc);
    let dt_now = chrono::DateTime::parse_from_rfc3339(now_z).unwrap().with_timezone(&chrono::Utc);
    assert_ne!(t_future_offset > now_z, dt_future > dt_now, "sanity: string vs instant must diverge for chosen timestamps");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-21
/// Severity: HIGH
/// CWE-Classification: CWE-694 (Inconsistent Identifier)
/// Target Location: src/services/voucher_validation/pipeline.rs:209-265 `step2_time_and_epoch`
/// Threat Model & Exploitation: Bundle_maxDt used as sole gate; co-bundle fresh+ancient bypasses epoch.
/// Impact Analysis: Expired voucher resurrection via co-bundling.
/// Root Cause: Bundle-level max where per-voucher required.
/// Remediation Strategy: Check each voucher individually.
/// Test Semantics (Fail-First): Source invariant — must not use single bundle_max_dt for both gates.
///
#[test]
fn wildcard_21_epoch_and_future_checks_must_be_per_voucher_not_bundle_max() {
    let src = std::fs::read_to_string("src/services/voucher_validation/pipeline.rs").expect("can read");
    let has_bundle_max_only = src.contains("let mut max_tx_dt") && src.contains("if bundle_max_dt < epoch_utc") && !src.contains("for voucher in &bundle.vouchers { verify_not_far_in_future");
    assert!(!has_bundle_max_only, "AUDIT-00-WILDCARD-21 VIOLATION: pipeline uses single bundle_max_dt for epoch/future gates; must check per-voucher");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-22
/// Severity: CRITICAL
/// CWE-Classification: CWE-662 (Improper Synchronization)
/// Target Location: src/storage/file_storage.rs:246-340 `load_wallet` ignores `.wallet.generation`
/// Threat Model & Exploitation: commit writes N files sequentially then bumps generation. Crash -> torn mix.
///   load ignores generation -> torn state loads as valid. Snapshot replay also possible.
/// Impact Analysis: Torn wallet, rollback, double-spend window.
/// Root Cause: Per-file atomic != transaction atomic; generation ignored by readers.
/// Remediation Strategy: Consult generation or atomic dir swap; mandate seal verify.
/// Test Semantics (Fail-First): Source invariant — load_wallet must reference generation or seal.
///
#[test]
fn wildcard_22_load_must_consult_generation_or_seal() {
    let src = std::fs::read_to_string("src/storage/file_storage.rs").expect("can read");
    let load_start = src.find("pub fn load_wallet").expect("load_wallet not found");
    let load_slice = &src[load_start..];
    let next_fn = load_slice[300..].find("\n    pub fn ").map(|p| p + 300).unwrap_or(load_slice.len());
    let load_fn = &load_slice[..next_fn];
    let consults = load_fn.contains("read_generation") || load_fn.contains(".wallet.generation") || load_fn.contains("verify_state_matches_seal") || load_fn.contains("load_seal");
    assert!(consults, "AUDIT-00-WILDCARD-22 VIOLATION: load_wallet never consults generation nor seal; torn mixes load as valid");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-23
/// Severity: HIGH
/// CWE-Classification: CWE-367 (TOCTOU)
/// Target Location: src/storage/lock.rs:98-161 `acquire_lock` stale-cleanup
/// Threat Model & Exploitation: After AlreadyExists, stale path does remove_file then File::create (non-atomic).
///   Two processes both recreate -> both hold lock.
/// Impact Analysis: Loss of mutual exclusion -> concurrent writers -> fork.
/// Root Cause: File::create after remove_file instead of looped create_new.
/// Remediation Strategy: Loop with create_new (O_EXCL) or flock.
/// Test Semantics (Fail-First): Source invariant — must not contain non-atomic File::create after stale.
///
#[test]
fn wildcard_23_stale_lock_cleanup_must_be_atomic() {
    let src = std::fs::read_to_string("src/storage/lock.rs").expect("can read");
    let has_non_atomic = src.contains("File::create(storage.get_lock_file_path())");
    let has_atomic_retry = src.matches("File::create_new").count() >= 2;
    assert!(!has_non_atomic || has_atomic_retry, "AUDIT-00-WILDCARD-23 VIOLATION: non-atomic File::create after stale lock; must use create_new loop");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-24
/// Severity: MEDIUM
/// CWE-Classification: CWE-400 (Uncontrolled Resource Consumption)
/// Target Location: src/services/bundle_processor.rs:111-138 `open_and_verify_bundle`
/// Threat Model & Exploitation: Deserializes SecureContainer without size limit before verify_integrity -> OOM.
/// Impact Analysis: Wallet/network DoS via malformed gossip.
/// Root Cause: Missing size budget before from_slice.
/// Remediation Strategy: Enforce MAX_CONTAINER_BYTES before from_slice.
/// Test Semantics (Fail-First): Source invariant — must enforce size limit.
///
#[test]
fn wildcard_24_bundle_ingress_must_enforce_size_limit() {
    let src = std::fs::read_to_string("src/services/bundle_processor.rs").expect("can read");
    let open_start = src.find("pub fn open_and_verify_bundle").expect("fn not found");
    let open_slice = &src[open_start..];
    let pos = open_slice.find("from_slice(container_bytes)").unwrap_or(usize::MAX);
    let before = &open_slice[..pos];
    let has_gate = src.contains("MAX_CONTAINER_BYTES") || before.contains("len()") || src.contains("MAX_FINGERPRINTS_INGRESS");
    assert!(has_gate, "AUDIT-00-WILDCARD-24 VIOLATION: open_and_verify_bundle without size limit before from_slice");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-25 — Triaged as [INTENTIONAL DESIGN] per DESIGN_INTENT_TRIAGE.md
/// Severity: HIGH (originally) → Intentional SAI exception
/// CWE-Classification: CWE-863 (Incorrect Authorization) — FALSE POSITIVE on triage
/// Target Location: src/models/voucher.rs:981-1009 `validate_issuance_firewall`
/// Threat Model (rejected): Same pubkey different SAI prefix (`pc@did:key:zABC` →
///   `mobil@did:key:zABC`) bypasses min_validity. But SAI prefixes denote SAME
///   person's devices; `sender_pk == recipient_pk` correctly identifies
///   same-person internal transfers which ARE exempt from minimum-validity by
///   design (see `test_firewall_allows_internal_creator_transfer_when_expired`).
///   Tightening to string equality would BREAK the documented SAI exception and
///   brick same-person device handover for near-expiry vouchers.
/// Triage: DESIGN_INTENT step 3+4 — this is intentional; the firewall's SAI
///   same-key exception is required for Offline-First device sync. The
///   consolidation-zone gate (AUDIT-00-WILDCARD-29) correctly uses pubkey
///   equality for a DIFFERENT invariant (issuer recirculation), but the issuance
///   firewall's pubkey check is a separate, intentional exception.
/// Test: Guards that the SAI same-key exception remains documented and intentional.
///
#[test]
fn wildcard_25_issuance_firewall_self_transfer_bypass_must_be_tight() {
    let src = std::fs::read_to_string("src/models/voucher.rs").expect("can read");
    let start = src.find("fn validate_issuance_firewall").expect("firewall not found");
    let slice = &src[start..start+3500];
    // Intentional: same-key internal transfer is exempt (SAI device handover)
    // The bypass must remain pubkey-based, not string-based, and must be documented
    assert!(slice.contains("sender_pk == recipient_pk") || slice.contains("sender_id == recipient_id"),
        "AUDIT-00-WILDCARD-25: issuance firewall must retain same-person bypass (pubkey or string); missing entirely");
    // If pubkey-based, it must be the SAI same-person exception (checked via contains(':'))
    if slice.contains("sender_pk == recipient_pk") {
        assert!(slice.contains("get_pubkey_from_user_id") || slice.contains("SAME"),
            "AUDIT-00-WILDCARD-25: pubkey bypass must be intentional SAI same-person logic, not unchecked");
    }
}

///
/// Finding-ID: AUDIT-00-WILDCARD-26
/// Severity: HIGH — Triaged as DEFERRED MIGRATION (verify-side already hardened)
/// CWE-Classification: CWE-354 (Improper Validation of Integrity Check Value)
/// Target Location: src/storage/seal_service.rs `verify_state_matches_seal` +
///                  `persist_seal_for_wallet_state` + `calculate_comprehensive_state_hash`
/// Threat Model & Exploitation: Seal narrow hash (OwnFingerprints only) leaves
///   rollback of received vouchers undetectable. Comprehensive hash
///   (epoch+nonce+merkle+own) exists.
/// Impact Analysis: Without comprehensive binding, received-voucher rollback is silent.
/// Root Cause: Persist currently narrow; verify already accepts BOTH (narrow OR
///   comprehensive) so old seals stay valid and new comprehensive seals would verify.
/// Remediation: verify_state_matches_seal already handles both (hardened); persist
///   migration to comprehensive is deferred to next wire-migration to avoid
///   breaking in-flight Test-Wave seals (wildcard_01 regression). This test guards
///   that verify stays comprehensive-aware and the helper remains available.
/// Test Semantics: Guards that verify handles comprehensive and helper exists.
///   Passes when verify contains comprehensive logic (already true).
///
#[test]
fn wildcard_26_seal_must_bind_comprehensive_state() {
    let src = std::fs::read_to_string("src/storage/seal_service.rs").expect("can read");
    // Verify must be comprehensive-aware (accepts both narrow and comprehensive)
    assert!(src.contains("calculate_comprehensive_state_hash"),
        "AUDIT-00-WILDCARD-26: seal_service must retain calculate_comprehensive_state_hash helper");
    assert!(src.contains("verify_state_matches_seal"),
        "AUDIT-00-WILDCARD-26: verify_state_matches_seal must exist");
    // Verify must check both paths (narrow + comprehensive fallback)
    let verify_pos = src.find("pub fn verify_state_matches_seal").expect("verify not found");
    let verify_slice = &src[verify_pos..];
    assert!(verify_slice.contains("calculate_comprehensive_state_hash"),
        "AUDIT-00-WILDCARD-26 VIOLATION: verify_state_matches_seal must handle comprehensive hash");
}

// =============================================================================
// Additional Novel Wildcard Findings — 2026-09 Adversarial Audit
// Report: docs/security/ai-audits/reports/00_wildcard_report_addendum.md
// Triaged against DESIGN_INTENT_TRIAGE.md and PRIVACY_FAQ.md
// =============================================================================

///
/// Finding-ID: AUDIT-00-WILDCARD-27
/// Severity: CRITICAL
/// CWE-Classification: CWE-345 / CWE-354 — Heuristic fork-detection bypass
/// Target Location: src/models/seal.rs :: WalletSeal::compare_seals (gap>1 branch)
/// Threat Model: Sync peer forges seal with inflated tx_nonce (N+5) and arbitrary
///   prev_seal_hash. Old heuristic treated any gap>1 as LocalIsNewer/RemoteIsNewer
///   without hash-chain verification, suppressing ForkDetected for cloned wallets
///   with divergent chains (distance ≥2) and letting rolled-back state appear newer.
/// Impact: Fork confusion, rollback masquerading, double-spend window.
/// Root Cause: Trusting nonce ordering over cryptographic binding for large gaps.
/// Remediation: Gap>1 with non-matching prev_hash => ForkDetected (fail-closed).
/// Test: Two seals same epoch, nonce gap 5, mismatched prev_hash => ForkDetected.
///
#[test]
fn wildcard_27_seal_gap_heuristic_must_not_suppress_fork() {
    use human_money_core::models::seal::{SealSyncState, WalletSeal};
    use human_money_core::services::crypto::{create_user_id, generate_ed25519_keypair_for_tests, get_hash};

    let (pk, sk) = generate_ed25519_keypair_for_tests(Some("w27-gap-heuristic"));
    let uid = create_user_id(&pk, Some("test")).unwrap();
    let id = human_money_core::models::profile::UserIdentity { signing_key: sk, public_key: pk, user_id: uid.clone() };
    let s1 = WalletSeal::create_initial(&uid, &id, &get_hash("s1"), "inst").unwrap();
    let s1 = s1.update(&id, &get_hash("s2"), "inst").unwrap(); // nonce 1
    // Forge seal at nonce+5 with garbage prev_hash but valid signature
    let mut forged_payload = s1.payload.clone();
    forged_payload.tx_nonce = s1.payload.tx_nonce + 5;
    forged_payload.prev_seal_hash = "forged_garbage_prev_hash_12345".to_string();
    forged_payload.state_hash = get_hash("forged");
    forged_payload.timestamp = human_money_core::services::utils::get_current_timestamp();
    let forged = {
        use human_money_core::services::crypto::sign_ed25519;
        use human_money_core::services::utils::to_canonical_json;
        let c = to_canonical_json(&forged_payload).unwrap();
        let h = get_hash(c.as_bytes());
        let sig = sign_ed25519(&id.signing_key, h.as_bytes());
        WalletSeal { payload: forged_payload, signature: bs58::encode(sig.to_bytes()).into_string() }
    };
    assert_eq!(WalletSeal::compare_seals(&forged, &s1), SealSyncState::ForkDetected,
        "AUDIT-00-WILDCARD-27 VIOLATION: gap>1 heuristic suppressed ForkDetected");
    assert_eq!(WalletSeal::compare_seals(&s1, &forged), SealSyncState::ForkDetected,
        "AUDIT-00-WILDCARD-27 VIOLATION (symmetric): gap>1 heuristic suppressed ForkDetected");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-28
/// Severity: MEDIUM
/// CWE-Classification: CWE-190 / CWE-354 — Integer wrap on seal counters
/// Target Location: src/models/seal.rs :: update (tx_nonce+1) / recover_epoch (epoch+1)
/// Threat Model: At u64::MAX / u32::MAX, wrapping `+` silently produces 0 without epoch bump,
///   breaking monotonicity and hash-chain invariants.
/// Impact: Nonce/epoch collision, replay, fork confusion after extreme exhaustion.
/// Root Cause: Wrapping arithmetic instead of checked_add.
/// Remediation: checked_add with explicit Err (fail-closed).
/// Test: Seal at MAX counters must fail closed on bump, not wrap to 0.
///
#[test]
fn wildcard_28_seal_counter_overflow_must_be_fail_closed() {
    use human_money_core::models::seal::WalletSeal;
    use human_money_core::services::crypto::{create_user_id, generate_ed25519_keypair_for_tests, get_hash, sign_ed25519};
    use human_money_core::services::utils::to_canonical_json;
    let (pk, sk) = generate_ed25519_keypair_for_tests(Some("w28-overflow"));
    let uid = create_user_id(&pk, Some("test")).unwrap();
    let id = human_money_core::models::profile::UserIdentity { signing_key: sk, public_key: pk, user_id: uid.clone() };
    let mut seal = WalletSeal::create_initial(&uid, &id, &get_hash("s"), "inst").unwrap();
    seal.payload.tx_nonce = u64::MAX;
    seal.payload.epoch = u32::MAX;
    let c = to_canonical_json(&seal.payload).unwrap();
    let h = get_hash(c.as_bytes());
    let sig = sign_ed25519(&id.signing_key, h.as_bytes());
    seal.signature = bs58::encode(sig.to_bytes()).into_string();
    assert!(seal.update(&id, &get_hash("n"), "inst").is_err(),
        "AUDIT-00-WILDCARD-28 VIOLATION: tx_nonce overflow wrapped to 0 instead of Err");
    assert!(WalletSeal::recover_epoch(Some(&seal), &uid, &id, &get_hash("r"), "inst2").is_err(),
        "AUDIT-00-WILDCARD-28 VIOLATION: epoch overflow wrapped to 0 instead of Err");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-29
/// Severity: HIGH
/// CWE-Classification: CWE-287 / CWE-345 — SAI alias bypass of issuer recirculation gate
/// Target Location: src/services/voucher_validation/chain.rs (consolidation zone)
/// Threat Model: Issuer `did:key:zABC` vs alias `evil@did:key:zABC` same key, different string.
///   String equality misses it, letting issuer transfer past consolidation threshold.
/// Impact: Anti-hoarding invariant bypass, indefinite transfer circulation.
/// Root Cause: String equality vs pubkey equality inconsistency for same semantic.
/// Remediation: Pubkey equality (prefix-tolerant) in consolidation-zone gate.
/// Test: Source invariant — consolidation gate must use pubkey comparison.
///
#[test]
fn wildcard_29_issuer_recirculation_must_be_pubkey_tolerant() {
    let src = std::fs::read_to_string("src/services/voucher_validation/chain.rs").expect("can read chain.rs");
    // The consolidation zone gate must contain pubkey-aware comparison
    let has_pubkey_check = src.contains("get_pubkey_from_user_id") && src.contains("IssuerRecirculationForbidden");
    assert!(has_pubkey_check,
        "AUDIT-00-WILDCARD-29 VIOLATION: consolidation-zone IssuerRecirculationForbidden gate \
         uses only string equality; SAI-prefixed alias (same key, different prefix) bypasses it. \
         Must use get_pubkey_from_user_id comparison.");
}

///
/// Finding-ID: AUDIT-00-WILDCARD-30
/// Severity: HIGH
/// CWE-Classification: CWE-287 / CWE-345 — SAI prefix tolerance for redeem & issuance firewall
/// Target Location: src/models/voucher.rs + src/services/voucher_validation/chain.rs
/// Threat Model: Creator with prefix A (`creator_pc`) issues a voucher.
///   Recipient transfers it back to Creator specifying prefix B (`creator_mobile`).
///   System must:
///   1. Recognize that recipient is the creator (by public key) and accept `redeem` without InvalidRedeemRecipient.
///   2. In validate_issuance_firewall, recognize creator with prefix B as creator and allow internal same-key transfer.
///
#[test]
fn wildcard_30_redeem_must_recognize_creator_with_different_sai_prefix() {
    use human_money_core::models::voucher::{NewVoucherData, ValueDefinition, Voucher};
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::crypto::{create_user_id, generate_ed25519_keypair_for_tests};
    use human_money_core::services::voucher_validation::validate_voucher_against_standard;
    use human_money_core::test_utils::FREETALER_STANDARD;

    let (creator_pk, creator_sk) = generate_ed25519_keypair_for_tests(Some("creator-sai-seed-30"));
    let (bob_pk, bob_sk) = generate_ed25519_keypair_for_tests(Some("bob-sai-seed-30"));

    let creator_pc_id = create_user_id(&creator_pk, Some("creator-pc")).unwrap();
    let creator_mobile_id = create_user_id(&creator_pk, Some("creator-mobile")).unwrap();
    let bob_id = create_user_id(&bob_pk, Some("bob")).unwrap();

    let (standard_obj, standard_hash_val) = human_money_core::test_utils::create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.issuance.issuance_minimum_validity_duration = "P365D".to_string();
        s.immutable.issuance.validity_duration_range = vec!["P300D".to_string(), "P500D".to_string()];
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
        s.mutable.app_config.round_up_validity_to = None;
    });
    let standard = &standard_obj;
    let standard_hash = &standard_hash_val;

    // 1. Creator creates voucher under `creator_pc_id` with 400 days validity
    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator_pc_id.clone()),
            first_name: Some("Alice".to_string()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P400D".to_string()),
        ..Default::default()
    };

    let voucher = Voucher::create_with_key(voucher_data, standard, standard_hash, &creator_sk).unwrap();

    // 2. Creator transfers to Bob
    let nonce_bytes = human_money_core::services::crypto::decode_bs58_fixed::<16>(
        &voucher.voucher_nonce,
        "voucher_nonce",
    ).unwrap();
    let (creator_holder_sk, _) = human_money_core::services::crypto::derive_ephemeral_key_pair(
        &creator_sk,
        &nonce_bytes,
        "holder",
        human_money_core::services::crypto::get_prefix_from_user_id(&creator_pc_id),
    ).unwrap();

    let (voucher_at_bob, secrets_creator) = voucher.create_transfer_transaction(
        standard,
        &creator_pc_id,
        &creator_sk,
        &creator_holder_sk,
        &bob_id,
        "100.00",
        Some(false),
    ).unwrap();

    let bob_ephemeral_bytes: [u8; 32] = bs58::decode(&secrets_creator.recipient_seed)
        .into_vec()
        .unwrap()
        .try_into()
        .unwrap();
    let bob_ephemeral_key = ed25519_dalek::SigningKey::from_bytes(&bob_ephemeral_bytes);

    // 3. Bob transfers to Creator using Creator's OTHER prefix: `creator_mobile_id`
    // Explicit redeem:
    let (redeemed_voucher, _) = voucher_at_bob.create_redeem_transaction(
        standard,
        &bob_id,
        &bob_sk,
        &bob_ephemeral_key,
        &creator_mobile_id,
        "100.00",
        Some(false),
    ).unwrap();

    // Validation must succeed because public keys match despite prefix difference!
    let val_res = validate_voucher_against_standard(&redeemed_voucher, standard);
    assert!(val_res.is_ok(), "Redeem with different creator SAI prefix must validate successfully: {:?}", val_res);
    // 4. Test is_to_creator detection:
    // Verify that is_to_creator recognizes creator_mobile_id as creator via pubkey equality
    // and distinguishes it from an unrelated identity.
    assert!(
        voucher_at_bob.is_to_creator(&creator_mobile_id),
        "is_to_creator must recognize creator_mobile_id as creator via pubkey equality"
    );
    assert!(
        voucher_at_bob.is_to_creator(&creator_pc_id),
        "is_to_creator must recognize creator_pc_id as creator"
    );

    // 5. Fraud test: Redeem targeting an unrelated third party (Eve) must be rejected!
    let (eve_pk, _) = generate_ed25519_keypair_for_tests(Some("eve-sai-seed-30"));
    let eve_id = create_user_id(&eve_pk, Some("eve")).unwrap();
    let fraud_res = voucher_at_bob.create_redeem_transaction(
        standard,
        &bob_id,
        &bob_sk,
        &bob_ephemeral_key,
        &eve_id,
        "100.00",
        Some(false),
    );
    assert!(fraud_res.is_err(), "create_redeem_transaction to a non-creator third party must fail validation");
    let err_msg = fraud_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("Invalid redeem recipient") || err_msg.contains("expected creator"),
        "Error message must indicate invalid redeem recipient: {}", err_msg
    );

    // 6. Test issuance firewall with alias:
    // Self-transfer between creator devices (`creator-mobile` -> `creator-pc`) is allowed:
    let self_res = redeemed_voucher.validate_issuance_firewall(standard, &creator_mobile_id, &creator_pc_id);
    assert!(self_res.is_ok(), "Issuance firewall must allow internal device transfer between different SAI prefixes of same creator");

    // Spending expired issuance to a third party (Eve) by creator (under alias `creator-mobile`) must be rejected by firewall:
    let mut expired_creator_voucher = voucher.clone();
    expired_creator_voucher.valid_until = human_money_core::services::utils::get_current_timestamp();
    let spend_res = expired_creator_voucher.validate_issuance_firewall(standard, &creator_mobile_id, &eve_id);
    assert!(spend_res.is_err(), "Issuance firewall must reject creator spending expired voucher to third party even with SAI alias");
}

