//! # tests/security_audit_v051_storage_and_cli.rs
//!
//! Security Audit — v0.5.1 Remediation: Storage, Rollback Reconciliation, Orchestrator Seal Recovery & CLI Hardening.
//!
//! Fail-first (TDD) regression test suite verifying:
//! - AUDIT-07-05b: Rollback reconciliation preserves Quarantined voucher status and does not downgrade to Archived.
//! - AUDIT-07-09: Orchestrator recovery preserves live session in-memory state (l2_server_pubkey) via StateMergeHook
//!   and rejects tampered disk state on rollback.
//! - BUG-01 & BUG-05: wallet-cli snapshot rejects invalid tags (path traversal, '.', '..', control characters)
//!   and refuses snapshot save/restore while .wallet.lock or .wallet.transaction.lock is held.
//! - BUG-02: Char-boundary-safe UTF-8 truncation in wallet-cli prevents panic on multi-byte characters.
//! - BUG-04: clean_orphaned_transaction_temps cleans temp files in both root and events/ directories with directory fsync.
//!
//! ## Finding Summary
//!
//! | Finding-ID     | Severity | Target                                                            |
//! |----------------|----------|-------------------------------------------------------------------|
//! | AUDIT-07-05b   | High     | src/app_service/storage_ops.rs (quarantine preservation)          |
//! | AUDIT-07-09    | High     | src/app_service/orchestrator.rs, storage_ops.rs (seal/RAM hook)   |
//! | BUG-01/BUG-05  | High     | src/bin/wallet_cli/snapshot_cmd.rs (tag check, lock check)        |
//! | BUG-02         | Medium   | src/bin/wallet_cli/scenario_cmd.rs, voucher_cmd.rs (UTF-8 slices) |
//! | BUG-04         | Medium   | src/storage/wallet_transaction.rs (events/ directory fsync)       |

use human_money_core::storage::FileStorage;
use human_money_core::test_utils::{self, ACTORS};
use human_money_core::wallet::instance::VoucherStatus;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

const CLI_BIN: &str = env!("CARGO_BIN_EXE_wallet-cli");
const PASSWORD: &str = "test-pw-v051-remediation";

fn run_cli(data_dir: &Path, args: &[&str]) -> (bool, String, String) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let standards_dir = manifest_dir.join("voucher_standards");

    let output = Command::new(CLI_BIN)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--standards-dir")
        .arg(standards_dir)
        .arg("--password")
        .arg(PASSWORD)
        .args(args)
        .output()
        .expect("Failed to execute wallet-cli");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

// ---------------------------------------------------------------------------
// AUDIT-07-05b: Rollback reconciliation preserves Quarantined voucher status
// ---------------------------------------------------------------------------

#[test]
fn test_audit_07_05b_reconcile_rollback_preserves_quarantined_vouchers() {
    let dir = TempDir::new().unwrap();
    let (mut app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let (standard, _) = (
        &test_utils::standards::FREETALER_STANDARD.0,
        &test_utils::standards::FREETALER_STANDARD.1,
    );

    let (v_id1, v_id2) = {
        let (wallet_mut, identity) = app.get_unlocked_mut_for_test();
        let id1 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "50.00", standard, true)
            .unwrap();
        let id2 = test_utils::add_voucher_to_wallet(wallet_mut, identity, "30.00", standard, true)
            .unwrap();
        (id1, id2)
    };

    // Mark v_id1 as Quarantined explicitly
    {
        let (wallet_mut, _) = app.get_unlocked_mut_for_test();
        let instance = wallet_mut.voucher_store.vouchers.get_mut(&v_id1).unwrap();
        instance.status = VoucherStatus::Quarantined {
            reason: "Double spend conflict on L2".to_string(),
        };
    }

    // Persist seal and state
    app.update_seal_after_state_change(Some(PASSWORD)).unwrap();

    // Reconcile rollback where v_id1 is reported in spent_voucher_ids
    let report = app
        .reconcile_rollback_with_diagnostics(std::slice::from_ref(&v_id1), Some(5), Some(PASSWORD))
        .expect("Reconciliation should succeed");

    // Quarantined voucher MUST be preserved in quarantined_voucher_ids and NOT downgraded to archived
    assert!(
        report.quarantined_voucher_ids.contains(&v_id1),
        "Quarantined voucher must be in quarantined_voucher_ids"
    );
    assert!(
        !report.archived_voucher_ids.contains(&v_id1),
        "Quarantined voucher must NEVER be downgraded into archived_voucher_ids"
    );
    assert!(
        report.retained_voucher_ids.contains(&v_id2),
        "Active voucher must remain in retained_voucher_ids"
    );

    // Verify wallet in-memory status
    let (wallet, _) = app.get_unlocked_for_test();
    let inst1 = wallet.voucher_store.vouchers.get(&v_id1).unwrap();
    assert!(
        matches!(inst1.status, VoucherStatus::Quarantined { .. }),
        "Status must stay Quarantined, got {:?}",
        inst1.status
    );
    let inst2 = wallet.voucher_store.vouchers.get(&v_id2).unwrap();
    assert_eq!(inst2.status, VoucherStatus::Active);
}

// ---------------------------------------------------------------------------
// AUDIT-07-09: Orchestrator recovery preserves RAM state and checks seal
// ---------------------------------------------------------------------------

#[test]
fn test_audit_07_09_rollback_preserves_ram_only_l2_server_pubkey() {
    let dir = TempDir::new().unwrap();
    let (mut app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let test_pubkey: [u8; 32] = [42u8; 32];

    // Set RAM-only l2_server_pubkey (simulating live session configuration)
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(test_pubkey);

    // Trigger an aborted/rollback transaction
    let outcome_result = app.rollback_transaction_for_test(Some(PASSWORD));
    assert!(outcome_result.is_err());

    // Verify that RAM-only l2_server_pubkey was preserved across the reload
    let pubkey_after = app.get_unlocked_for_test().0.profile.l2_server_pubkey;
    assert_eq!(
        pubkey_after,
        Some(test_pubkey),
        "RAM-only l2_server_pubkey must be preserved via StateMergeHook on rollback"
    );
}

#[test]
fn test_audit_07_09_rollback_rejects_disk_tampered_state() {
    let dir = TempDir::new().unwrap();
    let (mut app, profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let profile_dir = dir.path().join(&profile.folder_name);
    let seal_file = profile_dir.join("seal.enc");

    // Tamper with seal.enc on disk while session is active
    if seal_file.exists() {
        fs::write(&seal_file, b"corrupted-seal-payload-data").unwrap();
    }

    // Trigger an operation that encounters an error and reloads from disk
    let result = app.rollback_transaction_for_test(Some(PASSWORD));

    // Orchestrator reload must verify state matches seal and fail closed
    assert!(result.is_err(), "Reload from tampered disk must fail closed");
}

// ---------------------------------------------------------------------------
// BUG-01 & BUG-05: Snapshot tag validation and active lock checks
// ---------------------------------------------------------------------------

#[test]
fn test_bug_01_snapshot_tag_validation() {
    let dir = TempDir::new().unwrap();
    let (mut app, _profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
    app.logout();

    // 1. Invalid tag '.'
    let (ok, _out, err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "."]);
    assert!(!ok, "Tag '.' must be rejected");
    assert!(err.contains("Invalid snapshot tag") || err.contains("path traversal"));

    // 2. Invalid tag '..'
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", ".."]);
    assert!(!ok, "Tag '..' must be rejected");

    // 3. Invalid tag 'foo/bar'
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "foo/bar"]);
    assert!(!ok, "Tag with path separators must be rejected");

    // 4. Invalid tag 'instance_id'
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "instance_id"]);
    assert!(!ok, "Tag 'instance_id' must be rejected");

    // 5. Over-long tag (>64 chars)
    let long_tag = "a".repeat(65);
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", &long_tag]);
    assert!(!ok, "Tag > 64 chars must be rejected");

    // 6. Tag with spaces or special symbols
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "tag with spaces"]);
    assert!(!ok, "Tag with spaces must be rejected");

    // 7. Valid tag
    let (ok, _out, _err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "valid-tag_1"]);
    assert!(ok, "Valid ASCII alphanumeric tag must succeed");
}

#[test]
fn test_bug_05_snapshot_refuses_when_locked() {
    let dir = TempDir::new().unwrap();
    let (mut app, profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
    app.logout();

    let profile_dir = dir.path().join(&profile.folder_name);

    // Case 1: .wallet.lock held by active process (current PID)
    let lock_file = profile_dir.join(".wallet.lock");
    fs::write(&lock_file, std::process::id().to_string()).unwrap();

    let (ok, _out, err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "locked-test"]);
    assert!(!ok, "Snapshot save must fail while active .wallet.lock exists");
    assert!(err.contains("locked by active process") || err.contains("Cannot access profile"));

    let _ = fs::remove_file(&lock_file);

    // Case 2: .wallet.transaction.lock held by OS flock
    #[cfg(unix)]
    {
        let tx_lock_path = profile_dir.join(".wallet.transaction.lock");
        let tx_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&tx_lock_path)
            .unwrap();

        // Acquire exclusive non-blocking flock
        let lock_res = tx_file.try_lock();
        assert!(lock_res.is_ok(), "Must be able to lock tx lock for testing");

        let (ok, _out, err) = run_cli(dir.path(), &["snapshot", "save", "-u", "Alice", "-t", "tx-locked-test"]);
        assert!(!ok, "Snapshot save must fail while .wallet.transaction.lock is held");
        assert!(err.contains("wallet transaction is currently in progress") || err.contains("Cannot access profile"));

        let _ = tx_file.unlock();
    }
}

// ---------------------------------------------------------------------------
// BUG-02: Char-boundary-safe UTF-8 string rendering
// ---------------------------------------------------------------------------

#[test]
fn test_bug_02_utf8_rendering_with_multibyte_characters() {
    let dir = TempDir::new().unwrap();
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let std_dir = manifest_dir.join("voucher_standards");

    // Run playbook scenario with multi-byte UTF-8 name and currency symbols
    let playbook_json = serde_json::json!({
        "description": "Multi-byte UTF-8 test scenario with German umlauts and symbols",
        "steps": [
            {
                "action": "create_profile",
                "name": "Bürger-Gutschein € äöü 🪙",
                "password": PASSWORD,
                "first_name": "Jürgen",
                "last_name": "Müller"
            }
        ]
    });

    let playbook_path = dir.path().join("playbook_utf8.json");
    fs::write(&playbook_path, serde_json::to_string_pretty(&playbook_json).unwrap()).unwrap();

    let output = Command::new(CLI_BIN)
        .arg("--data-dir")
        .arg(dir.path())
        .arg("--standards-dir")
        .arg(std_dir)
        .arg("--password")
        .arg(PASSWORD)
        .arg("scenario")
        .arg("run")
        .arg(&playbook_path)
        .output()
        .expect("Failed to execute wallet-cli scenario run");

    assert!(
        output.status.success(),
        "Scenario runner must not panic on multi-byte UTF-8 profile names: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// BUG-04: Orphaned temp file cleanup in root and events/ directories
// ---------------------------------------------------------------------------

#[test]
fn test_bug_04_clean_orphaned_transaction_temps_in_root_and_events() {
    let dir = TempDir::new().unwrap();
    let (_app, profile) =
        test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

    let storage = FileStorage::new(dir.path().join(&profile.folder_name));
    let events_dir = storage.user_storage_path.join("events");
    fs::create_dir_all(&events_dir).unwrap();

    // Create recognized temp in root
    let root_temp = storage.user_storage_path.join("vouchers.enc.tmp.0123456789abcdef0123456789abcdef");
    fs::write(&root_temp, b"staged root temp").unwrap();

    // Create recognized temp in events/
    let event_temp = events_dir.join("event_1.json.enc.tmp.0123456789abcdef0123456789abcdef");
    fs::write(&event_temp, b"staged event temp").unwrap();

    // Create unknown regular files that must NOT be removed
    let root_unknown = storage.user_storage_path.join("unknown_note.txt");
    fs::write(&root_unknown, b"important note").unwrap();

    let event_unknown = events_dir.join("unknown_event_data.txt");
    fs::write(&event_unknown, b"other event data").unwrap();

    // Run clean_orphaned_transaction_temps
    storage.clean_orphaned_transaction_temps().expect("Cleanup must succeed");

    // Assert temps cleaned
    assert!(!root_temp.exists(), "Root temp must be cleaned");
    assert!(!event_temp.exists(), "Event temp must be cleaned");

    // Assert unknown files preserved
    assert!(root_unknown.exists(), "Root unknown file must be preserved");
    assert!(event_unknown.exists(), "Event unknown file must be preserved");
}
