//! Comprehensive end-to-end integration tests for `wallet-cli`.
//!
//! Verifies:
//! 1. Profile lifecycle, BIP-39 mnemonic generation/validation, WalletSeal device binding and handover.
//! 2. Minuto voucher issuance with multi-guarantor detached signing (CEL rules) and split transfers.
//! 3. Offline double-spending with time-travel snapshots and conflict detection/reputation commands.
//! 4. In-memory scenario runner playbooks.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const CLI_BIN: &str = env!("CARGO_BIN_EXE_wallet-cli");
const TEST_PASSWORD: &str = "test-pw-123";

#[derive(Clone)]
struct CliRunner {
    data_dir: PathBuf,
    standards_dir: PathBuf,
    password: Option<String>,
    device_id: Option<String>,
    auto_handover: bool,
}

impl CliRunner {
    fn new(data_dir: PathBuf) -> Self {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let standards_dir = manifest_dir.join("voucher_standards");
        Self {
            data_dir,
            standards_dir,
            password: Some(TEST_PASSWORD.to_string()),
            device_id: None,
            auto_handover: false,
        }
    }

    fn with_device_id(mut self, device_id: impl Into<String>) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    fn with_auto_handover(mut self, auto_handover: bool) -> Self {
        self.auto_handover = auto_handover;
        self
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(CLI_BIN);
        cmd.arg("--data-dir").arg(&self.data_dir);
        cmd.arg("--standards-dir").arg(&self.standards_dir);
        if let Some(ref pwd) = self.password {
            cmd.arg("--password").arg(pwd);
        }
        if let Some(ref dev) = self.device_id {
            cmd.arg("--device-id").arg(dev);
        }
        if self.auto_handover {
            cmd.arg("--auto-handover");
        }
        cmd.arg("--json");
        cmd.args(args);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd(args)
            .output()
            .unwrap_or_else(|e| panic!("failed to execute wallet-cli {:?}: {e}", args))
    }

    fn run_ok(&self, args: &[&str]) -> serde_json::Value {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "wallet-cli {:?} unexpectedly failed with code {:?}\nstdout: {}\nstderr: {}",
            args,
            output.status.code(),
            stdout,
            stderr
        );
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("failed to parse JSON from stdout:\n{}\nError: {}", stdout, e)
        });
        assert_eq!(
            parsed["ok"],
            true,
            "expected ok: true in envelope, got: {}",
            parsed
        );
        parsed["data"].clone()
    }

    fn run_err(&self, args: &[&str]) -> serde_json::Value {
        let output = self.run(args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !output.status.success(),
            "wallet-cli {:?} unexpectedly succeeded with exit code 0\nstdout: {}",
            args,
            stdout
        );
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("failed to parse error JSON from stdout:\n{}\nError: {}", stdout, e)
        });
        assert_eq!(
            parsed["ok"],
            false,
            "expected ok: false in error envelope, got: {}",
            parsed
        );
        parsed["error"].clone()
    }
}

/// 1. Profile lifecycle, BIP-39 mnemonic generation/validation, WalletSeal device binding,
/// and graceful handover when `--auto-handover` is supplied.
#[test]
fn test_cli_profile_lifecycle_and_device_handover() {
    let tmp = TempDir::new().expect("create temp dir");
    let cli = CliRunner::new(tmp.path().to_path_buf());

    // 1. Generate fresh 12-word mnemonic
    let gen_data = cli.run_ok(&["mnemonic", "generate", "--words", "12"]);
    assert_eq!(gen_data["words"], 12);
    let phrase = gen_data["mnemonic"].as_str().expect("mnemonic phrase");
    assert_eq!(phrase.split_whitespace().count(), 12);

    // Validate the generated phrase
    let val_data = cli.run_ok(&["mnemonic", "validate", "--phrase", phrase]);
    assert_eq!(val_data["valid"], true);

    // 2. Create profile Alice with specific public metadata
    let create_data = cli.run_ok(&[
        "profile", "create",
        "--name", "Alice",
        "--first-name", "Alice",
        "--gender", "2",
        "--mnemonic", phrase,
    ]);
    assert_eq!(create_data["profile_name"], "Alice");
    let folder_name = create_data["folder_name"]
        .as_str()
        .expect("folder_name")
        .to_string();

    // 3. Attempt to inspect profile with a DIFFERENT device ID without --auto-handover -> MUST fail
    let foreign_cli = cli.clone().with_device_id("other-ui-device");
    let err_data = foreign_cli.run_err(&["profile", "info", "--profile", "Alice"]);
    let err_msg = err_data["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("WalletSeal") || err_msg.contains("device") || err_msg.contains("handover"),
        "Error message should explain device mismatch: {}",
        err_msg
    );

    // 4. Inspect profile with the foreign device ID WITH --auto-handover -> MUST succeed and rebind
    let handover_cli = foreign_cli.with_auto_handover(true);
    let info_data = handover_cli.run_ok(&["profile", "info", "--profile", "Alice"]);
    assert_eq!(info_data["profile_name"], "Alice");
    assert_eq!(info_data["public_profile"]["first_name"], "Alice");
    assert_eq!(info_data["public_profile"]["gender"], "2");

    // 5. Confirm no leftover `.wallet.lock` file exists in Alice's folder after command termination
    let lock_path = tmp.path().join(&folder_name).join(".wallet.lock");
    assert!(
        !lock_path.exists(),
        "Expected .wallet.lock to be removed after process exit, but it exists at {:?}",
        lock_path
    );
}

/// 2. Minuto voucher issuance with multi-guarantor detached signing (satisfying CEL gender balance rules)
/// and split transfer to Bob.
#[test]
fn test_cli_minuto_guarantor_signing_and_split_transfer() {
    let tmp = TempDir::new().expect("create temp dir");
    let cli = CliRunner::new(tmp.path().to_path_buf());

    // 1. Create profiles:
    // Creator (male = 1)
    cli.run_ok(&[
        "profile", "create",
        "--name", "Creator",
        "--first-name", "Creator",
        "--gender", "1",
    ]);

    // GuarantorM (male = 1, satisfying CEL rule `gender_balance_male`)
    cli.run_ok(&[
        "profile", "create",
        "--name", "GuarantorM",
        "--first-name", "Max",
        "--last-name", "M",
        "--gender", "1",
        "--email", "max@example.org",
    ]);
    cli.run_ok(&[
        "profile", "update",
        "--profile", "GuarantorM",
        "--street", "Hauptstr",
        "--house-number", "1",
        "--zip-code", "10115",
        "--city", "Berlin",
        "--country", "DE",
    ]);

    // GuarantorF (female = 2, satisfying CEL rule `gender_balance_female`)
    cli.run_ok(&[
        "profile", "create",
        "--name", "GuarantorF",
        "--first-name", "Erika",
        "--last-name", "F",
        "--gender", "2",
        "--email", "erika@example.org",
    ]);
    cli.run_ok(&[
        "profile", "update",
        "--profile", "GuarantorF",
        "--street", "Nebenstr",
        "--house-number", "2",
        "--zip-code", "10115",
        "--city", "Berlin",
        "--country", "DE",
    ]);

    // Bob (recipient)
    cli.run_ok(&[
        "profile", "create",
        "--name", "Bob",
        "--first-name", "Bob",
        "--gender", "1",
    ]);

    // 2. Create Minuto voucher (60 Minuto, validity P3Y)
    let voucher_data = cli.run_ok(&[
        "voucher", "create",
        "--profile", "Creator",
        "--standard", "minuto",
        "--amount", "60",
        "--validity", "P3Y",
    ]);
    let local_id = voucher_data["local_instance_id"]
        .as_str()
        .expect("local_instance_id")
        .to_string();

    // Verify initial status is Incomplete
    assert!(
        voucher_data["status"].get("Incomplete").is_some(),
        "Expected status to be Incomplete, got: {:?}",
        voucher_data["status"]
    );

    // 3. Guarantor 1 (GuarantorM) endorsement roundtrip
    let req_m = tmp.path().join("sign_req_m.humoco");
    let resp_m = tmp.path().join("sign_resp_m.humoco");

    cli.run_ok(&[
        "sign", "request",
        "--profile", "Creator",
        "--voucher", &local_id,
        "--target", "GuarantorM",
        "--out", req_m.to_str().unwrap(),
    ]);

    cli.run_ok(&[
        "sign", "endorse",
        "--profile", "GuarantorM",
        "--in", req_m.to_str().unwrap(),
        "--role", "guarantor",
        "--out", resp_m.to_str().unwrap(),
    ]);

    let attach_m = cli.run_ok(&[
        "sign", "attach",
        "--profile", "Creator",
        "--in", resp_m.to_str().unwrap(),
        "--standard", "minuto",
    ]);

    // Voucher still lacks female guarantor endorsement -> still Incomplete
    assert!(
        attach_m["status"].get("Incomplete").is_some(),
        "Expected status to remain Incomplete after 1st signature, got: {:?}",
        attach_m["status"]
    );

    // 4. Guarantor 2 (GuarantorF) endorsement roundtrip
    let req_f = tmp.path().join("sign_req_f.humoco");
    let resp_f = tmp.path().join("sign_resp_f.humoco");

    cli.run_ok(&[
        "sign", "request",
        "--profile", "Creator",
        "--voucher", &local_id,
        "--target", "GuarantorF",
        "--out", req_f.to_str().unwrap(),
    ]);

    cli.run_ok(&[
        "sign", "endorse",
        "--profile", "GuarantorF",
        "--in", req_f.to_str().unwrap(),
        "--role", "guarantor",
        "--out", resp_f.to_str().unwrap(),
    ]);

    let attach_f = cli.run_ok(&[
        "sign", "attach",
        "--profile", "Creator",
        "--in", resp_f.to_str().unwrap(),
        "--standard", "minuto",
    ]);

    // Both CEL requirements met -> status transitions to Active!
    assert_eq!(
        attach_f["status"], "Active",
        "Expected status to transition to Active after both signatures"
    );

    // 5. Creator sends split transfer of 25 Minuto to Bob
    let split_bundle = tmp.path().join("split.humoco");
    cli.run_ok(&[
        "tx", "send",
        "--profile", "Creator",
        "--to", "Bob",
        "--standard", "minuto",
        "--amount", "25",
        "--out", split_bundle.to_str().unwrap(),
    ]);

    // Bob receives the transfer bundle
    cli.run_ok(&[
        "tx", "receive",
        "--profile", "Bob",
        "--in", split_bundle.to_str().unwrap(),
    ]);

    // 6. Verify Creator balance is 35 and Bob balance is 25
    let creator_balance = cli.run_ok(&["balance", "--profile", "Creator"]);
    let creator_minuto = creator_balance
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|b| b["display_standard_name"] == "Minuto")
        })
        .expect("Creator must have Minuto balance");
    assert_eq!(creator_minuto["total_amount"], "35");

    let bob_balance = cli.run_ok(&["balance", "--profile", "Bob"]);
    let bob_minuto = bob_balance
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|b| b["display_standard_name"] == "Minuto")
        })
        .expect("Bob must have Minuto balance");
    assert_eq!(bob_minuto["total_amount"], "25");
}

/// 3. Offline double-spending with point-in-time snapshots, verifiable conflict detection,
/// offender attribution/deanonymization, and conflict export/import.
#[test]
fn test_cli_snapshot_offline_double_spend_and_conflict_commands() {
    let tmp = TempDir::new().expect("create temp dir");
    let cli = CliRunner::new(tmp.path().to_path_buf());

    // 1. Create Alice, Bob, Charlie, Dave
    for name in &["Alice", "Bob", "Charlie", "Dave"] {
        cli.run_ok(&[
            "profile", "create",
            "--name", name,
            "--first-name", name,
            "--gender", "1",
        ]);
    }

    // 2. Alice creates a FreeTaler voucher (50.00, immediately Active)
    let created = cli.run_ok(&[
        "voucher", "create",
        "--profile", "Alice",
        "--standard", "freetaler",
        "--amount", "50.00",
        "--validity", "P1Y",
    ]);
    assert_eq!(created["status"], "Active");

    // Alice transfers 50.00 to Bob
    let ab_bundle = tmp.path().join("ab.humoco");
    cli.run_ok(&[
        "tx", "send",
        "--profile", "Alice",
        "--to", "Bob",
        "--standard", "freetaler",
        "--amount", "50.00",
        "--out", ab_bundle.to_str().unwrap(),
    ]);
    cli.run_ok(&[
        "tx", "receive",
        "--profile", "Bob",
        "--in", ab_bundle.to_str().unwrap(),
    ]);

    // Confirm Bob has 50.00 active balance
    let bob_bal1 = cli.run_ok(&["balance", "--profile", "Bob"]);
    assert_eq!(bob_bal1[0]["total_amount"], "50.00");

    // 3. Bob creates a snapshot before spending
    cli.run_ok(&[
        "snapshot", "save",
        "--profile", "Bob",
        "--tag", "before_spend",
    ]);

    // 4. Branch 1: Bob sends 50.00 to Charlie
    let tx1_path = tmp.path().join("tx1.humoco");
    cli.run_ok(&[
        "tx", "send",
        "--profile", "Bob",
        "--to", "Charlie",
        "--standard", "freetaler",
        "--amount", "50.00",
        "--out", tx1_path.to_str().unwrap(),
    ]);
    cli.run_ok(&[
        "tx", "receive",
        "--profile", "Charlie",
        "--in", tx1_path.to_str().unwrap(),
    ]);

    let charlie_bal1 = cli.run_ok(&["balance", "--profile", "Charlie"]);
    assert_eq!(charlie_bal1[0]["total_amount"], "50.00");

    // 5. Restore Bob's state to before_spend snapshot
    cli.run_ok(&[
        "snapshot", "restore",
        "--profile", "Bob",
        "--tag", "before_spend",
    ]);

    // Bob now has 50.00 active balance again
    let bob_bal2 = cli.run_ok(&["balance", "--profile", "Bob"]);
    assert_eq!(bob_bal2[0]["total_amount"], "50.00");

    // 6. Branch 2 (Double Spend): Bob spends the same 50.00 voucher again to Charlie
    let tx2_path = tmp.path().join("tx2.humoco");
    cli.run_ok(&[
        "tx", "send",
        "--profile", "Bob",
        "--to", "Charlie",
        "--standard", "freetaler",
        "--amount", "50.00",
        "--out", tx2_path.to_str().unwrap(),
    ]);

    // Charlie receives tx2 -> must detect colliding spends from the same fork point
    let recv2 = cli.run_ok(&[
        "tx", "receive",
        "--profile", "Charlie",
        "--in", tx2_path.to_str().unwrap(),
    ]);

    let verifiable_conflicts = &recv2["check_result"]["verifiable_conflicts"];
    assert!(
        !verifiable_conflicts.as_object().unwrap().is_empty(),
        "Charlie must detect verifiable double-spend conflicts upon receiving colliding tx2"
    );

    // 7. Inspect Charlie's conflict list and conflict details
    let conflicts = cli.run_ok(&["conflict", "list", "--profile", "Charlie"]);
    let conflict_list = conflicts.as_array().expect("array of conflicts");
    assert!(
        !conflict_list.is_empty(),
        "Charlie must have recorded the conflict in the conflict store"
    );

    let proof_id = conflict_list[0]["proof_id"]
        .as_str()
        .expect("proof_id string")
        .to_string();

    let proof_show = cli.run_ok(&["conflict", "show", "--profile", "Charlie", &proof_id]);
    assert_eq!(proof_show["proof_id"], proof_id);
    assert_eq!(proof_show["conflicting_transactions"].as_array().unwrap().len(), 2);

    // 8. Verify Bob's reputation from Charlie's perspective
    let rep_bob = cli.run_ok(&["conflict", "reputation", "--profile", "Charlie", "Bob"]);
    assert!(
        rep_bob["trust_status"].get("KnownOffender").is_some(),
        "Bob must be identified as KnownOffender: {:?}",
        rep_bob["trust_status"]
    );

    // 9. Export proof from Charlie to a file
    let proof_file = tmp.path().join("exported_proof.json");
    let export_res = cli.run_ok(&[
        "conflict", "export",
        "--profile", "Charlie",
        &proof_id,
        "--out", proof_file.to_str().unwrap(),
    ]);
    assert_eq!(export_res["proof_id"], proof_id);
    assert!(proof_file.exists());

    // 10. Import proof into Alice's wallet
    let import_res = cli.run_ok(&[
        "conflict", "import",
        "--profile", "Alice",
        "--in", proof_file.to_str().unwrap(),
    ]);
    assert_eq!(import_res["imported"], true);

    // Alice now sees the conflict in her conflict list
    let alice_conflicts = cli.run_ok(&["conflict", "list", "--profile", "Alice"]);
    assert!(
        alice_conflicts
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["proof_id"] == proof_id),
        "Alice must now have imported proof {}",
        proof_id
    );

    // Alice also recognizes Bob as KnownOffender
    let alice_rep_bob = cli.run_ok(&["conflict", "reputation", "--profile", "Alice", "Bob"]);
    assert!(
        alice_rep_bob["trust_status"].get("KnownOffender").is_some(),
        "Alice must recognize Bob as KnownOffender after gossip import"
    );
}

/// 4. In-memory scenario runner executing a multi-step playbook including profile creation,
/// voucher issuance, guarantor endorsement, snapshot preservation, transfer, and rollback.
#[test]
fn test_cli_scenario_runner_playbook() {
    let tmp = TempDir::new().expect("create temp dir");
    let cli = CliRunner::new(tmp.path().to_path_buf());

    // Write a scenario file that covers:
    // create_profile, create_voucher, endorse_voucher, snapshot_save, transfer, snapshot_restore
    let scenario_json = serde_json::json!({
        "description": "Multi-actor scenario playbook testing issuance, endorsement, snapshot, and transfer",
        "steps": [
            {
                "action": "create_profile",
                "name": "PlaybookAlice",
                "gender": "2",
                "first_name": "Alice"
            },
            {
                "action": "create_profile",
                "name": "PlaybookBob",
                "gender": "1",
                "first_name": "Bob"
            },
            {
                "action": "create_profile",
                "name": "PlaybookGuarantor",
                "gender": "1",
                "first_name": "Gordon"
            },
            {
                "action": "create_voucher",
                "profile": "PlaybookAlice",
                "standard": "freetaler",
                "amount": "100.00",
                "validity": "P1Y",
                "save_ref": "voucher_alice"
            },
            {
                "action": "endorse_voucher",
                "creator": "PlaybookAlice",
                "voucher_ref": "voucher_alice",
                "signer": "PlaybookGuarantor",
                "role": "guarantor"
            },
            {
                "action": "snapshot_save",
                "profile": "PlaybookAlice",
                "tag": "pre_transfer"
            },
            {
                "action": "transfer",
                "from": "PlaybookAlice",
                "to": "PlaybookBob",
                "standard": "freetaler",
                "amount": "40.00",
                "auto_receive": true
            },
            {
                "action": "snapshot_restore",
                "profile": "PlaybookAlice",
                "tag": "pre_transfer"
            }
        ]
    });

    let scenario_file = tmp.path().join("playbook.json");
    std::fs::write(&scenario_file, serde_json::to_string_pretty(&scenario_json).unwrap())
        .expect("write scenario file");

    let report = cli.run_ok(&[
        "scenario", "run",
        scenario_file.to_str().unwrap(),
    ]);

    assert_eq!(report["total_steps"], 8);
    assert_eq!(report["completed_steps"], 8);

    // Validate final actor balances:
    // Alice had 100.00, sent 40.00 to Bob, but was restored to pre_transfer -> Alice has 100.00!
    // Bob received 40.00 -> Bob has 40.00!
    let actors = report["actors"].as_array().expect("actors array");

    let alice = actors
        .iter()
        .find(|a| a["profile_name"] == "PlaybookAlice")
        .expect("PlaybookAlice in actor summary");
    let alice_bal = &alice["balances"][0]["total_amount"];
    assert_eq!(alice_bal, "100.00");

    let bob = actors
        .iter()
        .find(|a| a["profile_name"] == "PlaybookBob")
        .expect("PlaybookBob in actor summary");
    let bob_bal = &bob["balances"][0]["total_amount"];
    assert_eq!(bob_bal, "40.00");
}
