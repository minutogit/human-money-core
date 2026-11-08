//! Regression and mutation hardening test suite for human_money_core storage transactions and differential backups.
//!
//! Specifically hardens:
//! - AppService::inspect_backup user binding and sync_state assertion
//! - WalletTransaction::validate schema, generation, file bounds, path traversal and field isolation checks
//! - WalletTransaction::recover active fork lock preservation (preventing restoration of unlocked seals)
//! - WalletTransaction::recover idempotent commit marker verification (generation and path consistency)

use base64::{engine::general_purpose::STANDARD, Engine};
use human_money_core::{
    app_service::AppService,
    models::{
        backup::{BackupProtection, BackupRestoreCredentials},
        seal::SealSyncState,
    },
    services::{crypto, mnemonic::MnemonicLanguage},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
};
use tempfile::tempdir;

const PASSWORD: &str = "hardening-test-password-123";
const PHRASE_ALICE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PHRASE_BOB: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

mod base64_serde {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
struct SavedFile(#[serde(with = "base64_serde")] Vec<u8>);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Undo {
    version: u8,
    wallet_path: String,
    id: String,
    generation: u64,
    previous_commit: Option<String>,
    files: BTreeMap<String, SavedFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    #[serde(with = "base64_serde")]
    key_profile: Vec<u8>,
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    version: u8,
    wallet_path: String,
    id: String,
    generation: u64,
}

#[derive(Serialize, Deserialize)]
struct EncryptedStorageContainer {
    #[serde(with = "base64_serde")]
    encrypted_store_payload: Vec<u8>,
}

fn extract_master_key(wallet_path: &Path, password: &str) -> [u8; 32] {
    #[derive(Deserialize)]
    struct ProfileContainer {
        #[serde(with = "base64_serde")]
        password_wrapped_key_with_nonce: Vec<u8>,
        #[serde(with = "base64_serde")]
        password_kdf_salt: Vec<u8>,
    }
    let bytes = fs::read(wallet_path.join("profile.enc")).expect("read profile.enc");
    let container: ProfileContainer =
        serde_json::from_slice(&bytes).expect("parse ProfileContainer");
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&container.password_kdf_salt);
    let key_32: [u8; 32] = hasher.finalize().into();
    let master = crypto::decrypt_data(&key_32, &container.password_wrapped_key_with_nonce)
        .expect("decrypt master key");
    master.try_into().expect("32 byte key")
}

fn write_journal(
    wallet_path: &Path,
    master_key: &[u8; 32],
    key_profile: &[u8],
    undo: &Undo,
) {
    let plain = serde_json::to_vec(undo).expect("encode undo");
    let encrypted_store_payload =
        crypto::encrypt_data(master_key, &plain).expect("encrypt undo payload");
    let envelope = Envelope {
        key_profile: key_profile.to_vec(),
        encrypted_store_payload,
    };
    let bytes = serde_json::to_vec(&envelope).expect("encode envelope");
    fs::write(wallet_path.join(".wallet.undo.enc"), bytes).expect("write undo journal");
}

fn write_commit(wallet_path: &Path, master_key: &[u8; 32], commit: &Commit) {
    let plain = serde_json::to_vec(commit).expect("encode commit");
    let encrypted_store_payload =
        crypto::encrypt_data(master_key, &plain).expect("encrypt commit payload");
    let container = EncryptedStorageContainer {
        encrypted_store_payload,
    };
    let bytes = serde_json::to_vec(&container).expect("encode commit container");
    fs::write(wallet_path.join(".wallet.commit.enc"), bytes).expect("write commit marker");
}

fn canonical_path_string(path: &Path) -> String {
    path.canonicalize()
        .expect("canonicalize")
        .to_string_lossy()
        .into_owned()
}

fn read_generation(wallet_path: &Path) -> u64 {
    let p = wallet_path.join(".wallet.generation");
    if !p.exists() {
        return 0;
    }
    fs::read_to_string(&p)
        .expect("read gen")
        .trim()
        .parse()
        .expect("parse gen")
}

fn write_generation(wallet_path: &Path, generation_count: u64) {
    fs::write(
        wallet_path.join(".wallet.generation"),
        generation_count.to_string(),
    )
    .expect("write gen");
}

// ---------------------------------------------------------------------------
// 1. AppService::inspect_backup user binding & sync_state (Mutant line 398)
// ---------------------------------------------------------------------------
#[test]
fn test_inspect_backup_sync_state_strictly_matches_unlocked_user() {
    let dir = tempdir().expect("tempdir");
    let mut app = AppService::new(dir.path()).expect("app");

    // Alice
    app.create_profile(
        "Alice",
        PHRASE_ALICE,
        None,
        Some("sa"),
        PASSWORD,
        MnemonicLanguage::English,
        "dev-a".into(),
    )
    .expect("create alice");

    let alice_cred = BackupRestoreCredentials::Mnemonic {
        phrase: PHRASE_ALICE,
        passphrase: None,
        prefix: Some("sa"),
        language: MnemonicLanguage::English,
    };

    let alice_backup = app
        .create_differential_backup(None, BackupProtection::MnemonicOnly, Some(PASSWORD))
        .expect("create alice backup");

    // 1. Unlocked Alice inspecting Alice's own backup MUST have sync_state = Some(Synchronized)
    let alice_report = app
        .inspect_backup(&alice_backup.encrypted_manifest_bytes, &alice_cred)
        .expect("inspect alice own");
    assert_eq!(
        alice_report.sync_state,
        Some(SealSyncState::Synchronized),
        "Unlocked user inspecting their own backup must have Some(Synchronized) sync_state"
    );

    // 2. Create Bob in a separate root
    let bob_dir = tempdir().expect("bob dir");
    let mut bob_app = AppService::new(bob_dir.path()).expect("bob app");
    bob_app
        .create_profile(
            "Bob",
            PHRASE_BOB,
            None,
            Some("sb"),
            PASSWORD,
            MnemonicLanguage::English,
            "dev-b".into(),
        )
        .expect("create bob");

    let bob_cred = BackupRestoreCredentials::Mnemonic {
        phrase: PHRASE_BOB,
        passphrase: None,
        prefix: Some("sb"),
        language: MnemonicLanguage::English,
    };

    let bob_backup = bob_app
        .create_differential_backup(None, BackupProtection::MnemonicOnly, Some(PASSWORD))
        .expect("create bob backup");

    // 3. Alice (still unlocked) inspecting Bob's backup MUST have sync_state = None (user mismatch)
    let foreign_report = app
        .inspect_backup(&bob_backup.encrypted_manifest_bytes, &bob_cred)
        .expect("alice inspects bob backup");
    assert_eq!(
        foreign_report.sync_state, None,
        "Unlocked user inspecting another user's backup must have None sync_state"
    );

    // 4. Locked Alice inspecting Alice's backup MUST have sync_state = None
    app.logout();
    let locked_report = app
        .inspect_backup(&alice_backup.encrypted_manifest_bytes, &alice_cred)
        .expect("inspect locked");
    assert_eq!(
        locked_report.sync_state, None,
        "Locked app inspecting backup must have None sync_state"
    );
}

// ---------------------------------------------------------------------------
// 2. WalletTransaction::validate header & bounds (Mutants lines 434, 435, 436)
// ---------------------------------------------------------------------------
#[test]
fn test_wallet_transaction_validate_header_field_boundaries() {
    let dir = tempdir().expect("tempdir");
    let mut app = AppService::new(dir.path()).expect("app");
    app.create_profile(
        "HeaderTest",
        PHRASE_ALICE,
        None,
        Some("ht"),
        PASSWORD,
        MnemonicLanguage::English,
        "dev-1".into(),
    )
    .expect("create profile");

    let folder = app.list_profiles().expect("list")[0].folder_name.clone();
    app.logout();

    let wallet_path = dir.path().join(&folder);
    let master_key = extract_master_key(&wallet_path, PASSWORD);
    let key_profile = fs::read(wallet_path.join("profile.enc")).expect("read profile");
    let canonical_path = canonical_path_string(&wallet_path);
    let current_gen = read_generation(&wallet_path);

    let base_files = {
        let mut map = BTreeMap::new();
        map.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        map
    };

    // Case 2a: Version != 1 alone must trigger "foreign or invalid undo journal"
    {
        let undo = Undo {
            version: 2, // invalid
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Version != 1 must fail undo journal validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("foreign or invalid undo journal"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }

    // Case 2b: Foreign wallet_path alone must trigger "foreign or invalid undo journal"
    {
        let undo = Undo {
            version: 1,
            wallet_path: "/foreign/nonexistent/wallet/path".to_string(), // invalid
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Foreign wallet path must fail undo journal validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("foreign or invalid undo journal"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }

    // Case 2c: files.len() > MAX_FILES (4097) alone must trigger "foreign or invalid undo journal"
    {
        let mut oversized_files = BTreeMap::new();
        oversized_files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        for i in 0..4096 {
            oversized_files.insert(
                format!("generic_{i}.enc"),
                SavedFile(b"small payload".to_vec()),
            );
        }
        assert_eq!(oversized_files.len(), 4097);
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files: oversized_files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Files count 4097 > 4096 must fail undo journal validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("foreign or invalid undo journal"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }

    // Case 2d: files.len() == MAX_FILES (4096) MUST NOT trigger "foreign or invalid undo journal"
    {
        let mut max_files = BTreeMap::new();
        max_files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        for i in 0..4095 {
            max_files.insert(
                format!("generic_{i}.enc"),
                SavedFile(b"small payload".to_vec()),
            );
        }
        assert_eq!(max_files.len(), 4096);
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files: max_files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        // 4096 is <= MAX_FILES, so it must not be rejected by header validation
        if let Err(ref e) = login_res {
            let err_str = format!("{e:?}");
            assert!(
                !err_str.contains("foreign or invalid undo journal"),
                "Boundary files count 4096 must NOT fail with 'foreign or invalid undo journal'. Got: {err_str}"
            );
        }
        let _ = fs::remove_file(wallet_path.join(".wallet.undo.enc"));
    }

    // Case 2e: id.len() != 36 alone must trigger "foreign or invalid undo journal"
    {
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: "short-uuid-too-short".to_string(), // length != 36
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "id.len() != 36 must fail undo journal validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("foreign or invalid undo journal"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }
}

// ---------------------------------------------------------------------------
// 3. WalletTransaction::validate file entry bounds & paths (Mutants lines 442, 443)
// ---------------------------------------------------------------------------
#[test]
fn test_wallet_transaction_validate_file_entry_bounds_and_paths() {
    let dir = tempdir().expect("tempdir");
    let mut app = AppService::new(dir.path()).expect("app");
    app.create_profile(
        "EntryTest",
        PHRASE_ALICE,
        None,
        Some("et"),
        PASSWORD,
        MnemonicLanguage::English,
        "dev-1".into(),
    )
    .expect("create profile");

    let folder = app.list_profiles().expect("list")[0].folder_name.clone();
    app.logout();

    let wallet_path = dir.path().join(&folder);
    let master_key = extract_master_key(&wallet_path, PASSWORD);
    let key_profile = fs::read(wallet_path.join("profile.enc")).expect("read profile");
    let canonical_path = canonical_path_string(&wallet_path);
    let current_gen = read_generation(&wallet_path);

    // Case 3a: Non-managed file name must trigger "invalid undo entry"
    {
        let mut files = BTreeMap::new();
        files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        files.insert("malicious_shell.sh".to_string(), SavedFile(b"#!/bin/sh".to_vec()));
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Non-managed filename in undo files must fail"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid undo entry"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }

    // Case 3b: File bytes > MAX_FILE_BYTES (16MB + 1) must trigger "invalid undo entry"
    {
        let max_plus_one = 16 * 1024 * 1024 + 1;
        let mut files = BTreeMap::new();
        files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        files.insert(
            "generic_huge.enc".to_string(),
            SavedFile(vec![0u8; max_plus_one]),
        );
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "File > 16MB in undo journal must fail validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid undo entry"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }

    // Case 3c: File bytes == MAX_FILE_BYTES (16MB) must NOT trigger > check error
    // Note: Due to snapshot size limit (MAX_JOURNAL_BYTES/4 = 16MB total), 16MB alone reaches the limit,
    // but at the individual file level in validate, 16MB does NOT exceed MAX_FILE_BYTES.
    // We verify a valid 1MB file is accepted without "invalid undo entry".
    {
        let mut files = BTreeMap::new();
        files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        files.insert(
            "generic_valid.enc".to_string(),
            SavedFile(vec![0x42; 1024 * 1024]),
        );
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        if let Err(ref e) = login_res {
            let err_str = format!("{e:?}");
            assert!(
                !err_str.contains("invalid undo entry"),
                "1MB valid generic file must not fail with 'invalid undo entry': {err_str}"
            );
        }
        let _ = fs::remove_file(wallet_path.join(".wallet.undo.enc"));
    }

    // Case 3d: Non-normal path component (path traversal) must trigger "invalid undo entry"
    {
        let mut files = BTreeMap::new();
        files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        // "events/../profile.enc" has ParentDir ("..") component
        files.insert(
            "events/../profile.enc".to_string(),
            SavedFile(key_profile.clone()),
        );
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: uuid::Uuid::new_v4().to_string(),
            generation: current_gen,
            previous_commit: None,
            files,
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);
        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Path with non-normal component must fail validation"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid undo entry"),
            "Error was: {err_str}"
        );
        fs::remove_file(wallet_path.join(".wallet.undo.enc")).expect("cleanup");
    }
}

// ---------------------------------------------------------------------------
// 4. WalletTransaction::recover active fork lock preservation (Mutant line 468)
// ---------------------------------------------------------------------------
#[test]
fn test_wallet_transaction_recover_refuses_restoring_unlocked_seal_over_active_fork_lock() {
    let dir = tempdir().expect("tempdir");
    let mut app = AppService::new(dir.path()).expect("app");
    app.create_profile(
        "ForkLockTest",
        PHRASE_ALICE,
        None,
        Some("fl"),
        PASSWORD,
        MnemonicLanguage::English,
        "dev-1".into(),
    )
    .expect("create profile");

    let folder = app.list_profiles().expect("list")[0].folder_name.clone();
    let wallet_path = dir.path().join(&folder);
    let master_key = extract_master_key(&wallet_path, PASSWORD);
    let key_profile = fs::read(wallet_path.join("profile.enc")).expect("read profile");
    let canonical_path = canonical_path_string(&wallet_path);
    let current_gen = read_generation(&wallet_path);

    // 1. Snapshot the UNLOCKED seal currently on disk
    let unlocked_seal_bytes = fs::read(wallet_path.join("seal.enc")).expect("read seal.enc");

    // 2. Decode seal, mark is_locked_due_to_fork = true, re-encrypt and store as disk state
    #[derive(Serialize, Deserialize)]
    struct LocalSealContainer {
        #[serde(with = "base64_serde")]
        encrypted_store_payload: Vec<u8>,
    }
    let seal_container: LocalSealContainer =
        serde_json::from_slice(&unlocked_seal_bytes).expect("parse seal container");
    let decrypted_seal_bytes =
        crypto::decrypt_data(&master_key, &seal_container.encrypted_store_payload)
            .expect("decrypt seal");
    let mut seal_record: serde_json::Value =
        serde_json::from_slice(&decrypted_seal_bytes).expect("parse seal record json");
    assert!(seal_record["lock_reason"].is_null());

    // Mark locked
    seal_record["lock_reason"] = serde_json::json!("ForkDetected");
    let locked_seal_plain = serde_json::to_vec(&seal_record).expect("encode locked seal");
    let locked_seal_enc =
        crypto::encrypt_data(&master_key, &locked_seal_plain).expect("encrypt locked seal");
    let new_seal_container = LocalSealContainer {
        encrypted_store_payload: locked_seal_enc,
    };
    fs::write(
        wallet_path.join("seal.enc"),
        serde_json::to_vec(&new_seal_container).unwrap(),
    )
    .expect("write locked seal");

    app.logout();

    // 3. Stage an authentic undo journal containing the UNLOCKED seal
    let mut files = BTreeMap::new();
    files.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
    files.insert(
        "seal.enc".to_string(),
        SavedFile(unlocked_seal_bytes.clone()),
    );
    let undo = Undo {
        version: 1,
        wallet_path: canonical_path.clone(),
        id: uuid::Uuid::new_v4().to_string(),
        generation: current_gen,
        previous_commit: None,
        files,
    };
    write_journal(&wallet_path, &master_key, &key_profile, &undo);

    // 4. Login recovery must REFUSE to restore unlocked seal over active fork lock
    let mut app2 = AppService::new(dir.path()).expect("app2");
    let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
    assert!(
        login_res.is_err(),
        "Recovery must fail when trying to restore unlocked seal over active fork lock"
    );
    let err_str = format!("{:?}", login_res.err().unwrap());
    assert!(
        err_str.contains("refusing to restore unlocked seal over active fork lock"),
        "Error was: {err_str}"
    );

    // 5. Verify the disk seal is STILL locked (was not overwritten)
    let current_seal_disk = fs::read(wallet_path.join("seal.enc")).expect("read disk seal");
    let disk_container: LocalSealContainer =
        serde_json::from_slice(&current_seal_disk).expect("parse disk container");
    let disk_seal_plain =
        crypto::decrypt_data(&master_key, &disk_container.encrypted_store_payload)
            .expect("decrypt");
    let disk_seal_val: serde_json::Value = serde_json::from_slice(&disk_seal_plain).unwrap();
    assert_eq!(
        disk_seal_val["lock_reason"], "ForkDetected",
        "Fork lock must remain active and not be wiped"
    );
}

// ---------------------------------------------------------------------------
// 5. WalletTransaction::recover idempotent commit checks (Mutants lines 482, 484)
// ---------------------------------------------------------------------------
#[test]
fn test_wallet_transaction_recover_idempotent_commit_invariants() {
    let dir = tempdir().expect("tempdir");
    let mut app = AppService::new(dir.path()).expect("app");
    app.create_profile(
        "IdempotentTest",
        PHRASE_ALICE,
        None,
        Some("it"),
        PASSWORD,
        MnemonicLanguage::English,
        "dev-1".into(),
    )
    .expect("create profile");

    let folder = app.list_profiles().expect("list")[0].folder_name.clone();
    let wallet_path = dir.path().join(&folder);
    let master_key = extract_master_key(&wallet_path, PASSWORD);
    let key_profile = fs::read(wallet_path.join("profile.enc")).expect("read profile");
    let canonical_path = canonical_path_string(&wallet_path);
    let current_gen = read_generation(&wallet_path);

    app.logout();

    let tx_id = uuid::Uuid::new_v4().to_string();
    let base_files = {
        let mut map = BTreeMap::new();
        map.insert("profile.enc".to_string(), SavedFile(key_profile.clone()));
        map
    };

    // Case 5a: Commit marker has matching ID and generation (current_gen + 1),
    // but commit.wallet_path does not match undo.wallet_path.
    // Line 482 || must reject foreign path with "invalid committed generation"
    {
        write_generation(&wallet_path, current_gen + 1);
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: tx_id.clone(),
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);

        let commit = Commit {
            version: 1,
            wallet_path: "/foreign/wallet/path".to_string(), // mismatched path
            id: tx_id.clone(),
            generation: current_gen + 1,
        };
        write_commit(&wallet_path, &master_key, &commit);

        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Mismatched commit wallet_path in forward recovery must fail"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid committed generation"),
            "Error was: {err_str}"
        );
        let _ = fs::remove_file(wallet_path.join(".wallet.undo.enc"));
        let _ = fs::remove_file(wallet_path.join(".wallet.commit.enc"));
    }

    // Case 5b: Commit marker has matching ID, generation (current_gen + 1), and matching wallet_path,
    // but storage generation on disk != current_gen + 1 (e.g. rolled back to current_gen).
    // Line 484 || must reject storage generation mismatch with "invalid committed generation"
    {
        write_generation(&wallet_path, current_gen); // storage generation NOT bumped
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: tx_id.clone(),
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);

        let commit = Commit {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: tx_id.clone(),
            generation: current_gen + 1,
        };
        write_commit(&wallet_path, &master_key, &commit);

        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Storage generation mismatch in forward recovery must fail"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid committed generation"),
            "Error was: {err_str}"
        );
        let _ = fs::remove_file(wallet_path.join(".wallet.undo.enc"));
        let _ = fs::remove_file(wallet_path.join(".wallet.commit.enc"));
    }

    // Case 5c: Commit marker has matching ID and wallet_path,
    // but commit.generation != current_gen + 1.
    {
        write_generation(&wallet_path, current_gen + 1);
        let undo = Undo {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: tx_id.clone(),
            generation: current_gen,
            previous_commit: None,
            files: base_files.clone(),
        };
        write_journal(&wallet_path, &master_key, &key_profile, &undo);

        let commit = Commit {
            version: 1,
            wallet_path: canonical_path.clone(),
            id: tx_id.clone(),
            generation: current_gen + 2, // mismatched commit generation
        };
        write_commit(&wallet_path, &master_key, &commit);

        let mut app2 = AppService::new(dir.path()).expect("app2");
        let login_res = app2.login(&folder, PASSWORD, false, "dev-1".into());
        assert!(
            login_res.is_err(),
            "Commit generation mismatch in forward recovery must fail"
        );
        let err_str = format!("{:?}", login_res.err().unwrap());
        assert!(
            err_str.contains("invalid committed generation"),
            "Error was: {err_str}"
        );
        let _ = fs::remove_file(wallet_path.join(".wallet.undo.enc"));
        let _ = fs::remove_file(wallet_path.join(".wallet.commit.enc"));
    }
}
