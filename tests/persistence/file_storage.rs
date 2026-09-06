// tests/persistence/file_storage.rs
// cargo test --test persistence_tests
//!
//! Contains integration tests for the refactored profile and VoucherStore management,
//! including password recovery logic and edge cases.
//! Originally in `tests/test_file_storage.rs`.

use human_money_core::UserIdentity;
use human_money_core::VoucherStatus;
use human_money_core::error::VoucherCoreError;
use human_money_core::models::voucher::{ValueDefinition, Voucher};
use human_money_core::services::crypto_utils;
use human_money_core::services::voucher_manager;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::storage::AuthMethod;
use human_money_core::{FileStorage, Storage, StorageError, Wallet};
use std::fs;
use tempfile::tempdir;

// Load test helper functions from the parent directory.

use human_money_core::test_utils::{
    ACTORS, FREETALER_STANDARD, add_voucher_to_wallet, setup_in_memory_wallet,
};

// --- Helper Functions ---
fn create_test_voucher(identity: &UserIdentity) -> Voucher {
    let new_voucher_data = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(identity.user_id.clone()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            address: Some(Default::default()),
            organization: None,
            community: None,
            phone: None,
            email: None,
            url: None,
            gender: Some("9".to_string()),
            coordinates: Some("0,0".to_string()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    voucher_manager::create_voucher(
        new_voucher_data,
        standard,
        standard_hash,
        &identity.signing_key)
    .expect("Voucher creation failed")
}

// --- Tests ---

#[test]
fn test_wallet_creation_save_and_load() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";
    let identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);

    // 2. Save
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .expect("Failed to save wallet");

    // 3. Load and verify
    let (loaded_wallet, loaded_identity) =
        Wallet::load(&storage, &AuthMethod::Password(password), "test-id".to_string()).expect("Failed to load wallet");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert_eq!(identity.user_id, loaded_identity.user_id);
    assert!(loaded_wallet.voucher_store.vouchers.is_empty());

    // 4. Error case: Wrong password
    let result = Wallet::load(&storage, &AuthMethod::Password("wrongpassword"), "test-id".to_string());
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_password_recovery_and_reset_with_data() {
    // 1. Setup: Create a profile with a voucher.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let initial_password = "my-secret-password";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);
    let voucher = create_test_voucher(identity);
    let local_id = Wallet::calculate_local_instance_id(&voucher, &identity.user_id).unwrap();

    wallet.add_voucher_instance(local_id.clone(), voucher, VoucherStatus::Active);
    assert_eq!(wallet.voucher_store.vouchers.len(), 1);

    wallet
        .save(
            &mut storage,
            &identity,
            &AuthMethod::Password(initial_password),
        )
        .expect("Initial save failed");

    // 2. Recovery with the mnemonic phrase (identity).
    // Create an identity for reference (borrow) and a second for value passing (move).
    let (recovered_wallet, recovered_identity) =
        Wallet::load(&storage, &AuthMethod::RecoveryIdentity(identity), "test-id".to_string())
            .expect("Recovery with correct identity should succeed");

    // Verify that the recovered data (including voucher) is correct.
    assert_eq!(wallet.profile.user_id, recovered_wallet.profile.user_id);
    assert_eq!(identity.user_id, recovered_identity.user_id);
    assert_eq!(
        recovered_wallet.voucher_store.vouchers.len(),
        1,
        "Voucher should be present after recovery"
    );
    assert!(
        recovered_wallet
            .voucher_store
            .vouchers
            .contains_key(&local_id)
    );

    // 3. Reset password.
    let new_password = "my-new-strong-password-456";
    storage
        .reset_password(identity, new_password)
        .expect("Password reset should succeed");

    // 4. Verification after reset.
    // Login with old password must fail.
    let result = Wallet::load(&storage, &AuthMethod::Password(initial_password), "test-id".to_string());
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));

    // Login with new password must succeed and data must be intact.
    let (final_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(new_password), "test-id".to_string())
        .expect("Login with new password should succeed");

    assert_eq!(wallet.profile.user_id, final_wallet.profile.user_id);
    assert_eq!(
        final_wallet.voucher_store.vouchers.len(),
        1,
        "Voucher should still be present after reset"
    );
    assert!(final_wallet.voucher_store.vouchers.contains_key(&local_id));

    // 5. Error case: Recovery with the wrong identity.
    let imposter_identity = &ACTORS.hacker;
    let result = Wallet::load(&storage, &AuthMethod::RecoveryIdentity(imposter_identity), "test-id".to_string());
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_load_with_missing_voucher_store() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .unwrap();

    // Delete the voucher file
    fs::remove_file(storage.user_storage_path.join("vouchers.enc")).unwrap();

    // Loading should still succeed and return an empty store
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password(password), "test-id".to_string())
        .expect("Loading with missing voucher store should succeed");

    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);
    assert!(
        loaded_wallet.voucher_store.vouchers.is_empty(),
        "Voucher store should be empty by default"
    );
}

#[test]
fn test_load_from_corrupted_profile_file() {
    let temp_dir = tempdir().unwrap();
    let password = "password123";
    let identity = &ACTORS.victim;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password(password))
        .unwrap();

    // Corrupt the profile file
    // Path must point to user subfolder
    let profile_path = storage.user_storage_path.join("profile.enc");
    let mut contents = fs::read(&profile_path).unwrap();
    contents.truncate(contents.len() / 2); // Cut off half
    fs::write(&profile_path, contents).unwrap();

    // Loading should fail with a deserialization or format error
    let result = Wallet::load(&storage, &AuthMethod::Password(password), "test-id".to_string());
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(StorageError::InvalidFormat(_)))
    ));
}

#[test]
fn test_empty_password_handling() {
    let temp_dir = tempdir().unwrap();
    let empty_password = "";
    let identity = &ACTORS.test_user;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let mut wallet = setup_in_memory_wallet(identity);

    // SECURITY (AUDIT-W4-STO-003, parity with HMSEC-SA05-10): saving a wallet
    // under an EMPTY password is rejected in core - Argon2id("") is
    // deterministic and offline-reconstructable from profile.enc alone.
    wallet
        .save(
            &mut storage,
            &identity,
            &AuthMethod::Password(empty_password),
        )
        .expect_err("Saving with an empty password must be rejected");

    // No container may have been persisted by the rejected save.
    assert!(
        !storage.user_storage_path.join("profile.enc").exists(),
        "rejected initial save must not leave a profile.enc behind"
    );

    // Resetting an existing wallet's password to empty must be rejected too.
    wallet
        .save(&mut storage, &identity, &AuthMethod::Password("a-real-password"))
        .expect("Saving with a real password should succeed");
    storage
        .reset_password(&identity, empty_password)
        .expect_err("Resetting the password to empty must be rejected");

    // Loading with the still-valid password keeps working.
    let (loaded_wallet, _) = Wallet::load(&storage, &AuthMethod::Password("a-real-password"), "test-id".to_string())
        .expect("Loading with the valid password should succeed");
    assert_eq!(wallet.profile.user_id, loaded_wallet.profile.user_id);

    // Loading with a wrong, different password should fail
    let result = Wallet::load(&storage, &AuthMethod::Password("another-password"), "test-id".to_string());
    assert!(matches!(
        result,
        Err(VoucherCoreError::Storage(
            StorageError::AuthenticationFailed
        ))
    ));
}

#[test]
fn test_save_and_load_with_bundle_history() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "strongpassword123";

    // Create sender (Alice) and recipient (Bob)
    let alice_identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &alice_identity.mnemonic,
            alice_identity.passphrase.unwrap_or(""),
            alice_identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(alice_identity);

    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    // Alice creates a voucher and adds it to her wallet
    let local_id = add_voucher_to_wallet(
        &mut alice_wallet,
        alice_identity,
        "100",
        freetaler_standard,
        true,
    )
    .unwrap();

    // 2. Action: Perform a transaction to generate bundle metadata.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "100".to_string(), // Send full amount
        }],
        notes: Some("Test transfer".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        freetaler_standard.immutable.identity.uuid.clone(),
        freetaler_standard.clone(),
    );

    let _ = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            None::<&dyn human_money_core::archive::VoucherArchive>,
        )
        .expect("Transfer failed");

    // Verify state before saving
    assert_eq!(alice_wallet.bundle_meta_store.history.len(), 1);
    let original_bundle_id = alice_wallet
        .bundle_meta_store
        .history
        .keys()
        .next()
        .unwrap()
        .clone();

    // 3. Save
    alice_wallet
        .save(
            &mut storage,
            &alice_identity,
            &AuthMethod::Password(password),
        )
        .expect("Failed to save wallet with history");

    // Verify that the new metadata file was created
    assert!(storage.user_storage_path.join("bundles.meta.enc").exists());

    // 4. Load and verify
    let (loaded_wallet, _) =
        Wallet::load(&storage, &AuthMethod::Password(password), "test-id".to_string()).expect("Failed to load wallet");

    // **The crucial check:** Was history loaded correctly?
    assert_eq!(
        loaded_wallet.bundle_meta_store.history.len(),
        1,
        "Bundle history should have been loaded from bundles.meta.enc"
    );
    assert!(
        loaded_wallet
            .bundle_meta_store
            .history
            .contains_key(&original_bundle_id)
    );
    assert_eq!(loaded_wallet.profile.user_id, alice_wallet.profile.user_id);
}

/// Helper struct to test saving serialized data.
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
struct AppSettings {
    theme: String,
    notifications_enabled: bool,
    user_level: u32,
}

#[test]
fn test_save_and_load_arbitrary_data() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "arbitrary-data-password";
    let identity = &ACTORS.alice;
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);
    let mut storage = FileStorage::new(user_storage_path);

    println!(
        "--> Test storage created in: {:?}",
        storage.user_storage_path
    );
    let mut wallet = setup_in_memory_wallet(identity);

    // IMPORTANT: Save the wallet first to initialize the key infrastructure
    // (master_key.enc, recovery_key.enc) for encryption.
    wallet
        .save(&mut storage, identity, &AuthMethod::Password(password))
        .expect("Initial wallet save failed");

    // 2. Create test data (simple and complex)
    let blob_name1 = "simple_blob";
    let simple_data = b"this is some raw byte data".to_vec();

    let blob_name2 = "app_settings";
    let complex_data = AppSettings {
        theme: "dark".to_string(),
        notifications_enabled: true,
        user_level: 5,
    };
    let complex_data_bytes = bincode::serialize(&complex_data).unwrap();

    // 3. Save the data
    println!("--> Saving blobs to storage...");
    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
            &simple_data,
        )
        .expect("Saving simple blob should succeed");

    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name2,
            &complex_data_bytes,
        )
        .expect("Saving complex blob should succeed");

    println!("--> Blobs saved successfully.");

    // Verify that the files were created WITHOUT the user-specific hash
    let expected_path1 = storage
        .user_storage_path
        .join(format!("generic_{}.enc", blob_name1));
    let expected_path2 = storage
        .user_storage_path
        .join(format!("generic_{}.enc", blob_name2));

    println!("--> Verifying existence of file: {:?}", expected_path1);
    assert!(
        expected_path1.exists(),
        "File for simple blob was not created at the expected path!"
    );
    println!("--> Verifying existence of file: {:?}", expected_path2);
    assert!(
        expected_path2.exists(),
        "File for complex blob was not created at the expected path!"
    );

    // 4. Load and verify
    let loaded_simple_data = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
        )
        .expect("Loading simple blob should succeed");
    assert_eq!(simple_data, loaded_simple_data);

    let loaded_complex_data_bytes = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name2,
        )
        .expect("Loading complex blob should succeed");
    let loaded_complex_data: AppSettings =
        bincode::deserialize(&loaded_complex_data_bytes).unwrap();
    assert_eq!(complex_data, loaded_complex_data);

    // 5. Error cases
    // Wrong password
    let res = storage.load_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password("wrong-pass"),
        blob_name1,
    );
    assert!(matches!(res, Err(StorageError::AuthenticationFailed)));

    // Non-existent data
    let res = storage.load_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password(password),
        "non-existent-blob",
    );
    assert!(matches!(res, Err(StorageError::NotFound)));

    // 6. Test overwriting
    let new_simple_data = b"this is updated data".to_vec();
    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
            &new_simple_data,
        )
        .expect("Overwriting blob should succeed");

    let reloaded_data = storage
        .load_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            blob_name1,
        )
        .expect("Loading overwritten blob should succeed");
    assert_eq!(new_simple_data, reloaded_data);
    assert_ne!(simple_data, reloaded_data);
}

/// Tests re-entrancy protection.
/// Scenario: A process (PID X) already holds a lock (simulated by manually creating the .lock file).
/// The same process attempts to write again via a second Storage instance.
/// Expectation: The lock mechanism detects that the PID in the file is its own and permits access.
#[test]
fn test_storage_reentrancy_same_process() {
    // 1. Setup
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let password = "reentrancy_check";
    let identity = &ACTORS.alice;

    // Path computation analogous to other tests
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &identity.mnemonic,
            identity.passphrase.unwrap_or(""),
            identity.prefix.unwrap_or("")
        );
        const SALT: &[u8] = b"human-money-profile-folder-v1";
        crypto_utils::derive_argon2_id(secret_string.as_bytes(), SALT).unwrap()
    };
    let user_storage_path = temp_dir.path().join(folder_name);

    // Instance 1: Initialize to create keys (so save_arbitrary_data doesn't fail on auth later)
    let mut storage1 = FileStorage::new(user_storage_path.clone());
    let mut wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage1, identity, &AuthMethod::Password(password))
        .expect("Initial setup save failed");

    // 2. SIMULATION: Manually inject a lock file with OUR current PID.
    // This simulates that we (or another thread in this process) hold the lock.
    let lock_path = user_storage_path.join(".wallet.lock");
    let current_pid = std::process::id();
    fs::write(&lock_path, current_pid.to_string()).expect("Failed to inject fake lock file");

    // 3. Instance 2: Access the same path
    let mut storage2 = FileStorage::new(user_storage_path);

    // 4. ACT: Attempt to save data.
    // This internally calls lock(). If the re-entrancy fix is missing, it would see the lock file,
    // read the PID, and throw LockFailed because it "thinks" it is blocked.
    let res = storage2.save_arbitrary_data(
        &identity.user_id,
        &AuthMethod::Password(password),
        "reentrancy_blob",
        b"data",
    );

    // 5. ASSERT
    assert!(
        res.is_ok(),
        "Re-entrancy check failed! Process locked itself out. Error: {:?}",
        res.err()
    );
}

// ============================================================================
// Extended Storage Tests
// Verifies edge-case behavior of FileStorage: Lock lifecycle, path correctness,
// profile existence checks, and persistence of fingerprint data structures.
// ============================================================================

use human_money_core::models::conflict::{
    FingerprintMetadata, KnownFingerprints, OwnFingerprints, TransactionFingerprint,
};
use std::collections::HashMap;

/// Creates a minimal `TransactionFingerprint` for testing.
fn dummy_fingerprint(key: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: key.to_string(),
        trap_r: "u_value".to_string(),
        trap_s: "blinded".to_string(),
        t_id: "tid".to_string(),
        encrypted_timestamp: 0,
        layer2_signature: "sig".to_string(),
        sender_ephemeral_pub: String::new(),
        deletable_at: "2099-01-01".to_string(),
        layer2_voucher_id: String::new(),
        privacy_guard_hash: String::new(),
    }
}

/// Helper function: Creates a fully initialized FileStorage with saved wallet.
fn setup_file_storage_with_wallet(
    user_storage_path: std::path::PathBuf,
    identity: &human_money_core::UserIdentity,
    password: &str,
) -> FileStorage {
    let mut storage = FileStorage::new(user_storage_path);
    let mut wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, identity, &AuthMethod::Password(password))
        .expect("Initial wallet save failed");
    storage
}

/// Verifies that the `.wallet.lock` file is deleted after a complete write operation
/// (lock → write → unlock).
///
/// A correctly implemented `unlock()` must remove the lock file;
/// if it remains, the unlock path is broken.
#[test]
fn test_lock_file_is_deleted_after_unlock() {
    let temp_dir = tempdir().expect("tempdir");
    let identity = &ACTORS.alice;
    let password = "lock-test-pw";
    let path = temp_dir.path().join("lock_test_wallet");

    let mut storage = setup_file_storage_with_wallet(path, identity, password);

    // Perform a write operation – this internally calls lock() and unlock().
    storage
        .save_arbitrary_data(
            &identity.user_id,
            &AuthMethod::Password(password),
            "lock_test",
            b"payload",
        )
        .expect("save_arbitrary_data should succeed");

    // After writing, the lock file MUST have been removed.
    assert!(
        !storage.get_lock_file_path().exists(),
        ".wallet.lock must be deleted after unlock(), but still exists!"
    );
}

/// Verifies that `get_lock_file_path()` returns the correct, storage-specific path:
/// filename must be `.wallet.lock` and the parent directory must match the configured storage path.
#[test]
fn test_get_lock_file_path_is_correct() {
    let temp_dir = tempdir().expect("tempdir");
    let storage_path = temp_dir.path().join("lock_path_wallet");
    let storage = FileStorage::new(storage_path.clone());

    let lock_path = storage.get_lock_file_path();

    // The filename must be exactly ".wallet.lock".
    assert_eq!(
        lock_path.file_name().and_then(|n| n.to_str()),
        Some(".wallet.lock"),
        "Lock filename must be '.wallet.lock'"
    );

    // The parent directory must be the storage path.
    assert_eq!(
        lock_path.parent().expect("must have parent"),
        storage_path,
        "Lock file must reside in the correct wallet directory"
    );
}

/// Verifies that `profile_exists()` returns the correct boolean in all relevant states:
/// `false` before first save, `true` after,
/// and `false` again after the profile file is manually removed.
#[test]
fn test_profile_exists_returns_correct_booleans() {
    let temp_dir = tempdir().expect("tempdir");
    let identity = &ACTORS.alice;
    let password = "exists-test-pw";
    let path = temp_dir.path().join("exists_wallet");
    let mut storage = FileStorage::new(path.clone());

    // Before saving, no profile exists.
    assert!(
        !storage.profile_exists(),
        "profile_exists() must return false before the profile is saved"
    );

    // Save to create profile.
    let mut wallet = setup_in_memory_wallet(identity);
    wallet
        .save(&mut storage, identity, &AuthMethod::Password(password))
        .expect("save");

    // After saving, profile exists.
    assert!(
        storage.profile_exists(),
        "profile_exists() must return true after the profile has been saved"
    );

    // Manually delete -> false again.
    fs::remove_file(path.join("profile.enc")).expect("remove profile.enc");
    assert!(
        !storage.profile_exists(),
        "profile_exists() must return false after profile.enc was deleted"
    );
}

/// Verifies that `KnownFingerprints` are saved and loaded correctly.
/// After loading, all saved entries must be present completely and
/// with identical content.
#[test]
fn test_known_fingerprints_persist_and_load() {
    let temp_dir = tempdir().expect("tempdir");
    let identity = &ACTORS.alice;
    let password = "kfp-test-pw";
    let path = temp_dir.path().join("kfp_wallet");

    let mut storage = setup_file_storage_with_wallet(path, identity, password);
    let auth = AuthMethod::Password(password);

    // Create a KnownFingerprints store with a concrete entry.
    let mut store = KnownFingerprints::default();
    store
        .local_history
        .insert("voucher-abc".to_string(), vec![dummy_fingerprint("tag-1")]);

    // Save.
    storage
        .save_known_fingerprints(&identity.user_id, &auth, &store)
        .expect("save_known_fingerprints should succeed");

    // Load and verify.
    let loaded = storage
        .load_known_fingerprints(&identity.user_id, &auth)
        .expect("load_known_fingerprints should succeed");

    assert!(
        loaded.local_history.contains_key("voucher-abc"),
        "'voucher-abc' must be present in local_history after loading"
    );
    assert_eq!(
        loaded.local_history["voucher-abc"].len(),
        1,
        "There must be exactly 1 fingerprint in local_history['voucher-abc']"
    );
    assert_eq!(
        loaded.local_history["voucher-abc"][0].ds_tag,
        "tag-1",
        "The ds_tag of the loaded fingerprint must be 'tag-1'"
    );
}

/// Verifies that `OwnFingerprints` are saved and loaded correctly.
/// Analogous to `test_known_fingerprints_persist_and_load`, but for own
/// fingerprint history.
#[test]
fn test_own_fingerprints_persist_and_load() {
    let temp_dir = tempdir().expect("tempdir");
    let identity = &ACTORS.alice;
    let password = "ofp-test-pw";
    let path = temp_dir.path().join("ofp_wallet");

    let mut storage = setup_file_storage_with_wallet(path, identity, password);
    let auth = AuthMethod::Password(password);

    // Create an OwnFingerprints store with a concrete entry in history.
    let mut store = OwnFingerprints::default();
    store
        .history
        .insert("voucher-xyz".to_string(), vec![dummy_fingerprint("own-tag-1")]);

    // Save.
    storage
        .save_own_fingerprints(&identity.user_id, &auth, &store)
        .expect("save_own_fingerprints should succeed");

    // Load and verify.
    let loaded = storage
        .load_own_fingerprints(&identity.user_id, &auth)
        .expect("load_own_fingerprints should succeed");

    assert!(
        loaded.history.contains_key("voucher-xyz"),
        "'voucher-xyz' must be present in OwnFingerprints::history after loading"
    );
    assert_eq!(
        loaded.history["voucher-xyz"][0].ds_tag,
        "own-tag-1",
        "The ds_tag of the loaded fingerprint must be 'own-tag-1'"
    );
}

/// Verifies that `CanonicalMetadataStore` (a `HashMap<String, FingerprintMetadata>`)
/// is saved and loaded correctly, including all field values.
#[test]
fn test_fingerprint_metadata_persists_and_loads() {
    let temp_dir = tempdir().expect("tempdir");
    let identity = &ACTORS.alice;
    let password = "fpm-test-pw";
    let path = temp_dir.path().join("fpm_wallet");

    let mut storage = setup_file_storage_with_wallet(path, identity, password);
    let auth = AuthMethod::Password(password);

    // Create a CanonicalMetadataStore (= HashMap<String, FingerprintMetadata>) with content.
    let mut metadata_store: HashMap<String, FingerprintMetadata> = HashMap::new();
    let mut meta = FingerprintMetadata::default();
    meta.depth = 3;
    metadata_store.insert("ds_tag_sentinel".to_string(), meta);

    // Save.
    storage
        .save_fingerprint_metadata(&identity.user_id, &auth, &metadata_store)
        .expect("save_fingerprint_metadata should succeed");

    // Load and verify.
    let loaded = storage
        .load_fingerprint_metadata(&identity.user_id, &auth)
        .expect("load_fingerprint_metadata should succeed");

    assert!(
        loaded.contains_key("ds_tag_sentinel"),
        "'ds_tag_sentinel' must be present in CanonicalMetadataStore after loading"
    );
    assert_eq!(
        loaded["ds_tag_sentinel"].depth,
        3,
        "depth must have the saved value 3 after loading"
    );
}

#[test]
fn test_wallet_lock_guard_does_not_delete_persistent_lock() {
    use human_money_core::storage::{Storage, WalletLockGuard};
    use human_money_core::storage::file_storage::FileStorage;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let storage = FileStorage::new(dir.path());

    // 1. Simulate login: Acquire lock manually
    storage.lock().expect("Initial lock should succeed");
    assert!(
        storage.get_lock_file_path().exists(),
        "Lock file should exist after manual lock"
    );

    // 2. Simulate temporary data operation (e.g. save_encrypted_data)
    {
        let _guard = WalletLockGuard::new(&storage).expect("Guard creation should succeed via re-entrancy");
        assert!(
            storage.get_lock_file_path().exists(),
            "Lock file should exist inside guard scope"
        );
    } // HERE: The guard is dropped.

    // 3. REGRESSION CHECK: Lock file MUST still exist,
    // because the outer session is still active!
    // (This assert would fail before the bugfix)
    assert!(
        storage.get_lock_file_path().exists(),
        "REGRESSION BUG: WalletLockGuard deleted lock file on drop although lock already existed previously!"
    );

    // 4. Simulate logout
    storage.unlock().unwrap();
    assert!(!storage.get_lock_file_path().exists());
}
