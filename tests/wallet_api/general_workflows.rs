// tests/wallet_api/general_workflows.rs
// cargo test --test wallet_api_tests
//!
//! Contains integration tests for the primary, non-signature-related
//! end-to-end workflows handled through the `AppService` and `Wallet` facades.

// Explicitly include the `test_utils` module via its file path.

use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD, FREETALER_STANDARD, add_voucher_to_wallet,
    create_voucher_for_manipulation, generate_signed_standard_toml, generate_valid_mnemonic,
    setup_in_memory_wallet, setup_service_with_profile,
};
use human_money_core::{
    VoucherCoreError, VoucherStatus, MnemonicLanguage,
    app_service::AppService,
    models::{
        profile::PublicProfile, voucher::ValueDefinition,
        voucher_standard_definition::VoucherStandardDefinition,
    },
    NewVoucherData,
    storage::AuthMethod,
    wallet::Wallet,
};
use rust_decimal::Decimal;
use std::str::FromStr;
use tempfile::tempdir;

// --- 1. AppService Workflows ---

/// Simulates the entire lifecycle of a user via `AppService`.
///
/// ### Scenario:
/// 1.  Two temporary directories for Alice and Bob are created.
/// 2.  Two `AppService` instances are initialized.
/// 3.  Alice and Bob create their profiles with mnemonic and password.
/// 4.  Alice logs out and logs in again to test authentication.
/// 5.  Alice creates a new voucher in her wallet.
/// 6.  Alice transfers the entire voucher to Bob.
/// 7.  Alice's old voucher state is verified as archived.
/// 8.  Bob receives the bundle and verifies his new balance.
/// Tests the complete voucher lifecycle via AppService.
#[test]
fn api_app_service_full_lifecycle() {
    // --- 1. Setup ---
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let dir_bob = tempdir().expect("Failed to create temp dir for Bob");
    let actor_alice = &ACTORS.alice;
    let actor_bob = &ACTORS.bob;
    let password = "password";

    // --- 2. Create profiles ---
    let (mut service_alice, profile_info_alice) =
        setup_service_with_profile(dir_alice.path(), actor_alice, "Alice", "password");
    let (mut service_bob, _) =
        setup_service_with_profile(dir_bob.path(), actor_bob, "Bob", "password");

    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    let id_bob = service_bob.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // --- 3. Logout and login for Alice ---
    service_alice.logout();
    assert!(
        service_alice.with_wallet(|w| w.get_user_id().to_string()).is_err(),
        "Service should be locked after logout"
    );
    service_alice
        .login(&profile_info_alice.folder_name, "password", false, "test-id".to_string())
        .expect("Login with correct password should succeed");
    assert_eq!(service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap(), id_alice);

    // --- 4. Alice creates a voucher ---
    service_alice.unlock_session("password", 60).unwrap();
    service_alice
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("password"),
        )
        .expect("Voucher creation failed");
    let summaries_alice = service_alice
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    let local_id_alice = summaries_alice[0].local_instance_id.clone();

    // --- 5. Alice sends the voucher to Bob ---
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_bob.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id_alice.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_toml = std::collections::HashMap::new();
    standards_toml.insert(standard.immutable.identity.uuid.clone(), freetaler_standard_toml.clone());
    service_alice.unlock_session("password", 60).unwrap();
    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: transfer_bundle,
        ..
    } = service_alice
        .create_transfer_bundle(request, &standards_toml, None, Some("password"))
        .expect("Transfer failed");
    let summary = service_alice
        .with_wallet(|w| w.get_voucher_details(&local_id_alice).unwrap())
        .expect("Fuzzy search should resolve the old ID to the archived voucher");
    assert_eq!(summary.status, VoucherStatus::Archived, "The voucher should be archived after a full transfer");

    // --- 6. Bob receives the voucher ---
    service_bob.unlock_session(password, 60).unwrap();
    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), freetaler_standard_toml);
    service_bob
        .receive_bundle(&transfer_bundle, &standards, None, Some("password"), false)
        .unwrap();
    let balance_bob = service_bob
        .with_wallet_and_identity(|w, id| w.get_total_balance_by_currency(Some(id)))
        .unwrap();
    // CORRECTION: The balance is now grouped by currency abbreviation, not by unit.
    let silver_abbreviation = "Taler"; // Corrected, static abbreviation for the FreeTaler standard.
    let bob_silver_balance = balance_bob
        .iter()
        .find(|b| b.unit == silver_abbreviation)
        .map(|b| b.total_amount.as_str())
        .expect("Bob should have a silver balance");
    assert_eq!(bob_silver_balance, "100.00");
}

/// Tests the `AppService` lifecycle when a BIP39 passphrase is used.
///
/// ### Scenario:
/// 1.  A profile is created with mnemonic AND passphrase.
/// 2.  The resulting user ID is saved.
/// 3.  A recovery attempt with ONLY the mnemonic (without passphrase) fails,
///     because derived keys do not match.
#[test]
fn api_app_service_lifecycle_with_passphrase() {
    // --- 1. Setup ---
    let actor_with_passphrase = &ACTORS.test_user; // This actor is configured with a passphrase.
    let dir = tempdir().expect("Failed to create temp dir");

    // --- 2. Create profile with passphrase and unlock service ---
    let (mut service, profile_info) =
        setup_service_with_profile(dir.path(), actor_with_passphrase, "Test User", "password");
    let original_user_id = service.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    assert!(original_user_id.starts_with(actor_with_passphrase.prefix.unwrap()));
    service.logout();

    // --- 3. Recovery without passphrase (must fail) ---
    let recovery_result = service.recover_wallet_and_set_new_password(
        &profile_info.folder_name,
        &actor_with_passphrase.mnemonic,
        None, // <- Missing passphrase
        "any-new-password",
        MnemonicLanguage::English,
        "test-id".to_string(),
    );

    assert!(
        recovery_result.is_err(),
        "Recovery with mnemonic only (when passphrase was used for creation) should fail."
    );
    assert!(
        recovery_result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("recovery failed")
    );

    assert!(
        service.with_wallet(|w| w.get_user_id().to_string()).is_err(),
        "Service should remain locked after failed recovery"
    );
}

/// Tests static mnemonic helper functions of `AppService`.
///
/// ### Scenario:
/// 1.  Generates a valid 12-word phrase and checks correctness.
/// 2.  Attempts to generate a phrase with invalid word count (should fail).
/// 3.  Validates a freshly generated phrase (should succeed).
/// 4.  Validates phrases with invalid words or bad checksums (should fail).
#[test]
fn api_app_service_mnemonic_helpers() {
    let mnemonic = AppService::generate_mnemonic(12, MnemonicLanguage::English).unwrap();
    assert_eq!(
        mnemonic.split_whitespace().count(),
        12,
        "Mnemonic should have 12 words"
    );
    assert!(
        AppService::generate_mnemonic(11, MnemonicLanguage::English).is_err(),
        "Should fail with invalid word count"
    );
    assert!(
        AppService::validate_mnemonic(&mnemonic, MnemonicLanguage::English).is_ok(),
        "A freshly generated mnemonic should be valid"
    );
    let invalid_word_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon hello";
    assert!(
        AppService::validate_mnemonic(invalid_word_mnemonic, MnemonicLanguage::English).is_err(),
        "Should fail with an invalid word"
    );
    let bad_checksum_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(
        AppService::validate_mnemonic(bad_checksum_mnemonic, MnemonicLanguage::English).is_err(),
        "Should fail with a bad checksum"
    );
}

/// Tests the password recovery function of `AppService`.
///
/// ### Scenario:
/// 1.  A profile is created and immediately locked again.
/// 2.  A recovery attempt with a wrong mnemonic fails.
/// 3.  A recovery attempt with the correct mnemonic succeeds.
/// 4.  The wallet is unlocked after recovery.
/// 5.  After locking again, login with the old password fails,
///     while login with the new password works.
#[test]
fn api_app_service_password_recovery() {
    // --- 1. Setup ---
    let dir = tempdir().expect("Failed to create temp dir");
    let actor = &ACTORS.alice; // Alice has no passphrase.
    let initial_password = "password-123";
    let new_password = "password-ABC";

    // --- 2. Create profile and lock again ---
    let (mut service, profile_info) =
        setup_service_with_profile(dir.path(), actor, "Alice Recovery", initial_password);
    service.logout();

    // --- 3. Recovery with wrong mnemonic (must fail) ---
    let wrong_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // Bad checksum
    assert!(
        service
            .recover_wallet_and_set_new_password(
                &profile_info.folder_name,
                wrong_mnemonic,
                None,
                new_password,
                MnemonicLanguage::English,
                "test-id".to_string(),
            )
            .is_err()
    );
    assert!(
        service.with_wallet(|w| w.get_user_id().to_string()).is_err(),
        "Service should remain locked after failed recovery"
    );

    // --- 4. Recovery with correct mnemonic (must succeed) ---
    service
        .recover_wallet_and_set_new_password(
            &profile_info.folder_name,
            &actor.mnemonic,
            None,
            new_password,
            MnemonicLanguage::English,
            "test-id".to_string(),
        )
        .expect("Recovery with correct mnemonic should succeed");
    assert!(
        service.with_wallet(|w| w.get_user_id().to_string()).is_ok(),
        "Service should be unlocked after successful recovery"
    );

    service.logout();
    assert!(
        service
            .login(&profile_info.folder_name, initial_password, false, "test-id".to_string())
            .is_err(),
        "Login with old password should fail after recovery"
    );
    assert!(
        service
            .login(&profile_info.folder_name, new_password, false, "test-id".to_string())
            .is_ok(),
        "Login with new password should succeed after recovery"
    );
}

/// Tests password recovery explicitly for a wallet created with a passphrase.
///
/// ### Scenario:
/// 1.  A profile is created with mnemonic, passphrase, and password.
/// 2.  A recovery attempt with correct mnemonic but WITHOUT passphrase fails.
/// 3.  A recovery attempt with correct mnemonic AND correct passphrase succeeds.
/// 4.  Login with the newly set password works.
#[test]
fn api_app_service_password_recovery_with_passphrase() {
    let dir = tempdir().expect("Failed to create temp dir");
    let actor = &ACTORS.test_user; // This actor uses a passphrase.
    let initial_password = "password-123";
    let new_password = "password-ABC";

    // 1. Create profile with passphrase
    let (mut service, profile_info) =
        setup_service_with_profile(dir.path(), actor, "Passphrase User", initial_password);
    service.logout();

    // 2. Recovery WITHOUT passphrase (must fail)
    let recovery_fail = service.recover_wallet_and_set_new_password(
        &profile_info.folder_name,
        &actor.mnemonic,
        None,
        new_password,
        MnemonicLanguage::English,
        "test-id".to_string(),
    );
    assert!(
        recovery_fail.is_err(),
        "Recovery without the correct passphrase should fail"
    );

    // 3. Recovery WITH correct passphrase (must succeed)
    service
        .recover_wallet_and_set_new_password(
            &profile_info.folder_name,
            &actor.mnemonic,
            actor.passphrase,
            new_password,
            MnemonicLanguage::English,
            "test-id".to_string(),
        )
        .expect("Recovery with correct passphrase should succeed");

    // 4. Verification
    service.logout();
    // Re-login after recovery, false for cleanup
    let login_result = service.login(&profile_info.folder_name, new_password, false, "test-id".to_string());
    assert!(
        login_result.is_ok(),
        "Login with new password should succeed. Error: {:?}",
        login_result.err()
    );
}

// --- 2. Wallet Workflows ---

/// Tests basic wallet lifecycle: create, save, load.
///
/// ### Scenario:
/// 1.  A new wallet is created from a mnemonic phrase.
/// 2.  The wallet state is saved encrypted with a password.
/// 3.  The wallet is loaded from storage.
/// 4.  Verifies loaded user ID matches the original.
#[test]
fn api_wallet_lifecycle() {
    let dir = tempdir().unwrap();
    let test_user = &ACTORS.alice; // Use Alice as test person
    let (mut wallet_a, identity_a) =
        Wallet::new_from_mnemonic(&test_user.mnemonic, test_user.passphrase, test_user.prefix, MnemonicLanguage::English, "test-id".to_string())
            .expect("Wallet creation failed");
    let original_user_id = wallet_a.profile.user_id.clone();
    let folder_name = {
        let secret_string = format!(
            "{}{}{}",
            &test_user.mnemonic,
            test_user.passphrase.unwrap_or(""),
            test_user.prefix.unwrap_or("")
        );
        human_money_core::services::crypto::get_hash(secret_string.as_bytes())
    };
    let user_storage_path = dir.path().join(folder_name);
    let mut storage = human_money_core::storage::file_storage::FileStorage::new(user_storage_path);

    wallet_a
        .save(
            &mut storage,
            &identity_a,
            &AuthMethod::Password("password123"),
        )
        .expect("Saving wallet failed");

    let auth = AuthMethod::Password("password123");
    let (wallet_b, _) = Wallet::load(&storage, &auth, "test-id".to_string()).expect("Loading wallet failed");

    assert_eq!(
        wallet_b.profile.user_id, original_user_id,
        "Loaded user ID should match the original"
    );
}

/// Tests a full transfer of the entire voucher amount.
///
/// ### Scenario:
/// 1.  Alice has a voucher of 100m.
/// 2.  She creates a transfer of 100m to Bob.
/// 3.  Her original voucher is archived.
/// 4.  Bob receives the bundle and afterwards has an active voucher of 100m.
#[test]
fn api_wallet_transfer_full_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None)
        .unwrap();

    let summary = alice_wallet
        .list_vouchers(Some(&alice.identity), None, None, None)
        .into_iter()
        .find(|s| s.status == VoucherStatus::Archived)
        .unwrap();
    assert_eq!(summary.status, VoucherStatus::Archived);

    // CORRECTION: The map must contain the Minuto standard.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );
    bob_wallet
        .process_encrypted_transaction_bundle(
            &bob.identity,
            &bundle_bytes,
            None,
            &standards_for_bob,
        )
        .unwrap();

    let summary = bob_wallet.list_vouchers(Some(&bob.identity), None, None, None).pop().unwrap();
    assert_eq!(summary.current_amount, "100");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Tests a partial transfer where the remainder stays with the sender.
///
/// ### Scenario:
/// 1.  Alice has a voucher of 100m.
/// 2.  She sends 30m to Bob.
/// 3.  Her old voucher is archived and a new active voucher
///     of 70m is created for her.
/// 4.  Bob receives the bundle and afterwards has an active voucher of 30m.
#[test]
fn api_wallet_transfer_split_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "30".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None)
        .unwrap();

    let active_summary = alice_wallet
        .list_vouchers(Some(&alice.identity), None, None, None)
        .into_iter()
        .find(|s| s.status == VoucherStatus::Active)
        .unwrap();
    assert_eq!(active_summary.current_amount, "70");

    // CORRECTION: The map must contain the Minuto standard.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );
    bob_wallet
        .process_encrypted_transaction_bundle(
            &bob.identity,
            &bundle_bytes,
            None,
            &standards_for_bob,
        )
        .unwrap();
    let bob_summary = bob_wallet.list_vouchers(Some(&bob.identity), None, None, None).pop().unwrap();
    assert_eq!(bob_summary.current_amount, "30");
}

/// Ensures that transfers with invalid amounts fail.
///
/// ### Scenario:
/// 1.  A transfer with a negative amount is attempted and fails.
/// 2.  A transfer with decimal precision disallowed by the standard
///     is attempted and fails.
#[test]
fn api_wallet_transfer_invalid_amount() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let bob = &ACTORS.bob;

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "-50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let result_negative =
        alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None);
    assert!(matches!(result_negative, Err(VoucherCoreError::VoucherManagerGeneric(_)) | Err(VoucherCoreError::AmountPrecisionExceeded { .. })));

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "50.5".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let result_decimal =
        alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None);
    assert!(matches!(result_decimal, Err(VoucherCoreError::VoucherManagerGeneric(_)) | Err(VoucherCoreError::AmountPrecisionExceeded { .. })));
}

/// Ensures that transfers are only possible with `Active` vouchers.
///
/// ### Scenario:
/// 1.  A voucher is manually set to status `Quarantined`.
/// 2.  A transfer attempt with this voucher fails with a `VoucherNotActive`
///     error.
#[test]
fn api_wallet_transfer_inactive_voucher() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let bob = &ACTORS.bob;

    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    instance.status = VoucherStatus::Quarantined {
        reason: "test".to_string(),
    };

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let result =
        alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None);
    assert!(matches!(
        result,
        Err(VoucherCoreError::VoucherNotActive(
            VoucherStatus::Quarantined { .. }
        ))
    ));
}

/// Tests proactive double-spend prevention in `Wallet`.
///
/// ### Scenario:
/// 1.  Alice transfers a voucher to Bob. The `create_transfer` call
///     is successful and removes the old voucher state from active storage.
/// 2.  Alice attempts to send the same old voucher state a second time to Charlie.
/// 3.  The call fails with `VoucherNotFound` because the state was already
///     spent and archived. This is the built-in protection.
#[test]
fn api_wallet_proactive_double_spend_prevention() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let bob = &ACTORS.bob;

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    alice_wallet
        .execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None)
        .expect("First transfer should succeed");

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.charlie.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let result =
        alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None);
    assert!(matches!(result, Err(VoucherCoreError::VoucherNotFound(_))));
}

/// Tests creating a new voucher directly in the wallet.
///
/// ### Scenario:
/// 1.  A new wallet is created for an issuer (`issuer`).
/// 2.  The `get_user_id` method returns the correct ID.
/// 3.  A new voucher is created with `create_new_voucher`.
/// 4.  The voucher is then present in the wallet, with status `Active`
///     and the correct amount.
#[test]
fn api_wallet_create_voucher_and_get_id() {
    let issuer = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(&issuer.identity);
    assert_eq!(wallet.get_user_id(), issuer.identity.user_id);

    let new_voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(issuer.identity.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "500".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P4Y".to_string()),
        ..Default::default()
    };
    let (freetaler_standard, freetaler_standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    wallet
        .create_new_voucher(
            &issuer.identity,
            freetaler_standard,
            freetaler_standard_hash,
            new_voucher_data,
        )
        .unwrap();

    let summary = wallet
        .list_vouchers(Some(&issuer.identity), None, None, None)
        .pop()
        .expect("Wallet should contain one voucher");
    assert_eq!(summary.current_amount, "500.00");
    assert_eq!(summary.status, VoucherStatus::Active);
}

/// Tests correct balance calculation across multiple currencies.
///
/// ### Scenario:
/// 1.  A wallet is populated with multiple active vouchers for "Minuto" and "Taler"
///     as well as one non-active voucher.
/// 2.  The `get_total_balance_by_currency` method is called.
/// 3.  The result contains correct, aggregated balances for both currencies,
///     taking only active vouchers into account.
#[test]
fn api_wallet_query_total_balance() {
    let issuer = &ACTORS.issuer;
    let mut wallet = setup_in_memory_wallet(&issuer.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    let mut add_voucher =
        |amount: &str, status: VoucherStatus, standard: &VoucherStandardDefinition| {
            let new_voucher_data = NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(issuer.identity.user_id.clone()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: amount.to_string(),
                    ..Default::default()
                },
                validity_duration: Some("P4Y".to_string()),
                ..Default::default()
            };
            let mut standard_to_hash = standard.clone();
            standard_to_hash.signature = None;
            let correct_hash = human_money_core::services::crypto::get_hash(
                human_money_core::services::utils::to_canonical_json(&standard_to_hash).unwrap(),
            );
            let voucher = create_voucher_for_manipulation(
                new_voucher_data,
                standard,
                &correct_hash,
                &issuer.identity.signing_key);
            let local_id =
                Wallet::calculate_local_instance_id(&voucher, &issuer.identity.user_id).unwrap();
            wallet.add_voucher_instance(local_id, voucher, status);
        };

    add_voucher("100", VoucherStatus::Active, minuto_standard);
    add_voucher("50", VoucherStatus::Active, minuto_standard);
    add_voucher(
        "200",
        VoucherStatus::Quarantined {
            reason: "test".to_string(),
        },
        minuto_standard,
    ); // Ignored
    add_voucher("1.25", VoucherStatus::Active, freetaler_standard);
    add_voucher("0.75", VoucherStatus::Active, freetaler_standard);

    let balances = wallet.get_total_balance_by_currency(Some(&issuer.identity));

    assert_eq!(balances.len(), 2, "Two currencies should be present");
    // CORRECTION: Tests must use the correct currency abbreviations from standards.
    let minuto_abbreviation = "Minuto"; // Corrected, static abbreviation for the Minuto standard.
    let expected_minuto_balance = Decimal::from_str("150").unwrap();
    let actual_minuto_balance = Decimal::from_str(
        balances
            .iter()
            .find(|b| b.unit == minuto_abbreviation)
            .map(|b| b.total_amount.as_str())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual_minuto_balance, expected_minuto_balance);

    let silver_abbreviation = "Taler"; // Corrected, static abbreviation for the FreeTaler standard.
    let expected_silver_balance = Decimal::from_str("2.00").unwrap();
    let actual_silver_balance = Decimal::from_str(
        balances
            .iter()
            .find(|b| b.unit == silver_abbreviation)
            .map(|b| b.total_amount.as_str())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual_silver_balance, expected_silver_balance);
}

/// Ensures that the wallet rejects a bundle with an invalid voucher.
///
/// ### Scenario:
/// 1.  Alice creates a voucher violating a content rule of its standard.
/// 2.  She packages this invalid voucher into a bundle for Bob.
/// 3.  External logic (simulating the client) opens the bundle,
///     validates the voucher, and detects it is invalid.
/// 4.  Since validation fails, the voucher is **not** handed over
///     to Bob's wallet. Bob's wallet remains empty.
#[test]
fn api_wallet_rejects_invalid_bundle() {
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(&bob.identity);

    let toml_str = include_str!("../test_data/standards/standard_content_rules.toml");
    let mut standard: VoucherStandardDefinition = toml::from_str(toml_str).unwrap();
    standard.immutable.blueprint.unit = "EUR".to_string();
    standard.mutable.i18n.descriptions = std::collections::HashMap::from([("en".to_string(), "INV-123456".to_string())]);

    let voucher_data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(alice.identity.user_id.clone()),
            first_name: Some("Alice".to_string()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "50.00".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let standard_hash = human_money_core::services::crypto::get_hash(
        human_money_core::services::utils::to_canonical_json(&standard.immutable).unwrap(),
    );
    let mut voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        &standard,
        &standard_hash,
        &alice.identity.signing_key,
    )
    .unwrap();

    voucher.creator_profile.first_name = Some("123-bad-name".to_string()); // Violates regex
    
    // UPDATE VOUCHER HASH (prevents premature abort by InvalidVoucherHash check)
    let voucher_nonce = voucher.voucher_nonce.clone();
    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();
    voucher.voucher_id = human_money_core::services::crypto::get_hash(
        human_money_core::services::utils::to_canonical_json(&voucher_to_hash).unwrap()
    );
    if !voucher.transactions.is_empty() {
        let v_id_bytes = bs58::decode(&voucher.voucher_id).into_vec().unwrap();
        let v_nonce_bytes = bs58::decode(&voucher_nonce).into_vec().unwrap();
        voucher.transactions[0].prev_hash = human_money_core::services::crypto::get_hash_from_slices(&[&v_id_bytes, &v_nonce_bytes]);
        // Also update tx hash so it is valid
        let mut tx_to_hash = voucher.transactions[0].clone();
        tx_to_hash.t_id = "".to_string();
        tx_to_hash.sender_identity_signature = None;
        tx_to_hash.layer2_signature = None;
        voucher.transactions[0].t_id = human_money_core::services::crypto::get_hash(
            human_money_core::services::utils::to_canonical_json(&tx_to_hash).unwrap()
        );
    }

    human_money_core::set_signature_bypass(true);
    let (bundle_bytes, _header) = alice_wallet
        .create_and_encrypt_transaction_bundle(
            &alice.identity,
            vec![voucher.clone()],
            &bob.identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None, // sender_profile_name
        )
        .unwrap();

    let decrypted_bundle = human_money_core::services::bundle_processor::open_and_verify_bundle(
        &bob.identity,
        &bundle_bytes,
    )
    .unwrap();
    let received_voucher = decrypted_bundle.vouchers.first().unwrap();

    let validation_result =
        human_money_core::services::voucher_validation::validate_voucher_against_standard(
            received_voucher,
            &standard,
        );
    
    human_money_core::set_signature_bypass(false);

    assert!(
        validation_result.is_err(),
        "Validation of the manipulated voucher should fail"
    );

    assert!(
        bob_wallet.voucher_store.vouchers.is_empty(),
        "Bob's wallet should remain empty"
    );
}

/// Tests that get_voucher_details returns correct voucher details.
///
/// ### Scenario:
/// 1.  An AppService is created and a profile is added.
/// 2.  A voucher is created.
/// 3.  The local ID of the voucher is determined via get_voucher_summaries.
/// 4.  get_voucher_details is called to retrieve complete details.
/// 5.  Verifies returned details are correct:
///     - Status is 'Active'
///     - Voucher content matches expectations
///     - Nominal value is correct
///     - Transactions are present
#[test]
fn api_app_service_get_voucher_details_returns_correct_data() {
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let dir_alice = tempdir().expect("Failed to create temp dir for Alice");
    let _password = "password123";
    let mut service_alice =
        AppService::new(dir_alice.path()).expect("Failed to create service for Alice");
    let mnemonic = generate_valid_mnemonic();

    // 1. Create profile
    service_alice
        .create_profile("Alice Details", &mnemonic, None, Some("alice"), "password", MnemonicLanguage::English, "test-id".to_string())
        .expect("Alice profile creation failed");

    let id_alice = service_alice.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // 2. Alice creates a voucher
    service_alice.unlock_session("password", 60).unwrap();
    let created_voucher = service_alice
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                creator_profile: PublicProfile {
                    id: Some(id_alice.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("password"),
        )
        .expect("Voucher creation failed");

    // 3. Determine local ID of voucher
    let summaries_alice = service_alice
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(summaries_alice.len(), 1, "Should have one voucher");
    let local_id = &summaries_alice[0].local_instance_id;

    // 4. Retrieve voucher details
    let details = service_alice
        .with_wallet(|w| w.get_voucher_details(local_id).unwrap())
        .expect("Should be able to get voucher details");

    // 5. Verify details are correct
    assert_eq!(
        details.status,
        VoucherStatus::Active,
        "Voucher should be active"
    );
    assert_eq!(
        details.voucher.voucher_id, created_voucher.voucher_id,
        "Voucher ID should match"
    );
    assert_eq!(
        details.voucher.nominal_value.amount, "100",
        "Nominal value should match"
    );
    assert_eq!(
        details.voucher.creator_profile.id.as_ref().unwrap(),
        &id_alice,
        "Creator ID should match"
    );
    assert!(
        !details.voucher.transactions.is_empty(),
        "Voucher should have at least one transaction"
    );
    assert_eq!(
        details.voucher.transactions[0].t_type, "init",
        "First transaction should be init"
    );
}

/// Tests a multi-transfer where funds from multiple sources are bundled.
///
/// ### Scenario:
/// 1.  Alice has two vouchers (100m and 50m).
/// 2.  She sends 20m from the first and 30m from the second voucher in a single transaction to Bob.
/// 3.  Her old vouchers are archived and two new active vouchers
///     with remaining amounts (80m and 20m) are created for her.
/// 4.  Bob receives the bundle and afterwards has two new active vouchers (20m and 30m),
///     corresponding to a total balance of 50m.
#[test]
fn api_wallet_transfer_multi_source() {
    // 1. SETUP
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Add two vouchers to Alice's wallet
    let voucher_id_1 = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        true,
    )
    .unwrap();
    let voucher_id_2 = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "50",
        minuto_standard,
        true,
    )
    .unwrap();

    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    // 2. ACTION: Create a request sending 20 from the first and 30 from the second voucher.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![
            human_money_core::wallet::SourceTransfer {
                local_instance_id: voucher_id_1.clone(),
                amount_to_send: "20".to_string(),
            },
            human_money_core::wallet::SourceTransfer {
                local_instance_id: voucher_id_2.clone(),
                amount_to_send: "30".to_string(),
            },
        ],
        notes: Some("Payment from two sources".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );

    let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None)
        .unwrap();

    // 3. VERIFICATION (Alice)
    let alice_summaries = alice_wallet.list_vouchers(Some(&alice.identity), None, None, None);
    let mut remaining_amounts_alice: Vec<_> = alice_summaries
        .iter()
        .filter(|s| s.status == VoucherStatus::Active)
        .map(|s| Decimal::from_str(&s.current_amount).unwrap())
        .collect();
    remaining_amounts_alice.sort(); // Sort for deterministic comparison

    assert_eq!(
        remaining_amounts_alice.len(),
        2,
        "Alice should have two active remainder vouchers"
    );
    assert_eq!(
        remaining_amounts_alice,
        vec![Decimal::from(20), Decimal::from(80)]
    );

    // 4. VERIFICATION (Bob)
    // CORRECTION: The map must contain the Minuto standard.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        minuto_standard.immutable.identity.uuid.clone(),
        minuto_standard.clone(),
    );
    bob_wallet
        .process_encrypted_transaction_bundle(
            &bob.identity,
            &bundle_bytes,
            None,
            &standards_for_bob,
        )
        .unwrap();
    let balances = bob_wallet.get_total_balance_by_currency(Some(&bob.identity));
    let minuto_balance = balances.iter().find(|b| b.unit == "Minuto").unwrap();
    assert_eq!(
        minuto_balance.total_amount, "50",
        "Bob's total balance should be 50"
    );
    assert_eq!(
        bob_wallet.list_vouchers(Some(&bob.identity), None, None, None).len(),
        2,
        "Bob should have received two new vouchers"
    );
}

