// tests/wallet_api/lifecycle_and_data.rs
// cargo test --test wallet_api_tests
//!
//! Contains robustness tests for critical `AppService` functions
//! in the areas of lifecycle (creation, login, recovery) and
//! generic data encryption.

#[cfg(test)]
mod tests {

    use human_money_core::app_service::{AppService, ProfileInfo};
    use human_money_core::MnemonicLanguage;
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::test_utils;
    use human_money_core::test_utils::{ACTORS, generate_signed_standard_toml};
    use tempfile::tempdir;
    // ADDED: Imports for new test plan
    use human_money_core::wallet::MultiTransferRequest;
    use std::collections::HashMap;

    const PASSWORD: &str = "correct-password-123";
    const WRONG_PASSWORD: &str = "wrong-password-!@#";

    // --- Internal test helper functions ---

    /// Creates a dummy transfer request for testing.
    /// Requires a service that already has a voucher.
    fn create_dummy_transfer_request(service: &mut AppService) -> MultiTransferRequest {
        let summary = service
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Service has no vouchers to transfer");
        MultiTransferRequest {
            recipient_id: "did:key:z6MkhXrm1Rvwj3veuaDtiN2o22uVQdWKkXEkK84vEgJtB7Ti".to_string(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: summary.local_instance_id,
                amount_to_send: "1.0".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        }
    }

    /// Helper function that creates a service AND creates a voucher within it.
    /// Required for all tests that want to call `create_transfer_bundle`.
    /// Also returns TempDir to ensure it exists during the test.
    fn setup_service_with_voucher(
        password: &str,
    ) -> (AppService, ProfileInfo, String, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let (mut service, profile) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Voucher User",
            password,
        );

        let voucher_data = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(service.get_user_id().unwrap()),
                ..Default::default()
            },
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100.00".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");

        // NOTE: This call MUST use Some(password) (Mode A), as setup_service_with_profile
        // (and the anchor fix contained within) does NOT start a Mode B session.
        let _voucher = service
            .create_new_voucher(&signed_standard, voucher_data, Some(password))
            .expect("Voucher creation in setup_service_with_voucher failed");
        let local_id = service
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .unwrap()
            .local_instance_id;

        (service, profile, local_id, dir)
    }

    // --- Part 1: Guarding the Yellow Area (data_encryption.rs) ---

    /// **Test 1: test_data_encryption_workflow()** (Adapted for Mode B)
    ///
    /// Verifies the complete "Happy Path" of generic data storage
    /// in "remember password" mode (Mode B).
    #[test]
    fn test_data_encryption_workflow() {
        // 1. Create profile and unlock
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Data User",
            PASSWORD,
        );

        // 2. Save data (with Mode B)
        let data_name = "user_settings";
        let original_data = b"some secret application data".to_vec();
        service
            .save_encrypted_data(data_name, &original_data, Some(PASSWORD))
            .expect("Saving data should succeed");

        // 3. Load data (with Mode B)
        let loaded_data = service
            .load_encrypted_data(data_name, Some(PASSWORD))
            .expect("Loading data should succeed");

        // 4. Assert: Loaded data must match original data
        assert_eq!(original_data, loaded_data);
    }

    /// **Test 2: test_data_encryption_fails_when_locked()**
    ///
    /// Ensures that no access to sensitive data is possible in the `Locked` state.
    #[test]
    fn test_data_encryption_fails_when_locked() {
        let dir = tempdir().unwrap();
        // 1. Create profile (service is unlocked afterwards)
        let (mut service, _) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Lock User",
            PASSWORD,
        );
        // 2. Lock service
        service.logout();

        // 3. Attempt to save and load (with Mode A or B - both must fail)
        let save_result = service.save_encrypted_data("any_data", &[1, 2, 3], None);
        let load_result = service.load_encrypted_data("any_data", None);
        let save_result_pw = service.save_encrypted_data("any_data", &[1, 2, 3], Some(PASSWORD));
        let load_result_pw = service.load_encrypted_data("any_data", Some(PASSWORD));

        // 4. Assert: All calls must fail
        assert!(save_result.is_err());
        assert!(save_result.unwrap_err().to_string().contains("Wallet is locked"));
        assert!(load_result.is_err());
        assert!(load_result.unwrap_err().to_string().contains("Wallet is locked"));
        assert!(save_result_pw.is_err());
        assert!(save_result_pw.unwrap_err().to_string().contains("Wallet is locked"));
        assert!(load_result_pw.is_err());
        assert!(load_result_pw.unwrap_err().to_string().contains("Wallet is locked"));
    }

    /// **Test 3: test_data_encryption_fails_with_wrong_password()** (Adapted for Mode A)
    ///
    /// Verifies password checking for data storage in "always ask" mode (Mode A).
    #[test]
    fn test_data_encryption_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        // 1. Create profile
        let (mut service, _) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Wrong Pass User",
            PASSWORD,
        );

        let data_name = "user_settings";
        let original_data = b"some config".to_vec();
        // Save with Mode A (Some(PASSWORD))
        service
            .save_encrypted_data(data_name, &original_data, Some(PASSWORD))
            .expect("Saving data with correct password should work");

        // 2. Assert: Attempting to load with wrong password (Mode A) fails
        let load_err = service
            .load_encrypted_data(data_name, Some(WRONG_PASSWORD))
            .unwrap_err();
        assert!(load_err.to_string().contains("Authentication failed")); // Or "Password verification failed"

        // 3. Assert: Attempting to write with wrong password (Mode A) fails
        let save_err = service
            .save_encrypted_data("other_data", &[0], Some(WRONG_PASSWORD))
            .unwrap_err();
        assert!(save_err.to_string().contains("Authentication failed")); // Or "Password verification failed"
    }

    // --- Part 2: Guarding the Red Area (lifecycle.rs) ---

    /// **Test 4: test_create_profile_fails_with_invalid_mnemonic()**
    /// (Unchanged because `create_profile` does not use session logic)
    #[test]
    fn test_create_profile_fails_with_invalid_mnemonic() {
        let dir = tempdir().unwrap();
        let mut service = AppService::new(dir.path()).unwrap();
        let invalid_mnemonic = "this is not a valid bip39 phrase";
        let result = service.create_profile(
            "Invalid Mnemonic Profile",
            invalid_mnemonic,
            None,
            Some("test"),
            PASSWORD,
            MnemonicLanguage::English,
            "test-id".to_string(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mnemonic"));
        assert!(service.get_user_id().is_err());
    }

    /// **Test 4.2: Passphrase affects key derivation** (Plan C)
    #[test]
    fn test_passphrase_affects_keypair() {
        use human_money_core::Wallet;
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        let (_, id1) = Wallet::new_from_mnemonic(mnemonic, None, Some("test"), MnemonicLanguage::English, "test-id".to_string()).unwrap();
        let (_, id2) = Wallet::new_from_mnemonic(mnemonic, Some("secret-passphrase"), Some("test"), MnemonicLanguage::English, "test-id".to_string()).unwrap();
        
        assert_ne!(id1.user_id, id2.user_id, "Different passphrases must result in different UserIDs");
    }

    /// **Test 5: test_login_fails_with_wrong_password()**
    /// (Unchanged because `login` does not use session logic)
    #[test]
    fn test_login_fails_with_wrong_password() {
        let dir = tempdir().unwrap();
        let (mut service, profile_info) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.test_user,
            "Login Test",
            PASSWORD,
        );
        service.logout();
        let result = service.login(&profile_info.folder_name, WRONG_PASSWORD, false, "test-id".to_string());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Login failed (check password)")
        );
        assert!(
            service.get_user_id().is_err(),
            "Should not be able to get user ID while locked."
        );
    }

    /// **Test 6: test_recovery_preserves_wallet_data()** (Adapted for Mode B)
    ///
    /// Ensures that password recovery preserves existing wallet contents.
    #[test]
    fn test_recovery_preserves_wallet_data() {
        let dir = tempdir().unwrap();
        let test_user = &ACTORS.test_user;
        // 1. Create profile
        let (mut service, profile_info) = test_utils::setup_service_with_profile(
            dir.path(),
            test_user,
            "Recovery Test",
            PASSWORD,
        );

        // 2. Create a test voucher (requires Mode B)
        let user_id = service.get_user_id().unwrap();

        let voucher_data = NewVoucherData {
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100.00".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };

        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let created_voucher = service
            // FIX: Login (via setup_service_with_profile) does not start a session.
            // We MUST use Mode A (Some(PASSWORD)).
            .create_new_voucher(&signed_standard, voucher_data, Some(PASSWORD))
            .expect("Voucher creation should succeed");

        // 3. Check if the voucher is present
        let summaries_before = service.get_voucher_summaries(None, None, None).unwrap();
        assert_eq!(summaries_before.len(), 1);
        let local_id = summaries_before[0].local_instance_id.clone();

        // 4. Lock service
        service.logout();

        // 5. Recover wallet and set new password
        service
            .recover_wallet_and_set_new_password(
                &profile_info.folder_name,
                &test_user.mnemonic,
                test_user.passphrase,
                "new_password",
                MnemonicLanguage::English,
                "test-id".to_string(),
            )
            .expect("Recovery should succeed");

        // 6. Assert: Voucher must still be present after recovery
        let details_after = service.get_voucher_details(&local_id).unwrap();
        assert_eq!(details_after.local_instance_id, local_id);
        assert_eq!(details_after.voucher.voucher_id, created_voucher.voucher_id);

        // 7. Assert: Storage Integrity is Valid after recovery (prevents "ManipulatedItems" bug on next login)
        let integrity_report = service.check_integrity(Some("new_password")).expect("Integrity check should not error");
        assert_eq!(integrity_report, human_money_core::models::storage_integrity::IntegrityReport::Valid, "Integrity must be Valid after recovery");
    }

    /* * START: New test section (from Test Plan 5)
     * NOTE: Tests 1-3 are already covered above (test_data_encryption_...).
     * We add the new tests for session management here.
     */

    /// # 5. Tests for Session Management and Flexible Authentication
    ///
    /// These tests verify the "Secure password remembering" feature (Plan B),
    /// which covers both modes: "Always ask" (Mode A) and "Remember password" (Mode B).

    /// --- 5.1 Basic Session Management ---

    #[test]
    fn test_session_unlock_session_success() {
        let dir = tempdir().unwrap();
        let (mut service, _) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        // NOTE: setup_service_with_profile leaves the service in the Unlocked state.
        // This test checks whether unlock_session works with the correct PW in the Unlocked state.
        let result = service.unlock_session(PASSWORD, 60);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_unlock_session_fail() {
        let dir = tempdir().unwrap();
        let (mut service, _) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        let result = service.unlock_session(WRONG_PASSWORD, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }

    /// --- 5.2 Mode A: "Always ask" (Argument `Some(password)`) ---

    #[test]
    fn test_session_mode_a_action_succeeds_with_password_only() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // setup_service_with_voucher leaves the service in the Unlocked state,
        // but WITHOUT active session (since lock_session() was removed).
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result =
            service.create_transfer_bundle(request, &standard_definitions, None, Some(PASSWORD));
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_mode_a_action_fails_with_wrong_password() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(
            request,
            &standard_definitions,
            None,
            Some(WRONG_PASSWORD),
        );
        assert!(result.is_err());
        // Error comes from derive_key_for_session -> get_file_key -> AuthenticationFailed
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }

    /// --- 5.3 Mode B: "Remember password" (Argument `None` + Active Session) ---

    #[test]
    fn test_session_mode_b_action_fails_without_session() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Service is Unlocked, but Session is Locked (since setup_service_with_voucher removed lock_session())
        // The call with `None` must fail.
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Password required.")); // FIX: Error message is shorter.
    }

    #[test]
    fn test_session_mode_b_action_succeeds_with_session() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 60).unwrap();
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_mode_b_timeout() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 1).unwrap(); // 1 second timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Session timed out."));
    }

    #[test]
    fn test_session_mode_b_refresh_activity_sliding_window() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 3).unwrap(); // 3 seconds timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        service
            .refresh_session_activity()
            .expect("Refresh should succeed within timeout"); // Reset timer
        std::thread::sleep(std::time::Duration::from_secs(2)); // Total 4s elapsed
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(
            result.is_ok(),
            "Session should have been refreshed by refresh_session_activity"
        );
    }

    #[test]
    fn test_refresh_fails_on_expired_session() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);

        // 1. Start session with short timeout (1 second)
        service.unlock_session(PASSWORD, 1).unwrap();

        // 2. Wait until session has physically expired (2 seconds)
        std::thread::sleep(std::time::Duration::from_secs(2));

        // 3. Attempt to refresh expired session.
        // This must now fail because the core validates the timeout.
        let refresh_result = service.refresh_session_activity();
        assert!(
            refresh_result.is_err(),
            "Refresh must fail for expired sessions"
        );
        assert_eq!(refresh_result.unwrap_err().to_string(), "Session expired.");

        // 4. Verify that session is now also locked (cache cleared).
        // Access without password (Mode B) must fail.
        let load_result = service.load_encrypted_data("test_data", None);
        assert!(load_result.is_err());
        assert!(
            load_result.unwrap_err().to_string().contains("Password required"),
            "Session cache should have been cleared"
        );
    }

    #[test]
    fn test_logout_clears_active_session_immediately() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);

        // 1. Start session (activate Mode B)
        service.unlock_session(PASSWORD, 60).unwrap();

        // 2. Verify: Action without password succeeds
        service
            .save_encrypted_data("pre_logout", b"data", None)
            .expect("Session should work");

        // 3. Perform logout (hard reset)
        service.logout();

        // 4. Verify: Access must be completely denied (Wallet is locked),
        // not just "Password required". Status is now Locked, no longer Unlocked.
        let result = service.load_encrypted_data("pre_logout", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Wallet is locked"));
    }

    #[test]
    fn test_session_mode_b_action_refreshes_session() {
        let dir = tempdir().unwrap();
        let (mut service, _profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.test_user, "Test", PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 3).unwrap(); // 3 seconds timeout
        std::thread::sleep(std::time::Duration::from_secs(2));
        service.save_encrypted_data("test1", b"data", None).unwrap(); // Action resets timer
        std::thread::sleep(std::time::Duration::from_secs(2)); // Total 4s elapsed
        let result = service.load_encrypted_data("test1", None);
        assert!(
            result.is_ok(),
            "Session should have been refreshed by save_encrypted_data"
        );
    }

    #[test]
    fn test_session_mode_b_lock_session_works() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 60).unwrap();
        service.lock_session(); // Manually lock session
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(request, &standard_definitions, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Password required."));
    }

    /// --- 5.4 Edge Cases: Overriding the Session ---

    #[test]
    fn test_session_mode_a_overrides_mode_b_succeeds() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 60).unwrap(); // Mode B is active
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result =
            service.create_transfer_bundle(request, &standard_definitions, None, Some(PASSWORD));
        assert!(
            result.is_ok(),
            "Mode A (Some(pass)) should take precedence over Mode B (Session)."
        );
    }

    #[test]
    fn test_session_mode_a_wrong_password_fails_even_if_mode_b_is_active() {
        let (mut service, _profile, _local_id, _dir) = setup_service_with_voucher(PASSWORD);
        // Explicitly unlock session for this test
        service.unlock_session(PASSWORD, 60).unwrap(); // Mode B is active
        let request = create_dummy_transfer_request(&mut service);

        // Load the standard definition for a1b2c3d4-e5f6-4789-8012-3456789abcde
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
        let mut standard_definitions = HashMap::new();
        standard_definitions.insert("a1b2c3d4-e5f6-4789-8012-3456789abcde".to_string(), signed_standard);

        let result = service.create_transfer_bundle(
            request,
            &standard_definitions,
            None,
            Some(WRONG_PASSWORD),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Authentication failed"));
    }

    /* END: New test section */
}
