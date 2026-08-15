// tests/wallet_api/endorsed_vouchers.rs
// cargo test --test wallet_api_tests endorsed
//!
//! Integration tests for endorsed functionality (third-party signatures).
//! Verifies that witnessed vouchers are archived properly and
//! are not included in balance calculations or double-spend detection.

#[cfg(test)]
mod tests {
    use human_money_core::app_service::AppService;
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::test_utils;
    use human_money_core::test_utils::{ACTORS, generate_signed_standard_toml, TestUser};
    use human_money_core::models::secure_container::{ContainerConfig, PrivacyMode};
    use human_money_core::wallet::instance::VoucherStatus;
    use tempfile::tempdir;

    const PASSWORD: &str = "correct-password-123";

    /// Helper function to create a service with a voucher.
    fn setup_service_with_voucher(
        password: &str,
        actor: &TestUser,
        profile_name: &str,
    ) -> (AppService, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let (mut service, _) = test_utils::setup_service_with_profile(
            dir.path(),
            actor,
            profile_name,
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

        let _voucher = service
            .create_new_voucher(&signed_standard, voucher_data, Some(password))
            .expect("Voucher creation failed");

        (service, dir)
    }

    /// **Test 1: Balance test - Endorsed vouchers do not affect balance**
    ///
    /// Simulates User B guaranteeing for User A and verifies that User B's
    /// balance remains at 0.
    #[test]
    fn test_endorsed_voucher_does_not_affect_balance() {
        // User A creates a voucher
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // Verify that Alice has a balance
        let balance_a = service_a.get_total_balance_by_currency().unwrap();
        assert!(!balance_a.is_empty(), "Alice should have a balance");

        // User B creates a wallet (without vouchers)
        let dir_b = tempdir().unwrap();
        let (mut service_b, _) = test_utils::setup_service_with_profile(
            dir_b.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob should have no balance
        let balance_b_before = service_b.get_total_balance_by_currency().unwrap();
        assert!(balance_b_before.is_empty(), "Bob should have no balance initially");

        // Bob retrieves the voucher directly from Alice (simulating reception outside signature workflow)
        let voucher_details = service_a
            .get_voucher_details(&voucher_summary.local_instance_id)
            .unwrap();
        let voucher_to_sign = voucher_details.voucher;

        // Bob signs the voucher (this stores it as Endorsed)
        // Note: In practice, this would occur via the signing request workflow,
        // but for this test we simulate direct invocation.
        let _signature_bundle = service_b
            .create_detached_signature_response_bundle(
                &voucher_to_sign,
                "guarantor",
                true,
                ContainerConfig::TargetDid(ACTORS.alice.user_id.clone(), PrivacyMode::TrialDecryption),
                Some(PASSWORD),
            )
            .expect("Signature creation should succeed");

        // Verify that Bob's balance is still 0
        let balance_b_after = service_b.get_total_balance_by_currency().unwrap();
        assert!(
            balance_b_after.is_empty(),
            "Bob's balance should still be 0 after endorsing"
        );

        // Verify that the voucher was stored in Bob's wallet with Endorsed status
        let vouchers_b = service_b.get_voucher_summaries(None, None, None).unwrap();
        let endorsed_voucher = vouchers_b
            .iter()
            .find(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .expect("Bob should have an endorsed voucher");

        // Verify that current_amount is 0
        assert_eq!(
            endorsed_voucher.current_amount, "0",
            "Endorsed voucher should show current_amount as 0"
        );

        // Verify that the role was stored correctly
        if let VoucherStatus::Endorsed { role } = &endorsed_voucher.status {
            assert_eq!(role, "guarantor", "Role should be 'guarantor'");
        } else {
            panic!("Voucher should have Endorsed status");
        }
    }

    /// **Test 2: Double-spend test - Endorsed vouchers are ignored**
    ///
    /// Verifies that storing the witnessed voucher in the guarantor's wallet
    /// does not block their own fingerprint storage or read foreign vouchers
    /// as own fingerprints.
    #[test]
    fn test_endorsed_voucher_ignored_in_fingerprint_scan() {
        // User A creates a voucher
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // User B creates a wallet
        let dir_b = tempdir().unwrap();
        let (mut service_b, _) = test_utils::setup_service_with_profile(
            dir_b.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob signs Alice's voucher
        let voucher_details = service_a
            .get_voucher_details(&voucher_summary.local_instance_id)
            .unwrap();
        let voucher_to_sign = voucher_details.voucher;

        let _signature_bundle = service_b
            .create_detached_signature_response_bundle(
                &voucher_to_sign,
                "guarantor",
                true,
                ContainerConfig::TargetDid(ACTORS.alice.user_id.clone(), PrivacyMode::TrialDecryption),
                Some(PASSWORD),
            )
            .expect("Signature creation should succeed");

        // Verify that no double-spend conflicts are reported
        let conflicts = service_b.list_conflicts().unwrap();
        assert!(
            conflicts.is_empty(),
            "No conflicts should be reported for endorsed vouchers"
        );
    }

    /// **Test 3: Persistence test - Endorsed voucher survives restart**
    ///
    /// Verifies that the endorsed voucher remains in the wallet after logout/login.
    #[test]
    fn test_endorsed_voucher_persists_after_restart() {
        let dir = tempdir().unwrap();

        // User A creates a voucher
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // User B creates a wallet
        let (mut service_b, profile_b) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob retrieves the voucher directly from Alice (simulating reception outside signature workflow)
        let voucher_details = service_a
            .get_voucher_details(&voucher_summary.local_instance_id)
            .unwrap();
        let voucher_to_sign = voucher_details.voucher;

        // Bob signs Alice's voucher
        let _signature_bundle = service_b
            .create_detached_signature_response_bundle(
                &voucher_to_sign,
                "guarantor",
                true,
                ContainerConfig::TargetDid(ACTORS.alice.user_id.clone(), PrivacyMode::TrialDecryption),
                Some(PASSWORD),
            )
            .expect("Signature creation should succeed");

        // Verify that the endorsed voucher is present
        let vouchers_before = service_b.get_voucher_summaries(None, None, None).unwrap();
        let endorsed_count_before = vouchers_before
            .iter()
            .filter(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .count();
        assert_eq!(
            endorsed_count_before, 1,
            "Bob should have exactly one endorsed voucher before logout"
        );

        // Logout
        service_b.logout();

        // Login again
        service_b
            .login(&profile_b.folder_name, PASSWORD, false, "test-id".to_string())
            .expect("Login should succeed");

        // Verify that the endorsed voucher is still present
        let vouchers_after = service_b.get_voucher_summaries(None, None, None).unwrap();
        let endorsed_count_after = vouchers_after
            .iter()
            .filter(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .count();
        assert_eq!(
            endorsed_count_after, 1,
            "Bob should still have exactly one endorsed voucher after restart"
        );

        // Verify that the role was preserved correctly
        let endorsed_voucher = vouchers_after
            .iter()
            .find(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .expect("Endorsed voucher should still exist");

        if let VoucherStatus::Endorsed { role } = &endorsed_voucher.status {
            assert_eq!(role, "guarantor", "Role should persist as 'guarantor'");
        } else {
            panic!("Voucher should have Endorsed status");
        }
    }
}
