// tests/wallet_api/endorsed_vouchers.rs
// cargo test --test wallet_api_tests endorsed
//!
//! Integrationstests für die Endorsed-Funktionalität (Dritt-Signaturen).
//! Überprüft, dass bezeugte Gutscheine korrekt archiviert werden und
//! nicht in die Balance-Berechnung oder Double-Spend-Erkennung eingehen.

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

    /// Hilfsfunktion zum Erstellen eines Services mit einem Gutschein.
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
                amount: "100.0000".to_string(),
                ..Default::default()
            },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        };
        let signed_standard =
            generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");

        let _voucher = service
            .create_new_voucher(&signed_standard, "de", voucher_data, Some(password))
            .expect("Voucher creation failed");

        (service, dir)
    }

    /// **Test 1: Balance-Test - Endorsed-Gutscheine beeinflussen nicht die Balance**
    ///
    /// Simuliert, dass User B für User A bürgt und prüft, dass das Guthaben
    /// von User B bei 0 bleibt.
    #[test]
    fn test_endorsed_voucher_does_not_affect_balance() {
        // User A erstellt einen Gutschein
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // Prüfe, dass Alice eine Balance hat
        let balance_a = service_a.get_total_balance_by_currency().unwrap();
        assert!(!balance_a.is_empty(), "Alice should have a balance");

        // User B erstellt ein Wallet (ohne Gutscheine)
        let dir_b = tempdir().unwrap();
        let (mut service_b, _) = test_utils::setup_service_with_profile(
            dir_b.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob sollte keine Balance haben
        let balance_b_before = service_b.get_total_balance_by_currency().unwrap();
        assert!(balance_b_before.is_empty(), "Bob should have no balance initially");

        // Bob holt den Gutschein direkt von Alice (simuliert den Empfang außerhalb des Signatur-Workflows)
        let voucher_details = service_a
            .get_voucher_details(&voucher_summary.local_instance_id)
            .unwrap();
        let voucher_to_sign = voucher_details.voucher;

        // Bob unterzeichnet den Gutschein (dies speichert ihn als Endorsed)
        // Hinweis: In der Praxis würde dies über den Signaturanfrage-Workflow erfolgen,
        // aber für diesen Test simulieren wir den direkten Aufruf.
        let _signature_bundle = service_b
            .create_detached_signature_response_bundle(
                &voucher_to_sign,
                "guarantor",
                true,
                ContainerConfig::TargetDid(ACTORS.alice.user_id.clone(), PrivacyMode::TrialDecryption),
                Some(PASSWORD),
            )
            .expect("Signature creation should succeed");

        // Prüfe, dass Bobs Balance immer noch 0 ist
        let balance_b_after = service_b.get_total_balance_by_currency().unwrap();
        assert!(
            balance_b_after.is_empty(),
            "Bob's balance should still be 0 after endorsing"
        );

        // Prüfe, dass der Gutschein in Bobs Wallet mit Status Endorsed gespeichert wurde
        let vouchers_b = service_b.get_voucher_summaries(None, None, None).unwrap();
        let endorsed_voucher = vouchers_b
            .iter()
            .find(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .expect("Bob should have an endorsed voucher");

        // Prüfe, dass der current_amount 0 ist
        assert_eq!(
            endorsed_voucher.current_amount, "0",
            "Endorsed voucher should show current_amount as 0"
        );

        // Prüfe, dass die Rolle korrekt gespeichert wurde
        if let VoucherStatus::Endorsed { role } = &endorsed_voucher.status {
            assert_eq!(role, "guarantor", "Role should be 'guarantor'");
        } else {
            panic!("Voucher should have Endorsed status");
        }
    }

    /// **Test 2: Double-Spend-Test - Endorsed-Gutscheine werden ignoriert**
    ///
    /// Prüft, dass die Ablage des bezeugten Gutscheins im Wallet des Bürgen
    /// nicht den eigenen Fingerprint-Speicher blockiert oder Fremd-Gutscheine
    /// als eigene Fingerprints ausliest.
    #[test]
    fn test_endorsed_voucher_ignored_in_fingerprint_scan() {
        // User A erstellt einen Gutschein
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // User B erstellt ein Wallet
        let dir_b = tempdir().unwrap();
        let (mut service_b, _) = test_utils::setup_service_with_profile(
            dir_b.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob unterzeichnet Alices Gutschein
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

        // Prüfe, dass keine Double-Spend-Konflikte gemeldet werden
        let conflicts = service_b.list_conflicts().unwrap();
        assert!(
            conflicts.is_empty(),
            "No conflicts should be reported for endorsed vouchers"
        );
    }

    /// **Test 3: Persistenz-Test - Endorsed-Gutschein überlebt Neustart**
    ///
    /// Prüft, ob nach einem Logout/Login der Endorsed-Gutschein im Wallet verbleibt.
    #[test]
    fn test_endorsed_voucher_persists_after_restart() {
        let dir = tempdir().unwrap();

        // User A erstellt einen Gutschein
        let (service_a, _dir_a) = setup_service_with_voucher(PASSWORD, &ACTORS.alice, "Alice");
        let voucher_summary = service_a
            .get_voucher_summaries(None, None, None)
            .unwrap()
            .pop()
            .expect("Alice should have a voucher");

        // User B erstellt ein Wallet
        let (mut service_b, profile_b) = test_utils::setup_service_with_profile(
            dir.path(),
            &ACTORS.bob,
            "Bob",
            PASSWORD,
        );

        // Bob holt den Gutschein direkt von Alice (simuliert den Empfang außerhalb des Signatur-Workflows)
        let voucher_details = service_a
            .get_voucher_details(&voucher_summary.local_instance_id)
            .unwrap();
        let voucher_to_sign = voucher_details.voucher;

        // Bob unterzeichnet Alices Gutschein
        let _signature_bundle = service_b
            .create_detached_signature_response_bundle(
                &voucher_to_sign,
                "guarantor",
                true,
                ContainerConfig::TargetDid(ACTORS.alice.user_id.clone(), PrivacyMode::TrialDecryption),
                Some(PASSWORD),
            )
            .expect("Signature creation should succeed");

        // Prüfe, dass der Endorsed-Gutschein vorhanden ist
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

        // Login erneut
        service_b
            .login(&profile_b.folder_name, PASSWORD, false, "test-id".to_string())
            .expect("Login should succeed");

        // Prüfe, dass der Endorsed-Gutschein immer noch vorhanden ist
        let vouchers_after = service_b.get_voucher_summaries(None, None, None).unwrap();
        let endorsed_count_after = vouchers_after
            .iter()
            .filter(|v| matches!(v.status, VoucherStatus::Endorsed { .. }))
            .count();
        assert_eq!(
            endorsed_count_after, 1,
            "Bob should still have exactly one endorsed voucher after restart"
        );

        // Prüfe, dass die Rolle korrekt erhalten blieb
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
