use human_money_core::app_service::AppService;
use human_money_core::services::voucher_manager::NewVoucherData;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_voucher_creation_emits_event() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path();
    let mut app = AppService::new(storage_path).expect("Failed to create AppService");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    app.create_profile("Test Wallet", mnemonic, None, Some("user"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string())
        .expect("Failed to create profile");

    // Load standard
    let standard_toml = include_str!("../voucher_standards/minuto_v1/standard.toml");
    
    let user_id = app.get_user_id().expect("User ID missing");

    let data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "100".to_string(),
            unit: "Minuto".to_string(),
            ..Default::default()
        },
        collateral: None,
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(user_id),
            first_name: Some("Alice".to_string()),
            last_name: Some("Test".to_string()),
            ..Default::default()
        },
    };

    let voucher = app.create_new_voucher(standard_toml, "en", data, Some("password123"))
        .expect("Failed to create voucher");

    // Check event history
    let events = app.get_event_history(0, 10, Some("password123"))
        .expect("Failed to get event history");

    assert!(!events.is_empty(), "Event history should not be empty");
    
    let creation_event = events.iter().find(|e| matches!(e.event_type, human_money_core::models::wallet_event::WalletEventType::VoucherCreated));
    assert!(creation_event.is_some(), "VoucherCreated event should be present");
    
    let event = creation_event.unwrap();
    assert_eq!(event.bff_data.amount, "100");
    // format_bff_name will add "TEST-" prefix
    assert_eq!(event.bff_data.display_currency, "TEST-Minuto");
    assert!(event.bff_data.is_test_voucher);
}

#[test]
fn test_status_transition_emits_event() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path();
    let mut app = AppService::new(storage_path).expect("Failed to create AppService");

    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    app.create_profile("Test Wallet", mnemonic, None, Some("user"), "password123", human_money_core::MnemonicLanguage::English, "device-id".to_string())
        .expect("Failed to create profile");

    // 1. Create a voucher (will be Incomplete due to missing signatures in Minuto standard)
    let standard_toml = include_str!("../voucher_standards/minuto_v1/standard.toml");
    let user_id = app.get_user_id().expect("User ID missing");
    let data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        nominal_value: human_money_core::models::voucher::ValueDefinition {
            amount: "50".to_string(),
            unit: "Minuto".to_string(),
            ..Default::default()
        },
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(user_id.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    let voucher = app.create_new_voucher(standard_toml, "en", data, Some("password123"))
        .expect("Failed to create voucher");

    let local_id = app.get_voucher_summaries(None, None, None).expect("Failed to get summaries")[0].local_instance_id.clone();

    // 2. Manually transition to Quarantined
    {
        let wallet = app.get_wallet_mut().unwrap();
        wallet.update_voucher_status(&local_id, human_money_core::wallet::instance::VoucherStatus::Quarantined { 
            reason: "Test Quarantine".to_string() 
        });
    }

    // Reset to Incomplete to test Activation
    {
        let wallet = app.get_wallet_mut().unwrap();
        wallet.update_voucher_status(&local_id, human_money_core::wallet::instance::VoucherStatus::Incomplete { 
            reasons: vec![] 
        });
    }

    // 3. Manually transition to Active (simulating all signatures added)
    {
        let wallet = app.get_wallet_mut().unwrap();
        wallet.update_voucher_status(&local_id, human_money_core::wallet::instance::VoucherStatus::Active);
    }

    // 4. Check event history
    let events = app.get_event_history(0, 50, Some("password123"))
        .expect("Failed to get event history");

    let quarantined_event = events.iter().find(|e| matches!(e.event_type, human_money_core::models::wallet_event::WalletEventType::VoucherQuarantined));
    let activated_event = events.iter().find(|e| matches!(e.event_type, human_money_core::models::wallet_event::WalletEventType::VoucherActivated));

    assert!(quarantined_event.is_some(), "VoucherQuarantined event should be present");
    assert!(activated_event.is_some(), "VoucherActivated event should be present");
    
    assert_eq!(quarantined_event.unwrap().bff_data.amount, "50");
    assert_eq!(activated_event.unwrap().bff_data.amount, "50");
}
