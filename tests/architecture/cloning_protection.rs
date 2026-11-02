use human_money_core::app_service::AppService;
use tempfile::tempdir;
use human_money_core::test_utils::ACTORS;

#[test]
fn test_wallet_cloning_protection_and_handover() {
    let dir = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let password = "correct-password-123";
    let instance_a = "device-a".to_string();
    let instance_b = "device-b".to_string();

    // 1. Create wallet on device A
    let mut service_a = AppService::new(dir.path()).unwrap();
    service_a.create_profile(
        "Alice",
        &alice.mnemonic,
        alice.passphrase,
        alice.prefix,
        password,
        human_money_core::services::mnemonic::MnemonicLanguage::English,
        instance_a.clone(),
    ).unwrap();

    let folder_name = service_a.list_profiles().unwrap()[0].folder_name.clone();

    // Login on device A succeeds
    service_a.login(&folder_name, password, false, instance_a.clone()).unwrap();
    service_a.logout();

    // 2. Simulate cloning: Login on device B using the same directory
    let mut service_b = AppService::new(dir.path()).unwrap();
    let login_result = service_b.login(&folder_name, password, false, instance_b.clone());
    
    assert!(login_result.is_err(), "Login on device B should fail due to device mismatch");
    assert!(login_result.unwrap_err().to_string().contains("Device Mismatch"), "Error message should mention device mismatch");

    // 3. Force handover to device B
    service_b.handover_to_this_device(&folder_name, password, instance_b.clone())
        .expect("Handover to device B should succeed");

    // Wallet on device B is now ready to use
    assert!(service_b.is_wallet_unlocked());
    let id_b = service_b.with_wallet(|w| w.get_user_id().to_string()).unwrap();
    assert_eq!(id_b, alice.user_id);

    // 4. Back to device A: Device A should now be locked (since epoch was incremented on B)
    let mut service_a_again = AppService::new(dir.path()).unwrap();
    let login_a_result = service_a_again.login(&folder_name, password, false, instance_a.clone());
    
    assert!(login_a_result.is_err(), "Login on device A should now fail because it's bound to B");
    assert!(login_a_result.unwrap_err().to_string().contains("Device Mismatch"), "Error message should mention device mismatch");
}

#[test]
fn test_legacy_wallet_migration() {
    let dir = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let password = "correct-password-123";
    let instance_new = "device-new".to_string();

    // 1. Create a wallet with empty instance_id in the seal (Legacy format)
    {
        let mut service = AppService::new(dir.path()).unwrap();
        service.create_profile(
            "Legacy Alice",
            &alice.mnemonic,
            alice.passphrase,
            alice.prefix,
            password,
            human_money_core::services::mnemonic::MnemonicLanguage::English,
            "".to_string(), // Empty ID
        ).unwrap();
    }

    let mut service_new = AppService::new(dir.path()).unwrap();
    let folder_name = service_new.list_profiles().unwrap()[0].folder_name.clone();

    // 2. Zero-Compat Fail-Closed: Wallets without instance_id must NOT be silently migrated;
    // they are strictly rejected with DeviceMismatch.
    let login_result = service_new.login(&folder_name, password, false, instance_new);
    assert!(login_result.is_err(), "Login on wallet with empty instance_id must fail closed");
    assert!(
        login_result.unwrap_err().to_string().contains("Device Mismatch"),
        "Error message should mention device mismatch"
    );
}
