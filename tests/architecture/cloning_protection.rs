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
    let id_b = service_b.get_user_id().unwrap();
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

    // 1. Create a "Legacy" wallet (simulated by empty instance_id in the seal)
    // We use AppService to create one first and then manipulate the seal.
    {
        let mut service = AppService::new(dir.path()).unwrap();
        service.create_profile(
            "Legacy Alice",
            &alice.mnemonic,
            alice.passphrase,
            alice.prefix,
            password,
            human_money_core::services::mnemonic::MnemonicLanguage::English,
            "".to_string(), // Empty ID = Legacy
        ).unwrap();
    }

    let mut service_new = AppService::new(dir.path()).unwrap();
    let folder_name = service_new.list_profiles().unwrap()[0].folder_name.clone();

    // 2. Login with new ID on legacy wallet should succeed (migration)
    service_new.login(&folder_name, password, false, instance_new.clone()).unwrap();
    
    // Check if the nonce was incremented (migration now uses update_seal)
    {
        use human_money_core::storage::Storage;
        let unlocked = service_new.get_unlocked_mut_for_test();
        let (_wallet, identity) = (unlocked.0, unlocked.1);
        let auth = human_money_core::storage::AuthMethod::Password(password);
        let storage = human_money_core::storage::file_storage::FileStorage::new(dir.path().join(&folder_name));
        let seal_record = storage.load_seal(&identity.user_id, &auth).unwrap().unwrap();
        
        // Initial seal in create_profile (Legacy) had nonce 1 (Initial 0 + update after profile creation).
        // Migration via update_seal should now have nonce 2.
        assert_eq!(seal_record.seal.payload.tx_nonce, 2, "Nonce should be 2 after migration (prev 1 + 1)");
    }
    
    service_new.logout();

    // 3. Now it is bound. Login with a different ID should fail.
    let login_fail = service_new.login(&folder_name, password, false, "wrong-device".to_string());
    assert!(login_fail.is_err());
    assert!(login_fail.unwrap_err().to_string().contains("Device Mismatch"));
}
