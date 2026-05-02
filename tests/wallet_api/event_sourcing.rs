use human_money_core::test_utils::{setup_in_memory_wallet, ACTORS, setup_service_with_profile, FREETALER_STANDARD};
use human_money_core::wallet::Wallet;
use human_money_core::storage::{AuthMethod, Storage, file_storage::FileStorage};
use human_money_core::models::wallet_event::{WalletEventType, WalletEvent, EventBffData};
use human_money_core::models::profile::UserIdentity;
use tempfile::tempdir;
use chrono::{Utc, Duration};

#[test]
fn test_event_generation_on_create() {
    let identity = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(identity);
    
    // Initial state: no events
    assert_eq!(wallet.pending_events.len(), 0);
    
    // Create a voucher
    let standard = &FREETALER_STANDARD.0;
    let standard_hash = &FREETALER_STANDARD.1;
    
    let _ = wallet.create_new_voucher(
        identity,
        standard,
        standard_hash,
        "en",
        human_money_core::services::voucher_manager::NewVoucherData {
            nominal_value: human_money_core::models::voucher::ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(identity.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        },
    ).unwrap();
    
    // Should have 1 event: VoucherCreated
    assert_eq!(wallet.pending_events.len(), 1);
    assert!(matches!(wallet.pending_events[0].event_type, WalletEventType::VoucherCreated));
}

#[test]
fn test_transactional_safety_and_rollback() {
    let dir = tempdir().unwrap();
    let identity = &ACTORS.alice;
    let (mut service, _profile) = setup_service_with_profile(dir.path(), identity, "test", "pass");
    
    let auth = AuthMethod::Password("pass");
    let (wallet, identity_ref): (&mut Wallet, &UserIdentity) = service.get_unlocked_mut_for_test();

    // 1. Manually add a pending event
    let bff_data = EventBffData {
        display_currency: "Min".to_string(),
        amount: "100".to_string(),
        is_test_voucher: false,
        counterparty_id: None,
        counterparty_name: None,
    };
    wallet.emit_event(WalletEventType::VoucherCreated, "test-id", "voucher-id", bff_data);
    assert_eq!(wallet.pending_events.len(), 1);

    // 2. Perform a save (which clears events on success)
    let profile_path = dir.path().join(&_profile.folder_name);
    let mut storage = FileStorage::new(profile_path);
    
    wallet.save(&mut storage, identity_ref, &auth).unwrap();
    assert_eq!(wallet.pending_events.len(), 0);
    
    // 3. Verify it's in storage
    let events = storage.load_events(&identity.user_id, &auth, 0, 10).unwrap();
    assert_eq!(events.len(), 1);
}

#[test]
fn test_persistence_flush_order() {
    let dir = tempdir().unwrap();
    let identity = &ACTORS.alice;
    let (mut service, _profile) = setup_service_with_profile(dir.path(), identity, "test", "pass");
    
    let auth = AuthMethod::Password("pass");
    let (wallet, identity_ref): (&mut Wallet, &UserIdentity) = service.get_unlocked_mut_for_test();

    let bff_data = EventBffData {
        display_currency: "Min".to_string(),
        amount: "100".to_string(),
        is_test_voucher: false,
        counterparty_id: None,
        counterparty_name: None,
    };
    wallet.emit_event(WalletEventType::VoucherCreated, "test-id", "voucher-id", bff_data);
    
    let profile_path = dir.path().join(&_profile.folder_name);
    let mut storage = FileStorage::new(profile_path);
    
    wallet.save(&mut storage, identity_ref, &auth).unwrap();
    
    // Reload and check
    let (reloaded_wallet, _) = Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();
    let events = storage.load_events(&identity.user_id, &auth, 0, 10).unwrap();
    
    assert_eq!(events.len(), 1);
    assert_eq!(reloaded_wallet.pending_events.len(), 0);
}

#[test]
fn test_expiration_sweep_on_load() {
    let dir = tempdir().unwrap();
    let identity = &ACTORS.alice;
    let (mut service, _profile) = setup_service_with_profile(dir.path(), identity, "test", "pass");
    
    let auth = AuthMethod::Password("pass");
    let (wallet, identity_ref): (&mut Wallet, &UserIdentity) = service.get_unlocked_mut_for_test();

    // 1. Create a voucher that is already expired
    let mut voucher = human_money_core::models::voucher::Voucher::default();
    voucher.valid_until = (Utc::now() - Duration::days(1)).to_rfc3339();
    voucher.nominal_value.amount = "100".to_string();
    voucher.nominal_value.unit = "Minuto".to_string();
    voucher.voucher_standard.uuid = "minuto-uuid".to_string();
    
    let local_id = "expired-1";
    wallet.voucher_store.vouchers.insert(local_id.to_string(), human_money_core::VoucherInstance {
        voucher,
        status: human_money_core::VoucherStatus::Active,
        local_instance_id: local_id.to_string(),
    });
    
    // 2. Save it
    let profile_path = dir.path().join(&_profile.folder_name);
    let mut storage = FileStorage::new(profile_path);
    wallet.save(&mut storage, identity_ref, &auth).unwrap();
    
    // 3. Load it - should trigger sweep
    let (loaded_wallet, _) = Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();
    
    // 4. Should have a pending event: VoucherExpired
    assert_eq!(loaded_wallet.pending_events.len(), 1);
    assert!(matches!(loaded_wallet.pending_events[0].event_type, WalletEventType::VoucherExpired));
    assert_eq!(loaded_wallet.voucher_store.vouchers[local_id].status, human_money_core::VoucherStatus::Expired);
}

#[test]
fn test_get_event_history_merging() {
    let identity = &ACTORS.alice;
    let wallet = setup_in_memory_wallet(identity);
    
    // Mock storage
    let dir = tempdir().unwrap();
    let mut storage = FileStorage::new(dir.path().to_path_buf());
    let auth = AuthMethod::Password("pass");
    
    // 1. Initialisieren des Storages (Wallet speichern)
    let mut wallet = wallet;
    wallet.save(&mut storage, identity, &auth).unwrap();

    // 2. Persisted event
    let bff_data1 = EventBffData {
        display_currency: "Min".to_string(),
        amount: "100".to_string(),
        is_test_voucher: false,
        counterparty_id: None,
        counterparty_name: None,
    };
    let event1 = WalletEvent::new(
        "local-id-1".to_string(),
        "voucher-id-1".to_string(),
        WalletEventType::VoucherCreated,
        bff_data1
    );
    storage.append_events(&identity.user_id, &auth, &[event1]).unwrap();
    
    // 2. Pending event (newer)
    let bff_data2 = EventBffData {
        display_currency: "Min".to_string(),
        amount: "50".to_string(),
        is_test_voucher: false,
        counterparty_id: None,
        counterparty_name: None,
    };
    let mut event2 = WalletEvent::new(
        "local-id-1".to_string(),
        "voucher-id-1".to_string(),
        WalletEventType::TransferSent,
        bff_data2
    );
    // Ensure it has a newer timestamp
    event2.timestamp = Utc::now() + Duration::seconds(10);
    
    let mut wallet = wallet;
    wallet.pending_events.push(event2);
    
    // 3. Query
    let history = wallet.get_event_history(&storage, &auth, 0, 10).unwrap();
    
    assert_eq!(history.len(), 2);
    // Newest first
    assert!(matches!(history[0].event_type, WalletEventType::TransferSent));
    assert!(matches!(history[1].event_type, WalletEventType::VoucherCreated));
}
