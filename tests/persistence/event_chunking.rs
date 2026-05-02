use human_money_core::storage::{AuthMethod, Storage, file_storage::FileStorage};
use human_money_core::models::wallet_event::{WalletEvent, WalletEventType, EventBffData};
use tempfile::tempdir;
use chrono::{TimeZone, Utc};

#[test]
fn test_event_migration_and_chunking() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().to_path_buf();
    let mut storage = FileStorage::new(&storage_path);
    let auth = AuthMethod::Password("pass");
    let user_id = "test-user";

    // 1. Create a legacy events file manually
    // We need to simulate the old structure. FileStorage used to have EVENTS_FILE_NAME = "events.json.enc"
    // and it was a direct serialization of EventsStorageContainer.
    
    // We need a dummy wallet save first to establish the master key
    let mut profile = human_money_core::models::profile::UserProfile::default();
    profile.user_id = user_id.to_string();
    let store = human_money_core::models::profile::VoucherStore::default();
    let identity = human_money_core::models::profile::UserIdentity {
        signing_key: ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]),
        public_key: ed25519_dalek::SigningKey::from_bytes(&[0u8; 32]).verifying_key(),
        user_id: user_id.to_string(),
    };
    storage.save_wallet(&profile, &store, &identity, &auth).unwrap();

    let bff_data = EventBffData::default();
    
    // Event from January 2026
    let mut event_old = WalletEvent::new("l1".into(), "v1".into(), WalletEventType::VoucherCreated, bff_data.clone());
    event_old.timestamp = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();

    // Event from February 2026
    let mut event_new = WalletEvent::new("l2".into(), "v2".into(), WalletEventType::VoucherCreated, bff_data.clone());
    event_new.timestamp = Utc.with_ymd_and_hms(2026, 2, 20, 12, 0, 0).unwrap();

    let _legacy_events = vec![event_old.clone(), event_new.clone()];
    
    // Write legacy file manually (simulating old version)
    // We need to use the encryption logic from FileStorage or just use the old append_events implementation logic.
    // Since we just refactored it, we can't easily call the old one.
    // But we know how it worked: it encrypted the whole Vec<WalletEvent> and put it in EventsStorageContainer.
    
    // Actually, I can just use the NEW append_events once to create the legacy file IF I temporarily revert the change... 
    // No, better to just write it manually using the master key.
    
    // Wait, I can just use a trick:
    // 1. Revert to old append_events? No.
    // 2. Just use the fact that the migration code in the NEW append_events handles the legacy file.
    
    // Let's manually create the legacy file:
    {
        let _file_key = storage.derive_key_for_session("pass").unwrap(); // This gets the session key which is used to wrap the file key
        // Wait, FileStorage::get_master_key_from_auth is private.
        // But I can just call a save operation to see where it goes.
        
        // Actually, the easiest way to test migration is to write the legacy file using the SAME encryption logic.
        // I'll use a temporary hack in the code or just rely on the fact that I can't easily write it from outside.
        
        // Let's try to use the public API to create events, then RENAME the file to the legacy name.
    }

    // 1. Create events in the NEW system
    storage.append_events(user_id, &auth, &[event_old.clone(), event_new.clone()]).unwrap();
    
    // Verify they are in chunks
    assert!(storage_path.join("events/2026_01.json.enc").exists());
    assert!(storage_path.join("events/2026_02.json.enc").exists());

    // 2. Simulate Legacy: Move one back to root and delete the folder
    let legacy_path = storage_path.join("events.json.enc");
    std::fs::rename(storage_path.join("events/2026_01.json.enc"), &legacy_path).unwrap(); // This is NOT exactly the same as legacy because it only contains one month, but for the migration logic it's a Vec<WalletEvent> anyway.
    std::fs::remove_dir_all(storage_path.join("events")).unwrap();

    // 3. Trigger Migration via append_events
    let event_march = WalletEvent::new("l3".into(), "v3".into(), WalletEventType::VoucherCreated, bff_data.clone());
    let mut event_march = event_march;
    event_march.timestamp = Utc.with_ymd_and_hms(2026, 3, 10, 12, 0, 0).unwrap();
    
    storage.append_events(user_id, &auth, &[event_march.clone()]).unwrap();

    // 4. Verify migration
    assert!(!legacy_path.exists());
    assert!(storage_path.join("events/2026_01.json.enc").exists());
    assert!(storage_path.join("events/2026_03.json.enc").exists());

    // 5. Verify load_events pagination
    // Should return newest first: March, then January
    let all_events = storage.load_events(user_id, &auth, 0, 10).unwrap();
    assert_eq!(all_events.len(), 2);
    assert_eq!(all_events[0].event_id, event_march.event_id);
    assert_eq!(all_events[1].event_id, event_old.event_id);

    // Test offset
    let paged_events = storage.load_events(user_id, &auth, 1, 10).unwrap();
    assert_eq!(paged_events.len(), 1);
    assert_eq!(paged_events[0].event_id, event_old.event_id);
}
