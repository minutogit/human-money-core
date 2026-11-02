use human_money_core::storage::{AuthMethod, file_storage::FileStorage};
use human_money_core::models::wallet_event::{WalletEvent, WalletEventType, EventBffData};
use tempfile::tempdir;
use chrono::{TimeZone, Utc};

#[test]
fn test_event_chunking() {
    let dir = tempdir().unwrap();
    let storage_path = dir.path().to_path_buf();
    let mut storage = FileStorage::new(&storage_path);
    let auth = AuthMethod::Password("pass");
    let user_id = "test-user";

    // Setup initial wallet to establish master key
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
    let mut event_mid = WalletEvent::new("l2".into(), "v2".into(), WalletEventType::VoucherCreated, bff_data.clone());
    event_mid.timestamp = Utc.with_ymd_and_hms(2026, 2, 20, 12, 0, 0).unwrap();

    // 1. Create events in the chunked system
    storage.append_events(&auth, &[event_old.clone(), event_mid.clone()]).unwrap();

    // Verify they are in chunks
    assert!(storage_path.join("events/2026_01.json.enc").exists());
    assert!(storage_path.join("events/2026_02.json.enc").exists());

    // 2. Append March event
    let mut event_new = WalletEvent::new("l3".into(), "v3".into(), WalletEventType::VoucherCreated, bff_data.clone());
    event_new.timestamp = Utc.with_ymd_and_hms(2026, 3, 10, 12, 0, 0).unwrap();

    storage.append_events(&auth, &[event_new.clone()]).unwrap();
    assert!(storage_path.join("events/2026_03.json.enc").exists());

    // 3. Verify load_events pagination (newest first: March, Feb, Jan)
    let all_events = storage.load_events(&auth, 0, 10).unwrap();
    assert_eq!(all_events.len(), 3);
    assert_eq!(all_events[0].event_id, event_new.event_id);
    assert_eq!(all_events[1].event_id, event_mid.event_id);
    assert_eq!(all_events[2].event_id, event_old.event_id);

    // Test offset
    let paged_events = storage.load_events(&auth, 1, 10).unwrap();
    assert_eq!(paged_events.len(), 2);
    assert_eq!(paged_events[0].event_id, event_mid.event_id);
    assert_eq!(paged_events[1].event_id, event_old.event_id);

    let single_paged = storage.load_events(&auth, 2, 1).unwrap();
    assert_eq!(single_paged.len(), 1);
    assert_eq!(single_paged[0].event_id, event_old.event_id);
}
