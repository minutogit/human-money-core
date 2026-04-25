#[cfg(test)]
mod tests {
    use human_money_core::app_service::AppService;
    use human_money_core::storage::{Storage, AuthMethod};
    use human_money_core::FileStorage;
    use human_money_core::test_utils::{self, ACTORS};
    use std::collections::HashMap;
    use tempfile::TempDir;

    const PASSWORD: &str = "test-password-123";

    #[test]
    fn test_fork_lock_prevents_state_changes() {
        let dir = TempDir::new().unwrap();
        
        let (mut app, _profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

        // Access the underlying storage to simulate a Fork detection manually via FileStorage
        {
            let mut storage = FileStorage::new(dir.path().join(&_profile.folder_name));
            let auth = AuthMethod::Password(PASSWORD);
            let seal_record = human_money_core::models::seal::LocalSealRecord {
                seal: human_money_core::models::seal::WalletSeal {
                    payload: human_money_core::models::seal::SealPayload {
                        version: 1,
                        user_id: ACTORS.alice.identity.user_id.clone(),
                        epoch: 0,
                        epoch_start_time: "dummy".to_string(),
                        tx_nonce: 0,
                        prev_seal_hash: "".to_string(),
                        state_hash: "dummy".to_string(),
                        timestamp: "dummy".to_string(),
                    },
                    signature: "dummy".to_string(),
                },
                sync_status: human_money_core::models::seal::SyncStatus::Synced,
                is_locked_due_to_fork: true,
            };
            
            storage.save_seal(&ACTORS.alice.identity.user_id, &auth, &seal_record).unwrap();
        }

        // Drop the old app service reference 
        drop(app);

        // Force reload state by logging in again
        app = AppService::new(dir.path()).unwrap();
        let _ = app.login(&ACTORS.alice.identity.user_id, PASSWORD, false);

        // Receive Bundle sollte blockiert sein
        let res = app.receive_bundle(b"fake data", &HashMap::new(), None, Some(PASSWORD), false);
        assert!(res.is_err(), "Receiving bundle should be blocked by fork lock");
        let err = res.unwrap_err();
        assert!(err.contains("lock") || err.contains("Lock") || err.contains("Fork") || err.contains("fork"));
    }

    #[test]
    fn test_zone_2_soft_rejection_and_override() {
        let dir = TempDir::new().unwrap();
        let (mut receiver_service, _profile) =
            test_utils::setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);

        // In a real test we would need a bundle with an old timestamp.
        // For now we just verify the API change compiles and we can pass the flag.
        let bundle_data = b"fake data";
        let standards = HashMap::new();

        // This call will fail to compile until we update the signature!
        let _ = receiver_service.receive_bundle(
            bundle_data,
            &standards,
            None,
            Some(PASSWORD),
            true, // force_accept_tolerance_bundle
        );
    }
}
