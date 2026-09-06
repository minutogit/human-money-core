// tests/core_logic/security/double_spend.rs
// cargo test --test core_logic_tests

// NOTE: This `use` imports the module provided in `mod.rs`.

// ===================================================================================
// --- BEGIN: LOCAL DOUBLE SPEND DETECTION TESTS ---
// (Originally in `test_local_double_spend_detection.rs`)
// ===================================================================================

use human_money_core::archive::file_archive::FileVoucherArchive;
use human_money_core::storage::AuthMethod;
// NEW: Import AppService and Storage
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat};
use human_money_core::app_service::AppService; // CORRECTION: Incorrect import E0432
use std::collections::HashMap;
use std::path::Path;
// NOTE: This `use` was switched to `super::`.
use super::test_utils::{ACTORS, FREETALER_STANDARD, setup_in_memory_wallet};
use human_money_core::models::conflict::TransactionFingerprint;
use human_money_core::models::voucher::{Address, Collateral, ValueDefinition};
use human_money_core::services::voucher_manager::{self, NewVoucherData};
use human_money_core::wallet::Wallet;
use human_money_core::{UserIdentity, VoucherStatus, services::crypto_utils, MnemonicLanguage};

// ===================================================================================
// HELPER FUNCTIONS
// ===================================================================================

/// Creates a fresh, empty wallet for a predefined identity for a test.
/// Ensures test isolation via separate storage.
fn setup_test_wallet(identity: &UserIdentity, _name: &str, _storage_dir: &Path) -> Wallet {
    setup_in_memory_wallet(identity)
}

/// Creates an empty fingerprint for testing purposes.
fn new_dummy_fingerprint(t_id: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: "".to_string(),
        trap_r: "".to_string(),
        trap_s: "".to_string(),
        t_id: t_id.to_string(),
        encrypted_timestamp: 0,
        layer2_signature: "".to_string(),
        deletable_at: "2099-12-31T23:59:59.999999Z".to_string(),
        sender_ephemeral_pub: String::new(),
            layer2_voucher_id: String::new(),
            privacy_guard_hash: String::new(),
}
}

/// Creates empty `NewVoucherData` for testing purposes.
fn new_test_voucher_data(creator_id: String) -> NewVoucherData {
    NewVoucherData {
        validity_duration: Some("P5Y".to_string()),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            amount: "100".to_string(),
            unit: String::new(),
            abbreviation: Some(String::new()),
            description: Some(String::new()),
        },
        collateral: Some(Collateral::default()),
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator_id),
            first_name: Some(String::new()),
            last_name: Some(String::new()),
            address: Some(Address::default()),
            organization: Some(String::new()),
            community: Some(String::new()),
            phone: Some(String::new()),
            email: Some(String::new()),
            url: Some(String::new()),
            gender: Some(String::new()),
            coordinates: Some(String::new()),
            ..Default::default()
        },
    }
}

// ===================================================================================
// UNIT TESTS ("PRE-TESTS")
// ===================================================================================

#[test]
fn test_fingerprint_generation() {
    human_money_core::set_signature_bypass(true);
    let _temp_dir = tempfile::tempdir().unwrap();
    let identity = &ACTORS.test_user;
    let mut wallet = setup_in_memory_wallet(identity);

    // Create a voucher with 2 transactions (init + transfer)
    let voucher_data = new_test_voucher_data(identity.user_id.clone());
    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    // create_voucher expects &SigningKey, not the entire Identity.
    let voucher = voucher_manager::create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &identity.signing_key)
    .unwrap();
    let holder_key =
        human_money_core::test_utils::derive_holder_key(&voucher, &identity.signing_key);
    let (v, _secrets) = voucher_manager::create_transaction(
        &voucher,
        standard,
        &identity.user_id,
        &identity.signing_key, // Sender Permanent Key (ID)
        &holder_key,           // Sender Ephemeral Key (Anchor)
        &human_money_core::test_utils::ACTORS.bob.user_id,
        "50",
        None,
    )
    .unwrap();

    let instance = human_money_core::wallet::instance::VoucherInstance {
        voucher: v.clone(),
        status: VoucherStatus::Active,
        local_instance_id: Wallet::calculate_local_instance_id(&v, &identity.user_id).unwrap(),
    };
    wallet
        .voucher_store
        .vouchers
        .insert(instance.local_instance_id.clone(), instance);

    // Action
    wallet.scan_and_rebuild_fingerprints().unwrap();

    // Assertions
    assert_eq!(
        wallet
            .own_fingerprints
            .history
            .values()
            .map(|v| v.len())
            .sum::<usize>(),
        2,
        "Es sollten Fingerprints für 2 Transaktionen existieren."
    );

    let tx1 = &voucher.transactions[0];
    let ephem_key = tx1.sender_ephemeral_pub.as_deref().unwrap_or("");
    let expected_hash1 = {
        let prev_hash_bytes = bs58::decode(&tx1.prev_hash).into_vec().unwrap();
        let ephem_key_bytes = bs58::decode(ephem_key).into_vec().unwrap();
        crypto_utils::get_hash_from_slices(&[&prev_hash_bytes, &ephem_key_bytes])
    };
    assert!(
        wallet
            .own_fingerprints
            .history
            .contains_key(&expected_hash1),
        "Fingerprint für die init-Transaktion fehlt."
    );

    // Calculate the expected `valid_until` value rounded to end of month.
    let expected_rounded_valid_until = {
        let parsed_date = DateTime::parse_from_rfc3339(&voucher.valid_until).unwrap();
        let year = parsed_date.year();
        let month = parsed_date.month();
        let first_of_next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1).unwrap()
        };
        let last_day_of_month = first_of_next_month.pred_opt().unwrap();
        let end_of_month_dt = last_day_of_month
            .and_hms_micro_opt(23, 59, 59, 999999)
            .unwrap()
            .and_utc();
        end_of_month_dt.to_rfc3339_opts(SecondsFormat::Micros, true)
    };

    // V2 Protocol: 'init' fingerprints carry the RAW transaction-level
    // deletable_at because it is cryptographically bound into the
    // HMC_TX_AUTH_V2 layer2_signature. Init fingerprints never leave the
    // wallet via gossip (ingress/export exclusion), so the month-end
    // anonymization is intentionally applied to spend fingerprints only.
    assert_eq!(
        wallet
            .own_fingerprints
            .history
            .get(&expected_hash1)
            .unwrap()[0]
            .deletable_at,
        tx1.deletable_at.clone().unwrap(),
        "Init-Fingerprints muessen das rohe, signaturgebundene deletable_at tragen."
    );

    // The anonymization constant must still be computed correctly (used by
    // spend fingerprints): sanity-check the rounding helper output format.
    assert!(expected_rounded_valid_until.ends_with("23:59:59.999999Z"));
}

#[test]
fn test_fingerprint_exchange() {
    human_money_core::set_signature_bypass(true);
    let mut sender_wallet = setup_in_memory_wallet(&ACTORS.sender);
    let mut receiver_wallet = setup_in_memory_wallet(&ACTORS.recipient1);

    // Setup: Generate fingerprints in sender wallet.
    // V2: the signature binds the ds_tag, so it must be set BEFORE signing.
    let fp1 = human_money_core::test_utils::make_signed_fingerprint("hash1", "t1", 0);
    sender_wallet
        .own_fingerprints
        .history
        .insert("hash1".to_string(), vec![fp1]);

    // Action
    let exported_data = sender_wallet.export_own_fingerprints().unwrap();
    let import_count1 = receiver_wallet
        .import_foreign_fingerprints(&exported_data)
        .unwrap();
    let import_count2 = receiver_wallet
        .import_foreign_fingerprints(&exported_data)
        .unwrap();

    // Assertions
    assert_eq!(
        import_count1, 1,
        "Der erste Import sollte einen neuen Fingerprint hinzufügen."
    );
    assert_eq!(
        import_count2, 0,
        "Der zweite Import sollte keinen neuen Fingerprint hinzufügen."
    );
    assert!(
        receiver_wallet.own_fingerprints.history.is_empty(),
        "Die eigenen Fingerprints des Empfängers sollten leer sein."
    );
    assert_eq!(
        receiver_wallet
            .known_fingerprints
            .foreign_fingerprints
            .len(),
        1,
        "Die fremden Fingerprints des Empfängers sollten einen Eintrag enthalten."
    );
}

#[test]
fn test_conflict_classification() {
    human_money_core::set_signature_bypass(true);
    let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

    let conflict_hash = "shared_hash".to_string();
    let fp1 = new_dummy_fingerprint("t_id_1");
    let fp2 = new_dummy_fingerprint("t_id_2");

    // Case A: Verifiable conflict
    // To classify a conflict as verifiable, the hash must be present in
    // `local_history`. This simulates that the user owns or owned the voucher.
    wallet
        .known_fingerprints
        .local_history
        .insert(conflict_hash.clone(), vec![fp1.clone()]);
    wallet
        .known_fingerprints
        .foreign_fingerprints
        .insert(conflict_hash.clone(), vec![fp2.clone()]);

    let result_a = wallet.check_for_double_spend();
    assert_eq!(
        result_a.verifiable_conflicts.len(),
        1,
        "Fall A: Ein verifizierbarer Konflikt muss erkannt werden."
    );
    assert!(
        result_a.unverifiable_warnings.is_empty(),
        "Fall A: Es sollte keine unverifizierbaren Warnungen geben."
    );

    // Case B: Verifiable conflict exclusively via gossip (foreign_fingerprints)
    // Even if the user never directly owned the voucher, the fingerprints
    // received via gossip carry cryptographic data (u, blinded_id)
    // for DID key extraction. Therefore this case must also be considered verifiable.
    wallet.known_fingerprints.local_history.clear();
    wallet
        .known_fingerprints
        .foreign_fingerprints
        .insert(conflict_hash.clone(), vec![fp1.clone(), fp2.clone()]);

    let result_b = wallet.check_for_double_spend();
    assert_eq!(
        result_b.verifiable_conflicts.len(),
        1,
        "Fall B: Auch ein Gossip-only-Konflikt muss als verifizierbar erkannt werden."
    );
    assert!(
        result_b.unverifiable_warnings.is_empty(),
        "Fall B: Es sollte keine unverifizierbaren Warnungen geben."
    );

    // Case C: Unverifiable conflict
    // A conflict that only appears in own_fingerprints.history (without counterpart
    // in local_history or foreign_fingerprints) is not externally verifiable.
    wallet.known_fingerprints.local_history.clear();
    wallet.known_fingerprints.foreign_fingerprints.clear();
    wallet
        .own_fingerprints
        .history
        .insert(conflict_hash.clone(), vec![fp1, fp2]);

    let result_c = wallet.check_for_double_spend();
    assert_eq!(
        result_c.unverifiable_warnings.len(),
        1,
        "Fall C: Ein Konflikt nur in own_fingerprints.history ist eine unverifizierbare Warnung."
    );
    assert!(
        result_c.verifiable_conflicts.is_empty(),
        "Fall C: Es sollte keine verifizierbaren Konflikte geben."
    );
}

#[test]
fn test_cleanup_expired_fingerprints() {
    human_money_core::set_signature_bypass(true);
    let mut wallet = setup_in_memory_wallet(&ACTORS.test_user);

    let mut expired_fp_hist = new_dummy_fingerprint("t_hist_expired");
    expired_fp_hist.deletable_at = "2020-01-01T00:00:00Z".to_string();
    let valid_fp_hist = new_dummy_fingerprint("t_hist_valid");

    let mut expired_fp_foreign = new_dummy_fingerprint("t_foreign_expired");
    expired_fp_foreign.deletable_at = "2020-01-01T00:00:00Z".to_string();
    // V2: valid foreign fingerprints must be self-authenticating to survive cleanup.
    let valid_fp_foreign =
        human_money_core::test_utils::make_signed_fingerprint("foreign_valid", "t_foreign_valid", 0);

    // Add fingerprints to both stores
    wallet
        .own_fingerprints
        .history
        .insert("hist_expired".to_string(), vec![expired_fp_hist]);
    wallet
        .own_fingerprints
        .history
        .insert("hist_valid".to_string(), vec![valid_fp_hist]);
    wallet
        .known_fingerprints
        .foreign_fingerprints
        .insert("foreign_expired".to_string(), vec![expired_fp_foreign]);
    wallet
        .known_fingerprints
        .foreign_fingerprints
        .insert("foreign_valid".to_string(), vec![valid_fp_foreign]);

    // Action: Call central cleanup function with a 0-year period,
    // which should trigger immediate cleanup of all expired entries.
    wallet.run_storage_cleanup(None, 0).unwrap();

    // Assertions for volatile store (should be cleaned up)
    assert!(
        !wallet
            .known_fingerprints
            .foreign_fingerprints
            .contains_key("foreign_expired"),
        "Abgelaufener fremder Fingerprint sollte entfernt werden."
    );
    assert!(
        wallet
            .known_fingerprints
            .foreign_fingerprints
            .contains_key("foreign_valid"),
        "Gültiger fremder Fingerprint sollte erhalten bleiben."
    );

    // Assertions for history store (should now also be cleaned up)
    assert!(
        !wallet.own_fingerprints.history.contains_key("hist_expired"),
        "Abgelaufener History-Fingerprint sollte mit 0 Jahren Frist entfernt werden."
    );
    assert!(
        wallet.own_fingerprints.history.contains_key("hist_valid"),
        "Gültiger History-Fingerprint muss erhalten bleiben."
    );
}

// ===================================================================================
// PROACTIVE PREVENTION TEST
// ===================================================================================

#[test]
fn test_proactive_double_spend_prevention_and_self_healing_in_appservice() {
    human_money_core::set_signature_bypass(true);
    // ### Setup ###
    // Creates a sender and two potential recipients.
    let temp_dir = tempfile::tempdir().unwrap();
    let storage_path = temp_dir.path();

    let recipient1_identity = &ACTORS.recipient1;
    let recipient2_identity = &ACTORS.recipient2;

    // 1. Create and unlock AppService for sender
    let mut app_service = AppService::new(storage_path).unwrap();
    // CORRECTION: Use the correct path to sender mnemonic from test_utils.rs
    // CORRECTION (Panic-Fix): Pass the prefix defined in ACTORS ('Some("se")') to create_profile.
    app_service
        .create_profile(
            "sender",
            &ACTORS.sender.mnemonic,
            None,
            ACTORS.sender.prefix,
            "password123",
            MnemonicLanguage::English,
            "test-id".to_string(),
        )
        .unwrap();

    // CORRECTION (Panic-Fix): We need to retrieve the anonymous 'folder_name',
    // as 'login' expects it instead of 'profile_name'.
    let profile_info = app_service
        .list_profiles()
        .unwrap()
        .into_iter()
        .find(|p| p.profile_name == "sender")
        .expect("Konnte das 'sender'-Profil nach der Erstellung nicht finden");
    let sender_folder_name = profile_info.folder_name;

    let (standard, _standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    // CORRECTION: Load raw TOML string. The service expects TOML content, not the hash.
    let freetaler_toml_str = include_str!("../../../voucher_standards/freetaler_v1/standard.toml");

    let mut standards_map = HashMap::new();
    // CORRECTION: The map must contain UUID -> TOML content (for later transfer calls).
    standards_map.insert(standard.immutable.identity.uuid.clone(), freetaler_toml_str.to_string());

    // 2. Sender receives an initial voucher.
    let voucher_data = new_test_voucher_data(app_service.get_user_id().unwrap());
    let initial_voucher = app_service
        .create_new_voucher(
            freetaler_toml_str, // CORRECTION (Panic-Fix): Pass TOML content, not the hash
            voucher_data,
            Some("password123"),
        )
        .unwrap();

    // Remember the local ID of the voucher
    let initial_local_id = app_service.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let original_voucher_state_for_attack = initial_voucher.clone(); // Clone for later attack

    // ### Act 1: Legitimate Transaction ###
    // Sender sends voucher to recipient 1.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: recipient1_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: initial_local_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let transfer1_result =
        app_service.create_transfer_bundle(request, &standards_map, None, Some("password123"));
    assert!(
        transfer1_result.is_ok(),
        "Die erste Transaktion sollte erfolgreich sein."
    );

    // Status check: The voucher should now be 'Archived'
    let summary_after_send = app_service.get_voucher_summaries(None, None, None).unwrap();

    // CORRECTION: 'initial_local_id' no longer exists. Wallet logic
    // removed the old instance and created a NEW instance with a NEW local_id
    // and status 'Archived'.
    assert_eq!(
        summary_after_send.len(),
        1,
        "Es sollte genau eine Gutschein-Instanz (die archivierte) im Wallet geben."
    );

    let instance_status = &summary_after_send[0].status;
    assert!(
        matches!(instance_status, VoucherStatus::Archived),
        "Der Status des neuen Gutscheins sollte 'Archived' sein, war aber: {:?}",
        instance_status
    );

    // Ensure that the old ID is truly gone.
    let old_instance_exists = summary_after_send
        .iter()
        .any(|s| s.local_instance_id == initial_local_id);
    assert!(
        !old_instance_exists,
        "Die alte Gutschein-Instanz MUSS entfernt worden sein."
    );

    // ### Act 2: Manual Manipulation for a Fraud Attempt ###
    // We simulate the sender attempting to re-spend the same original voucher state.
    // We need to trick AppService by manually loading the wallet,
    // manipulating it, and reinitializing AppService (simulating a "restore").
    app_service.logout();

    // HERE IS THE FIX: We must initialize the `FileStorage` instance with the exact
    // path to the profile folder (which we know from Act 1),
    // not just with the base storage path.
    let profile_storage_path = storage_path.join(&sender_folder_name);
    let mut storage =
        human_money_core::storage::file_storage::FileStorage::new(&profile_storage_path);
    // CORRECTION: E0609 Use correct AuthMethod
    let auth = human_money_core::storage::AuthMethod::Password("password123");
    let (mut wallet, identity) = Wallet::load(&storage, &auth, "test-id".to_string()).unwrap();

    // HERE IS THE ATTACK: Add old spent voucher back as 'Active'.
    let user_id = identity.user_id.clone();
    let local_id_2 =
        Wallet::calculate_local_instance_id(&original_voucher_state_for_attack, &user_id).unwrap();
    wallet.add_voucher_instance(
        local_id_2,
        original_voucher_state_for_attack,
        VoucherStatus::Active,
    );
    wallet
        .save(
            &mut storage,
            &identity,
            &AuthMethod::Password("password123"),
        )
        .unwrap();

    // Reload AppService (simulates app restart after "restore")
    let mut app_service = AppService::new(storage_path).unwrap();
    // CORRECTION (Panic-Fix): Use 'sender_folder_name' instead of "sender".
    app_service
        .login(&sender_folder_name, "password123", false, "test-id".to_string())
        .unwrap();
    assert_eq!(
        app_service
            .get_voucher_summaries(None, Some(&[VoucherStatus::Active]), None)
            .unwrap()
            .len(),
        1,
        "Wallet sollte jetzt einen inkonsistenten 'Active' Gutschein haben."
    );

    // ### Act 3: Blocked Double-Spend Attempt ###
    // Sender attempts to send the restored original voucher to recipient 2.
    // This MUST fail AND trigger self-healing.
    let request_2 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: recipient2_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: initial_local_id.clone(), // KORREKTUR: E0063
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    // CORRECTION: E0425 Replace old sender_wallet logic
    let transfer2_result = app_service.create_transfer_bundle(
        request_2,
        &standards_map, // standards_map already exists from above
        None,
        Some("password123"),
    );

    assert!(
        transfer2_result.is_err(),
        "Die zweite Transaktion von demselben Zustand aus muss fehlschlagen."
    );
    assert!(
        transfer2_result
            .err()
            .unwrap()
            .to_string()
            .contains("Double spend attempt blocked")
    );

    // ### Act 4: Verification of Self-Healing ###
    // Verify whether AppService set the inconsistent voucher to 'Quarantined'.
    let summary_after_fail = app_service.get_voucher_summaries(None, None, None).unwrap();
    let instance = summary_after_fail
        .iter()
        .find(|s| s.local_instance_id.contains(&initial_local_id))
        .unwrap();

    assert!(
        matches!(instance.status, VoucherStatus::Quarantined { .. }),
        "Der inkonsistente Gutschein MUSS jetzt auf 'Quarantined' gesetzt sein (Self-Healing)."
    );
    println!(
        "Test erfolgreich: Inkonsistenz erkannt, Transfer blockiert UND Wallet-Zustand selbst geheilt."
    );
}

// ===================================================================================
// INTEGRATION TEST
// ===================================================================================

#[test]
fn test_local_double_spend_detection_lifecycle() {
    human_money_core::set_signature_bypass(true);
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_path = temp_dir.path();
    let archive = FileVoucherArchive::new_secure(storage_path.join("archive"), "audit-test-pw");

    // ### Act 1: Initialization & First Transfer ###
    println!("--- Akt 1: Alice erstellt einen Gutschein und sendet ihn an Bob ---");

    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;
    let mut alice_wallet = setup_test_wallet(alice_identity, "alice", storage_path);
    let mut bob_wallet = setup_test_wallet(bob_identity, "bob", storage_path);

    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    let voucher_data = new_test_voucher_data(alice_identity.user_id.clone());
    let initial_voucher = voucher_manager::create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &alice_identity.signing_key)
    .unwrap();
    let local_id =
        Wallet::calculate_local_instance_id(&initial_voucher, &alice_identity.user_id).unwrap();

    let instance = human_money_core::wallet::instance::VoucherInstance {
        voucher: initial_voucher.clone(),
        status: VoucherStatus::Active,
        local_instance_id: local_id.clone(),
    };
    alice_wallet
        .voucher_store
        .vouchers
        .insert(local_id, instance);

    // Alice uses the new, correct method to send the voucher to Bob.
    // We clone the ID to immediately end the immutable borrow on alice_wallet.
    let alice_initial_local_id = alice_wallet
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: alice_initial_local_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: bundle_to_bob,
        ..
    } = alice_wallet
        .execute_multi_transfer_and_bundle(alice_identity, &standards, request, Some(&archive))
        .unwrap();
    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_bob = std::collections::HashMap::new();
    standards_for_bob.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        FREETALER_STANDARD.0.clone(),
    );
    bob_wallet
        .process_encrypted_transaction_bundle(
            bob_identity,
            &bundle_to_bob,
            Some(&archive),
            &standards_for_bob,
        )
        .unwrap();

    assert_eq!(
        alice_wallet.voucher_store.vouchers.len(),
        1,
        "Alices Wallet muss den gesendeten Gutschein als 'Archived' behalten."
    );
    let instance_a = alice_wallet.voucher_store.vouchers.values().next().unwrap();
    assert!(
        matches!(instance_a.status, VoucherStatus::Archived),
        "Der Status von Alices Gutschein muss 'Archived' sein."
    );
    assert!(matches!(
        bob_wallet
            .voucher_store
            .vouchers
            .values()
            .next()
            .unwrap()
            .status,
        VoucherStatus::Active
    ));

    // ### Act 2: The Double Spend ###
    println!("--- Akt 2: Bob begeht einen Double Spend an Charlie und David ---");

    let charlie_identity = &ACTORS.charlie;
    let david_identity = &ACTORS.david;
    let mut charlie_wallet = setup_test_wallet(charlie_identity, "charlie", storage_path);
    let mut david_wallet = setup_test_wallet(david_identity, "david", storage_path);

    // Retrieve seed from Bob's wallet to authorize the double spend.
    // get_voucher_from_wallet returns only the voucher, we need the instance.
    let bob_instance = bob_wallet.voucher_store.vouchers.values().next().unwrap();
    let bob_ephemeral_key = bob_wallet
        .rederive_secret_seed(&bob_instance.voucher, bob_identity)
        .unwrap();

    let voucher_from_bob = bob_instance.voucher.clone(); // use instance.voucher instead of helper

    // Bob acts maliciously. He bypasses the protection mechanisms of his wallet (create_transfer would block this)
    // and manually creates two conflicting transactions from the same state.
    // Important: We insert a small delay to ensure that the timestamps
    // of the fraudulent transactions are deterministically distinguishable.
    let (voucher_for_charlie, _) = voucher_manager::create_transaction(
        &voucher_from_bob,
        standard,
        &bob_identity.user_id,
        &bob_identity.signing_key,
        &bob_ephemeral_key, // Bob's ephemeral key extracted from wallet
        &charlie_identity.user_id,
        "100",
        None,
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let (voucher_for_david, _) = voucher_manager::create_transaction(
        &voucher_from_bob,
        standard,
        &bob_identity.user_id,
        &bob_identity.signing_key,
        &bob_ephemeral_key, // Reuse same key for double spend
        &david_identity.user_id,
        "100",
        None,
    )
    .unwrap();

    // We remember the IDs of the two conflicting transactions.
    let winning_tx_id = voucher_for_charlie
        .transactions
        .last()
        .unwrap()
        .t_id
        .clone();
    let losing_tx_id = voucher_for_david.transactions.last().unwrap().t_id.clone();

    // He bundles and sends the first fraudulent version to Charlie using the old method.
    let (bundle_to_charlie, _header) = bob_wallet
        .create_and_encrypt_transaction_bundle(
            bob_identity,
            vec![voucher_for_charlie.clone()],
            &charlie_identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None,
        )
        .unwrap();
    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_charlie = std::collections::HashMap::new();
    standards_for_charlie.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        FREETALER_STANDARD.0.clone(),
    );
    charlie_wallet
        .process_encrypted_transaction_bundle(
            charlie_identity,
            &bundle_to_charlie,
            Some(&archive),
            &standards_for_charlie,
        )
        .unwrap();

    // To enable the second fraud, he artificially resets the state of his wallet.
    let local_id_bob =
        Wallet::calculate_local_instance_id(&voucher_from_bob, &bob_identity.user_id).unwrap();
    bob_wallet.add_voucher_instance(local_id_bob, voucher_from_bob, VoucherStatus::Active);
    let (bundle_to_david, _header) = bob_wallet
        .create_and_encrypt_transaction_bundle(
            bob_identity,
            vec![voucher_for_david.clone()],
            &david_identity.user_id,
            None,
            Vec::new(),
            std::collections::HashMap::new(),
            None,
        )
        .unwrap();
    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_david = std::collections::HashMap::new();
    standards_for_david.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        FREETALER_STANDARD.0.clone(),
    );
    david_wallet
        .process_encrypted_transaction_bundle(
            david_identity,
            &bundle_to_david,
            Some(&archive),
            &standards_for_david,
        )
        .unwrap();

    assert_eq!(charlie_wallet.voucher_store.vouchers.len(), 1);
    assert_eq!(david_wallet.voucher_store.vouchers.len(), 1);

    // ### Act 3: The Return (Part 1) ###
    println!("--- Akt 3: Charlie sendet seine Version zurück an Alice ---");

    // Charlie acts legitimately and uses the correct `create_transfer` method.
    // We clone the ID to immediately end the immutable borrow on charlie_wallet.
    let charlie_local_id = charlie_wallet
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: alice_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: charlie_local_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: bundle_to_alice_1,
        ..
    } = charlie_wallet
        .execute_multi_transfer_and_bundle(charlie_identity, &standards, request, Some(&archive))
        .unwrap();

    println!("\n[Debug Test] Alices Wallet VOR dem Empfang von Charlie:");
    for (id, instance) in &alice_wallet.voucher_store.vouchers {
        println!(
            "  -> Vorhanden: ID={}, Status={:?}, Tx-Anzahl={}",
            id,
            instance.status,
            instance.voucher.transactions.len()
        );
    }
    println!("[Debug Test] Verarbeite jetzt Bündel von Charlie...");

    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_alice = std::collections::HashMap::new();
    standards_for_alice.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        FREETALER_STANDARD.0.clone(),
    );
    let result1 = alice_wallet
        .process_encrypted_transaction_bundle(
            alice_identity,
            &bundle_to_alice_1,
            Some(&archive),
            &standards_for_alice,
        )
        .unwrap();
    assert_eq!(
        alice_wallet.voucher_store.vouchers.len(),
        2,
        "Alice muss jetzt einen 'Archived' und einen 'Active' Gutschein haben."
    );
    assert!(
        result1.check_result.verifiable_conflicts.is_empty(),
        "Nach dem ersten zurückerhaltenen Gutschein darf es noch keinen Konflikt geben."
    );

    // ### Act 4: The Revelation ###
    println!(
        "--- Akt 4: David sendet seine widersprüchliche Version an Alice. Der Betrug wird aufgedeckt. ---"
    );

    // David also acts legitimately (from his perspective) and uses `create_transfer`.
    // We clone the ID to immediately end the immutable borrow on david_wallet.
    let david_local_id = david_wallet
        .voucher_store
        .vouchers
        .keys()
        .next()
        .unwrap()
        .clone();

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: alice_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: david_local_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult {
        bundle_bytes: bundle_to_alice_2,
        ..
    } = david_wallet
        .execute_multi_transfer_and_bundle(david_identity, &standards, request, Some(&archive))
        .unwrap();

    // CORRECTION: The map must contain the standard being processed.
    let mut standards_for_alice_2 = std::collections::HashMap::new();
    standards_for_alice_2.insert(
        FREETALER_STANDARD.0.immutable.identity.uuid.clone(),
        FREETALER_STANDARD.0.clone(),
    );
    let result2 = alice_wallet
        .process_encrypted_transaction_bundle(
            alice_identity,
            &bundle_to_alice_2,
            Some(&archive),
            &standards_for_alice_2,
        )
        .unwrap();

    // Assertions
    assert_eq!(
        result2.check_result.verifiable_conflicts.len(),
        1,
        "Ein verifizierbarer Konflikt MUSS erkannt worden sein."
    );
    assert_eq!(
        alice_wallet.voucher_store.vouchers.len(),
        3,
        "Alices Wallet sollte am Ende drei Instanzen des Gutscheins enthalten."
    );

    // ### Act 5: Verification of Intelligent Conflict Resolution ###
    println!("--- Akt 5: Überprüfe, ob die korrekte Gutschein-Instanz aktiv geblieben ist ---");

    let mut winner_status: Option<VoucherStatus> = None;
    let mut loser_status: Option<VoucherStatus> = None;
    let mut loser_local_id: Option<String> = None;

    // Find both competing voucher instances in Alice's wallet and check their status.
    // We must search the entire transaction chain, not just the last transaction.
    for (local_id, instance) in &alice_wallet.voucher_store.vouchers {
        // Check if the winning transaction is part of this voucher's history.
        if instance
            .voucher
            .transactions
            .iter()
            .any(|tx| tx.t_id == winning_tx_id)
        {
            winner_status = Some(instance.status.clone());
        }
        // Check if the losing transaction is part of this voucher's history.
        if instance
            .voucher
            .transactions
            .iter()
            .any(|tx| tx.t_id == losing_tx_id)
        {
            loser_status = Some(instance.status.clone());
            loser_local_id = Some(local_id.clone());
        }
    }

    assert_eq!(
        winner_status,
        Some(VoucherStatus::Active),
        "Die 'Gewinner'-Instanz (von Charlie, weil früher) muss aktiv bleiben."
    );
    assert!(
        matches!(loser_status, Some(VoucherStatus::Quarantined { .. })),
        "Die 'Verlierer'-Instanz (von David, weil später) muss unter Quarantäne gestellt werden. Got: {:?}",
        loser_status
    );

    // Attempting to spend the quarantined voucher (the 'loser' instance) must fail.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: loser_local_id.unwrap(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let transfer_attempt = alice_wallet.execute_multi_transfer_and_bundle(
        alice_identity,
        &standards,
        request,
        Some(&archive), // archive
    );
    assert!(
        transfer_attempt.is_err(),
        "Die Verwendung eines unter Quarantäne stehenden Gutscheins via create_transfer muss fehlschlagen."
    );

    println!(
        "Test erfolgreich: Double Spend wurde erkannt, und die 'Der Früheste gewinnt'-Regel wurde korrekt angewendet."
    );
}
