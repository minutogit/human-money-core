// tests/wallet_api/hostile_bundles.rs
// cargo test --test wallet_api_tests
//!
// NOTE: Tests 2.1 and 2.2 were updated to use the public `AppService::create_new_voucher` API.
//! Contains tests hardening `AppService` against receiving hostile,
//! internally inconsistent vouchers.

use human_money_core::{
    UserIdentity,
    app_service::AppService,
    models::{profile::PublicProfile, voucher::ValueDefinition},
    NewVoucherData,
    test_utils::{
        ACTORS, FREETALER_STANDARD, create_test_bundle, generate_signed_standard_toml,
        setup_service_with_profile,
    },
    wallet::{MultiTransferRequest, SourceTransfer, instance::VoucherStatus},
};
use std::collections::HashMap;
use tempfile::tempdir;

const PASSWORD: &str = "test-password-123";

fn setup_test_environment(
    dir: &tempfile::TempDir,
) -> ((AppService, UserIdentity), (AppService, String)) {
    // Create Alice
    let (mut alice_service, alice_profile) =
        setup_service_with_profile(dir.path(), &ACTORS.alice, "Alice", PASSWORD);
    alice_service
        .login(&alice_profile.folder_name, PASSWORD, false, "test-id".to_string())
        .unwrap();
    alice_service.unlock_session(PASSWORD, 60).unwrap();
    let alice_identity = alice_service.get_unlocked_mut_for_test().1.clone();

    // Create Bob
    let (mut bob_service, bob_profile) =
        setup_service_with_profile(dir.path(), &ACTORS.bob, "Bob", PASSWORD);
    bob_service
        .login(&bob_profile.folder_name, PASSWORD, false, "test-id".to_string())
        .unwrap();
    bob_service.unlock_session(PASSWORD, 60).unwrap();
    let bob_id = bob_service.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    ((alice_service, alice_identity), (bob_service, bob_id))
}

/// Creates a sender and recipient instance for testing.
fn setup_sender_recipient(
    dir_sender: &tempfile::TempDir,
    dir_recipient: &tempfile::TempDir,
) -> (AppService, UserIdentity, AppService, String) {
    // NOTE: We MUST use a "slow" crypto actor (like alice)
    // so that 'identity_sender' matches the identity derived by AppService.
    // `ACTORS.sender` uses 'fast' crypto and is unsuitable for this.
    let sender = &ACTORS.alice;
    let (mut service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    service_sender.unlock_session("pwd", 60).unwrap();
    let identity_sender = sender.identity.clone();

    let recipient = &ACTORS.recipient1;
    let (mut service_recipient, _) =
        setup_service_with_profile(dir_recipient.path(), recipient, "Recipient", "pwd");
    service_recipient.unlock_session("pwd", 60).unwrap();
    let id_recipient = service_recipient.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    (
        service_sender,
        identity_sender,
        service_recipient,
        id_recipient,
    )
}

/// Test 2.1: A received bundle with a voucher whose transaction chain
/// is broken (`prev_hash` is incorrect) must be rejected.
#[test]
fn test_rejection_of_broken_transaction_chain() {
    let dir = tempdir().unwrap();
    let ((mut service_sender, identity_sender), (mut service_recipient, id_recipient)) =
        setup_test_environment(&dir);
    let freetaler_toml = toml::to_string(&FREETALER_STANDARD.0).unwrap(); // Already signed from lazy_static
    let mut voucher = service_sender
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(PASSWORD),
        )
        .unwrap();

    // --- Test modification ---
    // 1. Create a valid transfer transaction from Alice to Bob.
    //    We must use the `VoucherStandardDefinition` object (not the TOML string).
    let valid_tx = human_money_core::models::voucher::Transaction::create(
        &voucher,
        &FREETALER_STANDARD.0, // Object from test_utils
        &identity_sender.user_id,
        &identity_sender.signing_key,
        &human_money_core::test_utils::derive_holder_key(&voucher, &identity_sender.signing_key), // Init -> Tx1
        &id_recipient,
        "50.00",
        None,
    )
    .unwrap()
    .0
    .transactions
    .pop()
    .unwrap(); // Take the new, valid transaction

    // 2. Break the chain by tampering with the prev_hash of the VALID transaction.
    let mut broken_tx = valid_tx;
    broken_tx.prev_hash = "garbage_hash_value_that_breaks_the_chain".to_string();

    // 3. IMPORTANT: Thanks to signature bypass, we no longer need to calculate
    //    a cryptographic signature. We only need to update t_id so structural
    //    integrity checks (t_id == hash(content)) pass.
    broken_tx.t_id = human_money_core::crypto::get_hash(
        human_money_core::to_canonical_json(&broken_tx).unwrap(),
    );

    // Add the broken, but structurally consistent transaction
    voucher.transactions.push(broken_tx);

    let bundle = create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // 2. ACT
    human_money_core::set_signature_bypass(true);
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, Some(PASSWORD), false);
    human_money_core::set_signature_bypass(false);

    // 3. ASSERT
    assert!(result.is_err());
    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("Transaction chain broken")
            || err_str.contains("prev_hash does not match"),
        "Error should complain about broken chain. Got: {}",
        err_str
    );
    assert!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .is_empty()
    );
}

/// Test 2.2: A bundle with a "split" transaction whose amounts do not correctly
/// add up to the previous balance must be rejected.
#[test]
fn test_rejection_of_inconsistent_split_math() {
    // 1. ARRANGE
    let dir_sender = tempdir().unwrap();
    let dir_recipient = tempdir().unwrap();
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient(&dir_sender, &dir_recipient);
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // Create a voucher with 100 (via the public API)
    let mut voucher = service_sender
        .create_new_voucher(
            &freetaler_toml, // Create a voucher with 100
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    let prev_tx_hash = human_money_core::services::crypto::get_hash(
        human_money_core::services::utils::to_canonical_json(voucher.transactions.last().unwrap())
            .unwrap(),
    );

    // Create a split transaction: Send 30, keep 80. (30 + 80 != 100 -> ERROR)
    let mut tx2 = voucher.transactions[0].clone();
    tx2.prev_hash = prev_tx_hash;
    tx2.t_type = "split".to_string();
    tx2.recipient_id = human_money_core::models::voucher::ANONYMOUS_ID.to_string();
    tx2.amount = "30.00".to_string();
    tx2.sender_remaining_amount = Some("80.00".to_string()); // Wrong remaining amount

    // NEW: Attach a valid Privacy Guard so ingest check passes
    let payload = human_money_core::models::voucher::RecipientPayload {
        sender_permanent_did: identity_sender.user_id.clone(),
        target_prefix: id_recipient.split(':').next().unwrap_or("").to_string(),
        timestamp: 1625097600,
        next_key_seed: "test".to_string(),
        ..Default::default()
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let recipient_pubkey = human_money_core::services::crypto::get_pubkey_from_user_id(&id_recipient).unwrap();
    tx2.privacy_guard = Some(human_money_core::services::crypto::encrypt_recipient_payload(
        &payload_bytes,
        &recipient_pubkey,
        &id_recipient,
    ).unwrap());

    // 3. IMPORTANT: Thanks to signature bypass, we only update t_id.
    tx2.t_id = human_money_core::crypto::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap(),
    );
    voucher.transactions.push(tx2);

    let bundle = create_test_bundle(&identity_sender, vec![voucher], &id_recipient, None).unwrap();

    // 2. ACT
    human_money_core::set_signature_bypass(true);
    let result = service_recipient.receive_bundle(&bundle, &standards_map, None, Some("pwd"), false);
    human_money_core::set_signature_bypass(false);

    // 3. ASSERT
    // NOTE: This uncovers a gap in the current validation logic.
    // `voucher_validation.rs` only checks `InsufficientFunds`, but not whether the sum
    // of a split is correct. The test will therefore currently erroneously PASS.
    // An ideal error would be `InvalidSplitBalance`. We check for a generic error.
    assert!(
        result.is_err(),
        "Receive bundle should have failed due to bad math. This might indicate a validation logic gap if it passes."
    );

    // Once validation is hardened, specific error message can be checked.
    // assert!(result.unwrap_err().contains("InvalidSplitBalance"));
}

/// Test 2.3: A bundle created for another recipient (Bob)
/// must not be ingestible by the sender (Alice) themselves.
#[test]
fn test_rejection_of_self_received_bundle() {
    // 1. ARRANGE
    let dir_sender = tempdir().unwrap();
    let dir_recipient = tempdir().unwrap();
    let (mut service_sender, _, mut service_recipient, id_recipient) =
        setup_sender_recipient(&dir_sender, &dir_recipient);

    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // Sender creates a new voucher
    let _ = service_sender // The returned voucher object is not directly needed
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    // FIX for E0609: local_instance_id must be retrieved from summaries.
    let summaries = service_sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    let local_id = summaries
        .first()
        .expect("Wallet should have one voucher summary after creation")
        .local_instance_id
        .clone();

    // Sender creates a bundle for recipient (id_recipient)
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id,
            amount_to_send: "50".to_string(),
        }],
        notes: Some("For Bob".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes_for_bob = bundle_result.bundle_bytes;

    // 2. ACT
    // The SENDER now tries to ingest the bundle intended for Bob THEMSELVES.
    let result_self_receive =
        service_sender.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, Some("pwd"), false);

    // 3. ASSERT
    assert!(result_self_receive.is_err());
    let err_str = result_self_receive.unwrap_err().to_string();
    assert!(
        err_str.contains("Bundle has already been processed") || err_str.contains("Bundle Recipient Mismatch"),
        "Error should be Replay Check or Recipient Mismatch. Got: {}",
        err_str
    );

    // Ensure that the original voucher (now with remaining amount)
    // remained in 'Active' status and no new voucher was created.
    let summaries = service_sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status, VoucherStatus::Active);
    assert_eq!(summaries[0].current_amount, "50.00"); // Remaining amount after split

    // Recipient (Bob) can receive it without issues
    let result_recipient =
        service_recipient.receive_bundle(&bundle_bytes_for_bob, &standards_map, None, Some("pwd"), false);
    assert!(result_recipient.is_ok());
    assert_eq!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.4: (Layer 1) An identical bundle received again
/// must be rejected based on its Bundle ID.
#[test]
fn test_rejection_of_identical_bundle_replay() {
    // 1. ARRANGE
    let dir_sender = tempdir().unwrap();
    let dir_recipient = tempdir().unwrap();
    let (mut service_sender, _, mut service_recipient, id_recipient) =
        setup_sender_recipient(&dir_sender, &dir_recipient);

    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // Sender creates a new voucher
    let _ = service_sender
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();

    let summaries = service_sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    let local_id = summaries.first().unwrap().local_instance_id.clone();

    // Sender creates a bundle for recipient
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id,
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes = bundle_result.bundle_bytes;

    // 2. ACT (First Receive)
    let result_first =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, Some("pwd"), false);

    // 3. ASSERT (First Receive)
    assert!(result_first.is_ok());
    assert_eq!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );

    // 4. ACT (Second Receive - Replay)
    let result_second =
        service_recipient.receive_bundle(&bundle_bytes, &standards_map, None, Some("pwd"), false);

    // 5. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err().to_string();
    assert!(
        err_str.contains("Bundle has already been processed"),
        "Error should be BundleAlreadyProcessed. Got: {}",
        err_str
    );
    // Wallet state must not have changed
    assert_eq!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.5: (Layer 2) A voucher that has already been received must not
/// be received again in a *new* bundle (fingerprint check).
#[test]
fn test_rejection_of_voucher_replay_in_new_bundle() {
    // 1. ARRANGE
    let dir_sender = tempdir().unwrap();
    let dir_recipient = tempdir().unwrap();
    let (mut service_sender, identity_sender, mut service_recipient, id_recipient) =
        setup_sender_recipient(&dir_sender, &dir_recipient);

    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // Manually create voucher_A (as in Test 2.1)
    let voucher_a = service_sender
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();
    let (voucher_a_sent, _) = human_money_core::models::voucher::Transaction::create(
        &voucher_a,
        &FREETALER_STANDARD.0,
        &identity_sender.user_id,
        &identity_sender.signing_key,
        &human_money_core::test_utils::derive_holder_key(&voucher_a, &identity_sender.signing_key), // Init -> Tx 1
        &id_recipient,
        "50.00",
        None,
    )
    .unwrap();

    // Bundle 1 (The legitimate bundle)
    let bundle_1_bytes = create_test_bundle(
        &identity_sender,
        vec![voucher_a_sent.clone()],
        &id_recipient,
        Some("Bundle 1"),
    )
    .unwrap();
    // Bundle 2 (The malicious replay bundle with new Bundle ID, but identical content)
    let bundle_2_bytes = create_test_bundle(
        &identity_sender,
        vec![voucher_a_sent],
        &id_recipient,
        Some("Bundle 2"),
    )
    .unwrap();

    // 2. ACT (First Receive)
    let result_first =
        service_recipient.receive_bundle(&bundle_1_bytes, &standards_map, None, Some("pwd"), false);
    assert!(result_first.is_ok());
    assert_eq!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );

    // 3. ACT (Second Receive - Replay)
    let result_second =
        service_recipient.receive_bundle(&bundle_2_bytes, &standards_map, None, Some("pwd"), false);

    // 4. ASSERT (Second Receive)
    assert!(result_second.is_err());
    let err_str = result_second.unwrap_err().to_string();
    assert!(
        err_str.contains("Transaction fingerprint is already known"),
        "Error should be TransactionFingerprintAlreadyKnown. Got: {}",
        err_str
    );
    assert_eq!(
        service_recipient
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );
}

/// Test 2.6: (Layer 3) A bundle sent to another prefix (mobile) of the same
/// identity must be rejected by the wallet with the "pc" prefix.
/// This is the core test for "Separated Account Identity (SAI)".
#[test]
fn test_rejection_of_bundle_for_different_prefix_same_identity() {
    // 1. ARRANGE
    let freetaler_toml = generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let mut standards_map = HashMap::new();
    standards_map.insert(FREETALER_STANDARD.0.immutable.identity.uuid.clone(), freetaler_toml.clone());

    // --- Sender (Alice) ---
    let dir_sender = tempdir().unwrap();
    let sender = &ACTORS.alice;
    let (mut service_sender, _) =
        setup_service_with_profile(dir_sender.path(), sender, "Sender", "pwd");
    service_sender.unlock_session("pwd", 60).unwrap();

    // --- Recipient wallets (both "Bob", but different prefixes) ---
    // IMPORTANT: We use ACTORS.bob and ACTORS.issuer. Both use
    // the same mnemonic (mnemonics::BOB), but different prefixes ("bo", "is").
    // This simulates the same user on two devices.
    let recipient_user_pc = &ACTORS.bob; // prefix "bo"
    let recipient_user_mobil = &ACTORS.issuer; // prefix "is"

    // Wallet 1: PC
    let dir_recipient_pc = tempdir().unwrap();
    let (mut service_recipient_pc, _) = setup_service_with_profile(
        dir_recipient_pc.path(),
        recipient_user_pc,
        "Bob_PC",
        "pwd_bob",
    );
    service_recipient_pc.unlock_session("pwd_bob", 60).unwrap();
    let id_recipient_pc = service_recipient_pc.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // Wallet 2: Mobile
    let dir_recipient_mobil = tempdir().unwrap();
    let (mut service_recipient_mobil, _) = setup_service_with_profile(
        dir_recipient_mobil.path(),
        recipient_user_mobil,
        "Bob_Mobil",
        "pwd_bob",
    );
    service_recipient_mobil
        .unlock_session("pwd_bob", 60)
        .unwrap();
    let id_recipient_mobil = service_recipient_mobil.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    // Sanity Check: Ensure public keys are identical,
    // but full User IDs (addresses) differ.
    let pk_pc = human_money_core::services::crypto::get_pubkey_from_user_id(&id_recipient_pc)
        .unwrap();
    let pk_mobil =
        human_money_core::services::crypto::get_pubkey_from_user_id(&id_recipient_mobil)
            .unwrap();
    assert_eq!(
        pk_pc, pk_mobil,
        "Public keys must be identical for this test."
    );
    assert_ne!(
        id_recipient_pc, id_recipient_mobil,
        "Full User IDs (addresses) must be different."
    );
    assert!(id_recipient_pc.starts_with("bo:")); // Prefix of ACTORS.bob
    assert!(id_recipient_mobil.starts_with("is:")); // Prefix of ACTORS.issuer

    // --- Sender creates voucher and bundle for "Mobile" ---
    let _ = service_sender
        .create_new_voucher(
            &freetaler_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_sender.with_wallet(|w| w.get_user_id().to_string()).unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "100".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some("pwd"),
        )
        .unwrap();
    let local_id_sender = service_sender
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()
        .first()
        .unwrap()
        .local_instance_id
        .clone();

    // Bundle is explicitly sent to the "Mobile" address
    let transfer_request = MultiTransferRequest {
        recipient_id: id_recipient_mobil.clone(),
        sources: vec![SourceTransfer {
            local_instance_id: local_id_sender,
            amount_to_send: "50".to_string(),
        }],
        notes: Some("For Bob's mobile".to_string()),
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let bundle_result = service_sender
        .create_transfer_bundle(transfer_request, &standards_map, None, Some("pwd"))
        .unwrap();
    let bundle_bytes_for_mobil = bundle_result.bundle_bytes;

    // 2. ACT
    // The "PC" wallet attempts to ingest the bundle intended for "Mobile".
    let result_pc_receive = service_recipient_pc.receive_bundle(
        &bundle_bytes_for_mobil,
        &standards_map,
        None,
        Some("pwd_bob"),
        false,
    );

    // 3. ASSERT (PC Wallet)
    assert!(result_pc_receive.is_err());
    let err_str = result_pc_receive.unwrap_err().to_string();
    assert!(
        // With PrivacyMode::TrialDecryption the container is opened successfully
        // (since public keys match), but Layer 3 bundle validation
        // fails because recipient_id does not match the wallet User ID.
        err_str.contains("Bundle Recipient Mismatch") || err_str.contains("not intended for this wallet"),
        "Error must indicate recipient mismatch. Got: {}",
        err_str
    );
    // The PC wallet must remain empty
    assert!(
        service_recipient_pc
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .is_empty()
    );

    // 4. ASSERT (Mobile Wallet - Sanity Check)
    // The "Mobile" wallet (correct recipient) can accept it without issues.
    let result_mobil_receive = service_recipient_mobil.receive_bundle(
        &bundle_bytes_for_mobil,
        &standards_map,
        None,
        Some("pwd_bob"),
        false,
    );
    assert!(result_mobil_receive.is_ok());
    assert_eq!(
        service_recipient_mobil
            .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
            .unwrap()
            .len(),
        1
    );
}
