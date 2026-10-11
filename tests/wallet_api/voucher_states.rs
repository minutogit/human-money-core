// tests/wallet_api/voucher_states.rs
// cargo test --test wallet_api_tests wallet_api::voucher_states
//!
//! Tests the behavior of vouchers in various states,
//! especially restrictions for Quarantine.

use human_money_core::models::secure_container::{ContainerConfig, PrivacyMode};
use human_money_core::test_utils::{ACTORS, MINUTO_STANDARD, setup_in_memory_wallet, add_voucher_to_wallet};
use human_money_core::{VoucherStatus, VoucherCoreError};

#[test]
fn test_quarantined_voucher_behavior() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);
    let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let local_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, true).unwrap();

    // Manually set instance to Quarantined
    let instance = wallet.voucher_store.vouchers.get_mut(&local_id).unwrap();
    instance.status = VoucherStatus::Quarantined {
        reason: "Test".to_string(),
    };

    // 1. Test execute_multi_transfer_and_bundle
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: ACTORS.bob.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_map = std::collections::HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), standard.clone());
    let transfer_result = wallet.execute_multi_transfer_and_bundle(alice, &standards_map, request, None);
    assert!(
        matches!(
            transfer_result,
            Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined { .. }))
        ),
        "create_transfer should fail for a quarantined voucher"
    );

    // 2. Test create_signing_request
    let signing_request_result = wallet.create_signing_request(alice, &local_id, ContainerConfig::TargetDid(ACTORS.guarantor1.user_id.clone(), PrivacyMode::TrialDecryption));
    assert!(
        matches!(
            signing_request_result,
            Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined { .. }))
        ),
        "create_signing_request should fail for a quarantined voucher"
    );
}

#[test]
fn test_delete_incomplete_voucher() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut wallet = setup_in_memory_wallet(alice);
    let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // 1. Create incomplete voucher (without guarantors)
    let incomplete_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, false).unwrap();
    assert!(matches!(
        wallet.voucher_store.vouchers[&incomplete_id].status,
        VoucherStatus::Incomplete { .. }
    ));

    // 2. Foreign user cannot delete it
    let foreign_del = wallet.delete_incomplete_voucher(&incomplete_id, &bob.user_id);
    assert!(
        foreign_del.is_err(),
        "Foreign user must not be allowed to delete voucher"
    );

    // 3. Create active voucher - cannot be deleted
    let active_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, true).unwrap();
    let active_del = wallet.delete_incomplete_voucher(&active_id, &alice.user_id);
    assert!(
        active_del.is_err(),
        "Active voucher must not be allowed to be deleted"
    );

    // 4. Non-existent voucher cannot be deleted
    let non_existent_del = wallet.delete_incomplete_voucher("non-existent-id", &alice.user_id);
    assert!(non_existent_del.is_err());

    // 5. Creator can delete incomplete voucher
    let success_del = wallet.delete_incomplete_voucher(&incomplete_id, &alice.user_id);
    assert!(success_del.is_ok(), "Creator must be able to delete incomplete voucher");
    assert!(
        !wallet.voucher_store.vouchers.contains_key(&incomplete_id),
        "Deleted voucher must be removed from store"
    );
}

#[test]
fn test_detached_signature_reception_in_process_bundle() {
    let alice = &ACTORS.alice;
    let guarantor1 = &ACTORS.guarantor1;
    let guarantor2 = &ACTORS.guarantor2;
    let mut wallet = setup_in_memory_wallet(alice);
    let g1_wallet = setup_in_memory_wallet(guarantor1);
    let g2_wallet = setup_in_memory_wallet(guarantor2);
    let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Create incomplete voucher (needs 2 guarantors)
    let local_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, false).unwrap();
    assert!(matches!(
        wallet.voucher_store.vouchers[&local_id].status,
        VoucherStatus::Incomplete { .. }
    ));

    let voucher = wallet.voucher_store.vouchers[&local_id].voucher.clone();

    // Create first detached signature container (guarantor 1: gender "1")
    let sig1_data = human_money_core::test_utils::voucher_setup::create_guarantor_signature_data(
        guarantor1,
        "1",
        &voucher.voucher_id,
    );
    let sig1_container = g1_wallet
        .create_detached_signature_response(
            guarantor1,
            &voucher,
            sig1_data,
            true,
            ContainerConfig::TargetDid(alice.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    let mut standards_map = std::collections::HashMap::new();
    standards_map.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    // Process first signature via process_encrypted_transaction_bundle
    let res1 = wallet.process_encrypted_transaction_bundle(alice, &sig1_container, None, &standards_map);
    assert!(res1.is_ok(), "Processing first detached signature must succeed: {:?}", res1.err());
    // Still needs second guarantor -> Incomplete
    assert!(matches!(
        wallet.voucher_store.vouchers[&local_id].status,
        VoucherStatus::Incomplete { .. }
    ));

    // Voucher now has G1 signature attached
    let voucher_with_g1 = wallet.voucher_store.vouchers[&local_id].voucher.clone();

    // Create second detached signature container (guarantor 2: gender "2")
    let sig2_data = human_money_core::test_utils::voucher_setup::create_guarantor_signature_data(
        guarantor2,
        "2",
        &voucher.voucher_id,
    );
    let sig2_container = g2_wallet
        .create_detached_signature_response(
            guarantor2,
            &voucher_with_g1,
            sig2_data,
            true,
            ContainerConfig::TargetDid(alice.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    // Process second signature via process_encrypted_transaction_bundle
    let res2 = wallet.process_encrypted_transaction_bundle(alice, &sig2_container, None, &standards_map);
    assert!(res2.is_ok(), "Processing second detached signature must succeed: {:?}", res2.err());
    // All signatures present -> Active!
    assert!(matches!(
        wallet.voucher_store.vouchers[&local_id].status,
        VoucherStatus::Active
    ));
}
