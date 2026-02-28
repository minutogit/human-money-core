// tests/wallet_api/voucher_states.rs
// cargo test --test wallet_api_tests wallet_api::voucher_states
//!
//! Testet das Verhalten von Gutscheinen in verschiedenen Status-Zuständen,
//! insbesondere die Einschränkungen für Quarantäne.

use human_money_core::test_utils::{ACTORS, MINUTO_STANDARD, setup_in_memory_wallet, add_voucher_to_wallet};
use human_money_core::{VoucherStatus, VoucherCoreError};

#[test]
fn test_quarantined_voucher_behavior() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(alice);
    let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let local_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, true).unwrap();

    // Instanz manuell auf Quarantined setzen
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
    let signing_request_result = wallet.create_signing_request(alice, &local_id, &ACTORS.guarantor1.user_id);
    assert!(
        matches!(
            signing_request_result,
            Err(VoucherCoreError::VoucherNotActive(VoucherStatus::Quarantined { .. }))
        ),
        "create_signing_request should fail for a quarantined voucher"
    );
}
