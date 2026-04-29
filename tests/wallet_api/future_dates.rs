// tests/wallet_api/future_dates.rs

use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD, add_voucher_to_wallet,
    setup_in_memory_wallet,
};
use human_money_core::{
    VoucherCoreError, 
    services::utils::set_mock_time,
};
use chrono::{DateTime, Utc, Duration, SecondsFormat};

#[test]
fn test_future_dated_vouchers() {
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    
    // Set a baseline "now"
    let now_dt = DateTime::parse_from_rfc3339("2025-01-01T12:00:00Z").unwrap().with_timezone(&Utc);
    set_mock_time(Some(now_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));

    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

    // 1. Create a voucher for Alice
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        standard,
        true,
    ).unwrap();

    // 2. Mock time into the future for Alice to create a transfer
    // We mock time to 1 hour in the future relative to our current "now"
    let future_dt = now_dt + Duration::hours(1);
    let future_str = future_dt.to_rfc3339_opts(SecondsFormat::Micros, true);
    set_mock_time(Some(future_str.clone()));

    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "100".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let bundle_result = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request,
        None,
    ).unwrap();

    // 3. Reset time back to original "now" for Bob
    set_mock_time(Some(now_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));

    // 4. Bob tries to receive the bundle (1 hour in the future, within 2h grace period)
    // This should SUCCESS (Soft Accept)
    bob_wallet.process_encrypted_transaction_bundle(
        &bob.identity,
        &bundle_result.bundle_bytes,
        None,
        &standards,
    ).expect("Soft accept should allow 1 hour future-dated bundle");

    // 5. Bob tries to SPEND the voucher immediately (it's still in the future for him)
    // This should FAIL with VoucherLockedUntil
    let spend_request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: alice.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: bob_wallet.list_vouchers(Some(&bob.identity), None, None)[0].local_instance_id.clone(),
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    
    let spend_result = bob_wallet.execute_multi_transfer_and_bundle(
        &bob.identity,
        &standards,
        spend_request.clone(),
        None,
    );
    
    assert!(matches!(spend_result, Err(VoucherCoreError::VoucherLockedUntil { .. })), "Spend should fail because last tx is in the future");
    
    if let Err(VoucherCoreError::VoucherLockedUntil { until, now: _, wait_duration }) = spend_result {
        assert_eq!(until, future_str);
        assert!(wait_duration.contains("1h 0m 0s"));
    }

    // 6. Advance Bob's time to the future (past the lock)
    let even_further_dt = future_dt + Duration::minutes(1);
    set_mock_time(Some(even_further_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));

    // Now spend should succeed
    bob_wallet.execute_multi_transfer_and_bundle(
        &bob.identity,
        &standards,
        spend_request,
        None,
    ).expect("Spend should succeed now that time has passed");

    // 7. Test HARD REJECT
    // Reset time for Alice to create a "far future" voucher
    set_mock_time(Some(now_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));
    let far_future_dt = now_dt + Duration::hours(5);
    set_mock_time(Some(far_future_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));
    
    let voucher_id_2 = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "50",
        standard,
        true,
    ).unwrap();

    let request_2 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob.identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id_2.clone(),
            amount_to_send: "50".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let even_further_far_future_dt = far_future_dt + Duration::minutes(1);
    set_mock_time(Some(even_further_far_future_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));

    let bundle_result_2 = alice_wallet.execute_multi_transfer_and_bundle(
        &alice.identity,
        &standards,
        request_2,
        None,
    ).unwrap();

    // Bob tries to receive (Reset to now)
    set_mock_time(Some(now_dt.to_rfc3339_opts(SecondsFormat::Micros, true)));
    let receive_result_2 = bob_wallet.process_encrypted_transaction_bundle(
        &bob.identity,
        &bundle_result_2.bundle_bytes,
        None,
        &standards,
    );

    assert!(receive_result_2.is_err(), "Hard reject should trigger for 5 hours future-dated bundle");
    let err = receive_result_2.err().unwrap();
    let err_msg = format!("{:?}", err);
    
    assert!(err_msg.contains("FutureTimestampRejected"), "Error should be FutureTimestampRejected");
    assert!(err_msg.contains("5h 1m 0s"), "Error message should show wait duration (17:01:00 - 12:00:00 = 5h 1m). Got: {}", err_msg);
    
    // Cleanup mock time
    set_mock_time(None);
}
