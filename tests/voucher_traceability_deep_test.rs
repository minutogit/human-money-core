#[cfg(test)]
mod tests {
    use human_money_core::test_utils::{setup_in_memory_wallet, add_voucher_to_wallet, ACTORS, MINUTO_STANDARD};
    use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
    use std::collections::HashMap;

    #[test]
    fn test_deep_traceability_with_splits_and_transfers() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let charlie = &ACTORS.charlie;
        let david = &ACTORS.david;
        let test_user = &ACTORS.test_user;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        let mut charlie_wallet = setup_in_memory_wallet(&charlie.identity);
        let mut david_wallet = setup_in_memory_wallet(&david.identity);
        let mut test_user_wallet = setup_in_memory_wallet(&test_user.identity);

        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        // 1. Alice creates voucher (100)
        let alice_local_id = add_voucher_to_wallet(
            &mut alice_wallet,
            &alice.identity,
            "100",
            &MINUTO_STANDARD.0,
            true
        ).unwrap();

        // 2. Alice sends 100 to Bob
        let request = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
        };
        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();

        let bob_receive = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = bob_receive.involved_vouchers[0].clone();

        // 3. Bob verifies sender -> Alice
        let sender = bob_wallet.get_voucher_source_sender(&bob_local_id, &bob.identity).unwrap();
        assert_eq!(sender, Some(alice.identity.user_id.clone()));

        // 4. Bob sends 40 to Charlie (SPLIT)
        let request = MultiTransferRequest {
            recipient_id: charlie.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: bob_local_id.clone(),
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Bob".to_string()),
        };
        let bundle = bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request, None).unwrap();
        
        let bob_vouchers = bob_wallet.list_vouchers(None, None);
        let bob_new_local_id = bob_vouchers.iter()
            .find(|v| v.current_amount == "60")
            .unwrap().local_instance_id.clone();

        // 5. Bob (remaining 60) verifies sender -> Alice
        let sender = bob_wallet.get_voucher_source_sender(&bob_new_local_id, &bob.identity).unwrap();
        assert_eq!(sender, Some(alice.identity.user_id.clone()), "Bob's remaining voucher should still point to Alice as source");

        // 6. Charlie receives 40
        let charlie_receive = charlie_wallet.process_encrypted_transaction_bundle(&charlie.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let charlie_local_id = charlie_receive.involved_vouchers[0].clone();

        // 7. Charlie verifies sender -> Bob
        let sender = charlie_wallet.get_voucher_source_sender(&charlie_local_id, &charlie.identity).unwrap();
        assert_eq!(sender, Some(bob.identity.user_id.clone()));

        // 8. Bob sends 20 to David (SPLIT)
        let request = MultiTransferRequest {
            recipient_id: david.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: bob_new_local_id.clone(),
                amount_to_send: "20".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Bob".to_string()),
        };
        let bundle = bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request, None).unwrap();

        // Bob now has 40.
        let bob_vouchers = bob_wallet.list_vouchers(None, None);
        let bob_final_local_id = bob_vouchers.iter()
            .find(|v| v.current_amount == "40" && matches!(v.status, human_money_core::wallet::instance::VoucherStatus::Active))
            .unwrap().local_instance_id.clone();

        // 9. Bob (remaining 40) verifies sender -> Alice
        let sender = bob_wallet.get_voucher_source_sender(&bob_final_local_id, &bob.identity).unwrap();
        assert_eq!(sender, Some(alice.identity.user_id.clone()), "After second split, Bob's voucher should still point to Alice");

        // 10. David receives 20
        let david_receive = david_wallet.process_encrypted_transaction_bundle(&david.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let david_local_id = david_receive.involved_vouchers[0].clone();

        // 11. David verifies sender -> Bob
        let sender = david_wallet.get_voucher_source_sender(&david_local_id, &david.identity).unwrap();
        assert_eq!(sender, Some(bob.identity.user_id.clone()));

        // 12. Bob sends remaining 40 to Test User (FULL TRANSFER)
        let request = MultiTransferRequest {
            recipient_id: test_user.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: bob_final_local_id.clone(),
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Bob".to_string()),
        };
        let bundle = bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request, None).unwrap();

        // 13. Test User receives 40
        let test_user_receive = test_user_wallet.process_encrypted_transaction_bundle(&test_user.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let test_user_local_id = test_user_receive.involved_vouchers[0].clone();

        // 14. Test User verifies sender -> Bob
        let sender = test_user_wallet.get_voucher_source_sender(&test_user_local_id, &test_user.identity).unwrap();
        assert_eq!(sender, Some(bob.identity.user_id.clone()), "Test User should see Bob as the source sender");
    }
}
