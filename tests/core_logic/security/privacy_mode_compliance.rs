#[cfg(test)]
mod tests {
    use human_money_core::models::voucher_standard_definition::PrivacyMode;
    use human_money_core::test_utils::{setup_in_memory_wallet, add_voucher_to_wallet, ACTORS, MINUTO_STANDARD};
    use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};
    use human_money_core::models::voucher::ANONYMOUS_ID;
    use std::collections::HashMap;

    #[test]
    fn test_public_mode_compliance() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        
        let mut public_std = MINUTO_STANDARD.0.clone();
        public_std.immutable.features.privacy_mode = PrivacyMode::Public;
        public_std.immutable.identity.uuid = "public-test-uuid".to_string();
        
        let mut standards = HashMap::new();
        standards.insert(public_std.immutable.identity.uuid.clone(), public_std.clone());

        // 1. Create Public Voucher
        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &public_std, true).unwrap();

        // 2. Transfer: Must have DIDs
        let request = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(false),
        };
        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();
        
        // 3. Receive and Check
        let receive_result = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = &receive_result.involved_vouchers[0];
        let instance = bob_wallet.voucher_store.vouchers.get(bob_local_id).unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();
        
        // Assert: DIDs are visible
        assert_eq!(last_tx.sender_id, Some(alice.identity.user_id.clone()));
        assert_eq!(last_tx.recipient_id, bob.identity.user_id);
        assert!(last_tx.sender_identity_signature.is_some());

        // 4. Try to use privacy mode (Must Fail)
        let request_private = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: bob_local_id.clone(),
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true),
        };
        let result = bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request_private, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot use privacy mode on a public standard"));
    }

    #[test]
    fn test_flexible_mode_compliance() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        
        let mut flexible_std = MINUTO_STANDARD.0.clone();
        flexible_std.immutable.features.privacy_mode = PrivacyMode::Flexible;
        flexible_std.immutable.identity.uuid = "flexible-test-uuid".to_string();
        
        let mut standards = HashMap::new();
        standards.insert(flexible_std.immutable.identity.uuid.clone(), flexible_std.clone());

        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &flexible_std, true).unwrap();

        // Case A: Flexible + Privacy OFF
        let request_pub = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(false),
        };
        let bundle_pub = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request_pub, None).unwrap();
        let receive_pub = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle_pub.bundle_bytes, None, &standards).unwrap();
        let bob_local_id_pub = &receive_pub.involved_vouchers[0];
        let tx_pub = bob_wallet.voucher_store.vouchers.get(bob_local_id_pub).unwrap().voucher.transactions.last().unwrap();
        
        // Assert: Sender visible, Recipient ANONYMOUS
        assert_eq!(tx_pub.sender_id, Some(alice.identity.user_id.clone()));
        assert_eq!(tx_pub.recipient_id, ANONYMOUS_ID);
        assert!(tx_pub.sender_identity_signature.is_some());

        // Case B: Flexible + Privacy ON
        // Find remaining amount from Alice
        let alice_vouchers = alice_wallet.list_vouchers(Some(&alice.identity), None, None, None);
        let alice_local_id_rem = alice_vouchers.iter().find(|v| v.current_amount == "60").unwrap().local_instance_id.clone();

        let request_priv = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id_rem,
                amount_to_send: "60".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true),
        };
        let bundle_priv = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request_priv, None).unwrap();
        let receive_priv = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle_priv.bundle_bytes, None, &standards).unwrap();
        let bob_local_id_priv = &receive_priv.involved_vouchers[0];
        let tx_priv = bob_wallet.voucher_store.vouchers.get(bob_local_id_priv).unwrap().voucher.transactions.last().unwrap();
        
        // Assert: Sender ANONYMOUS, Recipient ANONYMOUS
        assert!(tx_priv.sender_id.is_none());
        assert_eq!(tx_priv.recipient_id, ANONYMOUS_ID);
        assert!(tx_priv.sender_identity_signature.is_none());
    }

    #[test]
    fn test_stealth_mode_compliance() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        
        let mut stealth_std = MINUTO_STANDARD.0.clone();
        stealth_std.immutable.features.privacy_mode = PrivacyMode::Stealth;
        stealth_std.immutable.identity.uuid = "stealth-test-uuid".to_string();
        
        let mut standards = HashMap::new();
        standards.insert(stealth_std.immutable.identity.uuid.clone(), stealth_std.clone());

        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &stealth_std, true).unwrap();

        // Transfer: privacy mode is implicit here, but let's be explicit too
        let request = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: None,
        };
        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();
        let receive_result = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = &receive_result.involved_vouchers[0];
        let tx = bob_wallet.voucher_store.vouchers.get(bob_local_id).unwrap().voucher.transactions.last().unwrap();
        
        // Assert: Both ANONYMOUS
        assert!(tx.sender_id.is_none());
        assert_eq!(tx.recipient_id, ANONYMOUS_ID);
    }
}
