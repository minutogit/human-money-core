#[cfg(test)]
mod tests {
    use human_money_core::models::voucher::{RecipientPayload, Transaction};
    use human_money_core::services::crypto_utils::{encrypt_recipient_payload, get_hash};
    use human_money_core::test_utils::{setup_in_memory_wallet, add_voucher_to_wallet, ACTORS, MINUTO_STANDARD, derive_holder_key};
    use human_money_core::services::utils::to_canonical_json;
    use std::collections::HashMap;

    #[test]
    fn test_privacy_traceability_direct_decryption() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

        let alice_local_id = add_voucher_to_wallet(
            &mut alice_wallet,
            &alice.identity,
            "100",
            &MINUTO_STANDARD.0,
            true
        ).unwrap();

        let voucher = alice_wallet.voucher_store.vouchers.get(&alice_local_id).unwrap().voucher.clone();

        let holder_key = derive_holder_key(&voucher, &alice.identity.signing_key);

        let (voucher_for_bob, _secrets) = human_money_core::services::voucher_manager::create_transaction(
            &voucher,
            &MINUTO_STANDARD.0,
            &alice.identity.user_id,
            &alice.identity.signing_key,
            &holder_key,
            &bob.identity.user_id,
            "100",
            None,
        ).unwrap();

        let (bundle_bytes, _header) = alice_wallet.create_and_encrypt_transaction_bundle(
            &alice.identity,
            vec![voucher_for_bob],
            &bob.identity.user_id,
            None,
            vec![],
            HashMap::new(),
            None,
        ).unwrap();

        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        let process_result = bob_wallet.process_encrypted_transaction_bundle(
            &bob.identity,
            &bundle_bytes,
            None,
            &standards,
        ).unwrap();

        let bob_local_id = &process_result.involved_vouchers[0];

        let revealed_sender = bob_wallet.get_voucher_source_sender(bob_local_id, &bob.identity).unwrap();
        assert_eq!(revealed_sender, Some(alice.identity.user_id.clone()));
    }

    #[test]
    fn test_receive_private_bundle_with_spoofed_identity() {
        human_money_core::set_signature_bypass(true);
        
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let mallory_id = "did:key:mallory_fake_id";

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let alice_local_id = add_voucher_to_wallet(
            &mut alice_wallet,
            &alice.identity,
            "100",
            &MINUTO_STANDARD.0,
            true
        ).unwrap();

        let voucher = alice_wallet.voucher_store.vouchers.get(&alice_local_id).unwrap().voucher.clone();
        
        let payload = RecipientPayload {
            sender_permanent_did: mallory_id.to_string(), // SPOOFED!
            target_prefix: bob.identity.user_id.clone(),
            timestamp: 0,
            next_key_seed: bs58::encode([0u8; 32]).into_string(),
        };
        
        let guard = encrypt_recipient_payload(
            &serde_json::to_vec(&payload).unwrap(),
            &bob.identity.public_key,
            &bob.identity.user_id,
        ).unwrap();

        let holder_key = derive_holder_key(&voucher, &alice.identity.signing_key);
        let public_key_b58 = bs58::encode(holder_key.verifying_key().to_bytes()).into_string();

        let mut tx = Transaction {
            t_id: "".to_string(),
            t_type: "transfer".to_string(),
            t_time: human_money_core::services::utils::get_current_timestamp(),
            prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
            receiver_ephemeral_pub_hash: None,
            sender_id: None, // Private
            sender_identity_signature: None,
            recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
            amount: "100".to_string(),
            sender_remaining_amount: None,
            sender_ephemeral_pub: Some(public_key_b58), // Reveal the key to pass fund check!
            change_ephemeral_pub_hash: None,
            privacy_guard: Some(guard),
            trap_data: None,
            layer2_signature: None,
            deletable_at: None,
        };
        
        tx.t_id = get_hash(to_canonical_json(&tx).unwrap());
        
        let mut voucher_spoofed = voucher.clone();
        voucher_spoofed.transactions.push(tx);

        let (bundle_bytes, _) = human_money_core::services::bundle_processor::create_and_encrypt_bundle(
            &alice.identity,
            vec![voucher_spoofed],
            &bob.identity.user_id,
            None,
            vec![],
            HashMap::new(),
            None,
        ).unwrap();

        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        let receive_result = bob_wallet.process_encrypted_transaction_bundle(
            &bob.identity,
            &bundle_bytes,
            None,
            &standards,
        );

        human_money_core::set_signature_bypass(false);

        assert!(receive_result.is_err());
        let err_msg = receive_result.unwrap_err().to_string();
        assert!(err_msg.contains("Privacy Guard Integrity") || err_msg.contains("MismatchedPrivacySenderId"), "Error was: {}", err_msg);
    }

    #[test]
    fn test_traceability_skips_outbound_split() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let charlie = &ACTORS.charlie;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        // 1. Alice creates voucher (100) and sends 100 to Bob
        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &MINUTO_STANDARD.0, true).unwrap();

        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: None,
        };
        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();
        
        let bob_receive = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = bob_receive.involved_vouchers[0].clone();

        // 2. Bob splits 40 to Charlie (Bob keeps 60)
        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: charlie.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: bob_local_id,
                amount_to_send: "40".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Bob".to_string()),
            use_privacy_mode: None,
        };
        bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request, None).unwrap();

        // Bob's new voucher (60)
        let bob_vouchers = bob_wallet.list_vouchers(Some(&bob.identity), None, None);
        let bob_new_local_id = bob_vouchers.iter().find(|v| v.current_amount == "60").unwrap().local_instance_id.clone();

        // Bob verifies sender -> Alice
        // Hier sollte die Outbound-Regel greifen: Bob kann den Split-Guard (für Charlie) nicht lesen, 
        // überspringt ihn aber, weil Bob NICHT der recipient_id des Splits ist.
        let revealed_sender = bob_wallet.get_voucher_source_sender(&bob_new_local_id, &bob.identity).unwrap();
        assert_eq!(revealed_sender, Some(alice.identity.user_id.clone()));
    }

    #[test]
    fn test_traceability_aborts_on_corrupt_inbound_guard() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let charlie = &ACTORS.charlie;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);
        let mut charlie_wallet = setup_in_memory_wallet(&charlie.identity);

        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        // Alice -> Bob (100)
        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &MINUTO_STANDARD.0, true).unwrap();
        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true),
        };
        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();
        let bob_receive = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = bob_receive.involved_vouchers[0].clone();

        // Bob -> Charlie (100)
        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: charlie.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: bob_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Bob".to_string()),
            use_privacy_mode: Some(true),
        };
        let bundle = bob_wallet.execute_multi_transfer_and_bundle(&bob.identity, &standards, request, None).unwrap();
        let charlie_receive = charlie_wallet.process_encrypted_transaction_bundle(&charlie.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let charlie_local_id = charlie_receive.involved_vouchers[0].clone();

        // Manipulation: Charlies letzter Transaktion-Guard ist korrupt
        {
            let instance = charlie_wallet.voucher_store.vouchers.get_mut(&charlie_local_id).unwrap();
            let last_tx = instance.voucher.transactions.last_mut().unwrap();
            // Korrumpiere den Guard (ungültiges Base64 simuliert fehlgeschlagene Entschlüsselung)
            last_tx.privacy_guard = Some("invalid_garbage".to_string());
        }

        // Charlie prüft Quelle -> None
        // Hier greift die Inbound-Regel: Da Charlie recipient_id ist, aber nicht lesen kann, 
        // wird abgebrochen. Es darf NICHT Alice zurückgegeben werden.
        let revealed_sender = charlie_wallet.get_voucher_source_sender(&charlie_local_id, &charlie.identity).unwrap();
        assert_eq!(revealed_sender, None);
    }

    #[test]
    fn test_flexible_privacy_toggle() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut bob_wallet = setup_in_memory_wallet(&bob.identity);

        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        // 1. Minuto ist Flexible. Alice sendet PRIVAT (obwohl Standard Public erlaubt)
        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &MINUTO_STANDARD.0, true).unwrap();
        
        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true), // <<--- TOGGLE PRIVACY ON
        };

        let bundle = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None).unwrap();
        
        // Bob empfängt
        let bob_receive = bob_wallet.process_encrypted_transaction_bundle(&bob.identity, &bundle.bundle_bytes, None, &standards).unwrap();
        let bob_local_id = bob_receive.involved_vouchers[0].clone();

        // Check A: Im Ledger (Klartext) steht kein Sender
        let instance = bob_wallet.voucher_store.vouchers.get(&bob_local_id).unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();
        assert!(last_tx.sender_id.is_none());
        assert!(last_tx.sender_identity_signature.is_none());

        // Check B: Rückverfolgbarkeit funktioniert trotzdem (via Guard)
        let revealed_sender = bob_wallet.get_voucher_source_sender(&bob_local_id, &bob.identity).unwrap();
        assert_eq!(revealed_sender, Some(alice.identity.user_id.clone()));
    }

    #[test]
    fn test_strict_privacy_validation() {
        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        let mut standards = HashMap::new();
        
        // 1. Test: Public Standard + use_privacy_mode: Some(true) -> Error
        let mut test_public_std = MINUTO_STANDARD.0.clone();
        test_public_std.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
        standards.insert(test_public_std.immutable.identity.uuid.clone(), test_public_std.clone());

        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &test_public_std, true).unwrap();
        
        let request = human_money_core::wallet::types::MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![human_money_core::wallet::types::SourceTransfer {
                local_instance_id: alice_local_id,
                amount_to_send: "100".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
            use_privacy_mode: Some(true),
        };

        let result = alice_wallet.execute_multi_transfer_and_bundle(&alice.identity, &standards, request, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot use privacy mode on a public standard"));
    }
}
