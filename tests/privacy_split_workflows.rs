#[cfg(test)]
mod tests {
    use human_money_core::test_utils::{setup_in_memory_wallet, add_voucher_to_wallet, ACTORS, MINUTO_STANDARD};
    use std::collections::HashMap;
    use human_money_core::wallet::types::{MultiTransferRequest, SourceTransfer};

    #[test]
    fn test_chained_privacy_splits() {
        // ========================================================================
        // WORKFLOW: Verkettete Split-Transaktionen im Privacy Mode
        // Alice -> Bob (Split, Alice behält Wechselgeld)
        // Alice -> Charlie (Weiterer Split vom Wechselgeld)
        // Dieser Test verifiziert, dass die kryptographische Schüsselableitung 
        // für Wechselgeld-Guthaben über mehrere Stufen hinweg korrekt funktioniert.
        // ========================================================================

        let alice = &ACTORS.alice;
        let bob = &ACTORS.bob;
        let charlie = &ACTORS.charlie;

        let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
        
        let mut standards = HashMap::new();
        standards.insert(MINUTO_STANDARD.0.immutable.identity.uuid.clone(), MINUTO_STANDARD.0.clone());

        // 1. Alice hat einen initialen Gutschein (100)
        let alice_local_id = add_voucher_to_wallet(&mut alice_wallet, &alice.identity, "100", &MINUTO_STANDARD.0, true).unwrap();

        // 2. ERSTER SPLIT: Alice -> Bob (40), Alice behält 60 (Wechselgeld)
        println!("--- Erster Privacy Split: Alice -> Bob (40) ---");
        let request1 = MultiTransferRequest {
            recipient_id: bob.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: alice_local_id.clone(),
                amount_to_send: "40".to_string(),
            }],
            notes: Some("Zahlung 1".to_string()),
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true),
        };

        alice_wallet.execute_multi_transfer_and_bundle(
            &alice.identity, 
            &standards, 
            request1, 
            None
        ).expect("Erster Split sollte erfolgreich sein");

        // Wir prüfen, ob Alice das Wechselgeld (60) korrekt in ihrem Wallet hat
        let alice_vouchers = alice_wallet.list_vouchers(Some(&alice.identity), None, None);
        let remainder_local_id = alice_vouchers.iter()
            .find(|v| v.current_amount == "60")
            .map(|v| v.local_instance_id.clone())
            .expect("Alice sollte das Wechselgeld von 60 besitzen");

        // 3. ZWEITER SPLIT: Alice -> Charlie (20) vom Wechselgeld der ersten Transaktion
        println!("--- Zweiter Privacy Split: Alice -> Charlie (20) ---");
        let request2 = MultiTransferRequest {
            recipient_id: charlie.identity.user_id.clone(),
            sources: vec![SourceTransfer {
                local_instance_id: remainder_local_id,
                amount_to_send: "20".to_string(),
            }],
            notes: Some("Zahlung 2".to_string()),
            sender_profile_name: Some("Alice".to_string()),
            use_privacy_mode: Some(true),
        };

        let result2 = alice_wallet.execute_multi_transfer_and_bundle(
            &alice.identity, 
            &standards, 
            request2, 
            None
        );

        // Verifikation
        assert!(result2.is_ok(), "Der zweite Split vom Wechselgeld muss kryptographisch valide sein: {:?}", result2.err());
        
        let final_vouchers = alice_wallet.list_vouchers(Some(&alice.identity), None, None);
        let final_remainder = final_vouchers.iter()
            .find(|v| v.current_amount == "40")
            .is_some();
        
        assert!(final_remainder, "Alice sollte nach zwei Splits noch einen Restbetrag von 40 besitzen");
        println!("Erfolg: Verkettete Privacy Splits wurden korrekt verarbeitet.");
    }
}
