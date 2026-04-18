//! # src/wallet/reputation_tests.rs
//! Modultests für das Reputationsmanagement und den ProofStore.

#[cfg(test)]
mod tests {
    use crate::test_utils::{ACTORS, setup_in_memory_wallet};
    use crate::models::conflict::{ProofOfDoubleSpend, ProofStoreEntry, ConflictRole, TransactionFingerprint, FingerprintMetadata};
    use crate::models::voucher::Transaction;
    use crate::VoucherStatus;
    use std::collections::HashMap;

    fn create_dummy_proof(proof_id: &str, offender_id: &str) -> ProofOfDoubleSpend {
        ProofOfDoubleSpend {
            proof_id: proof_id.to_string(),
            offender_id: offender_id.to_string(),
            fork_point_prev_hash: "hash".to_string(),
            conflicting_transactions: vec![
                Transaction { t_id: "t1".to_string(), ..Default::default() },
                Transaction { t_id: "t2".to_string(), ..Default::default() },
            ],
            deletable_at: "2099-01-01T00:00:00Z".to_string(),
            reporter_id: "reporter".to_string(),
            report_timestamp: "2024-01-01T00:00:00Z".to_string(),
            reporter_signature: "sig".to_string(),
            affected_voucher_name: Some("Test Voucher".to_string()),
            voucher_standard_uuid: Some("uuid".to_string()),
            resolutions: None,
            layer2_verdict: None,
        }
    }

    #[test]
    fn test_wrapper_serialization_and_hash_integrity() {
        let proof = create_dummy_proof("p1", "offender");
        let entry = ProofStoreEntry {
            proof: proof.clone(),
            local_override: true,
            conflict_role: ConflictRole::Victim,
        };

        let serialized = serde_json::to_string(&entry).unwrap();
        let deserialized: ProofStoreEntry = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.proof.proof_id, proof.proof_id);
        assert_eq!(deserialized.local_override, true);
        assert_eq!(deserialized.conflict_role, ConflictRole::Victim);
        
        // Export simulation: just the inner proof
        let exported_json = serde_json::to_string(&deserialized.proof).unwrap();
        let original_json = serde_json::to_string(&proof).unwrap();
        assert_eq!(exported_json, original_json, "Exported proof must be identical to original");
    }

    #[test]
    fn test_import_protection_immunity() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let proof_id = "p1";
        
        let mut proof = create_dummy_proof(proof_id, "offender");
        
        // 1. Manuellem Override setzen
        wallet.proof_store.proofs.insert(proof_id.to_string(), ProofStoreEntry {
            proof: proof.clone(),
            local_override: true,
            conflict_role: ConflictRole::Victim,
        });

        // 2. Erneuter Import desselben Beweises (z.B. mit anderer Signatur oder Metadaten)
        proof.reporter_id = "malicious_reporter".to_string();
        wallet.import_proof(proof).unwrap();

        // 3. Verifizieren, dass der lokale Stand (Override) erhalten blieb
        let entry = wallet.proof_store.proofs.get(proof_id).unwrap();
        assert_eq!(entry.local_override, true);
        assert_eq!(entry.proof.reporter_id, "reporter", "Original reporter should not be overwritten");
    }

    #[test]
    fn test_vip_effective_head_start_and_eviction() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // 1. Zwei normale Fingerprints (Tiefe 0 und Tiefe 5)
        wallet.fingerprint_metadata.insert("norm_0".to_string(), FingerprintMetadata { depth: 0, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "norm_0".to_string(), 
            vec![TransactionFingerprint { ds_tag: "norm_0".to_string(), ..Default::default() }]
        );

        wallet.fingerprint_metadata.insert("norm_5".to_string(), FingerprintMetadata { depth: 5, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "norm_5".to_string(), 
            vec![TransactionFingerprint { ds_tag: "norm_5".to_string(), ..Default::default() }]
        );

        // 2. Ein leicht gealterter VIP-Fingerprint (-3) -> Effektive Tiefe: abs(-3) - 2 = 1
        wallet.fingerprint_metadata.insert("vip_minus_3".to_string(), FingerprintMetadata { depth: -3, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "vip_minus_3".to_string(), 
            vec![TransactionFingerprint { ds_tag: "vip_minus_3".to_string(), ..Default::default() }]
        );

        // 3. Ein stark gealterter VIP-Fingerprint (-10) -> Effektive Tiefe: abs(-10) - 2 = 8
        wallet.fingerprint_metadata.insert("vip_minus_10".to_string(), FingerprintMetadata { depth: -10, ..Default::default() });
        wallet.own_fingerprints.history.insert(
            "vip_minus_10".to_string(), 
            vec![TransactionFingerprint { ds_tag: "vip_minus_10".to_string(), ..Default::default() }]
        );

        // Auswahl für Bundle
        let (selected, _) = wallet.select_fingerprints_for_bundle("recipient", &[]).unwrap();

        // Verifikation der Sortier-Reihenfolge basierend auf effektiver Tiefe!
        // Platz 1: norm_0 (effektiv: 0)
        // Platz 2: vip_minus_3 (effektiv: 1)
        // Platz 3: norm_5 (effektiv: 5)
        // Platz 4: vip_minus_10 (effektiv: 8)
        
        assert_eq!(selected[0].ds_tag, "norm_0");
        assert_eq!(selected[1].ds_tag, "vip_minus_3", "VIP mit -3 muss wie Tiefe 1 behandelt werden!");
        assert_eq!(selected[2].ds_tag, "norm_5");
        assert_eq!(selected[3].ds_tag, "vip_minus_10", "Stark gealterter VIP muss hinter frischem Normalen landen!");
    }

    #[test]
    fn test_vip_symmetry_check() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(),
            ..Default::default()
        };

        // Fall 1: Asymmetrischer VIP-Spam (nur ein Fingerprint mit -2)
        let f1 = TransactionFingerprint { ds_tag: "f1".to_string(), ..Default::default() };
        let mut depths = HashMap::new();
        depths.insert("f1".to_string(), -2);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1], &depths).unwrap();
        
        // Muss auf positiv normalisiert werden (z.B. 1 + 1 = 2)
        assert!(wallet.fingerprint_metadata["f1"].depth > 0);

        // Fall 2: Symmetrischer VIP (Zwei Partner mit -2)
        let f2a = TransactionFingerprint { ds_tag: "fraud".to_string(), t_id: "t1".to_string(), ..Default::default() };
        let f2b = TransactionFingerprint { ds_tag: "fraud".to_string(), t_id: "t2".to_string(), ..Default::default() };
        let mut depths2 = HashMap::new();
        depths2.insert("fraud".to_string(), -2);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f2a, f2b], &depths2).unwrap();
        
        // Muss VIP bleiben und altern (-2 -> -3)
        assert_eq!(wallet.fingerprint_metadata["fraud"].depth, -3);
    }

    #[test]
    fn test_loop_protection_ignore_fresher_vip() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let ds_tag = "loop_tag".to_string();
        wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
            depth: -10, // Bereits gealtert
            ..Default::default()
        });
        wallet.known_fingerprints.foreign_fingerprints.insert(ds_tag.clone(), vec![
            TransactionFingerprint { ds_tag: ds_tag.clone(), ..Default::default() }
        ]);

        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        
        // Jemand sendet den Fingerprint "frisch" mit -1
        let f = TransactionFingerprint { ds_tag: ds_tag.clone(), t_id: "t1".to_string(), ..Default::default() };
        let f2 = TransactionFingerprint { ds_tag: ds_tag.clone(), t_id: "t2".to_string(), ..Default::default() };
        let mut depths = HashMap::new();
        depths.insert(ds_tag.clone(), -1);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f, f2], &depths).unwrap();
        
        // Muss bei -10 bleiben (-1 ist "frischer" und wird ignoriert)
        assert_eq!(wallet.fingerprint_metadata[&ds_tag].depth, -10);
    }

    #[test]
    fn test_saturating_sub_boundary() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        
        let f1 = TransactionFingerprint { ds_tag: "bound".to_string(), t_id: "t1".to_string(), ..Default::default() };
        let f2 = TransactionFingerprint { ds_tag: "bound".to_string(), t_id: "t2".to_string(), ..Default::default() };
        let mut depths = HashMap::new();
        depths.insert("bound".to_string(), -128);

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1, f2], &depths).unwrap();
        
        assert_eq!(wallet.fingerprint_metadata["bound"].depth, -128); // Darf nicht umbrechen
    }

    #[test]
    fn test_multi_proof_reputation_check() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let offender = "bad_guy";

        // Proof A: Gelöst via Override
        let proof_a = create_dummy_proof("proof_a", offender);
        wallet.import_proof(proof_a).unwrap();
        wallet.set_conflict_local_override("proof_a", true).unwrap();

        // Proof B: Ungelöst
        let proof_b = create_dummy_proof("proof_b", offender);
        wallet.import_proof(proof_b).unwrap();

        use crate::models::conflict::TrustStatus;
        let status = wallet.check_reputation(offender);
        
        if let TrustStatus::KnownOffender(pid) = status {
            assert_eq!(pid, "proof_b", "Must return the unsolved proof_b, even if proof_a is resolved");
        } else {
            panic!("Should be KnownOffender(proof_b)");
        }
    }

    #[test]
    fn test_vip_overrides_existing_positive_fingerprint() {
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        let ds_tag = "transition_tag".to_string();

        // 1. Setup: Fingerprint ist lokal bereits als "normal" (positiv) bekannt
        wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
            depth: 5, // Positive Tiefe (harmlos)
            ..Default::default()
        });
        wallet.known_fingerprints.foreign_fingerprints.insert(ds_tag.clone(), vec![
            TransactionFingerprint { ds_tag: ds_tag.clone(), t_id: "t_old".to_string(), ..Default::default() }
        ]);

        // 2. Aktion: Ein legitimes, symmetrisches VIP-Update (Betrugserkennung) trifft ein
        let bundle_header = crate::models::profile::TransactionBundleHeader {
            sender_id: "sender".to_string(), ..Default::default()
        };
        // Zwei Fingerprints mit demselben ds_tag erfüllen die Symmetrie-Regel
        let f1 = TransactionFingerprint { ds_tag: ds_tag.clone(), t_id: "t1".to_string(), ..Default::default() };
        let f2 = TransactionFingerprint { ds_tag: ds_tag.clone(), t_id: "t2".to_string(), ..Default::default() };
        
        let mut depths = HashMap::new();
        depths.insert(ds_tag.clone(), -2); // Eingehender VIP-Status

        wallet.process_received_fingerprints(&bundle_header, &[], &[f1, f2], &depths).unwrap();

        // 3. Verifikation: Der positive Wert (5) muss vom negativen überschrieben worden sein.
        // Bei received_depth = -2 greift die Alterung via saturating_sub(1), das Ergebnis muss also -3 sein.
        let updated_depth = wallet.fingerprint_metadata[&ds_tag].depth;
        assert_eq!(
            updated_depth, -3, 
            "Der positive Wert (5) muss durch das legitime VIP-Update (-2 - 1 = -3) überschrieben werden!"
        );
    }

    #[test]
    fn test_conflict_role_victim_identification() {
        // Testet die Erkennungslogik: Wenn eine der betrügerischen Transaktionen
        // einen Gutschein betrifft, den wir lokal besitzen und der dadurch in Quarantäne ist,
        // MUSS unsere Rolle "Victim" sein.
        
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);
        
        // 1. Wir simulieren einen lokalen Gutschein, der Opfer eines Double-Spends wurde
        let tx_id_victim = "tx_local_victim_123";
        let mut instance = crate::wallet::instance::VoucherInstance {
            local_instance_id: "inst_1".to_string(),
            // Status ist Quarantäne (wurde durch den Konflikt dorthin verschoben)
            status: VoucherStatus::Quarantined { reason: "Double Spend".to_string() },
            ..Default::default()
        };
        // Historie enthält die betroffene Transaktion
        instance.voucher.transactions.push(Transaction { t_id: tx_id_victim.to_string(), ..Default::default() });
        wallet.voucher_store.vouchers.insert("inst_1".to_string(), instance);
        
        // 2. Wir erstellen einen simulierten Beweis, dessen Kollision uns betrifft
        let mut proof = create_dummy_proof("p_role_test", "offender");
        proof.conflicting_transactions = vec![
            Transaction { t_id: tx_id_victim.to_string(), ..Default::default() }, // Unser Pfad
            Transaction { t_id: "tx_foreign_456".to_string(), ..Default::default() }, // Der andere Pfad
        ];
        
        // 3. Wir führen exakt die Rollen-Check-Logik aus dem transaction_handler aus
        let mut conflict_role = ConflictRole::Witness;
        for tx in &proof.conflicting_transactions {
            if let Some(local_inst) = wallet.find_local_voucher_by_tx_id(&tx.t_id) {
                if matches!(local_inst.status, VoucherStatus::Quarantined { .. }) {
                    conflict_role = ConflictRole::Victim;
                    break;
                }
            }
        }
        
        // 4. Verifikation
        assert_eq!(
            conflict_role, 
            ConflictRole::Victim, 
            "Der Nutzer muss als Opfer (Victim) erkannt werden, da sein lokaler Gutschein betroffen und in Quarantäne ist."
        );
    }

    #[test]
    fn test_bundle_selection_priority_at_max_limit() {
        // Testet den Vorrang beim Senden: Wenn das Limit von 150 erreicht ist,
        // müssen VIP-Fingerprints (negativ) mitgesendet werden. Normale, schwache
        // Fingerprints (hohe positive Tiefe) werden für dieses Bundle ignoriert.
        
        let identity = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(identity);

        // 1. System mit 150 regulären Fingerprints füllen (alle Tiefe 10)
        for i in 1..=150 {
            let ds_tag = format!("norm_{:03}", i);
            wallet.fingerprint_metadata.insert(ds_tag.clone(), FingerprintMetadata {
                depth: 10,
                ..Default::default()
            });
            wallet.own_fingerprints.history.insert(
                ds_tag.clone(), 
                vec![TransactionFingerprint { ds_tag: ds_tag.clone(), ..Default::default() }]
            );
        }

        // 2. Einen VIP-Fingerprint hinzufügen (Tiefe -1)
        let vip_tag = "vip_fraud".to_string();
        wallet.fingerprint_metadata.insert(vip_tag.clone(), FingerprintMetadata {
            depth: -1,
            ..Default::default()
        });
        wallet.own_fingerprints.history.insert(
            vip_tag.clone(), 
            vec![TransactionFingerprint { ds_tag: vip_tag.clone(), ..Default::default() }]
        );

        // Wir haben nun 151 Fingerprints im Speicher.
        // 3. Bundle-Auswahl triggern (greift auf MAX_FINGERPRINTS_TO_SEND = 150 zu)
        let (selected, _depths) = wallet.select_fingerprints_for_bundle("recipient", &[]).unwrap();

        // 4. Verifikation
        assert_eq!(
            selected.len(), 
            150, 
            "Das Hard-Limit von exakt 150 Fingerprints im Bundle muss strikt eingehalten werden."
        );
        
        // Der VIP-Fingerprint MUSS sich einen Platz gesichert haben
        assert!(
            selected.iter().any(|f| f.ds_tag == vip_tag), 
            "Der VIP-Fingerprint wurde nicht priorisiert! Er muss trotz des Limits im Bundle sein."
        );
        
        // Der schwächste reguläre Fingerprint (Tiefe 150) wurde durch den VIP verdrängt / nicht ausgewählt
        assert!(
            !selected.iter().any(|f| f.ds_tag == "norm_150"), 
            "Der schwächste reguläre Fingerprint hätte zugunsten des VIP-Fingerprints ignoriert werden müssen."
        );
    }
}
