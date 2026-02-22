//! # src/wallet/tests.rs
//! Enthält die Modul-Tests für die `Wallet`-Struktur. Diese Datei ist
//! bewusst von `mod.rs` getrennt, um die Lesbarkeit zu verbessern.

// FIX: Externe Crates müssen ohne `crate::` importiert werden.
use bs58;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier};

// FIX: Interne Module werden mit `crate::` importiert.
use crate::{
    VoucherCoreError, VoucherStatus,
    models::conflict::{Layer2Verdict, ProofOfDoubleSpend, ResolutionEndorsement},
    services::crypto_utils,
    test_utils::{
        ACTORS, MINUTO_STANDARD, add_voucher_to_wallet, create_voucher_for_manipulation,
        setup_in_memory_wallet,
    },
};
/// Bündelt die Tests zur Validierung der `local_instance_id`-Logik.
mod local_instance_id_logic {
    // Importiert die benötigten Typen vom Crate-Anfang. Das ist robuster.
    use crate::{VoucherCoreError, Wallet};
    // Holt die Test-Helfer und die nur hier benötigte `create_transaction` Funktion
    use crate::services::voucher_manager::create_transaction;
    use crate::test_utils::{self, ACTORS};

    /// **Test 1: Grundlagen - Korrekte ID nach Split und Eindeutigkeit**
    ///
    /// Prüft, dass nach einer Split-Transaktion beide Parteien (Sender mit
    /// Restbetrag und Empfänger) unterschiedliche, aber korrekt abgeleitete
    /// lokale IDs erhalten, die beide auf derselben letzten Transaktion basieren.
    #[test]
    fn test_correct_id_after_split_and_uniqueness() {
        // --- Setup ---
        // Erstellt einen Gutschein von Alice (100) und eine Transaktion,
        // bei der sie 40 an Bob sendet.
        let (_, _, alice, bob, voucher_after_split, _) = test_utils::setup_voucher_with_one_tx();
        let split_tx = voucher_after_split.transactions.last().unwrap();

        // --- Aktion ---
        let alice_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_split, &alice.user_id).unwrap();
        let bob_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_split, &bob.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_split.voucher_id, split_tx.t_id, alice.user_id
        ));
        let expected_bob_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_split.voucher_id, split_tx.t_id, bob.user_id
        ));

        // 1 & 2: IDs müssen auf der `split`-Transaktion basieren.
        assert_eq!(alice_local_id, expected_alice_id);
        assert_eq!(bob_local_id, expected_bob_id);

        // 3: Die IDs müssen unterschiedlich sein, da der `owner_id` Teil des Hashes ist.
        assert_ne!(alice_local_id, bob_local_id);
    }

    /// **Test 2: Pfadabhängigkeit - Korrekte ID in einer langen Transaktionskette**
    ///
    /// Stellt sicher, dass immer die _letzte_ relevante Transaktion für die ID-Berechnung
    /// herangezogen wird.
    #[test]
    fn test_path_dependency_long_chain() {
        // --- Setup ---
        // Alice (100) -> Bob (40)
        let (standard, _, _, bob, voucher_after_tx1, secrets) =
            test_utils::setup_voucher_with_one_tx();
        let charlie = &ACTORS.charlie;

        // Recover Bob's ephemeral key from the secrets of the previous transaction
        let bob_seed_bytes = bs58::decode(secrets.recipient_seed).into_vec().unwrap();
        let bob_ephemeral_key =
            ed25519_dalek::SigningKey::from_bytes(&bob_seed_bytes.try_into().unwrap());

        // Bob (40) -> Charlie (40) - Voller Transfer
        let (voucher_after_tx2, _) = create_transaction(
            &voucher_after_tx1,
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_ephemeral_key,
            &charlie.user_id,
            "40.0000",
        )
        .unwrap();
        let final_tx = voucher_after_tx2.transactions.last().unwrap();

        // --- Aktion ---
        let charlie_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_tx2, &charlie.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        let expected_charlie_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_tx2.voucher_id, final_tx.t_id, charlie.user_id
        ));
        assert_eq!(charlie_local_id, expected_charlie_id);
    }

    /// **Test 3: Pfadabhängigkeit - "Bounce Back"-Szenario**
    ///
    /// Prüft, ob die ID korrekt ist, wenn ein Gutschein zum vorherigen Besitzer zurückkehrt.
    #[test]
    fn test_path_dependency_bounce_back() {
        // --- Setup ---
        // Alice (100) -> Bob (40)
        let (standard, _, alice, bob, voucher_after_tx1, secrets) =
            test_utils::setup_voucher_with_one_tx();

        // Recover Bob's ephemeral key
        let bob_seed_bytes = bs58::decode(secrets.recipient_seed).into_vec().unwrap();
        let bob_ephemeral_key =
            ed25519_dalek::SigningKey::from_bytes(&bob_seed_bytes.try_into().unwrap());

        // Bob (40) -> Alice (40) - Sendet den Betrag zurück
        let (voucher_after_tx2, _) = create_transaction(
            &voucher_after_tx1,
            standard,
            &bob.user_id,
            &bob.signing_key,
            &bob_ephemeral_key,
            &alice.user_id,
            "40.0000",
        )
        .unwrap();
        let final_tx = voucher_after_tx2.transactions.last().unwrap();

        // --- Aktion ---
        let alice_final_local_id =
            Wallet::calculate_local_instance_id(&voucher_after_tx2, &alice.user_id).unwrap();

        // --- Erwartetes Ergebnis ---
        // Die ID muss auf der letzten Transaktion (Bob -> Alice) basieren.
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_tx2.voucher_id, final_tx.t_id, alice.user_id
        ));
        assert_eq!(alice_final_local_id, expected_alice_id);
    }

    /// **Test 4: Korrekte ID für archivierte Zustände**
    ///
    /// Stellt sicher, dass die ID-Berechnung auch für einen Sender korrekt ist,
    /// nachdem dieser seinen gesamten Betrag transferiert hat (Saldo = 0).
    #[test]
    fn test_correct_id_for_archived_state() {
        // --- Setup ---
        // --- Setup ---
        let (standard, _, alice, bob, initial_voucher, secrets) =
            test_utils::setup_voucher_with_one_tx();

        let alice_change_seed = secrets
            .change_seed
            .expect("Alice should have received change from split");
        let alice_change_key_bytes = bs58::decode(alice_change_seed).into_vec().unwrap();
        let alice_ephemeral_key =
            ed25519_dalek::SigningKey::from_bytes(&alice_change_key_bytes.try_into().unwrap());

        let (voucher_after_full_transfer, _) = create_transaction(
            &initial_voucher,
            standard,
            &alice.user_id,
            &alice.signing_key,
            &alice_ephemeral_key, // Use change key!
            &bob.user_id,
            "60.0000",
        )
        .unwrap();
        let final_tx = voucher_after_full_transfer.transactions.last().unwrap();

        // --- Aktion ---
        // Berechne die ID für Alice, deren Guthaben nun 0 ist (archivierter Zustand).
        let alice_archived_id =
            Wallet::calculate_local_instance_id(&voucher_after_full_transfer, &alice.user_id)
                .unwrap();

        // --- Erwartetes Ergebnis ---
        // Die ID muss auf der letzten Transaktion basieren, an der Alice beteiligt war.
        let expected_alice_id = crate::services::crypto_utils::get_hash(format!(
            "{}{}{}",
            voucher_after_full_transfer.voucher_id, final_tx.t_id, alice.user_id
        ));
        assert_eq!(alice_archived_id, expected_alice_id);
    }

    /// **Test 5: Fehlerfall - Kein Besitz**
    ///
    /// Prüft die korrekte Fehlerbehandlung, wenn eine ID für einen Benutzer
    /// berechnet werden soll, der nie im Besitz des Gutscheins war.
    #[test]
    fn test_error_when_user_has_no_balance_or_history() {
        // --- Setup ---
        // Alice (100) -> Bob (40). Charlie war nie beteiligt.
        let (_, _, _, _, voucher, _) = test_utils::setup_voucher_with_one_tx();
        let charlie = &ACTORS.charlie;

        // --- Aktion ---
        let result = Wallet::calculate_local_instance_id(&voucher, &charlie.user_id);

        // DEBUG: Gib das Ergebnis aus, um zu sehen, was tatsächlich zurückkommt.
        println!("Debug: Das Ergebnis für Charlie ist: {:?}", &result);

        // --- Erwartetes Ergebnis ---
        assert!(
            result.is_err(),
            "Function should return an error for a non-owner."
        );
        assert!(matches!(
            result.unwrap_err(),
            VoucherCoreError::VoucherOwnershipNotFound(_)
        ));
    }
}

/// Bündelt Tests zur Überprüfung des korrekten Verhaltens von Gutscheinen
/// in verschiedenen Zuständen (z.B. unter Quarantäne).
mod instance_state_behavior {
    use super::*;

    /// **Test 1.2: Verhalten von Quarantined-Gutscheinen**
    ///
    /// Stellt sicher, dass Operationen, die einen aktiven Gutschein erfordern,
    /// für einen unter Quarantäne gestellten Gutschein fehlschlagen.
    ///
    /// ### Szenario:
    /// 1.  Ein Gutschein wird erstellt und manuell auf `Quarantined` gesetzt.
    /// 2.  Ein Transfer-Versuch wird gestartet.
    /// 3.  Ein Versuch, eine Signaturanfrage zu erstellen, wird gestartet.
    ///
    /// ### Erwartetes Ergebnis:
    /// -   `create_transfer` schlägt mit `VoucherCoreError::VoucherNotActive` fehl.
    /// -   `create_signing_request` schlägt mit `VoucherCoreError::VoucherNotReadyForSigning` fehl.
    #[test]
    fn test_quarantined_voucher_behavior() {
        // --- Setup ---
        let alice = &ACTORS.alice;
        let mut wallet = setup_in_memory_wallet(alice);
        let (standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
        let local_id = add_voucher_to_wallet(&mut wallet, alice, "100", standard, true).unwrap();

        // Instanz manuell auf Quarantined setzen
        let instance = wallet.voucher_store.vouchers.get_mut(&local_id).unwrap();
        instance.status = VoucherStatus::Quarantined {
            reason: "Test".to_string(),
        };

        // --- Aktion & Assertions ---

        // 1. Test execute_multi_transfer_and_bundle with MultiTransferRequest
        let request = crate::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.user_id.clone(),
            sources: vec![crate::wallet::SourceTransfer {
                local_instance_id: local_id.clone(),
                amount_to_send: "50".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        let mut standards_map = std::collections::HashMap::new();
        standards_map.insert(standard.metadata.uuid.clone(), standard.clone());
        let transfer_result =
            wallet.execute_multi_transfer_and_bundle(alice, &standards_map, request, None);
        assert!(
            matches!(
                transfer_result,
                Err(VoucherCoreError::VoucherNotActive(
                    VoucherStatus::Quarantined { .. }
                ))
            ),
            "create_transfer should fail for a quarantined voucher"
        );

        // 2. Test create_signing_request
        let signing_request_result =
            wallet.create_signing_request(alice, &local_id, &ACTORS.guarantor1.user_id);
        assert!(
            matches!(
                signing_request_result,
                Err(VoucherCoreError::VoucherNotActive(
                    VoucherStatus::Quarantined { .. }
                ))
            ),
            "create_signing_request should fail for a quarantined voucher"
        );
    }
}

/// Bündelt Tests für Wartungsfunktionen wie die Speicherbereinigung.
mod maintenance_logic {
    use super::*;
    use crate::wallet::Wallet;

    /// **Test 3.1: Korrektes Löschen abgelaufener, archivierter Instanzen**
    ///
    /// Verifiziert, dass `cleanup_storage` nur die archivierten Instanzen entfernt,
    /// deren Gültigkeit plus Gnadenfrist abgelaufen ist.
    ///
    /// ### Szenario:
    /// 1.  Ein Wallet wird mit zwei archivierten Gutscheinen gefüllt:
    ///     - Gutschein A: `valid_until` vor 3 Jahren.
    ///     - Gutschein B: `valid_until` vor 6 Monaten.
    /// 2.  Die Funktion `cleanup_storage` wird mit einer Gnadenfrist von 1 Jahr aufgerufen.
    ///
    /// ### Erwartetes Ergebnis:
    /// -   Gutschein A wird entfernt, da `valid_until` + 1 Jahr < heute.
    /// -   Gutschein B verbleibt im Speicher, da `valid_until` + 1 Jahr > heute.
    #[test]
    fn test_cleanup_of_expired_archived_instances() {
        // --- Setup ---
        let user = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(user);
        let (standard, hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

        // Fix: Erstelle eine gültige Datenvorlage, die von der Hilfsfunktion akzeptiert wird.
        let voucher_data = crate::services::voucher_manager::NewVoucherData {
            validity_duration: Some("P1Y".to_string()),
            // FIX: Setze den Creator explizit, damit die Ownership-Prüfung erfolgreich ist.
            creator_profile: crate::models::profile::PublicProfile {
                id: Some(user.user_id.clone()),
                ..Default::default()
            },
            ..Default::default()
        };

        // Gutschein A (abgelaufen)
        let mut voucher_a = create_voucher_for_manipulation(
            voucher_data.clone(),
            standard,
            hash,
            &user.signing_key,
            "en",
        );
        voucher_a.valid_until = (Utc::now() - Duration::days(365 * 3)).to_rfc3339();
        let id_a = Wallet::calculate_local_instance_id(&voucher_a, &user.user_id).unwrap();
        wallet.add_voucher_instance(id_a.clone(), voucher_a, VoucherStatus::Archived);

        // Gutschein B (noch in Gnadenfrist)
        let mut voucher_b =
            create_voucher_for_manipulation(voucher_data, standard, hash, &user.signing_key, "en");
        voucher_b.valid_until = (Utc::now() - Duration::days(180)).to_rfc3339();
        let id_b = Wallet::calculate_local_instance_id(&voucher_b, &user.user_id).unwrap();
        wallet.add_voucher_instance(id_b.clone(), voucher_b, VoucherStatus::Archived);

        // --- Aktion ---
        wallet.cleanup_storage(1); // Gnadenfrist von 1 Jahr

        // --- Assertions ---
        assert!(
            !wallet.voucher_store.vouchers.contains_key(&id_a),
            "Expired voucher A should have been removed"
        );
        assert!(
            wallet.voucher_store.vouchers.contains_key(&id_b),
            "Voucher B within grace period should remain"
        );
    }
}

/// Bündelt die Tests für das Konflikt-Management API.
mod conflict_management_api {
    // Importiert die notwendigen Typen und Helfer aus dem übergeordneten Modul.
    use super::*;
    use crate::models::voucher::Transaction;

    /// Lokale Test-Hilfsfunktion, um einen realistischen mock `ProofOfDoubleSpend` zu erzeugen.
    fn create_mock_proof_of_double_spend(
        offender_id: &str,
        _victim_id: &str, // FIX: Als unbenutzt markieren, da `ACTORS.victim` verwendet wird.
        resolutions: Option<Vec<ResolutionEndorsement>>,
        verdict: Option<Layer2Verdict>,
    ) -> ProofOfDoubleSpend {
        // FIX: Komplette Neufassung, um der exakten Struktur aus `conflict.rs` zu entsprechen
        // und `test_utils` für Signaturen/Hashes wiederzuverwenden.
        let reporter = &ACTORS.victim; // Nehmen wir an, das Opfer ist der Melder.
        let fork_point_prev_hash = "fork_hash_123".to_string();
        let proof_id = crypto_utils::get_hash(format!("{}{}", offender_id, fork_point_prev_hash));
        let signature = crypto_utils::sign_ed25519(&reporter.signing_key, proof_id.as_bytes());

        ProofOfDoubleSpend {
            proof_id,
            offender_id: offender_id.to_string(),
            fork_point_prev_hash,
            conflicting_transactions: vec![Transaction::default(), Transaction::default()],
            deletable_at: (Utc::now() + Duration::days(90)).to_rfc3339(),
            reporter_id: reporter.user_id.clone(),
            report_timestamp: Utc::now().to_rfc3339(),
            reporter_signature: bs58::encode(signature.to_bytes()).into_string(),
            resolutions,
            layer2_verdict: verdict,
        }
    }
    // === Tests für `Wallet::list_conflicts` ===

    /// **Test 1.1: Leerer Zustand**
    /// Überprüft, ob `list_conflicts` einen leeren Vektor zurückgibt,
    /// wenn der `proof_store` des Wallets leer ist.
    #[test]
    fn test_list_conflicts_empty_state() {
        // FIX: `setup_in_memory_wallet` benötigt eine Identität und gibt nur das Wallet zurück.
        let identity = &ACTORS.test_user;
        let wallet = setup_in_memory_wallet(identity);

        // Act: Rufe die Funktion auf.
        let conflicts = wallet.list_conflicts();

        // Assert: Das Ergebnis sollte ein leerer Vektor sein.
        assert!(conflicts.is_empty());
    }

    /// **Test 1.2: Ein ungelöster Konflikt**
    /// Stellt sicher, dass ein einzelner, ungelöster Konflikt korrekt
    /// als Zusammenfassung mit den richtigen Status-Flags zurückgegeben wird.
    #[test]
    fn test_list_conflicts_with_one_unresolved_conflict() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let identity = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(identity);
        let proof = create_mock_proof_of_double_spend("offender-id", "victim-id", None, None);
        // FIX: `insert` wird auf dem `proofs` Feld aufgerufen, nicht auf `ProofStore` selbst.
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof.clone());

        // Act: Rufe die Funktion auf.
        let conflicts = wallet.list_conflicts();

        // Assert: Es sollte genau eine Zusammenfassung zurückgegeben werden.
        assert_eq!(conflicts.len(), 1);
        let summary = &conflicts[0];

        // Überprüfe die Inhalte der Zusammenfassung.
        assert_eq!(summary.proof_id, proof.proof_id);
        assert_eq!(summary.offender_id, proof.offender_id);
        assert_eq!(summary.is_resolved, false);
        assert_eq!(summary.has_l2_verdict, false);
    }

    /// **Test 1.3: Ein beigelegter Konflikt**
    /// Überprüft, ob ein Konflikt, der eine `ResolutionEndorsement` enthält,
    /// korrekt mit `is_resolved: true` markiert wird.
    #[test]
    fn test_list_conflicts_with_one_resolved_conflict() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let identity = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(identity);
        // FIX: `resolution_timestamp` ist ein Pflichtfeld.
        let endorsement = ResolutionEndorsement {
            endorsement_id: "endorsement-1".to_string(),
            proof_id: "proof-1".to_string(),
            victim_id: "victim-id".to_string(),
            victim_signature: "sig".to_string(),
            resolution_timestamp: Utc::now().to_rfc3339(),
            notes: None,
        };
        let proof = create_mock_proof_of_double_spend(
            "offender-id",
            "victim-id",
            Some(vec![endorsement]),
            None,
        );
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof);

        // Act: Rufe die Funktion auf.
        let conflicts = wallet.list_conflicts();

        // Assert: Die Zusammenfassung sollte den korrekten Status anzeigen.
        assert_eq!(conflicts.len(), 1);
        let summary = &conflicts[0];
        assert_eq!(summary.is_resolved, true);
        assert_eq!(summary.has_l2_verdict, false);
    }

    /// **Test 1.4: Konflikt mit L2-Urteil**
    /// Überprüft, ob ein Konflikt, der ein `Layer2Verdict` enthält,
    /// korrekt mit `has_l2_verdict: true` markiert wird.
    #[test]
    fn test_list_conflicts_with_l2_verdict() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let identity = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(identity);
        // FIX: Felder von `Layer2Verdict` waren veraltet.
        let verdict = Layer2Verdict {
            verdict_timestamp: Utc::now().to_rfc3339(),
            valid_transaction_id: "tx-a".to_string(),
            server_id: "server-id".to_string(),
            server_signature: "sig".to_string(),
        };
        let proof =
            create_mock_proof_of_double_spend("offender-id", "victim-id", None, Some(verdict));
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof);

        // Act: Rufe die Funktion auf.
        let conflicts = wallet.list_conflicts();

        // Assert: Die Zusammenfassung sollte den korrekten Status anzeigen.
        assert_eq!(conflicts.len(), 1);
        let summary = &conflicts[0];
        assert_eq!(summary.has_l2_verdict, true);
    }

    // === Tests für `Wallet::get_proof_of_double_spend` ===

    /// **Test 2.1: Erfolgreicher Abruf**
    /// Stellt sicher, dass ein existierender Beweis korrekt anhand seiner ID
    /// abgerufen werden kann.
    #[test]
    fn test_get_proof_of_double_spend_success() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let identity = &ACTORS.test_user;
        let mut wallet = setup_in_memory_wallet(identity);
        let proof = create_mock_proof_of_double_spend("offender", "victim", None, None);
        wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof.clone());

        // Act: Rufe den Beweis mit der korrekten ID ab.
        let result = wallet.get_proof_of_double_spend(&proof.proof_id);

        // Assert: Das Ergebnis muss `Ok` sein und der Beweis muss identisch sein.
        assert!(result.is_ok());
        // FIX: `ProofOfDoubleSpend` hat kein `PartialEq`. Vergleiche stattdessen Schlüsselfelder.
        assert_eq!(result.unwrap().proof_id, proof.proof_id);
    }

    /// **Test 2.2: Fehler bei nicht gefundener ID**
    /// Überprüft, ob die Funktion ein `Err` zurückgibt, wenn eine
    /// unbekannte `proof_id` angefragt wird.
    #[test]
    fn test_get_proof_of_double_spend_not_found() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let identity = &ACTORS.test_user;
        let wallet = setup_in_memory_wallet(identity);

        // Act: Versuche, einen nicht existierenden Beweis abzurufen.
        let result = wallet.get_proof_of_double_spend("non-existent-id");

        // Assert: Das Ergebnis muss ein Fehler sein.
        assert!(result.is_err());
        // Optional: Überprüfe die spezifische Fehlermeldung.
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Proof with ID 'non-existent-id' not found")
        );
    }

    // === Tests für `Wallet::create_resolution_endorsement` ===

    /// **Test 3.1: Erfolgreiche Erstellung und Signaturvalidierung**
    /// Stellt sicher, dass eine Beilegungserklärung korrekt erstellt und
    /// digital signiert wird.
    #[test]
    fn test_create_resolution_endorsement_success_and_validation() {
        // FIX: Korrekter Aufruf von setup_in_memory_wallet
        let victim_identity = &ACTORS.victim;
        let mut wallet_with_proof = setup_in_memory_wallet(victim_identity);
        let proof =
            create_mock_proof_of_double_spend("offender-id", &victim_identity.user_id, None, None);
        wallet_with_proof
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof.clone());

        // Act: Das Opfer erstellt die Beilegungserklärung.
        let result = wallet_with_proof.create_resolution_endorsement(
            &victim_identity,
            &proof.proof_id,
            Some("Resolved amicably".to_string()),
        );

        // Assert: Die Erstellung war erfolgreich.
        assert!(result.is_ok());
        let endorsement = result.unwrap();

        // Überprüfe die Metadaten.
        assert_eq!(endorsement.proof_id, proof.proof_id);
        assert_eq!(endorsement.victim_id, victim_identity.user_id);
        assert_eq!(endorsement.notes, Some("Resolved amicably".to_string()));

        // Validiere die Signatur.
        // FIX: Korrekte Signatur-Verifizierung mit `ed25519_dalek`
        let public_key = crypto_utils::get_pubkey_from_user_id(&victim_identity.user_id).unwrap();
        // FIX: Die Bibliothek erwartet ein `[u8; 64]` Array, kein `Vec<u8>`.
        // Wir müssen den Vektor in ein Array konvertieren.
        let signature_bytes: [u8; 64] = bs58::decode(&endorsement.victim_signature)
            .into_vec()
            .expect("Failed to decode signature")
            .try_into()
            .expect("Decoded signature must be 64 bytes long");
        // FIX: `Signature::from_bytes` gibt keinen `Result`, daher kein `.unwrap()` nötig.
        let signature = Signature::from_bytes(&signature_bytes);

        let result = public_key.verify(endorsement.endorsement_id.as_bytes(), &signature);
        assert!(result.is_ok(), "Signature verification failed");
    }

    /// **Test 3.2: Fehler, wenn der Beweis nicht existiert**
    /// Stellt sicher, dass die Funktion fehlschlägt, wenn die `proof_id`
    /// nicht im Wallet vorhanden ist.
    #[test]
    fn test_create_resolution_endorsement_proof_not_found() {
        // Arrange: Erstelle ein leeres Wallet.
        let identity = &ACTORS.test_user;
        let wallet = setup_in_memory_wallet(identity);

        // Act: Versuche, eine Beilegung für einen nicht existierenden Beweis zu erstellen.
        let result = wallet.create_resolution_endorsement(identity, "non-existent-id", None);

        // Assert: Das Ergebnis muss ein Fehler sein.
        assert!(result.is_err());
    }

    // === Tests für `Wallet::add_resolution_endorsement` ===

    /// **Test 4.1: Erfolgreiches Hinzufügen**
    /// Überprüft, ob eine gültige, externe Beilegungserklärung erfolgreich
    /// zum entsprechenden Beweis im Wallet hinzugefügt wird.
    #[test]
    fn test_add_resolution_endorsement_success() {
        // Arrange: Zwei Wallets, eines für den Reporter, eines für das Opfer.
        let reporter_identity = &ACTORS.test_user;
        let mut reporter_wallet = setup_in_memory_wallet(reporter_identity);
        let victim_identity = &ACTORS.victim;
        let mut victim_wallet = setup_in_memory_wallet(victim_identity);

        // Der Reporter und das Opfer haben beide den Beweis.
        let proof =
            create_mock_proof_of_double_spend("offender-id", &victim_identity.user_id, None, None);
        reporter_wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof.clone());
        victim_wallet
            .proof_store
            .proofs
            .insert(proof.proof_id.clone(), proof.clone());

        // Das Opfer erstellt die Beilegung.
        let endorsement = victim_wallet
            .create_resolution_endorsement(&victim_identity, &proof.proof_id, None)
            .unwrap();

        // Act: Der Reporter fügt die empfangene Beilegung hinzu.
        let result = reporter_wallet.add_resolution_endorsement(endorsement.clone());

        // Assert: Der Vorgang war erfolgreich und der Beweis wurde aktualisiert.
        assert!(result.is_ok());
        let updated_proof = reporter_wallet
            .get_proof_of_double_spend(&proof.proof_id)
            .unwrap();
        let resolutions = updated_proof.resolutions.unwrap();
        assert_eq!(resolutions.len(), 1);
        assert_eq!(resolutions[0].endorsement_id, endorsement.endorsement_id);
    }

    /// **Test 4.2: Duplikate werden verhindert (Idempotenz)**
    /// Stellt sicher, dass das mehrfache Hinzufügen derselben Beilegung
    /// nicht zu Duplikaten im `resolutions`-Vektor führt.
    #[test]
    fn test_add_resolution_endorsement_is_idempotent() {
        // Arrange: Gleiches Setup wie in 4.1.
        let (mut reporter_wallet, _victim_wallet, _victim_identity, proof, endorsement) = {
            let reporter_identity = &ACTORS.test_user;
            let mut reporter_wallet = setup_in_memory_wallet(reporter_identity);
            let victim_identity = &ACTORS.victim;
            let mut victim_wallet = setup_in_memory_wallet(victim_identity);
            let proof = create_mock_proof_of_double_spend(
                "offender-id",
                &victim_identity.user_id,
                None,
                None,
            );
            reporter_wallet
                .proof_store
                .proofs
                .insert(proof.proof_id.clone(), proof.clone());
            victim_wallet
                .proof_store
                .proofs
                .insert(proof.proof_id.clone(), proof.clone());
            let endorsement = victim_wallet
                .create_resolution_endorsement(&victim_identity, &proof.proof_id, None)
                .unwrap();
            (
                reporter_wallet,
                victim_wallet,
                victim_identity,
                proof,
                endorsement,
            )
        };

        // Act: Füge dieselbe Beilegung ZWEIMAL hinzu.
        assert!(
            reporter_wallet
                .add_resolution_endorsement(endorsement.clone())
                .is_ok()
        );
        assert!(
            reporter_wallet
                .add_resolution_endorsement(endorsement.clone())
                .is_ok()
        );

        // Assert: Der Vektor enthält die Beilegung aber nur EINMAL.
        let updated_proof = reporter_wallet
            .get_proof_of_double_spend(&proof.proof_id)
            .unwrap();
        let resolutions = updated_proof.resolutions.unwrap();
        assert_eq!(resolutions.len(), 1, "Endorsement was added more than once");
    }
}

// --- NEUER TEST-BLOCK ---
/// Bündelt Tests zur Validierung der Schlüsselableitungslogik.
mod key_derivation_logic {
    use crate::wallet::Wallet;

    /// **Test: Passphrase beeinflusst Schlüsselableitung**
    ///
    /// Stellt sicher, dass die Bereitstellung einer BIP39-Passphrase zu einem
    /// völlig anderen Schlüsselpaar (und damit einer anderen User-ID) führt
    /// als die Ableitung nur aus der Mnemonic. Dies bestätigt, dass die
    /// Passphrase korrekt in den Ableitungsprozess einbezogen wird.
    #[test]
    fn test_passphrase_alters_key_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let passphrase = "my-secret-passphrase";

        // Ableitung OHNE Passphrase
        let (wallet_no_pass, identity_no_pass) =
            Wallet::new_from_mnemonic(mnemonic, None, Some("test")).unwrap();

        // Ableitung MIT Passphrase
        let (wallet_with_pass, identity_with_pass) =
            Wallet::new_from_mnemonic(mnemonic, Some(passphrase), Some("test")).unwrap();

        // Die resultierenden User-IDs MÜSSEN unterschiedlich sein.
        assert_ne!(
            wallet_no_pass.profile.user_id, wallet_with_pass.profile.user_id,
            "User IDs should be different when a passphrase is used."
        );

        // Zur Sicherheit auch die Public Keys der Identitäten vergleichen.
        assert_ne!(
            identity_no_pass.public_key, identity_with_pass.public_key,
            "Public keys should be different when a passphrase is used."
        );
    }
}
