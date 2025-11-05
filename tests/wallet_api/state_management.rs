//! # tests/wallet_api/state_management.rs
//!
//! Enthält Integrationstests für komplexes State-Management und die
//! Handhabung von Konflikten wie Double-Spending.

use voucher_lib::{
    app_service::AppService,
    models::{conflict::{ProofOfDoubleSpend, ResolutionEndorsement}, voucher::{Creator, NominalValue}},
    services::{crypto_utils, voucher_manager::NewVoucherData},
    test_utils::{
        create_test_bundle, generate_signed_standard_toml,
        resign_transaction, ACTORS, SILVER_STANDARD,
    },
    VoucherStatus,
};

use chrono::DateTime;
use chrono::{Duration, Utc};
use std::{collections::HashMap};
use voucher_lib::test_utils;
use tempfile::tempdir;
use voucher_lib::{models::voucher::Transaction, services::utils};

/// Lokale Test-Hilfsfunktion, um einen mock `ProofOfDoubleSpend` zu erzeugen.
fn create_mock_proof_of_double_spend(
    offender_id: &str,
    victim_id: &str,
    resolutions: Option<Vec<ResolutionEndorsement>>,
    verdict: Option<voucher_lib::models::conflict::Layer2Verdict>,
) -> ProofOfDoubleSpend {
    // FIX: Struct-Literal komplett überarbeitet, um den korrekten Feldern aus der
    // Compiler-Fehlermeldung zu entsprechen.
    ProofOfDoubleSpend {
        proof_id: crypto_utils::get_hash(offender_id), // Dummy-ID für den Test
        offender_id: offender_id.to_string(),
        // FIX: Dies ist ein Vec<Transaction>, kein eigener Struct.
        conflicting_transactions: vec![Transaction::default(), Transaction::default()],
        // FIX: `reporter_id` ist keine Option und wird hier gesetzt.
        reporter_id: victim_id.to_string(),
        resolutions,
        layer2_verdict: verdict,
        fork_point_prev_hash: "dummy_hash".to_string(),
        // FIX: Fehlendes Pflichtfeld hinzugefügt.
        voucher_valid_until: (Utc::now() + Duration::days(365)).to_rfc3339(),
        report_timestamp: Utc::now().to_rfc3339(),
        reporter_signature: "dummy_sig".to_string(),
    }
}

/// Test 5.1: Testet den vollständigen "Happy Path" der Konfliktlösung über den AppService.
///
/// ### Szenario:
/// 1.  Zwei `AppService`-Instanzen (`reporter`, `victim`) werden initialisiert und eingeloggt.
/// 2.  Dem `reporter`-Wallet wird manuell ein `ProofOfDoubleSpend` hinzugefügt.
/// 3.  Der `reporter` listet den Konflikt und verifiziert, dass er ungelöst ist.
/// 4.  Das `victim` erstellt eine signierte `ResolutionEndorsement`.
/// 5.  Der `reporter` importiert diese Beilegung erfolgreich.
/// 6.  Eine *dritte* `AppService`-Instanz wird mit den Daten des Reporters erstellt,
///     um zu prüfen, ob die Änderung korrekt auf die Festplatte geschrieben wurde.
///     Nach dem Login wird der Konflikt als gelöst (`is_resolved: true`) angezeigt.
#[test]
fn api_app_service_full_conflict_resolution_workflow() {
    // --- 1. Setup ---
    let dir_reporter = tempdir().unwrap();
    let dir_victim = tempdir().unwrap();
    let password = "conflict-password";
    let reporter = &ACTORS.reporter;
    let victim = &ACTORS.victim;

    let (mut service_reporter, profile_reporter) = test_utils::setup_service_with_profile(dir_reporter.path(), reporter, "Reporter", password);
    let (mut service_victim, _) = test_utils::setup_service_with_profile(dir_victim.path(), victim, "Victim", password);
    let id_victim = service_victim.get_user_id().unwrap();

    // --- 2. Beweis im Reporter-Wallet anlegen ---
    let proof = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    let proof_id = proof.proof_id.clone();

    // Test-interne Hilfsfunktion, um den Beweis direkt in den Store zu legen.
    let (wallet, _identity) = service_reporter.get_unlocked_mut_for_test();
    wallet.proof_store.proofs.insert(proof.proof_id.clone(), proof);
    // Der manuelle `save`-Aufruf hier ist nicht nötig und führt zu Borrowing-Fehlern.
    // Der Zustand wird in-memory modifiziert, was für die nächsten Schritte ausreicht.
    // Der `import_resolution_endorsement`-Aufruf speichert den Zustand später korrekt.

    // --- 3. Aktion 1 (Reporter): Konflikt als ungelöst listen ---
    let conflicts_before = service_reporter.list_conflicts().unwrap();
    assert_eq!(conflicts_before.len(), 1);
    assert_eq!(conflicts_before[0].is_resolved, false);

    // --- 4. Aktion 2 (Opfer): Beilegung erstellen ---
    // Das Opfer muss den Beweis auch kennen, um ihn zu unterzeichnen.
    let (wallet_victim, _identity_victim) = service_victim.get_unlocked_mut_for_test();
    let proof_for_victim = create_mock_proof_of_double_spend("offender-xyz", &id_victim, None, None);
    wallet_victim
        .proof_store.proofs
        .insert(proof_for_victim.proof_id.clone(), proof_for_victim);

    let endorsement = service_victim
        .create_resolution_endorsement(&proof_id, Some("We settled this.".to_string()))
        .unwrap();

    // --- 5. Aktion 3 (Reporter): Beilegung importieren ---
    service_reporter
        .import_resolution_endorsement(endorsement, password)
        .unwrap();

    // --- 6. Aktion 4 (Finale Prüfung): Persistenz verifizieren ---
    let mut service_checker = AppService::new(dir_reporter.path()).unwrap();
    service_checker
        .login(&profile_reporter.folder_name, password, false)
        .unwrap();
    let conflicts_after = service_checker.list_conflicts().unwrap();
    assert_eq!(conflicts_after.len(), 1);
    assert_eq!(conflicts_after[0].proof_id, proof_id);
    assert_eq!(
        conflicts_after[0].is_resolved, true,
        "Conflict should be resolved after importing the endorsement and reloading from disk"
    );
}

/// Test 5.2: Stellt sicher, dass alle Konflikt-API-Methoden fehlschlagen,
/// wenn das Wallet gesperrt ist.
#[test]
fn api_app_service_conflict_api_fails_when_locked() {
    // Arrange: Erstelle einen AppService, der aber nicht eingeloggt ist (Zustand: Locked).
    let dir = tempdir().unwrap();
    // FIX: `service` muss mutable sein, da `import_resolution_endorsement` `&mut self` erfordert.
    let mut service = AppService::new(dir.path()).unwrap();
    let fake_proof_id = "proof-123";

    // Act & Assert: Jeder Aufruf muss mit "Wallet is locked" fehlschlagen.
    let res_list = service.list_conflicts();
    assert!(res_list.is_err());
    assert!(res_list.unwrap_err().contains("Wallet is locked"));

    let res_get = service.get_proof_of_double_spend(fake_proof_id);
    assert!(res_get.is_err());
    assert!(res_get.unwrap_err().contains("Wallet is locked"));

    let res_create = service.create_resolution_endorsement(fake_proof_id, None);
    assert!(res_create.is_err());
    assert!(res_create.unwrap_err().contains("Wallet is locked"));

    // FIX: Struct-Literal verwenden, da `::default` nicht existiert.
    let dummy_endorsement = ResolutionEndorsement {
        endorsement_id: "".to_string(),
        proof_id: "".to_string(),
        victim_id: "".to_string(),
        victim_signature: "".to_string(),
        resolution_timestamp: Utc::now().to_rfc3339(),
        notes: None,
    };
    let res_import = service.import_resolution_endorsement(dummy_endorsement, "pwd");
    assert!(res_import.is_err());
    assert!(res_import.unwrap_err().contains("Wallet is locked"));
}

/// Test 1.1: Testet die reaktive Double-Spend-Erkennung via "Earliest Wins"-Heuristik.
///
/// ### Szenario:
/// 1.  Alice erstellt einen Gutschein (Zustand V1).
/// 2.  Sie erzeugt zwei widersprüchliche Transaktionen aus V1:
///     - TX_A (früherer Zeitstempel): Sendet den vollen Betrag an Bob -> V2_BOB.
///     - TX_B (späterer Zeitstempel): Sendet den vollen Betrag an Charlie -> V2_CHARLIE.
/// 3.  Ein neues Wallet für David wird erstellt.
/// 4.  David empfängt zuerst das Bundle mit V2_CHARLIE (spätere Transaktion). Der Gutschein
///     wird als `Active` hinzugefügt.
/// 5.  David empfängt danach das Bundle mit V2_BOB (frühere Transaktion). Dies löst die
///     Konflikterkennung aus.
///
/// ### Erwartetes Ergebnis:
/// -   Das Wallet erkennt den Konflikt.
/// -   Die "Earliest Wins"-Heuristik wird angewendet.
/// -   Der Gutschein von Bob (basierend auf TX_A) wird auf `Active` gesetzt.
/// -   Der Gutschein von Charlie (basierend auf TX_B) wird auf `Quarantined` gesetzt.
#[test]
fn api_wallet_reactive_double_spend_earliest_wins() {
    // --- 1. Setup ---
    let dir_alice = tempdir().unwrap();
    let dir_david = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let david = &ACTORS.david;
    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_david, _) = test_utils::setup_service_with_profile(dir_david.path(), david, "David", "pwd");
    let id_alice = service_alice.get_user_id().unwrap();
    let id_david = service_david.get_user_id().unwrap();
    let identity_alice = alice.identity.clone();
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.metadata.uuid.clone(), silver_standard_toml.clone());

    // --- 2. Alice erstellt einen Gutschein (V1) ---
    let voucher_v1 = service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                creator: Creator { id: id_alice.clone(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();

    // --- 3. Alice erzeugt zwei konkurrierende Transaktionen ---
    let prev_tx = voucher_v1.transactions.last().unwrap();
    // KORREKTUR: Zeitstempel müssen garantiert nach der vorherigen Transaktion liegen.
    let prev_tx_time = DateTime::parse_from_rfc3339(&prev_tx.t_time)
        .unwrap()
        .with_timezone(&Utc);
    let time_a = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let time_b = (prev_tx_time + Duration::seconds(2)).to_rfc3339();

    // KORREKTUR: Der prev_hash muss der Hash der *gesamten* vorherigen Transaktion sein.
    let prev_tx_hash = crypto_utils::get_hash(utils::to_canonical_json(prev_tx).unwrap());

    // TX_A -> Bob (früher)
    let mut tx_a = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: time_a,
        sender_id: id_alice.clone(),
        recipient_id: id_david.clone(),
        amount: "100".to_string(),
        ..Default::default()
    };
    tx_a = resign_transaction(tx_a, &identity_alice.signing_key);
    let mut voucher_v2_bob = voucher_v1.clone();
    voucher_v2_bob.transactions.push(tx_a);

    // TX_B -> Charlie (später)
    let mut tx_b = Transaction {
        prev_hash: prev_tx_hash,
        t_type: "transfer".to_string(),
        t_time: time_b,
        sender_id: id_alice.clone(),
        recipient_id: id_david.clone(),
        amount: "100".to_string(),
        ..Default::default()
    };
    tx_b = resign_transaction(tx_b, &identity_alice.signing_key);
    let mut voucher_v2_charlie = voucher_v1.clone();
    voucher_v2_charlie.transactions.push(tx_b);

    let bundle_bob = create_test_bundle(&identity_alice, vec![voucher_v2_bob], &id_david, None).unwrap();
    let bundle_charlie =
        create_test_bundle(&identity_alice, vec![voucher_v2_charlie], &id_david, None)
        .unwrap();

    // --- 4. David empfängt zuerst das spätere Bundle (Charlie) ---
    service_david
        .receive_bundle(&bundle_charlie, &standards_map, None, "pwd")
        .unwrap();
    let summaries_before = service_david.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_before.len(), 1);
    assert_eq!(summaries_before[0].status, VoucherStatus::Active);
    let charlie_instance_id = summaries_before[0].local_instance_id.clone();

    // --- 5. David empfängt das frühere Bundle (Bob), was den Konflikt auslöst ---
    println!("\n[Debug] Wallet-Zustand VOR dem zweiten Empfang (Konflikt-Auslöser):");
    dbg!(service_david.get_voucher_summaries(None, None).unwrap());
    service_david
        .receive_bundle(&bundle_bob, &standards_map, None, "pwd")
        .unwrap();

    println!("\n[Debug] Wallet-Zustand NACH dem zweiten Empfang:");
    let summaries_after = service_david.get_voucher_summaries(None, None).unwrap();
    dbg!(&summaries_after);

    // --- 6. Assertions ---
    let summaries_after = service_david.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_after.len(), 2, "Wallet should now contain two instances");

    let summary_charlie = service_david
        .get_voucher_details(&charlie_instance_id)
        .unwrap();

    println!("\n[Debug] Überprüfe den Status des 'späteren' Gutscheins (sollte Quarantined sein):");
    dbg!(&summary_charlie);
    assert!(
        matches!(summary_charlie.status, VoucherStatus::Quarantined { .. }),
        "Charlie's later voucher should be quarantined"
    );

    let bob_instance_id = summaries_after
        .iter()
        .find(|s| s.local_instance_id != charlie_instance_id)
        .unwrap()
        .local_instance_id
        .clone();
    let summary_bob = service_david.get_voucher_details(&bob_instance_id).unwrap();
    assert_eq!(
        summary_bob.status,
        VoucherStatus::Active,
        "Bob's earlier voucher should be active"
    );
}

/// Test 1.2: Testet die Konflikterkennung bei exakt identischen Zeitstempeln.
///
/// ### Szenario:
/// Wie bei `earliest_wins`, aber die Zeitstempel der konkurrierenden Transaktionen
/// sind identisch.
///
/// ### Erwartetes Ergebnis:
/// Das System muss ein deterministisches Tie-Breaking-Verfahren anwenden und darf
/// nicht in einen inkonsistenten Zustand geraten. Es wird ein Gewinner gekürt,
/// und der andere Gutschein landet in Quarantäne.
#[test]
fn api_wallet_reactive_double_spend_identical_timestamps() {
    // --- 1. Setup (identisch zu earliest_wins) ---
    let dir_alice = tempdir().unwrap();
    let alice = &ACTORS.alice;
    let dir_david = tempdir().unwrap();
    let david = &ACTORS.david;

    let (mut service_alice, _) = test_utils::setup_service_with_profile(dir_alice.path(), alice, "Alice", "pwd");
    let (mut service_david, _) = test_utils::setup_service_with_profile(dir_david.path(), david, "David", "pwd");
    let id_alice = service_alice.get_user_id().unwrap();
    let id_david = service_david.get_user_id().unwrap();
    let identity_alice = alice.identity.clone();
    let silver_standard_toml =
        generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(standard.metadata.uuid.clone(), silver_standard_toml.clone());

    let voucher_v1 = service_alice
        .create_new_voucher(
            &silver_standard_toml,
            "en",
            NewVoucherData {
                nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
                creator: Creator { id: id_alice.clone(), ..Default::default() },
                ..Default::default()
            },
            "pwd",
        )
        .unwrap();

    // --- 2. Erzeuge konkurrierende Transaktionen mit IDENTISCHEM Zeitstempel ---
    let prev_tx = voucher_v1.transactions.last().unwrap();
    let prev_tx_time = DateTime::parse_from_rfc3339(&prev_tx.t_time).unwrap().with_timezone(&Utc);
    let collision_time = (prev_tx_time + Duration::seconds(1)).to_rfc3339();
    let prev_tx_hash = crypto_utils::get_hash(utils::to_canonical_json(prev_tx).unwrap());

    // Erzeuge zwei UNTERSCHIEDLICHE Transaktionen vom selben Punkt mit identischem Zeitstempel.
    // Dies ist ein valides Double-Spend-Szenario und führt zu unterschiedlichen t_ids.

    // Pfad A: Ein Split-Transfer, der 99 sendet und 1 behält.
    let mut tx_a = Transaction {
        prev_hash: prev_tx_hash.clone(),
        t_type: "split".to_string(),
        t_time: collision_time.clone(),
        sender_id: id_alice.clone(),
        recipient_id: id_david.clone(),
        amount: "99.0000".to_string(),
        sender_remaining_amount: Some("1.0000".to_string()),
        ..Default::default()
    };
    tx_a = resign_transaction(tx_a, &identity_alice.signing_key);
    let mut voucher_a = voucher_v1.clone();
    voucher_a.transactions.push(tx_a.clone());

    // Pfad B: Ein vollständiger Transfer, der 100 sendet.
    let mut tx_b = Transaction {
        prev_hash: prev_tx_hash, t_type: "transfer".to_string(), t_time: collision_time,
        sender_id: id_alice.clone(), recipient_id: id_david.clone(), amount: "100".to_string(), ..Default::default()
    };
    tx_b = resign_transaction(tx_b, &identity_alice.signing_key);
    let mut voucher_b = voucher_v1.clone();
    voucher_b.transactions.push(tx_b.clone());

    let bundle_a = create_test_bundle(&identity_alice, vec![voucher_a], &id_david, None).unwrap();
    let bundle_b = create_test_bundle(&identity_alice, vec![voucher_b], &id_david, None).unwrap();

    // Sicherstellen, dass die Transaktionen unterschiedlich sind (und damit auch die Gutscheine)
    assert_ne!(tx_a.t_id, tx_b.t_id, "Conflicting transactions must have different t_ids");

    // --- 3. David empfängt beide Bundles ---
    service_david.receive_bundle(&bundle_a, &standards_map, None, "pwd").unwrap();
    service_david.receive_bundle(&bundle_b, &standards_map, None, "pwd").unwrap();

    // --- 4. Assertions ---
    let summaries_after = service_david.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_after.len(), 2, "Wallet should contain two instances");
    let active_count = summaries_after.iter().filter(|s| s.status == VoucherStatus::Active).count();
    let quarantined_count = summaries_after.iter().filter(|s| matches!(s.status, VoucherStatus::Quarantined{..})).count();
    assert_eq!(active_count, 1, "Exactly one voucher should be active (tie-break)");
    assert_eq!(quarantined_count, 1, "Exactly one voucher should be quarantined (tie-break)");
}

/// Test 2.1: Stellt sicher, dass der gesamte Zustand eines Wallets verlustfrei
/// gespeichert und wiederhergestellt werden kann.
///
/// ### Szenario:
/// 1.  Ein Wallet (`service_a`) wird erstellt und in einen komplexen Zustand versetzt:
///     - Mehrere aktive und archivierte Gutscheine.
///     - Metadaten von gesendeten und empfangenen Bundles.
/// 2.  Der Zustand wird durch die `AppService`-Operationen automatisch gespeichert.
/// 3.  Eine neue `AppService`-Instanz (`service_b`) wird für dasselbe Verzeichnis erstellt.
/// 4.  `service_b` wird entsperrt.
///
/// ### Erwartetes Ergebnis:
/// -   Der Zustand von `service_b` nach dem Laden ist identisch mit dem von `service_a`.
/// -   Abfragen wie `get_voucher_summaries` und `get_total_balance_by_currency`
///     liefern exakt dieselben Ergebnisse.
#[test]
fn api_wallet_save_and_load_fidelity() {
    // HINWEIS ZUR GETESTETEN LOGIK:
    // Dieser Test verifiziert das beabsichtigte Verhalten des Wallets bei Transfers:
    // 1. TEILTRANSFER (SPLIT): Wenn nur ein Teilbetrag eines Gutscheins gesendet wird,
    //    wird die alte Instanz durch eine neue mit dem Restguthaben ersetzt. Es findet
    //    KEINE Archivierung statt. Dies verhindert, dass gültige Gutscheine mit Restguthaben
    //    fälschlicherweise archiviert werden und spart Speicherplatz.
    // 2. VOLLSTÄNDIGER TRANSFER: Nur wenn der GESAMTE Betrag eines Gutscheins gesendet wird,
    //    wird die Instanz als "Archived" markiert, da sie vollständig verbraucht ist.

    // --- 1. Setup ---
    let dir = tempdir().unwrap();
    let test_user = &ACTORS.test_user;
    let password = "a-very-secure-password";
    let silver_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let (silver_standard, _) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);
    let mut standards_map = HashMap::new();
    standards_map.insert(silver_standard.metadata.uuid.clone(), silver_toml.clone());

    // --- 2. Wallet A in komplexen Zustand versetzen ---
    {
        let (mut service_a, _) = test_utils::setup_service_with_profile(dir.path(), test_user, "Test User A", password);
        let id_a = service_a.get_user_id().unwrap();

        // Aktive Gutscheine erstellen
        service_a
            .create_new_voucher(
                &silver_toml,
                "en",
                // KORREKTUR: Testdaten explizit machen, um Mehrdeutigkeiten zu vermeiden.
                // Wir geben die `NominalValue` vollständig an, wie sie im Standard erwartet wird.
                NewVoucherData {
                    creator: Creator { id: id_a.clone(), ..Default::default() },
                    nominal_value: NominalValue {
                        unit: "Unzen".to_string(),
                        amount: "10".to_string(),
                        abbreviation: "oz Ag".to_string(),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                password,
            )
            .unwrap();

        // --- Schritt A: Teiltransfer (Split) ---
        // Wir senden 3 von 10 Unzen. Die 10-Unzen-Instanz wird durch eine 7-Unzen-Instanz ersetzt.
        let summary = service_a.get_voucher_summaries(None, None).unwrap();
        let silver_voucher_id_10oz = summary
            .iter()
            .find(|s| s.current_amount == "10.0000" && s.status == VoucherStatus::Active)
            .expect("Silver voucher summary not found")
            .local_instance_id
            .clone();
        
        let request = voucher_lib::wallet::MultiTransferRequest {
            recipient_id: ACTORS.bob.identity.user_id.clone(),
            sources: vec![voucher_lib::wallet::SourceTransfer {
                local_instance_id: silver_voucher_id_10oz.clone(),
                amount_to_send: "3".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        };
        let mut standards_toml = std::collections::HashMap::new();
        standards_toml.insert(
            silver_standard.metadata.uuid.clone(),
            silver_toml.clone()
        );
        service_a.create_transfer_bundle(request, &standards_toml, None, password).unwrap();

        // Bundle-Metadaten durch Empfang erzeugen
        let transfer_back_bundle = {
            let dir_bob = tempdir().unwrap();
            let bob = &ACTORS.bob;
            let (mut service_bob, _) = test_utils::setup_service_with_profile(dir_bob.path(), bob, "Bob", "pwd");
            let id_bob = service_bob.get_user_id().unwrap();
            service_bob
                .create_new_voucher(
                    &silver_toml,
                    "en",
                    NewVoucherData {
                        creator: Creator { id: id_bob, ..Default::default() },
                        nominal_value: NominalValue { amount: "1".to_string(), ..Default::default() },
                        ..Default::default()
                    },
                    "pwd",
                )
                .unwrap();
            let local_id = service_bob.get_voucher_summaries(None, None).unwrap()[0].local_instance_id.clone();
            
            let request = voucher_lib::wallet::MultiTransferRequest {
                recipient_id: id_a.clone(),
                sources: vec![voucher_lib::wallet::SourceTransfer {
                    local_instance_id: local_id.clone(),
                    amount_to_send: "1".to_string(),
                }],
                notes: None,
                sender_profile_name: None,
            };

            let mut standards_toml = std::collections::HashMap::new();
            standards_toml.insert(
                silver_standard.metadata.uuid.clone(),
                silver_toml.clone()
            );

            let (bundle_bytes, _header) = service_bob.create_transfer_bundle(request, &standards_toml, None, "pwd").unwrap();
            bundle_bytes
        };
        service_a.receive_bundle(&transfer_back_bundle, &standards_map, None, password).unwrap();

        // --- Schritt B: Vollständiger Transfer ---
        // Nun senden wir die verbleibenden 7 Unzen, um die Archivierungslogik zu testen.
        let summary_before_full_transfer = service_a.get_voucher_summaries(None, None).unwrap();
        let silver_voucher_id_7oz = summary_before_full_transfer
            .iter()
            .find(|s| s.current_amount == "7.0000" && s.status == VoucherStatus::Active)
            .expect("7oz silver voucher for full transfer not found")
            .local_instance_id
            .clone();
        let request = voucher_lib::wallet::MultiTransferRequest { 
            recipient_id: ACTORS.charlie.identity.user_id.clone(), 
            sources: vec![voucher_lib::wallet::SourceTransfer { 
                local_instance_id: silver_voucher_id_7oz.clone(), 
                amount_to_send: "7".to_string(), 
            }], 
            notes: None, 
            sender_profile_name: None,
        }; 
        let mut standards_toml = std::collections::HashMap::new(); 
        standards_toml.insert( 
            silver_standard.metadata.uuid.clone(), 
            silver_toml.clone() 
        ); 
        service_a.create_transfer_bundle(request, &standards_toml, None, password).unwrap();
    } // service_a geht out of scope, Wallet wird aus dem Speicher entfernt

    // --- 3. Wallet B aus demselben Verzeichnis laden ---
    let mut service_b = AppService::new(dir.path()).unwrap();
    let profile_b = service_b.list_profiles().unwrap().pop().unwrap(); // Get the single profile
    service_b.login(&profile_b.folder_name, password, false)
        .expect("Login for service_b should succeed");

    // --- 4. Assertions ---
    let summaries = service_b.get_voucher_summaries(None, None).unwrap();

    println!("\n[Debug] Finale Gutschein-Zusammenfassungen vor der Längen-Assertion:");
    dbg!(&summaries);

    // ERWARTETER ZUSTAND:
    // - 1x Silber-Gutschein (1 Unze), der empfangen wurde -> Active
    // - 1x Silber-Gutschein (7 Unzen), der vollständig gesendet wurde -> Archived
    // Insgesamt also 2 Instanzen.
    assert_eq!(summaries.len(), 2, "Should have 2 voucher instances (1 active, 1 archived)");

    let archived_count = summaries.iter().filter(|s| s.status == VoucherStatus::Archived).count();
    let active_count = summaries.iter().filter(|s| s.status == VoucherStatus::Active).count();
    assert_eq!(active_count, 1, "Incorrect number of active vouchers found");
    assert_eq!(archived_count, 1, "Incorrect number of archived vouchers found");

    let balances = service_b.get_total_balance_by_currency().unwrap();

    // --- HINZUGEFÜGTER DEBUG-PRINT ---
    // Dieser Print zeigt den exakten Inhalt der `balances`-Map.
    // Erwartete Ausgabe: {"Oz": "1.0000"}
    println!("\n[Debug] Inhalt der Salden-Map:");
    dbg!(&balances);

    // ERWARTETE BILANZ:
    // 10 (start) - 3 (gesendet) + 1 (empfangen) - 7 (gesendet) = 1
    // KORREKTUR: Der Test muss auf die korrekte Einheit "Oz" prüfen, die aus dem Standard geladen wird.
    let silver_balance = balances
        .iter()
        .find(|b| b.unit == "Oz") // Korrigierte Abkürzung basierend auf Debug-Logs.
        .map(|b| b.total_amount.as_str());

    assert_eq!(
        silver_balance,
        Some("1.0000"),
        "Silver balance mismatch"
    );

    let minuto_balance_exists = balances.iter().any(|b| b.unit == "Min");
    assert!(!minuto_balance_exists, "Minuto balance should not exist as it was never created");
}


/// Test 6.1: Verifiziert, dass `create_new_voucher` exakt eine Instanz hinzufügt.
///
/// ### Szenario:
/// 1.  Ein neues, leeres Wallet wird erstellt.
/// 2.  Der Zustand wird überprüft, um sicherzustellen, dass es leer ist (Assertion Zero).
/// 3.  `create_new_voucher` wird genau einmal aufgerufen.
/// 4.  Der Zustand wird erneut überprüft.
///
/// ### Erwartetes Ergebnis:
/// -   Nach dem Aufruf darf sich nur exakt ein Gutschein im Wallet befinden.
/// -   Dieser Test hätte den "Double-Add"-Bug direkt aufgedeckt.
#[test]
fn test_create_voucher_adds_exactly_one_instance() {
    // 1. ARRANGE: Testumgebung und Anfangszustand herstellen
    let test_user = &ACTORS.test_user;
    let password = "test_password_123";
    let dir = tempdir().expect("Failed to create temp dir");
    let (mut app_service, _) = test_utils::setup_service_with_profile(dir.path(), test_user, "Test User", password);
    let user_id = app_service.get_user_id().unwrap();

    // Assertion Zero: Sicherstellen, dass das Wallet initial leer ist.
    let initial_summaries = app_service.get_voucher_summaries(None, None).unwrap();
    assert_eq!(initial_summaries.len(), 0, "Wallet should be empty at the beginning");

    // KORREKTUR: Umstellung auf den bewährten und vollständigen Silber-Standard.
    let standard_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");

    // KORREKTUR: NewVoucherData um die obligatorische `validity_duration` ergänzt.
    let voucher_data = NewVoucherData {
        creator: Creator { id: user_id, ..Default::default() },
        nominal_value: NominalValue { amount: "100".to_string(), ..Default::default() },
        // Die 'description' kommt aus dem Standard, nicht aus NewVoucherData.
        validity_duration: Some("P1Y".to_string()), // Gültigkeit von 1 Jahr hinzufügen
        ..Default::default()
    };

    // 2. ACT: Die Ziel-Funktion ausführen
    let created_voucher = app_service
        .create_new_voucher(&standard_toml, "de", voucher_data.clone(), password)
        .expect("Voucher creation failed");

    // 3. ASSERT: Das Ergebnis und den neuen Zustand überprüfen
    let final_summaries = app_service.get_voucher_summaries(None, None).unwrap();

    // DIE KERN-ASSERTION, die den Bug findet:
    assert_eq!(final_summaries.len(), 1, "There should be exactly one voucher in the wallet after creation");

    // Zusätzliche Prüfung der Datenintegrität
    let summary = &final_summaries[0];
    assert_eq!(summary.current_amount, "100.0000"); // Betrag wird kanonisiert

    // KORREKTUR: Die erwartete Beschreibung muss nun zum Silber-Standard passen.
    let expected_description = "Dieser Gutschein dient als Zahlungsmittel für Waren oder Dienstleistungen im Wert von 100 Unzen Silber.";
    assert_eq!(created_voucher.description, expected_description, "The description from the silver standard template was not applied correctly.");
}


/// Test 6.2: Stellt sicher, dass `create_new_voucher` transaktional ist.
///
/// ### Szenario:
/// 1.  Ein leeres Wallet wird erstellt.
/// 2.  Es wird versucht, einen Gutschein mit einem **falschen Passwort** zu erstellen.
///     - Die Operation muss fehlschlagen.
///     - Das Wallet muss danach immer noch leer sein.
/// 3.  Anschließend wird ein Gutschein mit dem **richtigen Passwort** erstellt.
///
/// ### Erwartetes Ergebnis:
/// -   Nach allen Operationen darf sich nur **ein einziger** Gutschein im Wallet befinden.
/// -   Dieser Test findet den Fehler, bei dem ein fehlgeschlagener Speicherversuch
///     den In-Memory-Zustand "schmutzig" hinterlässt.
#[test]
fn test_create_voucher_is_transactional_on_save_failure() {
    // 1. ARRANGE
    let test_user = &ACTORS.test_user;
    let correct_password = "correct_password";
    let wrong_password = "wrong_password";
    let dir = tempdir().expect("Failed to create temp dir");
    let (mut app_service, _) = test_utils::setup_service_with_profile(dir.path(), test_user, "Test User", correct_password);
    let user_id = app_service.get_user_id().unwrap();

    let standard_toml = generate_signed_standard_toml("voucher_standards/silver_v1/standard.toml");
    let voucher_data = NewVoucherData {
        creator: Creator { id: user_id, ..Default::default() },
        nominal_value: NominalValue { amount: "50".to_string(), ..Default::default() },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    // 2. ACT 1: Versuche, mit falschem Passwort zu erstellen
    let creation_result_fail = app_service
        .create_new_voucher(&standard_toml, "de", voucher_data.clone(), wrong_password);

    // 3. ASSERT 1: Operation ist fehlgeschlagen und Wallet ist immer noch leer
    assert!(creation_result_fail.is_err(), "Creation with wrong password should fail");
    let summaries_after_fail = app_service.get_voucher_summaries(None, None).unwrap();
    assert_eq!(summaries_after_fail.len(), 0, "Wallet should still be empty after a failed save");

    // 4. ACT 2: Erstelle einen Gutschein mit dem korrekten Passwort
    app_service
        .create_new_voucher(&standard_toml, "de", voucher_data.clone(), correct_password)
        .expect("Voucher creation with correct password should succeed");

    // 5. ASSERT 2 (FINAL): Es befindet sich nur EIN Gutschein im Wallet
    let final_summaries = app_service.get_voucher_summaries(None, None).unwrap();
    assert_eq!(final_summaries.len(), 1, "There should be exactly one voucher in the wallet after one failed and one successful creation");
}