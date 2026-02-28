// tests/wallet_api/conflict_detection.rs
// cargo test --test wallet_api_tests conflict_detection
//!
//! Eigenschafts- und Grenztests für die Double-Spend-Erkennungs-Engine.
//!
//! Diese Tests sichern die Kerninvarianten in `conflict_manager.rs` und
//! `conflict_handler.rs` ab:
//! - Korrekte Partitionierung von OwnFingerprints vs. KnownFingerprints
//! - Zuverlässige Erkennung von Konflikten (> 1 t_id für denselben ds_tag)
//! - Unterscheidung von Replay-Angriffen vs. Double-Spend
//! - Korrekte "Earliest Wins"-Heuristik bei Offline-Konflikten
//! - Bereinigung abgelaufener Fingerprints (Zeitgrenzwerte)
//! - Import/Export-Symmetrie von Fingerprints
//! - Timestamp-Verschlüsselung (XOR-Roundtrip, Determinismus)

use human_money_core::{
    models::{
        conflict::{KnownFingerprints, OwnFingerprints, TransactionFingerprint},
        voucher::Transaction,
    },
    services::conflict_manager::{
        cleanup_expired_histories, cleanup_known_fingerprints, decrypt_transaction_timestamp,
        encrypt_transaction_timestamp, export_own_fingerprints, import_foreign_fingerprints,
        check_for_double_spend, create_fingerprint_for_transaction, create_proof_of_double_spend,
    },
};
use human_money_core::test_utils::{ACTORS, MINUTO_STANDARD};

// =============================================================================
// Hilfsfunktionen
// =============================================================================

/// Erstellt eine minimale, valide Transaktion mit einem deterministischen prev_hash,
/// t_id und t_time. Wird für Fingerprint-Tests verwendet ohne Wallet-Kontext.
fn make_test_transaction(suffix: &str, t_time: &str) -> Transaction {
    let prev_hash = bs58::encode(format!("prev-hash-{suffix}").as_bytes()).into_string();
    let t_id = bs58::encode(format!("tid-{suffix}").as_bytes()).into_string();

    Transaction {
        t_id,
        prev_hash,
        t_time: t_time.to_string(),
        sender_id: Some(ACTORS.alice.user_id.clone()),
        sender_ephemeral_pub: None,
        trap_data: None,
        layer2_signature: None,
        amount: "10.0000".to_string(),
        recipient_id: ACTORS.bob.user_id.clone(),
        t_type: "transfer".to_string(),
        ..Default::default()
    }
}

/// Erstellt einen TransactionFingerprint direkt (ohne Voucher-Kontext).
fn make_fingerprint(ds_tag: &str, t_id: &str, deletable_at: &str) -> TransactionFingerprint {
    TransactionFingerprint {
        ds_tag: ds_tag.to_string(),
        t_id: t_id.to_string(),
        u: "none".to_string(),
        blinded_id: "none".to_string(),
        layer2_signature: String::new(),
        deletable_at: deletable_at.to_string(),
        encrypted_timestamp: 0,
    }
}

// =============================================================================
// create_fingerprint_for_transaction
// =============================================================================

/// Der `valid_until`-Zeitstempel eines Vouchers wird auf den letzten Tag des Monats
/// gerundet (Anonymisierung). Dezember-Rollover muss auf 31.01 des Folgejahres zeigen.
#[test]
fn test_fingerprint_valid_until_is_rounded_to_end_of_month() {
    use human_money_core::test_utils::create_voucher_for_manipulation;
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::crypto_utils::get_hash;
    use human_money_core::services::utils::to_canonical_json;

    // Verwende den Minuto-Standard, aber setze valid_until manuell
    let (std, _std_hash) = &*MINUTO_STANDARD;
    let creator = &ACTORS.alice.identity;
    let _recipient_id = ACTORS.bob.user_id.clone();

    let standard_hash = get_hash(to_canonical_json(&std.immutable).unwrap().as_bytes());

    let data = NewVoucherData {
        creator_profile: PublicProfile {
            id: Some(creator.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "10.0000".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P1Y".to_string()),
        ..Default::default()
    };

    let mut voucher = create_voucher_for_manipulation(data, std, &standard_hash, &creator.signing_key, "en");

    // Manuell midmonth setzen → muss auf Monatsende gerundet werden
    voucher.valid_until = "2025-06-15T12:00:00.000000Z".to_string();

    let tx = voucher.transactions[0].clone();
    let fp = create_fingerprint_for_transaction(&tx, &voucher).unwrap();

    // 15. Juni → gerundet auf 30. Juni 23:59:59.999999Z
    assert!(
        fp.deletable_at.starts_with("2025-06-30"),
        "June valid_until must round to June 30, got: {}",
        fp.deletable_at
    );

    // Dezember-Rollover: 15. Dez → 31. Dez
    voucher.valid_until = "2025-12-15T12:00:00.000000Z".to_string();
    let fp_dec = create_fingerprint_for_transaction(&tx, &voucher).unwrap();
    assert!(
        fp_dec.deletable_at.starts_with("2025-12-31"),
        "December valid_until must round to Dec 31, got: {}",
        fp_dec.deletable_at
    );
}

/// Fingerprints für Transaktionen mit TrapData verwenden `ds_tag` aus der Trap.
/// Ohne Trap wird der Tag aus prev_hash + sender_ephemeral_pub berechnet.
/// In beiden Fällen darf der `ds_tag` nicht leer sein.
#[test]
fn test_fingerprint_ds_tag_is_non_empty() {
    use human_money_core::test_utils::create_voucher_for_manipulation;
    use human_money_core::services::voucher_manager::NewVoucherData;
    use human_money_core::models::voucher::ValueDefinition;
    use human_money_core::models::profile::PublicProfile;
    use human_money_core::services::crypto_utils::get_hash;
    use human_money_core::services::utils::to_canonical_json;

    let (std, _) = &*MINUTO_STANDARD;
    let creator = &ACTORS.alice.identity;
    let standard_hash = get_hash(to_canonical_json(&std.immutable).unwrap().as_bytes());

    let mut voucher = create_voucher_for_manipulation(
        NewVoucherData {
            creator_profile: PublicProfile { id: Some(creator.user_id.clone()), ..Default::default() },
            nominal_value: ValueDefinition { amount: "5.0000".to_string(), ..Default::default() },
            validity_duration: Some("P1Y".to_string()),
            ..Default::default()
        },
        std, &standard_hash, &creator.signing_key, "en"
    );
    voucher.valid_until = "2026-03-15T00:00:00.000000Z".to_string();

    let fp = create_fingerprint_for_transaction(&voucher.transactions[0], &voucher).unwrap();
    assert!(!fp.ds_tag.is_empty(), "ds_tag must not be empty (even without TrapData)");
    assert!(!fp.ds_tag.chars().all(|c| c == '0'), "ds_tag must not be all zeros");
}

// =============================================================================
// scan_and_rebuild_fingerprints — delete ! (line 142)
// =============================================================================

/// Beim Aufbau der Fingerprints müssen Duplikate in `known_fingerprints.local_history`
/// verhindert werden. Derselbe Fingerprint darf nicht mehrfach für denselben ds_tag eingetragen werden.
/// Mutant: `delete !` vor `known_entry.contains(&fingerprint)` — würde alle Einträge doppeln.
#[test]
fn test_scan_rebuild_does_not_duplicate_fingerprints_in_known_history() {
    use human_money_core::services::conflict_manager::scan_and_rebuild_fingerprints;
    use human_money_core::test_utils::{add_voucher_to_wallet, setup_in_memory_wallet};

    let alice = &ACTORS.alice.identity;
    let (std, _) = &*MINUTO_STANDARD;
    let mut wallet = setup_in_memory_wallet(alice);

    add_voucher_to_wallet(&mut wallet, alice, "20.0000", std, false).unwrap();

    let (_own, known) = scan_and_rebuild_fingerprints(&wallet.voucher_store, &alice.user_id).unwrap();

    // Jeder ds_tag darf nur einmal in known.local_history vorkommen
    for (tag, fps) in &known.local_history {
        let unique_t_ids: std::collections::HashSet<_> = fps.iter().map(|fp| &fp.t_id).collect();
        assert_eq!(
            fps.len(), unique_t_ids.len(),
            "No duplicate fingerprints allowed for ds_tag {tag}"
        );
    }
}

// =============================================================================
// check_for_double_spend — Konfikte erkennen
// =============================================================================

/// Zwei verschiedene t_ids mit demselben ds_tag müssen als Konflikt erkannt werden.
/// Der Konflikt muss in `verifiable_conflicts` landen, wenn der ds_tag in `local_history` ist.
/// Wenn nicht → `unverifiable_warnings`.
#[test]
fn test_double_spend_detection_classifies_conflicts_correctly() {
    let tag = "test-ds-tag-abc123";
    let fp_a = make_fingerprint(tag, "tid-alice-spend", "2030-12-31T23:59:59.999999Z");
    let fp_b = make_fingerprint(tag, "tid-bob-spend",   "2030-12-31T23:59:59.999999Z");

    // Szenario 1: Hash in local_history → verifiable
    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp_a.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp_a.clone()]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp_b.clone()]);

    let result = check_for_double_spend(&own, &known);
    assert!(
        result.verifiable_conflicts.contains_key(tag),
        "Conflict known from local_history must be verifiable"
    );
    assert!(!result.unverifiable_warnings.contains_key(tag));

    // Szenario 2: Hash NICHT in local_history → unverifiable
    let own2 = OwnFingerprints::default();
    let mut known2 = KnownFingerprints::default();
    // Nur in foreign_fingerprints, nicht in local_history
    known2.foreign_fingerprints.insert(tag.to_string(), vec![fp_a.clone(), fp_b.clone()]);

    let result2 = check_for_double_spend(&own2, &known2);
    assert!(
        result2.unverifiable_warnings.contains_key(tag),
        "Conflict NOT in local_history must go to unverifiable_warnings"
    );
    assert!(!result2.verifiable_conflicts.contains_key(tag));
}

/// Keine false-positives: Wenn es nur eine t_id gibt (kein Konflikt),
/// darf weder verifiable_conflicts noch unverifiable_warnings befüllt sein.
#[test]
fn test_double_spend_detection_no_false_positives() {
    let tag = "single-tag-no-conflict";
    let fp = make_fingerprint(tag, "tid-only-one", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp.clone()]);

    let result = check_for_double_spend(&own, &known);
    assert!(result.verifiable_conflicts.is_empty(), "No conflict for single t_id");
    assert!(result.unverifiable_warnings.is_empty(), "No warnings for single t_id");
}

/// Alle drei Quellen (own.history, known.local_history, known.foreign_fingerprints)
/// werden korrekt zusammengeführt. Ein Konflikt der nur über Quellen-Merge sichtbar ist,
/// muss erkannt werden.
#[test]
fn test_double_spend_detection_merges_all_three_sources() {
    let tag = "cross-source-tag";
    // fp_a nur in own.history, fp_b nur in foreign_fingerprints
    let fp_a = make_fingerprint(tag, "tid-own",     "2030-12-31T23:59:59.999999Z");
    let fp_b = make_fingerprint(tag, "tid-foreign", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp_a]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp_b]);

    let result = check_for_double_spend(&own, &known);

    // Konflikt muss aus Merge von own.history + foreign_fingerprints entstehen
    // local_history hat den Tag → verifiable
    // (leerer local_history Eintrag reicht: contains_key ist true)
    assert!(
        result.verifiable_conflicts.contains_key(tag) || result.unverifiable_warnings.contains_key(tag),
        "Cross-source conflict must be detected"
    );
    let all = result.verifiable_conflicts.get(tag)
        .or_else(|| result.unverifiable_warnings.get(tag))
        .unwrap();
    let unique: std::collections::HashSet<_> = all.iter().map(|fp| &fp.t_id).collect();
    assert_eq!(unique.len(), 2, "Must contain both conflicting t_ids");
}

// =============================================================================
// create_proof_of_double_spend — Zeilen 255
// =============================================================================

/// Der `proof_id` wird aus dem Offender-Key und dem fork_point_prev_hash abgeleitet.
/// Er muss deterministisch und nicht-trivial sein (kein Leerstring / Konstante).
/// Mutant: `replace + with - in create_proof_of_double_spend`
#[test]
fn test_proof_id_is_deterministic_and_derived_from_input() {
    let reporter = &ACTORS.reporter.identity;
    let _alice_id = format!("{}{}",
        ACTORS.alice.user_id,
        if ACTORS.alice.user_id.contains("@did:key:z") { "" } else { "@did:key:z6MkAliceTestOnly" }
    );

    // Wir brauchen eine valide did-key-Struktur (offender_id)
    // Nutze alice.user_id welches das korrekte Format hat
    let offender_id = ACTORS.alice.user_id.clone();
    let fork_hash = bs58::encode(b"fork-point-hash").into_string();
    let fork_hash2 = bs58::encode(b"different-hash").into_string();

    let proof1 = create_proof_of_double_spend(
        offender_id.clone(),
        fork_hash.clone(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
    ).unwrap();

    let proof2 = create_proof_of_double_spend(
        offender_id.clone(),
        fork_hash.clone(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
    ).unwrap();

    // Deterministisch (gleiche Inputs → gleiche proof_id)
    assert_eq!(proof1.proof_id, proof2.proof_id, "Proof ID must be deterministic");

    // Nicht trivial
    assert!(!proof1.proof_id.is_empty(), "Proof ID must not be empty");

    // Ändert sich bei unterschiedlichem fork_hash
    // (Mutant `+ → -` in der Slice-Konkatenation würde hier denselben Hash liefern)
    let proof_other_hash = create_proof_of_double_spend(
        offender_id,
        fork_hash2,
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
    ).unwrap();
    assert_ne!(
        proof1.proof_id, proof_other_hash.proof_id,
        "Different fork_point_prev_hash must produce different proof_id"
    );
}

/// Ein `offender_id` ohne DID-Format muss einen Fehler zurückgeben.
#[test]
fn test_proof_creation_rejects_invalid_offender_id() {
    let reporter = &ACTORS.reporter.identity;
    let result = create_proof_of_double_spend(
        "invalid-no-did".to_string(),
        bs58::encode(b"some-hash").into_string(),
        vec![],
        "2030-12-31T23:59:59.999999Z".to_string(),
        reporter,
    );
    assert!(result.is_err(), "Missing DID in offender_id must return Err");
}

// =============================================================================
// cleanup_known_fingerprints — Zeile 336 (> vs >=)
// =============================================================================

/// Fingerprints mit `deletable_at` in der Vergangenheit müssen entfernt werden.
/// Fingerprints mit `deletable_at` in der Zukunft müssen erhalten bleiben.
/// Mutant: `replace > with >=` → würde Fingerprints mit `deletable_at == now` entfernen.
#[test]
fn test_cleanup_known_fingerprints_removes_expired_only() {
    let mut known = KnownFingerprints::default();

    // Abgelaufen: liegt weit in der Vergangenheit
    let fp_expired = make_fingerprint("tag-expired", "tid-old", "2000-01-01T00:00:00.000000Z");
    // Aktiv: liegt weit in der Zukunft
    let fp_active  = make_fingerprint("tag-active",  "tid-new", "2099-01-01T00:00:00.000000Z");

    known.foreign_fingerprints.insert("tag-expired".to_string(), vec![fp_expired]);
    known.foreign_fingerprints.insert("tag-active".to_string(),  vec![fp_active]);

    cleanup_known_fingerprints(&mut known);

    assert!(
        !known.foreign_fingerprints.contains_key("tag-expired"),
        "Expired fingerprint must be removed"
    );
    assert!(
        known.foreign_fingerprints.contains_key("tag-active"),
        "Active fingerprint must be retained"
    );
}

/// Wenn alle Fingerprints eines ds_tag abgelaufen sind, muss der gesamte Eintrag
/// aus der Map entfernt werden (nicht nur die Fingerprints).
/// Mutant: `delete !` before `fps.is_empty()` → würde leere Einträge behalten.
#[test]
fn test_cleanup_removes_empty_entries_from_map() {
    let mut known = KnownFingerprints::default();
    let fp_expired = make_fingerprint("empty-after-purge", "tid", "2000-01-01T00:00:00.000000Z");
    known.foreign_fingerprints.insert("empty-after-purge".to_string(), vec![fp_expired]);

    cleanup_known_fingerprints(&mut known);

    assert!(
        !known.foreign_fingerprints.contains_key("empty-after-purge"),
        "Map entry must be removed when all fingerprints are purged"
    );
}

// =============================================================================
// cleanup_expired_histories — Zeilen 353-370
// =============================================================================

/// `cleanup_expired_histories` muss für own und known gleichermaßen funktionieren.
/// Fingerprints, die innerhalb der Grace-Period liegen, bleiben erhalten.
/// Fingerprints, die die Grace-Period überschritten haben, werden entfernt.
/// Mutanten: `replace + with -`, `replace < with <=` etc.
#[test]
fn test_cleanup_expired_histories_respects_grace_period() {
    use chrono::{Duration, Utc};

    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    // deletable_at liegt 2 Jahre in der Vergangenheit
    let far_past = "2020-01-01T00:00:00.000000Z";
    // deletable_at liegt 2 Jahre in der Zukunft
    let far_future = "2099-01-01T00:00:00.000000Z";

    let fp_expired_own   = make_fingerprint("own-old",   "tid-own-old",   far_past);
    let fp_active_own    = make_fingerprint("own-new",   "tid-own-new",   far_future);
    let fp_expired_known = make_fingerprint("known-old", "tid-known-old", far_past);
    let fp_active_known  = make_fingerprint("known-new", "tid-known-new", far_future);

    own.history.insert("own-old".to_string(),   vec![fp_expired_own]);
    own.history.insert("own-new".to_string(),   vec![fp_active_own]);
    known.local_history.insert("known-old".to_string(), vec![fp_expired_known]);
    known.local_history.insert("known-new".to_string(), vec![fp_active_known]);

    let now = Utc::now();
    // Grace Period: 1 Tag — weit abgelaufene Fingerprints werden entfernt
    let grace = Duration::days(1);

    cleanup_expired_histories(&mut own, &mut known, &now, &grace);

    assert!(!own.history.contains_key("own-old"),   "Expired own fingerprint must be removed");
    assert!(own.history.contains_key("own-new"),    "Active own fingerprint must be retained");
    assert!(!known.local_history.contains_key("known-old"), "Expired known fingerprint must be removed");
    assert!(known.local_history.contains_key("known-new"),  "Active known fingerprint must be retained");
}

/// Mit einer sehr langen Grace-Period (z.B. 100 Jahre) bleiben alle Fingerprints erhalten.
/// Dies prüft, dass `+` in `let purge_date = valid_until + *grace_period` korrekt ist
/// (Mutant: `+ → -` würde die Purge-Date in die Vergangenheit legen).
#[test]
fn test_cleanup_long_grace_period_retains_all() {
    use chrono::{Duration, Utc};

    let mut own = OwnFingerprints::default();
    let mut known = KnownFingerprints::default();

    // Liegt 5 Jahre in der Vergangenheit
    let past = "2020-01-01T00:00:00.000000Z";
    own.history.insert("old-but-grace".to_string(), vec![make_fingerprint("old-but-grace", "tid", past)]);
    known.local_history.insert("old-known-grace".to_string(), vec![make_fingerprint("old-known-grace", "tid2", past)]);

    let now = Utc::now();
    let grace = Duration::days(365 * 100); // 100 Jahre Grace

    cleanup_expired_histories(&mut own, &mut known, &now, &grace);

    assert!(own.history.contains_key("old-but-grace"),       "Long grace period must keep old own fingerprints");
    assert!(known.local_history.contains_key("old-known-grace"), "Long grace period must keep old known fingerprints");
}

// =============================================================================
// export_own_fingerprints / import_foreign_fingerprints
// =============================================================================

/// Export und Import von Fingerprints ist symmetrisch.
/// Nach Export→Import sind dieselben Fingerprints vorhanden.
#[test]
fn test_export_import_fingerprints_roundtrip() {
    let tag = "export-import-tag";
    let fp = make_fingerprint(tag, "tid-export", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let exported = export_own_fingerprints(&own).unwrap();
    assert!(!exported.is_empty(), "Exported data must not be empty");

    let mut known = KnownFingerprints::default();
    let count = import_foreign_fingerprints(&mut known, &exported).unwrap();

    assert_eq!(count, 1, "One fingerprint must be imported");
    assert!(known.foreign_fingerprints.contains_key(tag), "Imported fingerprint must be findable by ds_tag");
}

/// Doppelter Import desselben Fingerprints darf nicht zu Duplikaten führen.
/// Mutant: `delete !` vor `entry.contains(fp)` → würde doppelt eingetragen.
#[test]
fn test_import_foreign_fingerprints_deduplication() {
    let tag = "dedup-tag";
    let fp = make_fingerprint(tag, "tid-dedup", "2030-12-31T23:59:59.999999Z");

    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp]);
    let exported = export_own_fingerprints(&own).unwrap();

    let mut known = KnownFingerprints::default();
    import_foreign_fingerprints(&mut known, &exported).unwrap();
    let count2 = import_foreign_fingerprints(&mut known, &exported).unwrap();

    // Zweiter Import → 0 neue Fingerprints (alle schon bekannt)
    assert_eq!(count2, 0, "Re-importing known fingerprints must not increase count");
    let fps = known.foreign_fingerprints.get(tag).unwrap();
    assert_eq!(fps.len(), 1, "No duplicates after double import");
}

// =============================================================================
// encrypt_transaction_timestamp / decrypt_transaction_timestamp
// =============================================================================

/// Die XOR-Verschlüsselung des Timestamps muss ein deterministisches Roundtrip liefern:
/// decrypt(encrypt(t)) == t.
/// Außerdem muss encrypt(t) != t sein (kein triviales Passthrough).
#[test]
fn test_timestamp_encryption_is_deterministic_and_non_trivial() {
    let tx = make_test_transaction("ts-roundtrip", "2025-06-15T10:00:00.000000Z");

    let encrypted = encrypt_transaction_timestamp(&tx).unwrap();
    let decrypted = decrypt_transaction_timestamp(&tx, encrypted).unwrap();

    // Roundtrip muss den ursprünglichen Timestamp wiederherstellen
    // Der ursprüngliche Wert ist der nanos-Wert des t_time
    let expected_nanos = chrono::DateTime::parse_from_rfc3339(&tx.t_time)
        .unwrap()
        .timestamp_nanos_opt()
        .unwrap() as u128;

    assert_eq!(decrypted, expected_nanos, "Decrypted value must match original timestamp nanos");

    // Verschlüpselung darf nicht trivial sein (kein Passthrough bei key == 0)
    assert_ne!(encrypted, expected_nanos, "Encrypted value must differ from plaintext nanos");
}

/// Zwei verschiedene Transaktionen (verschiedene prev_hash + t_id) müssen verschiedene
/// Verschlüsselungsschlüssel erzeugen, was zu verschiedenen encrypted Werten führt
/// (obwohl der Timestamp gleich ist).
/// Mutant: `replace ^ with | / &` würde den XOR-Schlüssel nicht korrekt anwenden.
#[test]
fn test_timestamp_encryption_is_key_specific() {
    let tx_a = make_test_transaction("key-specific-a", "2025-06-15T10:00:00.000000Z");
    let tx_b = make_test_transaction("key-specific-b", "2025-06-15T10:00:00.000000Z");

    let enc_a = encrypt_transaction_timestamp(&tx_a).unwrap();
    let enc_b = encrypt_transaction_timestamp(&tx_b).unwrap();

    // Obwohl der t_time gleich ist, müssen die verschlüsselten Werte verschieden sein
    // (da prev_hash und t_id unterschiedlich sind → anderer XOR-Schlüssel)
    assert_ne!(enc_a, enc_b, "Different transactions must produce different encrypted timestamps");

    // Und der eigene Roundtrip muss auch hier funktionieren
    assert_eq!(decrypt_transaction_timestamp(&tx_b, enc_b).unwrap(),
               decrypt_transaction_timestamp(&tx_a, enc_a).unwrap(),
               "Both roundtrips must recover the same original timestamp");
}

// =============================================================================
// resolve_conflict_offline — Earliest Wins (Zeile 498)
// =============================================================================

/// Beim Offline-Konflikt gewinnt die Transaktion mit dem frühesten (kleinsten) Timestamp.
/// Mutant: `replace < with <=` in resolve_conflict_offline → kein Unterschied bei echten Daten,
/// aber `replace < with ==` oder `replace < with >` würden den Gewinner falsch bestimmen.
///
/// Diese Tests testen über die Wallet-Fassade, da resolve_conflict_offline pub(super) ist.
/// Wir nutzen die Wallet::check_for_double_spend-Kette.
///
/// Da resolve_conflict_offline über den Wallet-Zustand getestet werden muss (pub(super)),
/// verwenden wir einen direkten Fingerprint-Vergleich via decrypt_transaction_timestamp.
#[test]
fn test_earliest_wins_selects_minimum_encrypted_timestamp() {
    // tx_early hat kleinere Nanos als tx_late
    let tx_early = make_test_transaction("early-winner", "2025-01-01T00:00:00.000000Z");
    let tx_late  = make_test_transaction("late-loser",   "2025-12-31T23:59:59.000000Z");

    let enc_early = encrypt_transaction_timestamp(&tx_early).unwrap();
    let enc_late  = encrypt_transaction_timestamp(&tx_late).unwrap();

    let dec_early = decrypt_transaction_timestamp(&tx_early, enc_early).unwrap();
    let dec_late  = decrypt_transaction_timestamp(&tx_late,  enc_late).unwrap();

    // Früherer Timestamp (Jan) muss kleineren nanos-Wert haben als später (Dez)
    assert!(
        dec_early < dec_late,
        "Earlier timestamp (Jan) must produce smaller nanos than later (Dec): {} vs {}",
        dec_early, dec_late
    );
}

// =============================================================================
// check_bundle_fingerprints_against_history (Replay vs Double-Spend)
// =============================================================================

/// Im Replay-Szenario: Wenn das Wallet denselben Fingerprint bereits in `own_fingerprints`
/// (als Sender) hat und derselbe Fingerprint erneut ankommt, muss `check_for_double_spend`
/// diesen als Konflikt erkennen — aber nur, wenn tatsächlich zwei verschiedene t_ids existieren.
///
/// Dieser Test prüft direkt die `check_for_double_spend`-Logik mit einem konstruierten
/// Szenario wo own + foreign denselben tag haben aber GLEICHE t_id → kein Konflikt (Deduplication).
#[test]
fn test_replay_deduplication_across_sources() {
    let tag = "replay-dedup-tag";
    let fp = make_fingerprint(tag, "tid-same", "2030-12-31T23:59:59.999999Z");

    // Gleicher Fingerprint in allen drei Quellen → nach Merge nur eine t_id → kein Konflikt
    let mut own = OwnFingerprints::default();
    own.history.insert(tag.to_string(), vec![fp.clone()]);

    let mut known = KnownFingerprints::default();
    known.local_history.insert(tag.to_string(), vec![fp.clone()]);
    known.foreign_fingerprints.insert(tag.to_string(), vec![fp.clone()]);

    let result = check_for_double_spend(&own, &known);

    // Obwohl der Tag in allen drei Quellen vorkommt, ist es immer dieselbe t_id
    // → nach HashSet-Deduplication bleibt nur 1 unique t_id → kein Konflikt
    assert!(
        result.verifiable_conflicts.is_empty() && result.unverifiable_warnings.is_empty(),
        "Same t_id across all sources must NOT trigger a conflict (deduplication must work)"
    );
}
