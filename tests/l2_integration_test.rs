// use human_money_core::app_service::AppService;
use human_money_core::models::layer2_api::{
    L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;
use human_money_core::models::voucher_standard_definition::PrivacySettings;
use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::test_utils::{self, ACTORS, SILVER_STANDARD, create_custom_standard};
use human_money_core::wallet::instance::VoucherStatus;
use std::collections::HashMap;
use tempfile::tempdir;

// --- Mock L2 Node ---
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashSet;

pub struct MockL2Node {
    // Simuliert den RAM-Bloom-Filter (Voucher IDs)
    vouchers: HashSet<String>,
    // Simuliert die L2-Datenbank (Key-Value)
    // Key: ds_tag (Base58), Value: L2LockEntry
    locks: HashMap<String, HashMap<String, human_money_core::models::layer2_api::L2LockEntry>>,
    // Simuliert das UTXO Modell für P2PKH Anker
    spendable_outputs: HashSet<[u8; 32]>,
    // Der private Schlüssel des L2-Servers zur Signatur der Urteile
    server_key: SigningKey,
}

impl MockL2Node {
    pub fn new() -> Self {
        Self {
            vouchers: HashSet::new(),
            locks: HashMap::new(),
            spendable_outputs: HashSet::new(),
            server_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }

    pub fn get_server_pubkey(&self) -> [u8; 32] {
        self.server_key.verifying_key().to_bytes()
    }

    fn wrap_and_sign(&self, verdict: L2Verdict) -> Vec<u8> {
        let verdict_serialized = serde_json::to_vec(&verdict).unwrap();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&verdict_serialized);
        let verdict_hash = hasher.finalize();

        let signature = self.server_key.sign(&verdict_hash);

        let envelope = L2ResponseEnvelope {
            verdict,
            server_signature: signature.to_bytes(),
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    pub fn handle_lock_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest = serde_json::from_slice(req_bytes).unwrap();

        // --- 1. Autorität Prüfen (layer2_signature) ---
        let ephem_key = VerifyingKey::from_bytes(&req.sender_ephemeral_pub)
            .expect("Invalid sender_ephemeral_pub key format");
        let signature = Signature::from_bytes(&req.layer2_signature);

        let payload_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash(&req);

        if !human_money_core::is_signature_bypass_active()
            && ephem_key.verify(&payload_hash, &signature).is_err()
        {
            let verdict = L2Verdict::Rejected {
                reason: "Invalid signature".to_string(),
            };
            return self.wrap_and_sign(verdict);
        }

        // Register Voucher in "Bloom Filter"
        self.vouchers.insert(req.layer2_voucher_id.clone());

        let ds_tag = if req.is_genesis {
            // Bei Genesis nutzen wir die t_id als Key (da kein ds_tag vorhanden)
            bs58::encode(req.transaction_hash).into_string()
        } else {
            match &req.ds_tag {
                Some(ds) => ds.clone(),
                None => {
                    let verdict = L2Verdict::Rejected {
                        reason: "Non-genesis must have ds_tag".to_string(),
                    };
                    return self.wrap_and_sign(verdict);
                }
            }
        };

        // --- 2. Double Spend Check via ds_tag ---
        let voucher_locks = self.locks.entry(req.layer2_voucher_id.clone()).or_default();
        if let Some(entry) = voucher_locks.get(&ds_tag) {
            // Wir geben den Beweis zurück
            let verdict = L2Verdict::Verified {
                lock_entry: entry.clone(),
            };
            return self.wrap_and_sign(verdict);
        }

        let entry = human_money_core::models::layer2_api::L2LockEntry {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            deletable_at: req.deletable_at.clone(),
        };
        voucher_locks.insert(ds_tag, entry);

        // Add new UTXOs
        if let Some(r) = req.receiver_ephemeral_pub_hash {
            self.spendable_outputs.insert(r);
        }
        if let Some(c) = req.change_ephemeral_pub_hash {
            self.spendable_outputs.insert(c);
        }

        let verdict = L2Verdict::Ok {
            signature: [0u8; 64],
        };
        self.wrap_and_sign(verdict)
    }

    pub fn handle_status_query(&self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2StatusQuery = serde_json::from_slice(req_bytes).unwrap();

        // 1. Bloom Filter Check
        if !self.vouchers.contains(&req.layer2_voucher_id) {
            let verdict = L2Verdict::UnknownVoucher;
            return self.wrap_and_sign(verdict);
        }

        let voucher_locks = self.locks.get(&req.layer2_voucher_id).unwrap();

        // 2. Direct Lookup (Challenge)
        if let Some(entry) = voucher_locks.get(&req.challenge_ds_tag) {
            let verdict = L2Verdict::Verified {
                lock_entry: entry.clone(),
            };
            return self.wrap_and_sign(verdict);
        }

        // 3. Logarithmic Locators (LCA Search)
        // Wir suchen das erste Präfix, das wir kennen
        for prefix in &req.locator_prefixes {
            for (ds_tag, _entry) in voucher_locks {
                if ds_tag.starts_with(prefix) {
                    let verdict = L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    };
                    return self.wrap_and_sign(verdict);
                }
            }
        }

        // Nichts gefunden -> Synchronisation ab Genesis
        let verdict = L2Verdict::MissingLocks {
            sync_point: "genesis".to_string(),
        };
        self.wrap_and_sign(verdict)
    }
}

#[test]
fn test_l2_double_spend_quarantine() {
    human_money_core::set_signature_bypass(true);
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    // Setup Service
    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.get_user_id().unwrap();

    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.privacy = Some(PrivacySettings {
            mode: "flexible".to_string(),
        });
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(correct_password),
    )
    .unwrap();

    let voucher_id = app.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Server-Identität im Client konfigurieren
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    let envelope_genesis: L2ResponseEnvelope = serde_json::from_slice(&resp_genesis).unwrap();
    assert!(matches!(envelope_genesis.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(&voucher_id, &resp_genesis, Some(correct_password))
        .unwrap();

    // 2. Status Query
    let query_bytes = app.generate_l2_status_query(&voucher_id).unwrap();
    let resp_query = mock_l2.handle_status_query(&query_bytes);
    let query_envelope: L2ResponseEnvelope = serde_json::from_slice(&resp_query).unwrap();
    assert!(matches!(query_envelope.verdict, L2Verdict::Verified { .. }));

    let id_david = test_utils::ACTORS.david.identity.user_id.clone();

    // 3. First Transaction (Transfer to Bob/David)
    let request_tx1 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_david.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.metadata.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    // Hole neue voucher_id (das Wallet erstellt für Split oft neue instances)
    // Einfachheitshalber nehmen wir die zuletzt modifizierte Instanz die noch Aktive ist
    let summaries_after_tx1 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // L2 Lock für die neue Transaktion
    let req_tx1 = app.generate_l2_lock_request(&voucher_id_tx1).unwrap();
    let resp_tx1 = mock_l2.handle_lock_request(&req_tx1);
    let envelope_tx1: L2ResponseEnvelope = serde_json::from_slice(&resp_tx1).unwrap();
    assert!(matches!(envelope_tx1.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(&voucher_id_tx1, &resp_tx1, Some(correct_password))
        .unwrap();

    // L2 Status Query
    let query_bytes_tx1 = app.generate_l2_status_query(&voucher_id_tx1).unwrap();
    let resp_query_tx1 = mock_l2.handle_status_query(&query_bytes_tx1);
    let query_envelope_tx1: L2ResponseEnvelope = serde_json::from_slice(&resp_query_tx1).unwrap();
    assert!(matches!(
        query_envelope_tx1.verdict,
        L2Verdict::Verified { .. }
    ));

    // 4. Second Transaction (Transfer to Bob/David again)
    let request_tx2 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_david.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id_tx1.clone(),
            amount_to_send: "5".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    app.create_transfer_bundle(request_tx2, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx2 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )
        .unwrap();
    let voucher_id_tx2 = summaries_after_tx2
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // Generiere den L2LockRequest req_valid
    let req_valid_bytes = app.generate_l2_lock_request(&voucher_id_tx2).unwrap();

    // 5. Double Spend Provokation (Hacker ist schneller)
    let mut req_malicious: L2LockRequest = serde_json::from_slice(&req_valid_bytes).unwrap();
    req_malicious.transaction_hash[0] = !req_malicious.transaction_hash[0]; // Hacker hat anderen tx Hash

    let req_malicious_bytes = serde_json::to_vec(&req_malicious).unwrap();
    let resp_malicious = mock_l2.handle_lock_request(&req_malicious_bytes);
    let envelope_malicious: L2ResponseEnvelope = serde_json::from_slice(&resp_malicious).unwrap();
    assert!(matches!(envelope_malicious.verdict, L2Verdict::Ok { .. })); // L2 Server akzeptiert den Hacker

    // 6. Legitime Einlösung (wir kommen zu spät)
    let resp_tx2 = mock_l2.handle_lock_request(&req_valid_bytes);
    let envelope_tx2: L2ResponseEnvelope = serde_json::from_slice(&resp_tx2).unwrap();
    assert!(matches!(envelope_tx2.verdict, L2Verdict::Verified { .. }));

    app.process_l2_response(&voucher_id_tx2, &resp_tx2, Some(correct_password))
        .unwrap();

    // 7. Finale Prüfung
    let final_details = app.get_voucher_details(&voucher_id_tx2).unwrap();
    assert!(matches!(
        final_details.status,
        VoucherStatus::Quarantined { .. }
    ));
}

#[test]
fn test_l2_signature_payload_manipulation() {
    human_money_core::set_signature_bypass(false); // Enable signature check
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    // Setup Service
    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.get_user_id().unwrap();

    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.privacy = Some(PrivacySettings {
            mode: "flexible".to_string(),
        });
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(correct_password),
    )
    .unwrap();

    let voucher_id = app.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Server-Identität im Client konfigurieren
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    let envelope_genesis: L2ResponseEnvelope = serde_json::from_slice(&resp_genesis).unwrap();
    assert!(matches!(envelope_genesis.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(&voucher_id, &resp_genesis, Some(correct_password))
        .unwrap();

    let id_david = test_utils::ACTORS.david.identity.user_id.clone();

    // 2. Transaction
    let request_tx1 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_david.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.metadata.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx1 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // 3. Generiere validen L2LockRequest
    let req_valid_bytes = app.generate_l2_lock_request(&voucher_id_tx1).unwrap();
    let mut req_manipulated: L2LockRequest = serde_json::from_slice(&req_valid_bytes).unwrap();

    // 4. Manipulation: Change receiver_ephemeral_pub_hash
    // This is the core of the vulnerability: the signature ONLY signs the transaction_hash (t_id).
    // An attacker can change routing fields like receiver_ephemeral_pub_hash without invalidating the signature.
    let old_hash = req_manipulated.receiver_ephemeral_pub_hash.unwrap();
    let mut fake_hash = old_hash;
    fake_hash[0] = !fake_hash[0]; // Flip bits of the first byte
    req_manipulated.receiver_ephemeral_pub_hash = Some(fake_hash);

    let req_manipulated_bytes = serde_json::to_vec(&req_manipulated).unwrap();

    // 5. Send manipulated request to L2 Node
    let resp_manipulated = mock_l2.handle_lock_request(&req_manipulated_bytes);
    let envelope_manipulated: L2ResponseEnvelope =
        serde_json::from_slice(&resp_manipulated).unwrap();

    // After the protocol fix, the L2 Node should REJECT the manipulated payload
    // because the signature (which signed the old hashes) no longer matches the payload_hash.
    assert!(
        matches!(envelope_manipulated.verdict, L2Verdict::Rejected { .. }),
        "Mock logic should return Rejected for invalid signature"
    );

    // Verify that the MockL2Node did NOT store the manipulated hash
    assert!(!mock_l2.spendable_outputs.contains(&fake_hash));
    // The old hash was not spent (request was rejected)
    // Wait, in handle_lock_request, it might have been removed if non-genesis?
    // In this test, it's non-genesis. Check MockL2Node code.
    // It removes it AFTER signature check. So old_hash should still be there?
    // Actually, it's added during resp_genesis.
}

#[test]
fn test_l2_fake_double_spend_protection() {
    human_money_core::set_signature_bypass(false); // Enable signature check
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    // Setup Service
    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.get_user_id().unwrap();

    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.privacy = Some(PrivacySettings {
            mode: "flexible".to_string(),
        });
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(correct_password),
    )
    .unwrap();

    let voucher_id = app.get_voucher_summaries(None, None).unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Server-Identität im Client konfigurieren
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    app.process_l2_response(&voucher_id, &resp_genesis, Some(correct_password))
        .unwrap();

    let id_david = test_utils::ACTORS.david.identity.user_id.clone();

    // 2. Transaction (Transfer to David)
    let request_tx1 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_david.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.metadata.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx1 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
        )
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // Legitime Parameter aus der Historie extrahieren
    let (challenge_ds_tag, l2_voucher_id, expected_ephem_pub) = {
        let wallet = app.get_wallet_for_test().unwrap();
        let instance = wallet.get_voucher_instance(&voucher_id_tx1).unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();

        let ds_tag = human_money_core::services::l2_gateway::derive_challenge_tag(last_tx).unwrap();
        let vid = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(
            &instance.voucher.transactions[0],
        )
        .unwrap();
        let ephem_bs58 = last_tx.sender_ephemeral_pub.as_ref().unwrap();
        let ephem_bytes: [u8; 32] = bs58::decode(ephem_bs58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();

        (ds_tag, vid, ephem_bytes)
    };

    // --- Scenario A: Gebrochene Signatur ---
    // Der Server behauptet einen Double-Spend mit t_id "FAKE", nutzt aber unseren echten Key.
    // Die Signatur ist aber ungültig (oder einfach Nullen).
    let mut fake_t_id = [0u8; 32];
    fake_t_id[0] = 0xEE;

    let malicious_entry_a = human_money_core::models::layer2_api::L2LockEntry {
        layer2_voucher_id: l2_voucher_id.clone(),
        t_id: fake_t_id,
        sender_ephemeral_pub: expected_ephem_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64], // Ungültig
        deletable_at: None,
    };

    let resp_a = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_a,
    });
    let result_a = app.process_l2_response(&voucher_id_tx1, &resp_a, Some(correct_password));

    assert!(
        result_a.is_err(),
        "Wallet darf mathematisch ungültigen Beweis nicht akzeptieren"
    );
    assert!(result_a.unwrap_err().contains("ungültig"));

    // Status prüfen -> muss Active bleiben
    assert!(matches!(
        app.get_voucher_details(&voucher_id_tx1).unwrap().status,
        VoucherStatus::Active
    ));

    // --- Scenario B: Fremder Key / Gefälschter Lock ---
    // Der Server generiert einen eigenen Key, erstellt einen mathematisch korrekten Lock für t_id "FAKE",
    // aber dieser Key gehört nicht zu unserer Transaktion.
    let malicious_key = SigningKey::generate(&mut rand::thread_rng());
    let malicious_pub = malicious_key.verifying_key().to_bytes();

    let payload_hash_b = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &l2_voucher_id,
        &fake_t_id,
        &malicious_pub,
        None,
        None,
        None,
    );
    let malicious_sig_b = malicious_key.sign(&payload_hash_b).to_bytes();

    let malicious_entry_b = human_money_core::models::layer2_api::L2LockEntry {
        layer2_voucher_id: l2_voucher_id.clone(),
        t_id: fake_t_id,
        sender_ephemeral_pub: malicious_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: malicious_sig_b,
        deletable_at: None,
    };

    let resp_b = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_b,
    });
    let result_b = app.process_l2_response(&voucher_id_tx1, &resp_b, Some(correct_password));

    assert!(
        result_b.is_err(),
        "Wallet muss Beweis mit fremdem Key ablehnen"
    );
    assert!(result_b.unwrap_err().contains("fremden Key"));

    // Status prüfen -> muss Active bleiben
    assert!(matches!(
        app.get_voucher_details(&voucher_id_tx1).unwrap().status,
        VoucherStatus::Active
    ));
}

#[test]
fn test_l2_voucher_id_mixup_protection() {
    human_money_core::set_signature_bypass(false);
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    // Setup Service
    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.get_user_id().unwrap();

    let (flexible_standard, _) = create_custom_standard(&SILVER_STANDARD.0, |s| {
        s.privacy = Some(PrivacySettings {
            mode: "flexible".to_string(),
        });
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id.clone()),
                ..Default::default()
            },
            nominal_value: ValueDefinition {
                amount: "100".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
        Some(correct_password),
    )
    .unwrap();

    let summaries = app.get_voucher_summaries(None, None).unwrap();
    let voucher_id = summaries[0].local_instance_id.clone();

    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    app.process_l2_response(&voucher_id, &resp_genesis, Some(correct_password))
        .unwrap();

    // Legitime Parameter aus der Historie extrahieren
    let (_challenge_ds_tag, l2_voucher_id, expected_ephem_pub, t_id) = {
        let wallet = app.get_wallet_for_test().unwrap();
        let instance = wallet.get_voucher_instance(&voucher_id).unwrap();
        let last_tx = instance.voucher.transactions.last().unwrap();

        let ds_tag = human_money_core::services::l2_gateway::derive_challenge_tag(last_tx).unwrap();
        let vid = human_money_core::services::l2_gateway::calculate_layer2_voucher_id(
            &instance.voucher.transactions[0],
        )
        .unwrap();
        let ephem_bs58 = last_tx.sender_ephemeral_pub.as_ref().unwrap();
        let ephem_bytes: [u8; 32] = bs58::decode(ephem_bs58)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let tid_bytes: [u8; 32] = bs58::decode(&last_tx.t_id)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();

        (ds_tag, vid, ephem_bytes, tid_bytes)
    };

    // --- Scenario C: Voucher ID Mix-up ---
    // Der Server behauptet einen Double-Spend für einen ANDEREN Voucher, nutzt aber dort
    // unsere echten Daten (Challenge, Key, Signatur).
    let mut fake_voucher_id = l2_voucher_id.clone();
    if fake_voucher_id.starts_with("0") {
        fake_voucher_id.replace_range(0..1, "1");
    } else {
        fake_voucher_id.replace_range(0..1, "0");
    }

    let mut fake_t_id = t_id;
    fake_t_id[0] = !fake_t_id[0]; // Andere t_id für Double-Spend Simulation

    // Signiere den gefälschten Lock-Eintrag (damit Math-Check PASSES)
    // Aber wir nutzen die FALSCHE Voucher ID
    let _signing_key = SigningKey::from_bytes(&[1u8; 32]); // Dummy key won't work, we need the real ephemeral or bypass
    // We use signature bypass for simplicity in forging the math-correct lock,
    // but the ID check should still fail.
    human_money_core::set_signature_bypass(true);

    let malicious_entry_c = human_money_core::models::layer2_api::L2LockEntry {
        layer2_voucher_id: fake_voucher_id,
        t_id: fake_t_id,
        sender_ephemeral_pub: expected_ephem_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64],
        deletable_at: None,
    };

    let resp_c = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_c,
    });
    let result_c = app.process_l2_response(&voucher_id, &resp_c, Some(correct_password));

    assert!(
        result_c.is_err(),
        "Wallet muss Beweis für falsche Voucher ID ablehnen"
    );
    assert!(result_c.unwrap_err().contains("Mix-up"));

    // Status prüfen -> muss Active bleiben
    assert!(matches!(
        app.get_voucher_details(&voucher_id).unwrap().status,
        VoucherStatus::Active
    ));
}
