// use human_money_core::app_service::AppService;
use human_money_core::models::layer2_api::{
    L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;

use human_money_core::NewVoucherData;
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD, create_custom_standard};
use human_money_core::wallet::instance::VoucherStatus;
use std::collections::HashMap;
use tempfile::tempdir;

// --- Mock L2 Node ---
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashSet;

pub struct MockL2Node {
    // Simulates the RAM bloom filter (voucher IDs)
    vouchers: HashSet<String>,
    // Simulates the L2 database (Key-Value)
    // Key: ds_tag (Base58), Value: L2LockEntry
    locks: HashMap<String, HashMap<String, human_money_core::models::layer2_api::L2LockEntry>>,
    // Simulates the UTXO model for P2PKH anchors
    spendable_outputs: HashSet<[u8; 32]>,
    // Private key of the L2 server for signing verdicts
    server_key: SigningKey,
}

impl Default for MockL2Node {
    fn default() -> Self {
        Self::new()
    }
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
            quorum_certificate: None,
        };
        serde_json::to_vec(&envelope).unwrap()
    }

    pub fn handle_lock_request(&mut self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2LockRequest = serde_json::from_slice(req_bytes).unwrap();

        // --- 1. Check authority (layer2_signature) ---
        // V3 Protocol (audit_02_11): a genesis lock signs the canonical "none"
        // placeholder for the voucher-id field (its own derived id would be
        // circular — see creation.rs/chain.rs), while spends bind the real hex
        // id. An honest L2 node therefore reconstructs the digest accordingly.
        let payload_hash = if req.is_genesis {
            let challenge_ds_tag = bs58::encode(req.transaction_hash).into_string();
            human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
                human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
                &challenge_ds_tag,
                &req.transaction_hash,
                &req.sender_ephemeral_pub,
                req.trap_r.as_deref()
                    .unwrap_or(human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER),
                req.trap_s.as_deref()
                    .unwrap_or(human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER),
                req.encrypted_timestamp,
                req.created_at_ms,
                req.deletable_at.as_deref(),
                &human_money_core::services::l2_gateway::privacy_guard_commitment(
                    req.privacy_guard.as_deref(),
                ),
            )
        } else {
            human_money_core::services::l2_gateway::calculate_l2_payload_hash(&req)
        };

        let ephem_key = VerifyingKey::from_bytes(&req.sender_ephemeral_pub)
            .expect("Invalid sender_ephemeral_pub key format");
        let signature = Signature::from_bytes(&req.layer2_signature);

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
            // For genesis we use t_id as key (since no ds_tag is present)
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
            // Return the proof
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
            trap_r: req.trap_r.clone(),
            trap_s: req.trap_s.clone(),
            encrypted_timestamp: req.encrypted_timestamp,
            created_at_ms: req.created_at_ms,
            deletable_at: req.deletable_at.clone(),
            privacy_guard: req.privacy_guard.clone(),
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
        // We search for the first prefix we know
        for prefix in &req.locator_prefixes {
            for ds_tag in voucher_locks.keys() {
                if ds_tag.starts_with(prefix) {
                    let verdict = L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    };
                    return self.wrap_and_sign(verdict);
                }
            }
        }

        // Nothing found -> Synchronization from genesis
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
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
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

    let voucher_id = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Configure server identity in client
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    let envelope_genesis: L2ResponseEnvelope = serde_json::from_slice(&resp_genesis).unwrap();
    assert!(matches!(envelope_genesis.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(voucher_id.clone(), &resp_genesis, Some(correct_password))
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
        use_privacy_mode: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    // Fetch new voucher_id (wallet often creates new instances for split)
    // For simplicity, take the last modified instance that is still active
    let summaries_after_tx1 = app
        .with_wallet_and_identity(|w, id| {
            w.list_vouchers(
                Some(id),
                None,
                Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
                None,
            )
        })
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // L2 Lock for the new transaction
    let req_tx1 = app.generate_l2_lock_request(&voucher_id_tx1).unwrap();
    let resp_tx1 = mock_l2.handle_lock_request(&req_tx1);
    let envelope_tx1: L2ResponseEnvelope = serde_json::from_slice(&resp_tx1).unwrap();
    assert!(matches!(envelope_tx1.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(voucher_id_tx1.clone(), &resp_tx1, Some(correct_password))
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
        use_privacy_mode: None,
    };
    app.create_transfer_bundle(request_tx2, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx2 = app
        .with_wallet_and_identity(|w, id| {
            w.list_vouchers(
                Some(id),
                None,
                Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
                None,
            )
        })
        .unwrap();
    let voucher_id_tx2 = summaries_after_tx2
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // Generate L2LockRequest req_valid
    let req_valid_bytes = app.generate_l2_lock_request(&voucher_id_tx2).unwrap();

    // 5. Double spend provocation (hacker is faster)
    let mut req_malicious: L2LockRequest = serde_json::from_slice(&req_valid_bytes).unwrap();
    req_malicious.transaction_hash[0] = !req_malicious.transaction_hash[0]; // Hacker has different tx hash

    let req_malicious_bytes = serde_json::to_vec(&req_malicious).unwrap();
    let resp_malicious = mock_l2.handle_lock_request(&req_malicious_bytes);
    let envelope_malicious: L2ResponseEnvelope = serde_json::from_slice(&resp_malicious).unwrap();
    assert!(matches!(envelope_malicious.verdict, L2Verdict::Ok { .. })); // L2 server accepts hacker

    // 6. Legitimate redemption (we arrive too late)
    let resp_tx2 = mock_l2.handle_lock_request(&req_valid_bytes);
    let envelope_tx2: L2ResponseEnvelope = serde_json::from_slice(&resp_tx2).unwrap();
    assert!(matches!(envelope_tx2.verdict, L2Verdict::Verified { .. }));

    app.process_l2_response(voucher_id_tx2.clone(), &resp_tx2, Some(correct_password))
        .unwrap();

    // 7. Final check
    let final_details = app.with_wallet(|w| w.get_voucher_details(&voucher_id_tx2).unwrap()).unwrap();
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
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
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

    let voucher_id = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Configure server identity in client
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    let envelope_genesis: L2ResponseEnvelope = serde_json::from_slice(&resp_genesis).unwrap();
    assert!(matches!(envelope_genesis.verdict, L2Verdict::Ok { .. }));
    app.process_l2_response(voucher_id.clone(), &resp_genesis, Some(correct_password))
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
        use_privacy_mode: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx1 = app
        .with_wallet_and_identity(|w, id| {
            w.list_vouchers(
                Some(id),
                None,
                Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
                None,
            )
        })
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // 3. Generate valid L2LockRequest
    let req_valid_bytes = app.generate_l2_lock_request(&voucher_id_tx1).unwrap();
    let mut req_manipulated: L2LockRequest = serde_json::from_slice(&req_valid_bytes).unwrap();

    // 4. Manipulation: Change the bound encrypted timestamp.
    // V2 Protocol (HMC_TX_AUTH_V2): the signature binds the trap components
    // (u, blinded_id), the encrypted timestamp and deletable_at. An attacker
    // flipping bits in ANY of these fields invalidates the signature.
    let tampered_ts = req_manipulated.encrypted_timestamp.wrapping_add(1);
    req_manipulated.encrypted_timestamp = tampered_ts;

    let req_manipulated_bytes = serde_json::to_vec(&req_manipulated).unwrap();

    // 5. Send manipulated request to L2 Node; the rejection MUST NOT mutate
    // any server-side state.
    let outputs_before_rejection = mock_l2.spendable_outputs.clone();
    let resp_manipulated = mock_l2.handle_lock_request(&req_manipulated_bytes);
    let envelope_manipulated: L2ResponseEnvelope =
        serde_json::from_slice(&resp_manipulated).unwrap();

    // After the protocol fix, the L2 Node should REJECT the manipulated payload
    // because the signature (which signed the old hashes) no longer matches the payload_hash.
    assert!(
        matches!(envelope_manipulated.verdict, L2Verdict::Rejected { .. }),
        "Mock logic should return Rejected for invalid signature"
    );

    // Verify that the manipulated request was rejected BEFORE mutating state:
    // the UTXO set must be identical to the pre-rejection snapshot.
    assert_eq!(
        mock_l2.spendable_outputs, outputs_before_rejection,
        "A signature-invalid lock request must not alter server state"
    );
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
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
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

    let voucher_id = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();

    // Configure server identity in client
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    app.process_l2_response(voucher_id.clone(), &resp_genesis, Some(correct_password))
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
        use_privacy_mode: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx1 = app
        .with_wallet_and_identity(|w, id| {
            w.list_vouchers(
                Some(id),
                None,
                Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
                None,
            )
        })
        .unwrap();
    let voucher_id_tx1 = summaries_after_tx1
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // Extract legitimate parameters from history
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

    // --- Scenario A: Broken signature ---
    // Server claims a double-spend with t_id "FAKE", but uses our real key.
    // However, signature is invalid (or just zeroes).
    let mut fake_t_id = [0u8; 32];
    fake_t_id[0] = 0xEE;

    let malicious_entry_a = human_money_core::models::layer2_api::L2LockEntry {
        layer2_voucher_id: l2_voucher_id.clone(),
        t_id: fake_t_id,
        sender_ephemeral_pub: expected_ephem_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: [0u8; 64], // Invalid
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let resp_a = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_a,
    });
    let result_a = app.process_l2_response(voucher_id_tx1.clone(), &resp_a, Some(correct_password));

    assert!(
        result_a.is_err(),
        "Wallet darf mathematisch ungültigen Beweis nicht akzeptieren"
    );
    assert!(result_a.unwrap_err().to_string().contains("ungültig"));

    // Check status -> must remain Active
    assert!(matches!(
        app.with_wallet(|w| w.get_voucher_details(&voucher_id_tx1).unwrap()).unwrap().status,
        VoucherStatus::Active
    ));

    // --- Scenario B: Foreign key / forged lock ---
    // Server generates its own key, creates a mathematically correct lock for t_id "FAKE",
    // but this key does not belong to our transaction.
    let malicious_key = SigningKey::generate(&mut rand::thread_rng());
    let malicious_pub = malicious_key.verifying_key().to_bytes();

    // V3 protocol: sign exactly what the wallet reconstructs from the entry.
    // The forged lock carries REAL-looking spend shards so the hardened
    // digest (audit_02_11 / HMSEC-SA04-08) takes the SPEND path — binding
    // this voucher container id and the empty privacy-guard commitment —
    // and the assertion below actually exercises the ephemeral-key pinning
    // check instead of failing earlier at the genesis-placeholder mismatch.
    let fake_trap_r = bs58::encode([0x33u8; 32]).into_string();
    let fake_trap_s = bs58::encode([0x44u8; 32]).into_string();
    let payload_hash_b = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        &l2_voucher_id,
        &challenge_ds_tag,
        &fake_t_id,
        &malicious_pub,
        &fake_trap_r,
        &fake_trap_s,
        0,
        0,
        None,
        "",
    );
    let malicious_sig_b = malicious_key.sign(&payload_hash_b).to_bytes();

    let malicious_entry_b = human_money_core::models::layer2_api::L2LockEntry {
        layer2_voucher_id: l2_voucher_id.clone(),
        t_id: fake_t_id,
        sender_ephemeral_pub: malicious_pub,
        receiver_ephemeral_pub_hash: None,
        change_ephemeral_pub_hash: None,
        layer2_signature: malicious_sig_b,
        trap_r: Some(fake_trap_r),
        trap_s: Some(fake_trap_s),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let resp_b = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_b,
    });
    let result_b = app.process_l2_response(voucher_id_tx1.clone(), &resp_b, Some(correct_password));

    assert!(
        result_b.is_err(),
        "Wallet muss Beweis mit fremdem Key ablehnen"
    );
    assert!(result_b.unwrap_err().to_string().contains("fremden Key"));

    // Check status -> must remain Active
    assert!(matches!(
        app.with_wallet(|w| w.get_voucher_details(&voucher_id_tx1).unwrap()).unwrap().status,
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
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // Create new voucher (Genesis)
    app.create_new_voucher(
        &flexible_toml,
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

    let summaries = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap();
    let voucher_id = summaries[0].local_instance_id.clone();

    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Genesis Lock
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    let resp_genesis = mock_l2.handle_lock_request(&req_genesis);
    app.process_l2_response(voucher_id.clone(), &resp_genesis, Some(correct_password))
        .unwrap();

    // Extract legitimate parameters from history
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
    // Server claims a double-spend for ANOTHER voucher, but uses
    // our real data (challenge, key, signature) there.
    let mut fake_voucher_id = l2_voucher_id.clone();
    if fake_voucher_id.starts_with("0") {
        fake_voucher_id.replace_range(0..1, "1");
    } else {
        fake_voucher_id.replace_range(0..1, "0");
    }

    let mut fake_t_id = t_id;
    fake_t_id[0] = !fake_t_id[0]; // Different t_id for double-spend simulation

    // Sign forged lock entry (so math check PASSES)
    // But we use the WRONG voucher ID
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
        trap_r: Some("none".to_string()),
        trap_s: Some("none".to_string()),
        encrypted_timestamp: 0,
        created_at_ms: 0,
        deletable_at: None,
        privacy_guard: None,
    };

    let resp_c = mock_l2.wrap_and_sign(L2Verdict::Verified {
        lock_entry: malicious_entry_c,
    });
    let result_c = app.process_l2_response(voucher_id.clone(), &resp_c, Some(correct_password));

    assert!(
        result_c.is_err(),
        "Wallet muss Beweis für falsche Voucher ID ablehnen"
    );
    assert!(result_c.unwrap_err().to_string().contains("Mix-up"));

    // Check status -> must remain Active
    assert!(matches!(
        app.with_wallet(|w| w.get_voucher_details(&voucher_id).unwrap()).unwrap().status,
        VoucherStatus::Active
    ));
}

#[test]
fn test_l2_lock_payload_hash_commits_to_created_at_ms() {
    human_money_core::set_signature_bypass(false);
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode =
            human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    // 1. Genesis lock request
    app.create_new_voucher(
        &flexible_toml,
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

    let voucher_id = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let req_genesis_bytes = app.generate_l2_lock_request(&voucher_id).unwrap();
    let req_genesis: L2LockRequest = serde_json::from_slice(&req_genesis_bytes).unwrap();

    assert!(req_genesis.is_genesis);
    assert!(req_genesis.created_at_ms > 0, "Genesis created_at_ms must be populated from t_time");

    let ephem_key = VerifyingKey::from_bytes(&req_genesis.sender_ephemeral_pub).unwrap();
    let sig = Signature::from_bytes(&req_genesis.layer2_signature);

    let challenge_ds_tag = bs58::encode(req_genesis.transaction_hash).into_string();
    let original_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        &challenge_ds_tag,
        &req_genesis.transaction_hash,
        &req_genesis.sender_ephemeral_pub,
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        req_genesis.encrypted_timestamp,
        req_genesis.created_at_ms,
        req_genesis.deletable_at.as_deref(),
        &human_money_core::services::l2_gateway::privacy_guard_commitment(
            req_genesis.privacy_guard.as_deref(),
        ),
    );
    assert!(
        ephem_key.verify(&original_hash, &sig).is_ok(),
        "Original signature must verify against hash with req_genesis.created_at_ms"
    );

    // Tamper with created_at_ms -> verify hash changes and signature fails
    let tampered_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        &challenge_ds_tag,
        &req_genesis.transaction_hash,
        &req_genesis.sender_ephemeral_pub,
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        req_genesis.encrypted_timestamp,
        req_genesis.created_at_ms + 1,
        req_genesis.deletable_at.as_deref(),
        &human_money_core::services::l2_gateway::privacy_guard_commitment(
            req_genesis.privacy_guard.as_deref(),
        ),
    );
    assert_ne!(original_hash, tampered_hash);
    assert!(
        ephem_key.verify(&tampered_hash, &sig).is_err(),
        "Signature must fail when created_at_ms is tampered"
    );

    // Verify MockL2Node rejects tampered request
    let mut mock_l2 = MockL2Node::new();
    let mut tampered_req = req_genesis.clone();
    tampered_req.created_at_ms += 1000;
    let tampered_bytes = serde_json::to_vec(&tampered_req).unwrap();
    let resp = mock_l2.handle_lock_request(&tampered_bytes);
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&resp).unwrap();
    assert!(matches!(
        envelope.verdict,
        L2Verdict::Rejected { reason } if reason.contains("Invalid signature")
    ));

    // 2. Spend lock request
    let id_david = ACTORS.david.identity.user_id.clone();
    let request_tx1 = human_money_core::wallet::MultiTransferRequest {
        recipient_id: id_david.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: voucher_id.clone(),
            amount_to_send: "10".to_string(),
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );
    app.create_transfer_bundle(request_tx1, &standards_toml, None, Some(correct_password))
        .unwrap();

    let summaries_after_tx1 = app
        .with_wallet_and_identity(|w, id| {
            w.list_vouchers(
                Some(id),
                None,
                Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
                None,
            )
        })
        .unwrap();
    let voucher_id_spend = summaries_after_tx1.last().unwrap().local_instance_id.clone();

    let req_spend_bytes = app.generate_l2_lock_request(&voucher_id_spend).unwrap();
    let req_spend: L2LockRequest = serde_json::from_slice(&req_spend_bytes).unwrap();
    assert!(!req_spend.is_genesis);
    assert!(req_spend.created_at_ms > 0);

    let spend_ephem_key = VerifyingKey::from_bytes(&req_spend.sender_ephemeral_pub).unwrap();
    let spend_sig = Signature::from_bytes(&req_spend.layer2_signature);
    let spend_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash(&req_spend);
    assert!(
        spend_ephem_key.verify(&spend_hash, &spend_sig).is_ok(),
        "Spend signature must verify"
    );

    let mut tampered_spend = req_spend.clone();
    tampered_spend.created_at_ms += 500;
    let tampered_spend_hash =
        human_money_core::services::l2_gateway::calculate_l2_payload_hash(&tampered_spend);
    assert_ne!(spend_hash, tampered_spend_hash);
    assert!(spend_ephem_key.verify(&tampered_spend_hash, &spend_sig).is_err());

    let tampered_spend_bytes = serde_json::to_vec(&tampered_spend).unwrap();
    let resp_spend_tampered = mock_l2.handle_lock_request(&tampered_spend_bytes);
    let env_spend_tampered: L2ResponseEnvelope =
        serde_json::from_slice(&resp_spend_tampered).unwrap();
    assert!(matches!(
        env_spend_tampered.verdict,
        L2Verdict::Rejected { reason } if reason.contains("Invalid signature")
    ));
}

#[test]
fn test_gateway_retry_invariance_idempotency() {
    human_money_core::set_signature_bypass(false);
    let dir = tempdir().unwrap();
    let correct_password = "correct_password";
    let test_user = &ACTORS.test_user;

    let (mut app, _) =
        test_utils::setup_service_with_profile(dir.path(), test_user, "Alice", correct_password);
    let user_id = app.with_wallet(|w| w.get_user_id().to_string()).unwrap();

    let (flexible_standard, _) = create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode =
            human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();

    app.create_new_voucher(
        &flexible_toml,
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

    let voucher_id = app
        .with_wallet_and_identity(|w, id| w.list_vouchers(Some(id), None, None, None))
        .unwrap()[0]
        .local_instance_id
        .clone();

    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // Generate request #1 and #2 - both must derive the exact same created_at_ms from t_time
    let req_bytes_1 = app.generate_l2_lock_request(&voucher_id).unwrap();
    let req_bytes_2 = app.generate_l2_lock_request(&voucher_id).unwrap();
    let req1: L2LockRequest = serde_json::from_slice(&req_bytes_1).unwrap();
    let req2: L2LockRequest = serde_json::from_slice(&req_bytes_2).unwrap();
    assert_eq!(
        req1.created_at_ms, req2.created_at_ms,
        "created_at_ms must be deterministically invariant across requests for the same tx"
    );

    // Initial submission of req_bytes_1 to Gateway
    let resp1 = mock_l2.handle_lock_request(&req_bytes_1);
    let env1: L2ResponseEnvelope = serde_json::from_slice(&resp1).unwrap();
    assert!(matches!(env1.verdict, L2Verdict::Ok { .. }));

    let outcome1 = app
        .process_l2_response(voucher_id.clone(), &resp1, Some(correct_password))
        .unwrap();
    assert_eq!(
        outcome1,
        human_money_core::models::layer2_api::L2ProcessingOutcome::Found
    );

    // Gateway retry: resending the EXACT same byte vector req_bytes_1 (as required by Gateway Retry Invariant)
    let resp_retry = mock_l2.handle_lock_request(&req_bytes_1);
    let env_retry: L2ResponseEnvelope = serde_json::from_slice(&resp_retry).unwrap();
    assert!(
        matches!(env_retry.verdict, L2Verdict::Verified { .. }),
        "Gateway returns 200 OK / Verified for idempotent retry of same lock"
    );

    // An idempotent matching response remains Found without a verified quorum.
    let outcome_retry = app
        .process_l2_response(voucher_id.clone(), &resp_retry, Some(correct_password))
        .unwrap();
    assert_eq!(
        outcome_retry,
        human_money_core::models::layer2_api::L2ProcessingOutcome::Found
    );

    // Voucher status must remain Active
    assert!(matches!(
        app.with_wallet(|w| w.get_voucher_details(&voucher_id).unwrap())
            .unwrap()
            .status,
        VoucherStatus::Active
    ));
}


