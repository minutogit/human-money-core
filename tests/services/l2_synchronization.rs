use human_money_core::models::layer2_api::{
    L2LockEntry, L2LockRequest, L2ResponseEnvelope, L2StatusQuery, L2Verdict,
};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::ValueDefinition;

use human_money_core::services::voucher_manager::NewVoucherData;
use human_money_core::test_utils::{self, ACTORS, FREETALER_STANDARD};
use std::collections::{HashMap, HashSet};
use tempfile::tempdir;

use ed25519_dalek::{Signer, SigningKey};

// --- Mock L2 Node (Adapted for Sync Protocol) ---
pub struct MockL2Node {
    vouchers: HashSet<String>,
    locks: HashMap<String, HashMap<String, L2LockEntry>>,
    server_key: SigningKey,
}

impl MockL2Node {
    pub fn new() -> Self {
        Self {
            vouchers: HashSet::new(),
            locks: HashMap::new(),
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
        self.vouchers.insert(req.layer2_voucher_id.clone());

        let ds_tag = if req.is_genesis {
            // Bei Genesis nutzen wir die t_id als Key (da kein ds_tag vorhanden)
            bs58::encode(req.transaction_hash).into_string()
        } else {
            req.ds_tag.clone().expect("Non-genesis must have ds_tag")
        };

        let voucher_locks = self.locks.entry(req.layer2_voucher_id.clone()).or_default();

        let entry = L2LockEntry {
            layer2_voucher_id: req.layer2_voucher_id.clone(),
            t_id: req.transaction_hash,
            sender_ephemeral_pub: req.sender_ephemeral_pub,
            receiver_ephemeral_pub_hash: req.receiver_ephemeral_pub_hash,
            change_ephemeral_pub_hash: req.change_ephemeral_pub_hash,
            layer2_signature: req.layer2_signature,
            deletable_at: req.deletable_at.clone(),
        };
        voucher_locks.insert(ds_tag, entry);

        let verdict = L2Verdict::Ok {
            signature: [0u8; 64],
        };
        self.wrap_and_sign(verdict)
    }

    pub fn handle_status_query(&self, req_bytes: &[u8]) -> Vec<u8> {
        let req: L2StatusQuery = serde_json::from_slice(req_bytes).unwrap();

        if !self.vouchers.contains(&req.layer2_voucher_id) {
            return self.wrap_and_sign(L2Verdict::UnknownVoucher);
        }

        let voucher_locks = self.locks.get(&req.layer2_voucher_id).unwrap();

        // 1. Direct Lookup
        if let Some(entry) = voucher_locks.get(&req.challenge_ds_tag) {
            return self.wrap_and_sign(L2Verdict::Verified {
                lock_entry: entry.clone(),
            });
        }

        // 2. Locator Search
        for prefix in &req.locator_prefixes {
            for (ds_tag, _entry) in voucher_locks {
                if ds_tag.starts_with(prefix) {
                    return self.wrap_and_sign(L2Verdict::MissingLocks {
                        sync_point: prefix.clone(),
                    });
                }
            }
        }

        self.wrap_and_sign(L2Verdict::MissingLocks {
            sync_point: "genesis".to_string(),
        })
    }
}

#[test]
fn test_scenario_1_happy_path() {
    human_money_core::set_signature_bypass(true);
    let dir = tempdir().unwrap();
    let correct_password = "password";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.test_user,
        "Alice",
        correct_password,
    );

    // Create and Lock Genesis
    let (flexible_standard, _) = test_utils::create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();
    let user_id = app.get_user_id().unwrap();
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
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

    let voucher_id = app.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    mock_l2.handle_lock_request(&req_genesis);

    // Query Status (Happy Path)
    let query_bytes = app.generate_l2_status_query(&voucher_id).unwrap();
    let resp_query = mock_l2.handle_status_query(&query_bytes);
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&resp_query).unwrap();

    // Should be Verified
    assert!(matches!(envelope.verdict, L2Verdict::Verified { .. }));

    // Process should confirm local
    app.process_l2_response(&voucher_id, &resp_query, Some(correct_password))
        .unwrap();
}

#[test]
fn test_scenario_2_offline_sync() {
    human_money_core::set_signature_bypass(true);
    let dir = tempdir().unwrap();
    let correct_password = "password";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.test_user,
        "Alice",
        correct_password,
    );

    // Create Voucher
    let (flexible_standard, _) = test_utils::create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();
    let user_id = app.get_user_id().unwrap();
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
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

    let voucher_id = app.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Lock Genesis on L2
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    mock_l2.handle_lock_request(&req_genesis);

    // 2. Perform 2 transfers OFFLINE (don't send to L2 yet)
    let id_david = test_utils::ACTORS.david.identity.user_id.clone();
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );

    // Tx 1
    app.create_transfer_bundle(
        human_money_core::wallet::MultiTransferRequest {
            recipient_id: id_david.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: voucher_id.clone(),
                amount_to_send: "10".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        },
        &standards_toml,
        None,
        Some(correct_password),
    )
    .unwrap();

    let v_id_tx1 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
            None,
        )
        .unwrap()
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // Tx 2
    app.create_transfer_bundle(
        human_money_core::wallet::MultiTransferRequest {
            recipient_id: id_david.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: v_id_tx1.clone(),
                amount_to_send: "5".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        },
        &standards_toml,
        None,
        Some(correct_password),
    )
    .unwrap();

    let v_id_tx2 = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
            None,
        )
        .unwrap()
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // 3. Query L2 for the latest state (v_id_tx2)
    let query_bytes = app.generate_l2_status_query(&v_id_tx2).unwrap();
    let resp_query = mock_l2.handle_status_query(&query_bytes);
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&resp_query).unwrap();

    // Should indicate MissingLocks with sync_point from Genesis (since only Genesis is known)
    if let L2Verdict::MissingLocks { sync_point } = envelope.verdict {
        assert!(sync_point.len() == 10 || sync_point == "genesis");
    } else {
        panic!("Expected MissingLocks, got {:?}", envelope.verdict);
    }

    // Process output
    app.process_l2_response(&v_id_tx2, &resp_query, Some(correct_password))
        .unwrap();
}

#[test]
fn test_scenario_3_double_spend_detection() {
    human_money_core::set_signature_bypass(true);
    let dir = tempdir().unwrap();
    let correct_password = "password";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.test_user,
        "Alice",
        correct_password,
    );

    // Create Voucher
    let (flexible_standard, _) = test_utils::create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();
    let user_id = app.get_user_id().unwrap();
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
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

    let voucher_id = app.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let mut mock_l2 = MockL2Node::new();
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // Lock Genesis
    let req_genesis = app.generate_l2_lock_request(&voucher_id).unwrap();
    mock_l2.handle_lock_request(&req_genesis);

    // Prepare Transfer
    let id_david = test_utils::ACTORS.david.identity.user_id.clone();
    let mut standards_toml = HashMap::new();
    standards_toml.insert(
        flexible_standard.immutable.identity.uuid.clone(),
        flexible_toml.clone(),
    );
    app.create_transfer_bundle(
        human_money_core::wallet::MultiTransferRequest {
            recipient_id: id_david.clone(),
            sources: vec![human_money_core::wallet::SourceTransfer {
                local_instance_id: voucher_id.clone(),
                amount_to_send: "10".to_string(),
            }],
            notes: None,
            sender_profile_name: None,
        use_privacy_mode: None,
        },
        &standards_toml,
        None,
        Some(correct_password),
    )
    .unwrap();

    let v_id_transfer = app
        .get_voucher_summaries(
            None,
            Some(&[human_money_core::wallet::instance::VoucherStatus::Active]),
            None,
        )
        .unwrap()
        .last()
        .unwrap()
        .local_instance_id
        .clone();

    // GENERATE valid lock request
    let req_valid_bytes = app.generate_l2_lock_request(&v_id_transfer).unwrap();

    // MOCK a different lock on L2 for the SAME ds_tag
    let mut malicious_req: L2LockRequest = serde_json::from_slice(&req_valid_bytes).unwrap();
    malicious_req.transaction_hash[0] = !malicious_req.transaction_hash[0]; // Different t_id
    mock_l2.handle_lock_request(&serde_json::to_vec(&malicious_req).unwrap());

    // 4. Query L2 for the state
    let query_bytes = app.generate_l2_status_query(&v_id_transfer).unwrap();
    let resp_query = mock_l2.handle_status_query(&query_bytes);

    // Should be Verified (but with conflicting t_id)
    app.process_l2_response(&v_id_transfer, &resp_query, Some(correct_password))
        .unwrap();

    // 5. Check if quarantined
    let details = app.get_voucher_details(&v_id_transfer).unwrap();
    assert!(matches!(
        details.status,
        human_money_core::wallet::instance::VoucherStatus::Quarantined { .. }
    ));
}

#[test]
fn test_scenario_4_initial_registration() {
    human_money_core::set_signature_bypass(true);
    let dir = tempdir().unwrap();
    let correct_password = "password";
    let (mut app, _) = test_utils::setup_service_with_profile(
        dir.path(),
        &ACTORS.test_user,
        "Alice",
        correct_password,
    );

    // Create Voucher
    let (flexible_standard, _) = test_utils::create_custom_standard(&FREETALER_STANDARD.0, |s| {
        s.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    });
    let flexible_toml = toml::to_string(&flexible_standard).unwrap();
    let user_id = app.get_user_id().unwrap();
    app.create_new_voucher(
        &flexible_toml,
        "en",
        NewVoucherData {
            creator_profile: PublicProfile {
                id: Some(user_id),
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

    let voucher_id = app.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();
    let mock_l2 = MockL2Node::new(); // EMPTY L2
    app.get_wallet_mut().unwrap().profile.l2_server_pubkey = Some(mock_l2.get_server_pubkey());

    // 1. Query L2
    let query_bytes = app.generate_l2_status_query(&voucher_id).unwrap();
    let resp_query = mock_l2.handle_status_query(&query_bytes);
    let envelope: L2ResponseEnvelope = serde_json::from_slice(&resp_query).unwrap();

    // Should be UnknownVoucher
    assert!(matches!(envelope.verdict, L2Verdict::UnknownVoucher));

    // Process output
    app.process_l2_response(&voucher_id, &resp_query, Some(correct_password))
        .unwrap();
}
