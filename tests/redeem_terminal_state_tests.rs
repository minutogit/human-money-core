//! tests/redeem_terminal_state_tests.rs
//!
//! Comprehensive integration tests for the 'redeem' transaction type and terminal state invariants:
//! 1. Terminal State: No transactions allowed after 'redeem'.
//! 2. Invalid Redeem Recipient: 'redeem' targeting a non-creator is rejected.
//! 3. Consolidation Zone: Transfers to creator at depth >= 512 must be 'redeem'.
//! 4. Expired Issuance: Transfers to creator with remaining validity < issuance_minimum_validity_duration must be 'redeem'.
//! 5. Split before Redeem (Partial Redemption): Split change remains spendable, redeemed branch is consumed (0 balance).
//! 6. Spendable Balance: Returns Decimal::ZERO for redeemed vouchers.
//! 7. Standards Signature & Content: All production and test standards are validly signed and include 'redeem' in allowed_t_types.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use rust_decimal::Decimal;
use human_money_core::error::{ValidationError, VoucherCoreError};
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{
    Transaction, ValueDefinition, Voucher, VoucherStandard, CONSOLIDATION_ZONE_THRESHOLD,
};
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::crypto::get_hash;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD, MINUTO_STANDARD};

fn enable_bypass() {
    human_money_core::set_signature_bypass(true);
}

fn base_dt() -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00.000000Z")
        .unwrap()
        .with_timezone(&Utc)
}

fn t_time_for(i: usize) -> String {
    (base_dt() + Duration::seconds(i as i64))
        .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn key_for_index(i: usize) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[0..4].copy_from_slice(&(i as u32).to_le_bytes());
    seed[4] = 0x42;
    seed[5] = 0x77;
    if seed.iter().all(|&b| b == 0) {
        seed[0] = 1;
    }
    SigningKey::from_bytes(&seed)
}

fn recompute_tid(tx: &mut Transaction) {
    let mut tmp = tx.clone();
    tmp.t_id = "".to_string();
    tmp.layer2_signature = None;
    tmp.sender_identity_signature = None;
    tmp.trap_data = None;
    tmp.privacy_guard = None;
    tx.t_id = get_hash(to_canonical_json(&tmp).unwrap());
    if tx.layer2_signature.is_none() {
        tx.layer2_signature = Some("dummy_sig".to_string());
    }
    if tx.sender_id.is_some() && tx.sender_identity_signature.is_none() {
        tx.sender_identity_signature = Some("dummy_id_sig".to_string());
    }
}

fn build_base_voucher(standard: &VoucherStandardDefinition, standard_hash: &str, valid_until: &str) -> Voucher {
    let creator = &ACTORS.alice.identity;
    let creator_id = creator.user_id.clone();

    let nonce_bytes = [0x22u8; 16];
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let creation_date = t_time_for(0);

    let decimal_places = standard.immutable.features.amount_decimal_places as usize;
    let initial_amount = format!("{:.1$}", 100.0, decimal_places);

    let mut voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            standard_definition_hash: standard_hash.to_string(),
        },
        voucher_id: String::new(),
        voucher_nonce: voucher_nonce.clone(),
        creation_date: creation_date.clone(),
        valid_until: valid_until.to_string(),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            unit: standard.immutable.blueprint.unit.clone(),
            amount: initial_amount.clone(),
            abbreviation: Some(standard.immutable.identity.abbreviation.clone()),
            description: None,
        },
        collateral: None,
        creator_profile: PublicProfile {
            id: Some(creator_id.clone()),
            ..Default::default()
        },
        transactions: vec![],
        signatures: vec![],
    };
    voucher.voucher_id = get_hash(to_canonical_json(&voucher).unwrap());

    let genesis_key = key_for_index(1);
    let holder_key = key_for_index(2);
    let genesis_pub_str = bs58::encode(genesis_key.verifying_key().to_bytes()).into_string();
    let holder_hash = get_hash(holder_key.verifying_key().to_bytes());
    let voucher_id_bytes = bs58::decode(&voucher.voucher_id).into_vec().unwrap();
    let nonce_decoded = bs58::decode(&voucher_nonce).into_vec().unwrap();
    let init_prev_hash = human_money_core::services::crypto::get_hash_from_slices(&[
        &voucher_id_bytes,
        &nonce_decoded,
    ]);

    let mut init_tx = Transaction {
        t_id: String::new(),
        prev_hash: init_prev_hash,
        t_type: "init".to_string(),
        t_time: creation_date.clone(),
        sender_id: Some(creator_id.clone()),
        recipient_id: creator_id.clone(),
        amount: initial_amount,
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(holder_hash),
        sender_ephemeral_pub: Some(genesis_pub_str),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: Some(valid_until.to_string()),
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut init_tx);
    voucher.transactions.push(init_tx);

    voucher
}

#[test]
fn test_all_standards_are_signed_and_contain_redeem() {
    // 1. Minuto V1
    let (minuto_std, _) = &*MINUTO_STANDARD;
    assert!(
        minuto_std.immutable.features.allowed_t_types.contains(&"redeem".to_string()),
        "minuto_v1 must contain 'redeem' in allowed_t_types"
    );
    assert!(
        minuto_std.verify_signature().unwrap_or(false),
        "minuto_v1 standard signature must be valid"
    );

    // 2. FreeTaler V1
    let (freetaler_std, _) = &*FREETALER_STANDARD;
    assert!(
        freetaler_std.immutable.features.allowed_t_types.contains(&"redeem".to_string()),
        "freetaler_v1 must contain 'redeem' in allowed_t_types"
    );
    assert!(
        freetaler_std.verify_signature().unwrap_or(false),
        "freetaler_v1 standard signature must be valid"
    );

    // 3. Test standards
    let test_standard_paths = [
        "tests/test_data/standards/standard_behavior_rules.toml",
        "tests/test_data/standards/standard_conflicting_rules.toml",
        "tests/test_data/standards/standard_content_rules.toml",
        "tests/test_data/standards/standard_field_group_rules.toml",
        "tests/test_data/standards/standard_no_split.toml",
        "tests/test_data/standards/standard_path_not_found.toml",
        "tests/test_data/standards/standard_required_signatures.toml",
        "tests/test_data/standards/standard_strict_counts.toml",
        "tests/test_data/standards/standard_strict_sig_description.toml",
    ];

    for path in test_standard_paths {
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("Failed to read {}: {}", path, e));
        let (std, _) = VoucherStandardDefinition::from_toml(&content)
            .unwrap_or_else(|e| panic!("{} signature must be valid: {:?}", path, e));
        assert!(
            std.immutable.features.allowed_t_types.contains(&"redeem".to_string()),
            "{} must contain 'redeem' in allowed_t_types", path
        );
    }
}

#[test]
fn test_terminal_state_transaction_after_redeem_forbidden() {
    enable_bypass();
    let (standard, std_hash) = &*FREETALER_STANDARD;
    let mut voucher = build_base_voucher(standard, std_hash, "2031-01-01T00:00:00.000000Z");

    let creator_id = ACTORS.alice.identity.user_id.clone();
    let bob_id = ACTORS.bob.identity.user_id.clone();

    // Tx 1: Transfer to Bob
    let holder_key = key_for_index(2);
    let bob_key = key_for_index(3);
    let bob_hash = get_hash(bob_key.verifying_key().to_bytes());
    let prev_tx = voucher.transactions.last().unwrap();
    let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());

    let mut tx1 = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: t_time_for(1),
        sender_id: Some(creator_id.clone()),
        recipient_id: bob_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(bob_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(holder_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx1);
    voucher.transactions.push(tx1);

    // Tx 2: Redeem to Creator (Alice)
    let prev_tx2 = voucher.transactions.last().unwrap();
    let prev_hash2 = get_hash(to_canonical_json(prev_tx2).unwrap());
    let alice_recv_key = key_for_index(4);
    let alice_recv_hash = get_hash(alice_recv_key.verifying_key().to_bytes());

    let mut tx2 = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash2,
        t_type: "redeem".to_string(),
        t_time: t_time_for(2),
        sender_id: Some(bob_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(alice_recv_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(bob_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx2);
    voucher.transactions.push(tx2);

    // Valid so far!
    human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect("Voucher with redeem should be valid");

    // Tx 3: Attempt another transaction AFTER redeem (Forbidden!)
    let prev_tx3 = voucher.transactions.last().unwrap();
    let prev_hash3 = get_hash(to_canonical_json(prev_tx3).unwrap());
    let charlie_key = key_for_index(5);
    let charlie_hash = get_hash(charlie_key.verifying_key().to_bytes());

    let mut tx3 = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash3,
        t_type: "transfer".to_string(),
        t_time: t_time_for(3),
        sender_id: Some(creator_id.clone()),
        recipient_id: ACTORS.charlie.identity.user_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(charlie_hash),
        sender_ephemeral_pub: Some(bs58::encode(alice_recv_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx3);
    voucher.transactions.push(tx3);

    let err = human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect_err("Transaction after redeem must fail");

    match err {
        VoucherCoreError::Validation(ValidationError::TransactionAfterRedeemForbidden { depth, redeem_depth }) => {
            assert_eq!(depth, 3);
            assert_eq!(redeem_depth, 2);
        }
        other => panic!("Expected TransactionAfterRedeemForbidden, got: {:?}", other),
    }
}

#[test]
fn test_redeem_to_non_creator_fails() {
    enable_bypass();
    let (standard, std_hash) = &*FREETALER_STANDARD;
    let mut voucher = build_base_voucher(standard, std_hash, "2031-01-01T00:00:00.000000Z");

    let creator_id = ACTORS.alice.identity.user_id.clone();
    let bob_id = ACTORS.bob.identity.user_id.clone();
    let charlie_id = ACTORS.charlie.identity.user_id.clone();

    // Tx 1: Transfer to Bob
    let holder_key = key_for_index(2);
    let bob_key = key_for_index(3);
    let bob_hash = get_hash(bob_key.verifying_key().to_bytes());
    let prev_tx = voucher.transactions.last().unwrap();
    let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());

    let mut tx1 = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: t_time_for(1),
        sender_id: Some(creator_id.clone()),
        recipient_id: bob_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(bob_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(holder_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx1);
    voucher.transactions.push(tx1);

    // Tx 2: Redeem to Charlie (Non-creator!) -> MUST FAIL
    let prev_tx2 = voucher.transactions.last().unwrap();
    let prev_hash2 = get_hash(to_canonical_json(prev_tx2).unwrap());
    let charlie_key = key_for_index(4);
    let charlie_hash = get_hash(charlie_key.verifying_key().to_bytes());

    let mut tx2 = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash2,
        t_type: "redeem".to_string(),
        t_time: t_time_for(2),
        sender_id: Some(bob_id.clone()),
        recipient_id: charlie_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(charlie_hash),
        sender_ephemeral_pub: Some(bs58::encode(bob_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx2);
    voucher.transactions.push(tx2);

    let err = human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect_err("Redeem to non-creator must fail");

    match err {
        VoucherCoreError::Validation(ValidationError::InvalidRedeemRecipient { recipient, creator }) => {
            assert_eq!(recipient, charlie_id);
            assert_eq!(creator, creator_id);
        }
        other => panic!("Expected InvalidRedeemRecipient, got: {:?}", other),
    }
}

#[test]
fn test_consolidation_zone_to_creator_requires_redeem() {
    enable_bypass();
    let (standard, std_hash) = &*FREETALER_STANDARD;
    let mut voucher = build_base_voucher(standard, std_hash, "2031-01-01T00:00:00.000000Z");

    let creator_id = ACTORS.alice.identity.user_id.clone();
    let mut prev_recv_key = key_for_index(2);

    // Build chain up to depth 511 (512 total transactions with init)
    for i in 1..512 {
        let sender_key = prev_recv_key;
        let receiver_key = key_for_index(1000 + i);
        let receiver_hash = get_hash(receiver_key.verifying_key().to_bytes());
        let prev_tx = voucher.transactions.last().unwrap();
        let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());
        let sender_id = if i % 2 == 1 { ACTORS.bob.identity.user_id.clone() } else { ACTORS.charlie.identity.user_id.clone() };
        let recipient_id = if i % 2 == 1 { ACTORS.charlie.identity.user_id.clone() } else { ACTORS.bob.identity.user_id.clone() };

        let mut tx = Transaction {
            t_id: String::new(),
            prev_hash,
            t_type: "transfer".to_string(),
            t_time: t_time_for(i),
            sender_id: Some(sender_id),
            recipient_id,
            amount: "100.00".to_string(),
            sender_remaining_amount: None,
            receiver_ephemeral_pub_hash: Some(receiver_hash),
            sender_ephemeral_pub: Some(bs58::encode(sender_key.verifying_key().to_bytes()).into_string()),
            privacy_guard: None,
            trap_data: None,
            layer2_signature: Some("dummy_sig".to_string()),
            deletable_at: None,
            change_ephemeral_pub_hash: None,
            sender_identity_signature: Some("dummy_id_sig".to_string()),
        };
        recompute_tid(&mut tx);
        voucher.transactions.push(tx);
        prev_recv_key = receiver_key;
    }

    assert_eq!(voucher.hop_depth(), 511);

    // Transaction at index 512 (Consolidation zone threshold >= 512) to Creator as 'transfer'
    let sender_key = prev_recv_key;
    let creator_recv_key = key_for_index(9999);
    let creator_recv_hash = get_hash(creator_recv_key.verifying_key().to_bytes());
    let prev_tx = voucher.transactions.last().unwrap();
    let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());

    let mut transfer_tx = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash.clone(),
        t_type: "transfer".to_string(),
        t_time: t_time_for(512),
        sender_id: Some(ACTORS.charlie.identity.user_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(creator_recv_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(sender_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut transfer_tx);
    voucher.transactions.push(transfer_tx);

    let err = human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect_err("Transfer to creator at consolidation depth >= 512 must fail");

    match err {
        VoucherCoreError::Validation(ValidationError::RedeemRequiredInConsolidationZone { depth, threshold }) => {
            assert_eq!(depth, 512);
            assert_eq!(threshold, CONSOLIDATION_ZONE_THRESHOLD);
        }
        other => panic!("Expected RedeemRequiredInConsolidationZone, got: {:?}", other),
    }

    // Now change t_type to 'redeem' -> Must succeed!
    voucher.transactions.pop();
    let mut redeem_tx = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "redeem".to_string(),
        t_time: t_time_for(512),
        sender_id: Some(ACTORS.charlie.identity.user_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(creator_recv_hash),
        sender_ephemeral_pub: Some(bs58::encode(sender_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut redeem_tx);
    voucher.transactions.push(redeem_tx);

    human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect("Redeem to creator at consolidation depth >= 512 must succeed");
}

#[test]
fn test_expired_issuance_to_creator_requires_redeem() {
    enable_bypass();
    let (mut standard, _) = (*MINUTO_STANDARD).clone();
    // Minuto standard has issuance_minimum_validity_duration = "P3Y"
    standard.immutable.issuance.issuance_minimum_validity_duration = "P3Y".to_string();
    let std_hash = get_hash(to_canonical_json(&standard.immutable).unwrap());

    // Voucher valid until only 1 year from creation (less than P3Y)
    let mut voucher = build_base_voucher(&standard, &std_hash, "2027-01-01T00:00:00.000000Z");

    let creator_id = ACTORS.alice.identity.user_id.clone();
    let bob_id = ACTORS.bob.identity.user_id.clone();

    // Tx 1: Transfer to Bob
    let holder_key = key_for_index(2);
    let bob_key = key_for_index(3);
    let bob_hash = get_hash(bob_key.verifying_key().to_bytes());
    let prev_tx = voucher.transactions.last().unwrap();
    let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());

    let mut tx1 = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: t_time_for(1),
        sender_id: Some(creator_id.clone()),
        recipient_id: bob_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(bob_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(holder_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx1);
    voucher.transactions.push(tx1);

    // Tx 2: Transfer back to Creator with remaining validity < 3 years -> MUST FAIL
    let prev_tx2 = voucher.transactions.last().unwrap();
    let prev_hash2 = get_hash(to_canonical_json(prev_tx2).unwrap());
    let alice_key = key_for_index(4);
    let alice_hash = get_hash(alice_key.verifying_key().to_bytes());

    let mut tx2_transfer = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash2.clone(),
        t_type: "transfer".to_string(),
        t_time: t_time_for(2),
        sender_id: Some(bob_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(alice_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(bob_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx2_transfer);
    voucher.transactions.push(tx2_transfer);

    let err = human_money_core::services::voucher_validation::verify_transactions(&voucher, &standard)
        .expect_err("Transfer to creator when validity duration < P3Y must fail");

    match err {
        VoucherCoreError::Validation(ValidationError::RedeemRequiredForExpiredIssuance { valid_until, .. }) => {
            assert_eq!(valid_until, "2027-01-01T00:00:00.000000Z");
        }
        other => panic!("Expected RedeemRequiredForExpiredIssuance, got: {:?}", other),
    }

    // Changing to 'redeem' must succeed!
    voucher.transactions.pop();
    let mut tx2_redeem = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash2,
        t_type: "redeem".to_string(),
        t_time: t_time_for(2),
        sender_id: Some(bob_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "100".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(alice_hash),
        sender_ephemeral_pub: Some(bs58::encode(bob_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx2_redeem);
    voucher.transactions.push(tx2_redeem);

    human_money_core::services::voucher_validation::verify_transactions(&voucher, &standard)
        .expect("Redeem to creator when validity duration < P3Y must succeed");
}

#[test]
fn test_spendable_balance_and_split_before_redeem() {
    enable_bypass();
    let (standard, std_hash) = &*FREETALER_STANDARD;
    let mut voucher = build_base_voucher(standard, std_hash, "2031-01-01T00:00:00.000000Z");

    let creator_id = ACTORS.alice.identity.user_id.clone();
    let bob_id = ACTORS.bob.identity.user_id.clone();

    // 1. Initial balance check
    assert_eq!(voucher.spendable_balance(None, None), Decimal::new(10000, 2));

    // 2. Transfer from Creator to Bob
    let holder_key = key_for_index(2);
    let bob_key = key_for_index(3);
    let bob_hash = get_hash(bob_key.verifying_key().to_bytes());
    let prev_tx = voucher.transactions.last().unwrap();
    let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());

    let mut tx1 = Transaction {
        t_id: String::new(),
        prev_hash,
        t_type: "transfer".to_string(),
        t_time: t_time_for(1),
        sender_id: Some(creator_id.clone()),
        recipient_id: bob_id.clone(),
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(bob_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(holder_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx1);
    voucher.transactions.push(tx1);

    // 3. Bob splits: 70 to redeem branch, 30 to change branch
    let prev_tx2 = voucher.transactions.last().unwrap();
    let prev_hash2 = get_hash(to_canonical_json(prev_tx2).unwrap());
    let redeem_branch_key = key_for_index(4);
    let redeem_branch_hash = get_hash(redeem_branch_key.verifying_key().to_bytes());
    let change_key = key_for_index(5);
    let change_hash = get_hash(change_key.verifying_key().to_bytes());

    let mut tx2_split = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash2,
        t_type: "split".to_string(),
        t_time: t_time_for(2),
        sender_id: Some(bob_id.clone()),
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        amount: "70.00".to_string(),
        sender_remaining_amount: Some("30.00".to_string()),
        receiver_ephemeral_pub_hash: Some(redeem_branch_hash.clone()),
        sender_ephemeral_pub: Some(bs58::encode(bob_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: Some(change_hash.clone()),
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx2_split);
    voucher.transactions.push(tx2_split);

    // Verify split voucher
    human_money_core::services::voucher_validation::verify_transactions(&voucher, standard)
        .expect("Split transaction must be valid");

    // Change branch has 30.00 spendable
    let change_balance = voucher.spendable_balance_for_user(
        &bob_id,
        standard,
        Some(&change_hash),
    ).unwrap();
    assert_eq!(change_balance, Decimal::new(3000, 2));

    // 4. Redeem branch (70.00) is redeemed to Creator (Alice)
    let mut redeemed_voucher = voucher.clone();
    let prev_tx3 = redeemed_voucher.transactions.last().unwrap();
    let prev_hash3 = get_hash(to_canonical_json(prev_tx3).unwrap());
    let creator_final_key = key_for_index(6);
    let creator_final_hash = get_hash(creator_final_key.verifying_key().to_bytes());

    let mut tx3_redeem = Transaction {
        t_id: String::new(),
        prev_hash: prev_hash3,
        t_type: "redeem".to_string(),
        t_time: t_time_for(3),
        sender_id: Some(bob_id.clone()),
        recipient_id: creator_id.clone(),
        amount: "70.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(creator_final_hash),
        sender_ephemeral_pub: Some(bs58::encode(redeem_branch_key.verifying_key().to_bytes()).into_string()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: None,
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut tx3_redeem);
    redeemed_voucher.transactions.push(tx3_redeem);

    human_money_core::services::voucher_validation::verify_transactions(&redeemed_voucher, standard)
        .expect("Redeem transaction on split branch must be valid");

    // Spendable balance of redeemed voucher must be ZERO
    assert_eq!(redeemed_voucher.spendable_balance(None, None), Decimal::ZERO);
    assert_eq!(
        redeemed_voucher.spendable_balance_for_user(&creator_id, standard, None).unwrap(),
        Decimal::ZERO
    );
    assert_eq!(
        redeemed_voucher.spendable_balance_for_user(&bob_id, standard, Some(&redeem_branch_hash)).unwrap(),
        Decimal::ZERO
    );
}
