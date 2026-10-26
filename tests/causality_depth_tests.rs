//! tests/causality_depth_tests.rs
//! Validates path-depth limits and consolidation rules per architecture spec.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use human_money_core::error::ValidationError;
use human_money_core::models::profile::PublicProfile;
use human_money_core::models::voucher::{
    Transaction, ValueDefinition, Voucher, VoucherStandard, CONSOLIDATION_ZONE_THRESHOLD,
    MAX_PATH_DEPTH,
};
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::crypto::get_hash;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD};

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

fn sender_id_for_depth(i: usize) -> String {
    match i % 3 {
        0 => ACTORS.bob.identity.user_id.clone(),
        1 => ACTORS.charlie.identity.user_id.clone(),
        _ => ACTORS.david.identity.user_id.clone(),
    }
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

fn build_voucher(depth: usize, standard: VoucherStandardDefinition, standard_hash: String) -> Voucher {
    let creator = &ACTORS.alice.identity;
    let creator_id = creator.user_id.clone();

    let nonce_bytes = [0x11u8; 16];
    let voucher_nonce = bs58::encode(nonce_bytes).into_string();
    let creation_date = t_time_for(0);
    let valid_until = "2031-01-01T00:00:00.000000Z".to_string();

    let mut voucher = Voucher {
        voucher_standard: VoucherStandard {
            name: standard.immutable.identity.name.clone(),
            uuid: standard.immutable.identity.uuid.clone(),
            standard_definition_hash: standard_hash.clone(),
        },
        voucher_id: String::new(),
        voucher_nonce: voucher_nonce.clone(),
        creation_date: creation_date.clone(),
        valid_until: valid_until.clone(),
        non_redeemable_test_voucher: false,
        nominal_value: ValueDefinition {
            unit: standard.immutable.blueprint.unit.clone(),
            amount: "100.00".to_string(),
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
        amount: "100.00".to_string(),
        sender_remaining_amount: None,
        receiver_ephemeral_pub_hash: Some(holder_hash.clone()),
        sender_ephemeral_pub: Some(genesis_pub_str.clone()),
        privacy_guard: None,
        trap_data: None,
        layer2_signature: Some("dummy_sig".to_string()),
        deletable_at: Some(valid_until.clone()),
        change_ephemeral_pub_hash: None,
        sender_identity_signature: Some("dummy_id_sig".to_string()),
    };
    recompute_tid(&mut init_tx);
    voucher.transactions.push(init_tx);

    let mut prev_receiver_key = holder_key;

    for i in 1..=depth {
        let sender_key = prev_receiver_key;
        let sender_pub_bytes = sender_key.verifying_key().to_bytes();
        let sender_pub_str = bs58::encode(sender_pub_bytes).into_string();
        let receiver_key = key_for_index(1000 + i);
        let receiver_hash = get_hash(receiver_key.verifying_key().to_bytes());
        let prev_tx = voucher.transactions.last().unwrap();
        let prev_hash = get_hash(to_canonical_json(prev_tx).unwrap());
        let t_time = t_time_for(i);
        let sender_id = if i == 1 { creator_id.clone() } else { sender_id_for_depth(i) };
        let mut tx = Transaction {
            t_id: String::new(),
            prev_hash,
            t_type: "transfer".to_string(),
            t_time,
            sender_id: Some(sender_id),
            recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
            amount: "100.00".to_string(),
            sender_remaining_amount: None,
            receiver_ephemeral_pub_hash: Some(receiver_hash.clone()),
            sender_ephemeral_pub: Some(sender_pub_str.clone()),
            privacy_guard: None,
            trap_data: None,
            layer2_signature: Some("dummy_sig".to_string()),
            deletable_at: None,
            change_ephemeral_pub_hash: None,
            sender_identity_signature: Some("dummy_id_sig".to_string()),
        };
        recompute_tid(&mut tx);
        voucher.transactions.push(tx);
        prev_receiver_key = receiver_key;
    }

    voucher
}

fn get_standard_with_min(min: Option<&str>) -> (VoucherStandardDefinition, String) {
    let (base, _) = &*FREETALER_STANDARD;
    let mut std = base.clone();
    std.immutable.features.min_transfer_amount = min.map(|s| s.to_string());
    let new_hash = get_hash(to_canonical_json(&std.immutable).unwrap());
    (std, new_hash)
}

fn verify(voucher: &Voucher, standard: &VoucherStandardDefinition) -> Result<(), human_money_core::VoucherCoreError> {
    human_money_core::services::voucher_validation::verify_transactions(voucher, standard)
}

// ---------------------------------------------------------------------------

#[test]
fn test_constants_and_hop_depth() {
    assert_eq!(MAX_PATH_DEPTH, 1024);
    assert_eq!(CONSOLIDATION_ZONE_THRESHOLD, 512);
    let mut v = Voucher::default();
    assert_eq!(v.hop_depth(), 0);
    v.transactions.push(Transaction::default());
    assert_eq!(v.hop_depth(), 0);
    v.transactions.push(Transaction::default());
    assert_eq!(v.hop_depth(), 1);
    let (std, hash) = get_standard_with_min(None);
    let v3 = build_voucher(3, std.clone(), hash.clone());
    assert_eq!(v3.hop_depth(), 3);
    let v1024 = build_voucher(1024, std, hash);
    assert_eq!(v1024.hop_depth(), 1024);
}

#[test]
fn test_hop_limit_boundary() {
    enable_bypass();
    let (std, hash) = get_standard_with_min(None);
    let voucher_ok = build_voucher(1024, std.clone(), hash.clone());
    let res_ok = verify(&voucher_ok, &std);
    assert!(res_ok.is_ok(), "depth 1024 should pass, got {:?}", res_ok);

    let voucher_fail = build_voucher(1025, std.clone(), hash.clone());
    let res_fail = verify(&voucher_fail, &std);
    match res_fail {
        Err(human_money_core::VoucherCoreError::Validation(ValidationError::HopLimitExceeded { depth, max })) => {
            assert_eq!(depth, 1025);
            assert_eq!(max, MAX_PATH_DEPTH);
        }
        _ => panic!("expected HopLimitExceeded, got {:?}", res_fail),
    }
}

#[test]
fn test_consolidation_split_forbidden() {
    enable_bypass();
    let (std, hash) = get_standard_with_min(None);

    // depth 511 split allowed
    let mut voucher_511 = build_voucher(511, std.clone(), hash.clone());
    {
        let last = voucher_511.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "60.00".to_string();
        last.sender_remaining_amount = Some("40.00".to_string());
        let change_key = key_for_index(9000 + 511);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_511 = verify(&voucher_511, &std);
    assert!(res_511.is_ok(), "split at 511 should be allowed, got {:?}", res_511);

    // depth 512 split forbidden
    let mut voucher_512 = build_voucher(512, std.clone(), hash.clone());
    {
        let last = voucher_512.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "60.00".to_string();
        last.sender_remaining_amount = Some("40.00".to_string());
        let change_key = key_for_index(9000 + 512);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_512 = verify(&voucher_512, &std);
    match res_512 {
        Err(human_money_core::VoucherCoreError::Validation(ValidationError::SplitForbiddenInConsolidationZone { depth, max_split_depth })) => {
            assert_eq!(depth, 512);
            assert_eq!(max_split_depth, CONSOLIDATION_ZONE_THRESHOLD);
        }
        _ => panic!("expected SplitForbiddenInConsolidationZone at 512, got {:?}", res_512),
    }

    // depth 600 split also forbidden
    let mut voucher_600 = build_voucher(600, std.clone(), hash.clone());
    {
        let last = voucher_600.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "60.00".to_string();
        last.sender_remaining_amount = Some("40.00".to_string());
        let change_key = key_for_index(9000 + 600);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_600 = verify(&voucher_600, &std);
    assert!(matches!(res_600, Err(human_money_core::VoucherCoreError::Validation(ValidationError::SplitForbiddenInConsolidationZone { .. }))));
}

#[test]
fn test_consolidation_split_allowed_before_threshold_with_transfer() {
    enable_bypass();
    let (std, hash) = get_standard_with_min(None);
    let voucher = build_voucher(512, std.clone(), hash.clone());
    // last is transfer (default) so should pass
    let res = verify(&voucher, &std);
    assert!(res.is_ok(), "transfer at 512 should be allowed, got {:?}", res);
}

#[test]
fn test_issuer_recirculation_forbidden() {
    enable_bypass();
    let (std, hash) = get_standard_with_min(None);
    let creator_id = ACTORS.alice.identity.user_id.clone();

    let mut voucher_511 = build_voucher(511, std.clone(), hash.clone());
    {
        let last = voucher_511.transactions.last_mut().unwrap();
        last.sender_id = Some(creator_id.clone());
        recompute_tid(last);
    }
    let res_511 = verify(&voucher_511, &std);
    assert!(res_511.is_ok(), "issuer at 511 should be allowed, got {:?}", res_511);

    let mut voucher_512 = build_voucher(512, std.clone(), hash.clone());
    {
        let last = voucher_512.transactions.last_mut().unwrap();
        last.sender_id = Some(creator_id.clone());
        recompute_tid(last);
    }
    let res_512 = verify(&voucher_512, &std);
    match res_512 {
        Err(human_money_core::VoucherCoreError::Validation(ValidationError::IssuerRecirculationForbidden { depth, threshold })) => {
            assert_eq!(depth, 512);
            assert_eq!(threshold, CONSOLIDATION_ZONE_THRESHOLD);
        }
        _ => panic!("expected IssuerRecirculationForbidden at 512, got {:?}", res_512),
    }

    let mut voucher_700 = build_voucher(700, std.clone(), hash.clone());
    {
        let last = voucher_700.transactions.last_mut().unwrap();
        last.sender_id = Some(creator_id.clone());
        recompute_tid(last);
    }
    let res_700 = verify(&voucher_700, &std);
    assert!(matches!(res_700, Err(human_money_core::VoucherCoreError::Validation(ValidationError::IssuerRecirculationForbidden { .. }))));
}

#[test]
fn test_min_transfer_amount() {
    enable_bypass();
    let (std_min, _) = get_standard_with_min(Some("10.00"));
    let (std_min2, _) = get_standard_with_min(Some("10.00"));

    // amount below min should fail (use split so balance passes but amount fails)
    let mut voucher_fail = build_voucher(1, std_min.clone(), get_standard_with_min(Some("10.00")).1);
    {
        let last = voucher_fail.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "5.00".to_string();
        last.sender_remaining_amount = Some("95.00".to_string());
        let change_key = key_for_index(9999);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_fail = verify(&voucher_fail, &std_min);
    match res_fail {
        Err(human_money_core::VoucherCoreError::Validation(ValidationError::MinTransferAmountViolated { amount, min_allowed })) => {
            assert_eq!(amount, "5.00");
            assert_eq!(min_allowed, "10.00");
        }
        _ => panic!("expected MinTransferAmountViolated for 5.00 < 10.00, got {:?}", res_fail),
    }

    // amount exactly at min should pass with full transfer (100 >=10)
    let voucher_ok = build_voucher(1, std_min2.clone(), get_standard_with_min(Some("10.00")).1);
    // default transfer 100 passes min
    let res_ok = verify(&voucher_ok, &std_min2);
    assert!(res_ok.is_ok(), "amount 100 >= 10 should pass, got {:?}", res_ok);

    // split remaining below min should fail
    let (std_min3, _) = get_standard_with_min(Some("10.00"));
    let mut voucher_split_fail = build_voucher(1, std_min3.clone(), get_standard_with_min(Some("10.00")).1);
    {
        let last = voucher_split_fail.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "95.00".to_string();
        last.sender_remaining_amount = Some("5.00".to_string());
        let change_key = key_for_index(8888);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_split_fail = verify(&voucher_split_fail, &std_min3);
    match res_split_fail {
        Err(human_money_core::VoucherCoreError::Validation(ValidationError::MinTransferAmountViolated { amount, min_allowed })) => {
            assert_eq!(amount, "5.00");
            assert_eq!(min_allowed, "10.00");
        }
        _ => panic!("expected MinTransferAmountViolated for remaining 5.00, got {:?}", res_split_fail),
    }

    // split with both amounts above min should pass (60+40)
    let (std_min4, _) = get_standard_with_min(Some("10.00"));
    let mut voucher_split_ok = build_voucher(1, std_min4.clone(), get_standard_with_min(Some("10.00")).1);
    {
        let last = voucher_split_ok.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "60.00".to_string();
        last.sender_remaining_amount = Some("40.00".to_string());
        let change_key = key_for_index(7777);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_split_ok = verify(&voucher_split_ok, &std_min4);
    assert!(res_split_ok.is_ok(), "split 60+40 both >=10 should pass, got {:?}", res_split_ok);

    // split where amount below min should also fail
    let (std_min5, _) = get_standard_with_min(Some("10.00"));
    let mut voucher_split_amount_fail = build_voucher(1, std_min5.clone(), get_standard_with_min(Some("10.00")).1);
    {
        let last = voucher_split_amount_fail.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "5.00".to_string();
        last.sender_remaining_amount = Some("95.00".to_string());
        let change_key = key_for_index(6666);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_split_amount_fail = verify(&voucher_split_amount_fail, &std_min5);
    assert!(matches!(res_split_amount_fail, Err(human_money_core::VoucherCoreError::Validation(ValidationError::MinTransferAmountViolated { .. }))));

    // when min is None, small amount should pass
    let (std_none, hash_none) = get_standard_with_min(None);
    let mut voucher_small_none = build_voucher(1, std_none.clone(), hash_none);
    {
        let last = voucher_small_none.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "1.00".to_string();
        last.sender_remaining_amount = Some("99.00".to_string());
        let change_key = key_for_index(5555);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res_small_none = verify(&voucher_small_none, &std_none);
    assert!(res_small_none.is_ok(), "without min, small split should pass, got {:?}", res_small_none);
}

#[test]
fn test_min_transfer_and_consolidation_combined() {
    enable_bypass();
    let (std_min, hash_min) = get_standard_with_min(Some("10.00"));
    let mut voucher = build_voucher(512, std_min.clone(), hash_min);
    {
        let last = voucher.transactions.last_mut().unwrap();
        last.t_type = "split".to_string();
        last.amount = "5.00".to_string();
        last.sender_remaining_amount = Some("5.00".to_string());
        let change_key = key_for_index(4444);
        last.change_ephemeral_pub_hash = Some(get_hash(change_key.verifying_key().to_bytes()));
        recompute_tid(last);
    }
    let res = verify(&voucher, &std_min);
    assert!(matches!(res, Err(human_money_core::VoucherCoreError::Validation(ValidationError::SplitForbiddenInConsolidationZone { .. }))));
}

#[test]
fn test_hop_depth_edge() {
    enable_bypass();
    let (std, hash) = get_standard_with_min(None);
    let voucher = build_voucher(0, std.clone(), hash);
    assert_eq!(voucher.hop_depth(), 0);
    let res = verify(&voucher, &std);
    assert!(res.is_ok());
}

#[test]
fn test_immutable_features_min_transfer_serialization() {
    let std = get_standard_with_min(Some("10.00")).0;
    let json = serde_json::to_string(&std).unwrap();
    assert!(json.contains("10.00"));
    let parsed: VoucherStandardDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.immutable.features.min_transfer_amount, Some("10.00".to_string()));

    let std_none = get_standard_with_min(None).0;
    let json_none = serde_json::to_string(&std_none).unwrap();
    // Should skip when None
    assert!(!json_none.contains("min_transfer_amount") || !json_none.contains("10.00"));

    let toml_str = toml::to_string(&std).unwrap();
    let parsed_toml: VoucherStandardDefinition = toml::from_str(&toml_str).unwrap();
    assert_eq!(parsed_toml.immutable.features.min_transfer_amount, Some("10.00".to_string()));
}
