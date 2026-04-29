use human_money_core::models::voucher::Transaction;

use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::get_current_timestamp;
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::setup_voucher_with_one_tx;
use human_money_core::to_canonical_json;

#[test]
fn test_public_mode_enforcement() {
    let (standard_ref, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();
    let mut standard = standard_ref.clone();

    standard.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Public;
    // Set matching validity in standard to satisfy validation checks
    standard.immutable.issuance.issuance_minimum_validity_duration = "P3Y".to_string();
    // Re-hash standard
    let mut std_no_sig = standard.clone();
    std_no_sig.signature = None;
    let new_hash = get_hash(to_canonical_json(&std_no_sig.immutable).unwrap());
    voucher.voucher_standard.standard_definition_hash = new_hash.clone();

    let desc_str = human_money_core::services::standard_manager::get_localized_text(
        &standard.mutable.i18n.descriptions,
        "en",
    )
    .unwrap_or("")
    .to_string();

    voucher.voucher_standard = human_money_core::models::voucher::VoucherStandard {
        name: standard.immutable.identity.name.clone(),
        uuid: standard.immutable.identity.uuid.clone(),
        standard_definition_hash: new_hash,
        template: human_money_core::models::voucher::VoucherTemplateData {
            description: desc_str,
            primary_redemption_type: "goods_or_services".to_string(),
            allow_partial_transfers: standard.immutable.features.allow_partial_transfers,
            issuance_minimum_validity_duration: "P3Y".to_string(),
            footnote: "".to_string(),
        },
    };

    // Recalculate Voucher ID
    let mut voucher_header = voucher.clone();
    voucher_header.voucher_id = "".to_string();
    voucher_header.transactions = vec![];
    voucher_header.signatures = vec![];
    let new_voucher_id = get_hash(to_canonical_json(&voucher_header).unwrap());
    voucher.voucher_id = new_voucher_id.clone();

    // Truncate
    voucher.transactions.truncate(1);

    // Mod Init for Linking
    let secret = bs58::encode("secret_link_seed").into_string();
    let secret_hash = get_hash(bs58::decode(&secret).into_vec().unwrap());
    voucher.transactions[0].receiver_ephemeral_pub_hash = Some(secret_hash);

    // Fix Genesis Transaction
    let genesis_prev_hash = {
        let v_id_bytes = bs58::decode(&new_voucher_id).into_vec().unwrap();
        let v_nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().unwrap();
        human_money_core::services::crypto_utils::get_hash_from_slices(&[
            &v_id_bytes,
            &v_nonce_bytes,
        ])
    };
    voucher.transactions[0].prev_hash = genesis_prev_hash;
    let genesis_hash = get_hash(to_canonical_json(&voucher.transactions[0]).unwrap());
    let amount = voucher.transactions[0].amount.clone();

    // Add Transfer Transaction
    let tx_1 = Transaction {
        t_id: "stub_public".to_string(),
        prev_hash: genesis_hash,
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: amount,
        sender_id: None, // Fail case first
        recipient_id: "did:key:recipient".to_string(),
        sender_ephemeral_pub: Some(secret.to_string()), // Needed for balance check
        ..Default::default()
    };
    voucher.transactions.push(tx_1);

    human_money_core::set_signature_bypass(true);
    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(result.is_err(), "Public mode must reject missing sender_id");

    // Fix it
    let last_idx = voucher.transactions.len() - 1;
    voucher.transactions[last_idx].sender_id = Some(voucher.transactions[0].recipient_id.clone());

    let result_ok = validate_voucher_against_standard(&voucher, &standard);
    if let Err(e) = &result_ok {
        panic!("Validation failed: {:?}", e);
    }
    assert!(
        result_ok.is_ok(),
        "Validation should pass with sender_id present"
    );
    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_private_mode_enforcement() {
    let (standard_ref, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();
    let mut standard = standard_ref.clone();

    standard.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Stealth;

    let mut std_no_sig = standard.clone();
    std_no_sig.signature = None;
    let new_hash = get_hash(to_canonical_json(&std_no_sig.immutable).unwrap());
    voucher.voucher_standard.standard_definition_hash = new_hash;

    // Recalculate Voucher ID for Private
    let mut voucher_header = voucher.clone();
    voucher_header.voucher_id = "".to_string();
    voucher_header.transactions = vec![];
    voucher_header.signatures = vec![];
    let new_voucher_id = get_hash(to_canonical_json(&voucher_header).unwrap());
    voucher.voucher_id = new_voucher_id.clone();

    // Truncate to Init Only
    voucher.transactions.truncate(1);

    // Modify Init to allow Private Spending (Set ephemeral hash we know)
    let secret_key = bs58::encode("secret_key_for_private").into_string();
    let secret_key_hash = get_hash(bs58::decode(&secret_key).into_vec().unwrap());

    // We KEEP recipient_id as Creator (Public) to pass Init rules.
    voucher.transactions[0].receiver_ephemeral_pub_hash = Some(secret_key_hash.clone());

    let genesis_prev_hash = {
        let v_id_bytes = bs58::decode(&new_voucher_id).into_vec().unwrap();
        let v_nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().unwrap();
        human_money_core::services::crypto_utils::get_hash_from_slices(&[
            &v_id_bytes,
            &v_nonce_bytes,
        ])
    };
    voucher.transactions[0].prev_hash = genesis_prev_hash;

    let genesis_hash = get_hash(to_canonical_json(&voucher.transactions[0]).unwrap());
    let amount = voucher.transactions[0].amount.clone();

    // Add Private Transfer Transaction
    let mut tx_1 = Transaction {
        t_id: "stub_private".to_string(),
        prev_hash: genesis_hash,
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: amount, // Must match exactly
        sender_id: None, // Correct for Private
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(), // Correct for Private
        sender_ephemeral_pub: Some(secret_key.to_string()), // Reveals key -> Links to Init
        ..Default::default()
    };

    // We intentionally violate rule first: Add sender_id
    tx_1.sender_id = Some("did:key:fail".to_string());
    voucher.transactions.push(tx_1);

    human_money_core::set_signature_bypass(true);
    let result = validate_voucher_against_standard(&voucher, &standard);

    assert!(
        result.is_err(),
        "Private mode must reject cleartext sender_id"
    );

    // Fix it
    let last_idx = voucher.transactions.len() - 1;
    voucher.transactions[last_idx].sender_id = None;

    let result_ok = validate_voucher_against_standard(&voucher, &standard);
    if let Err(e) = &result_ok {
        panic!("Validation failed: {:?}", e);
    }
    assert!(
        result_ok.is_ok(),
        "Private mode should accept anonymous sender"
    );

    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_flexible_mode_hybrid_behavior() {
    let (standard_ref, _hash, _creator, _recipient, mut voucher, _secrets) =
        setup_voucher_with_one_tx();
    let mut standard = standard_ref.clone();

    standard.immutable.features.privacy_mode = human_money_core::models::voucher_standard_definition::PrivacyMode::Flexible;
    let mut std_no_sig = standard.clone();
    std_no_sig.signature = None;
    let new_hash = get_hash(to_canonical_json(&std_no_sig.immutable).unwrap());
    voucher.voucher_standard.standard_definition_hash = new_hash;

    // Recalculate Voucher ID for Flexible
    let mut voucher_header = voucher.clone();
    voucher_header.voucher_id = "".to_string();
    voucher_header.transactions = vec![];
    voucher_header.signatures = vec![];
    let new_voucher_id = get_hash(to_canonical_json(&voucher_header).unwrap());
    voucher.voucher_id = new_voucher_id.clone();

    // Truncate
    voucher.transactions.truncate(1);

    // Mod Init for Linking
    let secret = bs58::encode("secret_link_flex").into_string();
    let secret_hash = get_hash(bs58::decode(&secret).into_vec().unwrap());
    voucher.transactions[0].receiver_ephemeral_pub_hash = Some(secret_hash);

    let genesis_prev_hash = {
        let v_id_bytes = bs58::decode(&new_voucher_id).into_vec().unwrap();
        let v_nonce_bytes = bs58::decode(&voucher.voucher_nonce).into_vec().unwrap();
        human_money_core::services::crypto_utils::get_hash_from_slices(&[
            &v_id_bytes,
            &v_nonce_bytes,
        ])
    };
    voucher.transactions[0].prev_hash = genesis_prev_hash;
    let genesis_hash = get_hash(to_canonical_json(&voucher.transactions[0]).unwrap());
    let amount = voucher.transactions[0].amount.clone();

    // Add Transfer Transaction
    let tx_1 = Transaction {
        t_id: "stub_flex".to_string(),
        prev_hash: genesis_hash,
        t_time: get_current_timestamp(),
        t_type: "transfer".to_string(),
        amount: amount,
        sender_id: Some(voucher.transactions[0].recipient_id.clone()), // Valid Sender (Public)
        recipient_id: human_money_core::models::voucher::ANONYMOUS_ID.to_string(),
        sender_ephemeral_pub: Some(secret.to_string()),
        receiver_ephemeral_pub_hash: Some("some_hash".to_string()),
        ..Default::default()
    };
    voucher.transactions.push(tx_1);

    human_money_core::set_signature_bypass(true);
    let result = validate_voucher_against_standard(&voucher, &standard);
    if let Err(e) = &result {
        panic!("Validation failed: {:?}", e);
    }
    assert!(result.is_ok());

    human_money_core::set_signature_bypass(false);
}
