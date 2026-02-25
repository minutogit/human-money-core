use human_money_core::services::crypto_utils::get_hash;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_manager::create_voucher;
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::set_signature_bypass;
use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD as BASE_STANDARD, create_guarantor_signature,
    create_minuto_voucher_data,
};

#[test]
fn test_prevent_signature_reuse_in_init() {
    // Disable signature bypass to actually verify the "real" signatures we generate
    set_signature_bypass(false);

    let (standard, standard_hash) = (BASE_STANDARD.0.clone(), BASE_STANDARD.1.clone());

    // Create first valid voucher instance
    let identity = &ACTORS.issuer;
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data1 = create_minuto_voucher_data(creator.clone());

    let mut voucher1 = create_voucher(
        voucher_data1,
        &standard,
        &standard_hash,
        &identity.signing_key,
        "en",
    )
    .unwrap();

    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher1.signatures.push(create_guarantor_signature(
        &voucher1,
        g1,
        "G1",
        "guarantor",
        "1",
    ));
    voucher1.signatures.push(create_guarantor_signature(
        &voucher1,
        g2,
        "G2",
        "guarantor",
        "2",
    ));

    // Validate voucher1 - this must succeed
    validate_voucher_against_standard(&voucher1, &standard).unwrap();

    // The attacker modifies the init transaction to create a separate parallel copy
    // of the voucher on Layer 2 (e.g. by changing the initial t_time slightly, changing the transaction hash)
    let mut voucher2 = voucher1.clone();
    let mut bad_tx = voucher2.transactions[0].clone();
    bad_tx.t_time = human_money_core::services::utils::get_current_timestamp();
    bad_tx.t_id = "".to_string();

    let mut tx_for_hash = bad_tx.clone();
    tx_for_hash.layer2_signature = None;
    tx_for_hash.sender_identity_signature = None;
    bad_tx.t_id = get_hash(to_canonical_json(&tx_for_hash).unwrap());

    // Recalculate Sender Identity Signature
    let t_id_raw = bs58::decode(&bad_tx.t_id).into_vec().unwrap();
    let identity_sig_bytes =
        human_money_core::services::crypto_utils::sign_ed25519(&identity.signing_key, &t_id_raw);
    bad_tx.sender_identity_signature =
        Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());

    // Recalculate Layer 2 Signature
    let nonce_bytes = bs58::decode(&voucher2.voucher_nonce).into_vec().unwrap();
    let creator_prefix = identity.user_id.split(':').next().unwrap();
    let (genesis_secret, genesis_pub) =
        human_money_core::services::crypto_utils::derive_ephemeral_key_pair(
            &identity.signing_key,
            &nonce_bytes,
            "genesis",
            Some(creator_prefix),
        )
        .unwrap();

    let sender_pub_raw = genesis_pub.to_bytes().to_vec();
    let receiver_hash_str = bad_tx.receiver_ephemeral_pub_hash.as_ref().unwrap();
    let receiver_hash_raw = bs58::decode(receiver_hash_str).into_vec().unwrap();

    let v_id =
        human_money_core::services::l2_gateway::calculate_layer2_voucher_id(&bad_tx).unwrap();
    let challenge_ds_tag = bad_tx.t_id.clone();

    let to_32_bytes = |vec: Vec<u8>| -> [u8; 32] { vec.try_into().unwrap() };

    let payload_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        &challenge_ds_tag,
        &v_id,
        &to_32_bytes(t_id_raw),
        &to_32_bytes(sender_pub_raw),
        Some(&to_32_bytes(receiver_hash_raw)),
        None,
        bad_tx.deletable_at.as_deref(),
    );
    let l2_sig_bytes =
        human_money_core::services::crypto_utils::sign_ed25519(&genesis_secret, &payload_hash);
    bad_tx.layer2_signature = Some(bs58::encode(l2_sig_bytes.to_bytes()).into_string());

    // Replace the init tx in voucher2
    voucher2.transactions[0] = bad_tx;

    // Ensure they really have different init transactions
    assert_ne!(voucher1.transactions[0].t_id, voucher2.transactions[0].t_id);

    let result = validate_voucher_against_standard(&voucher2, &standard);

    if let Err(e) = &result {
        println!(
            "Validation error for Voucher 2 (expected success if vulnerable): {:?}",
            e
        );
    }

    assert!(
        result.is_err(),
        "VULNERABILITY: Voucher 2 with stolen guarantor signatures from Voucher 1 was accepted!"
    );
}

#[test]
fn test_reject_same_key_different_prefix() {
    set_signature_bypass(false);
    let (standard, standard_hash) = (BASE_STANDARD.0.clone(), BASE_STANDARD.1.clone());

    let identity = &ACTORS.issuer; // Creator
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = create_minuto_voucher_data(creator.clone());

    let mut voucher = create_voucher(
        voucher_data,
        &standard,
        &standard_hash,
        &identity.signing_key,
        "en",
    )
    .unwrap();

    let g1 = &ACTORS.guarantor1;
    voucher.signatures.push(create_guarantor_signature(
        &voucher,
        g1,
        "G1",
        "guarantor",
        "1",
    ));

    // Create a fake guarantor 2 that uses the CREATOR'S key but a different prefix
    let mut fake_g2 = identity.clone();
    fake_g2.identity.user_id = format!("private:fake@{}", identity.user_id.split('@').last().unwrap());
    
    voucher.signatures.push(create_guarantor_signature(
        &voucher,
        &fake_g2,
        "G2",
        "guarantor",
        "2",
    ));

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(
        result.is_err(),
        "Voucher accepted despite creator's key being reused for guarantor role!"
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::DuplicateIdentityDetected { .. })) = result {
        // Expected
    } else {
        panic!("Expected DuplicateIdentityDetected error, got {:?}", result);
    }
}

#[test]
fn test_reject_two_guarantors_same_key() {
    set_signature_bypass(false);
    let (standard, standard_hash) = (BASE_STANDARD.0.clone(), BASE_STANDARD.1.clone());

    let identity = &ACTORS.issuer;
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = create_minuto_voucher_data(creator.clone());

    let mut voucher = create_voucher(
        voucher_data,
        &standard,
        &standard_hash,
        &identity.signing_key,
        "en",
    )
    .unwrap();

    // Use guarantor1
    let g1 = &ACTORS.guarantor1;
    voucher.signatures.push(create_guarantor_signature(
        &voucher,
        g1,
        "G1",
        "guarantor",
        "1",
    ));

    // Use guarantor1's key again but different prefix
    let mut fake_g2 = g1.clone();
    fake_g2.identity.user_id = format!("private:fake@{}", g1.user_id.split('@').last().unwrap());
    
    voucher.signatures.push(create_guarantor_signature(
        &voucher,
        &fake_g2,
        "G2",
        "guarantor",
        "2",
    ));

    let result = validate_voucher_against_standard(&voucher, &standard);
    assert!(
        result.is_err(),
        "Voucher accepted despite identical guarantor keys!"
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::DuplicateIdentityDetected { .. })) = result {
        // Expected
    } else {
        panic!("Expected DuplicateIdentityDetected error, got {:?}", result);
    }
}
