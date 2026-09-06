use human_money_core::services::crypto::get_hash;
use human_money_core::services::utils::to_canonical_json;
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

    let mut voucher1 = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data1,
        &standard,
        &standard_hash,
        &identity.signing_key)
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
        human_money_core::services::crypto::sign_ed25519(&identity.signing_key, &t_id_raw);
    bad_tx.sender_identity_signature =
        Some(bs58::encode(identity_sig_bytes.to_bytes()).into_string());

    // Recalculate Layer 2 Signature
    let nonce_bytes = bs58::decode(&voucher2.voucher_nonce).into_vec().unwrap();
    let creator_prefix = identity.user_id.split(':').next().unwrap();
    let (genesis_secret, genesis_pub) =
        human_money_core::services::crypto::derive_ephemeral_key_pair(
            &identity.signing_key,
            &nonce_bytes,
            "genesis",
            Some(creator_prefix),
        )
        .unwrap();

    let sender_pub_raw = genesis_pub.to_bytes().to_vec();

    // V2 protocol: bind trap data (trap_r/trap_s) and encrypted timestamp,
    // mirroring exactly what the production signer/verifier reconstructs.
    let challenge_ds_tag = if bad_tx.t_type == "init" {
        bad_tx.t_id.clone()
    } else {
        bad_tx
            .trap_data
            .as_ref()
            .map(|td| td.ds_tag.clone())
            .unwrap_or_else(|| bad_tx.t_id.clone())
    };
    let (trap_r_str, trap_s_str) = match &bad_tx.trap_data {
        Some(td) => (td.trap_r.as_str(), td.trap_s.as_str()),
        None => ("none", "none"),
    };
    let encrypted_timestamp =
        human_money_core::services::conflict_manager::encrypt_transaction_timestamp(&bad_tx)
            .unwrap_or(0);

    let to_32_bytes = |vec: Vec<u8>| -> [u8; 32] { vec.try_into().unwrap() };

    let payload_hash = human_money_core::services::l2_gateway::calculate_l2_payload_hash_raw(
        // V3 Protocol (audit_02_11): init/genesis locks sign the canonical
        // "none" placeholder for the voucher container id.
        human_money_core::services::l2_gateway::TRAP_NONE_PLACEHOLDER,
        &challenge_ds_tag,
        &to_32_bytes(t_id_raw),
        &to_32_bytes(sender_pub_raw),
        trap_r_str,
        trap_s_str,
        encrypted_timestamp,
        bad_tx.deletable_at.as_deref(),
        // SECURITY (HMSEC-SA04-08): bind the canonical privacy-guard
        // commitment ("" when no guard is present).
        &human_money_core::services::l2_gateway::privacy_guard_commitment(
            bad_tx.privacy_guard.as_deref(),
        ),
    );
    let l2_sig_bytes =
        human_money_core::services::crypto::sign_ed25519(&genesis_secret, &payload_hash);
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

    let mut voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        &standard,
        &standard_hash,
        &identity.signing_key)
    .unwrap();

    let g1 = &ACTORS.guarantor1;
    voucher.signatures.push(create_guarantor_signature(
        &voucher,
        g1,
        "G1",
        "guarantor",
        "1",
    ));

    // Create a fake guarantor 2 that uses the CREATOR'S key but a different
    // (canonical) prefix. The alias is grammatically valid per validate_user_id,
    // so rejection MUST come from raw-pubkey deduplication, not grammar checks.
    let mut fake_g2 = identity.clone();
    fake_g2.identity.user_id = human_money_core::services::crypto::create_user_id(
        &fake_g2.identity.public_key,
        Some("private-fake"),
    )
    .unwrap();
    
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

    let mut voucher = human_money_core::models::voucher::Voucher::create_with_key(
        voucher_data,
        &standard,
        &standard_hash,
        &identity.signing_key)
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

    // Use guarantor1's key again but a different (canonical) prefix. The alias
    // is grammatically valid per validate_user_id, so rejection MUST come from
    // raw-pubkey deduplication, not grammar checks.
    let mut fake_g2 = g1.clone();
    fake_g2.identity.user_id = human_money_core::services::crypto::create_user_id(
        &fake_g2.identity.public_key,
        Some("private-fake"),
    )
    .unwrap();
    
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
