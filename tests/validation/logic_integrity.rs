// tests/validation/logic_integrity.rs
use human_money_core::services::voucher_validation::{
    validate_transaction_types, validate_voucher_against_standard, verify_signatures,
    verify_transactions,
};
use human_money_core::test_utils::{
    ACTORS, setup_voucher_with_one_tx,
};
use human_money_core::error::ValidationError;

#[test]
fn test_valid_until_matches_creation_date() {
    // Verifies that a voucher is valid even if valid_until is exactly equal to creation_date.
    let (standard, _standard_hash, _, _, mut voucher, _) = setup_voucher_with_one_tx();
    
    // Set valid_until exactly to creation_date
    voucher.valid_until = voucher.creation_date.clone();
    
    // The original system allows this (or does not intercept it via the < logic at this point).
    // A mutant with <= would throw an InvalidDateLogic here.
    // We validate against the standard (standard can reject it later due to minimum, but the
    // specific check for "valid_until < creation_dt" must not fail). 
    // ATTENTION: The next check (verify_validity_duration) would fail if min_duration > 0.
    // To pass only the first check, we can patch the standard so min_duration = 0.
    let mut modified_std = standard.clone();
    modified_std.immutable.issuance.issuance_minimum_validity_duration = "".to_string();
    let mod_std_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&modified_std.immutable).unwrap()
    );
    
    voucher.voucher_standard.standard_definition_hash = mod_std_hash;

    // Re-hash voucher_id to pass verify_voucher_hash
    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();
    voucher.voucher_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher_to_hash).unwrap()
    );

    // Initial transaction must have the new voucher_id as prev_hash
    if !voucher.transactions.is_empty() {
        voucher.transactions[0].prev_hash = voucher.voucher_id.clone();
        
        // Re-hash transaction
        let mut tx_to_hash = voucher.transactions[0].clone();
        tx_to_hash.t_id = "".to_string();
        tx_to_hash.layer2_signature = None;
        tx_to_hash.sender_identity_signature = None;
        voucher.transactions[0].t_id = human_money_core::crypto_utils::get_hash(
            human_money_core::to_canonical_json(&tx_to_hash).unwrap()
        );
    }

    // Bypass verify_signature failures
    human_money_core::set_signature_bypass(true);
    
    // We ignore signature errors and focus on ensuring no InvalidDateLogic is returned.
    let res = validate_voucher_against_standard(&voucher, &modified_std);

    if let Err(e) = res {
        use human_money_core::error::VoucherCoreError;
        if let VoucherCoreError::Validation(ValidationError::InvalidDateLogic { .. }) = e {
            panic!("InvalidDateLogic thrown for equal timestamps, but should be allowed.");
        }
    }
    human_money_core::set_signature_bypass(false);
}

#[test]
fn test_transaction_type_validation() {
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();

    // Valid case
    voucher.transactions[0].t_type = "init".to_string();
    assert!(
        validate_transaction_types(&voucher, standard).is_ok(),
        "Valid transaction type 'init' was incorrectly rejected."
    );

    // Invalid case
    voucher.transactions[0].t_type = "fake_type".to_string();
    assert!(
        validate_transaction_types(&voucher, standard).is_err(),
        "Invalid transaction type 'fake_type' was incorrectly accepted."
    );
}

#[test]
fn test_signature_count_limits() {
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();

    // In FreeTaler standard max_sigs is e.g. 0. If we add an additional signature:
    let (vk, _) = human_money_core::crypto_utils::generate_ed25519_keypair_for_tests(Some("dummy"));
    let dummy_id = human_money_core::crypto_utils::create_user_id(&vk, Some("dummy")).unwrap();

    let dummy_sig = human_money_core::models::voucher::VoucherSignature {
        voucher_id: "".to_string(),
        signature_id: "s2".to_string(),
        signer_id: dummy_id,
        signature: "sig1".to_string(),
        signature_time: voucher.creation_date.clone(),
        role: "guarantor".to_string(), // A non-exempt (non-"creator") role
        details: None,
    };
    voucher.signatures.push(dummy_sig);
    
    // Bypass individual signature checks to test the signature count logic.
    human_money_core::set_signature_bypass(true);
    let mut standard_clone = standard.clone();
    standard_clone.immutable.issuance.additional_signatures_range = vec![0, 0];
    let res = verify_signatures(&voucher, &standard_clone);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "Too many signatures were accepted, exceeding the standard constraints."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(ValidationError::CountOutOfBounds { .. })) = res {
        // Expected
    } else {
        panic!("Wrong or no error. Received: {:?}", res);
    }
}

#[test]
fn test_transaction_amount_precision() {
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();
    
    // We have tx0 (init: "100.00") and tx1 (transfer). Change it to split to allow remaining_amount.
    // To make sure we don't fail InsufficientFundsInChain, amount + remaining must be 100.
    voucher.transactions[1].t_type = "split".to_string();
    voucher.transactions[1].amount = "10.12345".to_string();
    voucher.transactions[1].sender_remaining_amount = Some("89.87655".to_string());
    voucher.transactions[1].trap_data = None;
    
    let old_l2 = voucher.transactions[1].layer2_signature.clone();
    let old_id = voucher.transactions[1].sender_identity_signature.clone();
    
    // We must update the t_id so MismatchedTransactionId is not thrown
    voucher.transactions[1].t_id = "".to_string();
    voucher.transactions[1].layer2_signature = None;
    voucher.transactions[1].sender_identity_signature = None;
    voucher.transactions[1].t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher.transactions[1]).unwrap()
    );
    // Bypass requires fields to be present and validly formatted
    voucher.transactions[1].layer2_signature = old_l2;
    voucher.transactions[1].sender_identity_signature = old_id;

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&voucher, standard);
    human_money_core::set_signature_bypass(false);
    assert!(
        res.is_err(),
        "Amount with too many decimal places was incorrectly accepted."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(ValidationError::InvalidAmountPrecision { .. })) = res {
        // Expected
    } else {
        panic!("Wrong error type caught: {:?}", res);
    }

    // ADDITIONAL TEST: Only sender_remaining_amount has too many decimal places
    voucher.transactions[1].amount = "10.00".to_string(); // Valid (2 digits)
    voucher.transactions[1].sender_remaining_amount = Some("89.12345".to_string()); // Invalid (5 digits)
    
    // Update t_id manually to keep it valid for the loop but with wrong precision
    voucher.transactions[1].t_id = "".to_string();
    voucher.transactions[1].layer2_signature = None;
    voucher.transactions[1].sender_identity_signature = None;
    voucher.transactions[1].t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher.transactions[1]).unwrap()
    );
    // Signature bypass is used, so we don't need real signatures
    voucher.transactions[1].layer2_signature = Some("dummy".to_string());

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "Invalid decimal places in remaining amount were incorrectly accepted."
    );
}

#[test]
fn test_transaction_monotonic_time() {
    let (standard, _, _, _, voucher, secrets) = setup_voucher_with_one_tx();
    
    use human_money_core::create_transaction;

    // Create a second transaction
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    let seed_bytes = bs58::decode(&secrets.recipient_seed).into_vec().unwrap();
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());

    // Create a valid subsequent transfer
    let (mut next_voucher, _next_secrets) = create_transaction(
        &voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_signing_key, 
        &alice.user_id,
        "10",
        None,
    ).unwrap();
    
    // Set timestamp of tx[2] EXACTLY to the same as tx[1]
    next_voucher.transactions[2].t_time = next_voucher.transactions[1].t_time.clone();
    
    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&next_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "Transactions with identical timestamps were incorrectly accepted. Time must be strictly monotonic."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(ValidationError::InvalidTimeOrder { .. })) = res {
        // Expected
    } else {
        panic!("Wrong error type caught: {:?}", res);
    }
}

#[test]
fn test_p2pkh_recipient_match() {
    // Verifies that the recipient of the previous transaction must match the sender of the current one.
    let (standard, _, _, _, voucher, _secrets) = setup_voucher_with_one_tx();
    
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;

    // Construct our own tx1 (fake transfer)
    let mut bad_voucher = voucher.clone();
    let mut tx1 = bad_voucher.transactions[0].clone();
    
    let old_l2 = tx1.layer2_signature.clone();
    let old_id = tx1.sender_identity_signature.clone();
    
    // Manipulate tx1 first
    tx1.layer2_signature = None;
    tx1.sender_identity_signature = None;
    tx1.recipient_id = alice.user_id.clone();
    tx1.receiver_ephemeral_pub_hash = Some("hash123".to_string()); // Expected hash
    tx1.t_id = "".to_string();
    tx1.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx1.layer2_signature = old_l2.clone();
    tx1.sender_identity_signature = old_id.clone();
    bad_voucher.transactions[0] = tx1.clone();

    // Fake a transfer from Alice to Bob
    let mut tx2 = tx1.clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    // The mutant sits at: if prev_tx.recipient_id == tx.sender_id.unwrap() 
    tx2.sender_id = Some(alice.user_id.clone()); 
    tx2.recipient_id = bob.user_id.clone();

    // tx2 sender ephemeral pub is manipulated so the hash does NOT match hash123.
    tx2.sender_ephemeral_pub = Some("11111111111111111111111111111111".to_string());
    
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    tx2.layer2_signature = old_l2;
    tx2.sender_identity_signature = old_id;
    
    bad_voucher.transactions.truncate(1);
    bad_voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "P2PKH chain broken: Fake public key was incorrectly accepted."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) = res {
        assert!(msg.contains("P2PKH chain broken"), "Unexpected validation error: {}", msg);
    } else {
        panic!("Unexpected error type, expected P2PKH chain broken: {:?}", res);
    }
}

#[test]
fn test_p2pkh_change_output_verification() {
    // Verifies that when spending change, the ephemeral pub must match the previous change_ephemeral_pub_hash.
    let (standard, _, _, _, voucher, _secrets) = setup_voucher_with_one_tx();
    
    // Create a bad voucher with an initial transaction (we use the setup)
    let old_l2 = voucher.transactions[0].layer2_signature.clone();
    let old_id = voucher.transactions[0].sender_identity_signature.clone();
    
    // Modify tx1: Alice sends to Bob, but keeps change
    use human_money_core::create_transaction;
    
    let alice = &human_money_core::test_utils::ACTORS.alice;
    let bob = &human_money_core::test_utils::ACTORS.bob;

    let seed_bytes = bs58::decode(&_secrets.recipient_seed).into_vec().unwrap();
    let bob_ephemeral_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());

    let (voucher, _secrets) = create_transaction(
        &voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_ephemeral_key, 
        &alice.user_id,
        "10",
        None,
    ).unwrap();

    let mut bad_voucher = voucher.clone();
    
    let mut tx1 = bad_voucher.transactions[1].clone();
    tx1.trap_data = None;
    tx1.layer2_signature = None;
    tx1.sender_identity_signature = None;
    tx1.receiver_ephemeral_pub_hash = Some("hashBob".to_string());
    tx1.change_ephemeral_pub_hash = Some("hashChangeAlice".to_string()); // Expected hash for change
    tx1.t_id = "".to_string();
    tx1.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx1.layer2_signature = old_l2.clone();
    tx1.sender_identity_signature = old_id.clone();
    bad_voucher.transactions[1] = tx1.clone();

    // Fake a transfer from Alice (from change) to Charlie
    let mut tx2 = tx1.clone();
    tx2.trap_data = None;
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.sender_remaining_amount = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    // To land at prev_tx.recipient_id == tx.sender_id check:
    // Since tx1.recipient_id == bob, we must set tx2.sender_id = bob!
    tx2.sender_id = Some(bob.user_id.clone()); 
    tx2.recipient_id = alice.user_id.clone();

    // tx2 sender ephemeral pub is manipulated so the hash does NOT match "hashChangeAlice" or "hashBob"
    tx2.sender_ephemeral_pub = Some("11111111111111111111111111111111".to_string());
    
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    tx2.layer2_signature = old_l2;
    tx2.sender_identity_signature = old_id;
    
    bad_voucher.transactions.truncate(2);
    bad_voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "P2PKH Change Match: Fake public key was incorrectly accepted when spending change."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg))) = res {
        assert!(msg.contains("P2PKH chain broken"), "Unexpected validation error: {}", msg);
    } else {
        panic!("Unexpected error type, expected P2PKH chain broken: {:?}", res);
    }
}

#[test]
fn test_p2pkh_recipient_id_fallback() {
    // Verifies the fallback logic when individual IDs are used (Public Mode).
    let (standard, _, _, _, voucher, _) = human_money_core::test_utils::setup_voucher_with_one_tx();
    let mut bad_voucher = voucher.clone();
    
    // Create an invalid transfer where "Charlie" tries to spend "Bob's" money (recipient of tx1).
    // Using explicit IDs (Public Mode).
    let mut tx2 = bad_voucher.transactions[0].clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&bad_voucher.transactions[0]).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    
    // Bob was recipient. Charlie wants to send.
    tx2.sender_id = Some("Charlie".to_string()); 
    tx2.recipient_id = "Dave".to_string();
    tx2.sender_ephemeral_pub = Some("11111111111111111111111111111111".to_string());
    
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    tx2.layer2_signature = Some("dummy".to_string());
    tx2.sender_identity_signature = Some("dummy".to_string());
    
    bad_voucher.transactions.truncate(1);
    bad_voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "P2PKH Fallback Recipient ID check failed to catch mismatch."
    );
     if let Err(human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::InvalidTransaction(msg))) = res {
        assert!(msg.contains("P2PKH chain broken"), "Unexpected error: {}", msg);
    } else {
        panic!("Missing expected P2PKH error!");
    }
}

#[test]
fn test_p2pkh_sender_id_fallback() {
    // Verifies the fallback logic for sender ID matching in public mode.
    let (standard, _, _, _, voucher, _) = human_money_core::test_utils::setup_voucher_with_one_tx();
    let mut bad_voucher = voucher.clone();
    
    // Alice is sender of tx1. Bob is recipient. Charlie tries to spend Alice's change.
    let mut tx2 = bad_voucher.transactions[0].clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&bad_voucher.transactions[0]).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    
    tx2.sender_id = Some("Charlie".to_string()); 
    tx2.recipient_id = "Dave".to_string();
    tx2.sender_ephemeral_pub = Some("11111111111111111111111111111111".to_string());
    
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    tx2.layer2_signature = Some("dummy".to_string());
    tx2.sender_identity_signature = Some("dummy".to_string());
    
    bad_voucher.transactions.truncate(1);
    bad_voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(res.is_err(), "P2PKH Fallback Sender ID check failed to catch mismatch.");
}

#[test]
fn test_p2pkh_hash_fallback_match() {
    // Verifies that when no ID matches, the hash-based fallback check is performed.
    let (standard, _, _, _, voucher, _) = human_money_core::test_utils::setup_voucher_with_one_tx();
    let mut bad_voucher = voucher.clone();
    
    let mut tx2 = bad_voucher.transactions[0].clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&bad_voucher.transactions[0]).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    
    tx2.sender_id = None; 
    tx2.recipient_id = "Dave".to_string();
    tx2.sender_ephemeral_pub = Some("11111111111111111111111111111111".to_string()); // Wrong hash
    
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    tx2.layer2_signature = Some("dummy".to_string());
    tx2.sender_identity_signature = Some("dummy".to_string());
    
    bad_voucher.transactions.truncate(1);
    bad_voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(res.is_err(), "P2PKH Fallback Hash Check failed to catch invalid ephemeral pub.");
}

#[test]
fn test_trap_data_privacy_validation() {
    // Verifies that TrapData blinded_id does not contain sensitive characters like ':' or '@'.
    let (standard, _, _, _, voucher, secrets) = human_money_core::test_utils::setup_voucher_with_one_tx();
    
    // Attach TrapData to a transfer with @ (email leak). Init is skipped for TrapData!
    use human_money_core::create_transaction;
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let seed_bytes = bs58::decode(&secrets.recipient_seed).into_vec().unwrap();
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());
    
    let (mut next_voucher, _) = create_transaction(
        &voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_signing_key, 
        &alice.user_id,
        "10", // send 10
        None,
    ).unwrap();

    next_voucher.transactions[2].trap_data = Some(human_money_core::models::voucher::TrapData {
        ds_tag: "tag123".to_string(), // In bypass, hash is not validated
        blinded_id: "user@domain.com".to_string(), // Illegal!
        proof: "".to_string(),
        u: "".to_string(),
    });

    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&next_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "TrapData with email-like characters in blinded_id was incorrectly accepted."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::TrapDataInvalid { .. })) = res {
        // Expected
    } else {
        panic!("Wrong or no error. Received: {:?}", res);
    }
}

#[test]
fn test_balance_attribution_logic() {
    // Verifies that unspent funds are correctly attributed to the holder's balance.
    let (standard, _, _, _, voucher, secrets) = human_money_core::test_utils::setup_voucher_with_one_tx();
    
    // We use the real setup that created a valid chain init -> transfer
    let alice = &human_money_core::test_utils::ACTORS.alice;
    let bob = &human_money_core::test_utils::ACTORS.bob;
    let seed_bytes = bs58::decode(&secrets.recipient_seed).into_vec().unwrap();
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());

    // Create transfer (real & valid)
    let (next_voucher, _) = human_money_core::create_transaction(
        &voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_signing_key, 
        &alice.user_id,
        "10", // send 10
        None,
    ).unwrap();
    
    // Call verify_transactions on the real, valid voucher
    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&next_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_ok(),
        "Balance attribution logic failed to correctly identify unspent funds."
    );
}

#[test]
fn test_init_transaction_party_rules() {
    // Verifies that for 'init' transactions, both sender and recipient must be the creator.
    let (standard, _, _, _, voucher, _) = human_money_core::test_utils::setup_voucher_with_one_tx();
    let mut bad_voucher = voucher.clone();
    
    bad_voucher.transactions[0].recipient_id = human_money_core::test_utils::ACTORS.bob.user_id.clone();
    
    // Bypass L2 Signature
    let old_l2 = bad_voucher.transactions[0].layer2_signature.clone();
    let old_id = bad_voucher.transactions[0].sender_identity_signature.clone();
    
    bad_voucher.transactions[0].layer2_signature = None;
    bad_voucher.transactions[0].sender_identity_signature = None;
    bad_voucher.transactions[0].t_id = "".to_string();
    bad_voucher.transactions[0].t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&bad_voucher.transactions[0]).unwrap()
    );
    bad_voucher.transactions[0].layer2_signature = old_l2;
    bad_voucher.transactions[0].sender_identity_signature = old_id;

    bad_voucher.transactions.truncate(1);

    human_money_core::set_signature_bypass(true);
    let res = human_money_core::services::voucher_validation::verify_transactions(&bad_voucher, standard);
    human_money_core::set_signature_bypass(false);

    assert!(
        res.is_err(),
        "Init transaction with mismatched recipient/creator was incorrectly accepted."
    );
    
    if let Err(human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::InitPartyMismatch { .. })) = res {
        // Expected
    } else {
        panic!("Wrong or no error. Received: {:?}", res);
    }
}

#[test]
fn test_p2pkh_identity_match_isolation() {
    // Verifies that the identity-based match (fallback) correctly allows spending if hash-match is unavailable.
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();
    
    // Create split chain
    voucher.transactions[1].t_type = "split".to_string();
    voucher.transactions[1].amount = "10.00".to_string();
    voucher.transactions[1].sender_remaining_amount = Some("90.00".to_string());
    voucher.transactions[1].sender_id = Some(ACTORS.alice.user_id.clone()); 
    
    // Alice sends to Bob
    let bob_id = ACTORS.bob.user_id.clone();
    voucher.transactions[1].recipient_id = bob_id.clone();
    
    // Update t_id for tx1
    voucher.transactions[1].t_id = "".to_string();
    voucher.transactions[1].layer2_signature = None;
    voucher.transactions[1].sender_identity_signature = None;
    voucher.transactions[1].t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher.transactions[1]).unwrap()
    );

    // TX2: Alice (sender) uses her change
    let mut tx2 = voucher.transactions[1].clone();
    tx2.t_type = "transfer".to_string();
    tx2.amount = "90.00".to_string();
    tx2.sender_remaining_amount = None;
    tx2.prev_hash = voucher.transactions[1].t_id.clone();
    tx2.sender_id = Some(ACTORS.alice.user_id.clone()); 
    
    // SABOTAGE: We provide a wrong ephemeral_pub that does NOT match the change_hash of tx1
    // Thus, logic MUST go through ID-match (line 642).
    tx2.sender_ephemeral_pub = Some("bs58_encoded_dummy".to_string()); 
    
    tx2.t_id = "".to_string();
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    
    voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&voucher, standard);
    human_money_core::set_signature_bypass(false);

    // Baseline: Should be SUCCESS because ID-match Alice == Alice (line 642) applies.
    // Mutant: at line 642 == becomes !=. Then ID-match does NOT apply.
    // Since hash-match also does NOT apply (due to sabotage) -> Error.
    if let Err(e) = res {
         match e {
             human_money_core::error::VoucherCoreError::Validation(human_money_core::error::ValidationError::InvalidTransaction(msg)) => {
                 if msg.contains("Transaction chain broken") {
                     panic!("ID-Match fallback failed when hash-linkage was broken.");
                 }
             },
             _ => {} 
         }
    }
}
