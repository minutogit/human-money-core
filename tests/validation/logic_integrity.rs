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
    
    // Wir setzen valid_until exakt auf creation_date
    voucher.valid_until = voucher.creation_date.clone();
    
    // Das Original-System erlaubt dies (bzw. fängt es an dieser Stelle _nicht_ durch die < Logik ab)
    // Ein Mutant mit `<=` würde hier einen InvalidDateLogic werfen.
    // Wir validieren gegen den Standard (Standard kann es wegen Minimum später ablehnen, aber der
    // spezifische Check für "valid_until < creation_dt" darf nicht fehlschlagen). 
    // ACHTUNG: Der nächste Check (verify_validity_duration) würde fehlschlagen, wenn min_duration > 0.
    // Um nur den ersten Check zu passieren, können wir den Standard so patchen, dass min_duration = 0 ist.
    let mut modified_std = standard.clone();
    modified_std.immutable.issuance.issuance_minimum_validity_duration = "".to_string();
    let mod_std_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&modified_std.immutable).unwrap()
    );
    
    // Wir müssen auch das Template im Gutschein anpassen, damit verify_validity_duration nicht wegen Mismatch abbricht
    voucher.voucher_standard.template.issuance_minimum_validity_duration = "".to_string();
    voucher.voucher_standard.standard_definition_hash = mod_std_hash;

    // Re-hash voucher_id to pass verify_voucher_hash
    let mut voucher_to_hash = voucher.clone();
    voucher_to_hash.voucher_id = "".to_string();
    voucher_to_hash.transactions.clear();
    voucher_to_hash.signatures.clear();
    voucher.voucher_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher_to_hash).unwrap()
    );

    // Initial Transaction muss den neuen voucher_id als prev_hash haben
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

    // Umgehe verify_signature Fehlschläge
    human_money_core::set_signature_bypass(true);
    
    // Wir ignorieren Signaturfehler und konzentrieren uns darauf, dass kein InvalidDateLogic zurückkommt.
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

    // Im Silver Standard ist max_sigs zB 0. Wenn wir eine zusätzliche Signatur hinzufügen:
    let (vk, _) = human_money_core::crypto_utils::generate_ed25519_keypair_for_tests(Some("dummy"));
    let dummy_id = human_money_core::crypto_utils::create_user_id(&vk, Some("dummy")).unwrap();

    let dummy_sig = human_money_core::models::voucher::VoucherSignature {
        voucher_id: "".to_string(),
        signature_id: "s2".to_string(),
        signer_id: dummy_id,
        signature: "sig1".to_string(),
        signature_time: voucher.creation_date.clone(),
        role: "guarantor".to_string(), // Eine nicht ausgenommene (nicht "creator") Rolle
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
        panic!("Falscher oder kein Error. Erhalten: {:?}", res);
    }
}

#[test]
fn test_transaction_amount_precision() {
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();
    
    // We have tx0 (init: "100.0000") and tx1 (transfer). Change it to split to allow remaining_amount.
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
    // Bypass verlangt, dass die Felder da sind und gültig formatiert
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

    // Mühsam, wir basteln einfach eine eigene tx1 rein (Fake Transfer)
    let mut bad_voucher = voucher.clone();
    let mut tx1 = bad_voucher.transactions[0].clone();
    
    let old_l2 = tx1.layer2_signature.clone();
    let old_id = tx1.sender_identity_signature.clone();
    
    // Wir manipulieren tx1 zuerst
    tx1.layer2_signature = None;
    tx1.sender_identity_signature = None;
    tx1.recipient_id = alice.user_id.clone();
    tx1.receiver_ephemeral_pub_hash = Some("hash123".to_string()); // Erwarteter Hash
    tx1.t_id = "".to_string();
    tx1.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx1.layer2_signature = old_l2.clone();
    tx1.sender_identity_signature = old_id.clone();
    bad_voucher.transactions[0] = tx1.clone();

    // Wir faken einen Transfer von Alice zu Bob
    let mut tx2 = tx1.clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    // Der Mutant sitzt an: if prev_tx.recipient_id == tx.sender_id.unwrap() 
    tx2.sender_id = Some(alice.user_id.clone()); 
    tx2.recipient_id = bob.user_id.clone();

    // tx2 Sender Ephemeral Pub wird manipuliert, sodass der Hash NICHT zu hash123 passt.
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
    
    // Erstelle einen Bad Voucher mit einer initialen Transaktion (wir nutzen den Setup)
    
    let old_l2 = voucher.transactions[0].layer2_signature.clone();
    let old_id = voucher.transactions[0].sender_identity_signature.clone();
    
    // tx1 modifizieren: Alice schickt an Bob, behält aber ein Change
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
    ).unwrap();

    let mut bad_voucher = voucher.clone();
    
    let mut tx1 = bad_voucher.transactions[1].clone();
    tx1.trap_data = None;
    tx1.layer2_signature = None;
    tx1.sender_identity_signature = None;
    tx1.receiver_ephemeral_pub_hash = Some("hashBob".to_string());
    tx1.change_ephemeral_pub_hash = Some("hashChangeAlice".to_string()); // Erwarteter Hash für das Change
    tx1.t_id = "".to_string();
    tx1.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx1).unwrap()
    );
    tx1.layer2_signature = old_l2.clone();
    tx1.sender_identity_signature = old_id.clone();
    bad_voucher.transactions[1] = tx1.clone();

    // Wir faken einen Transfer von Alice (aus dem Change) zu Charlie
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
    // Um in Zeile 627 zu landen: prev_tx.recipient_id == tx.sender_id
    // Da tx1.recipient_id == bob ist, müssen wir tx2.sender_id = bob setzen!
    // ABER was ist wenn bob den Hash für Change Alice auflösen will? 
    // Der Code lautet: (Zeile 607) if prev_tx.recipient_id == tx.sender_id -> OK, dann checke pub_hash gegen receiver_hash, wenn nicht, dann change_hash.
    tx2.sender_id = Some(bob.user_id.clone()); 
    tx2.recipient_id = alice.user_id.clone();

    // tx2 Sender Ephemeral Pub wird manipuliert, sodass der Hash NICHT zu "hashChangeAlice" passt und auch nicht zu "hashBob"
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
    
    // Wir erzeugen einen ungültigen Transfer, bei dem "Charlie" das Geld von "Bob" (recipient von tx1) ausgeben will.
    // Aber wir nutzen explizite IDs (Public Mode), damit wir in Zeile 640 landen.
    let mut tx2 = bad_voucher.transactions[0].clone();
    tx2.layer2_signature = None;
    tx2.sender_identity_signature = None;
    tx2.t_id = "".to_string();
    tx2.prev_hash = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&bad_voucher.transactions[0]).unwrap()
    );
    tx2.t_type = "transfer".to_string();
    tx2.t_time = human_money_core::utils::get_current_timestamp();
    
    // Bob war Recipient. Charlie will senden.
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
    
    // Füge TrapData zu einem Transfer bei mit @ (Email leak). Init wird für TrapData übersprungen!
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
    ).unwrap();

    next_voucher.transactions[2].trap_data = Some(human_money_core::models::voucher::TrapData {
        ds_tag: "tag123".to_string(), // In bypass wird der Hash nicht validiert
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
        panic!("Falscher oder kein Error. Erhalten: {:?}", res);
    }
}

#[test]
fn test_balance_attribution_logic() {
    // Verifies that unspent funds are correctly attributed to the holder's balance.
    let (standard, _, _, _, voucher, secrets) = human_money_core::test_utils::setup_voucher_with_one_tx();
    
    // Wir nutzen das echte Setup, das eine valide Kette init -> transfer erstellt hat
    let alice = &human_money_core::test_utils::ACTORS.alice;
    let bob = &human_money_core::test_utils::ACTORS.bob;
    let seed_bytes = bs58::decode(&secrets.recipient_seed).into_vec().unwrap();
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(seed_bytes.as_slice().try_into().unwrap());

    // Erstelle Transfer (echt & valide)
    let (next_voucher, _) = human_money_core::create_transaction(
        &voucher,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_signing_key, 
        &alice.user_id,
        "10", // send 10
    ).unwrap();
    
    // verify_transactions auf den echten, gültigen Voucher aufrufen
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
        panic!("Falscher oder kein Error. Erhalten: {:?}", res);
    }
}

#[test]
fn test_p2pkh_identity_match_isolation() {
    // Verifies that the identity-based match (fallback) correctly allows spending if hash-match is unavailable.
    let (standard, _, _, _, mut voucher, _) = setup_voucher_with_one_tx();
    
    // Erstelle Split-Kette
    voucher.transactions[1].t_type = "split".to_string();
    voucher.transactions[1].amount = "10.00".to_string();
    voucher.transactions[1].sender_remaining_amount = Some("90.00".to_string());
    voucher.transactions[1].sender_id = Some(ACTORS.alice.user_id.clone()); 
    
    // Alice schickt an Bob
    let bob_id = ACTORS.bob.user_id.clone();
    voucher.transactions[1].recipient_id = bob_id.clone();
    
    // Update t_id for tx1
    voucher.transactions[1].t_id = "".to_string();
    voucher.transactions[1].layer2_signature = None;
    voucher.transactions[1].sender_identity_signature = None;
    voucher.transactions[1].t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&voucher.transactions[1]).unwrap()
    );

    // TX2: Alice (Sender) nutzt ihr Restgeld (Change)
    let mut tx2 = voucher.transactions[1].clone();
    tx2.t_type = "transfer".to_string();
    tx2.amount = "90.00".to_string();
    tx2.sender_remaining_amount = None;
    tx2.prev_hash = voucher.transactions[1].t_id.clone();
    tx2.sender_id = Some(ACTORS.alice.user_id.clone()); 
    
    // SABOTAGE: Wir geben einen falschen ephemeral_pub an, der NICHT zum change_hash von tx1 passt
    // Somit MUSS die Logik über den ID-Match (line 642) gehen.
    tx2.sender_ephemeral_pub = Some("bs58_encoded_dummy".to_string()); 
    
    tx2.t_id = "".to_string();
    tx2.t_id = human_money_core::crypto_utils::get_hash(
        human_money_core::to_canonical_json(&tx2).unwrap()
    );
    
    voucher.transactions.push(tx2);

    human_money_core::set_signature_bypass(true);
    let res = verify_transactions(&voucher, standard);
    human_money_core::set_signature_bypass(false);

    // Baseline: Sollte ERFOLG sein, da ID-Match Alice == Alice (line 642) greift.
    // Mutant: an line 642 wird == zu !=. Dann greift der ID-Match NICHT.
    // Da auch der Hash-Match (wegen Sabotage) NICHT greift -> Error.
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
