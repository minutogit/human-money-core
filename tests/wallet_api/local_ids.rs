// tests/wallet_api/local_ids.rs
// cargo test --test wallet_api_tests wallet_api::local_ids
//!
//! Verifiziert die Logik zur Berechnung von lokalen Gutschein-Instanz-IDs.
//! Diese IDs müssen pfadabhängig und besitzerspezifisch sein, um
//! Kollisionen bei Splits und Bounce-Backs zu verhindern.

use human_money_core::test_utils::{self, ACTORS};
use human_money_core::Wallet;
use human_money_core::services::voucher_manager::create_transaction;
use human_money_core::VoucherCoreError;
use bs58;

#[test]
fn test_correct_id_after_split_and_uniqueness() {
    let (_, _, alice, bob, voucher_after_split, _) = test_utils::setup_voucher_with_one_tx();
    let split_tx = voucher_after_split.transactions.last().unwrap();

    let alice_local_id = Wallet::calculate_local_instance_id(&voucher_after_split, &alice.user_id).unwrap();
    let bob_local_id = Wallet::calculate_local_instance_id(&voucher_after_split, &bob.user_id).unwrap();

    let expected_alice_id = human_money_core::services::crypto_utils::get_hash(format!(
        "{}{}{}",
        voucher_after_split.voucher_id, split_tx.t_id, alice.user_id
    ));
    let expected_bob_id = human_money_core::services::crypto_utils::get_hash(format!(
        "{}{}{}",
        voucher_after_split.voucher_id, split_tx.t_id, bob.user_id
    ));

    assert_eq!(alice_local_id, expected_alice_id);
    assert_eq!(bob_local_id, expected_bob_id);
    assert_ne!(alice_local_id, bob_local_id);
}

#[test]
fn test_path_dependency_long_chain() {
    let (standard, _, _, bob, voucher_after_tx1, secrets) = test_utils::setup_voucher_with_one_tx();
    let charlie = &ACTORS.charlie;

    let bob_seed_bytes = bs58::decode(secrets.recipient_seed).into_vec().unwrap();
    let bob_ephemeral_key = ed25519_dalek::SigningKey::from_bytes(&bob_seed_bytes.try_into().unwrap());

    let (voucher_after_tx2, _) = create_transaction(
        &voucher_after_tx1,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_ephemeral_key,
        &charlie.user_id,
        "40.0000",
        None,
    ).unwrap();
    let final_tx = voucher_after_tx2.transactions.last().unwrap();

    let charlie_local_id = Wallet::calculate_local_instance_id(&voucher_after_tx2, &charlie.user_id).unwrap();

    let expected_charlie_id = human_money_core::services::crypto_utils::get_hash(format!(
        "{}{}{}",
        voucher_after_tx2.voucher_id, final_tx.t_id, charlie.user_id
    ));
    assert_eq!(charlie_local_id, expected_charlie_id);
}

#[test]
fn test_path_dependency_bounce_back() {
    let (standard, _, alice, bob, voucher_after_tx1, secrets) = test_utils::setup_voucher_with_one_tx();

    let bob_seed_bytes = bs58::decode(secrets.recipient_seed).into_vec().unwrap();
    let bob_ephemeral_key = ed25519_dalek::SigningKey::from_bytes(&bob_seed_bytes.try_into().unwrap());

    let (voucher_after_tx2, _) = create_transaction(
        &voucher_after_tx1,
        standard,
        &bob.user_id,
        &bob.signing_key,
        &bob_ephemeral_key,
        &alice.user_id,
        "40.0000",
        None,
    ).unwrap();
    let final_tx = voucher_after_tx2.transactions.last().unwrap();

    let alice_final_local_id = Wallet::calculate_local_instance_id(&voucher_after_tx2, &alice.user_id).unwrap();

    let expected_alice_id = human_money_core::services::crypto_utils::get_hash(format!(
        "{}{}{}",
        voucher_after_tx2.voucher_id, final_tx.t_id, alice.user_id
    ));
    assert_eq!(alice_final_local_id, expected_alice_id);
}

#[test]
fn test_correct_id_for_archived_state() {
    let (standard, _, alice, bob, initial_voucher, secrets) = test_utils::setup_voucher_with_one_tx();

    let alice_change_seed = secrets.change_seed.expect("Alice should have received change from split");
    let alice_change_key_bytes = bs58::decode(alice_change_seed).into_vec().unwrap();
    let alice_ephemeral_key = ed25519_dalek::SigningKey::from_bytes(&alice_change_key_bytes.try_into().unwrap());

    let (voucher_after_full_transfer, _) = create_transaction(
        &initial_voucher,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &alice_ephemeral_key,
        &bob.user_id,
        "60.0000",
        None,
    ).unwrap();
    let final_tx = voucher_after_full_transfer.transactions.last().unwrap();

    let alice_archived_id = Wallet::calculate_local_instance_id(&voucher_after_full_transfer, &alice.user_id).unwrap();

    let expected_alice_id = human_money_core::services::crypto_utils::get_hash(format!(
        "{}{}{}",
        voucher_after_full_transfer.voucher_id, final_tx.t_id, alice.user_id
    ));
    assert_eq!(alice_archived_id, expected_alice_id);
}

#[test]
fn test_error_when_user_has_no_balance_or_history() {
    let (_, _, _, _, voucher, _) = test_utils::setup_voucher_with_one_tx();
    let charlie = &ACTORS.charlie;

    let result = Wallet::calculate_local_instance_id(&voucher, &charlie.user_id);

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), VoucherCoreError::VoucherOwnershipNotFound(_)));
}
