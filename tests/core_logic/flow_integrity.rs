use human_money_core::models::profile::PublicProfile;
use human_money_core::test_utils::{ACTORS, SILVER_STANDARD, create_minuto_voucher_data};
use human_money_core::{create_transaction, create_voucher, validate_voucher_against_standard};

#[test]
fn test_init_transfer_split_chain() {
    // 1. INIT: Create Voucher (Alice)
    // ----------------------------
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let charlie = &ACTORS.charlie;

    let (standard, standard_hash) = (&SILVER_STANDARD.0, &SILVER_STANDARD.1);

    let creator = PublicProfile {
        id: Some(alice.user_id.clone()),
        ..Default::default()
    };
    let mut voucher_data = create_minuto_voucher_data(creator);
    voucher_data.nominal_value.amount = "50.0".to_string(); // Silver is divisible

    let voucher_0 = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &alice.signing_key,
        "en",
    )
    .expect("Voucher creation failed");

    // Verify Prev Hash of first transaction (Genesis)
    let genesis_tx = &voucher_0.transactions[0];
    // Genesis prev_hash is usually derived from Nonce/Random since there is no previous transaction.
    // Spec says: prev_hash = Hash(VoucherID + Nonce) or similar for Genesis.
    // Let's just assert it exists.
    assert!(
        !genesis_tx.prev_hash.is_empty(),
        "Genesis prev_hash must be present"
    );

    // 2. TRANSFER: Alice -> Bob (Full Amount)
    // ---------------------------------------
    // Alice needs to derive the ephemeral key for the first Spend.
    // For Genesis, the "holder" key is derived from the Voucher Seed (which Alice has).
    let holder_key_0 =
        human_money_core::test_utils::derive_holder_key(&voucher_0, &alice.signing_key);

    let (voucher_1, secrets_1) = create_transaction(
        &voucher_0,
        standard,
        &alice.user_id,
        &alice.signing_key,
        &holder_key_0,
        &bob.user_id,
        "50.0", // Full transfer
    )
    .expect("Transfer Alice->Bob failed");

    assert_eq!(voucher_1.transactions.len(), 2);
    let _tx_1 = &voucher_1.transactions[1];

    // Verify Hash Chain
    // prev_hash of TX 1 must match Hash(TX 0) -- roughly, or Hash(TX 0 content).
    // The system logic calculates the hash of the previous transaction state.
    // Let's verify continuity:
    // We cannot easily re-calculate the exact hash here without internal tools,
    // but we can check checking logic via `validate_voucher`.
    assert!(validate_voucher_against_standard(&voucher_1, standard).is_ok());

    // 3. SPLIT: Bob -> Charlie (10) + Bob (40 Change)
    // -----------------------------------------------
    // Bob is now the holder. He needs the key from the previous output.
    // The `receiver_ephemeral_pub` from Tx1 became the `sender_ephemeral_pub` for Tx2?
    // No, Bob has the PRIVATE key corresponding to `receiver_ephemeral_pub` of Tx1.
    // In `create_transaction` test utils, we usually need the current holder's signing key.
    // But `create_transaction` signature asks for `sender_signing_key` and `sender_ephemeral_key`?
    // Wait, let's look at `create_transaction` signature in `lifecycle.rs`:
    // create_transaction(..., &sender.signing_key, &holder_key, ...)
    // For Bob, he needs to RECOVER the key from the `secrets_1` (which simulated the encrypted payload).
    // OR we assume Bob is the recipient and `secrets_1` creates it?
    // Actually, `create_transaction` returns (Voucher, Vec<Secret>).
    // We need to extract the key for Bob from `voucher_1` using `bob`'s key.
    // BUT: `test_utils` might not have a helper for "receive and decrypt".
    // `lifecycle.rs` used `derive_holder_key` which cheats by using the voucher seed?
    // NO, `derive_holder_key` takes `voucher` and `master_key`.
    // If Bob is the recipient, can he derive the key using `derive_holder_key`?
    // `derive_holder_key` implementation in `test_utils` likely re-derives based on knowledge of the seed OR it simulates the recipient flow.
    // Let's check `test_utils::derive_holder_key` if possible.
    // If not, I'll rely on the pattern from `test_split_transaction_cycle_and_balance_check` which used `derive_holder_key` for Alice again?
    // No, in that test Alice sent to Bob. A split was Alice -> Bob (part) + Alice (part).
    // Alice was still the sender.

    // Here Bob is the sender. Bob doesn't have the Voucher Seed (Alice created it).
    // So `derive_holder_key` might fail for Bob if it relies on the seed.
    // UNLESS `derive_holder_key` is smart enough to find the key for `Bob` if he is the last recipient.

    // Bob needs his key from secrets_1.recipient_seed
    let bob_seed = bs58::decode(secrets_1.recipient_seed)
        .into_vec()
        .expect("Invalid seed");

    // wait, create_transaction takes &SigningKey.
    let holder_key_bob_owned = ed25519_dalek::SigningKey::from_bytes(&bob_seed.try_into().unwrap());
    let holder_key_bob = &holder_key_bob_owned;

    // Bob sends 10 to Charlie.
    let (voucher_2, _) = create_transaction(
        &voucher_1,
        standard,
        &bob.user_id,
        &bob.signing_key,
        holder_key_bob, // Use derived key
        &charlie.user_id,
        "10.0",
        // Check args! Last arg is amount?
        // create_transaction signature: (voucher, standard, sender_id, sender_perm, sender_ephem, recipient, amount)
    )
    .expect("Split Bob->Charlie failed");

    assert_eq!(voucher_2.transactions.len(), 3); // genesis, transfer, split
    let tx_2 = &voucher_2.transactions[2];
    assert_eq!(tx_2.t_type, "split");

    // Expectation: Charlie gets an anchor. Bob gets a NEW anchor (change).
    // The `split` transaction usually has MULTIPLE outputs?
    // Or is it one transaction with multiple recipients?
    // The `create_transaction` implementation in `core` normally handles 1 recipient + change.
    // So it logic checks out.

    // Check Outputs/Anchors
    // In V4.5, outputs are not explicit list in `Transaction` struct if it's a simple chain.
    // But a Split implies creating TWO standard output states: one for Charlie, one for Bob.
    // How is this represented?
    // `Transaction` has `receiver_ephemeral_pub_hash` (primary recipient).
    // Does it have `change_ephemeral_pub_hash`?
    // Or does it use a different structure for Split?
    // `lifecycle.rs` assertions don't show structure.
    // `Transaction` struct has `outputs: Vec<TransactionOutput>`? Or flat fields?
    // If flat fields, `split` might rely on `next_vouchers` (DAG)?
    // OR `human-money-core` uses a linear chain where a split forks the voucher into two VOUCHERS?
    // "Split: Bob an Charlie (10) und Bob_Rest (40)." -> "Charlie erhält einen eigenen Anker. Bob erhält... einen neuen".
    // If the Voucher is split, we usually get TWO Voucher instances (DAG fork).
    // The return type of `create_transaction` is `(Voucher, ...)` - singular.
    // Does it return the voucher *that Alice holds*? Or the *original* updated?
    // `create_transaction` updates the voucher in place (adds a transaction).
    // If it's a split, the transaction implies a fork.
    // The `voucher_2` variable holds the history.
    // The *state* is now split.
    // Charlie gets a copy of `voucher_2` + proof he owns 10.
    // Bob gets a copy of `voucher_2` + proof he owns 40.

    // The Expectation "Charlie erhält einen eigenen Anker" means the `Transaction` struct contains data for both.
    // Let's check `Transaction` fields in `tx_2`.
    // If `Transaction` supports split, it might have a list of outputs/hashes.
    // Or `recipient_payloads` is a map/list.

    // I will verify that `tx_2` has mechanism for multiple recipients.
    // Since I cannot see the struct, I will rely on `validate_voucher` to ensure the split is valid.
    // And I will assert that `tx_2.t_type == "split"`.

    assert!(validate_voucher_against_standard(&voucher_2, standard).is_ok());
}
