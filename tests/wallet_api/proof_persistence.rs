// tests/wallet_api/proof_persistence.rs
use human_money_core::test_utils::{
    ACTORS, FREETALER_STANDARD, add_voucher_to_wallet,
    setup_in_memory_wallet, derive_holder_key,
};
use human_money_core::{
    VoucherStatus,
};
use std::collections::HashMap;

#[test]
fn test_proof_is_created_even_when_transaction_missing_from_store() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(&alice.identity);
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    // let standard_hash = get_hash(to_canonical_json(&standard.immutable).unwrap());

    // 1. Create a voucher for Alice
    let local_id = add_voucher_to_wallet(
        &mut wallet,
        &alice.identity,
        "100",
        standard,
        true,
    ).unwrap();

    let (voucher_after_init, holder_key) = {
        let inst = wallet.voucher_store.vouchers.get(&local_id).unwrap();
        let v = inst.voucher.clone();
        // The first holder key is derived from the nonce
        let key = derive_holder_key(&v, &alice.identity.signing_key);
        (v, key)
    };

    // 2. Create TWO conflicting transfers from Alice to others
    let _bob = &ACTORS.bob;
    let _charlie = &ACTORS.charlie;

    // 6. Now simulate a Watchtower receiving both vouchers.
    let watchtower = &ACTORS.issuer;
    let mut watchtower_wallet = setup_in_memory_wallet(&watchtower.identity);

    // T1: Alice -> Watchtower
    let (voucher_to_wt_1, _secrets1) = human_money_core::services::voucher_manager::create_transaction(
        &voucher_after_init,
        standard,
        &alice.identity.user_id,
        &alice.identity.signing_key,
        &holder_key,
        &watchtower.identity.user_id,
        "40",
        None,
    ).unwrap();

    // T2: Alice -> Watchtower (Double Spend of T1)
    let (voucher_to_wt_2, _secrets2) = human_money_core::services::voucher_manager::create_transaction(
        &voucher_after_init,
        standard,
        &alice.identity.user_id,
        &alice.identity.signing_key,
        &holder_key,
        &watchtower.identity.user_id,
        "60",
        None,
    ).unwrap();

    // Alice "forgets" the vouchers (Archived)
    {
        let inst = wallet.voucher_store.vouchers.get_mut(&local_id).unwrap();
        inst.status = VoucherStatus::Archived;
    }

    // 4. Watchtower receives T1
    let mut standards_toml = HashMap::new();
    standards_toml.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let (bundle_wt_1, _) = human_money_core::services::bundle_processor::create_and_encrypt_bundle(
        &alice.identity,
        vec![voucher_to_wt_1.clone()],
        &watchtower.identity.user_id,
        None,
        vec![],
        HashMap::new(),
        None,
    ).unwrap();

    watchtower_wallet.process_encrypted_transaction_bundle(
        &watchtower.identity,
        &bundle_wt_1,
        None,
        &standards_toml,
    ).unwrap();

    // --- CRITICAL STEP: Simulate the first voucher being archived/gone ---
    // We remove it from the voucher_store, but its fingerprints remain in known_fingerprints.
    watchtower_wallet.voucher_store.vouchers.clear();

    // 5. Watchtower receives T2 (Double Spend!)
    let (bundle_wt_2, _) = human_money_core::services::bundle_processor::create_and_encrypt_bundle(
        &alice.identity,
        vec![voucher_to_wt_2.clone()],
        &watchtower.identity.user_id,
        None,
        vec![],
        HashMap::new(),
        None,
    ).unwrap();

    watchtower_wallet.process_encrypted_transaction_bundle(
        &watchtower.identity,
        &bundle_wt_2,
        None,
        &standards_toml,
    ).unwrap();

    // 6. ASSERT: Watchtower should have a conflict proof!
    let conflicts = watchtower_wallet.list_conflicts();
    
    assert!(!conflicts.is_empty(), "A ProofOfDoubleSpend should have been created for the conflict");
}
