use human_money_core::models::voucher::{Transaction, Voucher};
use human_money_core::services::crypto_utils::get_hash_from_slices;
use human_money_core::services::voucher_validation::{
    verify_transaction_integrity_and_signature, verify_transactions,
};
use human_money_core::test_utils::MINUTO_STANDARD;
use human_money_core::error::VoucherCoreError;

#[test]
fn test_ds_tag_malleability_regression() {
    // This test ensures that the DS-Tag is NOT vulnerable to string concatenation malleability.
    // Case: prev_hash="A", ephem_pub="BC" vs prev_hash="AB", ephem_pub="C"
    // If we used format!("{}{}", prev_hash, ephem_pub), both would result in "ABC".
    
    // Base58 strings that collide when concatenated: "26" + "4" = "264" and "2" + "64" = "264"
    let part1_a = "26";
    let part1_b = "4";
    let part2_a = "2";
    let part2_b = "64";
    
    // Verify they collude as strings
    assert_eq!(format!("{}{}", part1_a, part1_b), format!("{}{}", part2_a, part2_b));
    
    // Verify they DO NOT collude with our new hashing logic because we decode them first
    let hash1 = get_hash_from_slices(&[
        &bs58::decode(part1_a).into_vec().unwrap(),
        &bs58::decode(part1_b).into_vec().unwrap(),
    ]);
    
    let hash2 = get_hash_from_slices(&[
        &bs58::decode(part2_a).into_vec().unwrap(),
        &bs58::decode(part2_b).into_vec().unwrap(),
    ]);
    
    assert_ne!(hash1, hash2, "Hashing MUST be resistant to concatenation malleability");
}

#[test]
fn test_verify_transactions_empty_list_no_panic() {
    // Test that an empty transaction list returns an error instead of panicking.
    let mut voucher = Voucher::default();
    voucher.transactions = vec![];
    
    let standard = &MINUTO_STANDARD.0;
    
    let result = verify_transactions(&voucher, standard);
    assert!(result.is_err());
    match result {
        Err(VoucherCoreError::Validation(_)) => (),
        _ => panic!("Expected Validation error, got {:?}", result),
    }
}

#[test]
fn test_verify_integrity_malformed_base58_no_panic() {
    // Test that malformed data in a transaction doesn't cause a panic.
    let mut tx = Transaction::default();
    tx.t_id = bs58::encode(vec![0; 32]).into_string();
    tx.sender_ephemeral_pub = Some("Invalid Base58!O0Il".to_string()); // Contains invalid chars for some b58 variants, but more importantly it won't decode to 32 bytes
    tx.layer2_signature = Some(bs58::encode(vec![0; 64]).into_string());
    
    // This should return an error, NOT panic.
    let result = verify_transaction_integrity_and_signature(&tx, "dummy_v_id");
    assert!(result.is_err());
}

#[test]
fn test_verify_integrity_wrong_length_no_panic() {
    // Test that wrong byte lengths (after decoding) don't cause a panic (try_into().unwrap() fix).
    let mut tx = Transaction::default();
    tx.t_id = bs58::encode(vec![0; 32]).into_string();
    tx.sender_ephemeral_pub = Some(bs58::encode(vec![1, 2, 3]).into_string()); // Too short
    tx.layer2_signature = Some(bs58::encode(vec![0; 64]).into_string());
    
    let result = verify_transaction_integrity_and_signature(&tx, "dummy_v_id");
    assert!(result.is_err());
}
