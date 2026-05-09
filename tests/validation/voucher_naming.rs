// tests/validation/voucher_naming.rs
use human_money_core::test_utils::{
    ACTORS, FREETALER_STANDARD, setup_in_memory_wallet, add_voucher_to_wallet,
};

#[test]
fn test_voucher_summary_uses_human_readable_standard_name() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(&alice.identity);
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    
    add_voucher_to_wallet(
        &mut wallet,
        &alice.identity,
        "100",
        standard,
        true,
    ).unwrap();
    
    // list_vouchers returns Vec<VoucherSummary>
    let summaries = wallet.list_vouchers(Some(&alice.identity), None, None, None);
    
    assert!(!summaries.is_empty(), "No vouchers found in test wallet");
    
    let ft_summary = summaries.iter().find(|s| s.voucher_standard_uuid == standard.immutable.identity.uuid)
        .expect("FreeTaler voucher not found in summaries");
        
    // FreeTaler standard name is "FreeTaler"
    // FREETALER_STANDARD in test_utils might be a test voucher.
    // Let's check what format_bff_name does.
    if ft_summary.is_test_voucher {
        assert_eq!(ft_summary.display_standard_name, "TEST-FreeTaler");
    } else {
        assert_eq!(ft_summary.display_standard_name, "FreeTaler");
    }
    
    assert_ne!(ft_summary.display_standard_name, "freetaler_v1");
}

#[test]
fn test_voucher_summary_uses_human_readable_currency_name() {
    let alice = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(&alice.identity);
    let (standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);
    
    add_voucher_to_wallet(
        &mut wallet,
        &alice.identity,
        "100",
        standard,
        true,
    ).unwrap();
    
    let summaries = wallet.list_vouchers(Some(&alice.identity), None, None, None);
    let ft_summary = summaries.iter().find(|s| s.voucher_standard_uuid == standard.immutable.identity.uuid)
        .expect("FreeTaler voucher not found in summaries");
        
    // FreeTaler abbreviation is "Taler"
    if ft_summary.is_test_voucher {
        assert_eq!(ft_summary.display_currency, "TEST-Taler");
    } else {
        assert_eq!(ft_summary.display_currency, "Taler");
    }
}
