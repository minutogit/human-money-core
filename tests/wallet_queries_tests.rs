use human_money_core::test_utils::{setup_in_memory_wallet, ACTORS};
use human_money_core::wallet::instance::{VoucherInstance, VoucherStatus};
use human_money_core::models::voucher::{Voucher, Transaction};

#[test]
fn test_balance_aggregation_strictly_separates_test_and_live_money() {
    let identity = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(identity);
    
    // 1. Live Minuto (10)
    let mut v1 = Voucher::default();
    v1.voucher_standard.uuid = "minuto-uuid".to_string();
    v1.voucher_standard.name = "Minuto".to_string();
    v1.nominal_value.unit = "Minuto".to_string();
    v1.nominal_value.abbreviation = Some("Min".to_string());
    v1.non_redeemable_test_voucher = false;
    v1.transactions.push(Transaction { amount: "10".to_string(), ..Default::default() });
    
    // 2. Live Minuto (5) -> Should be aggregated with v1
    let mut v2 = v1.clone();
    v2.transactions[0].amount = "5".to_string();
    
    // 3. Test Minuto (50) -> Should be separate
    let mut v3 = v1.clone();
    v3.non_redeemable_test_voucher = true;
    v3.transactions[0].amount = "50".to_string();
    
    wallet.voucher_store.vouchers.insert("v1".to_string(), VoucherInstance {
        voucher: v1, status: VoucherStatus::Active, local_instance_id: "v1".to_string()
    });
    wallet.voucher_store.vouchers.insert("v2".to_string(), VoucherInstance {
        voucher: v2, status: VoucherStatus::Active, local_instance_id: "v2".to_string()
    });
    wallet.voucher_store.vouchers.insert("v3".to_string(), VoucherInstance {
        voucher: v3, status: VoucherStatus::Active, local_instance_id: "v3".to_string()
    });
    
    let balances = wallet.get_total_balance_by_currency(Some(identity));
    
    assert_eq!(balances.len(), 2);
    
    let live_balance = balances.iter().find(|b| !b.is_test_voucher).unwrap();
    assert_eq!(live_balance.total_amount, "15");
    assert_eq!(live_balance.display_currency, "Min");
    assert_eq!(live_balance.display_standard_name, "Minuto");
    
    let test_balance = balances.iter().find(|b| b.is_test_voucher).unwrap();
    assert_eq!(test_balance.total_amount, "50");
    assert_eq!(test_balance.display_currency, "TEST-Min");
    assert_eq!(test_balance.display_standard_name, "TEST-Minuto");
}

#[test]
fn test_list_vouchers_respects_test_filter() {
    let identity = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(identity);
    
    let mut v_live = Voucher::default();
    v_live.non_redeemable_test_voucher = false;
    
    let mut v_test = Voucher::default();
    v_test.non_redeemable_test_voucher = true;

    wallet.voucher_store.vouchers.insert("l1".to_string(), VoucherInstance {
        voucher: v_live.clone(), status: VoucherStatus::Active, local_instance_id: "l1".to_string()
    });
    wallet.voucher_store.vouchers.insert("l2".to_string(), VoucherInstance {
        voucher: v_live, status: VoucherStatus::Active, local_instance_id: "l2".to_string()
    });
    wallet.voucher_store.vouchers.insert("t1".to_string(), VoucherInstance {
        voucher: v_test.clone(), status: VoucherStatus::Active, local_instance_id: "t1".to_string()
    });
    wallet.voucher_store.vouchers.insert("t2".to_string(), VoucherInstance {
        voucher: v_test.clone(), status: VoucherStatus::Active, local_instance_id: "t2".to_string()
    });
    wallet.voucher_store.vouchers.insert("t3".to_string(), VoucherInstance {
        voucher: v_test, status: VoucherStatus::Active, local_instance_id: "t3".to_string()
    });

    // None -> 5
    assert_eq!(wallet.list_vouchers(Some(identity), None, None, None).len(), 5);
    // Some(true) -> 3
    assert_eq!(wallet.list_vouchers(Some(identity), None, None, Some(true)).len(), 3);
    // Some(false) -> 2
    assert_eq!(wallet.list_vouchers(Some(identity), None, None, Some(false)).len(), 2);
}

#[test]
fn test_asset_class_listing() {
    let identity = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(identity);
    
    let mut v1 = Voucher::default();
    v1.voucher_standard.uuid = "std-1".to_string();
    v1.voucher_standard.name = "Minuto".to_string();
    v1.nominal_value.unit = "Minuto".to_string();
    v1.non_redeemable_test_voucher = false;
    
    let mut v2 = v1.clone();
    v2.non_redeemable_test_voucher = true;

    wallet.voucher_store.vouchers.insert("v1".to_string(), VoucherInstance {
        voucher: v1, status: VoucherStatus::Active, local_instance_id: "v1".to_string()
    });
    wallet.voucher_store.vouchers.insert("v2".to_string(), VoucherInstance {
        voucher: v2, status: VoucherStatus::Active, local_instance_id: "v2".to_string()
    });

    let classes = wallet.get_active_asset_classes();
    assert_eq!(classes.len(), 2);
    
    assert!(classes.iter().any(|c| !c.is_test_voucher && c.display_standard_name == "Minuto"));
    assert!(classes.iter().any(|c| c.is_test_voucher && c.display_standard_name == "TEST-Minuto"));
}

#[test]
fn test_get_voucher_details_fuzzy_lookup_success() {
    let identity = &ACTORS.alice;
    let mut wallet = setup_in_memory_wallet(identity);
    let user_id = &identity.user_id;

    // 1. Erstelle einen Gutschein mit zwei Transaktionen
    let mut v = Voucher::default();
    v.voucher_id = "v1".to_string();
    
    // Initiale Transaktion (TX1)
    v.transactions.push(Transaction {
        t_id: "tx1".to_string(),
        recipient_id: user_id.clone(),
        ..Default::default()
    });
    
    let id_tx1 = human_money_core::services::crypto_utils::get_hash(format!("v1tx1{}", user_id));
    
    // Zweite Transaktion (TX2) - simuliert einen Transfer/Split
    v.transactions.push(Transaction {
        t_id: "tx2".to_string(),
        recipient_id: user_id.clone(),
        sender_id: Some(user_id.clone()),
        ..Default::default()
    });
    
    let id_tx2 = human_money_core::services::crypto_utils::get_hash(format!("v1tx2{}", user_id));
    
    // Aktueller Zustand im Wallet ist ID_TX2
    wallet.voucher_store.vouchers.insert(id_tx2.clone(), VoucherInstance {
        voucher: v,
        status: VoucherStatus::Active,
        local_instance_id: id_tx2.clone(),
    });

    // Prüfung A: Direkter Lookup (TX2)
    let details = wallet.get_voucher_details(&id_tx2).unwrap();
    assert_eq!(details.local_instance_id, id_tx2);

    // Prüfung B: Fuzzy Lookup (TX1) - Dies ist der Kern der Neuerung!
    let details_fuzzy = wallet.get_voucher_details(&id_tx1).expect("Fuzzy lookup should find the voucher via historical ID");
    assert_eq!(details_fuzzy.local_instance_id, id_tx2, "Should return the current ID");
}

#[test]
fn test_get_voucher_details_not_found() {
    let identity = &ACTORS.alice;
    let wallet = setup_in_memory_wallet(identity);
    
    let result = wallet.get_voucher_details("non-existent");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("fully spent, deleted, or transferred"), "Error message should be descriptive");
}
