// tests/wallet_api/maintenance.rs
// cargo test --test wallet_api_tests wallet_api::maintenance
//!
//! Testet Wartungsfunktionen des Wallets, wie die automatische Bereinigung
//! von abgelaufenen Gutschein-Instanzen.

use human_money_core::test_utils::{ACTORS, MINUTO_STANDARD, setup_in_memory_wallet, create_voucher_for_manipulation};
use human_money_core::Wallet;
use human_money_core::VoucherStatus;
use chrono::{Utc, Duration};

#[test]
fn test_cleanup_of_expired_archived_instances() {
    let user = &ACTORS.test_user;
    let mut wallet = setup_in_memory_wallet(user);
    let (standard, hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_data = human_money_core::services::voucher_manager::NewVoucherData {
        validity_duration: Some("P1Y".to_string()),
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(user.user_id.clone()),
            ..Default::default()
        },
        ..Default::default()
    };

    // Gutschein A (abgelaufen)
    let mut voucher_a = create_voucher_for_manipulation(
        voucher_data.clone(),
        standard, hash, &user.signing_key, "en",
    );
    voucher_a.valid_until = (Utc::now() - Duration::days(365 * 3)).to_rfc3339();
    let id_a = Wallet::calculate_local_instance_id(&voucher_a, &user.user_id).unwrap();
    wallet.add_voucher_instance(id_a.clone(), voucher_a, VoucherStatus::Archived);

    // Gutschein B (noch in Gnadenfrist)
    let mut voucher_b = create_voucher_for_manipulation(
        voucher_data, standard, hash, &user.signing_key, "en"
    );
    voucher_b.valid_until = (Utc::now() - Duration::days(180)).to_rfc3339();
    let id_b = Wallet::calculate_local_instance_id(&voucher_b, &user.user_id).unwrap();
    wallet.add_voucher_instance(id_b.clone(), voucher_b, VoucherStatus::Archived);

    // Aktion: Bereinigung mit 1 Jahr Gnadenfrist
    wallet.run_storage_cleanup(None, 1).unwrap();

    assert!(!wallet.voucher_store.vouchers.contains_key(&id_a), "Expired voucher A should have been removed");
    assert!(wallet.voucher_store.vouchers.contains_key(&id_b), "Voucher B within grace period should remain");
}
