#![no_main]

use chrono::DateTime;
use human_money_core::models::voucher::Voucher;
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::utils::{add_iso8601_duration, round_up_date};
use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz Voucher JSON Parsing (binary & UTF-8)
    if let Ok(json_str) = std::str::from_utf8(data) {
        if let Ok(voucher) = Voucher::from_json_str(json_str) {
            let _ = voucher.hop_depth();
            let _ = voucher.is_expired(None);
            let alice = &ACTORS.alice.identity;
            let _ = voucher.spendable_balance_for_user(&alice.user_id, &FREETALER_STANDARD.0, None);
            let _ = voucher.validate_issuance_firewall(
                &FREETALER_STANDARD.0,
                &FREETALER_STANDARD.1,
                &alice.user_id,
            );
        }

        // 2. Fuzz Voucher Standard TOML Parsing
        if let Ok((standard, _hash)) = VoucherStandardDefinition::from_toml(json_str) {
            let _ = standard.compute_logic_hash();
            let _ = standard.verify_signature();
        }

        let pinned_issuer = &ACTORS.alice.identity.user_id;
        let _ = VoucherStandardDefinition::from_toml_with_issuer_pin(json_str, Some(pinned_issuer));

        // 3. Fuzz DateTime & ISO8601 Duration Parser
        if let Ok(dt) = DateTime::parse_from_rfc3339(json_str) {
            let dt_utc = dt.with_timezone(&chrono::Utc);
            let _ = add_iso8601_duration(dt_utc, "P1Y");
            let _ = add_iso8601_duration(dt_utc, json_str);
            let _ = round_up_date(dt_utc, "end_of_year");
            let _ = round_up_date(dt_utc, json_str);
        }
    }

    // Direct slice fallback for Voucher serde
    if let Ok(voucher) = serde_json::from_slice::<Voucher>(data) {
        let _ = voucher.hop_depth();
        let _ = voucher.is_expired(None);
    }
});
