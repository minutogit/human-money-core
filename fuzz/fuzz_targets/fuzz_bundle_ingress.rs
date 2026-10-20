#![no_main]

use human_money_core::models::profile::TransactionBundle;
use human_money_core::services::bundle_processor::{
    open_and_verify_bundle, MAX_FORWARDED_FINGERPRINTS_PER_BUNDLE, MAX_VOUCHERS_PER_BUNDLE,
};
use human_money_core::test_utils::ACTORS;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let alice = &ACTORS.alice.identity;
    let bob = &ACTORS.bob.identity;

    // Path 1: Fuzz the complete secure container bundle ingress boundary
    let _ = open_and_verify_bundle(alice, data);
    let _ = open_and_verify_bundle(bob, data);

    // Path 2: Fuzz direct TransactionBundle deserialization (inner layer)
    if data.len() <= 1024 * 1024 {
        if let Ok(bundle) = serde_json::from_slice::<TransactionBundle>(data) {
            let _oversized_vouchers = bundle.vouchers.len() > MAX_VOUCHERS_PER_BUNDLE;
            let _oversized_fps =
                bundle.forwarded_fingerprints.len() > MAX_FORWARDED_FINGERPRINTS_PER_BUNDLE;

            for v in &bundle.vouchers {
                let _ = v.hop_depth();
            }
        }
    }
});
