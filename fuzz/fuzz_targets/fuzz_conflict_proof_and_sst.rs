#![no_main]

use human_money_core::models::conflict::{ProofOfDoubleSpend, TransactionFingerprint};
use human_money_core::services::conflict_manager::{
    verify_fingerprint_signature, verify_proof_structure, verify_reporter_signature,
};
use human_money_core::test_utils::{setup_in_memory_wallet, ACTORS};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzz deserialization and verification of ProofOfDoubleSpend
    if let Ok(proof) = serde_json::from_slice::<ProofOfDoubleSpend>(data) {
        let _ = verify_proof_structure(&proof);
        let _ = verify_reporter_signature(&proof);

        // Invariant: importing into wallet must handle all invariants without panicking
        let mut wallet = setup_in_memory_wallet(&ACTORS.alice.identity);
        let _ = wallet.import_proof(proof);
    }

    // 2. Fuzz deserialization and verification of TransactionFingerprint (gossip ingress)
    if let Ok(fp) = serde_json::from_slice::<TransactionFingerprint>(data) {
        let _ = verify_fingerprint_signature(&fp);
    }
});
