#![no_main]

use libfuzzer_sys::fuzz_target;
use human_money_core::models::secure_container::{SecureContainer, MAX_RECIPIENTS};
use human_money_core::services::bundle_processor::MAX_CONTAINER_BYTES;
use human_money_core::test_utils::ACTORS;

fuzz_target!(|data: &[u8]| {
    // Untrusted ingress boundary: enforce MAX_CONTAINER_BYTES cap
    if data.len() > MAX_CONTAINER_BYTES {
        return;
    }

    if let Ok(container) = serde_json::from_slice::<SecureContainer>(data) {
        // Invariant 1: Recipient count limit
        if container.recipients.len() > MAX_RECIPIENTS {
            assert!(container.verify_integrity().is_err());
        } else {
            let _ = container.verify_integrity();
        }

        // Invariant 2: Envelope signature verification must never panic
        let alice = &ACTORS.alice.identity;
        let bob = &ACTORS.bob.identity;
        let _ = container.verify_container_signature(&alice.user_id);
        let _ = container.verify_container_signature(&bob.user_id);
        let _ = container.verify_container_signature("did:key:invalid_or_corrupt_id_structure");

        // Invariant 3: Decryption / open must never panic or allocate unbounded memory
        let _ = container.open(alice, None);
        let _ = container.open(bob, None);
        let _ = container.open(alice, Some("correct_or_wrong_password"));
        let _ = container.open(bob, Some(""));
    }
});
