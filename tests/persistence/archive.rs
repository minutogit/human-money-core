// tests/persistence/archive.rs
// cargo test --test persistence_tests
//!
//! Tests the functionality of the `VoucherArchive` trait and the `FileVoucherArchive` implementation.
//! Originally in `tests/test_archive.rs`.

use human_money_core::{
    NewVoucherData,
    VoucherStatus,
    archive::file_archive::FileVoucherArchive,
    models::voucher::ValueDefinition,
    
    wallet::Wallet,
};
use tempfile::tempdir;

// Load test helper functions from the parent directory.

use human_money_core::test_utils::{ACTORS, FREETALER_STANDARD};

// --- Main Test ---

#[test]
fn test_voucher_archiving_on_full_spend() {
    // 1. SETUP
    // Use the predefined test actors from `test_utils`.
    let alice_identity = &ACTORS.alice;
    let bob_identity = &ACTORS.bob;

    let mut alice_wallet = human_money_core::test_utils::setup_in_memory_wallet(&alice_identity.identity);

    // Create Alice's archive in the temporary directory.
    let temp_dir = tempdir().unwrap();
    let archive = FileVoucherArchive::new_secure(temp_dir.path(), "audit-test-pw");
    // Use the predefined standard signed at runtime.
    let (standard, standard_hash) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    // Alice creates a voucher and adds it to her wallet.
    let voucher = {
        let nominal_value = ValueDefinition {
            amount: "100.00".to_string(), // Four decimal places for the FreeTaler standard
            unit: "".to_string(),
            abbreviation: Some("".to_string()),
            description: Some("".to_string()),
        };
        let voucher_data = NewVoucherData {
            nominal_value,
            creator_profile: human_money_core::models::profile::PublicProfile {
                id: Some(alice_identity.user_id.clone()),
                // Populate only the necessary fields for this test.
                ..Default::default()
            },
            ..Default::default()
        };

        human_money_core::models::voucher::Voucher::create_with_key(
            voucher_data,
            standard,
            standard_hash,
            &alice_identity.signing_key)
        .unwrap()
    };

    let voucher_id = voucher.voucher_id.clone();
    let local_id = Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();

    // Insert voucher directly with seed (since add_voucher_instance has no seed parameter)
    alice_wallet.voucher_store.vouchers.insert(
        local_id.clone(),
        human_money_core::VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        },
    );

    // 2. ACTION
    // Alice sends her ENTIRE balance ("100") to Bob, passing her archive.
    let request = human_money_core::wallet::MultiTransferRequest {
        recipient_id: bob_identity.user_id.clone(),
        sources: vec![human_money_core::wallet::SourceTransfer {
            local_instance_id: local_id.clone(),
            amount_to_send: "100.00".to_string(), // Amount must also have the correct format.
        }],
        notes: None,
        sender_profile_name: None,
        use_privacy_mode: None,
    };

    let mut standards = std::collections::HashMap::new();
    standards.insert(standard.immutable.identity.uuid.clone(), standard.clone());

    let human_money_core::wallet::CreateBundleResult { bundle_bytes, .. } = alice_wallet
        .execute_multi_transfer_and_bundle(
            alice_identity,
            &standards,
            request,
            Some(&archive), // The archive backend is passed.
        )
        .expect("Transfer with archive should succeed.");

    // The new method returns only bundle bytes, not the voucher state, so we need to reconstruct
    // it from the bundle to maintain the test functionality
    let transferred_voucher_state = {
        // To get the transferred voucher state, we need to open the bundle
        let bundle_result = human_money_core::services::bundle_processor::open_and_verify_bundle(
            bob_identity,
            &bundle_bytes,
        )
        .unwrap();
        bundle_result.vouchers.into_iter().next().unwrap()
    };

    // 3. VERIFICATION
    // Check if the archive system created the correct file in the correct subdirectory.
    let last_tx = transferred_voucher_state.transactions.last().unwrap();
    let expected_file_path = temp_dir
        .path()
        .join(&voucher_id)
        .join(format!("{}.json", &last_tx.t_id));

    assert!(expected_file_path.exists(), "Archive file was not created.");

    // Load the archived voucher through the archive API. The record on disk is
    // encrypted at rest, so raw disk access can no longer yield the plaintext
    // state; decryption and integrity verification are handled by the archive.
    let archived_voucher: human_money_core::models::voucher::Voucher = archive
        .get_archived_voucher(&voucher_id)
        .expect("Archived voucher must be retrievable via the archive API.");

    // The archived voucher must match exactly the state returned by the `create_transfer` function.
    assert_eq!(archived_voucher, transferred_voucher_state);
}
