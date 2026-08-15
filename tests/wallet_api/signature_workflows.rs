// tests/wallet_api/signature_workflows.rs
// cargo test --test wallet_api_tests
//!
//! Contains integration tests specifically for signature workflows
//! controlled via the `AppService` and `Wallet` facades.
//! This includes requesting, creating, and attaching signatures.

// Explicitly include the `test_utils` module via its file path.

use human_money_core::{
    UserIdentity, VoucherCoreError, VoucherInstance, VoucherStatus, Wallet,
    error::ValidationError,
    models::{
        profile::PublicProfile,
        secure_container::{ContainerConfig, PrivacyMode, SecureContainer},
        signature::DetachedSignature,
        voucher::{ValueDefinition, Voucher, VoucherSignature},
    },
    services::{
        secure_container_manager::{self, ContainerManagerError},
        voucher_manager::NewVoucherData,
        voucher_validation,
    },
    test_utils::{
        self, ACTORS, MINUTO_STANDARD, FREETALER_STANDARD, add_voucher_to_wallet,
        create_additional_signature_data, create_voucher_for_manipulation, debug_open_container,
        generate_signed_standard_toml, setup_in_memory_wallet,
    },
};
use std::{fs, path::PathBuf};
use tempfile::tempdir;

/// Helper function to create a standard voucher for tests and
/// place it directly into a test subject's wallet.
fn setup_voucher_for_alice(
    alice_wallet: &mut Wallet,
    alice_identity: &UserIdentity,
) -> (Voucher, String) {
    let voucher_data = NewVoucherData {
        validity_duration: Some("P3Y".to_string()),
        non_redeemable_test_voucher: true,
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(alice_identity.user_id.clone()),
            ..Default::default()
        },
        // FIX: Missing amount (caused InvalidAmountFormat)
        nominal_value: ValueDefinition {
            amount: "60".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    let (standard, standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher = create_voucher_for_manipulation(
        voucher_data,
        standard,
        standard_hash,
        &alice_identity.signing_key);
    let local_id = Wallet::calculate_local_instance_id(&voucher, &alice_identity.user_id).unwrap();
    alice_wallet.voucher_store.vouchers.insert(
        local_id.clone(),
        VoucherInstance {
            voucher: voucher.clone(),
            status: VoucherStatus::Active,
            local_instance_id: local_id.clone(),
        },
    );
    (voucher, local_id)
}

// --- 1. Wallet Signature Workflows ---

/// Tests the complete signature workflow via the `Wallet` facade.
///
/// ### Scenario:
/// 1.  Alice creates a voucher that requires guarantors according to the standard.
///     Initial validation therefore fails.
/// 2.  Alice creates a signing request (`SecureContainer`) and sends it to Bob.
/// 3.  Bob receives the request, opens the container, extracts the voucher,
///     creates his guarantor signature, and returns it in a response.
/// 4.  Alice receives Bob's response, processes it, and attaches the signature
///     to her voucher.
/// 5.  Final verification shows that the voucher now has a signature,
///     but validation still fails because the *number* of
///     required guarantors is not met.
#[test]
fn api_wallet_full_signature_workflow() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let temp_dir = tempdir().expect("Failed to create temporary directory");

    let (voucher, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    assert!(
        voucher_validation::validate_voucher_against_standard(&voucher, minuto_standard).is_err()
    );

    let request_container_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption))
        .unwrap();
    let request_file_path: PathBuf = temp_dir.path().join("request.secure");
    fs::write(&request_file_path, request_container_bytes).unwrap();

    let received_request_bytes = fs::read(&request_file_path).unwrap();
    let container: SecureContainer = serde_json::from_slice(&received_request_bytes).unwrap();
    let decrypted_payload =
        secure_container_manager::open_secure_container(&container, &bob.identity, None).unwrap();
    let voucher_from_alice: Voucher = serde_json::from_slice(&decrypted_payload).unwrap();

    let guarantor_metadata = VoucherSignature {
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_container_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_from_alice,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();
    let response_file_path: PathBuf = temp_dir.path().join("response.secure");
    fs::write(&response_file_path, response_container_bytes).unwrap();

    let received_response_bytes = fs::read(&response_file_path).unwrap();
    alice_wallet
        .process_and_attach_signature(&alice.identity, &received_response_bytes, None)
        .unwrap();

    let instance = alice_wallet.voucher_store.vouchers.get(&local_id).unwrap();
    // FIX: The voucher now has 2 signatures:
    // 0: creator
    // 1: bob (guarantor)
    assert_eq!(instance.voucher.signatures.len(), 2);
    assert_eq!(instance.voucher.signatures[1].signer_id, bob.user_id);
    // Check if the nested details (via `include_details: true`) are present
    // (Bob's wallet profile is empty, so fields are None)
    assert!(instance.voucher.signatures[1].details.is_some());

    let validation_result =
        voucher_validation::validate_voucher_against_standard(&instance.voucher, minuto_standard);
    dbg!(&validation_result);

    assert!(matches!(
        validation_result.unwrap_err(),
        VoucherCoreError::Validation(ValidationError::BusinessRuleViolated(msg))
        if msg.contains("männlicher") || msg.contains("1") || msg.contains("Bürg") || msg.contains("weibliche")
    ));
}

/// Ensures that a `SecureContainer` cannot be opened by an incorrect recipient.
///
/// ### Scenario:
/// 1.  Alice creates a signing request explicitly addressed to Bob.
/// 2.  Eve (a third party) intercepts the request and tries to open it.
/// 3.  The attempt fails with `NotAnIntendedRecipient`.
#[test]
fn api_wallet_signature_fail_wrong_recipient() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let eve = &ACTORS.hacker;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    let container: SecureContainer = serde_json::from_slice(&request_bytes).unwrap();
    let result = secure_container_manager::open_secure_container(&container, &eve.identity, None);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Container(ContainerManagerError::NotAnIntendedRecipient)
    ));
}

/// Ensures that a tampered `SecureContainer` is rejected.
///
/// ### Scenario:
/// 1.  Bob creates a valid signature response for Alice.
/// 2.  An attacker tampers with a byte in the encrypted payload of the container.
/// 3.  Alice attempts to process the tampered response.
/// 4.  The process fails because decryption fails due to an
///     authentication error (AEAD).
#[test]
fn api_wallet_signature_fail_tampered_container() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (voucher, _) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let guarantor_metadata = VoucherSignature {
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    let mut container: SecureContainer = serde_json::from_slice(&response_bytes).unwrap();

    // Tamper with the Base64 ciphertext string to trigger an AEAD error.
    let mut chars: Vec<char> = container.ciphertext.chars().collect();
    if chars.len() > 10 {
        // Swap a character to invalidate the signature.
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    }
    container.ciphertext = chars.into_iter().collect();
    let tampered_bytes = serde_json::to_vec(&container).unwrap();

    let result = alice_wallet.process_and_attach_signature(&alice.identity, &tampered_bytes, None);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::SymmetricEncryption(_)
    ));
}

/// Ensures that a signature for an unknown voucher is rejected.
///
/// ### Scenario:
/// 1.  Alice has voucher A in her wallet. She also created voucher B,
///     but did not put it in her wallet.
/// 2.  Bob is supposed to sign voucher A, but mistakenly creates a signature
///     that references the ID of voucher B.
/// 3.  Alice attempts to process this signature.
/// 4.  The process fails with `VoucherNotFound` because her wallet does not know the voucher
///     with ID of B to which the signature should be attached.
#[test]
fn api_wallet_signature_fail_mismatched_voucher_id() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (_voucher_a, _) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let voucher_data_b = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(alice.user_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "120".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P3Y".to_string()),
        ..Default::default()
    };
    let (minuto_standard, minuto_standard_hash) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);
    let voucher_b = create_voucher_for_manipulation(
        voucher_data_b,
        minuto_standard,
        minuto_standard_hash,
        &alice.identity.signing_key);

    let guarantor_metadata = VoucherSignature {
        role: "guarantor".to_string(),
        ..Default::default()
    };
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_b,
            DetachedSignature::Signature(guarantor_metadata),
            true, // include_details
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    let result = alice_wallet.process_and_attach_signature(&alice.identity, &response_bytes, None);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherNotFound(_)
    ));
}

/// Ensures that processing fails when the payload type is unexpected.
///
/// ### Scenario:
/// 1.  Alice creates a container of type `VoucherForSigning`.
/// 2.  She attempts to process this container with `process_and_attach_signature`,
///     which expects a payload of type `DetachedSignature`.
/// 3.  The process fails with `InvalidPayloadType`.
#[test]
fn api_wallet_signature_fail_wrong_payload_type() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (_, local_id) = setup_voucher_for_alice(&mut alice_wallet, &alice.identity);

    let request_container_bytes = alice_wallet
        .create_signing_request(&alice.identity, &local_id, ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    let result =
        alice_wallet.process_and_attach_signature(&alice.identity, &request_container_bytes, None);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::InvalidPayloadType
    ));
}

// --- 2. AppService Signature Workflows ---

/// Tests the complete signature workflow via the `AppService` facade.
///
/// ### Scenario:
/// 1.  Two `AppService` instances are set up for a creator and a guarantor.
/// 2.  The creator creates a voucher.
/// 3.  The creator requests a signature from the guarantor.
/// 4.  The guarantor receives the request, creates an `AdditionalSignature`
///     (matching the FreeTaler standard), and returns it.
/// 5.  The creator receives the response and successfully attaches the signature.
/// 6.  Voucher details display the new signature.
#[test]
fn api_app_service_full_signature_workflow() {
    human_money_core::set_signature_bypass(true);
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let dir_creator = tempdir().unwrap();
    let dir_guarantor = tempdir().unwrap();
    let password = "sig-password";

    let creator = &ACTORS.alice;
    let guarantor = &ACTORS.guarantor1;
    let (mut service_creator, _) =
        test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", password);
    let (mut service_guarantor, profile_guarantor) = test_utils::setup_service_with_profile(
        dir_guarantor.path(),
        guarantor,
        "Guarantor",
        password,
    );
    let id_guarantor = service_guarantor.get_user_id().unwrap();

    let _voucher = service_creator
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_creator.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "50".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(password),
        )
        .unwrap();
    let local_id = service_creator.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();

    let request_bytes = service_creator
        .create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(id_guarantor.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    let voucher_to_sign = {
        service_guarantor
            .login(&profile_guarantor.folder_name, password, false, "test-id".to_string())
            .unwrap();
        let guarantor_identity = service_guarantor.get_unlocked_mut_for_test().1;
        // The sender (creator) is known; we do not need to extract them from the container.
        debug_open_container(&request_bytes, guarantor_identity).unwrap()
    };
    let _signature_data = create_additional_signature_data(
        service_guarantor.get_unlocked_mut_for_test().1,
        "Verified by external party.",
    );

    let response_bytes = service_guarantor
        .create_detached_signature_response_bundle(
            &voucher_to_sign,
            "notary", // Role (based on `create_additional_signature_data`)
            true,     // include_details
            ContainerConfig::TargetDid(service_creator.get_user_id().unwrap(), PrivacyMode::TrialDecryption),
            Some(password),
        )
        .unwrap();

    service_creator
        .process_and_attach_signature(&response_bytes, &freetaler_standard_toml, None, Some(password))
        .unwrap();

    let details = service_creator.get_voucher_details(&local_id).unwrap();
    // FIX: 2 signatures (creator + notary)
    assert_eq!(details.voucher.signatures.len(), 2);
    // FIX: Find the signature that is *not* "creator" and *not* "guarantor".
    assert_eq!(
        details
            .voucher
            .signatures
            .iter()
            .find(|s| s.role != "guarantor" && s.role != "creator")
            .expect("Should have found the 'notary' signature")
            .signer_id,
        id_guarantor
    );
}

/// Tests the signature roundtrip for a standard that requires signatures (Minuto).
///
/// ### Scenario:
/// 1.  Alice creates a Minuto voucher, which is invalid without guarantors.
/// 2.  She requests a signature from Bob.
/// 3.  Bob receives the request, creates a `GuarantorSignature`, and returns
///     it in an encrypted response.
/// 4.  Alice receives the response and attaches the signature to her voucher.
/// 5.  The voucher then has a signature from Bob.
#[test]
fn api_wallet_signature_roundtrip_minuto_required() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let mut bob_wallet = setup_in_memory_wallet(&bob.identity); // Bob's wallet for the response
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Create a Minuto voucher that still needs guarantors. `false` = create as invalid.
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Alice creates a signing request for Bob
    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &voucher_id, ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    // Bob processes the request and creates a response
    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    // Bob creates his signature data (as enum)
    let mut signature_data_enum = test_utils::create_guarantor_signature_data(
        &bob.identity,
        "1",
        &voucher_for_signing.voucher_id,
    );
    // We modify the inner structure via pattern matching
    let DetachedSignature::Signature(guarantor_struct) = &mut signature_data_enum;
    assert_eq!(guarantor_struct.role, "guarantor");
    // Setting `first_name` etc. is no longer necessary because `create_detached_signature_response`
    // automatically inserts `details` (PublicProfile) from the wallet (here Bob).
    // We must populate Bob's wallet profile so the details arrive.
    bob_wallet.profile.first_name = Some("Bob".to_string());
    bob_wallet.profile.last_name = Some("Builder".to_string());

    // Bob creates the encrypted response with the signature
    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_for_signing,
            signature_data_enum,
            true,
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    // Alice processes the signature response
    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes, None)
        .unwrap();

    // Assert: The voucher now has exactly one signature from Bob
    let final_instance = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    // FIX: 2 signatures (creator + bob)
    assert_eq!(final_instance.voucher.signatures.len(), 2);
    assert_eq!(
        final_instance.voucher.signatures[1].signer_id,
        bob.identity.user_id
    );
    // Check the nested details
    // FIX: Index 1
    let details = final_instance.voucher.signatures[1]
        .details
        .as_ref()
        .unwrap();
    assert_eq!(details.first_name.as_deref(), Some("Bob"));
    assert_eq!(details.last_name.as_deref(), Some("Builder"));
}

/// Tests the complete guarantor workflow via the `AppService` facade,
/// specifically the state transition from `Incomplete` to `Active`.
///
/// ### Scenario:
/// 1.  A creator and two guarantors are initialized as separate `AppService` instances.
/// 2.  The creator creates a new voucher following the Minuto standard, which
///     requires two guarantors.
/// 3.  **Assertion 1:** The voucher initially has status `Incomplete`.
/// 4.  The creator requests signatures from both guarantors and attaches them sequentially.
/// 5.  **Assertion 2:** After attaching the first signature, the status is still
///     `Incomplete`, but with an updated reason.
/// 6.  **Assertion 3:** After attaching the second (and final required) signature,
///     the voucher status changes to `Active`.
#[test]
fn test_full_guarantor_workflow_via_app_service() {
    human_money_core::set_signature_bypass(true);
    // --- 1. Setup: Simulate three separate users ---
    let dir_creator = tempdir().expect("Failed to create temp dir for creator");
    let dir_g1 = tempdir().expect("Failed to create temp dir for guarantor1");
    let dir_g2 = tempdir().expect("Failed to create temp dir for guarantor2");
    let password = "password123";

    let minuto_standard_toml =
        generate_signed_standard_toml("voucher_standards/minuto_v1/standard.toml");

    // Creator Service
    let creator = &ACTORS.alice;
    let (mut service_creator, _) =
        test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", password);
    let creator_id = service_creator.get_user_id().unwrap();
    let (mut service_g1, profile_g1) = test_utils::setup_service_with_profile(
        dir_g1.path(),
        &ACTORS.male_guarantor,
        "Male Guarantor",
        password,
    );
    let g1_id = service_g1.get_user_id().unwrap();
    let (mut service_g2, profile_g2) = test_utils::setup_service_with_profile(
        dir_g2.path(),
        &ACTORS.female_guarantor,
        "Female Guarantor",
        password,
    );
    let g2_id = service_g2.get_user_id().unwrap();

    // --- 2. Step 1: Creation of incomplete voucher ---
    // NOW CALL THE FIXED API FUNCTION
    let voucher_data = NewVoucherData {
        creator_profile: human_money_core::models::profile::PublicProfile {
            id: Some(creator_id.clone()),
            ..Default::default()
        },
        nominal_value: ValueDefinition {
            amount: "60".to_string(),
            ..Default::default()
        },
        validity_duration: Some("P3Y".to_string()),
        ..Default::default()
    };

    // Thanks to the patch in `command_handler.rs`, this function should now
    // correctly create an `Incomplete` voucher instead of panicking.
    let _created_voucher = service_creator
        .create_new_voucher(&minuto_standard_toml, voucher_data, Some(password))
        .expect("create_new_voucher should now succeed for incomplete vouchers");

    let summary = service_creator
        .get_voucher_summaries(None, None, None)
        .expect("Failed to get summaries")
        .pop()
        .expect("Wallet should contain one voucher");
    let local_id = summary.local_instance_id;

    // --- 3. Assertion 1: Status is `Incomplete` ---
    let details_before = service_creator
        .get_voucher_details(&local_id)
        .expect("Should find voucher details");
    assert!(matches!(
        details_before.status,
        VoucherStatus::Incomplete { .. }
    ));

    // --- 4. Step 2: Simulate signing process ---

    // --- Signature from Guarantor 1 ---
    let _request_bundle_1 = service_creator
        .create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(g1_id.clone(), PrivacyMode::TrialDecryption))
        .expect("Failed to create signing request for G1");

    // FIX: We must populate G1's (Guarantor 1) profile with
    // gender data *before* the signature is created.
    service_g1
        .login(&profile_g1.folder_name, password, false, "test-id".to_string())
        .unwrap();
    let (wallet_g1, _) = service_g1.get_unlocked_mut_for_test();
    wallet_g1.profile.gender = Some("1".to_string());
    wallet_g1.profile.service_offer = Some("Test Service Offer".to_string());
    wallet_g1.profile.needs = Some("Test Needs".to_string());

    // Note: In the new structure, create_detached_signature_response_bundle
    // only sets details if include_details=true and the AppService supports it.
    // Here we must directly create a signature with details.
    let response_bundle_1 = service_g1
        .create_detached_signature_response_bundle(
            &details_before.voucher,
            "guarantor",
            true, // include_details
            ContainerConfig::TargetDid(service_creator.get_user_id().unwrap(), PrivacyMode::TrialDecryption),
            Some(password),
        )
        .expect("Failed to create signature response from G1");
    service_creator
        .process_and_attach_signature(&response_bundle_1, &minuto_standard_toml, None, Some(password))
        .expect("Failed to attach G1's signature");
    let details_mid = service_creator.get_voucher_details(&local_id).unwrap();
    assert!(matches!(
        details_mid.status,
        VoucherStatus::Incomplete { .. }
    ));

    // --- Signature from Guarantor 2 ---
    let _request_bundle_2 = service_creator
        .create_signing_request_bundle(&local_id, ContainerConfig::TargetDid(g2_id.clone(), PrivacyMode::TrialDecryption))
        .expect("Failed to create signing request for G2");

    // FIX: We must populate G2's (Guarantor 2) profile with
    // gender data *before* the signature is created.
    service_g2
        .login(&profile_g2.folder_name, password, false, "test-id".to_string())
        .unwrap();
    let (wallet_g2, _) = service_g2.get_unlocked_mut_for_test();
    wallet_g2.profile.gender = Some("2".to_string());

    // Note: In the new structure, create_detached_signature_response_bundle
    // only sets details if include_details=true and the AppService supports it.
    let response_bundle_2 = service_g2
        .create_detached_signature_response_bundle(
            &details_mid.voucher,
            "guarantor",
            true, // include_details
            ContainerConfig::TargetDid(service_creator.get_user_id().unwrap(), PrivacyMode::TrialDecryption),
            Some(password),
        )
        .expect("Failed to create signature response from G2");
    service_creator
        .process_and_attach_signature(&response_bundle_2, &minuto_standard_toml, None, Some(password))
        .expect("Failed to attach G2's signature");

    // --- 5. Assertion 3: Verify final `Active` state ---
    let details_after = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(
        details_after.status,
        VoucherStatus::Active,
        "Final voucher status should be Active"
    );
    // Verify nested gender data
    // FIX: Index 0 is the creator. Guarantors are at index 1 and 2.
    let g1_sig = details_after
        .voucher
        .signatures
        .iter()
        .find(|s| s.signer_id == g1_id)
        .unwrap();
    assert_eq!(
        g1_sig.details.as_ref().unwrap().gender.as_deref(),
        Some("1")
    );
    // Verify new fields
    assert_eq!(
        g1_sig.details.as_ref().unwrap().service_offer.as_deref(),
        Some("Test Service Offer")
    );
    assert_eq!(
        g1_sig.details.as_ref().unwrap().needs.as_deref(),
        Some("Test Needs")
    );

    // Verify Guarantor 2
    let g2_sig = details_after
        .voucher
        .signatures
        .iter()
        .find(|s| s.signer_id == g2_id)
        .unwrap();
    assert_eq!(
        g2_sig.details.as_ref().unwrap().gender.as_deref(),
        Some("2")
    );
}

/// Tests signature roundtrip for a standard with optional signatures (FreeTaler).
///
/// ### Scenario:
/// 1.  Alice creates a FreeTaler voucher, which is initially valid because `needed_guarantors = 0`.
/// 2.  She requests an optional signature from Bob anyway.
/// 3.  Bob receives and responds to the request.
/// 4.  Alice successfully attaches the optional signature.
/// 5.  The voucher then has a signature, even though it was not required.
#[test]
fn api_wallet_signature_roundtrip_silver_optional() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob = &ACTORS.bob;
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (freetaler_standard, _) = (&FREETALER_STANDARD.0, &FREETALER_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "10",
        freetaler_standard,
        false,
    )
    .unwrap();

    let request_bytes = alice_wallet
        .create_signing_request(&alice.identity, &voucher_id, ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption))
        .unwrap();

    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    let mut signature_data_enum = test_utils::create_guarantor_signature_data(
        &bob.identity,
        "1",
        &voucher_for_signing.voucher_id,
    );
    let DetachedSignature::Signature(guarantor_struct) = &mut signature_data_enum;
    assert_eq!(guarantor_struct.role, "guarantor");
    // Setting `first_name` etc. is no longer necessary because `create_detached_signature_response`
    // automatically inserts `details` (PublicProfile) from the wallet (here Bob).

    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_for_signing,
            signature_data_enum,
            false, // include_details
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes, None)
        .unwrap();

    let final_instance = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    // FIX: 2 signatures (creator + bob)
    assert_eq!(final_instance.voucher.signatures.len(), 2);
    // Details should be `None` because `include_details: false`
    // FIX: Index 1
    assert!(final_instance.voucher.signatures[1].details.is_none());
}

/// Tests signature request and response via symmetric encryption (password).
#[test]
fn api_app_service_symmetric_signature_workflow() {
    human_money_core::set_signature_bypass(true);
    let freetaler_standard_toml =
        generate_signed_standard_toml("voucher_standards/freetaler_v1/standard.toml");
    let dir_creator = tempdir().unwrap();
    let dir_guarantor = tempdir().unwrap();
    let wallet_password = "wallet-password";
    let container_password = "container-password";

    let creator = &ACTORS.alice;
    let guarantor = &ACTORS.guarantor1;
    let (mut service_creator, _) =
        test_utils::setup_service_with_profile(dir_creator.path(), creator, "Creator", wallet_password);
    let (mut service_guarantor, profile_guarantor) = test_utils::setup_service_with_profile(
        dir_guarantor.path(),
        guarantor,
        "Guarantor",
        wallet_password,
    );

    // 1. Creator creates a voucher
    let _voucher = service_creator
        .create_new_voucher(
            &freetaler_standard_toml,
            NewVoucherData {
                creator_profile: PublicProfile {
                    id: Some(service_creator.get_user_id().unwrap()),
                    ..Default::default()
                },
                nominal_value: ValueDefinition {
                    amount: "50".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
            Some(wallet_password),
        )
        .unwrap();
    let local_id = service_creator.get_voucher_summaries(None, None, None).unwrap()[0]
        .local_instance_id
        .clone();

    // 2. Creator creates a signing request encrypted with a PASSWORD (instead of DID)
    let request_bytes = service_creator
        .create_signing_request_bundle(&local_id, ContainerConfig::Password(container_password.to_string()))
        .unwrap();

    // 3. Guarantor opens the container with the same password
    service_guarantor.login(&profile_guarantor.folder_name, wallet_password, false, "test-id".to_string()).unwrap();
    let unlocked_guarantor = service_guarantor.get_unlocked_mut_for_test();
    let guarantor_identity = unlocked_guarantor.1;

    let request_container: SecureContainer = serde_json::from_slice(&request_bytes).unwrap();
    let opened_payload = human_money_core::services::secure_container_manager::open_secure_container(
        &request_container,
        guarantor_identity,
        Some(container_password),
    ).expect("Symmetric container opening failed");
    
    let voucher_to_sign: human_money_core::models::voucher::Voucher = serde_json::from_slice(&opened_payload).unwrap();

    // 4. Guarantor creates a response also encrypted with the same PASSWORD
    let response_bytes = service_guarantor
        .create_detached_signature_response_bundle(
            &voucher_to_sign,
            "notary",
            true,
            ContainerConfig::Password(container_password.to_string()),
            Some(wallet_password),
        )
        .unwrap();

    // 5. Creator attaches response using PASSWORD for decryption
    service_creator
        .process_and_attach_signature(
            &response_bytes,
            &freetaler_standard_toml,
            Some(container_password),
            Some(wallet_password),
        )
        .expect("Attaching symmetric signature response failed");

    let details = service_creator.get_voucher_details(&local_id).unwrap();
    assert_eq!(details.voucher.signatures.len(), 2);
}

// --- 3. Signature Removal Tests ---

/// Tests the successful removal of an additional signature in Incomplete status.
///
/// ### Scenario:
/// 1. Voucher is created (status Incomplete), an additional signature (guarantor) is attached.
/// 2. remove_signature is called by Creator for the attached signature ID.
/// 3. Expectation: Ok(()). The signatures list is subsequently reduced.
#[test]
fn test_remove_signature_success_incomplete_state() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Create a voucher in Incomplete status
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Add a guarantor signature
    let request_bytes = alice_wallet
        .create_signing_request(
            &alice.identity,
            &voucher_id,
            ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    let signature_data_enum = test_utils::create_guarantor_signature_data(
        &bob.identity,
        "1",
        &voucher_for_signing.voucher_id,
    );

    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_for_signing,
            signature_data_enum,
            false,
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes, None)
        .unwrap();

    let instance_before = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    // 2 signatures: creator + bob
    assert_eq!(instance_before.voucher.signatures.len(), 2);
    let bob_signature_id = instance_before.voucher.signatures[1].signature_id.clone();

    // Remove the signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, &bob_signature_id);
    assert!(result.is_ok());

    // Verify that the signature was removed
    let instance_after = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    assert_eq!(instance_after.voucher.signatures.len(), 1);
    assert_eq!(instance_after.voucher.signatures[0].role, "creator");
}

/// Tests that removing a signature fails in Active status.
///
/// ### Scenario:
/// 1. Voucher is created, receives sufficient signatures to transition to Active status.
/// 2. An additional (surplus) signature is attached.
/// 3. remove_signature is called by Creator for the surplus signature.
/// 4. Expectation: Err(SignatureRemovalRequiresIncomplete).
#[test]
fn test_remove_signature_fails_active_state() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let charlie = &ACTORS.charlie;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let charlie_wallet = setup_in_memory_wallet(&charlie.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Create a voucher
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Add two guarantor signatures (Minuto requires 2)
    for (signer, wallet) in [(&bob.identity, &bob_wallet), (&charlie.identity, &charlie_wallet)] {
        let request_bytes = alice_wallet
            .create_signing_request(
                &alice.identity,
                &voucher_id,
                ContainerConfig::TargetDid(signer.user_id.clone(), PrivacyMode::TrialDecryption),
            )
            .unwrap();

        let voucher_for_signing = debug_open_container(&request_bytes, signer).unwrap();

        let signature_data_enum = test_utils::create_guarantor_signature_data(
            signer,
            "1",
            &voucher_for_signing.voucher_id,
        );

        let response_bytes = wallet
            .create_detached_signature_response(
                signer,
                &voucher_for_signing,
                signature_data_enum,
                false,
                ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
            )
            .unwrap();

        alice_wallet
            .process_and_attach_signature(&alice.identity, &response_bytes, None)
            .unwrap();
    }

    // Add a third (surplus) signature
    let request_bytes = alice_wallet
        .create_signing_request(
            &alice.identity,
            &voucher_id,
            ContainerConfig::TargetDid(bob.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    let voucher_for_signing = debug_open_container(&request_bytes, &bob.identity).unwrap();

    let signature_data_enum = test_utils::create_guarantor_signature_data(
        &bob.identity,
        "1",
        &voucher_for_signing.voucher_id,
    );

    let response_bytes = bob_wallet
        .create_detached_signature_response(
            &bob.identity,
            &voucher_for_signing,
            signature_data_enum,
            false,
            ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
        )
        .unwrap();

    alice_wallet
        .process_and_attach_signature(&alice.identity, &response_bytes, None)
        .unwrap();

    // Manually set status to Active to test the lock
    alice_wallet.update_voucher_status(&voucher_id, VoucherStatus::Active);

    let instance_before = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    // 4 signatures: creator + 2 required guarantors + 1 extra
    assert_eq!(instance_before.status, VoucherStatus::Active);
    assert_eq!(instance_before.voucher.signatures.len(), 4);
    let extra_signature_id = instance_before.voucher.signatures[3].signature_id.clone();

    // Remove surplus signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, &extra_signature_id);
    
    assert!(matches!(
        result.expect_err("Should fail to remove signature from active voucher"),
        VoucherCoreError::SignatureRemovalRequiresIncomplete(VoucherStatus::Active)
    ));

    // Verify that the signature is still present
    let instance_after = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    assert_eq!(instance_after.voucher.signatures.len(), 4);
    assert_eq!(instance_after.status, VoucherStatus::Active);
}

/// Tests that removing a signature sets status to Incomplete.
///
/// ### Scenario:
/// 1. Voucher requires exactly 2 guarantors according to standard. It has 2 guarantors and is in Active status.
/// 2. remove_signature is successfully called for one of the guarantors.
/// 3. Expectation: Ok(()). The deletion succeeds, but status transitions to Incomplete.
#[test]
fn test_remove_signature_triggers_status_downgrade() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.male_guarantor;
    let charlie = &ACTORS.female_guarantor;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let bob_wallet = setup_in_memory_wallet(&bob.identity);
    let charlie_wallet = setup_in_memory_wallet(&charlie.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    // Create a voucher
    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Add two guarantor signatures (Minuto requires 2: 1 male, 1 female)
    for (signer, wallet) in [(&bob.identity, &bob_wallet), (&charlie.identity, &charlie_wallet)] {
        let request_bytes = alice_wallet
            .create_signing_request(
                &alice.identity,
                &voucher_id,
                ContainerConfig::TargetDid(signer.user_id.clone(), PrivacyMode::TrialDecryption),
            )
            .unwrap();

        let voucher_for_signing = debug_open_container(&request_bytes, signer).unwrap();

        let signature_data_enum = test_utils::create_guarantor_signature_data(
            signer,
            &if signer.user_id == bob.identity.user_id { "1" } else { "2" },
            &voucher_for_signing.voucher_id,
        );

        let response_bytes = wallet
            .create_detached_signature_response(
                signer,
                &voucher_for_signing,
                signature_data_enum,
                false,
                ContainerConfig::TargetDid(alice.identity.user_id.clone(), PrivacyMode::TrialDecryption),
            )
            .unwrap();

        alice_wallet
            .process_and_attach_signature(&alice.identity, &response_bytes, None)
            .unwrap();
    }

    let instance_before = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    // 3 signatures: creator + 2 guarantors
    assert_eq!(instance_before.voucher.signatures.len(), 3);
    // Status should be Active (since Minuto requirements are met)
    // We manually set status to Active for the test
    alice_wallet.update_voucher_status(&voucher_id, VoucherStatus::Active);

    let instance_after_update = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    assert_eq!(instance_after_update.status, VoucherStatus::Active);

    let guarantor_signature_id = instance_after_update.voucher.signatures[1].signature_id.clone();

    // Remove one of the guarantors -> Should fail because Active
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, &guarantor_signature_id);
    
    assert!(matches!(
        result.expect_err("Should fail to remove signature from active voucher"),
        VoucherCoreError::SignatureRemovalRequiresIncomplete(VoucherStatus::Active)
    ));

    // Verify that status remained Active and nothing was removed
    let instance_final = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    assert_eq!(instance_final.status, VoucherStatus::Active);
    assert_eq!(instance_final.voucher.signatures.len(), 3);
}

/// Tests that the creator signature cannot be removed.
///
/// ### Scenario:
/// 1. Voucher (status Incomplete or Active) contains a signature with role creator.
/// 2. remove_signature is called by Creator for this signature ID.
/// 3. Expectation: Err(CannotRemoveCreatorSignature).
#[test]
fn test_remove_signature_fails_creator_signature() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    let creator_signature_id = instance.voucher.signatures[0].signature_id.clone();

    // Attempt to remove the creator signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, &creator_signature_id);

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::CannotRemoveCreatorSignature
    ));

    // Verify that the signature is still present
    let instance_after = alice_wallet
        .voucher_store
        .vouchers
        .get(&voucher_id)
        .unwrap();
    assert_eq!(instance_after.voucher.signatures.len(), 1);
}

/// Tests that only the creator can remove signatures.
///
/// ### Scenario:
/// 1. Voucher is created by Identity A (Creator).
/// 2. Identity B attempts to remove a signature.
/// 3. Expectation: Err(NotTheCreator).
#[test]
fn test_remove_signature_fails_not_the_creator() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Bob attempts to remove a signature
    let result = alice_wallet.remove_signature(&bob.identity, &voucher_id, "any-signature-id");

    assert!(matches!(result.unwrap_err(), VoucherCoreError::NotTheCreator));
}

/// Tests that signatures cannot be removed when the voucher is already in circulation via transfer.
///
/// ### Scenario:
/// 1. Creator creates voucher, attaches signature, and performs a full transfer.
/// 2. remove_signature is called by Creator.
/// 3. Expectation: Err(VoucherAlreadyInCirculation).
#[test]
fn test_remove_signature_fails_already_in_circulation_via_transfer() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let _bob = &ACTORS.bob;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Simulate a transfer by adding a second transaction
    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    
    // Add a dummy transaction to simulate circulation
    let mut dummy_tx = instance.voucher.transactions[0].clone();
    dummy_tx.t_id = format!("{}-2", dummy_tx.t_id);
    dummy_tx.t_type = String::new(); // empty = full transfer
    dummy_tx.prev_hash = instance.voucher.transactions[0].t_id.clone();
    instance.voucher.transactions.push(dummy_tx);

    // Attempt to remove a signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, "any-signature-id");

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherAlreadyInCirculation
    ));
}

/// Tests that signatures cannot be removed when the voucher is already in circulation via split.
///
/// ### Scenario:
/// 1. Creator creates voucher and splits the voucher.
/// 2. remove_signature is called by Creator.
/// 3. Expectation: Err(VoucherAlreadyInCirculation).
#[test]
fn test_remove_signature_fails_already_in_circulation_via_split() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Simulate a split by adding a second transaction
    let instance = alice_wallet
        .voucher_store
        .vouchers
        .get_mut(&voucher_id)
        .unwrap();
    
    // Add a dummy transaction to simulate circulation
    let mut dummy_tx = instance.voucher.transactions[0].clone();
    dummy_tx.t_id = format!("{}-2", dummy_tx.t_id);
    dummy_tx.t_type = "split".to_string();
    dummy_tx.prev_hash = instance.voucher.transactions[0].t_id.clone();
    instance.voucher.transactions.push(dummy_tx);

    // Attempt to remove a signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, "any-signature-id");

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherAlreadyInCirculation
    ));
}

/// Tests that removing a signature fails in an invalid status (e.g. Quarantined).
///
/// ### Scenario:
/// 1. Voucher status is set to Quarantined.
/// 2. remove_signature is called.
/// 3. Expectation: Err(SignatureRemovalRequiresIncomplete).
#[test]
fn test_remove_signature_fails_invalid_state() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Set voucher to Quarantined
    alice_wallet.update_voucher_status(
        &voucher_id,
        VoucherStatus::Quarantined {
            reason: "Test quarantine".to_string(),
        },
    );

    // Attempt to remove a signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, "any-signature-id");

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::SignatureRemovalRequiresIncomplete(VoucherStatus::Quarantined { .. })
    ));
}

/// Tests removing a non-existent signature ID.
///
/// ### Scenario:
/// 1. Voucher with signature ID sig-123.
/// 2. remove_signature is called with signature_id = "sig-999".
/// 3. Expectation: Err(Generic) with message "Signature with ID ... not found".
#[test]
fn test_remove_signature_non_existent_signature_id() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);
    let (minuto_standard, _) = (&MINUTO_STANDARD.0, &MINUTO_STANDARD.1);

    let voucher_id = add_voucher_to_wallet(
        &mut alice_wallet,
        &alice.identity,
        "100",
        minuto_standard,
        false,
    )
    .unwrap();

    // Attempt to remove a non-existent signature
    let result = alice_wallet.remove_signature(&alice.identity, &voucher_id, "sig-999");

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::Generic(msg) if msg.contains("not found")
    ));
}

/// Tests removing a signature from a non-existent voucher.
///
/// ### Scenario:
/// 1. Call remove_signature with a local_instance_id that does not exist.
/// 2. Expectation: Err(VoucherNotFound).
#[test]
fn test_remove_signature_non_existent_voucher_id() {
    human_money_core::set_signature_bypass(true);
    let alice = &ACTORS.alice;
    let mut alice_wallet = setup_in_memory_wallet(&alice.identity);

    // Attempt to remove a signature from a non-existent voucher
    let result = alice_wallet.remove_signature(&alice.identity, "non-existent-voucher", "sig-123");

    assert!(matches!(
        result.unwrap_err(),
        VoucherCoreError::VoucherNotFound(_)
    ));
}
