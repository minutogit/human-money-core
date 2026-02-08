use human_money_core::models::voucher::{TrapData, Voucher};
use human_money_core::models::voucher_standard_definition::VoucherStandardDefinition;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::services::voucher_manager::create_voucher;
use human_money_core::services::voucher_validation::validate_voucher_against_standard;
use human_money_core::test_utils::{
    ACTORS, MINUTO_STANDARD as BASE_STANDARD, create_minuto_voucher_data,
};
use human_money_core::VoucherCoreError;
use human_money_core::error::ValidationError;
use human_money_core::services::crypto_utils::get_hash;
use human_money_core::set_signature_bypass;

// --- Helper: Setup Standard and Valid Base Voucher ---

fn setup_standard(mode: &str) -> (VoucherStandardDefinition, String) {
    let (mut standard, _) = (BASE_STANDARD.0.clone(), BASE_STANDARD.1.clone());
    
    // Set privacy mode
    standard.privacy = Some(human_money_core::models::voucher_standard_definition::PrivacySettings {
        mode: mode.to_string(),
        ..Default::default()
    });

    // Re-hash standard
    let mut standard_to_hash = standard.clone();
    standard_to_hash.signature = None;
    let hash = get_hash(to_canonical_json(&standard_to_hash).unwrap());
    
    (standard, hash)
}

fn create_valid_voucher(standard: &VoucherStandardDefinition, standard_hash: &str) -> Voucher {
    let identity = &ACTORS.issuer;
    let creator = human_money_core::models::profile::PublicProfile {
        id: Some(identity.user_id.clone()),
        ..Default::default()
    };
    let voucher_data = create_minuto_voucher_data(creator);
    
    // Create the base voucher (genesis_tx is signed normally, which is fine)
    let mut voucher = create_voucher(
        voucher_data,
        standard,
        standard_hash,
        &identity.signing_key,
        "en",
    ).unwrap();

    // Add required guarantors so the base voucher is valid
    let g1 = &ACTORS.guarantor1;
    let g2 = &ACTORS.guarantor2;
    voucher.signatures.push(human_money_core::test_utils::create_guarantor_signature(&voucher, g1, "G1", "guarantor", "1"));
    voucher.signatures.push(human_money_core::test_utils::create_guarantor_signature(&voucher, g2, "G2", "guarantor", "2"));
    
    voucher
}

// 1. Test: detect_silent_signature_leak_in_stealth_mode
// Scenario: Privacy mode is "stealth". `sender_id` is None (correct). 
// However, `sender_identity_signature` is PRESENT.
// Even if it's "valid" or "invalid", its mere presence is a leak of information (signature uniqueness).
// We use bypass to fill it with "bypass_sig" to prove that we fail on the *structure*, not the verification.
#[test]
fn detect_silent_signature_leak_in_stealth_mode() {
    set_signature_bypass(true);
    let (standard, standard_hash) = setup_standard("stealth");
    let mut voucher = create_valid_voucher(&standard, &standard_hash);

    // Add a transaction that simulates Stealth Mode but LEAKS a signature
    let mut tx = human_money_core::models::voucher::Transaction {
        t_id: "tx_leak".to_string(),
        t_time: human_money_core::services::utils::get_current_timestamp(),
        t_type: "transfer".to_string(),
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        sender_id: None, // Correct for Stealth
        recipient_id: get_hash("some_anon_recipient"), // Correct for Stealth
        amount: "10".to_string(),
        ..Default::default()
    };
    
    // THE LEAK: Add a sender_identity_signature
    // With bypass enabled, "bypass_sig" satisfies the "structure is present" check for verification, 
    // but the PRIVACY CHECK should flag it as forbidden.
    tx.sender_identity_signature = Some("bypass_sig".to_string());
    
    voucher.transactions.push(tx);

    let result = validate_voucher_against_standard(&voucher, &standard);
    
    let err = result.expect_err("Stealth mode should reject transaction with sender_identity_signature");
    assert!(
        matches!(err, VoucherCoreError::Validation(ValidationError::StealthSignatureLeak { .. })),
        "Expected StealthSignatureLeak, got {:?}", err
    );
}

// 2. Test: enforce_identity_consistency_in_flexible_mode
// Scenario: Privacy mode is "flexible".
// If `sender_id` is None (anonymous), `sender_identity_signature` MUST be None.
// If `sender_id` is Some, `sender_identity_signature` MUST be Some.
// Here we test: None / Some("sig") -> Inconsistency.
#[test]
fn enforce_identity_consistency_in_flexible_mode() {
    set_signature_bypass(true);
    let (standard, standard_hash) = setup_standard("flexible");
    let mut voucher = create_valid_voucher(&standard, &standard_hash);

    let mut tx = human_money_core::models::voucher::Transaction {
        t_id: "tx_inconsistent".to_string(),
        t_time: human_money_core::services::utils::get_current_timestamp(),
        t_type: "transfer".to_string(),
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        sender_id: None, // Anonymous choice
        recipient_id: get_hash("some_anon_recipient"),
        amount: "10".to_string(),
        ..Default::default()
    };
    
    // THE INCONSISTENCY: Signature present but no ID
    tx.sender_identity_signature = Some("bypass_sig".to_string());
    
    voucher.transactions.push(tx);

    let result = validate_voucher_against_standard(&voucher, &standard);

    let err = result.expect_err("Flexible mode should reject orphan signature without sender_id");
    assert!(
        matches!(err, VoucherCoreError::Validation(ValidationError::FlexibleModeIdentityInconsistency { .. })),
        "Expected FlexibleModeIdentityInconsistency, got {:?}", err
    );
}

// 3. Test: prevent_trapezoidal_identity_leak
// Scenario: Stealth mode uses TrapData (Zero-Knowledge-like Proof).
// The `blinded_id` field inside TrapData MUST be a hash/blinded value, NOT a cleartext DID.
// We use bypass to skip the cryptographic proof verification so we can inject a cleartext ID
// and verify existing privacy checks catch it.
#[test]
fn prevent_trapezoidal_identity_leak() {
    set_signature_bypass(true);
    let (standard, standard_hash) = setup_standard("stealth");
    let mut voucher = create_valid_voucher(&standard, &standard_hash);

    let mut tx = human_money_core::models::voucher::Transaction {
        t_id: "tx_trap_leak".to_string(),
        t_time: human_money_core::services::utils::get_current_timestamp(),
        t_type: "transfer".to_string(),
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        sender_id: None, 
        recipient_id: get_hash("some_anon_recipient"),
        amount: "60".to_string(), // Match full amount of previous tx to pass continuity check
        ..Default::default()
    };
    
    // THE ATTACK: Cleartext DID in blinded_id
    // This leaks the sender's identity even if sender_id is None.
    tx.trap_data = Some(TrapData {
        ds_tag: "some_tag".to_string(),
        u: "valid_u".to_string(),
        blinded_id: "creator:fY7@did:key:z6Mk...".to_string(), // LEAK! NOT Base58/Hex Hash like
        proof: "valid_proof".to_string(),
    });

    // Fix ID to pass integrity check so we reach the TrapData validation
    tx.t_id = "".to_string(); 
    tx.t_id = get_hash(to_canonical_json(&tx).unwrap());
    
    // Bypass requires a non-empty signature string for presence check
    tx.sender_proof_signature = "bypass_sig".to_string();

    voucher.transactions.push(tx);

    let result = validate_voucher_against_standard(&voucher, &standard);

    let err = result.expect_err("Should reject cleartext ID in blinded_id");
    
    // We expect a TrapDataInvalid error, likely due to format or specific check if implemented.
    // If specific "Leak" error exists for TrapData, match that. Otherwise, TrapDataInvalid is good.
    // The previous implementation expected TrapDataInvalid.
    assert!(
        matches!(err, VoucherCoreError::Validation(ValidationError::TrapDataInvalid { .. })),
        "Expected TrapDataInvalid, got {:?}", err
    );
}

// 4. Test: detect_whitespace_obfuscation_in_public_mode
// Scenario: Public mode. Sender ID attempts to hide/spoof by adding whitespace.
// " did:key..." vs "did:key..."
// This is a structural integrity check that should fail before or during validation.
#[test]
fn detect_whitespace_obfuscation_in_public_mode() {
    set_signature_bypass(true);
    let (standard, standard_hash) = setup_standard("public");
    let mut voucher = create_valid_voucher(&standard, &standard_hash);

    let mut tx = human_money_core::models::voucher::Transaction {
        t_id: "tx_whitespace".to_string(),
        t_time: human_money_core::services::utils::get_current_timestamp(),
        t_type: "transfer".to_string(),
        prev_hash: get_hash(to_canonical_json(voucher.transactions.last().unwrap()).unwrap()),
        sender_id: Some("did:key:zSender".to_string()),
        recipient_id: " did:key:zObfuscated".to_string(), // LEADING SPACE in recipient
        amount: "10".to_string(),
        ..Default::default()
    };

    // We need signatures to be present for Public mode.
    // Bypass allows us to use dummy strings.
    tx.sender_identity_signature = Some("bypass_sig".to_string());
    
    voucher.transactions.push(tx);

    let result = validate_voucher_against_standard(&voucher, &standard);

    let err = result.expect_err("Should reject ID with whitespace");
    
    match err {
        VoucherCoreError::Validation(ValidationError::InvalidTransaction(msg)) => {
            assert!(msg.contains("whitespace") || msg.contains("obfuscation") || msg.contains("format"), "Error should mention whitespace/obfuscation/format, got: {}", msg);
        }
        e => panic!("Expected InvalidTransaction error mentioning whitespace, got: {:?}", e),
    }
}
