// tests/services/jws_profile.rs
//!
//! Roundtrip tests for JWS Profile Service (RFC 7515 Compact Serialization).

use human_money_core::models::profile::PublicProfile;
use human_money_core::services::crypto::generate_ed25519_keypair_for_tests;
use human_money_core::services::jws_profile_service::{
    export_profile_as_jws, verify_and_import_jws_profile,
};

#[test]
fn test_jws_profile_roundtrip_complete() {
    // Generate a test keypair
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("jws_test_seed"));

    // Create a did:key
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    // Create a complete test profile
    let mut profile = PublicProfile::default();
    profile.id = Some(did_key.clone());
    profile.protocol_version = Some("v1".to_string());
    profile.first_name = Some("Anna".to_string());
    profile.last_name = Some("Müller".to_string());
    profile.organization = Some("Gemeinschaftswerk".to_string());
    profile.community = Some("Berlin".to_string());
    profile.email = Some("anna@example.com".to_string());
    profile.service_offer = Some("Webentwicklung".to_string());

    // Export as JWS
    let jws_result = export_profile_as_jws(&signing_key, &profile);
    assert!(jws_result.is_ok(), "JWS export should succeed");
    let jws = jws_result.unwrap();

    // Verify JWS format (3 parts separated by dots)
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS must have exactly 3 parts");

    // Import and verification
    let import_result = verify_and_import_jws_profile(&jws);
    assert!(import_result.is_ok(), "JWS import should succeed");
    let (imported_profile, imported_did) = import_result.unwrap();

    // Compare imported profile with original
    assert_eq!(imported_profile, profile, "Imported profile should match original");
    assert_eq!(imported_did, did_key, "Imported did:key should match original");
}

#[test]
fn test_jws_profile_minimal() {
    // Test with a minimal profile (only ID and protocol_version)
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("minimal_seed"));

    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    let mut profile = PublicProfile::default();
    profile.id = Some(did_key.clone());
    profile.protocol_version = Some("v1".to_string());

    let jws = export_profile_as_jws(&signing_key, &profile).expect("Export failed");
    let (imported_profile, _) = verify_and_import_jws_profile(&jws).expect("Import failed");

    assert_eq!(imported_profile, profile);
}

#[test]
fn test_jws_profile_invalid_signature() {
    // Test: Manipulated signature should fail
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("sig_test"));

    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    let mut profile = PublicProfile::default();
    profile.id = Some(did_key);
    profile.first_name = Some("Test".to_string());

    let mut jws = export_profile_as_jws(&signing_key, &profile).expect("Export failed");

    // Manipulate the signature (replace the last character)
    let last_char = jws.pop().unwrap();
    jws.push(if last_char == 'A' { 'B' } else { 'A' });

    let result = verify_and_import_jws_profile(&jws);
    assert!(result.is_err(), "Invalid signature should fail verification");
}

#[test]
fn test_jws_profile_missing_parts() {
    // Test: Missing parts in JWS should fail
    let result = verify_and_import_jws_profile("invalid.jws");
    assert!(result.is_err());

    let result2 = verify_and_import_jws_profile("only.two.parts");
    assert!(result2.is_err());
}

#[test]
fn test_jws_profile_missing_id() {
    // Test: Profile without ID should fail
    let (_, signing_key) = generate_ed25519_keypair_for_tests(Some("no_id_test"));

    let profile = PublicProfile::default(); // No ID set

    let jws = export_profile_as_jws(&signing_key, &profile).expect("Export succeeded");

    let result = verify_and_import_jws_profile(&jws);
    assert!(result.is_err(), "Profile without ID should fail import");
}

#[test]
fn test_jws_profile_protocol_version_persistence() {
    // Test: protocol_version should be serialized correctly
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("version_test"));

    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    let mut profile = PublicProfile::default();
    profile.id = Some(did_key);
    profile.protocol_version = Some("v2".to_string()); // Different version

    let jws = export_profile_as_jws(&signing_key, &profile).expect("Export failed");
    let (imported_profile, _) = verify_and_import_jws_profile(&jws).expect("Import failed");

    assert_eq!(
        imported_profile.protocol_version,
        Some("v2".to_string()),
        "Protocol version should be preserved"
    );
}

#[test]
fn test_jws_profile_unicode_support() {
    // Test: Unicode characters (e.g. umlauts) should be handled correctly
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("unicode_test"));

    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    let mut profile = PublicProfile::default();
    profile.id = Some(did_key);
    profile.first_name = Some("François".to_string());
    profile.last_name = Some("Müller-Lüdenscheidt".to_string());

    let jws = export_profile_as_jws(&signing_key, &profile).expect("Export failed");
    let (imported_profile, _) = verify_and_import_jws_profile(&jws).expect("Import failed");

    assert_eq!(imported_profile.first_name, Some("François".to_string()));
    assert_eq!(
        imported_profile.last_name,
        Some("Müller-Lüdenscheidt".to_string())
    );
}

