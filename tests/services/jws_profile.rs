// tests/services/jws_profile.rs
//!
//! Roundtrip-Tests für JWS Profile Service (RFC 7515 Compact Serialization).

use human_money_core::models::profile::PublicProfile;
use human_money_core::services::crypto_utils::generate_ed25519_keypair_for_tests;
use human_money_core::services::jws_profile_service::{
    export_profile_as_jws, verify_and_import_jws_profile,
};

#[test]
fn test_jws_profile_roundtrip_complete() {
    // Erzeuge ein Test-Schlüsselpaar
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("jws_test_seed"));

    // Erstelle eine did:key
    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    // Erstelle ein vollständiges Test-Profil
    let mut profile = PublicProfile::default();
    profile.id = Some(did_key.clone());
    profile.protocol_version = Some("v1".to_string());
    profile.first_name = Some("Anna".to_string());
    profile.last_name = Some("Müller".to_string());
    profile.organization = Some("Gemeinschaftswerk".to_string());
    profile.community = Some("Berlin".to_string());
    profile.email = Some("anna@example.com".to_string());
    profile.service_offer = Some("Webentwicklung".to_string());

    // Export als JWS
    let jws_result = export_profile_as_jws(&signing_key, &profile);
    assert!(jws_result.is_ok(), "JWS export should succeed");
    let jws = jws_result.unwrap();

    // Verifiziere das JWS-Format (3 Teile durch Punkte getrennt)
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "JWS must have exactly 3 parts");

    // Import und Verifizierung
    let import_result = verify_and_import_jws_profile(&jws);
    assert!(import_result.is_ok(), "JWS import should succeed");
    let (imported_profile, imported_did) = import_result.unwrap();

    // Vergleiche das importierte Profil mit dem Original
    assert_eq!(imported_profile, profile, "Imported profile should match original");
    assert_eq!(imported_did, did_key, "Imported did:key should match original");
}

#[test]
fn test_jws_profile_minimal() {
    // Test mit einem minimalen Profil (nur ID und protocol_version)
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
    // Test: Manipulierte Signatur sollte fehlschlagen
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

    // Manipuliere die Signatur (ersetze das letzte Zeichen)
    let last_char = jws.pop().unwrap();
    jws.push(if last_char == 'A' { 'B' } else { 'A' });

    let result = verify_and_import_jws_profile(&jws);
    assert!(result.is_err(), "Invalid signature should fail verification");
}

#[test]
fn test_jws_profile_missing_parts() {
    // Test: Fehlende Teile im JWS sollten fehlschlagen
    let result = verify_and_import_jws_profile("invalid.jws");
    assert!(result.is_err());

    let result2 = verify_and_import_jws_profile("only.two.parts");
    assert!(result2.is_err());
}

#[test]
fn test_jws_profile_missing_id() {
    // Test: Profil ohne ID sollte fehlschlagen
    let (_, signing_key) = generate_ed25519_keypair_for_tests(Some("no_id_test"));

    let profile = PublicProfile::default(); // Keine ID gesetzt

    let jws = export_profile_as_jws(&signing_key, &profile).expect("Export succeeded");

    let result = verify_and_import_jws_profile(&jws);
    assert!(result.is_err(), "Profile without ID should fail import");
}

#[test]
fn test_jws_profile_protocol_version_persistence() {
    // Test: Die protocol_version sollte korrekt serialisiert werden
    let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("version_test"));

    const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xed, 0x01];
    let mut bytes_to_encode = Vec::with_capacity(34);
    bytes_to_encode.extend_from_slice(&ED25519_MULTICODEC_PREFIX);
    bytes_to_encode.extend_from_slice(&public_key.to_bytes());
    let did_key = format!("did:key:z{}", bs58::encode(bytes_to_encode).into_string());

    let mut profile = PublicProfile::default();
    profile.id = Some(did_key);
    profile.protocol_version = Some("v2".to_string()); // Andere Version

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
    // Test: Unicode-Zeichen (z.B. Umlaute) sollten korrekt behandelt werden
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
