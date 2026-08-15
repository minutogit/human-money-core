// tests/flexible_encryption.rs
//!
//! Tests for flexible container encryption (Asymmetric, Symmetric, Cleartext).

use human_money_core::{
    models::{
        profile::UserIdentity,
        secure_container::{ContainerConfig, EncryptionType, PayloadType, SecureContainer},
    },
    services::{
        crypto_utils::{self, encrypt_symmetric_password},
        secure_container_manager,
    },
    test_utils::setup_in_memory_wallet,
};
use serde_json;

/// Tests that old containers without the `et` field are correctly parsed as Asymmetric.
/// DEACTIVATED: Following JWE refactoring this format is no longer supported.
#[test]
#[ignore]
fn test_backward_compatibility_old_containers() {
    let old_container_json = r#"{
        "i": "test123",
        "c": "TransactionBundle",
        "esk": "testkey",
        "wk": [],
        "p": "testpayload",
        "t": "testsignature"
    }"#;

    let container: SecureContainer = serde_json::from_str(old_container_json).unwrap();
    assert_eq!(container.et, EncryptionType::Asymmetric);
    assert_eq!(container.i, "test123");
}

/// Tests that plaintext containers are blocked for financial payloads.
#[test]
#[cfg(feature = "test-utils")]
fn test_plaintext_blocked_for_financial_payloads() {
    let (pk, sk) = human_money_core::services::crypto_utils::generate_ed25519_keypair_for_tests(Some("alice"));

    let _alice_wallet = setup_in_memory_wallet(&UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk.clone(),
        public_key: pk,
    });

    let alice_identity = UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk,
        public_key: pk,
    };

    let payload = b"test financial payload";
    let result = secure_container_manager::create_secure_container(
        &alice_identity,
        ContainerConfig::Cleartext,
        payload,
        PayloadType::TransactionBundle,
    );

    assert!(result.is_err());
}

/// Tests that plaintext is allowed for non-financial payloads.
#[test]
#[cfg(feature = "test-utils")]
fn test_plaintext_allowed_for_non_financial_payloads() {
    let (pk, sk) = human_money_core::services::crypto_utils::generate_ed25519_keypair_for_tests(Some("alice"));

    let _alice_wallet = setup_in_memory_wallet(&UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk.clone(),
        public_key: pk,
    });

    let alice_identity = UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk,
        public_key: pk,
    };

    let payload = b"test voucher for signing";
    let result = secure_container_manager::create_secure_container(
        &alice_identity,
        ContainerConfig::Cleartext,
        payload,
        PayloadType::VoucherForSigning,
    );

    assert!(result.is_ok());
    let container = result.unwrap();
    assert_eq!(container.et, EncryptionType::None);
    assert!(container.salt.is_none());
}

/// Tests symmetric encryption with password.
#[test]
#[cfg(feature = "test-utils")]
fn test_symmetric_encryption() {
    let (pk, sk) = human_money_core::services::crypto_utils::generate_ed25519_keypair_for_tests(Some("alice"));

    let _alice_wallet = setup_in_memory_wallet(&UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk.clone(),
        public_key: pk,
    });

    let alice_identity = UserIdentity {
        user_id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        signing_key: sk,
        public_key: pk,
    };

    let payload = b"secret payload";
    let password = "test123";

    let container = secure_container_manager::create_secure_container(
        &alice_identity,
        ContainerConfig::Password(password.to_string()),
        payload,
        PayloadType::VoucherForSigning,
    ).unwrap();

    assert_eq!(container.et, EncryptionType::Symmetric);
    assert!(container.salt.is_some());

    let decrypted = secure_container_manager::open_secure_container(
        &container,
        &alice_identity,
        Some(password),
    ).unwrap();

    assert_eq!(decrypted, payload);
}

/// Tests PBKDF2 key derivation functions.
#[test]
fn test_pbkdf2_key_derivation() {
    let payload = b"test payload";
    let password = "test123";

    let (ciphertext, salt) = encrypt_symmetric_password(payload, password).unwrap();
    let decrypted = crypto_utils::decrypt_symmetric_password(&ciphertext, password, &salt).unwrap();
    assert_eq!(decrypted, payload);

    let result = crypto_utils::decrypt_symmetric_password(&ciphertext, "wrong", &salt);
    assert!(result.is_err());
}

