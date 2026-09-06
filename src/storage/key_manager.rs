//! # src/storage/key_manager.rs
//!
//! Key derivation and file-key unwrapping for [`FileStorage`](crate::storage::FileStorage).
//!
//! Extracted from `file_storage.rs` as part of the Streamline Phase-2
//! refactoring. All cryptographic material handling preserves 100% wire
//! compatibility with on-disk containers. The module is stateless; every
//! function is a thin, auditable wrapper around the underlying KDF or AEAD.

use super::{AuthMethod, StorageError};
use crate::services::crypto;
use crate::storage::file_storage::ProfileStorageContainer;
use ed25519_dalek::SigningKey;

#[cfg(not(any(test, feature = "test-utils")))]
use argon2::Argon2;

/// Size of the per-container KDF salt (bytes).
pub(crate) const SALT_SIZE: usize = 16;
/// Size of the derived master file key (bytes).
pub(crate) const KEY_SIZE: usize = 32;

/// Derives the authenticated store binding commitment (HMSEC-SA05-04/-07).
///
/// SHA3-256 over the secret file key concatenated with the exact serialized
/// `VoucherStorageContainer` bytes (length-prefixed via
/// `crypto::get_hash_from_slices`). Mixing in the file key makes the value a
/// keyed commitment: an attacker with disk write access (but without the
/// wallet credentials) cannot recompute it over a rolled-back store, and the
/// fixed 32-byte key length rules out concatenation ambiguity (SHA3 is not
/// susceptible to length-extension anyway).
pub(crate) fn derive_store_binding_hash(
    file_key: &[u8; KEY_SIZE],
    store_container_bytes: &[u8],
) -> String {
    crypto::get_hash_from_slices(&[file_key.as_slice(), store_container_bytes])
}

/// Decrypts the master file key (`file_key`) based on the authentication method.
///
/// Mirrors the previous private `get_file_key` in `file_storage.rs` without
/// changing error mapping or branching semantics.
pub(crate) fn get_file_key(
    auth: &AuthMethod,
    container: &ProfileStorageContainer,
) -> Result<Vec<u8>, StorageError> {
    match auth {
        AuthMethod::Password(password) => {
            let password_key = derive_key_from_password(password, &container.password_kdf_salt)?;
            crypto::decrypt_data(&password_key, &container.password_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::SessionKey(session_key) => {
            crypto::decrypt_data(session_key, &container.password_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::Mnemonic(mnemonic, passphrase, language) => {
            let (_, signing_key) = crypto::derive_ed25519_keypair(mnemonic, *passphrase, *language)
                .map_err(|e| {
                    StorageError::KeyDerivationFailed { method: "mnemonic".to_string(), reason: e.to_string() }
                })?;
            let mnemonic_key =
                derive_key_from_signing_key(&signing_key, &container.mnemonic_kdf_salt)?;
            crypto::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
        AuthMethod::RecoveryIdentity(identity) => {
            let mnemonic_key =
                derive_key_from_signing_key(&identity.signing_key, &container.mnemonic_kdf_salt)?;
            crypto::decrypt_data(&mnemonic_key, &container.mnemonic_wrapped_key_with_nonce)
                .map_err(|_| StorageError::AuthenticationFailed)
        }
    }
}

/// Helper to get Argon2 instance with appropriate parameters for the environment.
#[cfg(not(any(test, feature = "test-utils")))]
fn get_argon2() -> Argon2<'static> {
    Argon2::default()
}

/// Derives a cryptographic key from a password and salt.
///
/// In release builds this uses Argon2id (via `argon2::Argon2::default`);
/// under `test` or `test-utils` a fast SHA-256 fallback is used to keep
/// the test suite responsive. The branching and error messages are preserved
/// verbatim from the original `file_storage.rs` implementation to maintain
/// binary and behavioural compatibility.
pub(crate) fn derive_key_from_password(
    password: &str,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Ok(key)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let mut key = [0u8; KEY_SIZE];
        get_argon2()
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .map_err(|e| StorageError::KeyDerivationFailed { method: "password".to_string(), reason: e.to_string() })?;
        Ok(key)
    }
}

/// Derives a cryptographic key from the private key of the identity.
///
/// Mirrors `derive_key_from_signing_key` from `file_storage.rs` with identical
/// cfg-gating and error handling.
pub(crate) fn derive_key_from_signing_key(
    signing_key: &SigningKey,
    salt: &[u8; SALT_SIZE],
) -> Result<[u8; KEY_SIZE], StorageError> {
    #[cfg(any(test, feature = "test-utils"))]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(signing_key.to_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&result[..KEY_SIZE]);
        Ok(key)
    }
    #[cfg(not(any(test, feature = "test-utils")))]
    {
        let mut key = [0u8; KEY_SIZE];
        get_argon2()
            .hash_password_into(signing_key.to_bytes().as_ref(), salt, &mut key)
            .map_err(|e| StorageError::KeyDerivationFailed { method: "identity".to_string(), reason: e.to_string() })?;
        Ok(key)
    }
}
