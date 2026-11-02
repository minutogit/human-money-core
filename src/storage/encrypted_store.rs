//! # src/storage/encrypted_store.rs
//!
//! Generic encrypted-payload helpers.
//!
//! Extracted from `file_storage.rs` (Streamline Phase-2). The two public
//! helpers are generic over any `Serialize`/`Deserialize` payload and perform
//! the canonical `decrypt → deserialize` / `serialize → encrypt → write_atomic` cycle.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{AuthMethod, StorageError};
use crate::services::crypto;
use crate::storage::file_storage::{EncryptedStorageContainer, FileStorage};

// ---------------------------------------------------------------------------
// Generic encrypted payload helpers
// ---------------------------------------------------------------------------

/// Loads, decrypts and deserializes an encrypted payload from `relative_path`.
///
/// Returns `Ok(None)` when the file does not exist (caller maps to default).
/// This is the extracted `FileStorage::load_encrypted_payload` logic, now
/// operating as a free function that borrows `storage` for path and key resolution.
pub(crate) fn load_encrypted_payload<T>(
    storage: &FileStorage,
    relative_path: impl AsRef<Path>,
    auth: &AuthMethod,
) -> Result<Option<T>, StorageError>
where
    T: for<'de> Deserialize<'de>,
{
    let abs_path = storage.user_storage_path.join(relative_path.as_ref());
    if !abs_path.exists() {
        return Ok(None);
    }
    let file_key = storage.get_master_key_from_auth(auth)?;
    let container_bytes = fs::read(&abs_path)?;
    let container: EncryptedStorageContainer = serde_json::from_slice(&container_bytes)
        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
    let plain = crypto::decrypt_data(&file_key, &container.encrypted_store_payload).map_err(|e| {
        StorageError::InvalidFormat(format!(
            "Failed to decrypt {}: {}",
            relative_path.as_ref().display(),
            e
        ))
    })?;
    let value =
        serde_json::from_slice(&plain).map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
    Ok(Some(value))
}

/// Encrypts and atomically persists `value` to `relative_path`.
///
/// Mirrors the former `FileStorage::save_encrypted_payload` private method.
pub(crate) fn save_encrypted_payload<T>(
    storage: &mut FileStorage,
    relative_path: impl AsRef<Path>,
    auth: &AuthMethod,
    value: &T,
) -> Result<(), StorageError>
where
    T: Serialize,
{
    let file_key = storage.get_master_key_from_auth(auth)?;
    let plain =
        serde_json::to_vec(value).map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
    let encrypted =
        crypto::encrypt_data(&file_key, &plain).map_err(|e| StorageError::EncryptionFailed { reason: e.to_string() })?;
    let container = EncryptedStorageContainer {
        encrypted_store_payload: encrypted,
    };
    let data =
        serde_json::to_vec(&container).map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
    storage.write_atomic(relative_path, &data)
}
