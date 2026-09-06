//! # src/storage/encrypted_store.rs
//!
//! Generic encrypted-payload helpers and legacy schema gates.
//!
//! Extracted from `file_storage.rs` (Streamline Phase-2). The two public
//! helpers are generic over any `Serialize`/`Deserialize` payload and perform
//! the canonical `decrypt → gate → deserialize` / `serialize → encrypt →
//! write_atomic` cycle. Schema gates (`gate_legacy_*`) preserve HMSEC-SA05-08
//! hard-reject semantics.

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
/// Preserves schema gates for fingerprint stores. This is the extracted
/// `FileStorage::load_encrypted_payload` logic, now operating as a free
/// function that borrows `storage` for path and key resolution.
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
    // Schema gates for fingerprint stores (HMSEC-SA05-08)
    let rel_str = relative_path.as_ref().to_string_lossy();
    if rel_str == crate::storage::file_storage::KNOWN_FINGERPRINTS_FILE_NAME
        || rel_str == crate::storage::file_storage::OWN_FINGERPRINTS_FILE_NAME
    {
        gate_legacy_fingerprint_schema(&plain)?;
    }
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

// ---------------------------------------------------------------------------
// Schema gates (HMSEC-SA05-08)
// ---------------------------------------------------------------------------

/// Schema gate for the voucher store (HMSEC-SA05-08, wallet-side complement).
///
/// The V2 -> V3 protocol change replaced `TrapData` fields
/// (`u`/`blinded_id`/`proof`) with the SST shards (`trap_r`/`trap_s`).
/// Deserializing a store written by a pre-V3 client silently DROPS those
/// unknown fields (`serde` ignores unknown keys) and materializes empty
/// shard placeholders — destroying identity-trap evidence and leaving
/// stranded legacy chains indistinguishable from fresh state.
///
/// This gate scans the decrypted voucher-store payload BEFORE typed
/// deserialization and hard-rejects any transaction whose `trap_data` still
/// carries legacy V2 field names.
pub(crate) fn gate_legacy_transaction_schema(store_bytes: &[u8]) -> Result<(), StorageError> {
    let value: serde_json::Value = serde_json::from_slice(store_bytes)
        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

    if contains_legacy_trap_data(&value) {
        return Err(StorageError::InvalidFormat(
            "legacy V2 trap_data schema detected in voucher store (fields \
             'u'/'blinded_id'/'proof' are not part of the current protocol). \
             Loading would irreversibly degrade this forensic trap material \
             via serde field-drop; refusing to load. Migrate explicitly instead."
                .to_string(),
        ));
    }
    Ok(())
}

/// Recursively searches for `trap_data` objects still carrying legacy V2
/// field names (`u`, `blinded_id`, `proof`).
fn contains_legacy_trap_data(value: &serde_json::Value) -> bool {
    const LEGACY_TRAP_KEYS: [&str; 3] = ["u", "blinded_id", "proof"];
    match value {
        serde_json::Value::Object(map) => {
            if let Some(trap) = map.get("trap_data").and_then(|v| v.as_object())
                && LEGACY_TRAP_KEYS.iter().any(|k| trap.contains_key(*k))
            {
                return true;
            }
            map.values().any(contains_legacy_trap_data)
        }
        serde_json::Value::Array(items) => items.iter().any(contains_legacy_trap_data),
        _ => false,
    }
}

/// Schema gate for fingerprint stores (HMSEC-SA05-08).
///
/// Hard-rejects any entry still carrying legacy V2 identity material, so the
/// data survives untouched on disk until an explicit migration upgrades it.
pub(crate) fn gate_legacy_fingerprint_schema(store_bytes: &[u8]) -> Result<(), StorageError> {
    const LEGACY_SCHEMA_MARKER: &str = "legacy V2 fingerprint schema";

    let value: serde_json::Value = serde_json::from_slice(store_bytes)
        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

    let fingerprint_maps = [
        "history",
        "active_fingerprints",
        "local_history",
        "foreign_fingerprints",
    ];
    for map_key in fingerprint_maps {
        if let Some(entries) = value.get(map_key).and_then(|m| m.as_object()) {
            for fingerprint in entries
                .values()
                .filter_map(|v| v.as_array())
                .flatten()
            {
                let has_legacy_identity_material =
                    fingerprint.get("u").is_some() || fingerprint.get("blinded_id").is_some();
                if has_legacy_identity_material {
                    return Err(StorageError::InvalidFormat(format!(
                        "{} detected (fields 'u'/'blinded_id' are not part of the \
                         current schema). Loading would irreversibly degrade this \
                         forensic trap material via serde field-drop; refusing to \
                         load. Migrate explicitly instead.",
                        LEGACY_SCHEMA_MARKER
                    )));
                }
            }
        }
    }
    Ok(())
}
