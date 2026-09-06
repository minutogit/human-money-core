//! # src/storage/integrity.rs
//!
//! Path-traversal guards and storage integrity hashing.
//!
//! Extracted from `file_storage.rs` (Streamline Phase-2). `validate_item_name`
//! enforces wallet-relative component checks before any `Path::join`; the hash
//! helpers operate on raw on-disk bytes via `crypto::get_hash`.

use std::collections::HashMap;
use std::fs;

use super::StorageError;
use crate::models::storage_integrity::INTEGRITY_FILE_NAME;
use crate::services::crypto;
use crate::storage::file_storage::FileStorage;

/// Validates a wallet-relative item name against path traversal before any
/// path construction (HMSEC-SA05-11). Absolute paths would REPLACE the wallet
/// base directory via `Path::join`, backslashes and ".." components would
/// ESCAPE it. Used by the read/hash side, which legitimately supports
/// wallet-relative sub-paths (e.g. "events/YYYY_MM.json.enc").
pub(crate) fn validate_item_name(name: &str) -> Result<(), StorageError> {
    let candidate = std::path::Path::new(name);
    if candidate.is_absolute()
        || name.contains('\\')
        || candidate
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(StorageError::InvalidItemName {
            name: name.to_string(),
            reason: "path contains traversal or absolute component".to_string(),
        });
    }
    Ok(())
}

/// Computes the hash of a single wallet-relative item.
///
/// Mirrors `FileStorage::get_item_hash` with identical traversal guard and
/// error mapping.
pub(crate) fn get_item_hash(storage: &FileStorage, name: &str) -> Result<String, StorageError> {
    // Boundary discipline (HMSEC-SA05-11): reject hostile names before any
    // path construction. Unlike `save_arbitrary_data` (flat files), this
    // method legitimately accepts wallet-relative sub-path names
    // ("events/YYYY_MM.json.enc"), so validation is component-based:
    // absolute paths must not REPLACE the wallet base and ".." components
    // must not ESCAPE it.
    validate_item_name(name)?;

    let path = storage.user_storage_path.join(name);
    if !path.exists() {
        return Err(StorageError::NotFound);
    }
    let bytes = fs::read(path)?;
    Ok(crypto::get_hash(&bytes))
}

/// Collects hashes of all integrity-relevant items under the wallet directory.
///
/// Mirrors `FileStorage::get_all_item_hashes`: scans the top-level directory
/// (ignoring lock/integrity/seal/session-anchor/hidden files) and the
/// `events/` subdirectory for `*.json.enc` chunks.
pub(crate) fn get_all_item_hashes(
    storage: &FileStorage,
) -> Result<HashMap<String, String>, StorageError> {
    let mut hashes = HashMap::new();

    let entries = fs::read_dir(&storage.user_storage_path).map_err(StorageError::from)?;
    // Scan main directory
    for entry in entries {
        let entry = entry.map_err(StorageError::from)?;
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        // Ignore directories
        if entry.file_type().map_err(StorageError::from)?.is_dir() {
            continue;
        }

        // Ignore the integrity file itself (avoid circular reference)
        if name_str == INTEGRITY_FILE_NAME {
            continue;
        }

        // Ignore hidden files (e.g. .lock)
        if name_str.starts_with('.') {
            continue;
        }

        // Ignore the session anchor (new and old, to avoid privacy leaks in integrity reports)
        if name_str.starts_with("generic___storage_session_anchor") {
            continue;
        }

        // Ignore seal files (these are already logically protected via the seal_hash in the IntegrityRecord)
        if name_str == crate::storage::file_storage::SEAL_FILE_NAME
            || (name_str.starts_with("seal_") && name_str.ends_with(".json"))
        {
            continue;
        }

        if let Ok(hash) = get_item_hash(storage, &name_str) {
            hashes.insert(name_str.to_string(), hash);
        }
    }

    // Scan events subdirectory
    let events_dir = storage
        .user_storage_path
        .join(crate::storage::file_storage::EVENTS_DIR_NAME);
    if events_dir.exists() && events_dir.is_dir() {
        let event_entries = fs::read_dir(&events_dir).map_err(StorageError::from)?;
        for entry in event_entries {
            let entry = entry.map_err(StorageError::from)?;
            if entry.file_type().map_err(StorageError::from)?.is_file() {
                let file_name = entry.file_name();
                let name_str = file_name.to_string_lossy();
                if name_str.ends_with(".json.enc") {
                    let relative_path = format!(
                        "{}/{}",
                        crate::storage::file_storage::EVENTS_DIR_NAME,
                        name_str
                    );
                    if let Ok(hash) = get_item_hash(storage, &relative_path) {
                        hashes.insert(relative_path, hash);
                    }
                }
            }
        }
    }

    Ok(hashes)
}
