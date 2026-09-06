//! # src/storage/event_store.rs
//!
//! Monthly-chunked wallet event persistence with legacy migration.
//!
//! Extracted from `file_storage.rs` (Streamline Phase-2). Events are grouped
//! by `YYYY_MM` derived from `WalletEvent.timestamp` and stored as
//! `events/YYYY_MM.json.enc`. A lazy migration converts a legacy monolithic
//! `events.json.enc` into the chunked layout on the next `append_events` call.
//! `load_events` streams chunks newest-first, honoring `offset`/`limit`.

use std::collections::{HashMap, HashSet};
use std::fs;

use super::{AuthMethod, StorageError};
use crate::models::wallet_event::WalletEvent;
use crate::services::crypto;
use crate::storage::file_storage::{
    EncryptedStorageContainer, FileStorage, EVENTS_DIR_NAME, LEGACY_EVENTS_FILE_NAME,
};

type EventsStorageContainer = EncryptedStorageContainer;

/// Helper to group events by month string ("YYYY_MM").
fn group_events_by_month<I>(events: I) -> HashMap<String, Vec<WalletEvent>>
where
    I: IntoIterator<Item = WalletEvent>,
{
    let mut groups: HashMap<String, Vec<WalletEvent>> = HashMap::new();
    for ev in events {
        let month = ev.timestamp.format("%Y_%m").to_string();
        groups.entry(month).or_default().push(ev);
    }
    groups
}

/// Merges incoming events into a month-chunk on disk, deduplicating by event_id,
/// and atomically writes the encrypted chunk.
fn merge_and_write_chunk(
    storage: &mut FileStorage,
    file_key: &[u8; 32],
    month: &str,
    events_to_add: Vec<WalletEvent>,
) -> Result<(), StorageError> {
    let events_dir = storage.user_storage_path.join(EVENTS_DIR_NAME);
    let chunk_path = events_dir.join(format!("{}.json.enc", month));
    let mut all_events: Vec<WalletEvent> = if chunk_path.exists() {
        let c_bytes = fs::read(&chunk_path)?;
        let c_container: EventsStorageContainer = serde_json::from_slice(&c_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        let c_decrypted = crypto::decrypt_data(file_key, &c_container.encrypted_store_payload)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        serde_json::from_slice(&c_decrypted)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?
    } else {
        Vec::new()
    };

    let existing_ids: HashSet<String> = all_events.iter().map(|e| e.event_id.clone()).collect();
    let new_unique = events_to_add
        .into_iter()
        .filter(|e| !existing_ids.contains(&e.event_id));
    all_events.extend(new_unique);

    let e_bytes = serde_json::to_vec(&all_events)
        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
    let e_payload = crypto::encrypt_data(file_key, &e_bytes)
        .map_err(|e| StorageError::EncryptionFailed {
            reason: e.to_string(),
        })?;
    let e_container = EventsStorageContainer {
        encrypted_store_payload: e_payload,
    };
    let e_container_bytes = serde_json::to_vec(&e_container)
        .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

    storage.write_atomic(
        format!("{}/{}.json.enc", EVENTS_DIR_NAME, month),
        &e_container_bytes,
    )
}

/// Appends `events` to the month-chunked store, performing lazy migration
/// of a legacy `events.json.enc` if present.
///
/// Preserves the exact semantics of `FileStorage::append_events` including
/// per-month grouping, deduplication by `event_id`, atomic writes via
/// `FileStorage::write_atomic`, and legacy file removal after migration.
pub(crate) fn append_events(
    storage: &mut FileStorage,
    auth: &AuthMethod,
    events: &[WalletEvent],
) -> Result<(), StorageError> {
    if events.is_empty() {
        return Ok(());
    }

    let file_key = storage.get_master_key_from_auth(auth)?;
    let events_dir = storage.user_storage_path.join(EVENTS_DIR_NAME);
    fs::create_dir_all(&events_dir)?;

    // 1. Lazy Migration
    let legacy_path = storage.user_storage_path.join(LEGACY_EVENTS_FILE_NAME);
    if legacy_path.exists() {
        let container_bytes = fs::read(&legacy_path)?;
        let container: EventsStorageContainer = serde_json::from_slice(&container_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        let decrypted = crypto::decrypt_data(&file_key, &container.encrypted_store_payload)
            .map_err(|e| {
                StorageError::InvalidFormat(format!("Failed to decrypt legacy events: {}", e))
            })?;
        let legacy_events: Vec<WalletEvent> = serde_json::from_slice(&decrypted)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        for (month, m_events) in group_events_by_month(legacy_events) {
            merge_and_write_chunk(storage, &file_key, &month, m_events)?;
        }

        // Completion of migration
        fs::remove_file(&legacy_path)?;
    }

    // 2. Group and append new events
    for (month, m_events) in group_events_by_month(events.iter().cloned()) {
        merge_and_write_chunk(storage, &file_key, &month, m_events)?;
    }

    Ok(())
}

/// Loads wallet events newest-first with pagination (`offset`/`limit`).
///
/// Preserves the exact `FileStorage::load_events` semantics: descending chunk
/// order, per-chunk reversal (on-disk ascending → newest-first), offset/limit
/// accounting across chunks, and legacy fallback when migration has not run.
pub(crate) fn load_events(
    storage: &FileStorage,
    auth: &AuthMethod,
    offset: usize,
    limit: usize,
) -> Result<Vec<WalletEvent>, StorageError> {
    let file_key = storage.get_master_key_from_auth(auth)?;
    let mut result = Vec::new();
    let mut current_offset = offset;
    let mut remaining_limit = limit;

    // 1. List all chunks
    let events_dir = storage.user_storage_path.join(EVENTS_DIR_NAME);
    let mut chunks = Vec::new();
    if events_dir.exists() && events_dir.is_dir() {
        let entries = fs::read_dir(&events_dir).map_err(StorageError::from)?;
        for entry in entries {
            let entry = entry.map_err(StorageError::from)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json.enc") && !name.ends_with(".tmp") {
                chunks.push(name);
            }
        }
    }

    // Sort descending (newest first)
    chunks.sort_by(|a, b| b.cmp(a));

    // 2. Load chunks sequentially
    for chunk_name in chunks {
        if remaining_limit == 0 {
            break;
        }

        let chunk_path = events_dir.join(chunk_name);
        let c_bytes = fs::read(&chunk_path)?;
        let c_container: EventsStorageContainer = serde_json::from_slice(&c_bytes)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        let c_decrypted = crypto::decrypt_data(&file_key, &c_container.encrypted_store_payload)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
        let mut m_events: Vec<WalletEvent> = serde_json::from_slice(&c_decrypted)
            .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

        // Inside a chunk, events are sorted in ascending order.
        // Since we want the NEWEST first, we must reverse them or read from the back.
        m_events.reverse();

        let len = m_events.len();
        if current_offset >= len {
            current_offset -= len;
            continue;
        }

        let to_take = std::cmp::min(remaining_limit, len - current_offset);
        let page: Vec<_> = m_events.into_iter().skip(current_offset).take(to_take).collect();

        result.extend(page);
        remaining_limit -= to_take;
        current_offset = 0;
    }

    // 3. Legacy support (if migration has not run yet)
    if remaining_limit > 0 {
        let legacy_path = storage.user_storage_path.join(LEGACY_EVENTS_FILE_NAME);
        if legacy_path.exists() {
            let l_bytes = fs::read(&legacy_path)?;
            let l_container: EventsStorageContainer = serde_json::from_slice(&l_bytes)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let l_decrypted = crypto::decrypt_data(&file_key, &l_container.encrypted_store_payload)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;
            let mut l_events: Vec<WalletEvent> = serde_json::from_slice(&l_decrypted)
                .map_err(|e| StorageError::InvalidFormat(e.to_string()))?;

            l_events.reverse();

            let len = l_events.len();
            if current_offset < len {
                let to_take = std::cmp::min(remaining_limit, len - current_offset);
                let page: Vec<_> = l_events.into_iter().skip(current_offset).take(to_take).collect();
                result.extend(page);
            }
        }
    }

    Ok(result)
}
