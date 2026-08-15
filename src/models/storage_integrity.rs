//! # src/models/storage_integrity.rs
//!
//! Defines the data structures for Storage Integrity (integrity protection).
//! The Integrity Record functions as a "table of contents with checksums" for all items
//! in wallet storage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const INTEGRITY_FILE_NAME: &str = "storage_integrity.json";

/// The cryptographically signed record of storage integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalIntegrityRecord {
    /// The actual payload of storage integrity.
    pub payload: IntegrityPayload,
    /// Ed25519 signature over the canonical JSON serialization of the `payload`.
    /// This signature binds the storage integrity to the user's identity.
    pub signature: String,
}

/// The actual payload of storage integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityPayload {
    /// Schema version (currently 1).
    pub version: u32,
    /// Link to the current WalletSeal (Base58 hash of the seal).
    /// Ensures that storage integrity belongs to a specific state epoch.
    pub seal_hash: String,
    /// Map of storage item (name/key) to SHA3-256 hash.
    pub item_hashes: HashMap<String, String>,
    /// ISO-8601 timestamp of creation.
    pub timestamp: String,
}

/// The integrity report of the storage.
/// Used to indicate the status of storage integrity to the user (or app).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityReport {
    /// Everything is fine.
    Valid,
    /// Items that are listed in the integrity record, but missing from storage.
    MissingItems(Vec<String>),
    /// Items whose calculated hash does not match the integrity record.
    ManipulatedItems(Vec<String>),
    /// Items in storage that are NOT listed in the integrity record (unknown data).
    UnknownItems(Vec<String>),
    /// Integrity record does not match the current wallet epoch (rollback attempt).
    IntegrityOutdated,
    /// The signature of the integrity record is invalid (tampering with the record itself).
    InvalidSignature,
    /// The integrity record is completely missing (even though a seal exists).
    MissingIntegrityRecord,
}
