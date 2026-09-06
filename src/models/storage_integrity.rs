//! # src/models/storage_integrity.rs
//!
//! Defines the data structures for Storage Integrity (integrity protection).
//! The Integrity Record functions as a "table of contents with checksums" for all items
//! in wallet storage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::VoucherCoreError;
use crate::models::profile::UserIdentity;
use crate::models::seal::WalletSeal;
use crate::services::crypto::{get_hash, get_pubkey_from_user_id, sign_ed25519, verify_ed25519};
use crate::services::utils::{get_current_timestamp, to_canonical_json};

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

/// Type alias for `LocalIntegrityRecord` representing storage integrity records.
pub type StorageIntegrityRecord = LocalIntegrityRecord;

impl LocalIntegrityRecord {
    /// Creates a new signed Storage Integrity Record based on the current state.
    pub fn create_record(
        identity: &UserIdentity,
        current_seal: &WalletSeal,
        item_hashes: HashMap<String, String>,
    ) -> Result<Self, VoucherCoreError> {
        let seal_hash = current_seal.compute_hash()?;

        let payload = IntegrityPayload {
            version: 1,
            seal_hash,
            item_hashes,
            timestamp: get_current_timestamp(),
        };

        let payload_canonical = to_canonical_json(&payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());
        let signature = sign_ed25519(&identity.signing_key, payload_hash.as_bytes());
        let signature_str = bs58::encode(signature.to_bytes()).into_string();

        Ok(Self {
            payload,
            signature: signature_str,
        })
    }

    /// Alias for `create_record`.
    pub fn create_integrity_record(
        identity: &UserIdentity,
        current_seal: &WalletSeal,
        item_hashes: HashMap<String, String>,
    ) -> Result<Self, VoucherCoreError> {
        Self::create_record(identity, current_seal, item_hashes)
    }

    /// Verifies an Integrity Record and creates an integrity report.
    pub fn verify(
        &self,
        current_seal: &WalletSeal,
        actual_item_hashes: HashMap<String, String>,
        expected_pubkey_user_id: &str,
    ) -> Result<IntegrityReport, VoucherCoreError> {
        // 1. Verify signature of Integrity Record
        let pubkey = get_pubkey_from_user_id(expected_pubkey_user_id)?;
        let payload_canonical = to_canonical_json(&self.payload)?;
        let payload_hash = get_hash(payload_canonical.as_bytes());

        let signature_bytes = bs58::decode(&self.signature)
            .into_vec()
            .map_err(|e| VoucherCoreError::Bs58Decode(format!("Failed to decode integrity signature: {}", e)))?;

        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
            .map_err(|e| VoucherCoreError::Ed25519(format!("Invalid integrity signature format: {}", e)))?;

        if !verify_ed25519(&pubkey, payload_hash.as_bytes(), &signature) {
            return Ok(IntegrityReport::InvalidSignature);
        }

        // 2. Epoch check (Rollback Protection)
        let current_seal_hash = current_seal.compute_hash()?;
        if self.payload.seal_hash != current_seal_hash {
            return Ok(IntegrityReport::IntegrityOutdated);
        }

        let mut missing = Vec::new();
        let mut manipulated = Vec::new();
        let mut unknown = Vec::new();

        // 3. Check items from Integrity Record
        for (name, expected_hash) in &self.payload.item_hashes {
            match actual_item_hashes.get(name) {
                Some(actual_hash) => {
                    if actual_hash != expected_hash {
                        manipulated.push(name.clone());
                    }
                }
                None => {
                    missing.push(name.clone());
                }
            }
        }

        // 4. Unknown items in storage
        for name in actual_item_hashes.keys() {
            if !self.payload.item_hashes.contains_key(name) {
                // Some files are ignored (e.g. the Integrity Record itself or hidden files)
                if name != INTEGRITY_FILE_NAME && !name.starts_with('.') {
                    unknown.push(name.clone());
                }
            }
        }

        if missing.is_empty() && manipulated.is_empty() && unknown.is_empty() {
            Ok(IntegrityReport::Valid)
        } else {
            if !missing.is_empty() {
                Ok(IntegrityReport::MissingItems(missing))
            } else if !manipulated.is_empty() {
                Ok(IntegrityReport::ManipulatedItems(manipulated))
            } else {
                Ok(IntegrityReport::UnknownItems(unknown))
            }
        }
    }

    /// Alias for `verify`.
    pub fn verify_integrity(
        &self,
        current_seal: &WalletSeal,
        actual_item_hashes: HashMap<String, String>,
        expected_pubkey_user_id: &str,
    ) -> Result<IntegrityReport, VoucherCoreError> {
        self.verify(current_seal, actual_item_hashes, expected_pubkey_user_id)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::crypto::{generate_ed25519_keypair_for_tests, create_user_id};

    fn test_identity() -> UserIdentity {
        let (public_key, signing_key) = generate_ed25519_keypair_for_tests(Some("integrity_test_seed"));
        let user_id = create_user_id(&public_key, Some("test")).unwrap();
        UserIdentity {
            signing_key,
            public_key,
            user_id,
        }
    }

    #[test]
    fn test_storage_integrity_record_lifecycle() {
        let identity = test_identity();
        let seal = WalletSeal::create_initial(
            &identity.user_id,
            &identity,
            &get_hash("state"),
            "device_a",
        ).unwrap();

        let mut item_hashes = HashMap::new();
        item_hashes.insert("file_a.json".to_string(), get_hash("content_a"));
        item_hashes.insert("file_b.json".to_string(), get_hash("content_b"));

        let record = StorageIntegrityRecord::create_record(
            &identity,
            &seal,
            item_hashes.clone(),
        ).unwrap();

        // 1. Valid check
        let report = record.verify(&seal, item_hashes.clone(), &identity.user_id).unwrap();
        assert_eq!(report, IntegrityReport::Valid);

        // 2. Missing items check
        let mut partial_hashes = item_hashes.clone();
        partial_hashes.remove("file_a.json");
        let report_missing = record.verify(&seal, partial_hashes, &identity.user_id).unwrap();
        assert_eq!(report_missing, IntegrityReport::MissingItems(vec!["file_a.json".to_string()]));

        // 3. Manipulated items check
        let mut altered_hashes = item_hashes.clone();
        altered_hashes.insert("file_a.json".to_string(), get_hash("manipulated_content"));
        let report_manipulated = record.verify(&seal, altered_hashes, &identity.user_id).unwrap();
        assert_eq!(report_manipulated, IntegrityReport::ManipulatedItems(vec!["file_a.json".to_string()]));

        // 4. Unknown items check
        let mut extra_hashes = item_hashes.clone();
        extra_hashes.insert("unknown.json".to_string(), get_hash("extra"));
        let report_unknown = record.verify(&seal, extra_hashes, &identity.user_id).unwrap();
        assert_eq!(report_unknown, IntegrityReport::UnknownItems(vec!["unknown.json".to_string()]));

        // 5. Outdated seal check
        let seal_2 = seal.update(&identity, &get_hash("state_2"), "device_a").unwrap();
        let report_outdated = record.verify(&seal_2, item_hashes, &identity.user_id).unwrap();
        assert_eq!(report_outdated, IntegrityReport::IntegrityOutdated);
    }
}
