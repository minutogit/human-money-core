//! Portable, transport-independent encrypted wallet backups.
use super::{
    seal::{SealSyncState, WalletSeal},
    storage_integrity::StorageIntegrityRecord,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Protection for an exported backup; never includes the local password.
#[derive(Clone, Copy)]
pub enum BackupProtection<'a> {
    MnemonicOnly,
    CustomBackupPassword(&'a str),
}
/// Credentials for inspection and restoration. Prefix selects the SAI account.
pub enum BackupRestoreCredentials<'a> {
    Mnemonic {
        phrase: &'a str,
        passphrase: Option<&'a str>,
        prefix: Option<&'a str>,
        language: crate::MnemonicLanguage,
    },
    BackupPassword(&'a str),
}
/// Authenticated inventory of the exported bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupManifestPayload {
    pub format_version: u32,
    pub profile_name: String,
    pub folder_name: String,
    pub seal: WalletSeal,
    pub integrity: StorageIntegrityRecord,
    pub blob_map: HashMap<String, String>,
    /// Hashes before profile key-slot transformation, used only for diff reuse.
    pub source_integrity: StorageIntegrityRecord,
}
/// Public envelope. All identifying metadata is encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBackupManifest {
    pub format: String,
    pub protection_mode: String,
    pub kdf_salt: Option<String>,
    /// Envelope key wrapped under the account identity for mnemonic recovery.
    pub mnemonic_wrapped_envelope_key: Option<String>,
    pub ciphertext: String,
}
/// Transfer statistics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupSummary {
    pub total_blobs: usize,
    pub changed_blobs: usize,
    pub deleted_blobs: usize,
    pub upload_bytes: usize,
}
/// Publish the complete blob set and manifest as one destination generation.
/// Stable names require serialized access; remove obsolete blobs after publication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupDiff {
    pub encrypted_manifest_bytes: Vec<u8>,
    pub put_blobs: HashMap<String, Vec<u8>>,
    pub delete_blobs: Vec<String>,
    pub summary: BackupSummary,
}
/// Verified metadata and comparison with the currently unlocked account.
#[derive(Debug, Clone, PartialEq)]
pub struct BackupInspectionReport {
    pub manifest: BackupManifestPayload,
    pub sync_state: Option<SealSyncState>,
}
/// Queries are prepared locally; the application transports them to Layer 2.
#[derive(Debug)]
pub struct RestoreOutcome {
    pub folder_name: String,
    pub anchor_query: crate::models::layer2_api::L2StatusQuery,
    pub voucher_queries: HashMap<String, crate::models::layer2_api::L2StatusQuery>,
}
