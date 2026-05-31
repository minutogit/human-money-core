//! # src/archive/file_archive.rs
//!
//! An implementation of the `VoucherArchive` trait that stores each voucher state
//! as a separate JSON file in a structured directory hierarchy.
use super::{ArchiveError, VoucherArchive};
use crate::models::voucher::Transaction;
use crate::models::voucher::Voucher;
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use crate::services::utils::to_canonical_json;
use std::{fs, path::PathBuf};

/// A minimal placeholder that implements the `VoucherArchive` trait,
/// but does not store or find any data. Used when no real
/// archive backend is configured, so that proof generation can still
/// be performed with local data in the voucher_store.
pub struct NoOpArchive;

impl VoucherArchive for NoOpArchive {
    fn archive_voucher(
        &self,
        _voucher: &Voucher,
        _owner_id: &str,
        _standard: &VoucherStandardDefinition,
    ) -> Result<(), ArchiveError> {
        Ok(())
    }
    fn get_archived_voucher(&self, _voucher_id: &str) -> Result<Voucher, ArchiveError> {
        Err(ArchiveError::NotFound)
    }
    fn find_transaction_by_id(
        &self,
        _t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError> {
        Ok(None)
    }
    fn find_voucher_by_tx_id(&self, _t_id: &str) -> Result<Option<Voucher>, ArchiveError> {
        Ok(None)
    }
}

/// An implementation of the `VoucherArchive` trait based on the file system.
///
/// The structure is: `base_path/voucher_id/transaction_id.json`
pub struct FileVoucherArchive {
    archive_directory: PathBuf,
}

impl FileVoucherArchive {
    /// Creates a new `FileVoucherArchive` instance for a specific base directory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        FileVoucherArchive {
            archive_directory: path.into(),
        }
    }

    // TODO: Implement a cleanup function (`purge_deep_archive`)
    //       that deletes states after a retention period has expired.
}

impl VoucherArchive for FileVoucherArchive {
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        _owner_id: &str,
        _standard: &VoucherStandardDefinition,
    ) -> Result<(), ArchiveError> {
        // TODO: The archive files should be encrypted.

        // Each state is uniquely identified by the ID of the last transaction.
        let last_tx = voucher.transactions.last().ok_or_else(|| {
            ArchiveError::Generic("Cannot archive voucher with no transactions.".to_string())
        })?;

        // Create a subdirectory for each voucher to group the states.
        let voucher_dir = self.archive_directory.join(&voucher.voucher_id);
        fs::create_dir_all(&voucher_dir)?;

        let file_path = voucher_dir.join(format!("{}.json", &last_tx.t_id));
        if file_path.exists() {
            return Ok(()); // Already archived, all good.
        }

        let json_content = to_canonical_json(voucher)?;

        // Atomic write
        let temp_file_path = voucher_dir.join(format!("{}.json.tmp", &last_tx.t_id));
        fs::write(&temp_file_path, json_content)?;
        fs::rename(&temp_file_path, &file_path)?;

        Ok(())
    }

    fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, ArchiveError> {
        let file_path = self.archive_directory.join(format!("{}.json", voucher_id));

        if !file_path.exists() {
            return Err(ArchiveError::NotFound);
        }

        let file_content = fs::read(file_path)?;
        let voucher: Voucher = serde_json::from_slice(&file_content)?;
        Ok(voucher)
    }

    fn find_transaction_by_id(
        &self,
        t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError> {
        // Search all subdirectories (each `voucher_id` directory).
        for voucher_dir_entry in fs::read_dir(&self.archive_directory)? {
            let voucher_dir_path = voucher_dir_entry?.path();
            if voucher_dir_path.is_dir() {
                for entry in fs::read_dir(voucher_dir_path)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_file() && path.extension().map_or(false, |s| s == "json") {
                        if let Ok(voucher) = serde_json::from_slice::<Voucher>(&fs::read(&path)?) {
                            if let Some(tx) = voucher.transactions.iter().find(|t| t.t_id == t_id) {
                                return Ok(Some((voucher.clone(), tx.clone())));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
    fn find_voucher_by_tx_id(&self, t_id: &str) -> Result<Option<Voucher>, ArchiveError> {
        // Use the existing logic of `find_transaction_by_id`.
        if let Some((voucher, _)) = self.find_transaction_by_id(t_id)? {
            Ok(Some(voucher))
        } else {
            Ok(None)
        }
    }
}
