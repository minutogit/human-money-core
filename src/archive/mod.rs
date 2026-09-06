//! # src/archive/mod.rs
//!
//! Defines the abstraction for a persistent archive of voucher states.
//! This allows storing every historical state of a voucher and retrieving it
//! later for comparisons (e.g. for double-spend analysis).

use crate::models::voucher::{Transaction, Voucher};
use crate::models::voucher_standard_definition::VoucherStandardDefinition;
use thiserror::Error;

pub mod file_archive;

/// A generic error type for all archive operations.
#[derive(Debug, Error)]
pub enum ArchiveError {
    #[error("Voucher state not found for the given identifier.")]
    NotFound,

    #[error("Archived data failed integrity verification: {0}")]
    IntegrityViolation(String),

    #[error("Underlying I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Data could not be (de)serialized: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("An unexpected error occurred: {0}")]
    Generic(String),
}

/// The interface for a persistent voucher archive.
/// Unlike the `Storage` trait which manages the *current* wallet state,
/// `VoucherArchive` serves to store *every state ever seen* of a voucher,
/// creating an unbroken history for forensic analysis.
pub trait VoucherArchive {
    /// Stores a copy of the given voucher state unconditionally in the archive.
    ///
    /// This method is used for forensic logging. Every relevant state
    /// of a voucher (e.g. upon receipt or after creating a new transaction)
    /// is stored here to establish a complete and verifiable history.
    ///
    /// # Arguments
    /// * `voucher` - The voucher state to archive.
    /// * `owner_id` - The ID of the user in whose context the archiving takes place.
    /// * `standard` - The associated standard definition of the voucher.
    fn archive_voucher(
        &self,
        voucher: &Voucher,
        owner_id: &str,
        standard: &VoucherStandardDefinition,
    ) -> Result<(), ArchiveError>;

    /// Retrieves an archived voucher by its ID.
    fn get_archived_voucher(&self, voucher_id: &str) -> Result<Voucher, ArchiveError>;

    /// Finds a voucher and the transaction contained within by transaction ID.
    ///
    /// This method searches the entire archive.
    fn find_transaction_by_id(
        &self,
        t_id: &str,
    ) -> Result<Option<(Voucher, Transaction)>, ArchiveError>;

    /// Finds a voucher by a contained transaction ID.
    fn find_voucher_by_tx_id(&self, t_id: &str) -> Result<Option<Voucher>, ArchiveError>;
}
