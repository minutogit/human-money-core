//! # src/archive/mod.rs
//!
//! Defines the abstraction for a persistent archive of voucher states.
//! This allows storing every historical state of a voucher and retrieving it
//! later for comparisons (e.g. for double-spend analysis).

pub mod file_archive;
pub use file_archive::FileVoucherArchive;

