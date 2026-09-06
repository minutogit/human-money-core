//! # src/wallet/mod.rs
//!
//! Defines the `Wallet` facade, the central management structure for a
//! user profile. It encapsulates the in-memory state (`UserProfile`, `VoucherStore`)
//! and orchestrates interactions with a `Storage` backend and the
//! cryptographic operations of the `UserIdentity`.

// Declares the `instance` module as a public part of the `wallet` module.
pub mod instance;
pub mod types;
mod conflicts;
mod lifecycle;
mod queries;
mod transactions;

// in src/wallet/mod.rs
// ...
#[cfg(test)]
mod tests;
#[cfg(test)]
mod reputation_tests;

// NEW: Export all public types from the types module
pub use types::*;

pub(crate) use crate::wallet::types::format_bff_name;

use crate::models::conflict::{
    CanonicalMetadataStore, KnownFingerprints, OwnFingerprints, ProofStore,
};
use crate::models::profile::{BundleMetadataStore, UserProfile, VoucherStore};

// ALL STRUCT DEFINITIONS WERE MOVED TO src/wallet/types.rs.

/// The central management structure for a user wallet.
/// Holds the in-memory state and interacts with the storage system.
#[derive(Clone)]
pub struct Wallet {
    /// Public profile data and transaction history.
    pub profile: UserProfile,
    /// The user's voucher holdings.
    pub voucher_store: VoucherStore,
    /// History of transaction metadata.
    pub bundle_meta_store: BundleMetadataStore,
    /// Storage for all known (own and foreign) transaction fingerprints.
    pub known_fingerprints: KnownFingerprints,
    /// The critical, persistent history of own **sent** transactions.
    pub own_fingerprints: OwnFingerprints,
    /// Storage for cryptographically proven double-spend conflicts.
    pub proof_store: ProofStore,
    /// Central, canonical storage for dynamic metadata.
    /// Contains metadata for ALL fingerprints in the other stores.
    pub fingerprint_metadata: CanonicalMetadataStore,
    /// Unique ID of the local device for clone protection.
    pub local_instance_id: String,
    /// In-RAM events that have not yet been persistently flushed to disk.
    /// Saved atomically and cleared during `Wallet::save`.
    pub pending_events: Vec<crate::models::wallet_event::WalletEvent>,
    /// The generation counter read during loading.
    /// Checked against disk during save().
    pub(crate) loaded_generation: u64,
}

impl Wallet {
    // METHODS FOR lifecycle.rs WERE MOVED
    // - new_from_mnemonic
    // - load
    // - save
    // - reset_password
    // - create_new_voucher

    // METHODS FOR transaction_handler.rs WERE MOVED
    // - create_and_encrypt_transaction_bundle
    // - process_encrypted_transaction_bundle
    // - _execute_single_transfer
    // - execute_multi_transfer_and_bundle
}
