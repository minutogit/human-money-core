//! # src/storage/seal_service.rs
//!
//! Centralized cryptographic seal operations for wallet state integrity.
//!
//! Bundles all seal-related pure storage logic that was previously scattered
//! across `AppService` handlers. This module is stateless and storage-oriented:
//! it operates on `FileStorage`, `UserIdentity` and `Wallet` without holding
//! any `AppService` state.

use crate::models::profile::UserIdentity;
use crate::models::seal::{LocalSealRecord, SyncStatus, WalletSeal};
use crate::models::storage_integrity::StorageIntegrityRecord;
use crate::services::crypto::get_hash;
use crate::services::utils::to_canonical_json;
use crate::storage::{AuthMethod, FileStorage};
use crate::wallet::Wallet;
use crate::Error;

/// Stateless service for cryptographic wallet seals.
pub struct SealService;

impl SealService {
    /// Calculates the SHA3-256 state hash over the canonical JSON representation
    /// of `own_fingerprints`.
    ///
    /// This is the single canonical definition of the wallet state anchor that
    /// is signed inside `WalletSeal.payload.state_hash`. All call sites must
    /// use this function to avoid divergent hash computations.
    pub fn calculate_state_hash(
        own_fingerprints: &crate::models::conflict::OwnFingerprints,
    ) -> Result<String, Error> {
        let canonical = to_canonical_json(own_fingerprints)?;
        Ok(get_hash(canonical.as_bytes()))
    }

    /// Verifies that a freshly loaded wallet state is covered by the current
    /// cryptographic seal before it may be operated on.
    ///
    /// If no seal exists (legacy wallet before seal migration) the check is
    /// skipped and `Ok(())` is returned. Otherwise the current state hash
    /// (via [`Self::calculate_state_hash`]) is compared against
    /// `seal.payload.state_hash`; a mismatch is treated as a rollback attack
    /// and returns [`Error::StateRollbackDetected`].
    pub fn verify_state_matches_seal(
        storage: &FileStorage,
        auth: &AuthMethod<'_>,
        wallet: &Wallet,
    ) -> Result<(), Error> {
        let record_opt = storage.load_seal(auth)?;

        if let Some(record) = record_opt {
            let current_state_hash = Self::calculate_state_hash(&wallet.own_fingerprints)?;

            if record.seal.payload.state_hash != current_state_hash {
                return Err(Error::StateRollbackDetected);
            }
        }
        Ok(())
    }

    /// Persists the `WalletSeal` and the `StorageIntegrityRecord` for the given
    /// wallet state without touching the `AppService`'s in-memory state.
    ///
    /// 1. Loads the current seal (if any).
    /// 2. Computes the state hash via [`Self::calculate_state_hash`].
    /// 3. Either updates the existing seal (`seal.update`) or creates the
    ///    genesis seal (`WalletSeal::create_initial`).
    /// 4. Saves the new `LocalSealRecord` with `SyncStatus::PendingUpload`.
    /// 5. Recomputes all item hashes and creates/saves a new
    ///    `StorageIntegrityRecord` bound to the updated seal.
    pub fn persist_seal_for_wallet_state(
        storage: &mut FileStorage,
        identity: &UserIdentity,
        auth: &AuthMethod<'_>,
        wallet: &Wallet,
    ) -> Result<(), Error> {
        let record_opt = storage.load_seal(auth)?;

        let current_state_hash = Self::calculate_state_hash(&wallet.own_fingerprints)?;

        let updated_seal = match record_opt {
            Some(mut record) => {
                let seal = record.seal.update(
                    identity,
                    &current_state_hash,
                    &wallet.local_instance_id,
                )?;

                record.seal = seal.clone();
                record.sync_status = SyncStatus::PendingUpload;

                storage.save_seal(auth, &record)?;
                seal
            }
            None => {
                let seal = WalletSeal::create_initial(
                    &identity.user_id,
                    identity,
                    &current_state_hash,
                    &wallet.local_instance_id,
                )?;

                let new_record = LocalSealRecord {
                    seal: seal.clone(),
                    sync_status: SyncStatus::PendingUpload,
                    is_locked_due_to_fork: false,
                };
                storage.save_seal(auth, &new_record)?;
                seal
            }
        };

        // --- INTEGRITY UPDATE ---
        let item_hashes = storage.get_all_item_hashes()?;
        let integrity_record = StorageIntegrityRecord::create_record(
            identity,
            &updated_seal,
            item_hashes,
        )?;

        storage.save_integrity(&integrity_record)?;

        Ok(())
    }

    /// Compensates a half-committed transaction whose seal update failed
    /// AFTER the wallet data files were durably persisted.
    ///
    /// Re-persists the PRE-transaction wallet state (with the generation
    /// counter aligned to the value the aborted commit wrote) so that the
    /// on-disk data matches the untouched seal again. `save_seal` writes via
    /// tmp+rename, therefore a failed seal update always leaves the previous,
    /// fully intact seal behind - restoring the matching data re-establishes
    /// the invariant checked by `verify_seal_on_login` and keeps the wallet
    /// loginable.
    ///
    /// Best effort: if the compensating write itself fails (active I/O
    /// breakdown), the divergence remains and the next login will require
    /// recovery - nothing more can be done at this point.
    pub fn compensate_failed_seal_phase(
        storage: &mut FileStorage,
        pre_tx_wallet: &Wallet,
        identity: &UserIdentity,
        auth: &AuthMethod<'_>,
    ) -> Wallet {
        let mut rollback_wallet = pre_tx_wallet.clone();
        if let Ok(disk_gen) = storage.read_generation() {
            rollback_wallet.loaded_generation = disk_gen;
        }
        // Decoupled: use FileStorage atomic commit directly
        if let Err(e) = storage.commit_wallet_atomic(&mut rollback_wallet, identity, auth) {
            eprintln!(
                "Wallet seal compensation failed; manual recovery may be required: {}",
                e
            );
        }
        rollback_wallet
    }
}
