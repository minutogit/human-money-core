//! # src/app_service/orchestrator.rs
//!
//! Transactional orchestration for `AppService` state mutations.
//!
//! Extracts the 7-stage transaction lifecycle that was previously inlined
//! in `AppService::with_transactional_mut`. The orchestrator is stateless
//! and delegates seal-related operations to `crate::storage::seal_service::SealService`.

use super::{AppService, AppState, TransactionOutcome};
use crate::storage::WalletLockGuard;
use crate::storage::seal_service::SealService;
use crate::wallet::Wallet;

/// Policy controlling when a Reload-Before-Write is performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReloadPolicy {
    /// Only reload if the on-disk generation differs from `Wallet.loaded_generation`.
    #[default]
    IfGenerationMismatch,
    /// Always reload from disk (unconditional), even if generations match.
    /// Required for L2 verdicts where the generation marker alone is forgeable.
    Always,
    /// Unconditionally reload from disk for rollback reconciliation, bypassing the seal gate
    /// check since the seal was out-of-sync or from a restored backup that is now being reconciled.
    ReconcileReload,
}

pub(crate) struct TxPreamble<'a> {
    pub storage: crate::storage::FileStorage,
    pub wallet: Wallet,
    pub identity: crate::models::profile::UserIdentity,
    pub auth: crate::storage::AuthMethod<'a>,
    pub _guard: WalletLockGuard,
    pub session_cache: Option<super::SessionCache>,
}

/// Hook that merges live-session state into a freshly reloaded wallet.
///
/// When a Reload-Before-Write occurs, certain in-memory properties that are
/// intentionally kept only in RAM (and not yet persisted) must survive the
/// reload. This hook preserves:
/// - `ram_wallet.profile.l2_server_pubkey` (owner-controlled session trust anchor)
/// - `ram_wallet.pending_events` (unsaved UI events) – prepended before the
///   fresh wallet's own sweeps.
pub struct StateMergeHook;

impl StateMergeHook {
    /// Merges live-session properties from `ram_wallet` into `fresh_wallet`.
    pub fn apply(ram_wallet: &Wallet, fresh_wallet: &mut Wallet) {
        // Preserve the LIVE-SESSION L2 trust anchor across the mandatory
        // reload: `l2_server_pubkey` may have been configured on the
        // in-memory profile by the host application without an intermediate
        // persist. It is owner-controlled session configuration, NOT part of
        // the rolled-back disk content under attack; every persisted-
        // content integrity gate stays fully enforced on the fresh state.
        if fresh_wallet.profile.l2_server_pubkey.is_none() && ram_wallet.profile.l2_server_pubkey.is_some() {
            fresh_wallet.profile.l2_server_pubkey = ram_wallet.profile.l2_server_pubkey;
        }

        // Carry unsaved UI events from the live session into the adopted
        // state so a reload cannot silently drop pending history; events
        // emitted by the load's own sweeps are appended after them.
        if !ram_wallet.pending_events.is_empty() {
            let mut merged = ram_wallet.pending_events.clone();
            merged.extend(fresh_wallet.pending_events.iter().cloned());
            // fresh_wallet.pending_events currently contains events from Wallet::load sweeps.
            // We want ram events first, then fresh events.
            fresh_wallet.pending_events = merged;
        }
    }
}

/// Stateless orchestrator for the 7-stage transactional lifecycle.
///
/// The orchestrator enforces the following invariants 1:1 as the original
/// `with_transactional_mut` implementation:
///
/// 1. Fork-Lock Check
/// 2. WalletLockGuard RAII (via `AppState::Locked` swap)
/// 3. Generation-CAS Reload-Before-Write with `SealService::verify_state_matches_seal`
/// 4. 3-Wege `TransactionOutcome`: Commit, CommitAndReturnError (Proof-Persistenz), Rollback
/// 5. Authenticated undo recovery covering closure writes, wallet files and seal/integrity.
pub struct TransactionOrchestrator;

impl TransactionOrchestrator {
    fn prepare<'a>(
        service: &mut AppService,
        password: Option<&'a str>,
        policy: ReloadPolicy,
    ) -> Result<TxPreamble<'a>, crate::Error> {
        // 2. State Isolation (Unpacking)
        let old_state = std::mem::replace(&mut service.state, AppState::Locked);

        match old_state {
            AppState::Unlocked {
                storage,
                wallet,
                identity,
                session_cache,
            } => {
                // 3. Physical File Locking (RAII)
                let _guard = match WalletLockGuard::new(&storage) {
                    Ok(g) => g,
                    Err(e) => {
                        service.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(crate::Error::from(e));
                    }
                };

                // 4. Authentication
                let auth = match AppService::resolve_auth_method(password, &session_cache) {
                    Ok(a) => a,
                    Err(e) => {
                        service.state = AppState::Unlocked {
                            storage,
                            wallet,
                            identity,
                            session_cache,
                        };
                        return Err(e);
                    }
                };

                // Recovery precedes every disk gate while the OS lock is held.
                let recovered = storage.recover_wallet_transaction(&auth)?;
                if let Some(record) = storage.load_seal(&auth)?
                    && record.is_locked_due_to_fork
                {
                    return Err(crate::Error::WalletLockedDueToFork);
                }

                // Reload-Before-Write with policy
                let mut current_wallet = wallet;
                let should_reload = recovered
                    || match policy {
                        ReloadPolicy::IfGenerationMismatch => match storage.read_generation() {
                            Ok(disk_gen) => disk_gen != current_wallet.loaded_generation,
                            Err(e) => {
                                service.state = AppState::Unlocked {
                                    storage,
                                    wallet: current_wallet,
                                    identity,
                                    session_cache,
                                };
                                return Err(crate::Error::from(e));
                            }
                        },
                        ReloadPolicy::Always | ReloadPolicy::ReconcileReload => true,
                    };

                if should_reload {
                    let local_instance_id = current_wallet.local_instance_id.clone();
                    match Wallet::load(&storage, &auth, local_instance_id) {
                        Ok((mut fresh_wallet, _)) => {
                            if policy != ReloadPolicy::ReconcileReload {
                                if let Err(gate_err) = SealService::verify_state_matches_seal(
                                    &storage,
                                    &auth,
                                    &fresh_wallet,
                                ) {
                                    service.state = AppState::Unlocked {
                                        storage,
                                        wallet: current_wallet,
                                        identity,
                                        session_cache,
                                    };
                                    return Err(gate_err);
                                }
                            }
                            StateMergeHook::apply(&current_wallet, &mut fresh_wallet);
                            current_wallet = fresh_wallet;
                        }
                        Err(e) => {
                            service.state = AppState::Unlocked {
                                storage,
                                wallet: current_wallet,
                                identity,
                                session_cache,
                            };
                            match policy {
                                ReloadPolicy::Always | ReloadPolicy::ReconcileReload => {
                                    return Err(crate::Error::App(
                                        crate::error::AppError::ReloadFailedBeforeL2Write {
                                            reason: e.to_string(),
                                        },
                                    ));
                                }
                                ReloadPolicy::IfGenerationMismatch => {
                                    return Err(crate::Error::App(
                                        crate::error::AppError::ReloadFailed {
                                            reason: e.to_string(),
                                        },
                                    ));
                                }
                            }
                        }
                    }
                }

                Ok(TxPreamble {
                    storage,
                    wallet: current_wallet,
                    identity,
                    auth,
                    _guard,
                    session_cache,
                })
            }
            AppState::Locked => Err(crate::Error::WalletLocked),
        }
    }

    /// Executes the full 7-stage transaction lifecycle with default policy
    /// (`IfGenerationMismatch`) and `FullWallet` scope.
    ///
    /// Backward-compatible entry point for existing `with_transactional_mut` call sites.
    pub(crate) fn execute<F, R>(
        service: &mut AppService,
        password: Option<&str>,
        f: F,
    ) -> Result<R, crate::Error>
    where
        F: FnOnce(
            &mut Wallet,
            &crate::models::profile::UserIdentity,
            &mut crate::storage::FileStorage,
            &crate::storage::AuthMethod,
        ) -> TransactionOutcome<R, crate::Error>,
    {
        Self::execute_with_policy(service, password, ReloadPolicy::IfGenerationMismatch, f)
    }

    /// Executes the full 7-stage transaction lifecycle with an explicit
    /// [`ReloadPolicy`] and `FullWallet` mutation scope.
    ///
    /// # The 7-Step Transaction Lifecycle (extracted from `with_transactional_mut`)
    ///
    /// 1. **Fork-Lock Verification:** `AppService::check_fork_lock`
    /// 2. **State Isolation (Unpacking):** swap `AppState` with `Locked`
    /// 3. **Physical File Locking:** `WalletLockGuard::new`
    /// 4. **Authentication & Generation Verification (Reload-Before-Write):**
    ///    `resolve_auth_method` + `storage.read_generation` + `Wallet::load` +
    ///    `SealService::verify_state_matches_seal` + [`StateMergeHook::apply`]
    /// 5. **Atomic Isolation (Cloning):** clone `Wallet`
    /// 6. **Closure Execution:** invoke `f`
    /// 7. **Outcome Evaluation:** Commit / CommitAndReturnError / Rollback
    ///    with sealed commit (`save` + `SealService::persist_seal_for_wallet_state`)
    ///    and durable authenticated undo recovery on failure or process interruption.
    pub(crate) fn execute_with_policy<F, R>(
        service: &mut AppService,
        password: Option<&str>,
        policy: ReloadPolicy,
        f: F,
    ) -> Result<R, crate::Error>
    where
        F: FnOnce(
            &mut Wallet,
            &crate::models::profile::UserIdentity,
            &mut crate::storage::FileStorage,
            &crate::storage::AuthMethod,
        ) -> TransactionOutcome<R, crate::Error>,
    {
        let TxPreamble {
            mut storage,
            wallet: current_wallet,
            identity,
            auth,
            _guard,
            session_cache,
        } = Self::prepare(service, password, policy)?;

        // The undo journal must be durable before the closure can write any files.
        let transaction = match storage.begin_wallet_transaction(&auth) {
            Ok(transaction) => transaction,
            Err(error) => {
                service.state = AppState::Unlocked {
                    storage,
                    wallet: current_wallet,
                    identity,
                    session_cache,
                };
                return Err(error.into());
            }
        };
        let mut temp_wallet = current_wallet.clone();
        let outcome = f(&mut temp_wallet, &identity, &mut storage, &auth);
        let (result, needs_commit) = match outcome {
            TransactionOutcome::Commit(value) => (Ok(value), true),
            TransactionOutcome::CommitAndReturnError(error) => (Err(error), true),
            TransactionOutcome::Rollback(error) => (Err(error), false),
        };
        if !needs_commit {
            // Failure keeps the session locked if durable restoration fails.
            transaction.abort(&storage)?;
            service.state = AppState::Unlocked {
                storage,
                wallet: current_wallet,
                identity,
                session_cache,
            };
            return result;
        }
        let persistence = (|| -> Result<(), crate::Error> {
            storage.commit_wallet_atomic(&mut temp_wallet, &identity, &auth)?;
            SealService::persist_seal_for_wallet_state(
                &mut storage,
                &identity,
                &auth,
                &temp_wallet,
            )?;
            transaction.commit(&storage)?;
            Ok(())
        })();
        match persistence {
            Ok(()) => {
                service.state = AppState::Unlocked {
                    storage,
                    wallet: temp_wallet,
                    identity,
                    session_cache,
                };
                result
            }
            Err(crate::Error::Storage(crate::error::storage::StorageError::UncertainCommit {
                reason,
                transaction_id,
                generation,
            })) => {
                // Commit marker rename succeeded: new state remains installed on disk.
                // Complete journal cleanup if possible, but adopt the installed state.
                let _ = transaction.abort(&storage);
                let (recovered_wallet, _) =
                    Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?;
                let _ = SealService::verify_state_matches_seal(&storage, &auth, &recovered_wallet);
                service.state = AppState::Unlocked {
                    storage,
                    wallet: recovered_wallet,
                    identity,
                    session_cache,
                };
                Err(crate::Error::UncertainOutcome {
                    reason,
                    transaction_id,
                    recovered_generation: generation,
                })
            }
            Err(error) => {
                transaction.abort(&storage)?;
                let (recovered_wallet, _) =
                    Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?;
                let _ = SealService::verify_state_matches_seal(&storage, &auth, &recovered_wallet);
                service.state = AppState::Unlocked {
                    storage,
                    wallet: recovered_wallet,
                    identity,
                    session_cache,
                };
                Err(error)
            }
        }
    }

    /// Executes a seal-metadata-only transaction (no wallet bump).
    ///
    /// This covers operations like `acknowledge_seal_sync` where only
    /// `storage.save_seal` is performed without `Wallet::save` or
    /// `persist_seal_for_wallet_state`. The same 7-stage discipline
    /// (fork-lock, isolation, file-lock, reload-before-write, seal-gate,
    /// merge hook) is enforced, but the commit phase only publishes the
    /// (potentially reloaded) wallet in RAM and lets the closure handle
    /// seal persistence.
    ///
    /// The closure receives `&mut FileStorage`, `&AuthMethod`, `&Wallet` (post-reload)
    /// and `&UserIdentity` and is responsible for calling `storage.save_seal`
    /// itself. No generation bump or seal hash update is performed by the
    /// orchestrator.
    pub(crate) fn execute_seal_only<F, R>(
        service: &mut AppService,
        password: Option<&str>,
        f: F,
    ) -> Result<R, crate::Error>
    where
        F: FnOnce(
            &mut crate::storage::FileStorage,
            &crate::storage::AuthMethod,
            &Wallet,
            &crate::models::profile::UserIdentity,
        ) -> Result<R, crate::Error>,
    {
        Self::execute_seal_with_policy(service, password, ReloadPolicy::IfGenerationMismatch, f)
    }

    /// Seal-metadata-only execution with explicit [`ReloadPolicy`].
    pub(crate) fn execute_seal_with_policy<F, R>(
        service: &mut AppService,
        password: Option<&str>,
        policy: ReloadPolicy,
        f: F,
    ) -> Result<R, crate::Error>
    where
        F: FnOnce(
            &mut crate::storage::FileStorage,
            &crate::storage::AuthMethod,
            &Wallet,
            &crate::models::profile::UserIdentity,
        ) -> Result<R, crate::Error>,
    {
        let TxPreamble {
            mut storage,
            wallet: mut current_wallet,
            identity,
            auth,
            _guard,
            session_cache,
        } = Self::prepare(service, password, policy)?;

        let initial_gen = storage.read_generation()?;
        let res = f(&mut storage, &auth, &current_wallet, &identity);

        match res {
            Ok(val) => {
                let new_gen = storage.advance_generation(initial_gen)?;
                storage.record_commit_marker(&auth, new_gen)?;
                current_wallet.loaded_generation = new_gen;
                service.state = AppState::Unlocked {
                    storage,
                    wallet: current_wallet,
                    identity,
                    session_cache,
                };
                Ok(val)
            }
            Err(e) => {
                service.state = AppState::Unlocked {
                    storage,
                    wallet: current_wallet,
                    identity,
                    session_cache,
                };
                Err(e)
            }
        }
    }

    /// Executes a reconciliation transaction where the closure updates both the
    /// wallet state and the cryptographic seal explicitly to match network reality.
    pub(crate) fn execute_reconciliation<F, R>(
        service: &mut AppService,
        password: Option<&str>,
        f: F,
    ) -> Result<R, crate::Error>
    where
        F: FnOnce(
            &mut Wallet,
            &crate::models::profile::UserIdentity,
            &mut crate::storage::FileStorage,
            &crate::storage::AuthMethod,
        ) -> Result<R, crate::Error>,
    {
        let TxPreamble {
            mut storage,
            wallet: current_wallet,
            identity,
            auth,
            _guard,
            session_cache,
        } = Self::prepare(service, password, ReloadPolicy::ReconcileReload)?;

        let transaction = match storage.begin_wallet_transaction(&auth) {
            Ok(value) => value,
            Err(error) => {
                service.state = AppState::Unlocked {
                    storage,
                    wallet: current_wallet,
                    identity,
                    session_cache,
                };
                return Err(error.into());
            }
        };
        let mut temp_wallet = current_wallet.clone();
        let result = f(&mut temp_wallet, &identity, &mut storage, &auth);
        match result {
            Ok(value) => {
                let commit_res = storage
                    .commit_wallet_atomic(&mut temp_wallet, &identity, &auth)
                    .and_then(|()| transaction.commit(&storage));
                match commit_res {
                    Ok(()) => {
                        service.state = AppState::Unlocked {
                            storage,
                            wallet: temp_wallet,
                            identity,
                            session_cache,
                        };
                        Ok(value)
                    }
                    Err(crate::error::storage::StorageError::UncertainCommit {
                        reason,
                        transaction_id,
                        generation,
                    }) => {
                        let _ = transaction.abort(&storage);
                        let (recovered_wallet, _) =
                            Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?;
                        service.state = AppState::Unlocked {
                            storage,
                            wallet: recovered_wallet,
                            identity,
                            session_cache,
                        };
                        Err(crate::Error::UncertainOutcome {
                            reason,
                            transaction_id,
                            recovered_generation: generation,
                        })
                    }
                    Err(error) => {
                        transaction.abort(&storage)?;
                        let (restored_wallet, _) =
                            Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?;
                        service.state = AppState::Unlocked {
                            storage,
                            wallet: restored_wallet,
                            identity,
                            session_cache,
                        };
                        Err(error.into())
                    }
                }
            }
            Err(error) => {
                transaction.abort(&storage)?;
                let (restored_wallet, _) =
                    Wallet::load(&storage, &auth, current_wallet.local_instance_id.clone())?;
                service.state = AppState::Unlocked {
                    storage,
                    wallet: restored_wallet,
                    identity,
                    session_cache,
                };
                Err(error)
            }
        }
    }
}
