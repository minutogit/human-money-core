//! # src/services/trust_provider.rs
//!
//! Minimal Web-of-Trust trait interfaces (CORE-001).
//!
//! The core library defines **only** narrow, object-safe trait boundaries for
//! trust evaluation. Concrete WoT logic (graph storage, scoring, Cuckoo
//! filters, BLE/NFC discovery) lives in external crates such as
//! `humoco-web-of-trust`. This keeps `human_money_core` free of heavy
//! dependencies and WASM-compatible.
//!
//! The traits are intentionally tiny: a single `check_reputation` query that
//! returns the existing [`crate::models::conflict::TrustStatus`] enum. Callers
//! may optionally supply a [`TrustProvider`] to [`crate::wallet::Wallet::check_reputation`]
//! via [`crate::wallet::Wallet::check_reputation_with_provider`]; when no
//! provider is configured, the wallet falls back to its local proof-store
//! evaluation (the current `check_reputation` semantics).

use crate::models::conflict::TrustStatus;

/// Provider for Web-of-Trust reputation checks.
///
/// Implementations may query a local trust graph, a remote service, or an
/// in-memory cache. The trait is object-safe (`Send + Sync`) so it can be
/// passed as `&dyn TrustProvider` across WASM and native targets without
/// generic monomorphization.
///
/// # Example
///
/// ```rust
/// use human_money_core::services::trust_provider::{NoopTrustProvider, TrustProvider};
/// use human_money_core::models::conflict::TrustStatus;
///
/// let provider = NoopTrustProvider;
/// assert!(matches!(provider.check_reputation("did:key:z..."), TrustStatus::Clean));
/// ```
pub trait TrustProvider: Send + Sync {
    /// Returns the trust status for `subject_id`.
    ///
    /// Implementations should be pure and panic-free; invalid identifiers
    /// should map to `TrustStatus::Clean` rather than panicking.
    fn check_reputation(&self, subject_id: &str) -> TrustStatus;

    /// Convenience: `true` if `check_reputation` returns `KnownOffender`.
    fn is_known_offender(&self, subject_id: &str) -> bool {
        matches!(self.check_reputation(subject_id), TrustStatus::KnownOffender(_))
    }

    /// Convenience: `true` if `check_reputation` returns `Clean`.
    fn is_clean(&self, subject_id: &str) -> bool {
        matches!(self.check_reputation(subject_id), TrustStatus::Clean)
    }
}

/// No-op trust provider that reports every subject as `Clean`.
///
/// Useful as a default when no WoT crate is linked, and as a baseline in
/// tests. It introduces no state, I/O, or dependencies.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopTrustProvider;

impl TrustProvider for NoopTrustProvider {
    fn check_reputation(&self, _subject_id: &str) -> TrustStatus {
        TrustStatus::Clean
    }
}

/// Delegates `TrustProvider` to a closure `F: Fn(&str) -> TrustStatus`.
///
/// This helper allows quick ad-hoc providers in tests without defining a
/// struct, while keeping the production trait object-safe.
impl<F> TrustProvider for F
where
    F: Fn(&str) -> TrustStatus + Send + Sync,
{
    fn check_reputation(&self, subject_id: &str) -> TrustStatus {
        self(subject_id)
    }
}
