//! # src/models/seal.rs
//!
//! Definiert die Datenstrukturen für den WalletSeal-Mechanismus (Rollback Guard).
//! Schützt vor State Rollbacks, Multi-Device-Forks und alten Replay-Bundles
//! nach einer Wiederherstellung.
//!
//! ## Architektur: Wire-Format vs. Storage-Format
//!
//! Das Design trennt strikt zwischen dem **Wire-Format** (`WalletSeal` - wird
//! an den Server/Layer-2 gesendet) und dem **Storage-Format** (`LocalSealRecord` -
//! wird nur lokal auf der Festplatte gespeichert). Diese Trennung verhindert:
//! - Das versehentliche Hochladen von lokalen Metadaten (z.B. `SyncStatus`).
//! - Signatur-Endlosschleifen, da nur das reine `WalletSeal` signiert und
//!   synchronisiert wird.

use serde::{Deserialize, Serialize};

/// Die kryptographisch signierte Hülle des Siegels (Wire-Format für Uploads).
///
/// Enthält die signierten Nutzdaten (`SealPayload`) und die Ed25519-Signatur
/// über die kanonische JSON-Serialisierung des Payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletSeal {
    /// Die tatsächlichen Nutzdaten des Siegels.
    pub payload: SealPayload,
    /// Ed25519-Signatur über die kanonische JSON-Serialisierung des `payload`.
    /// Kodiert als Base58-String für konsistente Darstellung.
    pub signature: String,
}

/// Die tatsächlichen Nutzdaten des Siegels (Zähler, Hashes, Metadaten).
///
/// Diese Struktur wird kanonisch serialisiert und dann signiert, um die
/// Integrität des Wallet-Zustands kryptographisch zu verankern.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SealPayload {
    /// Schema-Version (aktuell 1). Erlaubt zukünftige Migration.
    pub version: u32,
    /// Die vollständige User-ID (inkl. SAI-Präfix), z.B. `pc:aB3@did:key:z...`
    pub user_id: String,
    /// Epoche des Siegels: 0 = Initial (neues Wallet), +1 bei jeder Recovery.
    /// Wird strikt inkrementiert und niemals zurückgesetzt.
    pub epoch: u32,
    /// ISO-8601 Zeitstempel des Starts der aktuellen Epoche.
    /// Wird für das Zonen-Modell beim Bündel-Empfang verwendet, um Pre-Epoch
    /// Replays zu erkennen.
    pub epoch_start_time: String,
    /// Monotoner Transaktionszähler innerhalb der aktuellen Epoche.
    /// Wird bei jeder ausgehenden Transaktion um 1 erhöht.
    /// Wird bei Epoch-Wechsel (Recovery) auf 0 zurückgesetzt.
    pub tx_nonce: u64,
    /// Base58-kodierter SHA3-256 Hash des vorherigen `WalletSeal`.
    /// Bildet eine kryptographische Hashkette zur Erkennung von Forks.
    /// Beim allerersten Siegel: Hash eines leeren Strings (deterministischer Genesis).
    pub prev_seal_hash: String,
    /// Base58-kodierter SHA3-256 Hash des aktuellen `OwnFingerprints`-Stores.
    /// Verankert den kritischen Wallet-Zustand im Siegel, um Rollbacks zu erkennen.
    pub state_hash: String,
    /// ISO-8601 Zeitstempel der Siegelerstellung.
    pub timestamp: String,
}

/// Der lokale Speicher-Wrapper für die Festplatte (Storage-Format).
///
/// Enthält das reine kryptographische Siegel plus lokale Metadaten, die
/// niemals an den Server gesendet werden dürfen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalSealRecord {
    /// Das reine kryptographische Siegel (Wire-Format).
    pub seal: WalletSeal,
    /// Der lokale Upload-Status bezüglich der Cloud/Layer-2.
    pub sync_status: SyncStatus,
    /// Persistente Sperre, falls ein Multi-Device-Fork erkannt wurde.
    /// Kann nur durch `recover_wallet_and_set_new_password` aufgehoben werden.
    pub is_locked_due_to_fork: bool,
}

/// Status des lokalen Siegels bezüglich der Cloud/Layer-2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    /// Siegel wurde lokal geändert (neue Transaktion, Recovery), muss noch
    /// online gesichert werden.
    PendingUpload,
    /// Das aktuelle Siegel ist nachweislich in der Cloud gesichert.
    Synced,
}

/// Das Ergebnis eines Vergleichs zwischen lokalem und entferntem Siegel.
///
/// Wird von `SealManager::compare_seals` zurückgegeben und bestimmt die
/// nächste Aktion des Sync-Workflows.
#[derive(Debug, Clone, PartialEq)]
pub enum SealSyncState {
    /// Lokal und Remote sind exakt identisch. Kein Handlungsbedarf.
    Synchronized,
    /// Lokaler `tx_nonce` ist höher und die Hash-Kette baut korrekt auf.
    /// Push empfohlen (lokales Siegel hochladen).
    LocalIsNewer,
    /// Remote `tx_nonce` ist höher und die Hash-Kette baut korrekt auf.
    /// Pull erforderlich — lokaler Zustand ist veraltet!
    RemoteIsNewer,
    /// Die Hash-Ketten stimmen nicht überein, obwohl eine Seite neuer ist.
    /// Indikator für einen Multi-Device-Konflikt oder Backup-Wiederherstellung.
    /// **Trigger für den Hard Lock!**
    ForkDetected,
}
