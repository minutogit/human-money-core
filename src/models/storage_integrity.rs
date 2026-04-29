//! # src/models/storage_integrity.rs
//!
//! Definiert die Datenstrukturen für die Storage Integrity (Integritätsschutz).
//! Der Integrity Record fungiert als "Inhaltsverzeichnis mit Prüfsummen" für alle Items
//! im Wallet-Speicher.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const INTEGRITY_FILE_NAME: &str = "storage_integrity.json";

/// Der kryptographisch signierte Datensatz der Storage Integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalIntegrityRecord {
    /// Die tatsächlichen Nutzdaten der Storage Integrity.
    pub payload: IntegrityPayload,
    /// Ed25519-Signatur über die kanonische JSON-Serialisierung des `payload`.
    /// Diese Signatur bindet die Storage Integrity an die Identität des Nutzers.
    pub signature: String,
}

/// Die tatsächlichen Nutzdaten der Storage Integrity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntegrityPayload {
    /// Schema-Version (aktuell 1).
    pub version: u32,
    /// Verknüpfung mit dem aktuellen WalletSeal (Base58-Hash des Siegels).
    /// Stellt sicher, dass die Storage Integrity zu einer bestimmten State-Epoche gehört.
    pub seal_hash: String,
    /// Map von Speicher-Item (Name/Key) zu SHA3-256 Hash.
    pub item_hashes: HashMap<String, String>,
    /// ISO-8601 Zeitstempel der Erstellung.
    pub timestamp: String,
}

/// Der Integritätsbericht des Speichers.
/// Wird verwendet, um dem Nutzer (oder der App) den Status der Speicher-Integrität anzuzeigen.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrityReport {
    /// Alles in Ordnung.
    Valid,
    /// Items, die im Integrity Record stehen, aber im Speicher fehlen.
    MissingItems(Vec<String>),
    /// Items, deren berechneter Hash nicht mit dem Integrity Record übereinstimmt.
    ManipulatedItems(Vec<String>),
    /// Items im Speicher, die NICHT im Integrity Record stehen (unbekannte Daten).
    UnknownItems(Vec<String>),
    /// Integrity Record passt nicht zur aktuellen Wallet-Epoche (Rollback-Versuch).
    IntegrityOutdated,
    /// Die Signatur des Integrity Record ist ungültig (Manipulation am Record selbst).
    InvalidSignature,
    /// Der Integrity Record fehlt vollständig (obwohl ein Siegel existiert).
    MissingIntegrityRecord,
}
