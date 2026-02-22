//! # src/models/conflict.rs
//!
//! Definiert die Datenstrukturen für die Erkennung, den Beweis und die
//! Lösung von Double-Spending-Konflikten.

use crate::models::voucher::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

//==============================================================================
// TEIL 1: STRUKTUREN ZUR KONFLIKTERKENNUNG (aus fingerprint.rs)
//==============================================================================

/// Repräsentiert einen einzelnen, anonymisierten Fingerprint einer Transaktion.
/// Diese Struktur enthält alle notwendigen Informationen, um einen Double Spend
/// nachzuweisen und abgelaufene Fingerprints zu verwalten.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TransactionFingerprint {
    /// Der Double-Spend-Tag (DS-Tag).
    /// Dies ist der primäre Schlüssel, um potenzielle Konflikte zu gruppieren.
    /// Er MUSS deterministisch und konstant für denselben Input sein.
    pub ds_tag: String,

    /// Der variierende Challenge-Punkt (U) der mathematischen Falle.
    /// Er hängt von der Transaktions-ID ab und ermöglicht (zusammen mit v)
    /// die Berechnung der Identität bei einem Double Spend.
    pub u: String,

    /// Die maskierte Identität (V = m*U + ID).
    pub blinded_id: String,

    /// Die eindeutige ID der Transaktion (`t_id`). Ein abweichender Wert hier bei
    /// identischem `ds_tag` signalisiert einen Double Spend.
    pub t_id: String,

    /// Der verschlüsselte Zeitstempel der Transaktion in Nanosekunden.
    /// `encrypted_nanos = original_nanos ^ hash(prev_hash + t_id)`
    pub encrypted_timestamp: u128,

    /// Die technische Signatur (Layer 2) des Senders. Dient als kryptographischer Beweis, 
    /// um den Betrugsversuch dem Verursacher (Inhaber des ephemeralen Schlüssels) 
    /// zweifelsfrei zuordnen zu können.
    pub layer2_signature: String,

    /// Das Datum, ab dem der Fingerprint sicher aus dem Speicher entfernt werden kann 
    /// (entspricht `deletable_at` der 'init' Transaktion).
    pub deletable_at: String,
}

/// Dient als Speichercontainer für alle bekannten Transaktions-Fingerprints, die
/// nicht kritisch für die Verhinderung eines eigenen Double-Spends sind.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct KnownFingerprints {
    /// **Historie (persistent):** Eine vollständige Historie aller Fingerprints von
    /// Transaktionen, die jemals auf Gutscheinen im Besitz des Nutzers stattfanden.
    /// Dies ist die umfassende Datenbasis zur Erkennung von Betrugsversuchen im Netzwerk.
    #[serde(default)]
    pub local_history: HashMap<String, Vec<TransactionFingerprint>>,

    /// **Fremddaten (flüchtig):** Eine Sammlung von Fingerprints, die von anderen
    /// Teilnehmern im Netzwerk empfangen wurden. Dient als "Sperrliste" und
    /// zur Erkennung von Double Spends, an denen man nicht direkt beteiligt war.
    #[serde(default)]
    pub foreign_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Dient als kritischer, persistenter Speicher für alle Fingerprints von Transaktionen,
/// bei denen der Wallet-Besitzer der **Sender** war. Diese kleine, separate Datei ist
/// essenziell, um versehentliches Double-Spending sicher zu verhindern.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct OwnFingerprints {
    /// **Aktiv (flüchtig):** Fingerprints von ausgebbareren Transaktionen. Dient der
    /// schnellen In-Memory-Prüfung vor dem Erstellen einer neuen Transaktion.
    #[serde(default)]
    pub active_fingerprints: HashMap<String, Vec<TransactionFingerprint>>,
    /// **Historie (persistent):** Eine vollständige und unveränderliche Historie
    /// aller Fingerprints von Transaktionen, bei denen der Nutzer der Sender war.
    /// Dies ist die kritische Komponente für Backups und zur Konfliktverifizierung.
    #[serde(default)]
    pub history: HashMap<String, Vec<TransactionFingerprint>>,
}

//==============================================================================
// TEIL 2: KANONISCHE METADATEN-SCHICHT (NEU)
//==============================================================================

/// Speichert die dynamischen, veränderlichen Metadaten für einen einzelnen
/// `TransactionFingerprint`. Diese Struktur wird von der kryptographischen
/// Fingerprint-Struktur entkoppelt, um Redundanz zu vermeiden.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct FingerprintMetadata {
    /// Die Verbreitungstiefe des Fingerprints im Netzwerk (Anzahl der Hops).
    /// Ein niedrigerer Wert bedeutet eine aktuellere, relevantere Information.
    pub depth: u8,

    /// Ein Set von Hash-Suffixen der Peer-IDs, die diesen Fingerprint bereits
    /// kennen. Dient als effizienter Redundanzfilter beim Senden von Bundles.
    #[serde(default)]
    pub known_by_peers: HashSet<[u8; 4]>,
}

/// Der zentrale, kanonische Speicher für alle dynamischen Fingerprint-Metadaten.
/// Der Schlüssel ist die eindeutige ID des `TransactionFingerprint`
/// (`ds_tag`), um eine 1:1-Beziehung sicherzustellen.
pub type CanonicalMetadataStore = HashMap<String, FingerprintMetadata>;

//==============================================================================
// TEIL 3: STRUKTUREN ZUM BEWEIS UND ZUR LÖSUNG VON KONFLIKTEN
//==============================================================================

/// Repräsentiert einen kryptographisch verifizierbaren Beweis für einen
/// Double-Spend-Versuch. Dieses Objekt ist portabel und dient als Grundlage
/// für soziale oder technische (Layer 2) Konfliktlösungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpend {
    /// Die eindeutige, deterministische ID dieses Konflikts.
    /// Sie wird aus dem Hash der Kerndaten des Konflikts gebildet:
    /// `proof_id = hash(offender_id + fork_point_prev_hash)`.
    /// Dadurch erzeugt jeder, der denselben Konflikt entdeckt, dieselbe ID.
    pub proof_id: String,

    /// Die ID des Senders (Verursacher), der den Double Spend durchgeführt hat.
    pub offender_id: String,

    /// Der `prev_hash`, von dem die betrügerischen Transaktionen abzweigen.
    pub fork_point_prev_hash: String,

    /// Die vollständigen, widersprüchlichen Transaktionen, die den Betrug beweisen.
    pub conflicting_transactions: Vec<Transaction>,

    /// Das Datum, ab dem dieser Beweis gelöscht werden kann.
    pub deletable_at: String,

    // Metadaten zum spezifischen Report dieses Beweises
    pub reporter_id: String,
    pub report_timestamp: String,

    /// Die Signatur des Erstellers (Reporters) über der `proof_id`, um die
    /// Authentizität dieses Reports zu bestätigen.
    pub reporter_signature: String,

    /// Eine Liste von Bestätigungen, die belegen, dass der Konflikt
    /// mit den Opfern beigelegt wurde. Kann `None` sein, wenn ungelöst.
    pub resolutions: Option<Vec<ResolutionEndorsement>>,

    /// Das optionale, signierte Urteil eines Layer-2-Dienstes.
    /// Wenn `Some`, überschreibt dieses Urteil die lokale "maximale Vorsicht"-Regel.
    #[serde(default)]
    pub layer2_verdict: Option<Layer2Verdict>,
}

/// Bestätigung durch ein Opfer, dass ein durch eine `proof_id` identifizierter
/// Konflikt beigelegt wurde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionEndorsement {
    /// Die eindeutige ID dieser Bestätigung.
    /// Wird erzeugt durch Hashing der eigenen Metadaten (alles außer id/signatur),
    /// inklusive der `proof_id`, um eine kryptographische Kette zu bilden.
    pub endorsement_id: String,

    /// Die ID des Beweises, auf den sich diese Lösung bezieht. Stellt die
    /// kryptographische Verbindung zum Konflikt her.
    pub proof_id: String,

    /// Die ID des Opfers, das die Lösung bestätigt. Muss mit einem der
    /// `recipient_id`s aus den `conflicting_transactions` übereinstimmen.
    pub victim_id: String,

    /// Zeitstempel der Bestätigung.
    pub resolution_timestamp: String,

    /// Optionale Notiz, z.B. "Schaden wurde vollständig beglichen".
    pub notes: Option<String>,

    /// Die Signatur des Opfers über der `endorsement_id`. Bestätigt, dass
    /// das Opfer der Beilegung des durch `proof_id` bezeichneten Konflikts zustimmt.
    pub victim_signature: String,
}

//==============================================================================
// TEIL 4: SPEICHER-CONTAINER FÜR KONFLIKTBEWEISE
//==============================================================================

/// Dient als Speichercontainer für alle kryptographisch bewiesenen Double-Spend-Konflikte.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ProofStore {
    /// Eine Sammlung aller `ProofOfDoubleSpend`-Objekte.
    /// Der Key ist die deterministische `proof_id` des jeweiligen Konflikts.
    #[serde(default)]
    pub proofs: HashMap<String, ProofOfDoubleSpend>,
}

/// Repräsentiert das fälschungssichere Urteil eines Layer-2-Servers über einen Konflikt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer2Verdict {
    /// Die ID des Servers oder Gremiums, das das Urteil gefällt hat.
    pub server_id: String,
    /// Der Zeitstempel des Urteils.
    pub verdict_timestamp: String,
    /// Die `t_id` der Transaktion, die vom Server als "gültig" (weil zuerst gesehen) eingestuft wurde.
    pub valid_transaction_id: String,
    /// Die Signatur des Servers über dem Hash dieses Verdict-Objekts, um es fälschungssicher zu machen.
    pub server_signature: String,
}
