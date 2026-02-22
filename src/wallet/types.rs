//! # src/wallet/types.rs
//!
//! Definiert öffentliche Datenstrukturen (Structs), die als "View-Models"
//! oder Datencontainer für die API-Interaktion des Wallets dienen.

use crate::models::conflict::TransactionFingerprint;
use crate::models::profile::TransactionBundleHeader;
use crate::models::voucher::Voucher;
use crate::wallet::instance::VoucherStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Beschreibt einen Teil-Transfer von einem spezifischen Quell-Gutschein.
/// Wird verwendet, um die Quellen (lokale ID und Betrag) für einen Multi-Transfer zu definieren.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceTransfer {
    /// Die lokale ID des Gutscheins, von dem ein Betrag abgezogen werden soll.
    pub local_instance_id: String,
    /// Der Betrag, der von diesem Gutschein abgezogen werden soll, als String.
    pub amount_to_send: String,
}

/// Die aggregierte Anforderung für den universellen Transfer-Befehl.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTransferRequest {
    /// Die User-ID des Empfängers.
    pub recipient_id: String,
    /// Eine Liste von Quell-Gutscheinen und den jeweils zu sendenden Beträgen (1 bis N).
    pub sources: Vec<SourceTransfer>,
    /// Optionale Notizen für das Bundle.
    pub notes: Option<String>,
    /// Optionaler Profilname des Senders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_profile_name: Option<String>,
}

/// Fasst die Ergebnisse eines Transfers pro Standard zusammen.
/// Key: Währungseinheit (z.B. "Minuto"), Value: Summe als String (teilbar) oder Anzahl (nicht-teilbar).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct TransferSummary {
    /// Aufsummierte Beträge für teilbare/summierbare Gutscheine (z.B. "10.50 Minuto").
    /// Key: Währungseinheit (z.B. "Minuto"), Value: Summe als String.
    #[serde(default)]
    pub summable_amounts: HashMap<String, String>,
    /// Gezählte Einheiten für nicht-teilbare/nicht-summierbare Gutscheine (z.B. "3 Brote").
    /// Key: Währungseinheit (z.B. "Brot"), Value: Anzahl.
    #[serde(default)]
    pub countable_items: HashMap<String, u32>,
}

/// Das Ergebnis der Verarbeitung eines eingehenden Transaktionsbündels.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ProcessBundleResult {
    pub header: TransactionBundleHeader,
    pub check_result: DoubleSpendCheckResult,
    /// Detaillierte Zusammenfassung der transferierten Werte (Summen und Zähler).
    #[serde(default)]
    pub transfer_summary: TransferSummary,
    /// Liste der lokalen IDs der Gutscheine, die im Wallet des Empfängers
    /// durch diesen Transfer erstellt oder aktualisiert wurden.
    #[serde(default)]
    pub involved_vouchers: Vec<String>,
    /// Detaillierte Aufschlüsselung jedes empfangenen Gutscheins.
    #[serde(default)]
    pub involved_vouchers_details: Vec<InvolvedVoucherInfo>,
}

/// Das Ergebnis einer Double-Spend-Prüfung.
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct DoubleSpendCheckResult {
    pub verifiable_conflicts: HashMap<String, Vec<TransactionFingerprint>>,
    pub unverifiable_warnings: HashMap<String, Vec<TransactionFingerprint>>,
}

/// Enthält detaillierte Informationen zu einem einzelnen Gutschein, der
/// an einer Transaktion (Senden oder Empfangen) beteiligt war.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct InvolvedVoucherInfo {
    /// Die lokale ID der Gutschein-Instanz im Wallet des Benutzers.
    pub local_instance_id: String,
    /// Die globale, unveränderliche ID des Gutscheins.
    pub voucher_id: String,
    /// Der menschenlesbare Name des Standards (z.B. "Minuto-Gutschein").
    pub standard_name: String,
    /// Die Währungseinheit (z.B. "Minuto", "Gramm").
    pub unit: String,
    /// Der Betrag, der von diesem Gutschein gesendet oder empfangen wurde.
    pub amount: String,
    /// Gibt an, ob der Gutschein teilbar ist.
    pub allow_partial_transfers: bool,
}

/// Das Ergebnis der Erstellung eines Transfer-Bündels.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct CreateBundleResult {
    /// Die serialisierten Bytes des SecureContainers, bereit zum Senden.
    pub bundle_bytes: Vec<u8>,
    /// Die eindeutige ID des erstellten Bundles.
    pub bundle_id: String,
    /// Detaillierte Aufschlüsselung jedes Quell-Gutscheins, der in der Transaktion verwendet wurde.
    #[serde(default)]
    pub involved_sources_details: Vec<InvolvedVoucherInfo>,
}

/// Ein Bericht, der die Ergebnisse der Speicherbereinigung zusammenfasst.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CleanupReport {
    pub expired_fingerprints_removed: u32,
    pub limit_based_fingerprints_removed: u32,
}

/// Repräsentiert ein aggregiertes Guthaben für einen bestimmten Gutschein-Standard und eine Währungseinheit.
/// Wird verwendet, um eine zusammenfassende Dashboard-Ansicht der Guthaben zu erstellen. use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AggregatedBalance {
    /// Der Name des Gutschein-Standards (z.B. "Minuto-Gutschein").
    pub standard_name: String,
    /// Die eindeutige UUID des Gutschein-Standards.
    pub standard_uuid: String,
    /// Die Währungseinheit des Guthabens (z.B. "Min", "€").
    pub unit: String,
    /// Der als String formatierte Gesamtbetrag.
    pub total_amount: String,
}

/// Eine zusammenfassende Ansicht eines Gutscheins für Listen-Darstellungen.
///
/// Diese Struktur wird von der Funktion `AppService::get_voucher_summaries`
/// zurückgegeben und dient dazu, eine übersichtliche Darstellung der
/// Gutschein-Daten zu liefern, ohne das gesamte, komplexe `Voucher`-Objekt
/// übertragen zu müssen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherSummary {
    /// Die eindeutige, lokale ID der Gutschein-Instanz im Wallet.
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    /// Die eindeutige ID des Erstellers (oft ein Public Key).
    pub creator_id: String,
    /// Das Gültigkeitsdatum des Gutscheins im ISO 8601-Format.
    pub valid_until: String,
    /// Eine allgemeine, menschenlesbare Beschreibung des Gutscheins.
    pub description: String,
    /// Der aktuelle, verfügbare Betrag des Gutscheins als String.
    pub current_amount: String,
    /// Die Einheit des Gutscheinwerts (z.B. "m" für Minuten).
    pub unit: String,
    /// Der Name des Standards, zu dem dieser Gutschein gehört (z.B. "Minuto-Gutschein").
    pub voucher_standard_name: String,
    /// Die eindeutige Kennung (UUID) des Standards, zu dem dieser Gutschein gehört.
    pub voucher_standard_uuid: String,
    /// Die Anzahl der Transaktionen, exklusive der initialen `init`-Transaktion.
    pub transaction_count: u32,
    /// Die Gesamtzahl der vorhandenen Signaturen (inkl. Bürgen).
    pub signatures_count: u32,
    /// Ein Flag, das anzeigt, ob der Gutschein besichert ist.
    pub has_collateral: bool,
    /// Der Vorname des ursprünglichen Erstellers.
    pub creator_first_name: String,
    /// Der Nachname des ursprünglichen Erstellers.
    pub creator_last_name: String,
    pub creator_coordinates: String,
    /// Eine Markierung, ob es sich um einen nicht einlösbaren Testgutschein handelt.
    pub non_redeemable_test_voucher: bool,
}

/// Eine zusammenfassende Ansicht eines Double-Spend-Beweises für Listen-Darstellungen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfDoubleSpendSummary {
    pub proof_id: String,
    pub offender_id: String,
    pub fork_point_prev_hash: String,
    pub report_timestamp: String,
    pub is_resolved: bool,
    pub has_l2_verdict: bool,
}

/// Eine detaillierte Ansicht eines Gutscheins inklusive seiner Transaktionshistorie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoucherDetails {
    pub local_instance_id: String,
    /// Der aktuelle Status des Gutscheins (z.B. `Active`, `Archived`).
    pub status: VoucherStatus,
    pub voucher: Voucher,
}
