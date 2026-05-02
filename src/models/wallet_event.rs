//! # src/models/wallet_event.rs
//!
//! Definiert die Datenstrukturen für das Lightweight Event Sourcing-System des Wallets.
//! Jede relevante Zustandsänderung (Gutschein-Erstellung, Transfer, Ablauf, etc.)
//! wird als immutables `WalletEvent` erfasst, um der UI eine sofortige, chronologische
//! Historie zu liefern, ohne den kompletten VoucherStore parsen zu müssen.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Die Typisierung eines Wallet-Events.
///
/// `#[non_exhaustive]` stellt sicher, dass externe Crates bei zukünftigen
/// Erweiterungen des Enums nicht brechen. Die `Unknown`-Variante ermöglicht
/// eine fehlerresiliente Deserialisierung älterer Clients.
#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum WalletEventType {
    /// Ein neuer Gutschein wurde vom Wallet-Besitzer erstellt.
    VoucherCreated,
    /// Ein Gutschein (oder Teile davon) wurde an einen Counterparty transferiert.
    TransferSent,
    /// Ein Gutschein wurde vom Wallet empfangen (eingehender Transfer).
    TransferReceived,
    /// Ein Gutschein wurde aufgrund eines verifizierten Double-Spend-Konflikts
    /// oder eines fatalen Validierungsfehlers in Quarantäne versetzt.
    VoucherQuarantined,
    /// Ein Gutschein hat den Status von `Incomplete` auf `Active` gewechselt
    /// (z.B. durch Hinzufügen einer fehlenden Unterschrift).
    VoucherActivated,
    /// Ein Gutschein wurde vom Nutzer oder durch Systemlogik explizit ungültig gemacht.
    VoucherVoided,
    /// Die Gültigkeitsdauer (`valid_until`) eines Gutscheins ist abgelaufen.
    VoucherExpired,
    /// Fallback-Variante für eine fehlerresiliente Deserialisierung älterer Clients.
    Unknown(String),
}

/// UI-optimierte Daten ("BFF-Daten"), die direkt in der Event-Historie angezeigt
/// werden können, ohne dass die UI den Gutschein-Store parsen muss.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct EventBffData {
    /// Die formatierte Währungseinheit für die Anzeige (z.B. "TEST-Minuto").
    pub display_currency: String,
    /// Der Betrag, der mit diesem Event assoziiert ist, als String für
    /// präzise Dezimaldarstellung (z.B. "10.50").
    pub amount: String,
    /// Gibt an, ob es sich um einen Test-Gutschein handelt.
    pub is_test_voucher: bool,
    /// Die User-ID des Counterpartys (Sender oder Empfänger), sofern bekannt.
    /// Ermöglicht der UI direkte Anzeigen wie "Gesendet an Bob".
    pub counterparty_id: Option<String>,
    /// Der Anzeigename des Counterpartys, sofern verfügbar.
    pub counterparty_name: Option<String>,
}

/// Ein einzelnes, immutables Event im Wallet-Event-Log.
///
/// Jedes Event hat eine globale UUID (`event_id`), einen globalen Anker
/// (`voucher_id`) und eine lokale Instanz-ID (`local_instance_id`) für
/// direkte UI-Navigation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WalletEvent {
    /// Eine eindeutige, globale Event-ID (UUID v4).
    pub event_id: String,
    /// Die lokale Instanz-ID des betroffenen Gutscheins für UI-Navigation.
    pub local_instance_id: String,
    /// Die globale, unveränderliche ID des betroffenen Gutscheins.
    pub voucher_id: String,
    /// Der Zeitstempel der Ereignis-Erkennung (nicht unbedingt der Persistierung).
    pub timestamp: DateTime<Utc>,
    /// Der Typ des Ereignisses.
    pub event_type: WalletEventType,
    /// UI-optimierte Anzeigedaten für dieses Event.
    pub bff_data: EventBffData,
}

impl WalletEvent {
    /// Erstellt ein neues WalletEvent mit einer frisch generierten UUID.
    pub fn new(
        local_instance_id: String,
        voucher_id: String,
        event_type: WalletEventType,
        bff_data: EventBffData,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            local_instance_id,
            voucher_id,
            timestamp: Utc::now(),
            event_type,
            bff_data,
        }
    }
}
