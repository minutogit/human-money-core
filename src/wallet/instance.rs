//! # src/wallet/instance.rs
//!
//! Definiert die zentralen Datenstrukturen für die Verwaltung von
//! Gutschein-Instanzen innerhalb des Wallets.

use crate::models::voucher::Voucher;
use serde::{Deserialize, Serialize};

/// Erfasst den genauen, für den Nutzer behebbaren Grund, warum ein Gutschein
/// als unvollständig (`Incomplete`) eingestuft wird.
/// Dies ermöglicht es der Benutzeroberfläche, eine präzise To-do-Liste anzuzeigen.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ValidationFailureReason {
    /// Die Anzahl der Bürgen-Signaturen ist zu niedrig.
    GuarantorCountLow {
        required: u32,
        max: u32,
        current: u32,
    },
    /// Die Anzahl der zusätzlichen Signaturen ist zu niedrig.
    AdditionalSignatureCountLow { required: u32, current: u32 },
    /// Eine spezifische, im Standard geforderte Signatur fehlt.
    RequiredSignatureMissing { role_description: String },
    // Zukünftig erweiterbar für andere behebbare Validierungsfehler.
}

/// Repräsentiert den übergeordneten Lebenszyklus-Zustand eines Gutscheins im Wallet.
/// Dieser Status wird nicht im Gutschein selbst gespeichert, sondern ist eine
/// Metainformation, die das Wallet verwaltet.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum VoucherStatus {
    /// Der Gutschein ist strukturell korrekt, erfüllt aber noch nicht alle
    /// Validierungsregeln des Standards (z.B. fehlende Signaturen).
    Incomplete {
        reasons: Vec<ValidationFailureReason>,
    },
    /// Der Gutschein ist vollständig valide und kann für Transaktionen verwendet werden.
    Active,
    /// Der Gutschein wurde vollständig ausgegeben oder an einen anderen Nutzer transferiert.
    /// Er wird nur noch zu historischen Zwecken aufbewahrt.
    Archived,
    /// Der Gutschein wurde aufgrund eines fatalen Validierungsfehlers oder eines
    /// verifizierten Double-Spend-Konflikts gesperrt. Er kann nicht mehr verwendet werden.
    Quarantined { reason: String },
}

/// Dient als Wrapper im Wallet, der die rohen `Voucher`-Daten mit ihrem
/// verwalteten Status und anderen wallet-internen Metadaten kombiniert.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VoucherInstance {
    /// Die vollständigen Daten des Gutscheins.
    pub voucher: Voucher,
    /// Der aktuelle Lebenszyklus-Zustand dieses Gutscheins im Wallet.
    pub status: VoucherStatus,
    /// Eine eindeutige, lokale ID für diese Instanz, die als Schlüssel im `VoucherStore` dient.
    pub local_instance_id: String,
}
