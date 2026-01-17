//! # src/services/decimal_utils.rs
//!
//! Enthält zentrale Hilfsfunktionen zur konsistenten Validierung und Formatierung
//! von `Decimal`-Werten. Die hier definierten Funktionen stellen sicher, dass
//! alle Beträge im System einheitlich behandelt werden, um Rundungs- und
//! Vergleichsfehler zu vermeiden.

use crate::error::VoucherCoreError;
use crate::services::voucher_manager::VoucherManagerError;
use rust_decimal::Decimal;

/// **Prinzip: Strenge Validierung am Eingang.**
///
/// Stellt sicher, dass ein `Decimal`-Wert die vom Standard erlaubte Anzahl
/// an Nachkommastellen nicht überschreitet. Schlägt fehl, wenn die Präzision
/// der Eingabe zu hoch ist.
///
/// # Arguments
/// * `amount` - Der zu prüfende `Decimal`-Wert.
/// * `allowed_places` - Die maximal erlaubte Anzahl an Nachkommastellen.
///
/// # Returns
/// Ein `Result`, das bei Erfolg leer ist oder einen `VoucherCoreError` enthält.
pub fn validate_precision(amount: &Decimal, allowed_places: u32) -> Result<(), VoucherCoreError> {
    if amount.scale() > allowed_places {
        Err(VoucherManagerError::AmountPrecisionExceeded {
            allowed: allowed_places,
            found: amount.scale(),
        }
        .into())
    } else {
        Ok(())
    }
}

/// **Prinzip: Kanonisches Speicherformat.**
///
/// Formatiert einen `Decimal`-Wert in den kanonischen String, der in der
/// Transaktionskette gespeichert wird (z.B. 60 -> "60.0000").
///
/// # Arguments
/// * `amount` - Der zu formatierende `Decimal`-Wert.
/// * `places` - Die Anzahl der Nachkommastellen im Ausgabe-String.
///
/// # Returns
/// Einen `String` mit der kanonischen Repräsentation des Betrags.
pub fn format_for_storage(amount: &Decimal, places: u32) -> String {
    format!("{:.1$}", amount, places as usize)
}
