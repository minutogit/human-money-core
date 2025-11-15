//! # src/services/utils.rs
//!
//! Enthält allgemeine Hilfsfunktionen, z.B. für Zeitstempel und kanonische Serialisierung.

use chrono::{Datelike, DateTime, TimeZone, Timelike, Utc};
use serde::Serialize;
use serde_json_canonicalizer::to_string;

/// Serialisiert eine beliebige `Serialize`-bare Struktur in einen kanonischen JSON-String
/// gemäß RFC 8785 (JCS - JSON Canonicalization Scheme).
///
/// Dies stellt sicher, dass die Ausgabe deterministisch ist:
/// - Schlüssel in Objekten sind alphabetisch sortiert.
/// - Keine überflüssigen Leerzeichen.
///
/// Diese Funktion ist essenziell für die kryptographische Signatur und Verifizierung,
/// da sie garantiert, dass derselbe logische Inhalt immer denselben Hash erzeugt.
///
/// # Arguments
/// * `value` - Ein Wert, der `serde::Serialize` implementiert.
///
/// # Returns
/// Ein `Result`, das entweder den kompakten, kanonischen JSON-String oder einen `UtilsError` enthält.
pub fn to_canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    to_string(value)
}

/// Returns the current timestamp in ISO 8601 format in UTC with microsecond precision.
/// Optionally adds a number of years to the current timestamp.
/// If end_of_year is true, sets the time to the end of that year (last microsecond of the last second).
///
/// # Arguments
///
/// * `years_to_add` - Optional number of years to add to the current date. Defaults to 0.
/// * `end_of_year` - If true, return the last moment of the current or future year. Defaults to false.
///
/// # Returns
///
/// A string representing the timestamp in ISO 8601 format (YYYY-MM-DDTHH:MM:SS.ffffffZ).
pub fn get_timestamp(years_to_add: i32, end_of_year: bool) -> String {
    // Current time in UTC
    let mut future_time: DateTime<Utc> = Utc::now();

    // Add the specified number of years
    if years_to_add != 0 {
        let current_nanos = future_time.nanosecond(); // Preserve original nanoseconds
        let new_year = future_time.year() + years_to_add;

        // Try to create the date with the original day and time components
        future_time = match Utc.with_ymd_and_hms(
            new_year,
            future_time.month(),
            future_time.day(),
            future_time.hour(),
            future_time.minute(),
            future_time.second(),
        ) {
            // If successful, re-apply nanoseconds
            chrono::LocalResult::Single(dt) => dt
                .with_nanosecond(current_nanos)
                .unwrap_or(dt), // Keep original dt if setting nanosecond fails (unlikely)
            // Handle potential ambiguities or errors (like invalid dates, e.g., Feb 29)
            chrono::LocalResult::None | chrono::LocalResult::Ambiguous(_, _) => {
                // Determine the last valid day of the target month/year
                // Calculate the first day of the *next* month
                let (next_month_year, next_month) = if future_time.month() == 12 {
                    (new_year + 1, 1)
                } else {
                    (new_year, future_time.month() + 1)
                };
                // Get the day *before* the first day of the next month
                let last_day_of_month = chrono::NaiveDate::from_ymd_opt(next_month_year, next_month, 1)
                    .unwrap() // This should always succeed for valid year/month combos
                    .pred_opt() // Get the previous day (last day of original month)
                    .unwrap() // This should always succeed
                    .day();

                // Use the minimum of the original day and the last valid day of the month
                let valid_day = std::cmp::min(future_time.day(), last_day_of_month);

                // Reconstruct the date with the valid day
                match Utc.with_ymd_and_hms(
                    new_year,
                    future_time.month(),
                    valid_day, // Use the calculated valid day
                    future_time.hour(),
                    future_time.minute(),
                    future_time.second(),
                ) {
                    chrono::LocalResult::Single(dt) => dt
                        .with_nanosecond(current_nanos)
                        .unwrap_or(dt), // Re-apply nanoseconds again
                    _ => Utc::now(), // Ultimate fallback if reconstruction still fails
                }
            }
        };
    }

    // Set to the last moment of that year if end_of_year is true
    if end_of_year {
        // Set to the very last moment (999,999 microseconds) of the year
        future_time = match Utc.with_ymd_and_hms(future_time.year(), 12, 31, 23, 59, 59) {
            chrono::LocalResult::Single(dt) => dt
                .with_nanosecond(999_999_000) // Max nanoseconds for microsecond precision
                .unwrap_or(dt), // Keep original dt if setting nanosecond fails (unlikely)
            _ => future_time, // Keep original if conversion fails (should not happen for Dec 31)
        };
    }

    // Format with microsecond precision and Z suffix for UTC
    // %Y-%m-%dT%H:%M:%S%.6fZ
    future_time.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}


/// Returns the current timestamp in ISO 8601 format in UTC with default parameters.
/// This is a convenience function that calls get_timestamp(0, false).
///
/// # Returns
///
/// A string representing the current timestamp in ISO 8601 format.
pub fn get_current_timestamp() -> String {
    get_timestamp(0, false)
}
