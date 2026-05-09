//! # Date Utilities for Voucher Management
//!
//! Provides functions for handling ISO 8601 durations and rounding dates,
//! which are essential for voucher validity calculations.

use chrono::{DateTime, Datelike, TimeZone, Utc, Timelike};
use super::VoucherManagerError;

/// Adds an ISO 8601 duration to a start date.
///
/// Supported units are:
/// - 'Y' (Years)
/// - 'M' (Months)
/// - 'D' (Days)
///
/// # Arguments
/// * `start_date` - The base date.
/// * `duration_str` - The duration in ISO 8601 format (e.g., "P1Y", "P6M", "P30D").
///
/// # Returns
/// A `Result` containing the new `DateTime<Utc>` or a `VoucherManagerError`.
pub fn add_iso8601_duration(
    start_date: DateTime<Utc>,
    duration_str: &str,
) -> Result<DateTime<Utc>, VoucherManagerError> {
    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherManagerError::Generic(format!(
            "Invalid ISO 8601 duration format: {}",
            duration_str
        )));
    }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| {
        VoucherManagerError::Generic(format!("Invalid number in duration: {}", duration_str))
    })?;
    match unit {
        "Y" => {
            let new_year = start_date.year() + value as i32;
            let new_date = start_date.with_year(new_year).unwrap_or_else(|| {
                Utc.with_ymd_and_hms(
                    new_year,
                    2,
                    28,
                    start_date.hour(),
                    start_date.minute(),
                    start_date.second(),
                )
                .unwrap()
            });
            Ok(new_date)
        }
        "M" => {
            let current_month0 = start_date.month0();
            let total_months0 = current_month0 + value;
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();
            let days_in_target_month = Utc
                .with_ymd_and_hms(
                    if new_month == 12 {
                        new_year + 1
                    } else {
                        new_year
                    },
                    if new_month == 12 { 1 } else { new_month + 1 },
                    1,
                    0,
                    0,
                    0,
                )
                .unwrap()
                .signed_duration_since(
                    Utc.with_ymd_and_hms(new_year, new_month, 1, 0, 0, 0)
                        .unwrap(),
                )
                .num_days() as u32;
            let new_day = original_day.min(days_in_target_month);
            let new_date = Utc
                .with_ymd_and_hms(
                    new_year,
                    new_month,
                    new_day,
                    start_date.hour(),
                    start_date.minute(),
                    start_date.second(),
                )
                .unwrap()
                .with_nanosecond(start_date.nanosecond())
                .unwrap();
            Ok(new_date)
        }
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherManagerError::Generic(format!(
            "Unsupported duration unit in: {}",
            duration_str
        ))),
    }
}

/// Rounds a date up to the end of the day, month, or year.
///
/// # Arguments
/// * `date` - The date to round.
/// * `rounding_str` - The rounding unit in ISO 8601 format ("P1D", "P1M", "P1Y").
///
/// # Returns
/// A `Result` containing the rounded `DateTime<Utc>` or a `VoucherManagerError`.
pub fn round_up_date(
    date: DateTime<Utc>,
    rounding_str: &str,
) -> Result<DateTime<Utc>, VoucherManagerError> {
    use chrono::Timelike;
    match rounding_str {
        "P1D" => Ok(date
            .with_hour(23)
            .unwrap()
            .with_minute(59)
            .unwrap()
            .with_second(59)
            .unwrap()
            .with_nanosecond(999_999_999)
            .unwrap()),
        "P1M" => {
            let next_month = if date.month() == 12 {
                1
            } else {
                date.month() + 1
            };
            let year = if date.month() == 12 {
                date.year() + 1
            } else {
                date.year()
            };
            let first_of_next_month = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_next_month - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => {
            let first_of_next_year = Utc
                .with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0)
                .unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!(
            "Unsupported rounding unit: {}",
            rounding_str
        ))),
    }
}
