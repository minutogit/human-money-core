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

/// Rounds a date up to the end of the day, month, quarter, half-year, or year.
///
/// # Arguments
/// * `date` - The date to round.
/// * `rounding_str` - The rounding unit in ISO 8601 format ("P1D", "P1M", "P3M", "P6M", "P1Y").
///
/// # Returns
/// A `Result` containing the rounded `DateTime<Utc>` or a `VoucherManagerError`.
pub fn round_up_date(
    date: DateTime<Utc>,
    rounding_str: &str,
) -> Result<DateTime<Utc>, VoucherManagerError> {
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
        "P3M" => {
            // Quarter ends: Q1 -> Mar 31, Q2 -> Jun 30, Q3 -> Sep 30, Q4 -> Dec 31
            let quarter_end_month = ((date.month() - 1) / 3 + 1) * 3;
            let (year, next_month) = if quarter_end_month == 12 {
                (date.year() + 1, 1)
            } else {
                (date.year(), quarter_end_month + 1)
            };
            let first_of_after_quarter = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_after_quarter - chrono::Duration::nanoseconds(1))
        }
        "P6M" => {
            // Half-year ends: H1 -> Jun 30, H2 -> Dec 31
            let half_end_month = if date.month() <= 6 { 6 } else { 12 };
            let (year, next_month) = if half_end_month == 12 {
                (date.year() + 1, 1)
            } else {
                (date.year(), half_end_month + 1)
            };
            let first_of_after_half = Utc.with_ymd_and_hms(year, next_month, 1, 0, 0, 0).unwrap();
            Ok(first_of_after_half - chrono::Duration::nanoseconds(1))
        }
        "P1Y" => {
            let first_of_next_year = Utc
                .with_ymd_and_hms(date.year() + 1, 1, 1, 0, 0, 0)
                .unwrap();
            Ok(first_of_next_year - chrono::Duration::nanoseconds(1))
        }
        _ => Err(VoucherManagerError::Generic(format!(
            "Unsupported rounding unit: {}. Supported units are: P1D, P1M, P3M, P6M, P1Y",
            rounding_str
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_up_date_all_intervals() {
        let dt = Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap();

        // P1D: Same day, 23:59:59.999999999
        let rounded_day = round_up_date(dt, "P1D").unwrap();
        assert_eq!(rounded_day.year(), 2026);
        assert_eq!(rounded_day.month(), 5);
        assert_eq!(rounded_day.day(), 15);
        assert_eq!(rounded_day.hour(), 23);
        assert_eq!(rounded_day.minute(), 59);
        assert_eq!(rounded_day.second(), 59);

        // P1M: End of May -> 2026-05-31 23:59:59
        let rounded_month = round_up_date(dt, "P1M").unwrap();
        assert_eq!(rounded_month.year(), 2026);
        assert_eq!(rounded_month.month(), 5);
        assert_eq!(rounded_month.day(), 31);
        assert_eq!(rounded_month.hour(), 23);

        // P3M: End of Q2 (May is in Q2) -> 2026-06-30 23:59:59
        let rounded_q2 = round_up_date(dt, "P3M").unwrap();
        assert_eq!(rounded_q2.year(), 2026);
        assert_eq!(rounded_q2.month(), 6);
        assert_eq!(rounded_q2.day(), 30);
        assert_eq!(rounded_q2.hour(), 23);

        // P3M in Q1, Q3, Q4
        let dt_q1 = Utc.with_ymd_and_hms(2026, 2, 10, 0, 0, 0).unwrap();
        let rounded_q1 = round_up_date(dt_q1, "P3M").unwrap();
        assert_eq!(rounded_q1.month(), 3);
        assert_eq!(rounded_q1.day(), 31);

        let dt_q3 = Utc.with_ymd_and_hms(2026, 8, 20, 0, 0, 0).unwrap();
        let rounded_q3 = round_up_date(dt_q3, "P3M").unwrap();
        assert_eq!(rounded_q3.month(), 9);
        assert_eq!(rounded_q3.day(), 30);

        let dt_q4 = Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap();
        let rounded_q4 = round_up_date(dt_q4, "P3M").unwrap();
        assert_eq!(rounded_q4.year(), 2026);
        assert_eq!(rounded_q4.month(), 12);
        assert_eq!(rounded_q4.day(), 31);

        // P6M: End of H1 (May is in H1) -> 2026-06-30 23:59:59
        let rounded_h1 = round_up_date(dt, "P6M").unwrap();
        assert_eq!(rounded_h1.year(), 2026);
        assert_eq!(rounded_h1.month(), 6);
        assert_eq!(rounded_h1.day(), 30);

        // P6M: End of H2 (August is in H2) -> 2026-12-31 23:59:59
        let rounded_h2 = round_up_date(dt_q3, "P6M").unwrap();
        assert_eq!(rounded_h2.year(), 2026);
        assert_eq!(rounded_h2.month(), 12);
        assert_eq!(rounded_h2.day(), 31);

        // P1Y: End of Year -> 2026-12-31 23:59:59
        let rounded_year = round_up_date(dt, "P1Y").unwrap();
        assert_eq!(rounded_year.year(), 2026);
        assert_eq!(rounded_year.month(), 12);
        assert_eq!(rounded_year.day(), 31);
    }

    #[test]
    fn test_round_up_date_invalid_interval() {
        let dt = Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap();
        assert!(round_up_date(dt, "P2Y").is_err());
        assert!(round_up_date(dt, "invalid").is_err());
    }
}
