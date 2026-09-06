//! # src/services/utils.rs
//!
//! Contains general helper functions, e.g. for timestamps and canonical serialization.

use chrono::{DateTime, Datelike, NaiveDate, TimeZone, Timelike, Utc};
use serde::Serialize;
use serde_json_canonicalizer::to_string;

// ---------------------------------------------------------------------------
// Private helpers — date arithmetic & formatting boilerplate
// ---------------------------------------------------------------------------

/// Returns the number of days in a given month/year.
///
/// Uses the "first day of next month minus one day" trick, which correctly
/// handles December → January year rollover and leap years.
fn days_in_month(year: i32, month: u32) -> u32 {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .expect("valid next month")
        .pred_opt()
        .expect("valid predecessor day")
        .day()
}

/// Tries to construct a `DateTime<Utc>` from components and re-applies `nanos`.
///
/// Returns `None` if the local result is not `Single` (e.g. invalid Feb 29).
fn try_ymd_hms_with_nanos(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
) -> Option<DateTime<Utc>> {
    match Utc.with_ymd_and_hms(year, month, day, hour, minute, second) {
        chrono::LocalResult::Single(dt) => Some(dt.with_nanosecond(nanos).unwrap_or(dt)),
        _ => None,
    }
}

/// Adds `years` to `dt` while clamping an invalid day (e.g. Feb 29 → Feb 28)
/// and preserving the original nanoseconds.
fn add_years_clamped(dt: DateTime<Utc>, years: i32) -> DateTime<Utc> {
    if years == 0 {
        return dt;
    }
    let new_year = dt.year() + years;
    let nanos = dt.nanosecond();

    if let Some(candidate) = try_ymd_hms_with_nanos(
        new_year,
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        nanos,
    ) {
        return candidate;
    }

    let last_day = days_in_month(new_year, dt.month());
    let valid_day = dt.day().min(last_day);
    try_ymd_hms_with_nanos(
        new_year,
        dt.month(),
        valid_day,
        dt.hour(),
        dt.minute(),
        dt.second(),
        nanos,
    )
    .unwrap_or_else(Utc::now)
}

/// Returns the last nanosecond before `year/month/1 00:00:00`.
/// Used by `round_up_date` to compute "end of period" as "first of next period minus 1 ns".
fn last_ns_before(year: i32, month: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, 1, 0, 0, 0)
        .single()
        .expect("valid date")
        - chrono::Duration::nanoseconds(1)
}

/// Returns `(year, month)` of the month following `(year, month)`.
fn next_month(year: i32, month: u32) -> (i32, u32) {
    if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    }
}

/// Parses an RFC 3339 string into `DateTime<Utc>`.
fn parse_rfc3339_utc(s: &str) -> Result<DateTime<Utc>, crate::error::VoucherCoreError> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| crate::error::VoucherCoreError::Generic(format!("Failed to parse timestamp: {}", e)))
}

/// Formats a duration in seconds as `"Xh Ym Zs"`.
fn format_wait_duration(total_seconds: i64) -> String {
    let d = chrono::Duration::seconds(total_seconds);
    format!(
        "{}h {}m {}s",
        d.num_hours(),
        d.num_minutes() % 60,
        d.num_seconds() % 60
    )
}

// ---------------------------------------------------------------------------
// Public API — must preserve canonical JSON and date/time semantics
// ---------------------------------------------------------------------------

/// Serializes any `Serialize`-able struct into a canonical JSON string
/// according to RFC 8785 (JCS - JSON Canonicalization Scheme).
///
/// This ensures deterministic output:
/// - Keys in objects are sorted lexicographically.
/// - No superfluous whitespace.
///
/// This function is essential for cryptographic signatures and verification,
/// as it guarantees that the same logical content always produces the exact same hash.
///
/// # Arguments
/// * `value` - A value that implements `serde::Serialize`.
///
/// # Returns
/// A `Result` containing either the compact, canonical JSON string or a `serde_json::Error`.
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
    let mut dt = Utc::now();

    if years_to_add != 0 {
        dt = add_years_clamped(dt, years_to_add);
    }

    if end_of_year {
        dt = Utc
            .with_ymd_and_hms(dt.year(), 12, 31, 23, 59, 59)
            .single()
            .expect("Dec 31 is always valid")
            .with_nanosecond(999_999_000)
            .unwrap_or(dt);
    }

    // Format with microsecond precision and Z suffix for UTC
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

#[cfg(not(any(test, feature = "test-utils")))]
pub fn get_current_timestamp() -> String {
    get_timestamp(0, false)
}

#[cfg(any(test, feature = "test-utils"))]
pub fn get_current_timestamp() -> String {
    MOCK_TIME.with(|time| {
        if let Some(t) = time.borrow().as_ref() {
            t.clone()
        } else {
            get_timestamp(0, false)
        }
    })
}

#[cfg(any(test, feature = "test-utils"))]
thread_local! {
    static MOCK_TIME: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

#[cfg(any(test, feature = "test-utils"))]
pub fn set_mock_time(time: Option<String>) {
    MOCK_TIME.with(|t| *t.borrow_mut() = time);
}

/// The maximum timespan into the future that we accept for a timestamp.
/// Anything beyond this is rejected as a "Hard Reject".
/// 2 hours (7200 seconds) accommodate moderate clock drifts and timezone issues.
pub const MAX_FUTURE_GRACE_PERIOD_SECONDS: i64 = 7200;

/// Checks whether a timestamp is too far in the future.
///
/// # Arguments
/// * `timestamp_iso` - The timestamp to check in ISO 8601 format.
/// * `entity_name` - Name of the entity (e.g. "Bundle", "Transaction") for the error message.
/// * `id` - ID of the entity for the error message.
///
/// # Returns
/// `Ok(())` if the timestamp is within tolerance, otherwise a `VoucherCoreError`.
pub fn verify_not_far_in_future(
    timestamp_iso: &str,
    entity_name: &str,
    id: &str,
) -> Result<(), crate::error::VoucherCoreError> {
    use crate::error::ValidationError;

    let now_str = get_current_timestamp();
    let now = parse_rfc3339_utc(&now_str)
        .map_err(|e| crate::error::VoucherCoreError::Generic(format!("Failed to parse now: {}", e)))?;

    let ts = parse_rfc3339_utc(timestamp_iso)?;

    let diff_seconds = ts.timestamp() - now.timestamp();

    if diff_seconds > MAX_FUTURE_GRACE_PERIOD_SECONDS {
        let wait_duration = format_wait_duration(diff_seconds);
        let limit_time = now + chrono::Duration::seconds(MAX_FUTURE_GRACE_PERIOD_SECONDS);

        return Err(ValidationError::FutureTimestampRejected {
            entity: entity_name.to_string(),
            id: id.to_string(),
            timestamp: timestamp_iso.to_string(),
            limit: limit_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            wait_duration,
        }
        .into());
    }

    Ok(())
}

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
/// A `Result` containing the new `DateTime<Utc>` or a `VoucherCoreError`.
pub fn add_iso8601_duration(
    start_date: DateTime<Utc>,
    duration_str: &str,
) -> Result<DateTime<Utc>, crate::error::VoucherCoreError> {
    use crate::error::VoucherCoreError;

    if !duration_str.starts_with('P') || duration_str.len() < 3 {
        return Err(VoucherCoreError::VoucherManagerGeneric(format!(
            "Invalid ISO 8601 duration format: {}",
            duration_str
        )));
    }
    let (value_str, unit) = duration_str.split_at(duration_str.len() - 1);
    let value: u32 = value_str[1..].parse().map_err(|_| {
        VoucherCoreError::VoucherManagerGeneric(format!("Invalid number in duration: {}", duration_str))
    })?;
    match unit {
        "Y" => Ok(add_years_clamped(start_date, value as i32)),
        "M" => {
            let current_month0 = start_date.month0();
            let total_months0 = current_month0 + value;
            let new_year = start_date.year() + (total_months0 / 12) as i32;
            let new_month = (total_months0 % 12) + 1;
            let original_day = start_date.day();
            let days_in_target = days_in_month(new_year, new_month);
            let new_day = original_day.min(days_in_target);
            Ok(Utc
                .with_ymd_and_hms(
                    new_year,
                    new_month,
                    new_day,
                    start_date.hour(),
                    start_date.minute(),
                    start_date.second(),
                )
                .single()
                .expect("valid clamped date")
                .with_nanosecond(start_date.nanosecond())
                .expect("valid nanosecond"))
        }
        "D" => Ok(start_date + chrono::Duration::days(i64::from(value))),
        _ => Err(VoucherCoreError::VoucherManagerGeneric(format!(
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
/// A `Result` containing the rounded `DateTime<Utc>` or a `VoucherCoreError`.
pub fn round_up_date(
    date: DateTime<Utc>,
    rounding_str: &str,
) -> Result<DateTime<Utc>, crate::error::VoucherCoreError> {
    use crate::error::VoucherCoreError;

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
            let (y, m) = next_month(date.year(), date.month());
            Ok(last_ns_before(y, m))
        }
        "P3M" => {
            let quarter_end_month = ((date.month() - 1) / 3 + 1) * 3;
            let (y, m) = next_month(date.year(), quarter_end_month);
            Ok(last_ns_before(y, m))
        }
        "P6M" => {
            let half_end_month = if date.month() <= 6 { 6 } else { 12 };
            let (y, m) = next_month(date.year(), half_end_month);
            Ok(last_ns_before(y, m))
        }
        "P1Y" => Ok(last_ns_before(date.year() + 1, 1)),
        _ => Err(VoucherCoreError::VoucherManagerGeneric(format!(
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
