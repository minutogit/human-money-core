pub mod actors;
pub mod standards;
pub mod voucher_setup;
pub mod wallet_setup;

pub use actors::*;
pub use standards::*;
pub use voucher_setup::*;
pub use wallet_setup::*;

use lazy_static::lazy_static;

lazy_static! {
    /// Ein deterministischer Herausgeber, der zum Signieren der Test-Standards verwendet wird.
    pub static ref TEST_ISSUER: actors::TestUser = actors::init_test_issuer();
}

lazy_static! {
    /// Initialisiert einmalig alle Akteure, sodass sie in allen Tests wiederverwendet werden können.
    pub static ref ACTORS: actors::TestActors = actors::init_actors();
}


#[cfg(test)]
mod tests {
    use crate::services::utils::{get_current_timestamp, get_timestamp};
    use chrono::{DateTime, Utc};
    use regex::Regex;

    // Helper function to parse the timestamp string and check basic format
    fn parse_and_validate_format(timestamp_str: &str) -> Result<DateTime<Utc>, String> {
        let re = Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        if !re.is_match(timestamp_str) {
            return Err(format!(
                "Timestamp '{}' does not match expected format YYYY-MM-DDTHH:MM:SS.ffffffZ",
                timestamp_str
            ));
        }

        DateTime::parse_from_rfc3339(timestamp_str)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("Failed to parse timestamp '{}': {}", timestamp_str, e))
    }

    #[test]
    fn test_get_current_timestamp_format() {
        let timestamp = get_current_timestamp();
        assert!(parse_and_validate_format(&timestamp).is_ok());
    }

    #[test]
    fn test_get_timestamp_add_years() {
        use chrono::Datelike;
        let years_to_add = 2;
        let now = Utc::now();
        let expected_year = now.year() + years_to_add;

        let timestamp = get_timestamp(years_to_add, false);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            expected_year,
            "Year should be incremented correctly"
        );
    }

    #[test]
    fn test_get_timestamp_end_of_current_year() {
        use chrono::Datelike;
        use chrono::Timelike;
        let now = Utc::now();
        let current_year = now.year();

        let timestamp = get_timestamp(0, true);
        let parsed_dt = parse_and_validate_format(&timestamp).expect("Timestamp should be valid");

        assert_eq!(
            parsed_dt.year(),
            current_year,
            "Year should be the current year"
        );
        assert_eq!(parsed_dt.month(), 12, "Month should be December");
        assert_eq!(parsed_dt.day(), 31, "Day should be 31st");
        assert_eq!(parsed_dt.hour(), 23, "Hour should be 23");
        assert_eq!(parsed_dt.minute(), 59, "Minute should be 59");
        assert_eq!(parsed_dt.second(), 59, "Second should be 59");
        assert_eq!(
            parsed_dt.nanosecond(),
            999_999_000,
            "Nanoseconds should indicate the last microsecond"
        );
    }
}
