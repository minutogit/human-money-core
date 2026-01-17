// examples/playground_utils.rs
// run with: cargo run --example playground_utils
// demonstrates the timestamp utility functions

use human_money_core::services::utils::{get_current_timestamp, get_timestamp};

fn main() {
    println!("Timestamp Utility Functions Demo\n");

    // Get current timestamp
    let current_timestamp = get_current_timestamp();
    println!("Current timestamp: {}", current_timestamp);

    // Get timestamp with years added
    let years_to_add = 2;
    let future_timestamp = get_timestamp(years_to_add, false);
    println!(
        "Timestamp {} years in the future: {}",
        years_to_add, future_timestamp
    );

    // Get timestamp at end of current year
    let end_of_year_timestamp = get_timestamp(0, true);
    println!("End of current year timestamp: {}", end_of_year_timestamp);

    // Get timestamp at end of future year
    let future_end_of_year = get_timestamp(5, true);
    println!(
        "End of year timestamp 5 years in the future: {}",
        future_end_of_year
    );
}
