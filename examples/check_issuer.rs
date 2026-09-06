//! # Check Issuer Example
//!
//! This example prints the calculated User ID for the default developer issuer key.
//!
//! Run with: `cargo run --example check_issuer`

use human_money_core::services::crypto;

fn main() {
    let (public_key, _) = crypto::generate_ed25519_keypair_for_tests(Some("freetaler-issuer"));
    let user_id = crypto::create_user_id(&public_key, Some("0")).unwrap();
    println!("User ID: {}", user_id);
}
