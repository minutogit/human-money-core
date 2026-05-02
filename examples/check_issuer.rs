
use std::fs;
use human_money_core::services::crypto_utils;

fn main() {
    let key_bytes = fs::read("target/dev-keys/issuer.key").expect("Failed to read key file");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes.try_into().unwrap());
    let public_key = signing_key.verifying_key();
    let user_id = crypto_utils::create_user_id(&public_key, Some("0")).unwrap();
    println!("User ID: {}", user_id);
}
