
use human_money_core::services::crypto_utils;
use human_money_core::services::utils::to_canonical_json;
use human_money_core::models::voucher_standard_definition::{VoucherStandardDefinition, SignatureBlock};
use std::fs;

fn main() {
    let toml_path = "voucher_standards/freetaler_v1/standard.toml";
    let toml_str = fs::read_to_string(toml_path).expect("Failed to read TOML");
    
    let mut standard: VoucherStandardDefinition = toml::from_str(&toml_str).expect("Failed to parse TOML");
    
    // Update decimal places (though already done, let's be sure)
    standard.immutable.features.amount_decimal_places = 2;
    
    // Setup signer (TEST_ISSUER from test_utils)
    let mnemonic = "seek ethics foam novel hat faculty royal donkey burger frost advice visa";
    let (public_key, signing_key) = crypto_utils::generate_ed25519_keypair_for_tests(Some(mnemonic));
    let issuer_id = crypto_utils::create_user_id(&public_key, Some("issuer")).unwrap();
    
    // Clear signature block for canonicalization
    standard.signature = None;
    
    // Canonicalize and hash
    let canonical_json = to_canonical_json(&standard).expect("Failed to canonicalize");
    let hash = crypto_utils::get_hash(canonical_json.as_bytes());
    
    // Sign
    let signature = crypto_utils::sign_ed25519(&signing_key, hash.as_bytes());
    
    // Create new signature block
    standard.signature = Some(SignatureBlock {
        issuer_id,
        signature: bs58::encode(signature.to_bytes()).into_string(),
    });
    
    // Serialize back to TOML
    let new_toml = toml::to_string(&standard).expect("Failed to serialize TOML");
    
    // Write back
    fs::write(toml_path, new_toml).expect("Failed to write TOML");
    
    println!("Updated and signed FreeTaler TOML at {}", toml_path);
}
