//! src/bin/voucher-cli.rs
//!
//! A command-line tool for managing and signing voucher standards.
//!
//! ## Commands:
//! - `generate-keys`: Generates a new key pair for the issuer.
//! - `sign-standard`: Signs a given standard definition file.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use human_money_core::{
    crypto::{self, get_hash},
    models::voucher_standard_definition::VoucherStandardDefinition,
    to_canonical_json, MnemonicLanguage,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Main struct for the CLI tool parsed by `clap`.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Defines available subcommands.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a new Ed25519 key pair and mnemonic phrase for the issuer.
    GenerateKeys {
        /// Prefix for the user ID (e.g. "0" for standard issuer).
        #[arg(short, long)]
        prefix: String,
    },

    /// Signs a standard definition file with a given private key.
    SignStandard {
        /// Path to issuer's private key file (e.g. target/dev-keys/issuer.key).
        #[arg(short, long)]
        key: PathBuf,

        /// Prefix for user ID (e.g. "0" for standard issuer).
        #[arg(short, long)]
        prefix: String,

        /// Path to standard .toml file to be signed.
        standard_file: PathBuf,
    },
}

/// Main program entry point.
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { prefix } => generate_keys(&prefix)?,
        Commands::SignStandard {
            key,
            prefix,
            standard_file,
        } => sign_standard(&key, &prefix, &standard_file)?,
    }

    Ok(())
}

/// Logic for the `generate-keys` command.
fn generate_keys(prefix: &str) -> Result<()> {
    let key_dir = Path::new("target/dev-keys");
    fs::create_dir_all(key_dir).with_context(|| {
        format!(
            "Konnte das Verzeichnis {} nicht erstellen",
            key_dir.display()
        )
    })?;

    let mnemonic_path = key_dir.join("issuer.mnemonic");
    let key_path = key_dir.join("issuer.key");

    println!("🔑 Erzeuge neue Mnemonic-Phrase und Schlüsselpaar...");

    // 1. Generate and save mnemonic
    let mnemonic = crypto::generate_mnemonic(12, MnemonicLanguage::English)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("Mnemonic konnte nicht generiert werden")?;
    fs::write(&mnemonic_path, &mnemonic).with_context(|| {
        format!(
            "Konnte Mnemonic nicht in {} schreiben",
            mnemonic_path.display()
        )
    })?;

    // 2. Derive key pair from mnemonic
    let (public_key, signing_key) = crypto::derive_ed25519_keypair(&mnemonic, None, MnemonicLanguage::English)?;

    // 3. Save private key
    fs::write(&key_path, signing_key.to_bytes()).with_context(|| {
        format!(
            "Konnte privaten Schlüssel nicht in {} schreiben",
            key_path.display()
        )
    })?;

    // 4. Generate and output Issuer ID
    let issuer_id = crypto::create_user_id(&public_key, Some(prefix))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    println!("✅ Schlüssel erfolgreich generiert!");
    println!("   - Mnemonic gespeichert in: {}", mnemonic_path.display());
    println!(
        "   - Privater Schlüssel gespeichert in: {}",
        key_path.display()
    );
    println!("   - Ihre Issuer ID (did:key) lautet: {}", issuer_id);

    Ok(())
}

/// Logic for the `sign-standard` command.
fn sign_standard(key_path: &Path, prefix: &str, standard_path: &Path) -> Result<()> {
    println!("✍️  Signiere Standard: {}", standard_path.display());

    // 1. Load private key
    let key_bytes: [u8; 32] = fs::read(key_path)
        .with_context(|| {
            format!(
                "Konnte privaten Schlüssel aus {} nicht laden",
                key_path.display()
            )
        })?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Schlüsseldatei hat eine ungültige Länge"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key = signing_key.verifying_key();

    // 2. Load standard file
    let toml_content = fs::read_to_string(standard_path).with_context(|| {
        format!(
            "Konnte Standard-Datei {} nicht laden",
            standard_path.display()
        )
    })?;

    // 3. Remove old signature block and prepare canonical content for signing
    let mut toml_value: toml::Value = toml::from_str(&toml_content)?;
    if let Some(table) = toml_value.as_table_mut() {
        table.remove("signature");
    }

    // 4. Create canonical form for signature
    let mut standard_def: VoucherStandardDefinition =
        toml::from_str(&toml::to_string(&toml_value)?)?;
    standard_def.signature = None; // Ensure signature is empty for canonicalization
    let canonical_json = to_canonical_json(&standard_def)
        .context("Kanonisches JSON konnte nicht erstellt werden")?;

    // 5. Compute hash and sign
    let hash_to_sign = get_hash(canonical_json.as_bytes());
    let signature = crypto::sign_ed25519(&signing_key, hash_to_sign.as_bytes());
    let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

    // 6. Create Issuer ID
    let issuer_id = crypto::create_user_id(&public_key, Some(prefix))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // 7. Create new signature block
    let signature_block = format!(
        "\n[signature]\n# The issuer `did:key` containing their public key.\nissuer_id = \"{}\"\n\n# The final Base58-encoded Ed25519 signature of the canonicalized content (without this block).\nsignature = \"{}\"\n",
        issuer_id, signature_b58
    );

    // 8. Insert signature into original file without modifying formatting
    let final_toml_content = update_signature_in_toml(&toml_content, &signature_block);

    // 9. Overwrite file
    fs::write(standard_path, final_toml_content).with_context(|| {
        format!(
            "Konnte signierten Standard nicht in {} schreiben",
            standard_path.display()
        )
    })?;

    println!("✅ Standard erfolgreich signiert.");
    Ok(())
}

/// Helper function to update the signature block in a TOML file
/// without altering original formatting
fn update_signature_in_toml(original_content: &str, new_signature_block: &str) -> String {
    // Locate signature block in file
    let signature_start = original_content.find("\n[signature]");

    if let Some(pos) = signature_start {
        // If a signature block was found, replace it
        // Preserve empty line before [signature] block
        let content_before_signature = &original_content[..pos + 1];
        content_before_signature.to_string() + new_signature_block.trim_start()
    } else {
        // If no signature block was found, append at the end
        original_content.trim_end().to_string() + new_signature_block
    }
}

