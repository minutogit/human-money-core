//! src/bin/voucher-cli.rs
//!
//! Ein Kommandozeilen-Tool zum Verwalten und Signieren von Gutschein-Standards.
//!
//! ## Befehle:
//! - `generate-keys`: Erzeugt ein neues Schlüsselpaar für den Herausgeber.
//! - `sign-standard`: Signiert eine gegebene Standard-Definitionsdatei.

use anyhow::{Context, Result};
use bip39::Language;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};
use human_money_core::{
    crypto_utils::{self, get_hash},
    models::voucher_standard_definition::VoucherStandardDefinition,
    to_canonical_json,
};

/// Das Haupt-Struct für das CLI-Tool, das von `clap` geparst wird.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Definiert die verfügbaren Unterbefehle.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Erzeugt ein neues Ed25519-Schlüsselpaar und eine Mnemonic-Phrase für den Herausgeber.
    GenerateKeys {
        /// Das Präfix für die User-ID (z.B. "0" für den Standard-Issuer).
        #[arg(short, long)]
        prefix: String,
    },

    /// Signiert eine Standard-Definitionsdatei mit einem gegebenen privaten Schlüssel.
    SignStandard {
        /// Pfad zur privaten Schlüsseldatei des Herausgebers (z.B. target/dev-keys/issuer.key).
        #[arg(short, long)]
        key: PathBuf,

        /// Das Präfix für die User-ID (z.B. "0" für den Standard-Issuer).
        #[arg(short, long)]
        prefix: String,

        /// Pfad zur .toml-Datei des Standards, die signiert werden soll.
        standard_file: PathBuf,
    },
}

/// Hauptfunktion des Programms.
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { prefix } => generate_keys(&prefix)?,
        Commands::SignStandard { key, prefix, standard_file } => sign_standard(&key, &prefix, &standard_file)?,
    }

    Ok(())
}

/// Logik für den `generate-keys`-Befehl.
fn generate_keys(prefix: &str) -> Result<()> {
    let key_dir = Path::new("target/dev-keys");
    fs::create_dir_all(key_dir)
        .with_context(|| format!("Konnte das Verzeichnis {} nicht erstellen", key_dir.display()))?;

    let mnemonic_path = key_dir.join("issuer.mnemonic");
    let key_path = key_dir.join("issuer.key");

    println!("🔑 Erzeuge neue Mnemonic-Phrase und Schlüsselpaar...");

    // 1. Mnemonic erzeugen und speichern
    let mnemonic = crypto_utils::generate_mnemonic(12, Language::English)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("Mnemonic konnte nicht generiert werden")?;
    fs::write(&mnemonic_path, &mnemonic)
        .with_context(|| format!("Konnte Mnemonic nicht in {} schreiben", mnemonic_path.display()))?;

    // 2. Schlüsselpaar aus Mnemonic ableiten
    let (public_key, signing_key) = crypto_utils::derive_ed25519_keypair(&mnemonic, None)?;

    // 3. Privaten Schlüssel speichern
    fs::write(&key_path, signing_key.to_bytes())
        .with_context(|| format!("Konnte privaten Schlüssel nicht in {} schreiben", key_path.display()))?;

    // 4. Issuer ID generieren und ausgeben
    let issuer_id = crypto_utils::create_user_id(&public_key, Some(prefix))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    println!("✅ Schlüssel erfolgreich generiert!");
    println!("   - Mnemonic gespeichert in: {}", mnemonic_path.display());
    println!("   - Privater Schlüssel gespeichert in: {}", key_path.display());
    println!("   - Ihre Issuer ID (did:key) lautet: {}", issuer_id);

    Ok(())
}

/// Logik für den `sign-standard`-Befehl.
fn sign_standard(key_path: &Path, prefix: &str, standard_path: &Path) -> Result<()> {
    println!("✍️  Signiere Standard: {}", standard_path.display());

    // 1. Privaten Schlüssel laden
    let key_bytes: [u8; 32] = fs::read(key_path)
        .with_context(|| format!("Konnte privaten Schlüssel aus {} nicht laden", key_path.display()))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Schlüsseldatei hat eine ungültige Länge"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let public_key = signing_key.verifying_key();

    // 2. Standard-Datei laden
    let toml_content = fs::read_to_string(standard_path)
        .with_context(|| format!("Konnte Standard-Datei {} nicht laden", standard_path.display()))?;
    
    // 3. Alten Signatur-Block entfernen und kanonischen Inhalt für die Signatur erstellen
    let mut toml_value: toml::Value = toml::from_str(&toml_content)?;
    if let Some(table) = toml_value.as_table_mut() {
        table.remove("signature");
    }
    
    // 4. Kanonische Form für die Signatur erstellen
    let mut standard_def: VoucherStandardDefinition = toml::from_str(&toml::to_string(&toml_value)?)?;
    standard_def.signature = None; // Sicherstellen, dass die Signatur für die Kanonisierung leer ist
    let canonical_json = to_canonical_json(&standard_def)
        .context("Kanonisches JSON konnte nicht erstellt werden")?;

    // 5. Hash berechnen und signieren
    let hash_to_sign = get_hash(canonical_json.as_bytes());
    let signature = crypto_utils::sign_ed25519(&signing_key, hash_to_sign.as_bytes());
    let signature_b58 = bs58::encode(signature.to_bytes()).into_string();

    // 6. Issuer ID erstellen
    let issuer_id = crypto_utils::create_user_id(&public_key, Some(prefix))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    // 7. Neuen Signatur-Block erstellen
    let signature_block = format!(
        "\n[signature]\n# Die `did:key` des Herausgebers, die seinen öffentlichen Schlüssel enthält.\nissuer_id = \"{}\"\n\n# Die finale Base58-kodierte Ed25519-Signatur des kanonisierten Inhalts (ohne diesen Block).\nsignature = \"{}\"\n",
        issuer_id,
        signature_b58
    );

    // 8. Signatur in die ursprüngliche Datei einfügen, ohne die Formatierung zu verändern
    let final_toml_content = update_signature_in_toml(&toml_content, &signature_block);

    // 9. Datei überschreiben
    fs::write(standard_path, final_toml_content)
        .with_context(|| format!("Konnte signierten Standard nicht in {} schreiben", standard_path.display()))?;

    println!("✅ Standard erfolgreich signiert.");
    Ok(())
}

/// Hilfsfunktion zum Aktualisieren des Signaturblocks in einer TOML-Datei
/// ohne die ursprüngliche Formatierung zu verändern
fn update_signature_in_toml(original_content: &str, new_signature_block: &str) -> String {
    // Suchen des Signaturblocks in der Datei
    let signature_start = original_content.find("\n[signature]");
    
    if let Some(pos) = signature_start {
        // Wenn ein Signaturblock gefunden wurde, ersetzen wir ihn
        // Wir behalten die Leerzeile vor dem [signature] Block bei
        let content_before_signature = &original_content[..pos + 1];
        content_before_signature.to_string() + new_signature_block.trim_start()
    } else {
        // Wenn kein Signaturblock gefunden wurde, fügen wir ihn am Ende hinzu
        original_content.trim_end().to_string() + new_signature_block
    }
}