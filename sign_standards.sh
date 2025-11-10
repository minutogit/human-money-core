#!/bin/bash

# Stellt sicher, dass das Skript bei einem Fehler sofort abbricht.
set -e

# Definiert den Pfad zur Schlüsseldatei.
KEY_FILE="target/dev-keys/issuer.key"

echo "--- Standard Signatur-Skript ---"

# 1. Überprüfen, ob die Schlüsseldatei existiert. Wenn nicht, neue Schlüssel generieren.
if [ ! -f "$KEY_FILE" ]; then
  echo "🔑 Schlüsseldatei unter '$KEY_FILE' nicht gefunden. Erzeuge ein neues Schlüsselpaar..."
  # Das Rust-CLI-Tool aufrufen, um die Schlüssel zu generieren.
  cargo run --bin voucher-cli -- generate-keys --prefix "0"
else
  echo "🔑 Schlüsseldatei unter '$KEY_FILE' gefunden."
fi

# 2. Alle 'standard.toml'-Dateien in den Unterverzeichnissen von 'voucher_standards' finden und signieren.
echo ""
echo "✍️  Suche nach Standards zum Signieren..."
for standard_file in voucher_standards/*/standard.toml; do
  echo ""
  # Das Rust-CLI-Tool aufrufen, um jede gefundene Datei zu signieren.
  cargo run --bin voucher-cli -- sign-standard --key "$KEY_FILE" --prefix "0" "$standard_file"
done

