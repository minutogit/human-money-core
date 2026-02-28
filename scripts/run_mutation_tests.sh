#!/bin/bash
# Ermittle das Projektwurzelverzeichnis (ein Level über dem script-Ordner)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"
# set -e entfernt, damit wir bei Fehlern (überlebende Mutanten) weitermachen

echo "--- 🛡️ Human Money Core - Mutation Testing Runner ---"

# Prüfe auf cargo-mutants
if ! command -v cargo-mutants &> /dev/null; then
    echo "❌ Fehler: 'cargo-mutants' ist nicht installiert."
    echo "Bitte installiere es mit: cargo install cargo-mutants"
    exit 1
fi

# Definiere die kritischen Dateien für gezielte Tests (Sicherheits-Hotspots)
CRITICAL_FILES=(
    "src/services/trap_manager.rs"
    "src/services/voucher_validation.rs"
    "src/wallet/transaction_handler.rs"
)

echo "🔍 Starte gezielte Mutationstests für Kernmodule..."

for file in "${CRITICAL_FILES[@]}"; do
    echo ""
    echo "🚀 Analysiere Modul: $file"
    # Führt Mutationstests nur für die spezifische Datei aus
    cargo mutants -v -f "$file"
    
    if [ $? -ne 0 ]; then
        echo "⚠️  Warnung: Manche Mutanten in $file haben überlebt."
    else
        echo "✅ Modul $file ist zu 100% gehärtet."
    fi
done

echo ""
echo "🏁 Mutationstest-Session abgeschlossen."
