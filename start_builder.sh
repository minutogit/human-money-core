#!/usr/bin/env bash
# ==============================================================================
# start_builder.sh
#
# Startet den Voucher Standard Builder lokal:
# 1. Prüft / baut die WASM-Bridge (bindings/wasm)
# 2. Prüft / installiert Node-Dependencies (tools/standard-builder)
# 3. Startet den Vite Dev-Server und öffnet die App im Browser
# ==============================================================================

set -e

# Wechsle ins Repository-Root-Verzeichnis
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================="
echo "🛠️  Human Money — Voucher Standard Builder"
echo "=============================================="

# 1. WASM-Bridge bauen falls noch nicht vorhanden oder aktualisiert
WASM_PKG="bindings/wasm/pkg/human_money_wasm_bg.wasm"

if [ ! -f "$WASM_PKG" ]; then
    echo "📦 Baue WASM-Bridge (bindings/wasm)..."
    (cd bindings/wasm && npx wasm-pack build --target web)
else
    echo "✅ WASM-Bridge vorhanden."
fi

# 2. Node Dependencies prüfen
if [ ! -d "tools/standard-builder/node_modules" ]; then
    echo "📥 Installiere Frontend-Abhängigkeiten..."
    (cd tools/standard-builder && npm install)
fi

# 3. Vite Dev-Server starten
echo "🚀 Starte Dev-Server auf http://localhost:3000..."
cd tools/standard-builder
npm run dev -- --open
