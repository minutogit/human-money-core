#!/bin/bash
# scripts/retest_missed.sh
# Runs cargo mutants only for the mutants listed in mutants.out/missed.txt

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PATH="$HOME/.cargo/bin:$PATH"

MISSED_FILE="mutants.out/missed.txt"

if [ ! -f "$MISSED_FILE" ]; then
    echo "❌ Error: $MISSED_FILE not found."
    exit 1
fi

echo "--- 🎯 Human Money Core - Surgical Mutation Retest ---"

while IFS= read -r line || [ -n "$line" ]; do
    if [[ -z "$line" ]]; then continue; fi
    
    # Extract file and description
    # Example: src/services/voucher_validation.rs:50:23: replace < with <= in validate_voucher_against_standard
    FILE_PATH=$(echo "$line" | cut -d: -f1)
    LINE_NUM=$(echo "$line" | cut -d: -f2)
    DESC=$(echo "$line" | cut -d: -f4- | sed 's/^[[:space:]]*//')
    
    echo ""
    echo "🚀 Retesting mutant in $FILE_PATH at line $LINE_NUM"
    echo "   Description: $DESC"
    
    # Create a regex to match this specific mutant. 
    # We include the line number to be very specific.
    # cargo mutants list output format is: "file:line:col: description"
    SAFE_REGEX=$(echo "$DESC" | sed 's/[^^a-zA-Z0-9 ]/./g')
    FULL_REGEX="$FILE_PATH:$LINE_NUM:.*$SAFE_REGEX"
    
    echo "   Using Regex: $FULL_REGEX"
    
    # Run cargo mutants for this specific location
    cargo mutants -v --re "$FULL_REGEX"
done < "$MISSED_FILE"

echo ""
echo "✅ Surgical retest completed."
