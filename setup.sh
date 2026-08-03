#!/bin/bash
set -e

echo ""
echo "  ♥ SofiaVault — macOS Setup ♥"
echo ""

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "✗ Python 3 is not installed."
    echo "  Install it with: brew install python3"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VAULT_PY="$SCRIPT_DIR/sofiavault.py"
BIN_DIR="$HOME/.local/bin"
WRAPPER="$BIN_DIR/sofiavault"

# Install dependencies
echo "[1/3] Installing dependencies..."
python3 -m pip install --quiet argon2-cffi cryptography rapidfuzz
echo "  ✓ Dependencies installed"

# Create bin directory
mkdir -p "$BIN_DIR"

# Make script executable
chmod +x "$VAULT_PY"

# Remove old wrapper/symlink if it exists
if [ -e "$WRAPPER" ] || [ -L "$WRAPPER" ]; then
    rm -f "$WRAPPER"
fi

# Create symlink (not a wrapper file — avoids overwrite risks)
ln -s "$VAULT_PY" "$WRAPPER"
echo "[2/3] Linked: $WRAPPER -> $VAULT_PY"

# Add to PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_NAME="$(basename "$SHELL")"
    if [[ "$SHELL_NAME" == "zsh" ]]; then
        RC_FILE="$HOME/.zshrc"
    else
        RC_FILE="$HOME/.bashrc"
    fi

    # Only add if not already in rc file
    if ! grep -q '.local/bin' "$RC_FILE" 2>/dev/null; then
        echo '' >> "$RC_FILE"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$RC_FILE"
        echo "[3/3] Added ~/.local/bin to PATH in $RC_FILE"
        echo ""
        echo "  ⚠  Run this to apply now:"
        echo "     source $RC_FILE"
    else
        echo "[3/3] PATH already configured in $RC_FILE"
    fi
else
    echo "[3/3] PATH already includes $BIN_DIR"
fi

echo ""
echo "  ✅ Installation complete!"
echo ""
echo "  Usage:"
echo "    sofiavault                  Interactive mode"
echo "    sofiavault add              Add a password"
echo "    sofiavault amazon           Get a password (fuzzy match)"
echo "    sofiavault list             List all entries"
echo "    sofiavault delete amazon    Delete an entry"
echo "    sofiavault import file.csv  Import from CSV"
echo "    sofiavault help             Show help"
echo ""
