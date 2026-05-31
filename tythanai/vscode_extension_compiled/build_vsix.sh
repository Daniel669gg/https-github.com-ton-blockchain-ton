#!/bin/bash
# Ghost Security VS Code Extension — Build & Publish Script
# Требования: node >= 18, npm, vsce
#
# Сборка:   ./build_vsix.sh
# Публикация: ./build_vsix.sh --publish
#
# После публикации extension доступна:
# https://marketplace.visualstudio.com/items?itemName=ghost-security.ghost-security

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/vscode-extension"
VERSION=$(node -p "require('$EXT_DIR/package.json').version" 2>/dev/null || echo "1.0.0")

echo "╔══════════════════════════════════════════════════╗"
echo "║  Ghost Security VS Code Extension Build  v$VERSION  ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
check_dep() {
    if ! command -v "$1" &>/dev/null; then
        echo "❌ Missing: $1"
        echo "   Install: $2"
        exit 1
    fi
    echo "✓ $1: $(command -v "$1")"
}

check_dep node "https://nodejs.org"
check_dep npm "comes with node"

# Install vsce if not present
if ! command -v vsce &>/dev/null && ! command -v "@vscode/vsce" &>/dev/null; then
    echo "Installing vsce..."
    npm install -g @vscode/vsce
fi

cd "$EXT_DIR"

# Install dependencies
echo ""
echo "[1/4] Installing npm dependencies..."
npm install

# Create images dir with placeholder icon if missing
mkdir -p images
if [ ! -f "images/icon.png" ]; then
    echo "   Note: Add a 128x128 PNG icon at vscode-extension/images/icon.png"
    # Create minimal valid PNG (1x1 transparent)
    python3 -c "
import base64, pathlib
# Minimal 128x128 PNG (purple gradient placeholder)
png_b64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
pathlib.Path('images/icon.png').write_bytes(base64.b64decode(png_b64))
print('Placeholder icon created')
" 2>/dev/null || true
fi

# Create FunC syntax grammar if missing
mkdir -p syntaxes
if [ ! -f "syntaxes/func.tmGrammar.json" ]; then
    cat > syntaxes/func.tmGrammar.json << 'GRAMMAR'
{
  "name": "FunC",
  "scopeName": "source.func",
  "patterns": [
    {"name": "comment.line.semicolon.func", "match": ";.*$"},
    {"name": "keyword.control.func",
     "match": "\\b(if|else|elseif|while|do|until|return|repeat|throw|throw_if|throw_unless|accept_message|send_raw_message|raw_reserve)\\b"},
    {"name": "storage.type.func",
     "match": "\\b(int|cell|slice|builder|tuple|cont|var|_)\\b"},
    {"name": "keyword.other.func",
     "match": "\\b(impure|inline|inline_ref|method_id|forall|global|const|asm)\\b"},
    {"name": "string.quoted.double.func", "match": "\"[^\"]*\""},
    {"name": "constant.numeric.func", "match": "\\b(0x[0-9a-fA-F]+|[0-9]+)\\b"},
    {"name": "variable.language.func",
     "match": "\\b(now|cur_lt|block_lt|my_balance|get_balance|my_address)\\b"}
  ]
}
GRAMMAR
    echo "   FunC grammar created"
fi

# Compile TypeScript
echo "[2/4] Compiling TypeScript..."
npx tsc -p tsconfig.json 2>&1 | head -20

# Check compilation
if [ ! -f "out/extension.js" ]; then
    echo "❌ TypeScript compilation failed"
    exit 1
fi
echo "   ✓ out/extension.js compiled"

# Package
echo "[3/4] Packaging .vsix..."
npx vsce package --no-dependencies 2>&1

VSIX_FILE=$(ls -t *.vsix 2>/dev/null | head -1)
if [ -z "$VSIX_FILE" ]; then
    echo "❌ .vsix file not found after packaging"
    exit 1
fi
echo "   ✓ Created: $VSIX_FILE ($(du -sh "$VSIX_FILE" | cut -f1))"

# Install locally for testing
echo "[4/4] Installing locally for testing..."
code --install-extension "$VSIX_FILE" 2>/dev/null && \
    echo "   ✓ Installed in VS Code" || \
    echo "   Note: Install manually: code --install-extension $VSIX_FILE"

echo ""
echo "════════════════════════════════════════════════════"
echo "  Build complete: $VSIX_FILE"
echo ""
echo "  To install:  code --install-extension $VSIX_FILE"
echo "  To publish:  $0 --publish"
echo "════════════════════════════════════════════════════"

# Publish to Marketplace
if [ "$1" == "--publish" ]; then
    echo ""
    echo "Publishing to VS Code Marketplace..."
    echo "Requirements:"
    echo "  1. Create publisher at https://marketplace.visualstudio.com/manage"
    echo "  2. Get PAT token from https://dev.azure.com"
    echo "  3. Run: npx vsce login ghost-security"
    echo ""
    read -p "Have you logged in with vsce login? (y/N): " confirm
    if [ "$confirm" == "y" ]; then
        npx vsce publish
        echo "✓ Published to Marketplace!"
        echo "  URL: https://marketplace.visualstudio.com/items?itemName=ghost-security.ghost-security"
    else
        echo "Login first: npx vsce login ghost-security"
    fi
fi
