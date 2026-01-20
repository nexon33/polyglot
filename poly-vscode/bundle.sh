#!/bin/bash
# Bundle polyglot binaries into the VS Code extension

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🔨 Building Polyglot release binaries..."
cd "$PROJECT_ROOT"
cargo build --release

echo "📦 Creating bin directory..."
mkdir -p "$SCRIPT_DIR/bin"

echo "📋 Copying binaries..."
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    cp "$PROJECT_ROOT/target/release/polyglot.exe" "$SCRIPT_DIR/bin/"
    cp "$PROJECT_ROOT/target/release/poly-lsp.exe" "$SCRIPT_DIR/bin/"
else
    cp "$PROJECT_ROOT/target/release/polyglot" "$SCRIPT_DIR/bin/"
    cp "$PROJECT_ROOT/target/release/poly-lsp" "$SCRIPT_DIR/bin/"
fi

echo "🧹 Compiling TypeScript..."
cd "$SCRIPT_DIR"
npm run compile

echo "📦 Packaging extension..."
npx vsce package

echo "✅ Done! Extension packaged with bundled binaries."
ls -la *.vsix
