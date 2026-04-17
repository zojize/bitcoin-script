#!/usr/bin/env bash
# Download pre-built K artifacts from GitHub Releases and install them
# into the kdist cache so the server can use the K backend.
#
# Usage: ./presentation/download-k-artifacts.sh
#
# No authentication required (public repo release asset).

set -euo pipefail

RELEASE_URL="https://github.com/zojize/bitcoin-script/releases/download/k-artifacts/k-linux-x86_64.tar.gz"

echo "==> Downloading K artifacts from release..."
TMPDIR=$(mktemp -d)
curl -fsSL "$RELEASE_URL" -o "$TMPDIR/k-linux-x86_64.tar.gz"

echo "==> Finding kdist cache dir..."
CACHE_DIR=$(python3 -c "
from pyk.kdist._kdist import KDist
from pyk.kdist import kdist
tid = kdist._resolve('bitcoin-script-semantics.llvm')
print(kdist._target_dir(tid).parent)
" 2>/dev/null || echo "")

if [ -z "$CACHE_DIR" ]; then
  XDG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
  CACHE_DIR=$(find "$XDG_CACHE" -maxdepth 1 -name "kdist-*" -type d 2>/dev/null | head -1)
  if [ -n "$CACHE_DIR" ]; then
    CACHE_DIR="$CACHE_DIR/bitcoin-script-semantics"
  else
    echo "Error: Cannot find kdist cache directory"
    echo "Make sure pyk is installed: uv sync"
    exit 1
  fi
fi

echo "==> Installing to $CACHE_DIR"
mkdir -p "$CACHE_DIR"
tar xzf "$TMPDIR/k-linux-x86_64.tar.gz" -C "$CACHE_DIR"
rm -rf "$TMPDIR"

echo "==> Verifying..."
if [ -f "$CACHE_DIR/llvm/compiled.json" ]; then
  echo "==> K artifacts installed successfully!"
  echo "    llvm:     $CACHE_DIR/llvm/"
  echo "    llvm-lib: $CACHE_DIR/llvm-lib/"
else
  echo "Error: compiled.json not found after extraction"
  ls -la "$CACHE_DIR/" 2>/dev/null
  exit 1
fi
