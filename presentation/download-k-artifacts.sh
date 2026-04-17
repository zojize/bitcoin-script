#!/usr/bin/env bash
# Download pre-built K artifacts from GitHub Releases and install them
# into the kdist cache so the server can use the K backend.
#
# Usage: ./presentation/download-k-artifacts.sh
#
# For private repos, set GITHUB_TOKEN env var.

set -euo pipefail

REPO="zojize/bitcoin-script"
TAG="k-artifacts"
ASSET="k-linux-x86_64.tar.gz"

echo "==> Downloading K artifacts..."
TMPDIR=$(mktemp -d)

if [ -n "${GITHUB_TOKEN:-}" ]; then
  # Private repo: use API to get the asset download URL
  ASSET_URL=$(curl -fsSL \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$REPO/releases/tags/$TAG" \
    | python3 -c "import json,sys; assets=json.load(sys.stdin)['assets']; print(next(a['url'] for a in assets if a['name']=='$ASSET'))")

  curl -fsSL \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/octet-stream" \
    "$ASSET_URL" \
    -o "$TMPDIR/$ASSET"
else
  # Public repo: direct download
  curl -fsSL \
    "https://github.com/$REPO/releases/download/$TAG/$ASSET" \
    -o "$TMPDIR/$ASSET"
fi

echo "==> Finding kdist cache dir..."
# Use uv run so pyk resolves within the project venv
CACHE_DIR=$(uv run python3 -c "
from pyk.kdist import kdist
tid = kdist._resolve('bitcoin-script-semantics.llvm')
print(kdist._target_dir(tid).parent)
" 2>/dev/null || echo "")

if [ -z "$CACHE_DIR" ]; then
  # Fallback: compute from kdist hash
  CACHE_DIR=$(uv run python3 -c "
from pyk.kdist._kdist import KDist
kd = KDist()
tid = kd._resolve('bitcoin-script-semantics.llvm')
print(kd._target_dir(tid).parent)
" 2>/dev/null || echo "")
fi

if [ -z "$CACHE_DIR" ]; then
  # Last resort: find or create the kdist dir
  XDG_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}"
  EXISTING=$(find "$XDG_CACHE" -maxdepth 1 -name "kdist-*" -type d 2>/dev/null | head -1)
  if [ -n "$EXISTING" ]; then
    CACHE_DIR="$EXISTING/bitcoin-script-semantics"
  else
    # Trigger kdist to create its cache dir by querying it
    uv run python3 -c "from pyk.kdist import kdist; kdist.get_or_none('bitcoin-script-semantics.source')" 2>/dev/null || true
    EXISTING=$(find "$XDG_CACHE" -maxdepth 1 -name "kdist-*" -type d 2>/dev/null | head -1)
    if [ -n "$EXISTING" ]; then
      CACHE_DIR="$EXISTING/bitcoin-script-semantics"
    else
      echo "Error: Cannot find or create kdist cache directory"
      exit 1
    fi
  fi
fi

echo "==> Installing to $CACHE_DIR"
mkdir -p "$CACHE_DIR"
tar xzf "$TMPDIR/$ASSET" -C "$CACHE_DIR"
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
