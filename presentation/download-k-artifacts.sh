#!/usr/bin/env bash
# Download pre-built K artifacts from GitHub Releases and install them
# into the kdist cache so the server can use the K backend.
#
# Usage: ./presentation/download-k-artifacts.sh
# For private repos, set GITHUB_TOKEN env var.

set -euo pipefail

REPO="zojize/bitcoin-script"
TAG="k-artifacts"
ASSET="k-linux-x86_64.tar.gz"

# --- Download ---
echo "==> Downloading K artifacts..."
TMPDIR=$(mktemp -d)

if [ -n "${GITHUB_TOKEN:-}" ]; then
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
  curl -fsSL \
    "https://github.com/$REPO/releases/download/$TAG/$ASSET" \
    -o "$TMPDIR/$ASSET"
fi

# --- Compute kdist cache path ---
# pyk computes: XDG_CACHE_HOME / "kdist-{sha256(str({'module-dir': pyk_dir}))[:7]}"
# We replicate that exactly.
echo "==> Computing kdist cache path..."
CACHE_DIR=$(uv run python3 -c "
import hashlib, pathlib, pyk
module_dir = str(pathlib.Path(pyk.__file__).parent)
digest = hashlib.sha256(str({'module-dir': module_dir}).encode('utf-8')).hexdigest()[:7]
from xdg_base_dirs import xdg_cache_home
print(xdg_cache_home() / f'kdist-{digest}' / 'bitcoin-script-semantics')
")

echo "==> Installing to $CACHE_DIR"
mkdir -p "$CACHE_DIR"
tar xzf "$TMPDIR/$ASSET" -C "$CACHE_DIR"
rm -rf "$TMPDIR"

# --- Verify ---
if [ -f "$CACHE_DIR/llvm/compiled.json" ]; then
  echo "==> K artifacts installed successfully!"
  echo "    llvm:     $CACHE_DIR/llvm/"
  echo "    llvm-lib: $CACHE_DIR/llvm-lib/"
else
  echo "Error: compiled.json not found after extraction"
  ls -laR "$CACHE_DIR/" 2>/dev/null
  exit 1
fi
