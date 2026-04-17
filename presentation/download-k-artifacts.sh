#!/usr/bin/env bash
# Download pre-built K artifacts from GitHub Releases and install them
# into a fixed kdist directory. Set KDIST_DIR env var to the same path
# at runtime so pyk finds them.
#
# Usage: ./presentation/download-k-artifacts.sh
# For private repos, set GITHUB_TOKEN env var.

set -euo pipefail

REPO="zojize/bitcoin-script"
TAG="k-artifacts"
ASSET="k-linux-x86_64.tar.gz"

# Fixed path — must match KDIST_DIR env var at runtime
KDIST_DIR="${KDIST_DIR:-/opt/render/project/src/.kdist}"
CACHE_DIR="$KDIST_DIR/bitcoin-script-semantics"

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

# --- Install ---
echo "==> Installing to $CACHE_DIR"
mkdir -p "$CACHE_DIR"
tar xzf "$TMPDIR/$ASSET" -C "$CACHE_DIR"

# Install bundled shared libraries if present
SYSLIBS_DIR="$CACHE_DIR/k-syslibs"
if [ -d "$SYSLIBS_DIR" ]; then
  LIB_INSTALL="$KDIST_DIR/lib"
  mkdir -p "$LIB_INSTALL"
  cp "$SYSLIBS_DIR"/* "$LIB_INSTALL/"
  echo "==> Installed shared libraries to $LIB_INSTALL"
  ls -lh "$LIB_INSTALL/"
fi
rm -rf "$TMPDIR"

# --- Verify ---
if [ -f "$CACHE_DIR/llvm/compiled.json" ]; then
  echo "==> K artifacts installed successfully!"
  echo "    KDIST_DIR=$KDIST_DIR"
  echo "    llvm:     $CACHE_DIR/llvm/"
  echo "    llvm-lib: $CACHE_DIR/llvm-lib/"
  if [ -d "$LIB_INSTALL" ]; then
    echo "    libs:     $LIB_INSTALL/"
    echo ""
    echo "    Add to Render env: LD_LIBRARY_PATH=$LIB_INSTALL"
  fi
else
  echo "Error: compiled.json not found after extraction"
  ls -laR "$CACHE_DIR/" 2>/dev/null
  exit 1
fi
