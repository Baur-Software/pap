#!/usr/bin/env bash
# Build Python wheels for the PAP SDK locally.
#
# Usage:
#   ./scripts/build-wheels.sh              # Build wheel (release)
#   ./scripts/build-wheels.sh --debug      # Debug build
#   ./scripts/build-wheels.sh --sdist      # Source distribution only
#
# Prerequisites: Rust toolchain, Python 3.8+, maturin (pip install maturin)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(dirname "$SCRIPT_DIR")"
WORKSPACE_DIR="$(cd "$CRATE_DIR/../.." && pwd)"
DIST_DIR="$CRATE_DIR/dist"

BUILD_MODE="--release"
BUILD_SDIST=false

for arg in "$@"; do
  case "$arg" in
    --debug)   BUILD_MODE="" ;;
    --release) BUILD_MODE="--release" ;;
    --sdist)   BUILD_SDIST=true ;;
    *)         echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

if ! command -v maturin &>/dev/null; then
  echo "Error: maturin not found. Install with: pip install maturin"
  exit 1
fi

echo "=== PAP Python SDK Wheel Builder ==="
echo "Workspace: $WORKSPACE_DIR"
echo "Crate:     $CRATE_DIR"
echo "Output:    $DIST_DIR"
echo ""

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

if [ "$BUILD_SDIST" = true ]; then
  echo "Building source distribution..."
  cd "$WORKSPACE_DIR"
  maturin sdist \
    --out "$DIST_DIR" \
    --manifest-path "$CRATE_DIR/Cargo.toml"
else
  echo "Building wheel ($BUILD_MODE)..."
  cd "$WORKSPACE_DIR"
  # shellcheck disable=SC2086
  maturin build \
    $BUILD_MODE \
    --out "$DIST_DIR" \
    --manifest-path "$CRATE_DIR/Cargo.toml"
fi

echo ""
echo "=== Build complete ==="
ls -lh "$DIST_DIR"
echo ""
echo "Install with:"
echo "  pip install $DIST_DIR/*.whl"
