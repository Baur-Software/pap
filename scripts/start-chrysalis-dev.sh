#!/usr/bin/env bash
# start-chrysalis-dev.sh
#
# Starts the Chrysalis PAP Registry in local development mode (plain HTTP,
# no TLS) so that Papillon can connect via navigate_registry().
#
# Usage:
#   ./scripts/start-chrysalis-dev.sh
#
# Environment:
#   PAP_REGISTRY_PORT          — TCP port, default 7890
#   PAP_REGISTRY_ADMIN_TOKEN   — optional Bearer token for admin routes
#
# After starting, connect from Papillon:
#   Fleet page → Chrysalis sidebar → enter  http://localhost:7890
#
# Or from the command line (example):
#   curl http://localhost:7890/api/status

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT="${PAP_REGISTRY_PORT:-7890}"
ADMIN_TOKEN="${PAP_REGISTRY_ADMIN_TOKEN:-}"

echo "Building Chrysalis registry (pap-registry)..."
cd "$REPO_ROOT"
cargo build -p pap-registry --release 2>&1 | tail -5

BINARY="$REPO_ROOT/target/release/pap-registry"
if [[ ! -f "$BINARY" ]]; then
  # Try debug build as fallback
  cargo build -p pap-registry 2>&1 | tail -5
  BINARY="$REPO_ROOT/target/debug/pap-registry"
fi

echo ""
echo "Starting Chrysalis on http://localhost:$PORT"
echo "  Admin API:   http://localhost:$PORT/api/status"
echo "  Browse:      http://localhost:$PORT/api/browse"
if [[ -n "$ADMIN_TOKEN" ]]; then
  echo "  Auth:        Bearer $ADMIN_TOKEN"
else
  echo "  Auth:        none (open — suitable for localhost only)"
fi
echo ""
echo "Connect from Papillon:"
echo "  Fleet page → Chrysalis sidebar → http://localhost:$PORT"
echo ""
echo "Press Ctrl-C to stop."
echo ""

exec env \
  PAP_REGISTRY_PORT="$PORT" \
  PAP_REGISTRY_NO_TLS=true \
  PAP_REGISTRY_ENDPOINT="http://localhost:$PORT" \
  PAP_REGISTRY_ADMIN_TOKEN="${ADMIN_TOKEN}" \
  "$BINARY"
