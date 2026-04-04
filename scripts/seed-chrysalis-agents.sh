#!/usr/bin/env bash
# seed-chrysalis-agents.sh
#
# Verifies that a running Chrysalis registry has been seeded with catalog
# agents and reports a summary of what is available.
#
# Chrysalis auto-seeds the full PAP agent catalog from the TOML files at
# crates/pap-agents/catalog/ on first boot (when the database is empty).
# There is no need to POST agents manually — the registry bootstraps itself.
#
# Usage:
#   ./scripts/seed-chrysalis-agents.sh [CHRYSALIS_URL]
#
# Default URL: http://localhost:7890
# Requires: curl, jq
#
# To register a NEW agent at runtime (requires admin token + signed advertisement):
#   See docs/specification.md §5 — advertisements must carry an Ed25519 signature
#   from the operator's did:key DID. The server rejects unsigned submissions.

set -euo pipefail

CHRYSALIS_URL="${1:-http://localhost:7890}"

echo "Checking Chrysalis catalog at $CHRYSALIS_URL..."
echo ""

# ── Federation identity ────────────────────────────────────────────────────────
echo "Federation identity:"
identity=$(curl -s "$CHRYSALIS_URL/federation/identity")
node_did=$(echo "$identity" | jq -r '.did // "unknown"')
agent_count=$(echo "$identity" | jq -r '.agent_count // 0')
peer_count=$(echo "$identity" | jq -r '.peer_count // 0')
echo "  DID:          $node_did"
echo "  Agents:       $agent_count"
echo "  Peers:        $peer_count"
echo ""

# ── Browse agents ──────────────────────────────────────────────────────────────
echo "Catalog agents (GET /api/browse):"
browse=$(curl -s "$CHRYSALIS_URL/api/browse")
total=$(echo "$browse" | jq 'length')
echo "  Total agents: $total"
echo ""

if [[ "$total" -eq 0 ]]; then
  echo "  No agents found. The registry may not have completed first-boot seeding."
  echo "  Restart Chrysalis against a fresh database to trigger auto-seeding:"
  echo "    rm -f ~/.local/share/pap-registry/*.db"
  echo "    ./scripts/start-chrysalis-dev.sh"
  exit 1
fi

# ── Capability summary ─────────────────────────────────────────────────────────
echo "Capabilities in use (schema.org action types):"
echo "$browse" | jq -r '.[].capabilities[]' | sort -u | while read -r cap; do
  echo "  $cap"
done
echo ""

# ── Domain coverage ────────────────────────────────────────────────────────────
echo "Sample agents by domain:"
echo ""

domains=(
  "search"
  "weather"
  "movie"
  "music"
  "book"
  "news"
  "travel"
  "finance"
  "health"
  "job"
)

for domain in "${domains[@]}"; do
  sample=$(echo "$browse" | jq -r --arg d "$domain" \
    'map(select(.name | ascii_downcase | contains($d))) | .[0].name // ""')
  if [[ -n "$sample" ]]; then
    echo "  [$domain] $sample"
  fi
done
echo ""

# ── Quick validation ───────────────────────────────────────────────────────────
echo "Validation:"
invalid=$(echo "$browse" | jq '[.[] | select(.capabilities | map(startswith("schema:")) | all | not)] | length')
if [[ "$invalid" -gt 0 ]]; then
  echo "  WARNING: $invalid agent(s) have capabilities without schema: prefix"
else
  echo "  All $total agents have schema: prefixed capabilities ✓"
fi

dup_check=$(echo "$browse" | jq '[.[].content_hash] | length - (unique | length)')
if [[ "$dup_check" -gt 0 ]]; then
  echo "  WARNING: $dup_check duplicate content_hash(es) found"
else
  echo "  All content_hash values are unique ✓"
fi
echo ""

echo "Chrysalis is ready. Connect from Papillon:"
echo "  Fleet page → CHRYSALIS DROP-INS sidebar → $CHRYSALIS_URL"
echo ""
echo "Run integration tests:"
echo "  CHRYSALIS_URL=$CHRYSALIS_URL npx playwright test chrysalis-integration --reporter=line"
