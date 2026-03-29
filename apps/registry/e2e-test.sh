#!/usr/bin/env bash
# ── Chrysalis Registry E2E Regression Test ─────────────────────────────────
# Runs against a live Docker container. Tests the full agent lifecycle:
#   1. Health / federation identity endpoint
#   2. Agent creation (signed Ed25519 advertisement)
#   3. Agent listing + search
#   4. Agent appears in federation query (network advertisement)
#   5. Peer management (add/list/remove)
#   6. Agent deletion
set -uo pipefail

BASE_URL="${PAP_REGISTRY_URL:-https://localhost:7890}"
PASS=0
FAIL=0
TOTAL=0

# Use whichever python has nacl available
PY=python
if ! $PY -c "from nacl.signing import SigningKey" 2>/dev/null; then
    PY=python3
fi

# ── Helpers ─────────────────────────────────────────────────────────────────

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); echo "  FAIL: $1 — $2"; }

assert_status() {
    local desc="$1" url="$2" expected="$3" method="${4:-GET}" body="${5:-}"
    local args=(-sk -o /dev/null -w '%{http_code}' -X "$method")
    if [ -n "$body" ]; then
        args+=(-H 'Content-Type: application/json' -d "$body")
    fi
    local status
    status=$(curl "${args[@]}" "$url" 2>/dev/null || echo "000")
    if [ "$status" = "$expected" ]; then
        pass "$desc (HTTP $status)"
    else
        fail "$desc" "expected $expected, got $status"
    fi
}

pyjson() {
    $PY -c "import sys,json; d=json.loads(sys.stdin.read()); $1" 2>/dev/null
}

# ── Wait for registry to be ready ──────────────────────────────────────────

echo "=== Chrysalis Registry E2E Regression Test ==="
echo "Target: $BASE_URL"
echo ""

echo "--- Waiting for registry to be ready ---"
for i in $(seq 1 30); do
    if curl -sfk "$BASE_URL/federation/identity" > /dev/null 2>&1; then
        echo "  Registry is up (attempt $i)"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  FATAL: Registry did not become ready after 30 attempts"
        exit 1
    fi
    sleep 2
done
echo ""

# ── T1: Federation identity endpoint ───────────────────────────────────────

echo "--- T1: Federation Identity Endpoint ---"
assert_status "GET /federation/identity returns 200" "$BASE_URL/federation/identity" "200"

IDENTITY=$(curl -sk "$BASE_URL/federation/identity" 2>/dev/null)
NODE_DID=$(echo "$IDENTITY" | pyjson "print(d['did'])" || echo "")
if [ -n "$NODE_DID" ] && [[ "$NODE_DID" == did:key:* ]]; then
    pass "Node has valid DID ($NODE_DID)"
else
    fail "Node DID" "expected did:key:..., got '$NODE_DID'"
fi

FINGERPRINT=$(echo "$IDENTITY" | pyjson "print(d['cert_fingerprint'])" || echo "")
if [ -n "$FINGERPRINT" ] && [ ${#FINGERPRINT} -ge 32 ]; then
    pass "Node has cert fingerprint (${FINGERPRINT:0:16}...)"
else
    fail "Node cert fingerprint" "expected hex fingerprint, got '$FINGERPRINT'"
fi

AGENT_COUNT=$(echo "$IDENTITY" | pyjson "print(d['agent_count'])" || echo "")
PEER_COUNT=$(echo "$IDENTITY" | pyjson "print(d['peer_count'])" || echo "")
pass "Federation identity reports agent_count=$AGENT_COUNT, peer_count=$PEER_COUNT"
echo ""

# ── T2: Admin API — Status ─────────────────────────────────────────────────

echo "--- T2: Admin API Status ---"
assert_status "GET /api/status returns 200" "$BASE_URL/api/status" "200"

STATUS=$(curl -sk "$BASE_URL/api/status" 2>/dev/null)
VERSION=$(echo "$STATUS" | pyjson "print(d['version'])" || echo "")
if [ -n "$VERSION" ]; then
    pass "Registry version: $VERSION"
else
    fail "Registry version" "missing from /api/status"
fi
echo ""

# ── T3: Agent List (empty) ─────────────────────────────────────────────────

echo "--- T3: Agent List (initially empty) ---"
AGENTS_RESP=$(curl -sk "$BASE_URL/api/agents" 2>/dev/null)
AGENT_TOTAL=$(echo "$AGENTS_RESP" | pyjson "print(d['total'])" || echo "-1")
if [ "$AGENT_TOTAL" -ge 0 ] 2>/dev/null; then
    pass "Agent list returns paginated response (total=$AGENT_TOTAL)"
else
    fail "Agent list" "unexpected response: $AGENTS_RESP"
fi
echo ""

# ── T4: Register a signed agent ────────────────────────────────────────────

echo "--- T4: Register Signed Agent ---"

# Generate a signed agent advertisement using inline Python + Ed25519.
# This mirrors what gen_test_ad.rs does but from the client side.
# The JSON must match the Rust AgentAdvertisement struct exactly (JSON-LD with
# @context, @type, provider.@type, provider.did, capability as Vec<String>, etc.)
# Signing uses canonical JSON (compact, sorted keys) matching serde_json BTreeMap.
SIGNED_AD=$($PY << 'PYEOF'
import json, base64, sys
try:
    from nacl.signing import SigningKey
    from nacl.encoding import RawEncoder
except ImportError:
    print("", end="")
    sys.exit(1)

# Generate a fresh Ed25519 keypair
sk = SigningKey.generate()
vk = sk.verify_key

# Build did:key from public key (multicodec ed25519-pub = 0xed01)
pub_bytes = bytes(vk)
multicodec = bytes([0xed, 0x01]) + pub_bytes
# Base58 encode with z prefix (multibase base58btc)
ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58encode(data):
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r:r+1])
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0:1])
        else:
            break
    return b''.join(reversed(result)).decode()

did = "did:key:z" + b58encode(multicodec)

# Build the canonical object matching Rust's AgentAdvertisement::canonical_bytes().
# serde_json uses BTreeMap so all keys are sorted alphabetically at every level.
canonical = {
    "@context": "https://schema.org",
    "@type": "schema:Service",
    "capability": ["schema:SearchAction"],
    "name": "E2E Test Agent",
    "object_types": ["schema:Flight"],
    "provider": {
        "@type": "schema:Organization",
        "did": did,
        "name": "E2E TestCorp",
    },
    "requires_disclosure": ["schema:Person.name"],
    "returns": ["schema:Flight"],
    "signed_by": did,
    "ttl_min": 300,
}

# Sign canonical JSON bytes (compact, sorted keys — matches Rust serde_json::to_vec)
canonical_bytes = json.dumps(canonical, separators=(',', ':'), sort_keys=True).encode()
signed = sk.sign(canonical_bytes, encoder=RawEncoder)
sig_b64 = base64.urlsafe_b64encode(signed.signature).rstrip(b'=').decode()

# Full advertisement = canonical fields + signature
ad = dict(canonical)
ad["signature"] = sig_b64

print(json.dumps(ad))
PYEOF
)

AGENT_HASH=""
if [ -n "$SIGNED_AD" ]; then
    # Register the agent
    REG_RESP=$(curl -sk -X POST "$BASE_URL/api/agents" \
        -H 'Content-Type: application/json' \
        -d "$SIGNED_AD" 2>/dev/null)
    REG_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/agents" \
        -H 'Content-Type: application/json' \
        -d "$SIGNED_AD" 2>/dev/null)

    REG_OK=$(echo "$REG_RESP" | pyjson "print(d.get('ok',''))" || echo "")
    REG_HASH=$(echo "$REG_RESP" | pyjson "print(d.get('hash',''))" || echo "")
    REG_ERR=$(echo "$REG_RESP" | pyjson "print(d.get('error',''))" || echo "")

    if [ "$REG_OK" = "True" ] && [ -n "$REG_HASH" ]; then
        pass "Agent registered successfully (hash=$REG_HASH)"
        AGENT_HASH="$REG_HASH"
    elif [ -n "$REG_ERR" ]; then
        fail "Agent registration" "$REG_ERR"
    else
        fail "Agent registration" "unexpected response: $REG_RESP"
    fi
else
    echo "  SKIP: Could not generate signed agent advertisement (no PyNaCl)"
fi
echo ""

# ── T5: Register unsigned agent (should fail) ─────────────────────────────

echo "--- T5: Reject Unsigned Agent ---"
UNSIGNED_AD='{"@context":"https://schema.org","@type":"schema:Service","name":"UnsignedBot","provider":{"@type":"schema:Organization","name":"Corp","did":"did:key:zFakeKey"},"capability":[],"object_types":[],"requires_disclosure":[],"returns":[],"ttl_min":0,"signed_by":"did:key:zFakeKey","signature":null}'
assert_status "POST unsigned agent returns 422" "$BASE_URL/api/agents" "422" "POST" "$UNSIGNED_AD"
echo ""

# ── T6: Federation query ───────────────────────────────────────────────────

echo "--- T6: Federation Query (Network Advertisement) ---"
assert_status "GET /federation/query?action=schema:SearchAction returns 200" \
    "$BASE_URL/federation/query?action=schema:SearchAction" "200"

FED_RESP=$(curl -sk "$BASE_URL/federation/query?action=schema:SearchAction" 2>/dev/null)
if echo "$FED_RESP" | $PY -c "import sys,json; d=json.loads(sys.stdin.read()); assert 'advertisements' in str(d) or 'QueryResponse' in str(d)" 2>/dev/null; then
    pass "Federation query returns advertisement list"

    # If we registered an agent, check it appears in federation query
    if [ -n "$AGENT_HASH" ]; then
        AD_COUNT=$(echo "$FED_RESP" | pyjson "print(len(d.get('QueryResponse',{}).get('advertisements',d.get('advertisements',[]))))" || echo "0")
        if [ "$AD_COUNT" -gt 0 ] 2>/dev/null; then
            pass "Agent is advertised on the network ($AD_COUNT ads for schema:SearchAction)"
        else
            fail "Agent network advertisement" "expected >0 ads, got $AD_COUNT"
        fi
    fi
else
    fail "Federation query" "unexpected response format: $FED_RESP"
fi

# Wildcard query — federation query does exact action matching, so action=*
# returns empty unless an agent literally has "*" as a capability. This is by
# design in the protocol. We only verify the endpoint returns a valid 200.
assert_status "GET /federation/query?action=* returns 200" \
    "$BASE_URL/federation/query?action=*" "200"
echo ""

# ── T7: Peer management ───────────────────────────────────────────────────

echo "--- T7: Peer Management ---"
assert_status "GET /api/peers returns 200" "$BASE_URL/api/peers" "200"

# Add a test peer
PEER_BODY='{"did":"did:key:zE2EPeer","endpoint":"https://e2e-peer.example.com"}'
PEER_RESP=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/api/peers" \
    -H 'Content-Type: application/json' \
    -d "$PEER_BODY" 2>/dev/null)
if [ "$PEER_RESP" = "201" ]; then
    pass "Add peer returns 201"
else
    fail "Add peer" "expected 201, got $PEER_RESP"
fi

# Verify peer appears in list
PEERS=$(curl -sk "$BASE_URL/api/peers" 2>/dev/null)
if echo "$PEERS" | grep -q "zE2EPeer"; then
    pass "Peer appears in /api/peers list"
else
    fail "Peer listing" "did:key:zE2EPeer not found in response"
fi

# Also check federation peers endpoint
assert_status "GET /federation/peers returns 200" "$BASE_URL/federation/peers" "200"

FED_PEERS=$(curl -sk "$BASE_URL/federation/peers" 2>/dev/null)
if echo "$FED_PEERS" | grep -q "zE2EPeer"; then
    pass "Peer visible in /federation/peers"
else
    fail "Federation peer visibility" "zE2EPeer not in federation peers response"
fi

# Remove the test peer
DEL_PEER_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE \
    "$BASE_URL/api/peers/did%3Akey%3AzE2EPeer" 2>/dev/null)
if [ "$DEL_PEER_STATUS" = "200" ]; then
    pass "Delete peer returns 200"
else
    fail "Delete peer" "expected 200, got $DEL_PEER_STATUS"
fi
echo ""

# ── T8: Agent search ──────────────────────────────────────────────────────

echo "--- T8: Agent Search ---"
assert_status "GET /api/agents?q=test returns 200" \
    "$BASE_URL/api/agents?q=test" "200"

# If we registered an agent, search for it by name
if [ -n "$AGENT_HASH" ]; then
    SEARCH_RESP=$(curl -sk "$BASE_URL/api/agents?q=E2E" 2>/dev/null)
    SEARCH_TOTAL=$(echo "$SEARCH_RESP" | pyjson "print(d['total'])" || echo "0")
    if [ "$SEARCH_TOTAL" -gt 0 ] 2>/dev/null; then
        pass "Search finds registered agent (total=$SEARCH_TOTAL for 'E2E')"
    else
        fail "Agent search" "expected >0 results for 'E2E', got $SEARCH_TOTAL"
    fi
fi

# FTS special chars regression (I8)
assert_status "FTS special chars don't cause 500" \
    "$BASE_URL/api/agents?q=%22NOT%22%28%2A" "200"
echo ""

# ── T9: Agent deletion ────────────────────────────────────────────────────

echo "--- T9: Agent Deletion ---"
if [ -n "$AGENT_HASH" ]; then
    DEL_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' -X DELETE \
        "$BASE_URL/api/agents/$AGENT_HASH" 2>/dev/null)
    if [ "$DEL_STATUS" = "200" ]; then
        pass "Delete agent returns 200 (hash=$AGENT_HASH)"
    else
        fail "Delete agent" "expected 200, got $DEL_STATUS"
    fi

    # Verify agent no longer appears in specific action query after deletion
    POST_DEL=$(curl -sk "$BASE_URL/federation/query?action=schema:SearchAction" 2>/dev/null)
    POST_COUNT=$(echo "$POST_DEL" | pyjson "print(len(d.get('QueryResponse',{}).get('advertisements',d.get('advertisements',[]))))" || echo "0")
    if [ "$POST_COUNT" -eq 0 ] 2>/dev/null; then
        pass "Agent removed from federation after deletion"
    else
        fail "Agent removal" "expected 0 agents after deletion, got $POST_COUNT"
    fi
else
    echo "  SKIP: No agent hash from registration step"
fi

# Delete non-existent agent
assert_status "DELETE non-existent agent returns 404" \
    "$BASE_URL/api/agents/nonexistenthash123" "404" "DELETE"
echo ""

# ── T10: Pagination ───────────────────────────────────────────────────────

echo "--- T10: Pagination ---"
PAGINATED=$(curl -sk "$BASE_URL/api/agents?page=1&per_page=5" 2>/dev/null)
HAS_PAGE=$(echo "$PAGINATED" | pyjson "print('yes' if 'page' in d and 'per_page' in d and 'total_pages' in d else 'no')" || echo "no")
if [ "$HAS_PAGE" = "yes" ]; then
    pass "Paginated response has page/per_page/total_pages fields"
else
    fail "Pagination" "missing pagination fields in response"
fi
echo ""

# ── Summary ────────────────────────────────────────────────────────────────

echo "========================================"
echo "  Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "========================================"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
