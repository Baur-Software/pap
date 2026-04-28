# Federation Test Suite Design

**Date:** 2026-04-27  
**Status:** Approved  
**Goal:** Create comprehensive integration tests that verify federation sync works correctly across 3-4 registry instances using full UI automation

## Overview

This spec describes an end-to-end test suite for PAP registry federation. The suite validates that agent advertisements propagate correctly across multiple registry instances using different publishing methods (API, pre-seeding, UI) and network topologies (star, mesh, chain).

## Requirements

### Primary Goal
Verify federation sync validation: when Registry A peers with B, C, D, agent advertisements propagate correctly across the network with support for:
- Direct peer-to-peer sync
- Transitive discovery (multi-hop)
- Conflict resolution and deduplication
- Incremental sync (late joiners)
- Network failure recovery

### Testing Scope
- **Full UI automation** using Playwright (not just API tests)
- **Mixed publishing methods**: API POST, pre-seeded TOML files, Agent Designer UI
- **Mixed topology**: Star, mesh, chain, and custom patterns
- **Real catalog agents** from `crates/pap-agents/catalog/`
- **Chaos testing**: Network partitions, container failures, timeouts, resource exhaustion

## Architecture

### Infrastructure Setup

**Docker Compose Configuration** (`apps/registry/e2e/docker-compose.federation.yml`):

Four registry instances with this topology:
```
Registry A (hub)  ←→  Registry B
     ↕                    ↕
Registry C        ←→  Registry D
     ↕___________________↑
```

This topology provides:
- Star pattern: A as hub connected to B and C
- Mesh pattern: C↔D direct peering
- Chain pattern: A→C→D transitive path

**Port Allocation** (avoiding user's 7890 instance):
- Registry A: 7900 (host) → 7890 (container)
- Registry B: 7901 (host) → 7890 (container)
- Registry C: 7902 (host) → 7890 (container)
- Registry D: 7903 (host) → 7890 (container)

**Parallel Execution** (resource-optimized):
Each Playwright worker spawns isolated port ranges:
- Worker 0: 7900-7903
- Worker 1: 7910-7913
- Worker 2: 7920-7923
- Worker 3: 7930-7933

This enables up to 16 concurrent registry containers (4 workers × 4 registries).

**Container Configuration**:
- Isolated volumes: `registry_data_{a,b,c,d}` per instance
- Environment:
  - `PAP_REGISTRY_ENDPOINT`: https://localhost:790X
  - `PAP_REGISTRY_NO_TLS=true` (avoid cert issues in testing)
  - `LEPTOS_SITE_ROOT=/app/site`
  - No admin tokens (unauthenticated for easier automation)
- Healthchecks: Wait for `/federation/identity` before tests start
- Network: Single Docker network `federation-test-net`
- Resources: 512MB memory per container, tmpfs for DB (faster I/O)

### Test File Structure

```
apps/registry/e2e/
├── docker-compose.federation.yml      # 4 registry infrastructure
├── playwright.config.ts               # Parallel workers config
├── tests/
│   ├── federation-sync.spec.ts        # Main test suite (10 scenarios)
│   └── federation-chaos.spec.ts       # Failure mode tests (opt-in)
└── helpers/
    ├── federation-helpers.ts          # UI automation helpers
    ├── docker-helpers.ts              # Container lifecycle
    └── chaos-helpers.ts               # Failure injection
```

## Test Scenarios

### Core Federation Tests (federation-sync.spec.ts)

**Test 1: Direct Sync (Star Pattern)**
- Registry A: Publish `github_repos`, `npm_registry` via API POST
- Registry B: Pre-seeded with `hacker_news`, `docker_hub`
- Use Playwright to add B as peer to A via UI
- Verify A's UI shows all 4 agents (2 local + 2 from B)
- Verify B's UI shows all 4 agents (2 local + 2 from A)
- **Validates:** Basic peer-to-peer sync, UI peer management

**Test 2: Transitive Discovery (Chain Pattern)**
- Registry A: Publish `github_repos`
- Add peers via UI: A↔C, C↔D (no direct A↔D)
- Verify `github_repos` appears on D (multi-hop propagation)
- **Validates:** Transitive federation without direct peering

**Test 3: Conflict Resolution (Duplicate Handling)**
- Registry A: Publish "SearchAgent" with action "schema:SearchAction"
- Registry B: Publish "SearchAgent" with same action (different DID)
- Peer A↔B via UI
- Verify both registries show both agents (kept since different publishers)
- **Validates:** Identity-based deduplication, not name-based

**Test 4: Incremental Sync (Late Joiner)**
- Registries A, B, C already peered with agents
- Start Registry D fresh
- Use UI to add D as peer to A, B, C
- Verify D catches up and shows all agents from network
- **Validates:** New peer syncs existing network state

**Test 5: Full Mesh Propagation**
- Peer all registries: A↔B, A↔C, A↔D, B↔C, B↔D, C↔D via UI
- Each registry publishes 1 unique agent (4 total)
- Verify all registries end up with 4 agents
- **Validates:** Mesh network eventually consistent

### Chaos/Failure Tests (federation-chaos.spec.ts)

**Test 6: Network Partition (Split Brain)**
- Start with full mesh, all synced
- Partition network: {A,B} vs {C,D} using `docker network disconnect`
- Publish new agents in both partitions
- Verify each partition has diverged state
- Reconnect: `docker network connect`
- Verify eventual consistency and conflict-free merge
- **Validates:** Split-brain recovery

**Test 7: Cascading Failure**
- Chain topology: A→B→C→D
- Kill Registry B mid-sync: `docker kill registry-b`
- Verify C and D still accessible but isolated from A
- Restart B: `docker start registry-b`
- Verify sync resumes and completes
- **Validates:** Resilience to intermediate node failure

**Test 8: Slow Peer (Timeout Handling)**
- Add 5s network delay to Registry B: `tc qdisc add dev eth0 root netem delay 5000ms`
- Registry A tries to sync with slow B
- Verify timeout occurs gracefully (no hang)
- Verify A continues syncing with C and D
- **Validates:** Non-blocking sync, timeout enforcement

**Test 9: Concurrent Conflict (Race Condition)**
- Registries A and B both publish agent with same name simultaneously
- Both then peer with each other
- Verify deterministic conflict resolution
- **Validates:** Concurrent write handling

**Test 10: Resource Exhaustion**
- Registry A has 100+ agents
- New Registry D peers and syncs all at once
- Verify D handles large sync batch without OOM/crash
- **Validates:** Large dataset handling

## Agent Publishing Methods

Each registry uses different publishing methods to test all user workflows:

**Registry A: API POST**
- Playwright makes POST requests to `/admin/agents`
- Publishes: `github_repos`, `npm_registry` from catalog
- **Tests:** Headless/scripted publishing

**Registry B: Pre-seeded via Environment**
- Docker compose mounts agent TOML files
- `PAP_REGISTRY_SEED_DIR=/app/seed-agents` env var
- Pre-loaded: `hacker_news`, `docker_hub`
- **Tests:** Operator pre-seeding at deployment

**Registry C: Agent Designer UI**
- Playwright navigates to `/agents/new`
- Fills form fields (name, provider, action, returns, etc.)
- Clicks "Publish" button
- Creates: `art_institute_chicago` manually
- **Tests:** Interactive UI publishing workflow

**Registry D: Mixed (API + UI)**
- API: `crates_io`
- UI: `rijksmuseum`
- **Tests:** Coexistence of both methods

All agents sourced from `crates/pap-agents/catalog/` for realism.

## Helper Utilities

### Federation Helpers (federation-helpers.ts)

```typescript
// Add a peer via UI
async addPeerViaUI(page: Page, peerEndpoint: string, trustMode = 'tofu'): Promise<void>
  → Navigate to /peers
  → Click "+ Add Peer" button
  → Fill endpoint input
  → Select trust mode dropdown
  → Click "Add" button
  → Wait for success banner

// Publish agent via API
async publishAgentViaAPI(registryUrl: string, agentToml: string): Promise<void>
  → Parse TOML to JSON
  → POST to /admin/agents
  → Verify 200 response

// Publish agent via UI (Agent Designer)
async publishAgentViaUI(page: Page, agentData: AgentFormData): Promise<void>
  → Navigate to /agents/new
  → Fill form fields (name, provider, action, returns, disclosure)
  → Click "Publish" button
  → Wait for success message

// Wait for agent to appear in list
async waitForAgentInList(page: Page, agentName: string, timeout = 10000): Promise<boolean>
  → Navigate to /agents
  → Poll every 1s until agent appears in table
  → Return true if found, false if timeout

// Get agent count from UI
async getAgentCount(page: Page): Promise<number>
  → Navigate to /dashboard
  → Read agent count from stat card
  → Parse and return integer

// Trigger manual sync (if button exists)
async triggerSync(page: Page, peerEndpoint: string): Promise<void>
  → Navigate to /peers
  → Find peer row by endpoint
  → Click "Sync Now" button
  → Wait for sync completion indicator
```

### Docker Helpers (docker-helpers.ts)

```typescript
// Start all registries
async startFederationCluster(workerIndex = 0): Promise<void>
  → Calculate port offset: 7900 + (workerIndex * 10)
  → docker compose -f docker-compose.federation.yml up -d
  → Override ports via env vars
  → Wait for all healthchecks (30s timeout per registry)

// Stop and cleanup
async stopFederationCluster(): Promise<void>
  → docker compose -f docker-compose.federation.yml down -v
  → Remove volumes

// Reset specific registry DB
async resetRegistryDB(registryName: string): Promise<void>
  → docker compose restart registry-{name}
  → Set PAP_REGISTRY_RESET_DB=true env var
  → Wait for restart

// Get container logs
async getRegistryLogs(registryName: string): Promise<string>
  → docker logs registry-{name}
  → Return full log output
```

### Chaos Helpers (chaos-helpers.ts)

```typescript
// Network partition
async partitionNetwork(groupA: string[], groupB: string[]): Promise<void>
  → For each container in groupA:
      docker network disconnect federation-test-net {container}
  → Create isolated network for each group
  → Reconnect containers to their group networks

// Reconnect network
async reconnectNetwork(containers: string[]): Promise<void>
  → For each container:
      docker network connect federation-test-net {container}

// Kill container
async killRegistry(name: string): Promise<void>
  → docker kill registry-{name}

// Restart with delay
async restartWithDelay(name: string, delayMs: number): Promise<void>
  → Wait delayMs
  → docker start registry-{name}
  → Wait for healthcheck

// Add network latency
async addNetworkDelay(name: string, delayMs: number): Promise<void>
  → docker exec registry-{name} tc qdisc add dev eth0 root netem delay {delayMs}ms

// Remove network effects
async resetNetwork(name: string): Promise<void>
  → docker exec registry-{name} tc qdisc del dev eth0 root

// Throttle CPU
async throttleCPU(name: string, cpuPercent: number): Promise<void>
  → docker update --cpus={cpuPercent} registry-{name}
```

## Error Handling & Edge Cases

### Failure Scenarios

**Network Unreachable:**
- Stop Registry B container mid-test
- Verify A's UI shows peer as "offline" or "unreachable"
- Restart B, verify automatic reconnection
- **Validates:** Resilience to temporary network failures

**Invalid Peer Endpoint:**
- Try to add peer with invalid URL via UI (e.g., "https://no-such-host:9999")
- Verify error message appears in UI
- Verify peer is NOT added to the list
- **Validates:** Input validation and error messaging

**Sync Timeout:**
- Configure one registry with artificially slow response
- Verify sync doesn't hang indefinitely
- **Validates:** Timeout handling

**Conflicting Agent Signatures:**
- Two registries publish agents with same name but different DIDs
- Verify both are kept (identity-based, not name-based dedup)
- **Validates:** Proper deduplication logic

### Retry and Polling Strategy

All sync verification uses exponential backoff:
- Delays: 100ms, 200ms, 500ms, 1s, 2s, 5s
- Max timeout: 30s (configurable via `FEDERATION_SYNC_TIMEOUT` env var)
- If sync fails: Capture screenshots + container logs

### Test Isolation

**Per-test cleanup:**
- `beforeEach`: Reset all DBs via `PAP_REGISTRY_RESET_DB=true` environment flag
- Alternative: Use separate compose profiles per test (slower but cleaner)

**Debugging aids on failure:**
- Screenshot all 4 registry UIs
- Dump container logs to `e2e/logs/federation-{timestamp}/`
- Save network state: `docker network inspect federation-test-net`
- Capture docker-compose ps output

## CI Integration

### GitHub Actions Workflow

Add to `.github/workflows/ci.yml`:

```yaml
federation-e2e:
  runs-on: ubuntu-latest
  timeout-minutes: 15
  steps:
    - uses: actions/checkout@v4
    
    - name: Install Playwright
      run: cd apps/registry/e2e && npm ci && npx playwright install --with-deps chromium
    
    - name: Build registry image
      run: docker build -f apps/registry/Dockerfile -t pap-registry .
    
    - name: Run federation tests
      run: cd apps/registry/e2e && npx playwright test federation-sync.spec.ts --reporter=html
    
    - name: Upload test results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: federation-test-results
        path: apps/registry/e2e/playwright-report/
    
    - name: Upload logs on failure
      if: failure()
      uses: actions/upload-artifact@v4
      with:
        name: federation-logs
        path: apps/registry/e2e/logs/

federation-chaos:
  runs-on: ubuntu-latest
  timeout-minutes: 20
  if: github.event_name == 'schedule' || contains(github.event.head_commit.message, '[chaos]')
  steps:
    - uses: actions/checkout@v4
    - name: Install Playwright
      run: cd apps/registry/e2e && npm ci && npx playwright install --with-deps chromium
    - name: Build registry image
      run: docker build -f apps/registry/Dockerfile -t pap-registry .
    - name: Run chaos tests
      run: cd apps/registry/e2e && RUN_CHAOS_TESTS=true npx playwright test federation-chaos.spec.ts --reporter=html
    - name: Upload results
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: chaos-test-results
        path: apps/registry/e2e/playwright-report/
```

### Local Development

```bash
# Run full sync test suite
cd apps/registry/e2e
npm test federation-sync.spec.ts

# Run specific test
npm test federation-sync.spec.ts -g "Direct Sync"

# Debug mode (headed browser, slower execution)
npm test federation-sync.spec.ts --headed --debug

# Keep containers running after test (for inspection)
KEEP_CONTAINERS=true npm test federation-sync.spec.ts

# Run chaos tests (opt-in)
RUN_CHAOS_TESTS=true npm test federation-chaos.spec.ts

# Run with specific worker count
npm test -- --workers=2
```

## Performance & Resources

### With Parallel Execution (4 workers)

**Container resources:**
- Up to 16 registries running simultaneously (4 workers × 4 registries)
- Memory: 512MB per container = 8GB total for full parallel run
- CPU: No limits, use all available cores
- Disk: tmpfs for DB volumes (faster I/O, auto-cleared)

**Performance targets:**
- Container startup: ~40s (parallelized across workers)
- Each test scenario: 20-40s
- **Total suite runtime: 2-3 minutes** (core tests)
- Chaos tests: +5-7 minutes (opt-in)

**Playwright configuration:**

```typescript
// playwright.config.ts
export default defineConfig({
  workers: 4, // Run 4 tests simultaneously
  fullyParallel: true,
  timeout: 60000, // 60s per test
  use: {
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
})
```

### Resource Requirements

**Minimum:**
- Docker: 8GB RAM
- Disk: 2GB (images + volumes)
- CPU: 4 cores

**Recommended (for parallel execution):**
- Docker: 12GB RAM
- Disk: 4GB (multiple worker volumes)
- CPU: 8+ cores

## Page Object Pattern

For maintainability, abstract UI interactions:

**PeersPage:**
- `addPeer(endpoint, trustMode)`: Click "+ Add Peer", fill form, submit
- `listPeers()`: Return array of peer objects from table
- `removePeer(endpoint)`: Find peer row, click remove button
- `triggerSync(endpoint)`: Click "Sync Now" button for peer
- `getPeerStatus(endpoint)`: Return "online" | "offline" | "syncing"

**AgentsPage:**
- `listAgents()`: Return array of agent objects from table
- `filterAgents(query)`: Use search/filter input
- `getAgentCount()`: Parse count from UI
- `viewAgent(name)`: Click agent row to view details

**AgentDesignerPage:**
- `fillForm(agentData)`: Fill all form fields
- `publish()`: Click publish button
- `getValidationErrors()`: Return array of error messages

**DashboardPage:**
- `getStats()`: Return object with agent_count, peer_count, etc.
- `getRecentActivity()`: Parse activity feed

## Success Criteria

The test suite is considered complete when:

1. ✅ All 5 core federation tests pass consistently
2. ✅ All 5 chaos tests pass (when enabled)
3. ✅ Tests run in < 3 minutes with parallel execution
4. ✅ Zero false positives (flaky tests)
5. ✅ CI integration works on GitHub Actions
6. ✅ Screenshots captured on failure
7. ✅ Container logs accessible for debugging
8. ✅ Mixed publishing methods all tested (API, pre-seed, UI)
9. ✅ All catalog agents federate correctly
10. ✅ Documentation covers local dev + CI usage

## Out of Scope

- Load testing (1000+ agents, 10+ registries) - separate performance suite
- Security testing (auth bypass, injection attacks) - separate security suite
- Browser compatibility (only Chromium for e2e) - cross-browser not needed for backend federation
- Mobile/responsive testing - registry is admin tool, desktop-focused
- Accessibility testing - separate audit process

## Open Questions

None - all design decisions approved.

## References

- Existing Papillon e2e tests: `apps/papillon/e2e/tests/chrysalis-integration.spec.ts`
- Federation crate: `crates/pap-federation/`
- Registry UI: `apps/registry/src/ui/pages/peers.rs`
- Docker Compose docs: `apps/registry/docker-compose.yml`
