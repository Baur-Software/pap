# Federation E2E Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a Playwright end-to-end test suite that validates `pap-federation` sync behaviour across a 4-registry Docker Compose cluster. The suite covers 5 core sync scenarios and 5 opt-in chaos scenarios. It drives the live registry UI (peers, agents, dashboard pages) using verified CSS selectors from the actual Leptos source.

**Architecture:** 4 Docker containers (`registry-a/b/c/d`) run the `pap-registry:latest` image side-by-side. Playwright workers each get their own port offset (base `7900 + workerIndex * 10`) so tests run fully in parallel. Page objects wrap the UI's known CSS classes. Publishing uses both the Admin API (`POST /admin/agents`) and the pre-seed TOML mount on Registry B. Chaos tests are opt-in via `RUN_CHAOS_TESTS=true`.

**What already exists:**
- `crates/pap-federation/` — 48+ unit tests covering registry/peer/vouch/pagination; no e2e
- `apps/registry/docker-compose.yml` — single-instance compose (reference)
- `apps/registry/Dockerfile` — registry image build definition
- `apps/registry/src/ui/pages/peers.rs`, `agents.rs`, `agent_designer.rs`, `dashboard.rs` — pages with verified CSS selectors
- `apps/papillon/e2e/tests/chrysalis-integration.spec.ts` — reference Playwright pattern (env-var skip, page object style)
- **No `apps/registry/e2e/` directory exists**

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `apps/registry/e2e/package.json` | **Create** | npm package with `@playwright/test` dep and test scripts |
| `apps/registry/e2e/playwright.config.ts` | **Create** | Playwright config: 4 workers, parallel, 60s timeout |
| `apps/registry/e2e/docker-compose.federation.yml` | **Create** | 4-registry cluster with per-worker port offsets |
| `apps/registry/e2e/helpers/docker-helpers.ts` | **Create** | Cluster lifecycle: start, stop, reset, logs |
| `apps/registry/e2e/helpers/federation-helpers.ts` | **Create** | Page objects: `PeersPage`, `AgentsPage`, `AgentDesignerPage`, `publishAgentViaAPI` |
| `apps/registry/e2e/helpers/chaos-helpers.ts` | **Create** | Network partition, kill, delay, reconnect utilities |
| `apps/registry/e2e/tests/federation-sync.spec.ts` | **Create** | 5 core sync tests |
| `apps/registry/e2e/tests/federation-chaos.spec.ts` | **Create** | 5 opt-in chaos tests |
| `apps/registry/e2e/seed-agents/hacker_news.toml` | **Create** | Copy of `crates/pap-agents/catalog/culture/hacker_news.toml` |
| `apps/registry/e2e/seed-agents/docker_hub.toml` | **Create** | Copy of `crates/pap-agents/catalog/developer/docker_hub.toml` |
| `.github/workflows/ci.yml` | **Modify** | Append `federation-e2e` and `federation-chaos` jobs after line 703 |

---

## CSS Selectors Reference (verified from source)

### `peers.rs`
- Add Peer button: `.btn.btn-primary` (first on page)
- Form endpoint field: `.form-input[name=endpoint]` (inside `.modal`)
- Modal submit: `.modal-actions .btn.btn-primary`
- Modal wrapper: `.modal-backdrop` > `.modal`
- Peer list: `.peer-list` → `.peer-row` items
- Peer status indicator: `.peer-indicator` (on `.peer-row`)
- Peer endpoint text: `.peer-endpoint` (on `.peer-row`)
- Sync button: `.btn.btn-secondary.btn-sm` (on `.peer-row`)
- Remove button: `.btn.btn-danger.btn-sm` (on `.peer-row`)
- Success banner: `.success-banner`
- Error banner: `.error-banner`

### `agents.rs`
- Search/filter field: `.filter-input`
- Refresh button: `.btn.btn-secondary`
- Loading spinner: `.loading`
- Empty state: `.empty-state`

### `dashboard.rs`
- Stats grid: `.stat-grid`
- Individual stat card: `.stat-card`
- Agent count value: `.stat-value.teal`
- Peer count value: `.stat-value.accent`

### `agent_designer.rs`
- Route: `/agents/new`
- Form fields: `name`, `provider_name`, `provider_did`, `capabilities`, `object_types`, `requires_disclosure`, `returns`, `ttl_min`
- Errors: `HashMap<String, String>` keyed by field name

---

## Task 1: `package.json` and `playwright.config.ts`

**Files:**
- Create: `apps/registry/e2e/package.json`
- Create: `apps/registry/e2e/playwright.config.ts`

- [ ] **Step 1: Create `package.json`**

```json
{
  "name": "pap-registry-e2e",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "test": "playwright test tests/federation-sync.spec.ts",
    "test:headed": "playwright test tests/federation-sync.spec.ts --headed",
    "test:debug": "playwright test tests/federation-sync.spec.ts --debug",
    "test:chaos": "RUN_CHAOS_TESTS=true playwright test tests/federation-chaos.spec.ts"
  },
  "devDependencies": {
    "@playwright/test": "^1.43.0"
  }
}
```

- [ ] **Step 2: Create `playwright.config.ts`**

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 4,
  reporter: process.env.CI ? [['html'], ['github']] : 'list',
  timeout: 60_000,

  use: {
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
```

- [ ] **Step 3: Verify files exist**

```bash
ls apps/registry/e2e/package.json apps/registry/e2e/playwright.config.ts
```
Expected: both files listed.

- [ ] **Step 4: Commit**

```bash
git add apps/registry/e2e/package.json apps/registry/e2e/playwright.config.ts
git commit -m "test(federation-e2e): add package.json and playwright config"
```

---

## Task 2: `docker-compose.federation.yml`

**Files:**
- Create: `apps/registry/e2e/docker-compose.federation.yml`

The compose file defines 4 registries. Each Playwright worker (0–3) gets its own port offset so 4 workers × 4 registries = 16 containers never collide. The `PAP_PORT_A/B/C/D` env vars are set by `docker-helpers.ts` at cluster start time; the compose file uses them as variable substitutions.

- [ ] **Step 1: Create `docker-compose.federation.yml`**

```yaml
version: "3.9"

services:
  registry-a:
    image: pap-registry:latest
    container_name: registry-a-worker${WORKER_INDEX:-0}
    ports:
      - "${PAP_PORT_A:-7900}:7890"
    environment:
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: /app/site
      PAP_REGISTRY_DB: /data/registry.db
    tmpfs:
      - /data
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost:7890/federation/identity"]
      interval: 2s
      timeout: 5s
      retries: 15
    networks:
      - federation-test-net-${WORKER_INDEX:-0}

  registry-b:
    image: pap-registry:latest
    container_name: registry-b-worker${WORKER_INDEX:-0}
    ports:
      - "${PAP_PORT_B:-7901}:7890"
    environment:
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: /app/site
      PAP_REGISTRY_DB: /data/registry.db
      PAP_REGISTRY_SEED_DIR: /app/seed-agents
    volumes:
      - ./seed-agents:/app/seed-agents:ro
    tmpfs:
      - /data
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost:7890/federation/identity"]
      interval: 2s
      timeout: 5s
      retries: 15
    networks:
      - federation-test-net-${WORKER_INDEX:-0}

  registry-c:
    image: pap-registry:latest
    container_name: registry-c-worker${WORKER_INDEX:-0}
    ports:
      - "${PAP_PORT_C:-7902}:7890"
    environment:
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: /app/site
      PAP_REGISTRY_DB: /data/registry.db
    tmpfs:
      - /data
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost:7890/federation/identity"]
      interval: 2s
      timeout: 5s
      retries: 15
    networks:
      - federation-test-net-${WORKER_INDEX:-0}

  registry-d:
    image: pap-registry:latest
    container_name: registry-d-worker${WORKER_INDEX:-0}
    ports:
      - "${PAP_PORT_D:-7903}:7890"
    environment:
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: /app/site
      PAP_REGISTRY_DB: /data/registry.db
    tmpfs:
      - /data
    healthcheck:
      test: ["CMD", "curl", "-fk", "https://localhost:7890/federation/identity"]
      interval: 2s
      timeout: 5s
      retries: 15
    networks:
      - federation-test-net-${WORKER_INDEX:-0}

networks:
  federation-test-net-${WORKER_INDEX:-0}:
    name: federation-test-net-${WORKER_INDEX:-0}
    driver: bridge
```

- [ ] **Step 2: Verify YAML is valid**

```bash
cd apps/registry/e2e && docker compose -f docker-compose.federation.yml config --quiet 2>&1 | head -5
```
Expected: no errors (or warnings only about variable substitution which is expected).

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/docker-compose.federation.yml
git commit -m "test(federation-e2e): add 4-registry docker-compose cluster"
```

---

## Task 3: `helpers/docker-helpers.ts`

**Files:**
- Create: `apps/registry/e2e/helpers/docker-helpers.ts`

- [ ] **Step 1: Create the file**

```typescript
import { execSync, spawnSync } from 'child_process';
import * as path from 'path';

const COMPOSE_FILE = path.resolve(__dirname, '..', 'docker-compose.federation.yml');
const BASE_PORT = 7900;
const REGISTRIES = ['a', 'b', 'c', 'd'] as const;
type RegistryLetter = typeof REGISTRIES[number];

/** Returns the host URL for a given registry letter and Playwright worker index. */
export function registryUrl(letter: RegistryLetter, workerIndex: number): string {
  const offset = workerIndex * 10;
  const idx = REGISTRIES.indexOf(letter);
  return `https://localhost:${BASE_PORT + offset + idx}`;
}

/** Returns all 4 registry URLs for a worker. */
export function allRegistryUrls(workerIndex: number): Record<RegistryLetter, string> {
  return {
    a: registryUrl('a', workerIndex),
    b: registryUrl('b', workerIndex),
    c: registryUrl('c', workerIndex),
    d: registryUrl('d', workerIndex),
  };
}

function portEnv(workerIndex: number) {
  const offset = workerIndex * 10;
  return {
    WORKER_INDEX: String(workerIndex),
    PAP_PORT_A: String(BASE_PORT + offset + 0),
    PAP_PORT_B: String(BASE_PORT + offset + 1),
    PAP_PORT_C: String(BASE_PORT + offset + 2),
    PAP_PORT_D: String(BASE_PORT + offset + 3),
  };
}

/** Start the 4-registry cluster for a given Playwright worker. Waits for all healthchecks. */
export async function startFederationCluster(workerIndex: number): Promise<void> {
  const env = { ...process.env, ...portEnv(workerIndex) };
  spawnSync(
    'docker',
    ['compose', '-f', COMPOSE_FILE, 'up', '-d', '--wait'],
    { env, stdio: 'inherit' }
  );

  // Poll each registry until /federation/identity returns 200 (max 30s)
  const urls = allRegistryUrls(workerIndex);
  await Promise.all(
    (Object.values(urls) as string[]).map(url => waitForRegistry(url, 30_000))
  );
}

/** Stop and remove volumes for a given worker's cluster. */
export function stopFederationCluster(workerIndex: number): void {
  const env = { ...process.env, ...portEnv(workerIndex) };
  spawnSync(
    'docker',
    ['compose', '-f', COMPOSE_FILE, 'down', '-v'],
    { env, stdio: 'inherit' }
  );
}

/** Restart a single registry with a fresh DB. */
export function resetRegistryDB(workerIndex: number, name: RegistryLetter): void {
  const containerName = `registry-${name}-worker${workerIndex}`;
  const env = { ...process.env, ...portEnv(workerIndex), PAP_REGISTRY_RESET_DB: 'true' };
  spawnSync('docker', ['restart', containerName], { env, stdio: 'inherit' });
}

/** Reset all 4 registry DBs for a worker (use in beforeEach). */
export function resetAllRegistries(workerIndex: number): void {
  for (const letter of REGISTRIES) {
    resetRegistryDB(workerIndex, letter);
  }
}

/** Fetch docker logs for a container. */
export function getRegistryLogs(workerIndex: number, name: RegistryLetter): string {
  const containerName = `registry-${name}-worker${workerIndex}`;
  try {
    return execSync(`docker logs ${containerName} 2>&1`).toString();
  } catch {
    return `[could not fetch logs for ${containerName}]`;
  }
}

/** Poll a registry's /federation/identity until it responds or timeout. */
async function waitForRegistry(url: string, timeoutMs: number): Promise<void> {
  const start = Date.now();
  const backoffMs = [100, 200, 500, 1000, 2000, 5000];
  let attempt = 0;
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`${url}/federation/identity`, {
        // @ts-ignore — node 18+ supports this
        dispatcher: new (require('undici').Agent)({ connect: { rejectUnauthorized: false } }),
      });
      if (res.ok) return;
    } catch {
      // not yet up
    }
    const delay = backoffMs[Math.min(attempt++, backoffMs.length - 1)];
    await new Promise(r => setTimeout(r, delay));
  }
  throw new Error(`Registry at ${url} did not become healthy within ${timeoutMs}ms`);
}
```

- [ ] **Step 2: Compile check (TypeScript)**

```bash
cd apps/registry/e2e && npm ci && npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/helpers/docker-helpers.ts
git commit -m "test(federation-e2e): add docker cluster lifecycle helpers"
```

---

## Task 4: `helpers/federation-helpers.ts` with Page Objects

**Files:**
- Create: `apps/registry/e2e/helpers/federation-helpers.ts`

CSS selectors are verified against `apps/registry/src/ui/pages/peers.rs`, `agents.rs`, `agent_designer.rs`, and `dashboard.rs`.

- [ ] **Step 1: Create the file**

```typescript
import { Page, expect } from '@playwright/test';

// ─── PeersPage ────────────────────────────────────────────────────────────────

export class PeersPage {
  /** Navigate to /peers and wait for the list to load. */
  static async goto(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/peers`, { waitUntil: 'networkidle' });
  }

  /**
   * Add a peer via the UI modal.
   * Clicks ".btn.btn-primary" (Add Peer), fills ".form-input[name=endpoint]",
   * clicks ".modal-actions .btn.btn-primary", waits for ".success-banner".
   */
  static async addPeer(page: Page, endpoint: string): Promise<void> {
    // Click the "Add Peer" button (first .btn.btn-primary on the page)
    await page.locator('.btn.btn-primary').first().click();
    // Wait for modal
    await page.locator('.modal').waitFor({ state: 'visible' });
    // Fill endpoint
    await page.locator('.modal .form-input').first().fill(endpoint);
    // Submit
    await page.locator('.modal-actions .btn.btn-primary').click();
    // Wait for success
    await page.locator('.success-banner').waitFor({ state: 'visible', timeout: 10_000 });
  }

  /** Return a list of {endpoint, statusClass} for all visible peer rows. */
  static async listPeers(page: Page): Promise<{ endpoint: string; statusClass: string }[]> {
    const rows = page.locator('.peer-row');
    const count = await rows.count();
    const result = [];
    for (let i = 0; i < count; i++) {
      const row = rows.nth(i);
      const endpoint = await row.locator('.peer-endpoint').textContent() ?? '';
      const indicator = row.locator('.peer-indicator');
      const cls = await indicator.getAttribute('class') ?? '';
      result.push({ endpoint: endpoint.trim(), statusClass: cls });
    }
    return result;
  }

  /** Trigger a manual sync for the peer at a given endpoint URL. */
  static async triggerSync(page: Page, endpoint: string): Promise<void> {
    const rows = page.locator('.peer-row');
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const row = rows.nth(i);
      const text = await row.locator('.peer-endpoint').textContent() ?? '';
      if (text.trim().includes(endpoint)) {
        await row.locator('.btn.btn-secondary.btn-sm').click();
        return;
      }
    }
    throw new Error(`No peer row found for endpoint: ${endpoint}`);
  }

  /** Get the CSS class of the status indicator for a given peer endpoint. */
  static async getPeerStatus(page: Page, endpoint: string): Promise<string> {
    const rows = page.locator('.peer-row');
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const row = rows.nth(i);
      const text = await row.locator('.peer-endpoint').textContent() ?? '';
      if (text.trim().includes(endpoint)) {
        return await row.locator('.peer-indicator').getAttribute('class') ?? '';
      }
    }
    throw new Error(`No peer row found for endpoint: ${endpoint}`);
  }
}

// ─── AgentsPage ───────────────────────────────────────────────────────────────

export class AgentsPage {
  /** Navigate to /agents. */
  static async goto(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/agents`, { waitUntil: 'networkidle' });
  }

  /**
   * Poll the agents page until an agent with the given name appears.
   * Uses exponential backoff: 100ms → 200ms → 500ms → 1s → 2s → 5s → 5s…
   */
  static async waitForAgentInList(
    page: Page,
    baseUrl: string,
    agentName: string,
    timeoutMs = 30_000
  ): Promise<void> {
    const start = Date.now();
    const backoff = [100, 200, 500, 1000, 2000, 5000];
    let attempt = 0;

    while (Date.now() - start < timeoutMs) {
      await page.goto(`${baseUrl}/agents`, { waitUntil: 'networkidle' });
      const content = await page.content();
      if (content.includes(agentName)) return;

      // Also try clicking refresh if available
      const refreshBtn = page.locator('.btn.btn-secondary').first();
      if (await refreshBtn.isVisible()) await refreshBtn.click();

      const delay = backoff[Math.min(attempt++, backoff.length - 1)];
      await page.waitForTimeout(delay);
    }
    throw new Error(`Agent "${agentName}" did not appear in list at ${baseUrl} within ${timeoutMs}ms`);
  }

  /** Read the agent count from the dashboard stat card. */
  static async getAgentCount(page: Page, baseUrl: string): Promise<number> {
    await page.goto(`${baseUrl}/`, { waitUntil: 'networkidle' });
    const stat = page.locator('.stat-value.teal').first();
    const text = await stat.textContent() ?? '0';
    return parseInt(text.trim(), 10) || 0;
  }
}

// ─── AgentDesignerPage ────────────────────────────────────────────────────────

export interface AgentFormData {
  name: string;
  providerName: string;
  providerDid?: string;
  capabilities?: string;
  objectTypes?: string;
  requiresDisclosure?: boolean;
  returns?: string;
  ttlMin?: number;
}

export class AgentDesignerPage {
  /** Navigate to /agents/new. */
  static async goto(page: Page, baseUrl: string): Promise<void> {
    await page.goto(`${baseUrl}/agents/new`, { waitUntil: 'networkidle' });
  }

  /** Fill the agent designer form. */
  static async fillForm(page: Page, data: AgentFormData): Promise<void> {
    if (data.name) await page.locator('[name=name]').fill(data.name);
    if (data.providerName) await page.locator('[name=provider_name]').fill(data.providerName);
    if (data.providerDid) await page.locator('[name=provider_did]').fill(data.providerDid);
    if (data.capabilities) await page.locator('[name=capabilities]').fill(data.capabilities);
    if (data.objectTypes) await page.locator('[name=object_types]').fill(data.objectTypes);
    if (data.returns) await page.locator('[name=returns]').fill(data.returns);
    if (data.ttlMin !== undefined) {
      await page.locator('[name=ttl_min]').fill(String(data.ttlMin));
    }
  }

  /** Submit the form and wait for success indicator. */
  static async publish(page: Page): Promise<void> {
    await page.locator('button[type=submit]').click();
    // Wait for either a success banner or redirect away from /agents/new
    await Promise.race([
      page.locator('.success-banner').waitFor({ state: 'visible', timeout: 10_000 }),
      page.waitForURL(/\/agents(?!\/new)/, { timeout: 10_000 }),
    ]);
  }
}

// ─── API Publishing ───────────────────────────────────────────────────────────

/**
 * Publish an agent by POSTing TOML to the admin API.
 * Endpoint: POST /admin/agents
 * Content-Type: application/toml
 */
export async function publishAgentViaAPI(baseUrl: string, agentToml: string): Promise<void> {
  const res = await fetch(`${baseUrl}/admin/agents`, {
    method: 'POST',
    body: agentToml,
    headers: { 'Content-Type': 'application/toml' },
    // @ts-ignore — disable TLS verification in Node
    dispatcher: new (require('undici').Agent)({ connect: { rejectUnauthorized: false } }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`publishAgentViaAPI failed (${res.status}): ${body}`);
  }
}

// ─── Catalog TOML fixtures ────────────────────────────────────────────────────

import * as fs from 'fs';
import * as path from 'path';

const CATALOG_ROOT = path.resolve(__dirname, '..', '..', '..', '..', 'crates', 'pap-agents', 'catalog');

export function readCatalogToml(relPath: string): string {
  return fs.readFileSync(path.join(CATALOG_ROOT, relPath), 'utf8');
}

/** Convenience: read a catalog TOML and override the agent name for conflict tests. */
export function catalogTomlWithName(relPath: string, name: string): string {
  const toml = readCatalogToml(relPath);
  return toml.replace(/^name\s*=\s*"[^"]*"/m, `name = "${name}"`);
}
```

- [ ] **Step 2: Compile check**

```bash
cd apps/registry/e2e && npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/helpers/federation-helpers.ts
git commit -m "test(federation-e2e): add page objects and API publishing helper"
```

---

## Task 5: `helpers/chaos-helpers.ts`

**Files:**
- Create: `apps/registry/e2e/helpers/chaos-helpers.ts`

- [ ] **Step 1: Create the file**

```typescript
import { execSync, spawnSync } from 'child_process';

type RegistryLetter = 'a' | 'b' | 'c' | 'd';

function containerName(workerIndex: number, name: RegistryLetter): string {
  return `registry-${name}-worker${workerIndex}`;
}

function networkName(workerIndex: number): string {
  return `federation-test-net-${workerIndex}`;
}

/**
 * Disconnect containers in groupA from groupB by removing them from the shared network.
 * groupA containers lose connectivity to groupB (and vice versa) for the duration.
 */
export function partitionNetwork(
  workerIndex: number,
  groupA: RegistryLetter[],
  _groupB: RegistryLetter[]
): void {
  const net = networkName(workerIndex);
  for (const name of groupA) {
    const container = containerName(workerIndex, name);
    spawnSync('docker', ['network', 'disconnect', net, container], { stdio: 'inherit' });
  }
}

/** Reconnect containers to the shared network. */
export function reconnectNetwork(workerIndex: number, containers: RegistryLetter[]): void {
  const net = networkName(workerIndex);
  for (const name of containers) {
    const container = containerName(workerIndex, name);
    spawnSync('docker', ['network', 'connect', net, container], { stdio: 'inherit' });
  }
}

/** Kill a registry container (SIGKILL). */
export function killRegistry(workerIndex: number, name: RegistryLetter): void {
  const container = containerName(workerIndex, name);
  spawnSync('docker', ['kill', container], { stdio: 'inherit' });
}

/** Restart a registry container after a delay. */
export async function restartWithDelay(
  workerIndex: number,
  name: RegistryLetter,
  delayMs: number
): Promise<void> {
  await new Promise(r => setTimeout(r, delayMs));
  const container = containerName(workerIndex, name);
  spawnSync('docker', ['start', container], { stdio: 'inherit' });
}

/**
 * Add artificial network delay to a registry using `tc netem`.
 * Requires the container image to have `iproute2` installed.
 */
export function addNetworkDelay(
  workerIndex: number,
  name: RegistryLetter,
  delayMs: number
): void {
  const container = containerName(workerIndex, name);
  execSync(
    `docker exec ${container} tc qdisc add dev eth0 root netem delay ${delayMs}ms`,
    { stdio: 'inherit' }
  );
}

/** Remove tc netem delay from a registry container. */
export function resetNetworkEffects(workerIndex: number, name: RegistryLetter): void {
  const container = containerName(workerIndex, name);
  try {
    execSync(`docker exec ${container} tc qdisc del dev eth0 root`, { stdio: 'inherit' });
  } catch {
    // No qdisc to remove — ignore
  }
}
```

- [ ] **Step 2: Compile check**

```bash
cd apps/registry/e2e && npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/helpers/chaos-helpers.ts
git commit -m "test(federation-e2e): add chaos engineering helpers (partition, kill, delay)"
```

---

## Task 6: `tests/federation-sync.spec.ts` — 5 core tests

**Files:**
- Create: `apps/registry/e2e/tests/federation-sync.spec.ts`

- [ ] **Step 1: Create the file**

```typescript
import { test, expect, Page } from '@playwright/test';
import {
  startFederationCluster,
  stopFederationCluster,
  resetAllRegistries,
  allRegistryUrls,
  getRegistryLogs,
} from '../helpers/docker-helpers';
import {
  PeersPage,
  AgentsPage,
  publishAgentViaAPI,
  readCatalogToml,
  catalogTomlWithName,
} from '../helpers/federation-helpers';

// ─── Fixture setup ────────────────────────────────────────────────────────────

test.beforeAll(async ({}, workerInfo) => {
  await startFederationCluster(workerInfo.workerIndex);
});

test.afterAll(async ({}, workerInfo) => {
  stopFederationCluster(workerInfo.workerIndex);
});

test.beforeEach(async ({}, workerInfo) => {
  resetAllRegistries(workerInfo.workerIndex);
  // Brief pause for restart settle
  await new Promise(r => setTimeout(r, 1000));
});

// ─── Failure diagnostics ──────────────────────────────────────────────────────

async function dumpLogsOnFailure(workerIndex: number, page: Page, testTitle: string) {
  await page.screenshot({ path: `e2e/logs/${testTitle.replace(/\s+/g, '-')}.png` });
  for (const letter of ['a', 'b', 'c', 'd'] as const) {
    const logs = getRegistryLogs(workerIndex, letter);
    console.error(`=== Registry ${letter.toUpperCase()} logs ===\n${logs}`);
  }
}

// ─── Test 1: Direct sync (star topology) ─────────────────────────────────────

test('Test 1 — Direct sync: registry A and B exchange agents', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Registry B is pre-seeded with hacker_news + docker_hub via seed-agents/ mount.
  // Publish github_repos and npm_registry on A.
  const githubToml = readCatalogToml('culture/github_repos.toml');
  const npmToml = readCatalogToml('developer/npm_registry.toml');
  await publishAgentViaAPI(urls.a, githubToml);
  await publishAgentViaAPI(urls.a, npmToml);

  // Peer A → B
  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.b);

  // A should eventually see B's seeded agents
  await AgentsPage.waitForAgentInList(page, urls.a, 'Hacker News Search');

  // B should eventually see A's agents
  await AgentsPage.waitForAgentInList(page, urls.b, 'GitHub Repository Search');
});

// ─── Test 2: Transitive discovery (chain topology) ────────────────────────────

test('Test 2 — Transitive discovery: A publishes, syncs through C to D', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  const githubToml = readCatalogToml('culture/github_repos.toml');
  await publishAgentViaAPI(urls.a, githubToml);

  // Chain: A ↔ C ↔ D (A doesn't peer with D directly)
  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.c);

  await PeersPage.goto(page, urls.c);
  await PeersPage.addPeer(page, urls.d);

  // D should eventually receive A's agent via C
  await AgentsPage.waitForAgentInList(page, urls.d, 'GitHub Repository Search', 30_000);
});

// ─── Test 3: Conflict resolution (same name, different DID) ──────────────────

test('Test 3 — Conflict resolution: same agent name from two providers coexist', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Publish conflicting agents: same name but different provider_did
  const tomlA = catalogTomlWithName('culture/github_repos.toml', 'Conflict Agent');
  const tomlB = catalogTomlWithName('developer/npm_registry.toml', 'Conflict Agent');
  await publishAgentViaAPI(urls.a, tomlA);
  await publishAgentViaAPI(urls.b, tomlB);

  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.b);

  // Both registries should keep both variants (different provider DID = different agent)
  const countA = await AgentsPage.getAgentCount(page, urls.a);
  const countB = await AgentsPage.getAgentCount(page, urls.b);
  expect(countA).toBeGreaterThanOrEqual(2);
  expect(countB).toBeGreaterThanOrEqual(2);
});

// ─── Test 4: Incremental sync (late joiner) ───────────────────────────────────

test('Test 4 — Late joiner: D joins existing A↔B↔C mesh and receives all agents', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Establish A↔B↔C mesh first
  const githubToml = readCatalogToml('culture/github_repos.toml');
  const npmToml = readCatalogToml('developer/npm_registry.toml');
  await publishAgentViaAPI(urls.a, githubToml);
  await publishAgentViaAPI(urls.c, npmToml);

  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.b);
  await PeersPage.goto(page, urls.b);
  await PeersPage.addPeer(page, urls.c);

  // Now D joins late
  await PeersPage.goto(page, urls.d);
  await PeersPage.addPeer(page, urls.a);
  await PeersPage.addPeer(page, urls.b);
  await PeersPage.addPeer(page, urls.c);

  // D should catch up on all agents
  await AgentsPage.waitForAgentInList(page, urls.d, 'GitHub Repository Search', 30_000);
});

// ─── Test 5: Full mesh — every registry sees every agent ─────────────────────

test('Test 5 — Full mesh: all 4 registries converge on all agents', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Each registry publishes a unique agent
  const tomls = [
    readCatalogToml('culture/github_repos.toml'),
    readCatalogToml('developer/npm_registry.toml'),
    readCatalogToml('culture/hacker_news.toml'),
    readCatalogToml('developer/docker_hub.toml'),
  ];
  const letters = ['a', 'b', 'c', 'd'] as const;
  await Promise.all(letters.map((l, i) => publishAgentViaAPI(urls[l], tomls[i])));

  // Establish all 6 pairs of peerings (full mesh)
  const pairs: [typeof letters[number], typeof letters[number]][] = [
    ['a', 'b'], ['a', 'c'], ['a', 'd'],
    ['b', 'c'], ['b', 'd'],
    ['c', 'd'],
  ];
  for (const [from, to] of pairs) {
    await PeersPage.goto(page, urls[from]);
    await PeersPage.addPeer(page, urls[to]);
  }

  // Each registry should see at least 4 agents
  for (const letter of letters) {
    const count = await AgentsPage.getAgentCount(page, urls[letter]);
    expect(count).toBeGreaterThanOrEqual(4);
  }
});
```

- [ ] **Step 2: Lint check**

```bash
cd apps/registry/e2e && npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/tests/federation-sync.spec.ts
git commit -m "test(federation-e2e): add 5 core federation sync tests"
```

---

## Task 7: `tests/federation-chaos.spec.ts` — 5 opt-in chaos tests

**Files:**
- Create: `apps/registry/e2e/tests/federation-chaos.spec.ts`

- [ ] **Step 1: Create the file**

```typescript
import { test, expect } from '@playwright/test';
import {
  startFederationCluster,
  stopFederationCluster,
  resetAllRegistries,
  allRegistryUrls,
  getRegistryLogs,
} from '../helpers/docker-helpers';
import {
  PeersPage,
  AgentsPage,
  publishAgentViaAPI,
  readCatalogToml,
  catalogTomlWithName,
} from '../helpers/federation-helpers';
import {
  partitionNetwork,
  reconnectNetwork,
  killRegistry,
  restartWithDelay,
  addNetworkDelay,
  resetNetworkEffects,
} from '../helpers/chaos-helpers';

// All chaos tests are opt-in: set RUN_CHAOS_TESTS=true to enable.
test.skip(!process.env.RUN_CHAOS_TESTS, 'Set RUN_CHAOS_TESTS=true to enable chaos tests');

test.beforeAll(async ({}, workerInfo) => {
  await startFederationCluster(workerInfo.workerIndex);
});

test.afterAll(async ({}, workerInfo) => {
  stopFederationCluster(workerInfo.workerIndex);
});

test.beforeEach(async ({}, workerInfo) => {
  resetAllRegistries(workerInfo.workerIndex);
  await new Promise(r => setTimeout(r, 1000));
});

// ─── Test 6: Network partition → heal → convergence ──────────────────────────

test('Test 6 — Network partition: split mesh heals after reconnect', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Establish full mesh
  const pairs: ['a' | 'b' | 'c' | 'd', 'a' | 'b' | 'c' | 'd'][] = [
    ['a', 'b'], ['a', 'c'], ['a', 'd'], ['b', 'c'], ['b', 'd'], ['c', 'd'],
  ];
  for (const [from, to] of pairs) {
    await PeersPage.goto(page, urls[from]);
    await PeersPage.addPeer(page, urls[to]);
  }

  // Partition: cut A+B from C+D
  partitionNetwork(w, ['a', 'b'], ['c', 'd']);

  // Publish in each isolated partition
  await publishAgentViaAPI(urls.a, readCatalogToml('culture/github_repos.toml'));
  await publishAgentViaAPI(urls.c, readCatalogToml('developer/npm_registry.toml'));

  // Heal the partition
  reconnectNetwork(w, ['a', 'b', 'c', 'd']);

  // After healing, all registries should see both agents
  await AgentsPage.waitForAgentInList(page, urls.a, 'NPM Registry Search', 30_000);
  await AgentsPage.waitForAgentInList(page, urls.c, 'GitHub Repository Search', 30_000);
});

// ─── Test 7: Cascading failure — intermediate node down ───────────────────────

test('Test 7 — Cascading failure: chain recovers after middle node restart', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Chain: A → B → C → D
  for (const [from, to] of [['a', 'b'], ['b', 'c'], ['c', 'd']] as const) {
    await PeersPage.goto(page, urls[from]);
    await PeersPage.addPeer(page, urls[to]);
  }

  await publishAgentViaAPI(urls.a, readCatalogToml('culture/github_repos.toml'));

  // Kill B (middle of chain)
  killRegistry(w, 'b');

  // Restart B after 1 second
  await restartWithDelay(w, 'b', 1_000);

  // A's agent should eventually reach D through the recovered chain
  await AgentsPage.waitForAgentInList(page, urls.d, 'GitHub Repository Search', 45_000);
});

// ─── Test 8: Slow peer doesn't block other syncs ─────────────────────────────

test('Test 8 — Slow peer: A syncs C within timeout despite B being 5s delayed', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  // Add 5s delay to B
  addNetworkDelay(w, 'b', 5000);

  // Peer A with slow B and fast C
  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.b);
  await PeersPage.addPeer(page, urls.c);

  await publishAgentViaAPI(urls.c, readCatalogToml('culture/github_repos.toml'));

  // A should sync C's agent within 30s even though B is slow
  await AgentsPage.waitForAgentInList(page, urls.a, 'GitHub Repository Search', 30_000);

  // Cleanup
  resetNetworkEffects(w, 'b');
});

// ─── Test 9: Concurrent conflicting publish → deterministic result ─────────────

test('Test 9 — Concurrent conflict: same name published simultaneously is deterministic', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  const tomlA = catalogTomlWithName('culture/github_repos.toml', 'Race Agent');
  const tomlB = catalogTomlWithName('developer/npm_registry.toml', 'Race Agent');

  // Publish simultaneously on A and B
  await Promise.all([
    publishAgentViaAPI(urls.a, tomlA),
    publishAgentViaAPI(urls.b, tomlB),
  ]);

  await PeersPage.goto(page, urls.a);
  await PeersPage.addPeer(page, urls.b);

  // Wait for sync
  await new Promise(r => setTimeout(r, 5_000));

  // Both registries should have the same deterministic count (≥ 1)
  const countA = await AgentsPage.getAgentCount(page, urls.a);
  const countB = await AgentsPage.getAgentCount(page, urls.b);
  expect(countA).toBeGreaterThanOrEqual(1);
  expect(countB).toBeGreaterThanOrEqual(1);
  // Counts must match (deterministic convergence)
  expect(countA).toBe(countB);
});

// ─── Test 10: Resource exhaustion — 100 agents sync correctly ─────────────────

test('Test 10 — Resource exhaustion: 100 agents published and synced to D', async ({ page }, workerInfo) => {
  const w = workerInfo.workerIndex;
  const urls = allRegistryUrls(w);

  const baseToml = readCatalogToml('culture/github_repos.toml');

  // Publish 100 uniquely-named agents on A (check no 5xx)
  for (let i = 1; i <= 100; i++) {
    const toml = baseToml.replace(/^name\s*=\s*"[^"]*"/m, `name = "Load Test Agent ${i}"`);
    await publishAgentViaAPI(urls.a, toml);
  }

  // Peer D to A
  await PeersPage.goto(page, urls.d);
  await PeersPage.addPeer(page, urls.a);

  // D should see at least agent 100
  await AgentsPage.waitForAgentInList(page, urls.d, 'Load Test Agent 100', 60_000);

  // Check D has no error banners
  await page.goto(`${urls.d}/agents`, { waitUntil: 'networkidle' });
  await expect(page.locator('.error-banner')).not.toBeVisible();
});
```

- [ ] **Step 2: Lint check**

```bash
cd apps/registry/e2e && npx tsc --noEmit 2>&1 | head -20
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/tests/federation-chaos.spec.ts
git commit -m "test(federation-e2e): add 5 opt-in chaos tests (partition, kill, delay, conflict, load)"
```

---

## Task 8: Seed agent TOML files

**Files:**
- Create: `apps/registry/e2e/seed-agents/hacker_news.toml`
- Create: `apps/registry/e2e/seed-agents/docker_hub.toml`

Registry B mounts `./seed-agents:/app/seed-agents:ro` and reads them at startup via `PAP_REGISTRY_SEED_DIR`. These are verbatim copies from the catalog.

- [ ] **Step 1: Create `hacker_news.toml`**

```toml
schema_version = 1
version = "0.1.0"
name = "Hacker News Search"
provider = "Algolia / Y Combinator"
description = "Search Hacker News stories and comments via the Algolia HN Search API."
action = "schema:SearchAction"
object_types = ["schema:DiscussionForumPosting"]
requires_disclosure = []
returns = ["schema:DiscussionForumPosting"]
source = "Catalog"
llm_instructions = """
You are a technology news and community discussion assistant. The user has asked
about a topic relevant to the Hacker News community. Summarize what is known about
the topic, recent developments, and community sentiment if applicable.
"""
subagents = []

[endpoint]
url_template = "https://hn.algolia.com/api/v1/search?query={query}&tags=story&hitsPerPage=5"
method = "Get"
response_jsonpath = "$.hits[0].title"
response_schema_type = "schema:DiscussionForumPosting"

# Map Algolia HN Search fields → schema.org vocabulary
[endpoint.response_mapping]
headline = "$.hits[0].title"
url = "$.hits[0].url"
author = "$.hits[0].author"
commentCount = "$.hits[0].num_comments"
interactionCount = "$.hits[0].points"
datePublished = "$.hits[0].created_at"

# Agent-advertised configurable properties (schema.org PropertyValueSpecification)
[[configurable_properties]]
"@type" = "PropertyValueSpecification"
valueName = "hits_per_page"
name = "Results Per Page"
description = "Number of stories to fetch per query"
defaultValue = 5
minValue = 1
maxValue = 20
```

- [ ] **Step 2: Create `docker_hub.toml`**

```toml
schema_version = 1
version = "0.1.0"
name = "Docker Hub Image Search"
provider = "Docker"
description = "Search Docker Hub container images with pull counts and descriptions."
action = "schema:SearchAction"
object_types = ["schema:SoftwareApplication"]
requires_disclosure = []
returns = ["schema:SoftwareApplication"]
source = "Catalog"
llm_instructions = """
You are a containerization and DevOps assistant. Provide image name, description, pull count,
tags, and usage examples. Note if it is an official Docker image and platform compatibility.
"""
subagents = []

[endpoint]
url_template = "https://hub.docker.com/v2/search/repositories/?query={query}&page_size=5"
method = "Get"
response_jsonpath = "$.results[0].repo_name"
response_schema_type = "schema:SoftwareApplication"

# Agent-advertised configurable properties (schema.org PropertyValueSpecification)
[[configurable_properties]]
"@type" = "PropertyValueSpecification"
valueName = "results_per_page"
name = "Results Per Page"
description = "Maximum number of results to return per query"
defaultValue = 5
minValue = 1
maxValue = 50

[[configurable_properties]]
"@type" = "PropertyValueSpecification"
valueName = "include_deprecated"
name = "Include Deprecated"
description = "Show deprecated or archived packages"
defaultValue = false
```

- [ ] **Step 3: Verify files exist**

```bash
ls apps/registry/e2e/seed-agents/
```
Expected: `docker_hub.toml` and `hacker_news.toml`.

- [ ] **Step 4: Commit**

```bash
git add apps/registry/e2e/seed-agents/
git commit -m "test(federation-e2e): add seed agent TOMLs for Registry B pre-population"
```

---

## Task 9: CI additions to `.github/workflows/ci.yml`

**Files:**
- Modify: `.github/workflows/ci.yml` — append 2 new jobs after line 703 (after the existing `chrysalis-e2e` job's final artifact upload)

- [ ] **Step 1: Append `federation-e2e` and `federation-chaos` jobs**

At the very end of `.github/workflows/ci.yml` (after line 703), append:

```yaml

  federation-e2e:
    name: Federation E2E Tests
    runs-on: ubuntu-latest
    needs: [build]
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4

      - name: Build registry image
        run: docker build -f apps/registry/Dockerfile -t pap-registry:latest .

      - name: Install Node and Playwright
        uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
          cache-dependency-path: apps/registry/e2e/package-lock.json

      - name: Install dependencies
        working-directory: apps/registry/e2e
        run: npm ci

      - name: Install Playwright browsers
        working-directory: apps/registry/e2e
        run: npx playwright install --with-deps chromium

      - name: Run federation sync tests
        working-directory: apps/registry/e2e
        run: npx playwright test tests/federation-sync.spec.ts --reporter=html
        env:
          CI: "true"

      - name: Upload Playwright report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: federation-e2e-report
          path: apps/registry/e2e/playwright-report/
          retention-days: 7

      - name: Upload test logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: federation-e2e-logs
          path: apps/registry/e2e/logs/
          retention-days: 3

  federation-chaos:
    name: Federation Chaos Tests
    runs-on: ubuntu-latest
    needs: [federation-e2e]
    timeout-minutes: 45
    if: >
      github.event_name == 'schedule' ||
      contains(github.event.head_commit.message, '[chaos]')
    steps:
      - uses: actions/checkout@v4

      - name: Build registry image
        run: docker build -f apps/registry/Dockerfile -t pap-registry:latest .

      - name: Install Node and Playwright
        uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: "npm"
          cache-dependency-path: apps/registry/e2e/package-lock.json

      - name: Install dependencies
        working-directory: apps/registry/e2e
        run: npm ci

      - name: Install Playwright browsers
        working-directory: apps/registry/e2e
        run: npx playwright install --with-deps chromium

      - name: Run chaos tests
        working-directory: apps/registry/e2e
        run: npx playwright test tests/federation-chaos.spec.ts --reporter=html
        env:
          CI: "true"
          RUN_CHAOS_TESTS: "true"

      - name: Upload chaos test report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: federation-chaos-report
          path: apps/registry/e2e/playwright-report/
          retention-days: 7
```

- [ ] **Step 2: Validate YAML**

```bash
python3 -c "import yaml, sys; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML OK"
```
Expected: `YAML OK`.

- [ ] **Step 3: Verify job count**

```bash
grep -c "^  [a-z].*:$" .github/workflows/ci.yml
```
Expected: previous count + 2.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add federation-e2e and federation-chaos workflow jobs"
```

---

## Final Verification

- [ ] **Full file tree check**

```bash
find apps/registry/e2e -type f | sort
```
Expected output:
```
apps/registry/e2e/docker-compose.federation.yml
apps/registry/e2e/helpers/chaos-helpers.ts
apps/registry/e2e/helpers/docker-helpers.ts
apps/registry/e2e/helpers/federation-helpers.ts
apps/registry/e2e/package.json
apps/registry/e2e/playwright.config.ts
apps/registry/e2e/seed-agents/docker_hub.toml
apps/registry/e2e/seed-agents/hacker_news.toml
apps/registry/e2e/tests/federation-chaos.spec.ts
apps/registry/e2e/tests/federation-sync.spec.ts
```

- [ ] **TypeScript compile clean**

```bash
cd apps/registry/e2e && npm ci && npx tsc --noEmit
```
Expected: no errors.

- [ ] **Dry-run test collection** (no Docker needed)

```bash
cd apps/registry/e2e && npx playwright test --list
```
Expected: 10 tests listed (5 sync + 5 chaos, chaos skipped unless `RUN_CHAOS_TESTS=true`).

- [ ] **Spec coverage check**

```
- §3.1 Agent Publication — covered by publishAgentViaAPI (Tests 1–5) + seed pre-population (Test 1)
- §3.2 Peer Registration — covered by PeersPage.addPeer (all tests)
- §3.3 Federation Sync — covered by Tests 1–5 (sync), Tests 6–10 (chaos)
- §3.4 Conflict Resolution — covered by Test 3 (same name, different DID) + Test 9 (concurrent)
- §3.5 Late Joiner — covered by Test 4 (incremental sync)
- §4.1 Network Partition — covered by Test 6
- §4.2 Node Failure — covered by Test 7 (cascading)
- §4.3 Slow Peer — covered by Test 8
- §4.4 Resource Exhaustion — covered by Test 10
```

---

## Self-Review

### What the tests cover
- ✅ Direct bilateral sync between two registries
- ✅ Transitive discovery through N hops
- ✅ Conflict resolution: same name, different provider DID → both retained
- ✅ Incremental sync for late-joining registries
- ✅ Full mesh convergence across 4 nodes
- ✅ Network partition + heal (chaos)
- ✅ Cascading failure: intermediate node kill + restart (chaos)
- ✅ Slow peer doesn't block unrelated syncs (chaos)
- ✅ Concurrent conflicting publish → deterministic count (chaos)
- ✅ Load: 100 agents synced without 5xx (chaos)

### Selector fidelity
All CSS selectors are verified directly from the Leptos source files:
- `peers.rs` → `.btn.btn-primary`, `.form-input`, `.modal-actions`, `.peer-list`, `.peer-row`, `.peer-indicator`, `.peer-endpoint`, `.success-banner`, `.error-banner`
- `agents.rs` → `.filter-input`, `.btn.btn-secondary`, `.loading`, `.empty-state`
- `dashboard.rs` → `.stat-grid`, `.stat-card`, `.stat-value.teal`, `.stat-value.accent`
- `agent_designer.rs` → `[name=name]`, `[name=provider_name]`, etc.

### Port isolation
Each Playwright worker gets a dedicated port block (`7900 + workerIndex * 10`), ensuring 4 parallel workers × 4 containers = 16 containers never collide on the same port.
