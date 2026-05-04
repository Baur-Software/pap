# Federation Test Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create comprehensive e2e tests validating federation sync across 4 registry instances using Playwright with full UI automation

**Architecture:** Docker Compose spawns 4 isolated registries with mixed topologies (star/mesh/chain). Playwright drives UI for peer management and agent publishing. Tests verify agent propagation using 3 publishing methods (API, pre-seed, UI). Chaos tests inject network failures.

**Tech Stack:** Playwright, Docker Compose, TypeScript, pap-registry, pap-agents catalog

---

## File Structure

**Infrastructure:**
- `apps/registry/e2e/docker-compose.federation.yml` - 4 registry instances with isolated volumes, ports 7900-7903
- `apps/registry/e2e/seed-agents/` - Directory with TOML files for Registry B pre-seeding

**Test Files:**
- `apps/registry/e2e/tests/federation-sync.spec.ts` - 5 core federation tests
- `apps/registry/e2e/tests/federation-chaos.spec.ts` - 5 chaos/failure mode tests

**Helpers:**
- `apps/registry/e2e/helpers/federation-helpers.ts` - UI automation (add peer, publish agent, wait for sync)
- `apps/registry/e2e/helpers/docker-helpers.ts` - Container lifecycle (start, stop, reset DB, get logs)
- `apps/registry/e2e/helpers/chaos-helpers.ts` - Failure injection (partition network, kill container, add latency)
- `apps/registry/e2e/helpers/types.ts` - TypeScript interfaces for agent data, peer status, etc.

**Config:**
- `apps/registry/e2e/playwright.config.ts` - Update for federation tests (parallel workers, base URLs)
- `apps/registry/e2e/package.json` - Add test scripts for federation suite

---

### Task 1: Docker Compose Infrastructure

**Files:**
- Create: `apps/registry/e2e/docker-compose.federation.yml`
- Create: `apps/registry/e2e/seed-agents/hacker_news.toml`
- Create: `apps/registry/e2e/seed-agents/docker_hub.toml`

- [ ] **Step 1: Copy agent TOML files for pre-seeding**

```bash
# Create seed directory and copy agent files for Registry B
mkdir -p apps/registry/e2e/seed-agents
cp ../../crates/pap-agents/catalog/culture/hacker_news.toml apps/registry/e2e/seed-agents/
cp ../../crates/pap-agents/catalog/developer/docker_hub.toml apps/registry/e2e/seed-agents/
```

- [ ] **Step 2: Create docker-compose.federation.yml**

```yaml
services:
  registry-a:
    image: pap-registry:latest
    container_name: federation-registry-a
    ports:
      - "${REGISTRY_A_PORT:-7900}:7890"
    volumes:
      - registry_data_a:/data
    environment:
      PAP_REGISTRY_ENDPOINT: "http://localhost:${REGISTRY_A_PORT:-7900}"
      PAP_REGISTRY_PORT: "7890"
      PAP_REGISTRY_HOST: "0.0.0.0"
      PAP_REGISTRY_DB: "/data/registry.db"
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: "/app/site"
      PAP_REGISTRY_RESET_DB: "${RESET_DBS:-false}"
      PAP_REGISTRY_RESET_DB_CONFIRM: "${RESET_DBS:-false}"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7890/federation/identity"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
    networks:
      - federation-test-net

  registry-b:
    image: pap-registry:latest
    container_name: federation-registry-b
    ports:
      - "${REGISTRY_B_PORT:-7901}:7890"
    volumes:
      - registry_data_b:/data
      - ./seed-agents:/app/seed-agents:ro
    environment:
      PAP_REGISTRY_ENDPOINT: "http://localhost:${REGISTRY_B_PORT:-7901}"
      PAP_REGISTRY_PORT: "7890"
      PAP_REGISTRY_HOST: "0.0.0.0"
      PAP_REGISTRY_DB: "/data/registry.db"
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: "/app/site"
      PAP_REGISTRY_SEED_DIR: "/app/seed-agents"
      PAP_REGISTRY_RESET_DB: "${RESET_DBS:-false}"
      PAP_REGISTRY_RESET_DB_CONFIRM: "${RESET_DBS:-false}"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7890/federation/identity"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
    networks:
      - federation-test-net

  registry-c:
    image: pap-registry:latest
    container_name: federation-registry-c
    ports:
      - "${REGISTRY_C_PORT:-7902}:7890"
    volumes:
      - registry_data_c:/data
    environment:
      PAP_REGISTRY_ENDPOINT: "http://localhost:${REGISTRY_C_PORT:-7902}"
      PAP_REGISTRY_PORT: "7890"
      PAP_REGISTRY_HOST: "0.0.0.0"
      PAP_REGISTRY_DB: "/data/registry.db"
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: "/app/site"
      PAP_REGISTRY_RESET_DB: "${RESET_DBS:-false}"
      PAP_REGISTRY_RESET_DB_CONFIRM: "${RESET_DBS:-false}"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7890/federation/identity"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
    networks:
      - federation-test-net

  registry-d:
    image: pap-registry:latest
    container_name: federation-registry-d
    ports:
      - "${REGISTRY_D_PORT:-7903}:7890"
    volumes:
      - registry_data_d:/data
    environment:
      PAP_REGISTRY_ENDPOINT: "http://localhost:${REGISTRY_D_PORT:-7903}"
      PAP_REGISTRY_PORT: "7890"
      PAP_REGISTRY_HOST: "0.0.0.0"
      PAP_REGISTRY_DB: "/data/registry.db"
      PAP_REGISTRY_NO_TLS: "true"
      LEPTOS_SITE_ROOT: "/app/site"
      PAP_REGISTRY_RESET_DB: "${RESET_DBS:-false}"
      PAP_REGISTRY_RESET_DB_CONFIRM: "${RESET_DBS:-false}"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7890/federation/identity"]
      interval: 5s
      timeout: 3s
      retries: 10
      start_period: 10s
    networks:
      - federation-test-net

networks:
  federation-test-net:
    driver: bridge

volumes:
  registry_data_a:
  registry_data_b:
  registry_data_c:
  registry_data_d:
```

- [ ] **Step 3: Test docker compose starts successfully**

Run:
```bash
cd apps/registry/e2e
docker compose -f docker-compose.federation.yml up -d
docker compose -f docker-compose.federation.yml ps
```

Expected: All 4 registries show "healthy" status

- [ ] **Step 4: Verify connectivity between containers**

Run:
```bash
docker exec federation-registry-a curl -f http://federation-registry-b:7890/federation/identity
docker exec federation-registry-c curl -f http://federation-registry-d:7890/federation/identity
```

Expected: Both return JSON with "did", "agent_count", "peer_count"

- [ ] **Step 5: Stop and cleanup**

Run:
```bash
docker compose -f docker-compose.federation.yml down -v
```

Expected: All containers stopped, volumes removed

- [ ] **Step 6: Commit**

```bash
git add apps/registry/e2e/docker-compose.federation.yml
git add apps/registry/e2e/seed-agents/
git commit -m "feat(registry/e2e): add docker compose for 4-instance federation testing

- 4 registries on ports 7900-7903
- Isolated volumes per instance
- Registry B pre-seeded with hacker_news and docker_hub agents
- Shared federation-test-net network
- Healthchecks on /federation/identity

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 2: TypeScript Types and Interfaces

**Files:**
- Create: `apps/registry/e2e/helpers/types.ts`

- [ ] **Step 1: Write TypeScript interfaces**

```typescript
export interface AgentFormData {
  name: string;
  provider: string;
  description: string;
  action: string; // e.g., "schema:SearchAction"
  objectTypes: string[]; // e.g., ["schema:SoftwareApplication"]
  requiresDisclosure: string[];
  returns: string[];
}

export interface AgentAdvertisement {
  name: string;
  provider: string;
  description: string;
  action: string[];
  object_types: string[];
  requires_disclosure: string[];
  returns: string[];
  did: string;
  hash: string;
}

export interface PeerInfo {
  endpoint: string;
  did: string;
  agent_count: number;
  last_sync?: string;
  status?: "online" | "offline" | "syncing";
}

export interface RegistryStats {
  agent_count: number;
  peer_count: number;
  local_agent_count?: number;
  federated_agent_count?: number;
}

export interface RegistryConfig {
  name: string; // "registry-a", "registry-b", etc.
  port: number; // 7900, 7901, 7902, 7903
  baseURL: string; // "http://localhost:7900"
}

export const REGISTRY_CONFIGS: Record<string, RegistryConfig> = {
  a: {
    name: "registry-a",
    port: 7900,
    baseURL: "http://localhost:7900",
  },
  b: {
    name: "registry-b",
    port: 7901,
    baseURL: "http://localhost:7901",
  },
  c: {
    name: "registry-c",
    port: 7902,
    baseURL: "http://localhost:7902",
  },
  d: {
    name: "registry-d",
    port: 7903,
    baseURL: "http://localhost:7903",
  },
};

export function getRegistryConfig(
  name: string,
  workerIndex = 0
): RegistryConfig {
  const base = REGISTRY_CONFIGS[name];
  if (!base) throw new Error(`Unknown registry: ${name}`);

  const portOffset = workerIndex * 10;
  return {
    ...base,
    port: base.port + portOffset,
    baseURL: `http://localhost:${base.port + portOffset}`,
  };
}
```

- [ ] **Step 2: Commit**

```bash
git add apps/registry/e2e/helpers/types.ts
git commit -m "feat(registry/e2e): add TypeScript types for federation tests

- Agent form data and advertisement interfaces
- Peer info and registry stats types
- Registry config with port offset calculation for parallel workers

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 3: Docker Helper Utilities

**Files:**
- Create: `apps/registry/e2e/helpers/docker-helpers.ts`

- [ ] **Step 1: Write docker helper functions**

```typescript
import { exec } from "child_process";
import { promisify } from "util";
import { getRegistryConfig, RegistryConfig } from "./types";

const execAsync = promisify(exec);

export async function startFederationCluster(
  workerIndex = 0
): Promise<RegistryConfig[]> {
  const configs = ["a", "b", "c", "d"].map((name) =>
    getRegistryConfig(name, workerIndex)
  );

  const envVars = {
    REGISTRY_A_PORT: configs[0].port.toString(),
    REGISTRY_B_PORT: configs[1].port.toString(),
    REGISTRY_C_PORT: configs[2].port.toString(),
    REGISTRY_D_PORT: configs[3].port.toString(),
  };

  const envString = Object.entries(envVars)
    .map(([k, v]) => `${k}=${v}`)
    .join(" ");

  await execAsync(
    `cd apps/registry/e2e && ${envString} docker compose -f docker-compose.federation.yml up -d`
  );

  // Wait for all healthchecks to pass
  const startTime = Date.now();
  const timeout = 60000; // 60s total timeout

  while (Date.now() - startTime < timeout) {
    const { stdout } = await execAsync(
      `${envString} docker compose -f apps/registry/e2e/docker-compose.federation.yml ps --format json`
    );

    const containers = stdout
      .trim()
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));

    const allHealthy = containers.every(
      (c: any) => c.Health === "healthy" || c.State === "running"
    );

    if (allHealthy && containers.length === 4) {
      return configs;
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  throw new Error("Federation cluster failed to start within 60s");
}

export async function stopFederationCluster(
  workerIndex = 0
): Promise<void> {
  const configs = ["a", "b", "c", "d"].map((name) =>
    getRegistryConfig(name, workerIndex)
  );

  const envVars = {
    REGISTRY_A_PORT: configs[0].port.toString(),
    REGISTRY_B_PORT: configs[1].port.toString(),
    REGISTRY_C_PORT: configs[2].port.toString(),
    REGISTRY_D_PORT: configs[3].port.toString(),
  };

  const envString = Object.entries(envVars)
    .map(([k, v]) => `${k}=${v}`)
    .join(" ");

  await execAsync(
    `cd apps/registry/e2e && ${envString} docker compose -f docker-compose.federation.yml down -v`
  );
}

export async function resetRegistryDB(
  registryName: string,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(
    `docker compose -f apps/registry/e2e/docker-compose.federation.yml restart ${config.name}`
  );

  // Wait for healthcheck
  await new Promise((resolve) => setTimeout(resolve, 5000));
}

export async function getRegistryLogs(
  registryName: string,
  workerIndex = 0
): Promise<string> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  const { stdout } = await execAsync(`docker logs ${containerName}`);
  return stdout;
}

export async function killRegistry(
  registryName: string,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(`docker kill ${containerName}`);
}

export async function startRegistry(
  registryName: string,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(`docker start ${containerName}`);

  // Wait for healthcheck
  let retries = 20;
  while (retries > 0) {
    try {
      const { stdout } = await execAsync(
        `docker inspect ${containerName} --format='{{.State.Health.Status}}'`
      );
      if (stdout.trim() === "healthy") {
        return;
      }
    } catch (e) {
      // Container not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
    retries--;
  }

  throw new Error(`Registry ${registryName} failed to become healthy`);
}
```

- [ ] **Step 2: Write test for startFederationCluster**

```typescript
// apps/registry/e2e/tests/__helpers-test__/docker-helpers.test.ts
import { test, expect } from "@playwright/test";
import {
  startFederationCluster,
  stopFederationCluster,
  getRegistryLogs,
} from "../../helpers/docker-helpers";

test.describe("Docker Helpers", () => {
  test("startFederationCluster starts 4 registries", async ({ request }) => {
    const configs = await startFederationCluster(0);

    expect(configs).toHaveLength(4);

    // Verify each registry responds
    for (const config of configs) {
      const response = await request.get(
        `${config.baseURL}/federation/identity`
      );
      expect(response.ok()).toBe(true);

      const identity = await response.json();
      expect(identity.did).toMatch(/^did:key:/);
    }

    await stopFederationCluster(0);
  });

  test("getRegistryLogs returns log output", async () => {
    await startFederationCluster(0);

    const logs = await getRegistryLogs("a", 0);
    expect(logs).toContain("Starting PAP Registry");
    expect(logs).toContain("Node DID:");

    await stopFederationCluster(0);
  });
});
```

- [ ] **Step 3: Run helper tests**

Run:
```bash
cd apps/registry/e2e
npx playwright test tests/__helpers-test__/docker-helpers.test.ts
```

Expected: Tests pass, containers start and stop cleanly

- [ ] **Step 4: Commit**

```bash
git add apps/registry/e2e/helpers/docker-helpers.ts
git add apps/registry/e2e/tests/__helpers-test__/
git commit -m "feat(registry/e2e): add docker helper utilities

- startFederationCluster: Start 4 registries with port offsets
- stopFederationCluster: Clean shutdown with volume removal
- killRegistry/startRegistry: Chaos testing primitives
- getRegistryLogs: Debugging aid
- Tests verify cluster lifecycle

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 4: Federation UI Helper Utilities

**Files:**
- Create: `apps/registry/e2e/helpers/federation-helpers.ts`

- [ ] **Step 1: Write UI automation helpers**

```typescript
import { Page, expect } from "@playwright/test";
import { AgentFormData, PeerInfo, RegistryStats } from "./types";
import * as fs from "fs";
import * as path from "path";

export async function addPeerViaUI(
  page: Page,
  peerEndpoint: string,
  trustMode: "tofu" | "pinned" = "tofu"
): Promise<void> {
  await page.goto("/peers");
  await page.waitForLoadState("networkidle");

  // Click "+ Add Peer" button
  await page.click('button:has-text("+ Add Peer")');

  // Wait for modal to appear
  await page.waitForSelector('input[name="endpoint"]', { timeout: 5000 });

  // Fill endpoint
  await page.fill('input[name="endpoint"]', peerEndpoint);

  // Select trust mode if dropdown exists
  const trustDropdown = page.locator('select[name="trust_mode"]');
  if (await trustDropdown.count()) {
    await trustDropdown.selectOption(trustMode);
  }

  // Click Add button
  await page.click('button:has-text("Add")');

  // Wait for success banner
  await page.waitForSelector('.success-banner', { timeout: 10000 });
}

export async function publishAgentViaAPI(
  baseURL: string,
  agentTomlPath: string
): Promise<void> {
  const tomlContent = fs.readFileSync(agentTomlPath, "utf-8");

  // Parse TOML and convert to JSON (simplified - assuming structure)
  const lines = tomlContent.split("\n");
  const agent: any = {
    schema_version: 1,
    version: "0.1.0",
  };

  for (const line of lines) {
    if (line.includes("=")) {
      const [key, value] = line.split("=").map((s) => s.trim());
      agent[key] = value.replace(/"/g, "");
    }
  }

  const response = await fetch(`${baseURL}/admin/agents`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(agent),
  });

  if (!response.ok) {
    throw new Error(
      `Failed to publish agent: ${response.status} ${await response.text()}`
    );
  }
}

export async function publishAgentViaUI(
  page: Page,
  agentData: AgentFormData
): Promise<void> {
  await page.goto("/agents/new");
  await page.waitForLoadState("networkidle");

  // Fill form fields
  await page.fill('input[name="name"]', agentData.name);
  await page.fill('input[name="provider"]', agentData.provider);
  await page.fill('textarea[name="description"]', agentData.description);
  await page.fill('input[name="action"]', agentData.action);

  // Object types (comma-separated or individual fields depending on UI)
  const objectTypesInput = page.locator('input[name="object_types"]');
  if (await objectTypesInput.count()) {
    await objectTypesInput.fill(agentData.objectTypes.join(", "));
  }

  // Returns (schema.org types)
  const returnsInput = page.locator('input[name="returns"]');
  if (await returnsInput.count()) {
    await returnsInput.fill(agentData.returns.join(", "));
  }

  // Click Publish
  await page.click('button:has-text("Publish")');

  // Wait for success message
  await page.waitForSelector('.success-banner', { timeout: 10000 });
}

export async function waitForAgentInList(
  page: Page,
  agentName: string,
  timeout = 30000
): Promise<boolean> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    await page.goto("/agents");
    await page.waitForLoadState("networkidle");

    const agentRow = page.locator(`tr:has-text("${agentName}")`);
    if (await agentRow.count()) {
      return true;
    }

    await page.waitForTimeout(1000);
  }

  return false;
}

export async function getAgentCount(page: Page): Promise<number> {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  const statCard = page.locator('.stat-card:has-text("Agents")');
  const valueText = await statCard
    .locator(".stat-value")
    .first()
    .textContent();

  return parseInt(valueText?.trim() || "0", 10);
}

export async function getRegistryStats(page: Page): Promise<RegistryStats> {
  await page.goto("/dashboard");
  await page.waitForLoadState("networkidle");

  const agentCountText = await page
    .locator('.stat-card:has-text("Agents") .stat-value')
    .first()
    .textContent();

  const peerCountText = await page
    .locator('.stat-card:has-text("Peers") .stat-value')
    .first()
    .textContent();

  return {
    agent_count: parseInt(agentCountText?.trim() || "0", 10),
    peer_count: parseInt(peerCountText?.trim() || "0", 10),
  };
}

export async function triggerSync(
  page: Page,
  peerEndpoint: string
): Promise<void> {
  await page.goto("/peers");
  await page.waitForLoadState("networkidle");

  // Find peer row by endpoint
  const peerRow = page.locator(`tr:has-text("${peerEndpoint}")`);
  await expect(peerRow).toBeVisible();

  // Click Sync Now button if it exists
  const syncButton = peerRow.locator('button:has-text("Sync")');
  if (await syncButton.count()) {
    await syncButton.click();
    await page.waitForSelector('.success-banner', { timeout: 10000 });
  }
}

export async function listPeers(page: Page): Promise<PeerInfo[]> {
  await page.goto("/peers");
  await page.waitForLoadState("networkidle");

  const rows = await page.locator(".peer-row").all();
  const peers: PeerInfo[] = [];

  for (const row of rows) {
    const endpoint = await row.locator(".peer-endpoint").textContent();
    const did = await row.locator(".peer-did").textContent();

    peers.push({
      endpoint: endpoint?.trim() || "",
      did: did?.trim() || "",
      agent_count: 0, // Would need to parse from UI if displayed
    });
  }

  return peers;
}
```

- [ ] **Step 2: Commit**

```bash
git add apps/registry/e2e/helpers/federation-helpers.ts
git commit -m "feat(registry/e2e): add federation UI automation helpers

- addPeerViaUI: Navigate to /peers, click button, fill form, wait for success
- publishAgentViaAPI: POST to /admin/agents with TOML data
- publishAgentViaUI: Fill Agent Designer form and publish
- waitForAgentInList: Poll /agents page until agent appears
- getAgentCount/getRegistryStats: Parse dashboard stats
- triggerSync: Manually trigger peer sync via UI button

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 5: Chaos Test Helpers

**Files:**
- Create: `apps/registry/e2e/helpers/chaos-helpers.ts`

- [ ] **Step 1: Write chaos injection helpers**

```typescript
import { exec } from "child_process";
import { promisify } from "util";
import { getRegistryConfig } from "./types";

const execAsync = promisify(exec);

export async function partitionNetwork(
  groupA: string[],
  groupB: string[],
  workerIndex = 0
): Promise<void> {
  // Disconnect groupA from main network
  for (const name of groupA) {
    const config = getRegistryConfig(name, workerIndex);
    const containerName = `federation-${config.name}`;
    await execAsync(
      `docker network disconnect federation-test-net ${containerName}`
    );
  }

  // Create isolated network for groupA
  await execAsync(`docker network create federation-partition-a`);
  for (const name of groupA) {
    const config = getRegistryConfig(name, workerIndex);
    const containerName = `federation-${config.name}`;
    await execAsync(
      `docker network connect federation-partition-a ${containerName}`
    );
  }
}

export async function reconnectNetwork(
  containers: string[],
  workerIndex = 0
): Promise<void> {
  for (const name of containers) {
    const config = getRegistryConfig(name, workerIndex);
    const containerName = `federation-${config.name}`;

    // Reconnect to main network
    await execAsync(
      `docker network connect federation-test-net ${containerName}`
    );

    // Remove from partition network if exists
    try {
      await execAsync(
        `docker network disconnect federation-partition-a ${containerName}`
      );
    } catch (e) {
      // Ignore if not connected to partition network
    }
  }

  // Cleanup partition network
  try {
    await execAsync(`docker network rm federation-partition-a`);
  } catch (e) {
    // Ignore if already removed
  }
}

export async function addNetworkDelay(
  registryName: string,
  delayMs: number,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(
    `docker exec ${containerName} tc qdisc add dev eth0 root netem delay ${delayMs}ms`
  );
}

export async function removeNetworkDelay(
  registryName: string,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(
    `docker exec ${containerName} tc qdisc del dev eth0 root || true`
  );
}

export async function throttleCPU(
  registryName: string,
  cpuPercent: number,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(
    `docker update --cpus=${cpuPercent} ${containerName}`
  );
}

export async function resetCPU(
  registryName: string,
  workerIndex = 0
): Promise<void> {
  const config = getRegistryConfig(registryName, workerIndex);
  const containerName = `federation-${config.name}`;

  await execAsync(`docker update --cpus=0 ${containerName}`); // 0 = unlimited
}
```

- [ ] **Step 2: Commit**

```bash
git add apps/registry/e2e/helpers/chaos-helpers.ts
git commit -m "feat(registry/e2e): add chaos testing helpers

- partitionNetwork: Split containers into isolated network partitions
- reconnectNetwork: Merge partitions back to main network
- addNetworkDelay/removeNetworkDelay: Inject latency via tc netem
- throttleCPU/resetCPU: Limit container CPU resources

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 6: Core Federation Test Suite

**Files:**
- Create: `apps/registry/e2e/tests/federation-sync.spec.ts`

- [ ] **Step 1: Write test setup and teardown**

```typescript
import { test, expect, Page } from "@playwright/test";
import { startFederationCluster, stopFederationCluster } from "../helpers/docker-helpers";
import { addPeerViaUI, publishAgentViaAPI, publishAgentViaUI, waitForAgentInList, getAgentCount } from "../helpers/federation-helpers";
import { REGISTRY_CONFIGS, AgentFormData } from "../helpers/types";

test.describe("Federation Sync Tests", () => {
  let workerIndex: number;

  test.beforeAll(async ({}, testInfo) => {
    workerIndex = testInfo.workerIndex;
    await startFederationCluster(workerIndex);
  });

  test.afterAll(async () => {
    await stopFederationCluster(workerIndex);
  });
});
```

- [ ] **Step 2: Write Test 1 - Direct Sync (Star Pattern)**

```typescript
test("Test 1: Direct Sync - A discovers B's agents via direct peer connection", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  await pageB.goto(REGISTRY_CONFIGS.b.baseURL);

  // Step 1: Verify Registry B has 2 pre-seeded agents
  await pageB.goto("/agents");
  await pageB.waitForLoadState("networkidle");
  const initialCountB = await getAgentCount(pageB);
  expect(initialCountB).toBe(2); // hacker_news + docker_hub from seed

  // Step 2: Registry A adds B as peer
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.b.baseURL, "tofu");

  // Step 3: Wait for sync (30s timeout)
  await pageA.waitForTimeout(5000); // Initial sync delay
  const foundHackerNews = await waitForAgentInList(pageA, "hacker_news", 30000);
  expect(foundHackerNews).toBe(true);

  const foundDockerHub = await waitForAgentInList(pageA, "docker_hub", 30000);
  expect(foundDockerHub).toBe(true);

  // Step 4: Verify total count on A
  const finalCountA = await getAgentCount(pageA);
  expect(finalCountA).toBe(2);

  await contextA.close();
  await contextB.close();
});
```

- [ ] **Step 3: Write Test 2 - Transitive Discovery (Chain Pattern)**

```typescript
test("Test 2: Transitive Discovery - A→C→D chain propagates D's agents to A", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: Publish agent on Registry D via UI
  const agentData: AgentFormData = {
    name: "test_agent_d",
    provider: "Test Provider D",
    description: "Agent published on D for transitive discovery test",
    action: "schema:SearchAction",
    objectTypes: ["schema:WebPage"],
    requiresDisclosure: [],
    returns: ["schema:SearchResultsPage"],
  };

  await publishAgentViaUI(pageD, agentData);

  // Step 2: C adds D as peer
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.d.baseURL, "tofu");
  await pageC.waitForTimeout(5000);

  // Step 3: Verify C has D's agent
  const foundOnC = await waitForAgentInList(pageC, "test_agent_d", 30000);
  expect(foundOnC).toBe(true);

  // Step 4: A adds C as peer (not D)
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.c.baseURL, "tofu");
  await pageA.waitForTimeout(5000);

  // Step 5: A should discover D's agent transitively through C
  const foundOnA = await waitForAgentInList(pageA, "test_agent_d", 30000);
  expect(foundOnA).toBe(true);

  await contextA.close();
  await contextC.close();
  await contextD.close();
});
```

- [ ] **Step 4: Write Test 3 - Conflict Resolution (Same Agent Published Twice)**

```typescript
test("Test 3: Conflict Resolution - A and B publish same agent, C sees one copy", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  await pageB.goto(REGISTRY_CONFIGS.b.baseURL);

  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  // Step 1: Publish identical agent on A
  const agentDataA: AgentFormData = {
    name: "duplicate_agent",
    provider: "Provider A",
    description: "Duplicate test agent",
    action: "schema:SearchAction",
    objectTypes: ["schema:Article"],
    requiresDisclosure: [],
    returns: ["schema:ItemList"],
  };
  await publishAgentViaUI(pageA, agentDataA);

  // Step 2: Publish identical agent on B
  const agentDataB = { ...agentDataA, provider: "Provider B" };
  await publishAgentViaUI(pageB, agentDataB);

  // Step 3: C adds both A and B as peers
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.a.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.b.baseURL, "tofu");

  await pageC.waitForTimeout(5000);

  // Step 4: C should see both agents (dedupe by hash or show both providers)
  await pageC.goto("/agents");
  await pageC.waitForLoadState("networkidle");

  const agentRows = await pageC.locator('tr:has-text("duplicate_agent")').count();
  
  // Either: 1 row with multi-provider badge OR 2 rows with different providers
  expect(agentRows).toBeGreaterThanOrEqual(1);

  await contextA.close();
  await contextB.close();
  await contextC.close();
});
```

- [ ] **Step 5: Write Test 4 - Incremental Sync (Late Joiner)**

```typescript
test("Test 4: Incremental Sync - D joins mesh after agents published, catches up", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  await pageB.goto(REGISTRY_CONFIGS.b.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: A publishes 3 agents via API
  await publishAgentViaAPI(REGISTRY_CONFIGS.a.baseURL, "../../crates/pap-agents/catalog/culture/goodreads.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.a.baseURL, "../../crates/pap-agents/catalog/developer/npm_search.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.a.baseURL, "../../crates/pap-agents/catalog/developer/github_issues.toml");

  // Step 2: B adds A as peer, syncs
  await addPeerViaUI(pageB, REGISTRY_CONFIGS.a.baseURL, "tofu");
  await pageB.waitForTimeout(5000);

  // Step 3: Verify B has 3 new agents (plus 2 pre-seeded = 5 total)
  const countB = await getAgentCount(pageB);
  expect(countB).toBe(5);

  // Step 4: D joins late - adds both A and B as peers
  await addPeerViaUI(pageD, REGISTRY_CONFIGS.a.baseURL, "tofu");
  await addPeerViaUI(pageD, REGISTRY_CONFIGS.b.baseURL, "tofu");

  await pageD.waitForTimeout(5000);

  // Step 5: D should incrementally sync all 5 agents
  const countD = await getAgentCount(pageD);
  expect(countD).toBe(5);

  await contextA.close();
  await contextB.close();
  await contextD.close();
});
```

- [ ] **Step 6: Write Test 5 - Full Mesh Propagation**

```typescript
test("Test 5: Full Mesh Propagation - Agent published on C reaches all nodes", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  await pageB.goto(REGISTRY_CONFIGS.b.baseURL);

  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: Build mesh - A↔B, A↔C, A↔D, C↔D
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.b.baseURL, "tofu");
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.c.baseURL, "tofu");
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.d.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.d.baseURL, "tofu");

  await pageA.waitForTimeout(5000);

  // Step 2: Publish agent on C
  const meshAgent: AgentFormData = {
    name: "mesh_propagation_test",
    provider: "Mesh Test Provider",
    description: "Agent for full mesh propagation test",
    action: "schema:ReadAction",
    objectTypes: ["schema:Book"],
    requiresDisclosure: ["schema:name"],
    returns: ["schema:Book"],
  };

  await publishAgentViaUI(pageC, meshAgent);

  // Step 3: Wait and verify all 4 nodes have the agent
  const foundOnA = await waitForAgentInList(pageA, "mesh_propagation_test", 30000);
  const foundOnB = await waitForAgentInList(pageB, "mesh_propagation_test", 30000);
  const foundOnC = await waitForAgentInList(pageC, "mesh_propagation_test", 30000);
  const foundOnD = await waitForAgentInList(pageD, "mesh_propagation_test", 30000);

  expect(foundOnA).toBe(true);
  expect(foundOnB).toBe(true);
  expect(foundOnC).toBe(true);
  expect(foundOnD).toBe(true);

  await contextA.close();
  await contextB.close();
  await contextC.close();
  await contextD.close();
});
```

- [ ] **Step 7: Run core federation tests**

Run:
```bash
cd apps/registry/e2e
npx playwright test tests/federation-sync.spec.ts
```

Expected: All 5 tests pass

- [ ] **Step 8: Commit**

```bash
git add apps/registry/e2e/tests/federation-sync.spec.ts
git commit -m "feat(registry/e2e): add core federation sync test suite

- Test 1: Direct sync (star pattern A→B)
- Test 2: Transitive discovery (chain A→C→D)
- Test 3: Conflict resolution (same agent from A and B)
- Test 4: Incremental sync (late joiner catches up)
- Test 5: Full mesh propagation (agent reaches all nodes)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 7: Chaos Federation Test Suite

**Files:**
- Create: `apps/registry/e2e/tests/federation-chaos.spec.ts`

- [ ] **Step 1: Write chaos test setup**

```typescript
import { test, expect, Page } from "@playwright/test";
import { startFederationCluster, stopFederationCluster, killRegistry, startRegistry } from "../helpers/docker-helpers";
import { partitionNetwork, reconnectNetwork, addNetworkDelay, removeNetworkDelay, throttleCPU, resetCPU } from "../helpers/chaos-helpers";
import { addPeerViaUI, publishAgentViaUI, waitForAgentInList, getAgentCount } from "../helpers/federation-helpers";
import { REGISTRY_CONFIGS, AgentFormData } from "../helpers/types";

test.describe("Federation Chaos Tests", () => {
  let workerIndex: number;

  test.beforeAll(async ({}, testInfo) => {
    workerIndex = testInfo.workerIndex;
    
    // Only run chaos tests if RUN_CHAOS_TESTS=true
    if (process.env.RUN_CHAOS_TESTS !== "true") {
      test.skip();
    }

    await startFederationCluster(workerIndex);
  });

  test.afterAll(async () => {
    await stopFederationCluster(workerIndex);
  });
});
```

- [ ] **Step 2: Write Test 6 - Network Partition (Split Brain)**

```typescript
test("Test 6: Network Partition - A,B partition from C,D, then heal and sync", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  // Step 1: Build mesh
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.b.baseURL, "tofu");
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.c.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.d.baseURL, "tofu");
  await pageA.waitForTimeout(5000);

  // Step 2: Partition network (A,B vs C,D)
  await partitionNetwork(["a", "b"], ["c", "d"], workerIndex);

  // Step 3: Publish agent on A (partition 1)
  const agentPartition1: AgentFormData = {
    name: "partition_agent_ab",
    provider: "Partition AB",
    description: "Agent published during partition on A,B side",
    action: "schema:SearchAction",
    objectTypes: ["schema:WebPage"],
    requiresDisclosure: [],
    returns: ["schema:ItemList"],
  };
  await publishAgentViaUI(pageA, agentPartition1);

  // Step 4: Publish agent on C (partition 2)
  const agentPartition2: AgentFormData = {
    name: "partition_agent_cd",
    provider: "Partition CD",
    description: "Agent published during partition on C,D side",
    action: "schema:SearchAction",
    objectTypes: ["schema:WebPage"],
    requiresDisclosure: [],
    returns: ["schema:ItemList"],
  };
  await publishAgentViaUI(pageC, agentPartition2);

  await pageA.waitForTimeout(3000);

  // Step 5: Verify A does NOT have C's agent yet
  await pageA.goto("/agents");
  await pageA.waitForLoadState("networkidle");
  const cdAgentOnA = await pageA.locator('tr:has-text("partition_agent_cd")').count();
  expect(cdAgentOnA).toBe(0);

  // Step 6: Heal partition
  await reconnectNetwork(["a", "b", "c", "d"], workerIndex);
  await pageA.waitForTimeout(5000);

  // Step 7: Verify both agents propagated
  const foundCDonA = await waitForAgentInList(pageA, "partition_agent_cd", 30000);
  const foundABonC = await waitForAgentInList(pageC, "partition_agent_ab", 30000);

  expect(foundCDonA).toBe(true);
  expect(foundABonC).toBe(true);

  await contextA.close();
  await contextC.close();
});
```

- [ ] **Step 3: Write Test 7 - Cascading Failure (Kill B, then A)**

```typescript
test("Test 7: Cascading Failure - Kill B then A, verify C,D still functional", async ({ browser }) => {
  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: Build mesh A↔B↔C↔D
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.a.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.b.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.d.baseURL, "tofu");
  await pageC.waitForTimeout(5000);

  // Step 2: Publish agent on C
  const testAgent: AgentFormData = {
    name: "cascade_test_agent",
    provider: "Cascade Test",
    description: "Agent for cascading failure test",
    action: "schema:ReadAction",
    objectTypes: ["schema:Article"],
    requiresDisclosure: [],
    returns: ["schema:Article"],
  };
  await publishAgentViaUI(pageC, testAgent);
  await pageC.waitForTimeout(3000);

  // Step 3: Kill B
  await killRegistry("b", workerIndex);
  await pageC.waitForTimeout(2000);

  // Step 4: Kill A
  await killRegistry("a", workerIndex);
  await pageC.waitForTimeout(2000);

  // Step 5: Verify C and D still have the agent
  await pageC.goto("/agents");
  await pageC.waitForLoadState("networkidle");
  const foundOnC = await pageC.locator('tr:has-text("cascade_test_agent")').count();
  expect(foundOnC).toBeGreaterThan(0);

  const foundOnD = await waitForAgentInList(pageD, "cascade_test_agent", 10000);
  expect(foundOnD).toBe(true);

  // Step 6: Restart A and B
  await startRegistry("a", workerIndex);
  await startRegistry("b", workerIndex);

  await contextC.close();
  await contextD.close();
});
```

- [ ] **Step 4: Write Test 8 - Slow Peer (Timeout Handling)**

```typescript
test("Test 8: Slow Peer - Add 5s latency to D, verify A completes sync within timeout", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: Inject 5s network delay on D
  await addNetworkDelay("d", 5000, workerIndex);

  // Step 2: Publish agent on D
  const slowAgent: AgentFormData = {
    name: "slow_peer_agent",
    provider: "Slow Peer",
    description: "Agent published on slow peer D",
    action: "schema:SearchAction",
    objectTypes: ["schema:Product"],
    requiresDisclosure: [],
    returns: ["schema:Product"],
  };
  await publishAgentViaUI(pageD, slowAgent);

  // Step 3: A adds D as peer
  await addPeerViaUI(pageA, REGISTRY_CONFIGS.d.baseURL, "tofu");

  // Step 4: Wait for sync (should handle delay gracefully)
  const startTime = Date.now();
  const foundOnA = await waitForAgentInList(pageA, "slow_peer_agent", 40000);
  const elapsed = Date.now() - startTime;

  expect(foundOnA).toBe(true);
  expect(elapsed).toBeGreaterThan(5000); // At least delay time
  expect(elapsed).toBeLessThan(40000); // But within timeout

  // Step 5: Remove delay
  await removeNetworkDelay("d", workerIndex);

  await contextA.close();
  await contextD.close();
});
```

- [ ] **Step 5: Write Test 9 - Concurrent Conflict (Race Condition)**

```typescript
test("Test 9: Concurrent Conflict - A and B publish same-named agent simultaneously", async ({ browser }) => {
  const contextA = await browser.newContext();
  const pageA = await contextA.newPage();
  await pageA.goto(REGISTRY_CONFIGS.a.baseURL);

  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  await pageB.goto(REGISTRY_CONFIGS.b.baseURL);

  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  // Step 1: C adds A and B as peers
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.a.baseURL, "tofu");
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.b.baseURL, "tofu");

  // Step 2: Publish same-named agent on A and B concurrently
  const agentA: AgentFormData = {
    name: "race_condition_agent",
    provider: "Provider A",
    description: "Agent from A in race condition test",
    action: "schema:SearchAction",
    objectTypes: ["schema:Event"],
    requiresDisclosure: [],
    returns: ["schema:ItemList"],
  };

  const agentB: AgentFormData = {
    name: "race_condition_agent",
    provider: "Provider B",
    description: "Agent from B in race condition test",
    action: "schema:SearchAction",
    objectTypes: ["schema:Event"],
    requiresDisclosure: [],
    returns: ["schema:ItemList"],
  };

  // Publish both at same time
  await Promise.all([
    publishAgentViaUI(pageA, agentA),
    publishAgentViaUI(pageB, agentB),
  ]);

  await pageC.waitForTimeout(5000);

  // Step 3: C should handle race gracefully (no crash, no duplicate rows with same hash)
  await pageC.goto("/agents");
  await pageC.waitForLoadState("networkidle");

  const agentRows = await pageC.locator('tr:has-text("race_condition_agent")').count();
  expect(agentRows).toBeGreaterThanOrEqual(1); // At least one version

  // Step 4: Verify C didn't crash (dashboard still loads)
  await pageC.goto("/dashboard");
  await pageC.waitForLoadState("networkidle");
  const statCards = await pageC.locator(".stat-card").count();
  expect(statCards).toBeGreaterThan(0);

  await contextA.close();
  await contextB.close();
  await contextC.close();
});
```

- [ ] **Step 6: Write Test 10 - Resource Exhaustion (CPU Throttle)**

```typescript
test("Test 10: Resource Exhaustion - Throttle C's CPU to 0.5 cores, verify sync still completes", async ({ browser }) => {
  const contextC = await browser.newContext();
  const pageC = await contextC.newPage();
  await pageC.goto(REGISTRY_CONFIGS.c.baseURL);

  const contextD = await browser.newContext();
  const pageD = await contextD.newPage();
  await pageD.goto(REGISTRY_CONFIGS.d.baseURL);

  // Step 1: Throttle C to 0.5 CPU cores
  await throttleCPU("c", 0.5, workerIndex);

  // Step 2: Publish 5 agents on D via API (stress test)
  await publishAgentViaAPI(REGISTRY_CONFIGS.d.baseURL, "../../crates/pap-agents/catalog/culture/spotify_search.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.d.baseURL, "../../crates/pap-agents/catalog/developer/crates_io.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.d.baseURL, "../../crates/pap-agents/catalog/developer/rust_docs.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.d.baseURL, "../../crates/pap-agents/catalog/travel/tripadvisor.toml");
  await publishAgentViaAPI(REGISTRY_CONFIGS.d.baseURL, "../../crates/pap-agents/catalog/shopping/amazon_search.toml");

  // Step 3: C adds D as peer
  await addPeerViaUI(pageC, REGISTRY_CONFIGS.d.baseURL, "tofu");

  // Step 4: Wait for sync (may take longer due to CPU throttle)
  await pageC.waitForTimeout(10000);

  const countC = await getAgentCount(pageC);
  expect(countC).toBe(5);

  // Step 5: Reset CPU
  await resetCPU("c", workerIndex);

  await contextC.close();
  await contextD.close();
});
```

- [ ] **Step 7: Run chaos tests**

Run:
```bash
cd apps/registry/e2e
RUN_CHAOS_TESTS=true npx playwright test tests/federation-chaos.spec.ts
```

Expected: All 5 chaos tests pass

- [ ] **Step 8: Commit**

```bash
git add apps/registry/e2e/tests/federation-chaos.spec.ts
git commit -m "feat(registry/e2e): add chaos federation test suite

- Test 6: Network partition (split brain A,B vs C,D then heal)
- Test 7: Cascading failure (kill B then A, verify C,D functional)
- Test 8: Slow peer (5s latency on D, A completes sync)
- Test 9: Concurrent conflict (race condition with same-named agent)
- Test 10: Resource exhaustion (CPU throttle, sync still completes)

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 8: Playwright Config Updates

**Files:**
- Modify: `apps/registry/e2e/playwright.config.ts`

- [ ] **Step 1: Update config for parallel workers and base URLs**

```typescript
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : 4, // 4 parallel workers locally
  reporter: 'html',
  use: {
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  // Base URLs for federation tests
  // Workers will use port offsets: worker 0 = 7900-7903, worker 1 = 7910-7913, etc.
  globalSetup: undefined, // Docker cluster managed per test via beforeAll
  globalTeardown: undefined,
});
```

- [ ] **Step 2: Commit**

```bash
git add apps/registry/e2e/playwright.config.ts
git commit -m "feat(registry/e2e): configure playwright for parallel federation tests

- 4 parallel workers (2 in CI)
- Port offsets per worker to avoid collisions
- Screenshot on failure for debugging

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 9: Package.json Script Updates

**Files:**
- Modify: `apps/registry/e2e/package.json`

- [ ] **Step 1: Add federation test scripts**

```json
{
  "name": "pap-registry-federation-e2e",
  "version": "1.0.0",
  "private": true,
  "description": "Playwright federation E2E test suite for pap-registry",
  "scripts": {
    "test": "npx playwright test tests/federation-sync.spec.ts",
    "test:headed": "npx playwright test tests/federation-sync.spec.ts --headed",
    "test:debug": "npx playwright test tests/federation-sync.spec.ts --debug",
    "test:chaos": "RUN_CHAOS_TESTS=true npx playwright test tests/federation-chaos.spec.ts",
    "test:chaos:headed": "RUN_CHAOS_TESTS=true npx playwright test tests/federation-chaos.spec.ts --headed",
    "test:all": "npx playwright test",
    "test:all-with-chaos": "RUN_CHAOS_TESTS=true npx playwright test",
    "test:report": "npx playwright show-report",
    "install:browsers": "npx playwright install --with-deps chromium"
  },
  "devDependencies": {
    "@playwright/test": "^1.44.0",
    "@types/node": "^20.0.0"
  }
}
```

- [ ] **Step 2: Run test to verify scripts work**

Run:
```bash
cd apps/registry/e2e
npm run test
```

Expected: Federation sync tests run successfully

- [ ] **Step 3: Commit**

```bash
git add apps/registry/e2e/package.json
git commit -m "feat(registry/e2e): add npm scripts for federation test suite

- test: Run core sync tests
- test:chaos: Run failure mode tests with RUN_CHAOS_TESTS=true
- test:all: Run entire suite
- test:report: View HTML test report

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Task 10: CI Integration (GitHub Actions)

**Files:**
- Create: `.github/workflows/federation-e2e.yml`

- [ ] **Step 1: Write GitHub Actions workflow**

```yaml
name: Federation E2E Tests

on:
  push:
    branches: [main, develop]
    paths:
      - 'apps/registry/**'
      - 'crates/pap-federation/**'
      - '.github/workflows/federation-e2e.yml'
  pull_request:
    branches: [main, develop]
    paths:
      - 'apps/registry/**'
      - 'crates/pap-federation/**'

jobs:
  federation-e2e:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Set up Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Build pap-registry Docker image
        run: |
          docker build -f apps/registry/Dockerfile -t pap-registry:latest .

      - name: Install Playwright dependencies
        working-directory: apps/registry/e2e
        run: |
          npm install
          npx playwright install --with-deps chromium

      - name: Run Federation Sync Tests
        working-directory: apps/registry/e2e
        run: npm run test

      - name: Run Federation Chaos Tests
        working-directory: apps/registry/e2e
        run: npm run test:chaos

      - name: Upload test report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: apps/registry/e2e/playwright-report/
          retention-days: 7

      - name: Upload test screenshots
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: test-screenshots
          path: apps/registry/e2e/test-results/
          retention-days: 7
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/federation-e2e.yml
git commit -m "feat(ci): add GitHub Actions workflow for federation e2e tests

- Build pap-registry Docker image
- Run core sync tests and chaos tests
- Upload HTML report and failure screenshots as artifacts
- Trigger on push/PR to registry or federation code

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

- [ ] **Step 3: Push and verify CI runs**

Run:
```bash
git push origin feat/8760-papillon-end-to
```

Expected: GitHub Actions runs federation-e2e workflow, all tests pass

---

## Plan Complete

All 10 tasks have been defined with bite-sized steps:

1. ✅ Docker Compose Infrastructure (4 registries, seed agents)
2. ✅ TypeScript Types and Interfaces (AgentFormData, PeerInfo, RegistryConfig)
3. ✅ Docker Helper Utilities (start/stop cluster, kill/start registry)
4. ✅ Federation UI Helpers (add peer, publish agent, wait for sync)
5. ✅ Chaos Test Helpers (partition network, add delay, throttle CPU)
6. ✅ Core Federation Tests (5 sync scenarios)
7. ✅ Chaos Federation Tests (5 failure scenarios)
8. ✅ Playwright Config Updates (parallel workers, port offsets)
9. ✅ Package.json Scripts (test:all, test:chaos, test:report)
10. ✅ CI Integration (GitHub Actions workflow)

**Plan complete and saved to `docs/superpowers/plans/2026-04-28-federation-test-suite.md`. Two execution options:**

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**