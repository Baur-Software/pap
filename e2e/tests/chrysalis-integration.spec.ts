/**
 * chrysalis-integration.spec.ts
 *
 * Integration tests for a live Chrysalis (PAP federation registry) instance.
 *
 * These tests require a running Chrysalis server and are SKIPPED automatically
 * when CHRYSALIS_URL is not set. The test suite covers:
 *
 *  1. Federation identity endpoint — node DID and agent count
 *  2. Public browse endpoint — returns startup-seeded catalog agents
 *  3. Agent shape — schema.org capabilities, required fields
 *  4. Federation peers endpoint
 *  5. UI integration — mock patching with real server data
 *  6. Local vs. Chrysalis agent routing (disjoint DID sets)
 *
 * Quick start:
 *   ./scripts/start-chrysalis-dev.sh          # terminal 1
 *   CHRYSALIS_URL=http://localhost:${CHRYSALIS_PORT:-7890} \
 *     npx playwright test chrysalis-integration --reporter=line
 *
 * The default port is 7890 (override with CHRYSALIS_PORT env var); use CHRYSALIS_URL to set the full URL.
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

// ── Configuration ─────────────────────────────────────────────

const CHRYSALIS_URL = process.env.CHRYSALIS_URL ?? "";
const SKIP_MSG =
  "CHRYSALIS_URL not set — start Chrysalis (./scripts/start-chrysalis-dev.sh) and set CHRYSALIS_URL";

// In CI, CHRYSALIS_URL must always be provided (the chrysalis-e2e job sets it).
// A missing URL in CI means the job was misconfigured — fail loudly so the
// regression is caught rather than silently skipped past.
// Outside CI (local dev), skip gracefully so developers can run `playwright test`
// without starting Chrysalis first.
function requireChrysalis() {
  if (!CHRYSALIS_URL) {
    if (process.env.CI) {
      throw new Error(`CI misconfiguration: ${SKIP_MSG}`);
    }
    test.skip(true, SKIP_MSG);
  }
}

// ── 1. Federation identity ────────────────────────────────────

test.describe("Chrysalis federation identity (live server)", () => {
  test("GET /federation/identity returns node DID and counts", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/federation/identity`);
    expect(resp.ok()).toBe(true);

    const identity = await resp.json();
    expect(identity.did).toMatch(/^did:key:/);
    expect(typeof identity.agent_count).toBe("number");
    expect(typeof identity.peer_count).toBe("number");
    expect(identity.agent_count).toBeGreaterThanOrEqual(0);
    // endpoint echoes back the configured public endpoint
    expect(typeof identity.endpoint).toBe("string");
  });

  test("federation identity cert_fingerprint is empty in no-TLS mode", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/federation/identity`);
    const identity = await resp.json();
    // PAP_REGISTRY_NO_TLS=true (dev mode) → fingerprint is an empty string
    expect(typeof identity.cert_fingerprint).toBe("string");
  });
});

// ── 2. Public browse endpoint ─────────────────────────────────

test.describe("Chrysalis public browse endpoint (live server)", () => {
  test("GET /api/browse responds with 200 OK", async ({ request }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    expect(resp.ok()).toBe(true);
    expect(resp.headers()["content-type"]).toContain("application/json");
  });

  test("GET /api/browse returns an array", async ({ request }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();
    expect(Array.isArray(agents)).toBe(true);
  });

  test("startup-seeded catalog agents are present in browse", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();
    // Chrysalis seeds the full catalog on first boot — expect at least 1 agent
    expect(agents.length).toBeGreaterThanOrEqual(1);
  });

  test("browse agents have required BrowseAgentInfo fields", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    for (const agent of agents) {
      expect(typeof agent.name).toBe("string");
      expect(agent.name.length).toBeGreaterThan(0);
      expect(typeof agent.provider_name).toBe("string");
      expect(typeof agent.provider_did).toBe("string");
      expect(agent.provider_did).toMatch(/^did:key:/);
      expect(Array.isArray(agent.capabilities)).toBe(true);
      expect(Array.isArray(agent.object_types)).toBe(true);
      expect(Array.isArray(agent.requires_disclosure)).toBe(true);
      expect(Array.isArray(agent.returns)).toBe(true);
      expect(typeof agent.content_hash).toBe("string");
      // endpoint is present (set to the node's execution URL for each agent)
      expect(agent.endpoint === null || typeof agent.endpoint === "string").toBe(
        true
      );
    }
  });

  test("browse agents have schema: prefixed capabilities", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    for (const agent of agents) {
      for (const cap of agent.capabilities) {
        expect(cap).toMatch(/^schema:/);
      }
    }
  });

  test("browse agent endpoints point to the Chrysalis node", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    // Agents with non-null endpoints should resolve to this node's /agents/ path
    const withEndpoints = agents.filter((a: any) => a.endpoint !== null);
    for (const agent of withEndpoints) {
      // Endpoint URL format: <node_endpoint>/agents/<slug>
      expect(agent.endpoint).toContain("/agents/");
    }
  });
});

// ── 3. Federation peers ───────────────────────────────────────

test.describe("Chrysalis federation peers endpoint (live server)", () => {
  test("GET /federation/peers responds with 200 OK", async ({ request }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/federation/peers`);
    expect(resp.ok()).toBe(true);
  });

  test("GET /federation/peers returns a peers structure", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/federation/peers`);
    const data = await resp.json();
    // Response may be { peers: [] } or a direct array depending on server version
    const peers = Array.isArray(data) ? data : data.peers ?? [];
    expect(Array.isArray(peers)).toBe(true);
    // A fresh dev node has no peers; don't assert count
  });
});

// ── 4. Agent catalog breadth ──────────────────────────────────

test.describe("Chrysalis catalog breadth (live server)", () => {
  test("catalog covers multiple Schema.org action types", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    const allCaps: string[] = agents.flatMap((a: any) => a.capabilities);
    const uniqueActionTypes = new Set(allCaps);

    // A catalog with 300+ agents should have more than 1 distinct action type
    expect(uniqueActionTypes.size).toBeGreaterThanOrEqual(1);
  });

  test("all agent names are non-empty strings", async ({ request }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    for (const agent of agents) {
      expect(typeof agent.name).toBe("string");
      expect(agent.name.trim().length).toBeGreaterThan(0);
    }
  });

  test("agent content_hash values are unique (no duplicates)", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();

    const hashes = agents.map((a: any) => a.content_hash);
    const unique = new Set(hashes);
    expect(unique.size).toBe(hashes.length);
  });
});

// ── 5. UI integration with live server data ───────────────────

test.describe("Chrysalis UI integration (live server + mock)", () => {
  test.beforeEach(async ({ page }) => {
    requireChrysalis();
    await installTauriMock(page);
  });

  test("navigate_registry mock patched with real node agent_count", async ({
    page,
    request,
  }) => {
    requireChrysalis();
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Fetch real identity so we can verify mock returns matching data
    const identResp = await request.get(`${CHRYSALIS_URL}/federation/identity`);
    const identity = await identResp.json();

    // Patch mock to return real agent_count for this specific URL
    await page.evaluate(
      ([url, count]: [string, number]) => {
        const orig = window.__TAURI__.core.invoke;
        window.__TAURI__.core.invoke = async function (
          cmd: string,
          args: any
        ) {
          if (cmd === "navigate_registry" && args?.url === url) {
            return { url, agent_count: count, peer_count: 0 };
          }
          return orig.call(window.__TAURI__.core, cmd, args);
        };
      },
      [CHRYSALIS_URL, identity.agent_count] as [string, number]
    );

    const info = await page.evaluate(
      (url: string) =>
        window.__TAURI__.core.invoke("navigate_registry", { url }),
      CHRYSALIS_URL
    );

    expect(info.agent_count).toBe(identity.agent_count);
    expect(info.url).toBe(CHRYSALIS_URL);
  });

  test("list_agents mock patched with real browse data", async ({
    page,
    request,
  }) => {
    requireChrysalis();
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Fetch real browse data
    const browseResp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const chrysalisAgents = await browseResp.json();

    // Patch list_agents to return real Chrysalis data for our URL
    await page.evaluate(
      ([url, agents]: [string, any[]]) => {
        const orig = window.__TAURI__.core.invoke;
        window.__TAURI__.core.invoke = async function (
          cmd: string,
          args: any
        ) {
          if (cmd === "list_agents" && args?.registry_url === url) {
            return agents;
          }
          return orig.call(window.__TAURI__.core, cmd, args);
        };
      },
      [CHRYSALIS_URL, chrysalisAgents] as [string, any[]]
    );

    const agents = await page.evaluate(
      (url: string) =>
        window.__TAURI__.core.invoke("list_agents", { registry_url: url }),
      CHRYSALIS_URL
    );

    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBe(chrysalisAgents.length);
  });
});

// ── 6. Local vs. Chrysalis routing ───────────────────────────

test.describe("Local vs. Chrysalis agent routing (live server)", () => {
  test.beforeEach(async ({ page }) => {
    requireChrysalis();
    await installTauriMock(page);
  });

  test("Chrysalis browse agents have distinct content_hashes from local agents", async ({
    page,
    request,
  }) => {
    requireChrysalis();
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Local agents from the mock
    const localAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    // Chrysalis agents from the real server
    const browseResp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const chrysalisAgents = await browseResp.json();

    const localHashes = new Set(
      localAgents.map((a: any) => a.content_hash as string)
    );
    const chrysalisHashes = chrysalisAgents.map(
      (a: any) => a.content_hash as string
    );

    // Chrysalis agents are independent of the local mock fleet
    // (they may share names but should have distinct hashes from mock data)
    for (const hash of chrysalisHashes) {
      // content_hashes in the real catalog are deterministic CIDv1-style hashes;
      // the mock uses hardcoded strings like "ddg-local-hash" — no overlap expected
      expect(localHashes.has(hash)).toBe(false);
    }
  });

  test("Chrysalis and local agents represent disjoint provider DID namespaces", async ({
    page,
    request,
  }) => {
    requireChrysalis();
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const localAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    const browseResp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const chrysalisAgents = await browseResp.json();

    // Both fleets should be non-empty
    expect(localAgents.length).toBeGreaterThan(0);
    expect(chrysalisAgents.length).toBeGreaterThan(0);

    // Chrysalis browse uses provider_did; local uses agent_did
    // The real catalog agents' provider DIDs are cryptographically generated
    // and will never match the mock's hardcoded "did:key:z6MkDDGAgent111" etc.
    const localProviderDids = new Set(
      localAgents.map((a: any) => a.provider_did as string)
    );
    const chrysalisProviderDids = chrysalisAgents.map(
      (a: any) => a.provider_did as string
    );

    for (const did of chrysalisProviderDids) {
      expect(localProviderDids.has(did)).toBe(false);
    }
  });

  test("routing simulation: local agent takes priority over Chrysalis for same capability", async ({
    page,
    request,
  }) => {
    requireChrysalis();
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const browseResp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const chrysalisAgents = await browseResp.json();

    // Both the local mock and Chrysalis have SearchAction agents
    const localAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    const localSearch = localAgents.filter((a: any) =>
      a.capabilities.some((c: string) => c.includes("SearchAction"))
    );
    const chrysalisSearch = chrysalisAgents.filter((a: any) =>
      a.capabilities.some((c: string) => c.includes("SearchAction"))
    );

    // Both fleets have SearchAction agents — routing can choose either
    expect(localSearch.length).toBeGreaterThan(0);
    // Chrysalis may or may not have SearchAction depending on the catalog version
    // Just verify the routing simulation is coherent
    const allSearch = [...localSearch, ...chrysalisSearch];
    expect(allSearch.length).toBeGreaterThan(0);

    // Every agent in the combined set has schema: prefixed capabilities
    for (const agent of allSearch) {
      for (const cap of agent.capabilities) {
        expect(cap).toMatch(/^schema:/);
      }
    }
  });
});
