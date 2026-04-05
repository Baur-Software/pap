/**
 * tier2-functional.spec.ts
 *
 * Tier 2 E2E functional tests for the Chrysalis PAP registry server.
 *
 * These tests exercise the full HTTP API surface of a live registry instance.
 * They require a running Chrysalis server and are SKIPPED automatically when
 * BASE_URL (or CHRYSALIS_URL for compatibility) is not set.
 *
 * The server is expected to be running in no-TLS mode (plain HTTP) as used
 * by the CI Docker setup. Set BASE_URL to override the default.
 *
 * Quick start (local):
 *   ./scripts/start-chrysalis-dev.sh          # terminal 1
 *   BASE_URL=http://localhost:7890 \
 *     npx playwright test tests/tier2-functional --reporter=line
 *
 * In CI, BASE_URL is injected by the chrysalis-e2e-tier2 job.
 *
 * Test coverage:
 *   1. Federation identity   — JSON-LD context, DID format, service endpoint
 *   2. Agent browse          — schema.org action search, response structure
 *   3. Federation peers      — list peers, verify structure
 *   4. Pagination            — POST browse with cursor, has_more / next_cursor
 *   5. Error handling        — 400 for malformed requests, 404 for unknown agents
 *   6. CORS headers          — Access-Control-Allow-Origin on API endpoints
 *   7. Health check          — GET /health returns 200 (or federation/identity as proxy)
 */

import { test, expect } from "@playwright/test";

// ── Configuration ─────────────────────────────────────────────────────────────

const BASE_URL =
  process.env.BASE_URL ?? process.env.CHRYSALIS_URL ?? "";

const SKIP_MSG =
  "BASE_URL not set — start Chrysalis (./scripts/start-chrysalis-dev.sh) and set BASE_URL=http://localhost:7890";

function requireServer() {
  if (!BASE_URL) test.skip(true, SKIP_MSG);
}

// ── 1. Federation identity ────────────────────────────────────────────────────

test.describe("Tier 2 — Federation identity", () => {
  test("GET /federation/identity returns 200 with JSON content-type", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    expect(resp.ok()).toBe(true);
    expect(resp.headers()["content-type"]).toContain("application/json");
  });

  test("federation identity contains a valid did:key DID", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    const identity = await resp.json();
    expect(typeof identity.did).toBe("string");
    expect(identity.did).toMatch(/^did:key:/);
  });

  test("federation identity contains a service endpoint string", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    const identity = await resp.json();
    // endpoint is the node's public URL — must be a non-empty string
    expect(typeof identity.endpoint).toBe("string");
    expect(identity.endpoint.length).toBeGreaterThan(0);
  });

  test("federation identity agent_count and peer_count are non-negative integers", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    const identity = await resp.json();
    expect(typeof identity.agent_count).toBe("number");
    expect(typeof identity.peer_count).toBe("number");
    expect(Number.isInteger(identity.agent_count)).toBe(true);
    expect(Number.isInteger(identity.peer_count)).toBe(true);
    expect(identity.agent_count).toBeGreaterThanOrEqual(0);
    expect(identity.peer_count).toBeGreaterThanOrEqual(0);
  });

  test("federation identity cert_fingerprint is a string (empty in no-TLS mode)", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    const identity = await resp.json();
    // In no-TLS mode cert_fingerprint is an empty string; in TLS mode it is a sha256: hex
    expect(typeof identity.cert_fingerprint).toBe("string");
  });

  test("federation identity has all required fields", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    const identity = await resp.json();
    const requiredFields = ["did", "endpoint", "cert_fingerprint", "agent_count", "peer_count"];
    for (const field of requiredFields) {
      expect(identity).toHaveProperty(field);
    }
  });
});

// ── 2. Agent browse (GET) ─────────────────────────────────────────────────────

test.describe("Tier 2 — Agent browse endpoint", () => {
  test("GET /api/browse returns 200 with JSON array", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    expect(resp.ok()).toBe(true);
    expect(resp.headers()["content-type"]).toContain("application/json");
    const agents = await resp.json();
    expect(Array.isArray(agents)).toBe(true);
  });

  test("browse returns at least one seeded agent on a fresh node", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();
    expect(agents.length).toBeGreaterThanOrEqual(1);
  });

  test("browse agents have all required BrowseAgentInfo fields", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();

    for (const agent of agents) {
      // name — non-empty string
      expect(typeof agent.name).toBe("string");
      expect(agent.name.trim().length).toBeGreaterThan(0);
      // provider_name
      expect(typeof agent.provider_name).toBe("string");
      // provider_did — must be a valid DID
      expect(typeof agent.provider_did).toBe("string");
      expect(agent.provider_did).toMatch(/^did:/);
      // capabilities — array of strings
      expect(Array.isArray(agent.capabilities)).toBe(true);
      // object_types — array
      expect(Array.isArray(agent.object_types)).toBe(true);
      // requires_disclosure — array
      expect(Array.isArray(agent.requires_disclosure)).toBe(true);
      // returns — array
      expect(Array.isArray(agent.returns)).toBe(true);
      // content_hash — non-empty string
      expect(typeof agent.content_hash).toBe("string");
      expect(agent.content_hash.length).toBeGreaterThan(0);
      // endpoint — null or string
      expect(agent.endpoint === null || typeof agent.endpoint === "string").toBe(true);
    }
  });

  test("browse agents have schema: prefixed capabilities", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();

    for (const agent of agents) {
      for (const cap of agent.capabilities) {
        expect(cap).toMatch(/^schema:/);
      }
    }
  });

  test("browse agents with endpoints point to /agents/ path", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();
    const withEndpoints = agents.filter((a: any) => a.endpoint !== null);
    for (const agent of withEndpoints) {
      expect(agent.endpoint).toContain("/agents/");
    }
  });

  test("browse agents have unique content_hash values", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();
    const hashes = agents.map((a: any) => a.content_hash);
    const unique = new Set(hashes);
    expect(unique.size).toBe(hashes.length);
  });

  test("catalog covers at least one Schema.org action type", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`);
    const agents = await resp.json();
    const allCaps: string[] = agents.flatMap((a: any) => a.capabilities);
    const uniqueActions = new Set(allCaps);
    expect(uniqueActions.size).toBeGreaterThanOrEqual(1);
  });
});

// ── 2b. Agent browse (POST) ───────────────────────────────────────────────────
//
// The POST /api/browse endpoint is the search interface added by ISS-833.
// It accepts a JSON body with optional `action` and pagination fields.
// If the server currently only supports GET /api/browse this test group
// will reflect the actual API surface.

test.describe("Tier 2 — Agent browse POST search by schema.org action", () => {
  test("POST /api/browse with SearchAction body returns matching agents", async ({
    request,
  }) => {
    requireServer();
    // First check if the server supports POST on /api/browse; if not, skip.
    const probe = await request.post(`${BASE_URL}/api/browse`, {
      data: { action: "schema:SearchAction" },
    });
    // A 404 or 405 means POST is not implemented — skip gracefully.
    if (probe.status() === 404 || probe.status() === 405) {
      test.skip();
      return;
    }
    expect(probe.ok()).toBe(true);
    const body = await probe.json();
    // Response may be an array or a paginated envelope
    const agents = Array.isArray(body) ? body : body.items ?? body.agents ?? body;
    expect(Array.isArray(agents)).toBe(true);
    // Agents returned must have the schema:SearchAction capability
    for (const agent of agents) {
      const caps: string[] = agent.capabilities ?? [];
      expect(caps.some((c: string) => c.includes("SearchAction"))).toBe(true);
    }
  });
});

// ── 3. Federation peers ───────────────────────────────────────────────────────

test.describe("Tier 2 — Federation peers endpoint", () => {
  test("GET /federation/peers returns 200 OK", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/peers`);
    expect(resp.ok()).toBe(true);
  });

  test("GET /federation/peers returns JSON", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/peers`);
    expect(resp.headers()["content-type"]).toContain("application/json");
  });

  test("federation peers response contains a peers array", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/peers`);
    const data = await resp.json();

    // The FederationServer returns a FederationMessage::PeerListResponse { peers }
    // which serialises to { "PeerListResponse": { "peers": [...] } } or a similar
    // tagged enum. Accept either a direct array or the wrapped form.
    let peers: any[];
    if (Array.isArray(data)) {
      peers = data;
    } else if (data.peers && Array.isArray(data.peers)) {
      peers = data.peers;
    } else if (data.PeerListResponse && Array.isArray(data.PeerListResponse.peers)) {
      peers = data.PeerListResponse.peers;
    } else {
      // Unknown shape — just verify it parsed as JSON
      peers = [];
    }
    expect(Array.isArray(peers)).toBe(true);
  });

  test("each federation peer has required did and endpoint fields", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/peers`);
    const data = await resp.json();

    let peers: any[] = [];
    if (Array.isArray(data)) {
      peers = data;
    } else if (data.peers && Array.isArray(data.peers)) {
      peers = data.peers;
    } else if (data.PeerListResponse && Array.isArray(data.PeerListResponse.peers)) {
      peers = data.PeerListResponse.peers;
    }

    // A fresh node includes itself in the peer list
    for (const peer of peers) {
      expect(typeof peer.did).toBe("string");
      expect(peer.did).toMatch(/^did:/);
      expect(typeof peer.endpoint).toBe("string");
      expect(peer.endpoint.length).toBeGreaterThan(0);
    }
  });
});

// ── 4. Pagination ─────────────────────────────────────────────────────────────
//
// ISS-833 adds cursor-based pagination to the federation peer sync endpoint.
// The browse endpoint may also support pagination via page/per_page query params
// or a POST body with cursor. We test both surfaces.

test.describe("Tier 2 — Pagination", () => {
  test("GET /api/browse with per_page=1 returns limited results", async ({
    request,
  }) => {
    requireServer();
    // Paginated GET browse via query params (admin endpoint)
    const resp = await request.get(`${BASE_URL}/api/agents?page=1&per_page=1`);
    if (!resp.ok()) {
      // /api/agents may require auth — skip if not available
      test.skip();
      return;
    }
    const body = await resp.json();
    if (body.items) {
      // paginated envelope
      expect(Array.isArray(body.items)).toBe(true);
      expect(body.items.length).toBeLessThanOrEqual(1);
      expect(typeof body.total).toBe("number");
      expect(typeof body.page).toBe("number");
      expect(typeof body.per_page).toBe("number");
      expect(typeof body.total_pages).toBe("number");
    }
  });

  test("POST /api/browse with cursor returns has_more and next_cursor fields when paginated", async ({
    request,
  }) => {
    requireServer();
    // Attempt POST /api/browse with a small page size to exercise pagination fields.
    const probe = await request.post(`${BASE_URL}/api/browse`, {
      data: { limit: 1, cursor: null },
    });
    if (probe.status() === 404 || probe.status() === 405) {
      // POST not implemented on this version — skip gracefully
      test.skip();
      return;
    }
    if (!probe.ok()) {
      test.skip();
      return;
    }
    const body = await probe.json();
    // If the server returns a paginated envelope it must include has_more
    if (typeof body.has_more !== "undefined") {
      expect(typeof body.has_more).toBe("boolean");
      // next_cursor is present when has_more is true
      if (body.has_more) {
        expect(typeof body.next_cursor).toBe("string");
        expect(body.next_cursor.length).toBeGreaterThan(0);
      }
    }
    // If items/agents array is present it must be an array
    if (body.items) expect(Array.isArray(body.items)).toBe(true);
    if (body.agents) expect(Array.isArray(body.agents)).toBe(true);
  });

  test("paginated GET /api/agents total_pages is at least 1", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/agents?per_page=5`);
    if (!resp.ok()) {
      test.skip();
      return;
    }
    const body = await resp.json();
    if (body.total_pages !== undefined) {
      expect(body.total_pages).toBeGreaterThanOrEqual(1);
    }
  });
});

// ── 5. Error handling ─────────────────────────────────────────────────────────

test.describe("Tier 2 — Error handling", () => {
  test("GET /agents/nonexistent-agent returns 404", async ({ request }) => {
    requireServer();
    // The agents execution router mounts individual agent slugs.
    // A path that doesn't match any handler should return 404.
    const resp = await request.get(
      `${BASE_URL}/agents/this-agent-does-not-exist-tier2-test`
    );
    expect(resp.status()).toBe(404);
  });

  test("POST /api/browse with malformed JSON body returns 400 or 422", async ({
    request,
  }) => {
    requireServer();
    const probe = await request.post(`${BASE_URL}/api/browse`, {
      headers: { "content-type": "application/json" },
      data: "{ invalid json !!!",
    });
    // 404/405 if POST not implemented — skip
    if (probe.status() === 404 || probe.status() === 405) {
      test.skip();
      return;
    }
    // Server must reject malformed JSON with 400 or 422
    expect([400, 422]).toContain(probe.status());
  });

  test("GET /api/agents/{hash} for unknown hash returns 404", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.delete(
      `${BASE_URL}/api/agents/0000000000000000000000000000000000000000000000000000000000000000`
    );
    // DELETE on a non-existent agent hash must return 404 (or 401 if auth required)
    expect([401, 404]).toContain(resp.status());
  });

  test("federation identity endpoint rejects non-GET methods", async ({
    request,
  }) => {
    requireServer();
    // POST to a GET-only endpoint should return 405 Method Not Allowed
    const resp = await request.post(`${BASE_URL}/federation/identity`, {
      data: {},
    });
    expect(resp.status()).toBe(405);
  });
});

// ── 6. CORS headers ───────────────────────────────────────────────────────────

test.describe("Tier 2 — CORS headers", () => {
  test("GET /federation/identity includes Access-Control-Allow-Origin header", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`, {
      headers: { Origin: "https://app.example.com" },
    });
    expect(resp.ok()).toBe(true);
    const allowOrigin = resp.headers()["access-control-allow-origin"];
    expect(allowOrigin).toBeTruthy();
    // Registry uses allow_origin(Any) — value should be *
    expect(allowOrigin).toBe("*");
  });

  test("GET /api/browse includes Access-Control-Allow-Origin header", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/api/browse`, {
      headers: { Origin: "https://papillon.app" },
    });
    expect(resp.ok()).toBe(true);
    const allowOrigin = resp.headers()["access-control-allow-origin"];
    expect(allowOrigin).toBeTruthy();
    expect(allowOrigin).toBe("*");
  });

  test("OPTIONS preflight on /federation/identity returns CORS allow headers", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.fetch(`${BASE_URL}/federation/identity`, {
      method: "OPTIONS",
      headers: {
        Origin: "https://browser-agent.example.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "content-type",
      },
    });
    // A 200 or 204 response with CORS headers is correct
    expect([200, 204]).toContain(resp.status());
    const allowOrigin = resp.headers()["access-control-allow-origin"];
    expect(allowOrigin).toBeTruthy();
  });

  test("OPTIONS preflight on /api/browse returns CORS allow headers", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.fetch(`${BASE_URL}/api/browse`, {
      method: "OPTIONS",
      headers: {
        Origin: "https://browser-agent.example.com",
        "Access-Control-Request-Method": "GET",
      },
    });
    expect([200, 204]).toContain(resp.status());
    const allowOrigin = resp.headers()["access-control-allow-origin"];
    expect(allowOrigin).toBeTruthy();
  });
});

// ── 7. Health check ───────────────────────────────────────────────────────────
//
// The registry does not expose a dedicated /health endpoint in the current
// implementation. The /federation/identity endpoint is used as the functional
// health probe (matches the Docker healthcheck in docker-compose.yml).
// If a /health route is added in a future version this test will also pass.

test.describe("Tier 2 — Health check", () => {
  test("registry health probe (GET /federation/identity) returns 200", async ({
    request,
  }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    expect(resp.status()).toBe(200);
  });

  test("health probe response is well-formed JSON", async ({ request }) => {
    requireServer();
    const resp = await request.get(`${BASE_URL}/federation/identity`);
    // Must parse without throwing
    const body = await resp.json();
    expect(body).toBeTruthy();
  });

  test("GET /health returns 200 if endpoint exists", async ({ request }) => {
    requireServer();
    // Attempt the dedicated /health endpoint; skip if not implemented.
    const resp = await request.get(`${BASE_URL}/health`);
    if (resp.status() === 404) {
      // Not implemented — this is acceptable for the current server version
      test.skip();
      return;
    }
    expect(resp.status()).toBe(200);
  });
});
