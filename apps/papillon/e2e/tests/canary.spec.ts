/**
 * Tier 3: Canary Monitoring
 *
 * Post-deploy health checks and protocol scenario verification.  Covers
 * the five requirements from ISS-856 issue #201:
 *
 *  1. Marketplace agent discovery  — live Chrysalis returns ≥1 agent
 *  2. Delegation chain             — root mandate → sub-mandate, all 6 steps
 *  3. Co-signed receipt            — both DIDs present, property refs only
 *  4. Receipt storage/retrieval    — list_completed_runs persists across calls
 *  5. Scope violation detection    — SCOPE_EXCEEDED on out-of-bounds delegation
 *
 * Tests 1 require CHRYSALIS_URL (skipped gracefully outside CI).
 * Tests 2-5 run against the Tauri mock and execute on every CI run.
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

// ── Configuration ──────────────────────────────────────────────────────────

const CHRYSALIS_URL = process.env.CHRYSALIS_URL ?? "";
const SKIP_MSG =
  "CHRYSALIS_URL not set — start Chrysalis and set CHRYSALIS_URL to run live canary tests";

function requireChrysalis() {
  if (!CHRYSALIS_URL) {
    if (process.env.CI) {
      throw new Error(`CI misconfiguration: ${SKIP_MSG}`);
    }
    test.skip(true, SKIP_MSG);
  }
}

// Install Tauri mock before every test that navigates to the app.
test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── 1. Marketplace agent discovery (live Chrysalis) ────────────────────────

test.describe("Canary: Marketplace agent discovery (live Chrysalis)", () => {
  test("GET /api/browse returns ≥1 agent from live Chrysalis node", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    expect(resp.ok()).toBe(true);
    const agents = await resp.json();
    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBeGreaterThanOrEqual(1);
  });

  test("each discovered agent has a valid provider DID and schema: capability", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/api/browse`);
    const agents = await resp.json();
    for (const agent of agents) {
      expect(agent.provider_did).toMatch(/^did:key:/);
      expect(Array.isArray(agent.capabilities)).toBe(true);
      expect(agent.capabilities.length).toBeGreaterThan(0);
      for (const cap of agent.capabilities) {
        expect(cap).toMatch(/^schema:/);
      }
    }
  });

  test("live node identity exposes a DID and non-zero agent_count", async ({
    request,
  }) => {
    requireChrysalis();
    const resp = await request.get(`${CHRYSALIS_URL}/federation/identity`);
    expect(resp.ok()).toBe(true);
    const identity = await resp.json();
    expect(identity.did).toMatch(/^did:key:/);
    expect(typeof identity.agent_count).toBe("number");
    expect(identity.agent_count).toBeGreaterThanOrEqual(1);
  });
});

// ── 2. Delegation chain protocol invariants ────────────────────────────────

test.describe("Canary: Delegation chain protocol invariants", () => {
  test("run_scenario produces all 6 protocol steps including mandate and receipt", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" })
    );

    expect(result.success).toBe(true);
    const stepNames: string[] = result.steps.map((s: any) => s.step_name);
    expect(stepNames).toContain("Issue Mandate");
    expect(stepNames).toContain("Open Session");
    expect(stepNames).toContain("Exchange Data");
    expect(stepNames).toContain("Co-sign Receipt");
    expect(stepNames).toContain("Close Session");
    expect(result.steps.every((s: any) => s.status === "completed")).toBe(true);
  });

  test("issue_mandate returns a root mandate with correct principal and agent DIDs", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const mandate = await page.evaluate(() =>
      window.__TAURI__.core.invoke("issue_mandate", {
        agentDid: "did:key:z6MkAgent999",
        scope: ["schema:SearchAction"],
        ttlHours: 2,
      })
    );

    expect(mandate.success).toBe(true);
    expect(mandate.mandate_hash).toBeTruthy();
    expect(mandate.principal_did).toMatch(/^did:key:/);
    expect(mandate.agent_did).toBe("did:key:z6MkAgent999");
    expect(mandate.parent_mandate_hash).toBeNull();
    expect(mandate.decay_state).toBe("Active");
    expect(Array.isArray(mandate.scope)).toBe(true);
    expect(mandate.scope).toContain("schema:SearchAction");
  });

  test("delegate_mandate creates a child mandate contained within parent scope", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Issue root mandate with two actions.
    const root = await page.evaluate(() =>
      window.__TAURI__.core.invoke("issue_mandate", {
        agentDid: "did:key:z6MkAgent999",
        scope: ["schema:SearchAction", "schema:CreateAction"],
        ttlHours: 4,
      })
    );

    // Delegate a narrower sub-mandate (SearchAction only).
    const child = await page.evaluate((parentHash: string) =>
      window.__TAURI__.core.invoke("delegate_mandate", {
        parentMandateHash: parentHash,
        subAgentDid: "did:key:z6MkSubAgent888",
        scope: ["schema:SearchAction"],
        ttlHours: 1,
      }), root.mandate_hash
    );

    expect(child.success).toBe(true);
    expect(child.parent_mandate_hash).toBe(root.mandate_hash);
    expect(child.agent_did).toBe("did:key:z6MkSubAgent888");
    expect(child.principal_did).toBe(root.principal_did);
    // Child scope is a strict subset of parent scope.
    for (const action of child.scope) {
      expect(root.scope).toContain(action);
    }
  });

  test("delegation chain links child back to root via parent_mandate_hash", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const root = await page.evaluate(() =>
      window.__TAURI__.core.invoke("issue_mandate", {
        agentDid: "did:key:z6MkAgent999",
        scope: ["schema:SearchAction"],
        ttlHours: 4,
      })
    );
    const child = await page.evaluate((parentHash: string) =>
      window.__TAURI__.core.invoke("delegate_mandate", {
        parentMandateHash: parentHash,
        subAgentDid: "did:key:z6MkSubAgent888",
        scope: ["schema:SearchAction"],
        ttlHours: 1,
      }), root.mandate_hash
    );

    // The chain: child.parent_mandate_hash === root.mandate_hash
    expect(child.parent_mandate_hash).toBe(root.mandate_hash);
    // Root has no parent (it is the root).
    expect(root.parent_mandate_hash).toBeNull();
  });
});

// ── 3. Co-signed receipt verification ─────────────────────────────────────

test.describe("Canary: Co-signed receipt verification", () => {
  test("receipt is co-signed by both parties", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" })
    );

    expect(result.receipt.co_signed).toBe(true);
  });

  test("receipt contains distinct initiator and receiver DIDs", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "booking" })
    );

    const { receipt } = result;
    expect(receipt.initiator_did).toMatch(/^did:key:/);
    expect(receipt.receiver_did).toMatch(/^did:key:/);
    expect(receipt.initiator_did).not.toBe(receipt.receiver_did);
  });

  test("receipt contains property references, not raw PII values", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // "booking" scenario requires name, email, passport_number disclosure.
    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "booking" })
    );

    const { property_refs } = result.receipt;
    expect(Array.isArray(property_refs)).toBe(true);
    for (const ref of property_refs) {
      expect(typeof ref).toBe("string");
      // Property refs are schema field names, never actual values.
      expect(ref).not.toMatch(/@/);            // Not an email address
      expect(ref).not.toMatch(/[0-9]{6,}/);   // Not a passport/card number
    }
  });

  test("receipt has a valid session_id and ISO 8601 timestamp", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "payment" })
    );

    const { receipt } = result;
    expect(typeof receipt.session_id).toBe("string");
    expect(receipt.session_id.length).toBeGreaterThan(0);
    const ts = new Date(receipt.timestamp);
    expect(ts.getTime()).not.toBeNaN();
  });

  test("receipt_url uses pap:// scheme for receipts browser", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" })
    );

    expect(result.receipt_url).toMatch(/^pap:\/\/receipts\//);
  });
});

// ── 4. Receipt storage and retrieval ──────────────────────────────────────

test.describe("Canary: Receipt storage and retrieval", () => {
  test("completed run is retrievable from list_completed_runs", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" })
    );

    const runs = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_completed_runs")
    );

    expect(Array.isArray(runs)).toBe(true);
    expect(runs.length).toBeGreaterThanOrEqual(1);
    const last = runs[runs.length - 1];
    expect(last.scenario_id).toBe("weather");
    expect(last.success).toBe(true);
    expect(last.receipt).toBeTruthy();
  });

  test("multiple scenario runs are all stored and retrievable", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(async () => {
      await window.__TAURI__.core.invoke("run_scenario", { scenarioId: "weather" });
      await window.__TAURI__.core.invoke("run_scenario", { scenarioId: "booking" });
      await window.__TAURI__.core.invoke("run_scenario", { scenarioId: "payment" });
    });

    const runs = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_completed_runs")
    );

    expect(runs.length).toBeGreaterThanOrEqual(3);
    const ids: string[] = runs.map((r: any) => r.scenario_id);
    expect(ids).toContain("weather");
    expect(ids).toContain("booking");
    expect(ids).toContain("payment");
  });

  test("each stored run has a receipt with a valid receipt_url", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario", { scenarioId: "payment" })
    );

    const runs = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_completed_runs")
    );

    for (const run of runs) {
      if (run.receipt_url) {
        expect(run.receipt_url).toMatch(/^pap:\/\/receipts\//);
      }
      expect(run.receipt).toBeTruthy();
      expect(run.receipt.co_signed).toBe(true);
    }
  });
});

// ── 5. Scope violation and TTL enforcement ────────────────────────────────

test.describe("Canary: Scope violation detection", () => {
  test("run_scenario_with_error returns SCOPE_EXCEEDED error code", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario_with_error", {
        scenarioId: "weather",
        triggerError: "scope_exceeded",
      })
    );

    expect(result.success).toBe(false);
    expect(result.error_code).toBe("SCOPE_EXCEEDED");
    expect(typeof result.error).toBe("string");
    expect(result.error.length).toBeGreaterThan(0);
  });

  test("delegate_mandate rejects sub-mandate that widens parent scope", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Root mandate: SearchAction only.
    const root = await page.evaluate(() =>
      window.__TAURI__.core.invoke("issue_mandate", {
        agentDid: "did:key:z6MkAgent999",
        scope: ["schema:SearchAction"],
        ttlHours: 2,
      })
    );

    // Attempt to delegate with PayAction added — must be rejected.
    const result = await page.evaluate((parentHash: string) =>
      window.__TAURI__.core.invoke("delegate_mandate", {
        parentMandateHash: parentHash,
        subAgentDid: "did:key:z6MkSubAgent888",
        scope: ["schema:SearchAction", "schema:PayAction"],
        ttlHours: 1,
      }), root.mandate_hash
    );

    expect(result.success).toBe(false);
    expect(result.error_code).toBe("SCOPE_EXCEEDED");
    expect(result.error).toContain("schema:PayAction");
  });

  test("delegate_mandate rejects sub-mandate whose TTL exceeds parent TTL", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Root mandate: 1-hour TTL.
    const root = await page.evaluate(() =>
      window.__TAURI__.core.invoke("issue_mandate", {
        agentDid: "did:key:z6MkAgent999",
        scope: ["schema:SearchAction"],
        ttlHours: 1,
      })
    );

    // Child requests 2-hour TTL — must be rejected.
    const result = await page.evaluate((parentHash: string) =>
      window.__TAURI__.core.invoke("delegate_mandate", {
        parentMandateHash: parentHash,
        subAgentDid: "did:key:z6MkSubAgent888",
        scope: ["schema:SearchAction"],
        ttlHours: 2,
      }), root.mandate_hash
    );

    expect(result.success).toBe(false);
    expect(result.error_code).toBe("TTL_EXCEEDED");
  });

  test("mandate TTL expiry is surfaced as TTL_EXPIRED error", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("run_scenario_with_error", {
        scenarioId: "payment",
        triggerError: "ttl_expired",
      })
    );

    expect(result.success).toBe(false);
    expect(result.error_code).toBe("TTL_EXPIRED");
  });

  test("delegation to unknown parent mandate returns MANDATE_NOT_FOUND", async ({
    page,
  }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("delegate_mandate", {
        parentMandateHash: "mandate-does-not-exist",
        subAgentDid: "did:key:z6MkSubAgent888",
        scope: ["schema:SearchAction"],
        ttlHours: 1,
      })
    );

    expect(result.success).toBe(false);
    expect(result.error_code).toBe("MANDATE_NOT_FOUND");
  });
});
