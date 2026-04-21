/**
 * E2E tests for:
 *
 * 1. Local LLM configuration — Ollama, Mistral, OpenAI-compatible, and None
 *    providers can be configured and persisted via configure_orchestrator /
 *    get_orchestrator_config.
 *
 * 2. JSON-LD block rendering — canvas blocks with schema.org @type values are
 *    rendered with the correct typed CSS classes by the block_renderer templates.
 *    Tests use tauri-mock prompt keywords (mock:movie, mock:weather, etc.) that
 *    trigger the mock's canvas_prompt handler to emit block_resolved events with
 *    real typed content payloads.
 *
 * 3. Chrysalis federation — navigate_registry, sync_agents, list_agents round-
 *    trips; local vs. remote agent routing simulation.
 *
 * 4. 300+ agent catalog — verifies that the mock fleet contains the expected
 *    agent shapes and that the catalog breadth requirement is expressed in tests.
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── 1. LLM Provider Configuration ────────────────────────────

test.describe("LLM provider configuration", () => {
  test("default config has llm_provider None", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const cfg = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    expect(cfg).not.toBeNull();
    expect(cfg.llm_provider).toBe("None");
    expect(typeof cfg.mandate_ttl_hours).toBe("number");
    expect(typeof cfg.auto_approve_zero_disclosure).toBe("boolean");
  });

  test("configure Ollama provider and verify persistence", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const ollamaCfg = {
      llm_provider: {
        Ollama: { endpoint: "http://localhost:11434", model: "llama3.2" },
      },
      mandate_ttl_hours: 8,
      auto_approve_zero_disclosure: true,
    };

    await page.evaluate(
      (cfg) => window.__TAURI__.core.invoke("configure_orchestrator", { config: cfg }),
      ollamaCfg
    );

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    expect(saved.llm_provider).toMatchObject({
      Ollama: { endpoint: "http://localhost:11434", model: "llama3.2" },
    });
  });

  test("configure Mistral provider and verify persistence", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const mistralCfg = {
      llm_provider: {
        Mistral: { api_key: "test-key-abc123", model: "mistral-small" },
      },
      mandate_ttl_hours: 12,
      auto_approve_zero_disclosure: false,
    };

    await page.evaluate(
      (cfg) => window.__TAURI__.core.invoke("configure_orchestrator", { config: cfg }),
      mistralCfg
    );

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    expect(saved.llm_provider).toMatchObject({
      Mistral: { api_key: "test-key-abc123", model: "mistral-small" },
    });
    expect(saved.mandate_ttl_hours).toBe(12);
    expect(saved.auto_approve_zero_disclosure).toBe(false);
  });

  test("configure OpenAI-compatible provider and verify persistence", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const openaiCfg = {
      llm_provider: {
        OpenAiCompatible: {
          endpoint: "https://api.openai.com/v1",
          api_key: "sk-test-xyz",
          model: "gpt-4o-mini",
        },
      },
      mandate_ttl_hours: 4,
      auto_approve_zero_disclosure: true,
    };

    await page.evaluate(
      (cfg) => window.__TAURI__.core.invoke("configure_orchestrator", { config: cfg }),
      openaiCfg
    );

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    expect(saved.llm_provider).toMatchObject({
      OpenAiCompatible: {
        endpoint: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
      },
    });
  });

  test("reset to None provider and verify", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // First configure Ollama
    await page.evaluate(() =>
      window.__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "llama3" } }, mandate_ttl_hours: 8, auto_approve_zero_disclosure: true },
      })
    );

    // Then reset to None
    await page.evaluate(() =>
      window.__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: "None", mandate_ttl_hours: 8, auto_approve_zero_disclosure: true },
      })
    );

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    expect(saved.llm_provider).toBe("None");
  });

  test("multiple configure calls are idempotent — last write wins", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      window.__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "llama3" } }, mandate_ttl_hours: 8, auto_approve_zero_disclosure: true },
      })
    );
    await page.evaluate(() =>
      window.__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: { Mistral: { api_key: "key2", model: "mistral-medium" } }, mandate_ttl_hours: 24, auto_approve_zero_disclosure: false },
      })
    );

    const saved = await page.evaluate(() =>
      window.__TAURI__.core.invoke("get_orchestrator_config")
    );

    // Only the last write should be reflected
    expect(saved.llm_provider).toMatchObject({ Mistral: { model: "mistral-medium" } });
    expect(saved.mandate_ttl_hours).toBe(24);
  });

  test("settings UI Orchestrator tab shows AI model select", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);

    // Settings page defaults to Profiles tab; navigate to Orchestrator first
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();

    await expect(page.locator("text=AI Model")).toBeVisible();
    // First select on the page is the provider dropdown
    await expect(page.locator("select").first()).toBeVisible();
  });

  test("check_llm_connection returns mock response", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const response = await page.evaluate(() =>
      window.__TAURI__.core.invoke("check_llm_connection")
    );

    expect(typeof response).toBe("string");
    expect(response.length).toBeGreaterThan(0);
  });
});

// ── 2. JSON-LD Block Rendering ────────────────────────────────

// Helper: submit a prompt that resolves to a typed block, then wait for the
// typed CSS class to be visible in the canvas.
async function submitAndAwaitTypedBlock(
  page: import("@playwright/test").Page,
  mockKeyword: string,
  cssClass: string,
  timeout = 15000
): Promise<void> {
  // Navigate to canvas
  await page.goto("/", { waitUntil: "commit" });
  await waitForApp(page);

  // Fill in the prompt and submit
  await page.locator(".topbar-address-input").fill(mockKeyword);
  await page.locator(".topbar-address-input").press("Enter");

  // Wait for the typed CSS class to appear
  await expect(page.locator(cssClass).first()).toBeVisible({ timeout });
}

test.describe("JSON-LD block rendering — schema.org typed templates", () => {
  test("Movie block renders .typed-movie with title", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:movie", ".typed-movie");
    await expect(page.locator(".typed-movie-title").first()).toContainText("Inception");
    await expect(page.locator(".typed-movie-director").first()).toContainText("Christopher Nolan");
  });

  test("TVSeries block renders .typed-tv-series with network", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:tvseries", ".typed-tv-series");
    await expect(page.locator(".typed-tv-title").first()).toContainText("Breaking Bad");
    await expect(page.locator(".typed-tv-network").first()).toContainText("AMC");
  });

  test("VideoGame block renders .typed-video-game with title and platform", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:videogame", ".typed-video-game");
    await expect(page.locator(".typed-game-title").first()).toContainText("Legend of Zelda");
    await expect(page.locator(".typed-game-platform").first()).toContainText("Nintendo Switch");
  });

  test("MusicRecording block renders .typed-music-recording with artist", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:musicrecording", ".typed-music-recording");
    await expect(page.locator(".typed-music-title").first()).toContainText("Bohemian Rhapsody");
    await expect(page.locator(".typed-music-artist").first()).toContainText("Queen");
  });

  test("MusicGroup block renders .typed-music-group", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:musicgroup", ".typed-music-group");
    await expect(page.locator(".typed-music-group-name").first()).toContainText("The Beatles");
  });

  test("Book block renders .typed-book with author and publisher", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:book", ".typed-book");
    await expect(page.locator(".typed-book-title").first()).toContainText("Rust Programming Language");
    await expect(page.locator(".typed-book-author").first()).toContainText("Steve Klabnik");
    await expect(page.locator(".typed-book-publisher").first()).toContainText("No Starch Press");
  });

  test("NewsArticle block renders .typed-news-article with headline", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:newsarticle", ".typed-news-article");
    await expect(page.locator(".typed-news-headline").first()).toContainText("Rust Tops Developer Survey");
    await expect(page.locator(".typed-news-source").first()).toContainText("Stack Overflow");
  });

  test("ScholarlyArticle block renders .typed-scholarly-article with paper info", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:scholarlyarticle", ".typed-scholarly-article");
    await expect(page.locator(".typed-paper-title").first()).toContainText("Attention Is All You Need");
    await expect(page.locator(".typed-paper-journal").first()).toContainText("NeurIPS 2017");
  });

  test("Person block renders .typed-person with name and job title", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:person", ".typed-person");
    await expect(page.locator(".typed-person-name").first()).toContainText("Grace Hopper");
    await expect(page.locator(".typed-person-title").first()).toContainText("Rear Admiral");
  });

  test("Organization block renders .typed-organization with name", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:organization", ".typed-organization");
    await expect(page.locator(".typed-org-name").first()).toContainText("Mozilla Foundation");
  });

  test("WeatherForecast block renders .typed-weather with location and temp", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:weather", ".typed-weather");
    await expect(page.locator(".typed-weather-location").first()).toContainText("San Francisco");
    await expect(page.locator(".typed-weather-temp").first()).toContainText("65°F");
    await expect(page.locator(".typed-weather-conditions").first()).toContainText("Foggy");
  });

  test("GeoCoordinates block renders .typed-geocoords with lat/lon", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:geocoords", ".typed-geocoords");
    await expect(page.locator(".typed-geo-name").first()).toContainText("Eiffel Tower");
    await expect(page.locator(".typed-geo-lat").first()).toContainText("Lat:");
    await expect(page.locator(".typed-geo-lon").first()).toContainText("Lon:");
  });

  test("Product block renders .typed-product with name and price", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:product", ".typed-product");
    await expect(page.locator(".typed-product-name").first()).toContainText("Framework Laptop 16");
    await expect(page.locator(".typed-product-brand").first()).toContainText("Framework");
    await expect(page.locator(".typed-product-price").first()).toContainText("$");
  });

  test("Event block renders .typed-event with name and dates", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:event", ".typed-event");
    await expect(page.locator(".typed-event-name").first()).toContainText("RustConf 2024");
    await expect(page.locator(".typed-event-location").first()).toContainText("Montreal");
  });

  test("SportsTeam block renders .typed-sports-event with teams", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:sportsteam", ".typed-sports-event");
    await expect(page.locator(".typed-sports-name").first()).toContainText("World Cup Final");
    await expect(page.locator(".typed-sports-home").first()).toContainText("Spain");
    await expect(page.locator(".typed-sports-away").first()).toContainText("Brazil");
  });

  test("Course block renders .typed-course with provider", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:course", ".typed-course");
    await expect(page.locator(".typed-course-name").first()).toContainText("CS50");
    await expect(page.locator(".typed-course-provider").first()).toContainText("Harvard");
  });

  test("NutritionInformation block renders .typed-nutrition with macros", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:nutrition", ".typed-nutrition");
    await expect(page.locator(".typed-nutrition-name").first()).toContainText("Avocado");
    await expect(page.locator(".typed-nutrition-calories").first()).toContainText("kcal");
    await expect(page.locator(".typed-nutrition-protein").first()).toContainText("Protein:");
  });

  test("JobPosting block renders .typed-job-posting with title and company", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:jobposting", ".typed-job-posting");
    await expect(page.locator(".typed-job-title").first()).toContainText("Senior Rust Engineer");
    await expect(page.locator(".typed-job-company").first()).toContainText("Fastly");
  });

  test("VisualArtwork block renders .typed-visual-artwork with artist", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:visualartwork", ".typed-visual-artwork");
    await expect(page.locator(".typed-artwork-title").first()).toContainText("Starry Night");
    await expect(page.locator(".typed-artwork-artist").first()).toContainText("van Gogh");
  });

  test("DefinedTerm block renders .typed-defined-term with word", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:definedterm", ".typed-defined-term");
    await expect(page.locator(".typed-term-word").first()).toContainText("monad");
    await expect(page.locator(".typed-term-definition").first()).toContainText("functional programming");
  });

  test("Quotation block renders .typed-quotation with text and author", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "mock:quotation", ".typed-quotation");
    await expect(page.locator(".typed-quote-text").first()).toContainText("people to read");
    await expect(page.locator(".typed-quote-author").first()).toContainText("Abelson");
  });

  test("generic prompt renders block-content (no typed class fallback)", async ({ page }) => {
    await submitAndAwaitTypedBlock(page, "tell me about the protocol", ".block-content");
    // No specific typed class — should fall through to generic answer rendering
    await expect(page.locator(".canvas-block.canvas-block").first()).toBeVisible();
  });

  test("block is clickable and shows reprompt input on resolved block", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("mock:book");
    await page.locator(".topbar-address-input").press("Enter");

    // Wait for book block
    await expect(page.locator(".typed-book").first()).toBeVisible({ timeout: 8000 });

    // Click the block to open reprompt
    const block = page.locator(".canvas-block").first();
    await block.click();

    await expect(block.locator(".block-reprompt input")).toBeVisible();
  });

  test("Escape closes reprompt input", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("mock:book");
    await page.locator(".topbar-address-input").press("Enter");
    await expect(page.locator(".typed-book").first()).toBeVisible({ timeout: 8000 });

    const block = page.locator(".canvas-block").first();
    await block.click();
    const repromptInput = block.locator(".block-reprompt input");
    await expect(repromptInput).toBeVisible();

    // Press Escape directly on the input (keydown handler is on the input element)
    await repromptInput.press("Escape");
    await expect(repromptInput).not.toBeVisible();
  });
});

// ── 3. Chrysalis Federation ───────────────────────────────────

test.describe("Chrysalis federation commands", () => {
  test("navigate_registry returns node info with agent_count", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const info = await page.evaluate(() =>
      window.__TAURI__.core.invoke("navigate_registry", {
        url: "https://chrysalis.example.com",
      })
    );

    expect(info).not.toBeNull();
    expect(info.url).toBeTruthy();
    expect(typeof info.agent_count).toBe("number");
    expect(info.agent_count).toBeGreaterThanOrEqual(0);
  });

  test("list_agents returns remote agents from a registry URL", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_agents", {
        registry_url: "https://chrysalis.example.com",
      })
    );

    expect(Array.isArray(agents)).toBe(true);
    expect(agents.length).toBeGreaterThan(0);

    // Every remote agent must have required fields
    for (const agent of agents) {
      expect(agent).toHaveProperty("name");
      expect(agent).toHaveProperty("agent_did");
      expect(agent).toHaveProperty("capabilities");
      expect(Array.isArray(agent.capabilities)).toBe(true);
    }
  });

  test("sync_agents returns null (fire-and-forget sync)", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const result = await page.evaluate(() =>
      window.__TAURI__.core.invoke("sync_agents", {
        registry_url: "https://chrysalis.example.com",
        action: "schema:SearchAction",
      })
    );

    // sync_agents returns () (null) on success
    expect(result).toBeNull();
  });

  test("discover_peers returns an empty list when no peers are configured", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const peers = await page.evaluate(() =>
      window.__TAURI__.core.invoke("discover_peers", {
        registry_url: "https://chrysalis.example.com",
      })
    );

    expect(Array.isArray(peers)).toBe(true);
    // Mock returns empty — no peers seeded
    expect(peers).toHaveLength(0);
  });

  test("navigate_registry then list_agents simulates connect+browse flow", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const registryUrl = "https://chrysalis.local";

    // Step 1: connect to the registry
    const info = await page.evaluate((url: string) =>
      window.__TAURI__.core.invoke("navigate_registry", { url }),
      registryUrl
    );
    expect(info.url).toBeTruthy();

    // Step 2: browse agents at that registry
    const agents = await page.evaluate((url: string) =>
      window.__TAURI__.core.invoke("list_agents", { registry_url: url }),
      registryUrl
    );
    expect(agents.length).toBeGreaterThan(0);
  });

  test("local agents and remote agents have different source fields", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Local agents — from list_local_agents
    const localAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    // Remote agents — from list_agents (simulates Chrysalis federation)
    const remoteAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_agents", {
        registry_url: "https://chrysalis.example.com",
      })
    );

    // Local agents have explicit source fields (compiled, catalog, user_created)
    for (const a of localAgents) {
      expect(["compiled", "catalog", "user_created"]).toContain(a.source);
    }

    // Remote agents from a registry are a separate list
    expect(remoteAgents.length).toBeGreaterThan(0);

    // Remote and local agents must have disjoint agent_did sets
    const localDids = new Set(localAgents.map((a: any) => a.agent_did));
    const remoteHasDistinctDids = remoteAgents.every((a: any) => !localDids.has(a.agent_did));
    expect(remoteHasDistinctDids).toBe(true);
  });

  test("publish to Chrysalis adds URL to agent published_to", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const chrysalisUrl = "https://chrysalis.network";

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const target = agents.find((a: any) => a.published_to.length === 0);
    expect(target).toBeDefined();

    await page.evaluate(
      ([did, url]) =>
        window.__TAURI__.core.invoke("publish_agent", { agent_did: did, registry_url: url }),
      [target.agent_did, chrysalisUrl]
    );

    const after = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    const published = after.find((a: any) => a.agent_did === target.agent_did);
    expect(published.published_to).toContain(chrysalisUrl);
  });

  test("fleet sidebar panel shows Chrysalis drop-in UI", async ({ page }) => {
    await page.goto("/fleet", { waitUntil: "commit" });
    await waitForApp(page);

    await expect(page.locator(".fleet-sidebar")).toBeVisible();
    await expect(page.locator(".fleet-panel-header")).toContainText("CHRYSALIS DROP-INS");
  });
});

// ── 4. Agent catalog breadth ─────────────────────────────────

test.describe("Agent catalog breadth (300+ agents)", () => {
  test("list_local_agents fleet contains at least 3 seeded agents", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    // The mock seeds 3 representative agents; the real catalog has 300+
    expect(agents.length).toBeGreaterThanOrEqual(3);
  });

  test("all seeded agents have schema: prefixed capabilities", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );

    for (const agent of agents) {
      for (const cap of agent.capabilities) {
        expect(cap).toMatch(/^schema:/);
      }
    }
  });

  test("generate_agent with domain-specific prompt returns schema: action", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const domains = [
      "search for movies on TMDB",
      "look up weather forecasts from OpenWeatherMap",
      "find npm packages for JavaScript",
      "look up books in Google Books",
      "search medical clinical trials",
      "get stock prices from Alpha Vantage",
      "find sports scores from ESPN",
      "search government data",
    ];

    for (const prompt of domains) {
      const preview = await page.evaluate((p: string) =>
        window.__TAURI__.core.invoke("generate_agent", { prompt: p }),
        prompt
      );

      expect(preview).not.toBeNull();
      expect(preview.action).toMatch(/^schema:/);
      expect(preview.endpoint?.url_template).toMatch(/^https:\/\//);
      expect(preview.agent_did).toBeNull(); // Not yet saved
    }
  });

  test("save_agent round-trip works for all domain agent types", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const agentDefs = [
      { name: "Movie DB", provider: "TMDB", action: "schema:SearchAction", returns: ["schema:Movie"] },
      { name: "Weather API", provider: "OpenWeatherMap", action: "schema:SearchAction", returns: ["schema:WeatherForecast"] },
      { name: "Book Search", provider: "Google Books", action: "schema:SearchAction", returns: ["schema:Book"] },
      { name: "Jobs Board", provider: "HN Jobs", action: "schema:SearchAction", returns: ["schema:JobPosting"] },
      { name: "Nutrition DB", provider: "USDA", action: "schema:SearchAction", returns: ["schema:NutritionInformation"] },
      { name: "Art Museum", provider: "Met Museum", action: "schema:SearchAction", returns: ["schema:VisualArtwork"] },
    ];

    for (const def of agentDefs) {
      const saved = await page.evaluate(
        (d) => window.__TAURI__.core.invoke("save_agent", { def: d }),
        def
      );

      expect(saved.name).toBe(def.name);
      expect(saved.agent_did).toBeTruthy();
      expect(saved.source).toBe("user_created");
    }

    // Verify all agents were added
    const allAgents = await page.evaluate(() =>
      window.__TAURI__.core.invoke("list_local_agents")
    );
    // 3 seeded + 6 new = 9
    expect(allAgents.length).toBeGreaterThanOrEqual(9);
  });

  test("agents cover diverse action types across domains", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Save agents across domains to validate action type breadth
    const actionTypes = [
      "schema:SearchAction",
      "schema:ReadAction",
      "schema:ViewAction",
      "schema:DownloadAction",
      "schema:CheckAction",
    ];

    for (const action of actionTypes) {
      const saved = await page.evaluate(
        (a: string) =>
          window.__TAURI__.core.invoke("save_agent", {
            def: {
              name: "Test Agent for " + a,
              provider: "Test",
              action: a,
              object_types: [],
              requires_disclosure: [],
              returns: [],
              schema_version: 1,
            },
          }),
        action
      );

      expect(saved.capabilities).toContain(action);
    }
  });
});

// ── 5. Block lifecycle (resolving → resolved → retry) ────────

test.describe("Canvas block lifecycle", () => {
  test("block starts in resolving state then transitions to resolved", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    // Submit a prompt — block should appear in resolving state first
    await page.locator(".topbar-address-input").fill("mock:book");

    // The block will be in .resolving state momentarily before the event fires
    await page.locator(".topbar-address-input").press("Enter");

    // Eventually resolves (event fires after 200ms mock delay)
    await expect(page.locator(".typed-book").first()).toBeVisible({ timeout: 15000 });

    // After resolution the block should NOT have the resolving class
    const block = page.locator(".canvas-block").first();
    await expect(block).not.toHaveClass(/resolving/);
  });

  test("failed block shows retry button and phase dots", async ({ page }) => {
    // Override canvas_prompt to emit a failed block event
    await page.addInitScript(`
      const origInvoke = window.__TAURI__.core.invoke;
      window.__TAURI__.core.invoke = async function(cmd, args) {
        if (cmd === 'canvas_plan_prompt') {
          const blockId = (args && (args.block_id || args.blockId)) || 'block-fail';
          setTimeout(function() {
            window.__TAURI__.event.emit('block_resolved', {
              block: {
                id: blockId,
                prompt_id: 'p-fail',
                state: { Failed: { phase: 3, reason: 'Network timeout during key exchange' } },
                schema_type: null,
                content: null,
                linked_block_ids: [],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              }
            });
          }, 150);
          return null;
        }
        return origInvoke.call(this, cmd, args);
      };
    `);

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("trigger a failure");
    await page.locator(".topbar-address-input").press("Enter");

    // Should render failed block with retry button
    await expect(page.locator(".canvas-block.failed").first()).toBeVisible({ timeout: 8000 });
    await expect(page.locator(".btn-retry").first()).toBeVisible();
    await expect(page.locator(".block-failed-msg").first()).toContainText("Network timeout");
  });

  test("ghost block shows will-see and will-return scope badges", async ({ page }) => {
    // Override to emit a ghost block
    await page.addInitScript(`
      const origInvoke = window.__TAURI__.core.invoke;
      window.__TAURI__.core.invoke = async function(cmd, args) {
        if (cmd === 'canvas_plan_prompt') {
          const blockId = (args && (args.block_id || args.blockId)) || 'block-ghost';
          setTimeout(function() {
            window.__TAURI__.event.emit('block_resolved', {
              block: {
                id: blockId,
                prompt_id: 'p-ghost',
                state: { Ghost: { agent_name: 'TravelBot', action_type: 'schema:ReserveAction', disclosure_preview: ['name', 'passport'], returns_preview: ['schema:FlightReservation'] } },
                schema_type: null,
                content: null,
                linked_block_ids: [],
                created_at: new Date().toISOString(),
                updated_at: new Date().toISOString(),
              }
            });
          }, 150);
          return null;
        }
        return origInvoke.call(this, cmd, args);
      };
    `);

    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.locator(".topbar-address-input").fill("book a flight for me");
    await page.locator(".topbar-address-input").press("Enter");

    const ghostBlock = page.locator(".canvas-block.ghost").first();
    await expect(ghostBlock).toBeVisible({ timeout: 8000 });
    await expect(ghostBlock.locator(".ghost-agent")).toContainText("TravelBot");
    await expect(ghostBlock.locator(".scope-badge.disclosure").first()).toContainText("name");
    await expect(ghostBlock.locator(".scope-badge.returns").first()).toContainText("FlightReservation");
  });
});
