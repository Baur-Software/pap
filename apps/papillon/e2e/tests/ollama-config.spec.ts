/**
 * Tests for Ollama + Mistral LLM configuration via Settings UI and IPC.
 *
 * Covers:
 * 1. Configuring Ollama with mistral:latest via IPC
 * 2. Verifying configuration persists across invocations
 * 3. Verifying check_llm_connection returns a response
 * 4. Verifying provider switching (Ollama → None → Ollama)
 * 5. Verifying Mistral API key configuration
 * 6. Settings UI Orchestrator tab renders provider fields
 */

import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";
import { waitForApp } from "./helpers";

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

// ── IPC-level configuration ──────────────────────────────────

test.describe("Ollama configuration — IPC level", () => {
  test("configure Ollama with mistral:latest and verify persistence", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );

    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect(provider).toMatchObject({
      Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" },
    });
  });

  test("configure Ollama with mistral:7b variant", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:7b" } },
          mandate_ttl_hours: 8,
          auto_approve_zero_disclosure: false,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    const ollamaModel =
      provider && typeof provider === "object" && (provider as any).Ollama
        ? (provider as any).Ollama.model
        : null;
    expect(ollamaModel).toBe("mistral:7b");
  });

  test("configure Mistral API provider", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Mistral: { api_key: "test-mistral-key", model: "mistral-small-latest" } },
          mandate_ttl_hours: 8,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect(provider).toMatchObject({ Mistral: { model: "mistral-small-latest" } });
  });

  test("check_llm_connection returns non-empty string", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    const response = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("check_llm_connection")
    );
    expect(typeof response).toBe("string");
    expect((response as string).length).toBeGreaterThan(0);
  });

  test("switch from Ollama to None clears provider", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" } },
          mandate_ttl_hours: 8,
          auto_approve_zero_disclosure: true,
        },
      })
    );
    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: { llm_provider: "None", mandate_ttl_hours: 8, auto_approve_zero_disclosure: true },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect(provider).toBe("None");
  });

  test("mandate TTL persists when set to 1 hour for Ollama config", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      })
    );
    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    expect(saved.mandate_ttl_hours).toBe(1);
  });

  test("multiple configure calls — last write wins", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "llama3" } },
          mandate_ttl_hours: 8,
          auto_approve_zero_disclosure: true,
        },
      })
    );
    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Mistral: { api_key: "key2", model: "mistral-medium" } },
          mandate_ttl_hours: 24,
          auto_approve_zero_disclosure: false,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect(provider).toMatchObject({ Mistral: { model: "mistral-medium" } });
    expect(saved.mandate_ttl_hours).toBe(24);
  });

  test("configure OpenAI-compatible endpoint", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: {
            OpenAiCompatible: {
              endpoint: "https://api.openai.com/v1",
              api_key: "sk-test-xyz",
              model: "gpt-4o-mini",
            },
          },
          mandate_ttl_hours: 4,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect(provider).toMatchObject({
      OpenAiCompatible: { endpoint: "https://api.openai.com/v1", model: "gpt-4o-mini" },
    });
  });

  test("Ollama endpoint field accepts custom port", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11435", model: "mistral:latest" } },
          mandate_ttl_hours: 8,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    const saved = await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("get_orchestrator_config")
    );
    const provider = saved.inference_substrate ?? saved.llm_provider;
    expect((provider as any).Ollama.endpoint).toBe("http://localhost:11435");
  });
});

// ── Settings UI ──────────────────────────────────────────────

test.describe("Ollama configuration — Settings UI", () => {
  test("Orchestrator tab renders AI Model heading and provider selector", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();
    await expect(page.locator("text=AI Model")).toBeVisible();
    await expect(page.locator("select").first()).toBeVisible();
  });

  test("provider dropdown includes an ollama option", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();

    const options = await page.locator("select").first().locator("option").allTextContents();
    const hasOllama = options.some((o) => o.toLowerCase().includes("ollama"));
    expect(hasOllama).toBe(true);
  });

  test("selecting ollama reveals at least one text input field", async ({ page }) => {
    await page.goto("/settings", { waitUntil: "commit" });
    await waitForApp(page);
    await page.locator(".settings-nav-link").filter({ hasText: "Orchestrator" }).click();
    await page.locator("select").first().selectOption("ollama");

    const inputs = page.locator('input[type="text"], input:not([type])');
    const count = await inputs.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test("status bar is visible on canvas when Ollama is configured", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    await expect(page.locator(".status-bar")).toBeVisible();
  });

  test("canvas address bar accepts prompt after Ollama configured", async ({ page }) => {
    await page.goto("/", { waitUntil: "commit" });
    await waitForApp(page);

    await page.evaluate(() =>
      (window as any).__TAURI__.core.invoke("configure_orchestrator", {
        config: {
          llm_provider: { Ollama: { endpoint: "http://localhost:11434", model: "mistral:latest" } },
          mandate_ttl_hours: 1,
          auto_approve_zero_disclosure: true,
        },
      })
    );

    await page.locator(".topbar-address-input").fill("What is the weather today?");
    await expect(page.locator(".topbar-address-input")).toHaveValue("What is the weather today?");
  });
});
