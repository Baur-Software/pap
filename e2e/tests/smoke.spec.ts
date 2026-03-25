import { test, expect } from "@playwright/test";
import { installTauriMock } from "./tauri-mock";

/**
 * Diagnostic smoke test — ONE test that captures everything.
 *
 * Previous runs showed .app-shell-canvas never appears even after 4+ minutes.
 * Instead of adding more timeouts, this test captures all page state
 * (network, console, errors, DOM) so we can see WHY the app doesn't render.
 */

test("diagnostic: capture full page state on CI", async ({ page }) => {
  const messages: string[] = [];
  const pageErrors: string[] = [];
  const networkLog: string[] = [];

  page.on("console", (msg) => {
    messages.push(`[${msg.type()}] ${msg.text()}`);
  });
  page.on("pageerror", (err) => {
    pageErrors.push(`${err.name}: ${err.message}`);
  });
  page.on("response", (resp) => {
    networkLog.push(
      `${resp.status()} ${resp.headers()["content-type"] ?? "?"} ${resp.url()}`
    );
  });

  // Install mock BEFORE navigation
  await installTauriMock(page);

  // Navigate — use 'load' with generous timeout so we know whether
  // DOMContentLoaded fires at all (it blocks on the module script's
  // `await init(WASM)`)
  let loadSucceeded = false;
  const loadStart = Date.now();
  try {
    await page.goto("/", { waitUntil: "load", timeout: 180_000 });
    loadSucceeded = true;
  } catch {
    // Timeout — page.goto exceeded 180s
  }
  const loadMs = Date.now() - loadStart;

  // ── Dump diagnostics regardless of load success ──
  console.log(`\n[diag] ====== DIAGNOSTIC DUMP ======`);
  console.log(`[diag] page.goto result: ${loadSucceeded ? "OK" : "TIMEOUT"} (${loadMs}ms)`);

  console.log(`\n[diag] --- NETWORK (${networkLog.length} responses) ---`);
  for (const n of networkLog) console.log(`[diag]   ${n}`);

  console.log(`\n[diag] --- CONSOLE (${messages.length} messages) ---`);
  for (const m of messages) console.log(`[diag]   ${m}`);

  console.log(`\n[diag] --- PAGE ERRORS (${pageErrors.length}) ---`);
  for (const e of pageErrors) console.log(`[diag]   ${e}`);

  // Check key state
  const tauriDefined = await page.evaluate(() => typeof (window as any).__TAURI__ !== "undefined");
  console.log(`\n[diag] window.__TAURI__ defined: ${tauriDefined}`);

  const bodyHTML = await page.evaluate(() => document.body.innerHTML);
  console.log(`\n[diag] --- BODY innerHTML (${bodyHTML.length} chars) ---`);
  console.log(`[diag] ${bodyHTML.substring(0, 2000)}`);

  const headScripts = await page.evaluate(() => {
    return Array.from(document.querySelectorAll("head script")).map((s) => ({
      type: s.getAttribute("type"),
      src: s.getAttribute("src"),
      textLength: s.textContent?.length ?? 0,
    }));
  });
  console.log(`\n[diag] --- HEAD SCRIPTS ---`);
  for (const s of headScripts) console.log(`[diag]   ${JSON.stringify(s)}`);

  const appShellExists = await page.evaluate(() => !!document.querySelector(".app-shell-canvas"));
  console.log(`\n[diag] .app-shell-canvas exists: ${appShellExists}`);

  console.log(`[diag] ====== END DIAGNOSTIC DUMP ======\n`);

  // This test's only assertion: diagnostics were captured
  expect(networkLog.length).toBeGreaterThan(0);
});
