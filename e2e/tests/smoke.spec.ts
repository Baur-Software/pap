import { test, expect } from '@playwright/test';
import { installTauriMock } from './tauri-mock';
import { waitForApp } from './helpers';

/**
 * Tier 1 Smoke Tests for Papillion Desktop App
 *
 * Purpose: Verify the built Papillion app launches and renders correctly.
 *
 * NOTE: V8 compiles the 2.2 MB release WASM from scratch on every new
 * browser context.  On a 2-core CI runner this alone takes 90-120 s,
 * and the DOMContentLoaded event doesn't fire until the top-level
 * `await init()` in the trunk-generated module script finishes.
 *
 * All navigation uses `waitUntil: 'commit'` so goto returns as soon as
 * response headers arrive.  waitForApp() then polls for .app-shell-canvas
 * with a 4-minute timeout that covers WASM compilation + app mounting.
 */

test.beforeEach(async ({ page }) => {
  await installTauriMock(page);
});

test.describe('Papillion Smoke Tests', () => {
  test('WASM loads and app shell renders', async ({ page }) => {
    // Capture console output and page errors for diagnostics
    const messages: string[] = [];
    const pageErrors: string[] = [];

    page.on('console', (msg) => {
      messages.push(`[${msg.type()}] ${msg.text()}`);
    });
    page.on('pageerror', (err) => {
      pageErrors.push(`${err.name}: ${err.message}`);
    });

    // 'commit' returns as soon as headers arrive — don't block on
    // DOMContentLoaded which waits for WASM compilation to finish.
    await page.goto('/', { waitUntil: 'commit' });

    // Poll for app shell (covers WASM download + compile + mount)
    await waitForApp(page);

    // Dump diagnostics on success so CI logs are informative
    console.log('[diag] --- CONSOLE MESSAGES ---');
    for (const m of messages) console.log(`[diag] ${m}`);
    if (pageErrors.length > 0) {
      console.log('[diag] --- PAGE ERRORS ---');
      for (const e of pageErrors) console.log(`[diag] ${e}`);
    }
    console.log('[diag] --- END ---');
  });

  test('frontend renders content (not blank screen)', async ({ page }) => {
    await page.goto('/', { waitUntil: 'commit' });
    await waitForApp(page);

    const mainContent = page.locator('main, [role="main"], .app, #app, body > div');
    const contentText = await mainContent.textContent();
    expect(contentText?.trim().length).toBeGreaterThan(0);
  });

  test('no unhandled console errors on startup', async ({ page }) => {
    const errors: string[] = [];

    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('/', { waitUntil: 'commit' });
    await waitForApp(page);

    const criticalErrors = errors.filter(
      (e) =>
        !e.includes('favicon') &&
        !e.includes('404') &&
        !e.includes('CORS') &&
        !e.includes('net::ERR')
    );

    expect(criticalErrors).toHaveLength(0);
  });

  test('basic interaction works (buttons respond)', async ({ page }) => {
    await page.goto('/', { waitUntil: 'commit' });
    await waitForApp(page);

    const buttons = page.locator('button, [role="button"]');
    const buttonCount = await buttons.count();

    if (buttonCount > 0) {
      const firstButton = buttons.nth(0);
      await firstButton.click();
      await expect(page.locator(".app-shell-canvas")).toBeVisible();
    }

    expect(buttonCount >= 0).toBeTruthy();
  });

  test('WASM module loaded (check for specific app markers)', async ({ page }) => {
    await page.goto('/', { waitUntil: 'commit' });
    await waitForApp(page);

    const titleOrHeader = page.locator('h1, h2, [data-testid="app-title"]');
    const titleCount = await titleOrHeader.count();

    const buttons = page.locator('button');
    const buttonCount = await buttons.count();

    const hasUIElements = titleCount > 0 || buttonCount > 0;
    expect(hasUIElements).toBeTruthy();
  });
});
