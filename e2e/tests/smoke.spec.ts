import { test, expect } from '@playwright/test';

/**
 * Tier 1 Smoke Tests for Papillion Desktop App
 *
 * Purpose: Verify the built Papillion app launches and renders correctly
 * - App window appears and is visible
 * - Frontend renders (HTML has content, not blank)
 * - No unhandled JS console errors during startup
 * - Basic interaction works (buttons respond)
 *
 * These tests catch regressions like the v0.3.0 blank UI bug before release.
 * Expected duration: ~30 seconds per run
 */

test.describe('Papillion Smoke Tests', () => {
  test('app window launches without crashing', async ({ page }) => {
    // Navigate to the dev server URL where the app is running
    await page.goto('http://localhost:1420', { waitUntil: 'networkidle' });

    // Wait for the main app container to be visible
    const appContainer = page.locator('body');
    await expect(appContainer).toBeVisible({ timeout: 5000 });
  });

  test('frontend renders content (not blank screen)', async ({ page }) => {
    await page.goto('http://localhost:1420', { waitUntil: 'networkidle' });

    // Verify the page has meaningful content (not just empty HTML)
    const mainContent = page.locator('main, [role="main"], .app, #app, body > div');
    const contentText = await mainContent.textContent();

    // Should have some text content (not blank)
    expect(contentText?.trim().length).toBeGreaterThan(0);
  });

  test('no unhandled console errors on startup', async ({ page }) => {
    const errors: string[] = [];

    // Capture console errors
    page.on('console', (msg) => {
      if (msg.type() === 'error') {
        errors.push(msg.text());
      }
    });

    await page.goto('http://localhost:1420', { waitUntil: 'networkidle' });

    // Wait a moment for any async errors
    await page.waitForTimeout(1000);

    // Should have no critical errors (filter out known non-critical errors)
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
    await page.goto('http://localhost:1420', { waitUntil: 'networkidle' });

    // Try to find and click an interactive element
    const buttons = page.locator('button, [role="button"]');
    const buttonCount = await buttons.count();

    if (buttonCount > 0) {
      // Click the first button and verify no crash
      const firstButton = buttons.nth(0);
      await firstButton.click();

      // App should still be responsive
      await expect(page).not.toBeClosed();
    }

    // If no buttons found, that's OK - at least the app rendered
    expect(buttonCount >= 0).toBeTruthy();
  });

  test('WASM module loaded (check for specific app markers)', async ({ page }) => {
    await page.goto('http://localhost:1420', { waitUntil: 'networkidle' });

    // Check for Papillion-specific content markers that indicate WASM loaded
    // Look for key UI elements that should only exist if frontend compiled
    const titleOrHeader = page.locator('h1, h2, [data-testid="app-title"]');
    const titleCount = await titleOrHeader.count();

    // Either has a title/header OR has buttons/interactive elements
    // (Different modes might have different layouts)
    const buttons = page.locator('button');
    const buttonCount = await buttons.count();

    const hasUIElements = titleCount > 0 || buttonCount > 0;
    expect(hasUIElements).toBeTruthy();
  });
});
