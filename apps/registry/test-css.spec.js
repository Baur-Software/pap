// @ts-check
const { test, expect } = require('@playwright/test');

test('CSS loads correctly in Docker', async ({ page }) => {
  // Navigate to the app
  await page.goto('https://localhost:7890/', {
    waitUntil: 'networkidle',
    // Accept self-signed cert
    ignoreHTTPSErrors: true
  });

  // Check that the CSS file request succeeded (not 404)
  const cssRequest = page.waitForResponse(
    response => response.url().includes('pap-registry-ui.css')
  );

  await page.reload({ waitUntil: 'networkidle' });
  const cssResponse = await cssRequest;

  console.log(`CSS Response Status: ${cssResponse.status()}`);
  console.log(`CSS URL: ${cssResponse.url()}`);

  // Assert CSS loaded with 200 status
  expect(cssResponse.status()).toBe(200);
  expect(cssResponse.headers()['content-type']).toContain('text/css');

  // Verify CSS content is not empty
  const cssContent = await cssResponse.text();
  expect(cssContent.length).toBeGreaterThan(0);
  console.log(`CSS Content Length: ${cssContent.length} bytes`);

  // Take a screenshot to verify visual rendering
  await page.screenshot({ path: 'registry-with-css.png', fullPage: true });
});
