const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 }
  });
  const page = await context.newPage();

  // Enable console logging
  page.on('console', msg => {
    const type = msg.type();
    const text = msg.text();
    if (type === 'error' || type === 'warn' || text.includes('approve') || text.includes('Block') || text.includes('persist')) {
      console.log(`[BROWSER ${type.toUpperCase()}]`, text);
    }
  });

  console.log('🚀 Opening Papillon...');
  await page.goto('http://127.0.0.1:1420/');
  await page.waitForTimeout(2000);

  // Take initial screenshot
  await page.screenshot({ path: 'papillon-01-initial.png', fullPage: true });
  console.log('📸 Screenshot 1: Initial state');

  // Check for setup overlay blocking interaction
  const setupOverlay = page.locator('.setup-overlay');
  if (await setupOverlay.isVisible()) {
    console.log('⚠️  Setup overlay detected - this blocks all interactions!');
    await page.screenshot({ path: 'papillon-02-setup-overlay.png', fullPage: true });
    console.log('📸 Screenshot 2: Setup overlay blocking UI');

    // Try to dismiss it
    const skipBtn = page.locator('button:has-text("Skip"), button:has-text("skip")');
    if (await skipBtn.isVisible()) {
      console.log('🎯 Found Skip button, clicking...');
      await skipBtn.click();
      await page.waitForTimeout(1000);
    }
  }

  // Look for Sources/Workflow tabs
  const sourcesTab = page.locator('button:has-text("SOURCES")').first();
  const workflowTab = page.locator('button:has-text("WORKFLOW")').first();

  if (await sourcesTab.isVisible()) {
    console.log('✅ Found SOURCES tab');
    await page.screenshot({ path: 'papillon-03-sources-view.png', fullPage: true });
    console.log('📸 Screenshot 3: Sources view');
  }

  if (await workflowTab.isVisible()) {
    console.log('✅ Found WORKFLOW tab, clicking...');
    await workflowTab.click({ force: true });
    await page.waitForTimeout(1000);
    await page.screenshot({ path: 'papillon-04-workflow-view.png', fullPage: true });
    console.log('📸 Screenshot 4: Workflow view');
  }

  // Look for failed blocks or stopped steps
  const failedElements = await page.locator('[class*="failed"], [class*="Failed"], text="Failed", text="FAILED"').all();
  const stoppedElements = await page.locator('text="STOPPED STEP", text="Stopped step"').all();

  console.log(`🔍 Found ${failedElements.length} failed elements, ${stoppedElements.length} stopped elements`);

  if (failedElements.length > 0 || stoppedElements.length > 0) {
    await page.screenshot({ path: 'papillon-05-errors-found.png', fullPage: true });
    console.log('📸 Screenshot 5: Error states visible');

    // Look for Try again button
    const tryAgainBtn = page.locator('button:has-text("Try again")').first();
    if (await tryAgainBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      console.log('🎯 Found "Try again" button, clicking...');
      await tryAgainBtn.click({ force: true });
      await page.waitForTimeout(3000);
      await page.screenshot({ path: 'papillon-06-after-retry.png', fullPage: true });
      console.log('📸 Screenshot 6: After clicking retry');
    }
  }

  // Try to find and use the search input
  console.log('🔍 Looking for search/prompt input...');
  const searchInput = page.locator('input[type="text"], input[placeholder*="search"], input[placeholder*="Search"], input[placeholder*="agent"]').first();
  if (await searchInput.isVisible({ timeout: 2000 }).catch(() => false)) {
    console.log('✅ Found input, typing test query...');
    await searchInput.click();
    await searchInput.fill('weather in San Francisco');
    await page.screenshot({ path: 'papillon-07-typed-query.png', fullPage: true });
    console.log('📸 Screenshot 7: Query typed');

    // Submit
    await page.keyboard.press('Enter');
    await page.waitForTimeout(2000);
    await page.screenshot({ path: 'papillon-08-query-submitted.png', fullPage: true });
    console.log('📸 Screenshot 8: Query submitted');

    // Wait for resolution
    await page.waitForTimeout(5000);
    await page.screenshot({ path: 'papillon-09-query-result.png', fullPage: true });
    console.log('📸 Screenshot 9: Query result');
  }

  // Analyze layout
  console.log('\n📊 Layout Analysis:');
  const body = await page.locator('body').boundingBox();
  const canvas = await page.locator('.canvas-page, .canvas-stream').first().boundingBox().catch(() => null);
  const workflow = await page.locator('[class*="workflow"]').first().boundingBox().catch(() => null);

  console.log('  Body:', body);
  console.log('  Canvas:', canvas);
  console.log('  Workflow:', workflow);

  console.log('\n✅ All screenshots saved!');
  console.log('📝 Check browser console messages above');

  // Keep browser open
  console.log('\n⏸️  Browser will stay open for 30 seconds...');
  await page.waitForTimeout(30000);

  await browser.close();
})();
