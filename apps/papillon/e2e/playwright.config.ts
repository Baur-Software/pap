import { defineConfig } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./tests",
  // WASM compile+mount takes ~15ms; 60s covers slow CI runners.
  timeout: 60_000,
  retries: 1,
  // Limit parallel workers in CI to reduce CPU contention from 8 concurrent
  // WASM + Playwright instances (prevents typed-block render timeouts).
  workers: isCI ? 4 : undefined,
  expect: {
    timeout: 30_000,
  },
  use: {
    baseURL: "http://localhost:1420",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    // CI: trunk build --release already ran; serve the static dist directory.
    //     npx serve handles WASM MIME types correctly.
    // Local: trunk serve compiles on-the-fly in dev mode.
    command: isCI
      ? "npx -y serve -s ../frontend/dist -l 1420 --cors --no-clipboard"
      : "cd ../frontend && trunk serve --port 1420",
    port: 1420,
    reuseExistingServer: !isCI,
    timeout: isCI ? 30_000 : 300_000,
  },
});
