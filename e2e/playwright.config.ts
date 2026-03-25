import { defineConfig } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./tests",
  timeout: 120_000,
  retries: 0,
  expect: {
    timeout: 30_000,
  },
  use: {
    baseURL: "http://localhost:1420",
    trace: "on-first-retry",
  },
  webServer: {
    // CI: trunk build --release already ran; serve the static dist directory.
    // Local: trunk serve compiles on-the-fly in dev mode.
    command: isCI
      ? "python3 -m http.server 1420 --directory ../apps/papillion/frontend/dist"
      : "cd ../apps/papillion/frontend && trunk serve --port 1420",
    port: 1420,
    reuseExistingServer: !isCI,
    timeout: isCI ? 10_000 : 120_000,
  },
});
