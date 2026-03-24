import { defineConfig } from "@playwright/test";

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
    command:
      "cd ../apps/papillion/frontend && trunk serve --port 1420",
    port: 1420,
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
