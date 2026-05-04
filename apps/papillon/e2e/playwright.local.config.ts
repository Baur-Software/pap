import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 60_000,
  retries: 1,
  workers: 1,
  expect: {
    timeout: 30_000,
  },
  use: {
    baseURL: process.env.PAP_BASE_URL || "http://127.0.0.1:1420",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
