import { defineConfig } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./tests",
  // WASM compilation on a 2-core CI runner takes 90-120s.
  // Allow 5 minutes total per test to cover compilation + assertions.
  timeout: 300_000,
  retries: 0,
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
      ? "npx -y http-server ../apps/papillion/frontend/dist -p 1420 -c-1 --silent"
      : "cd ../apps/papillion/frontend && trunk serve --port 1420",
    port: 1420,
    reuseExistingServer: !isCI,
    timeout: isCI ? 30_000 : 120_000,
  },
});
