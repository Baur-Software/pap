#!/usr/bin/env node
/**
 * Generate a Firefox-compatible manifest.json from the Chrome MV3 manifest.
 *
 * Firefox Manifest V3 differences:
 * - Uses "background.scripts" instead of "service_worker"
 * - No "offscreen" permission (use background page instead)
 * - browser_specific_settings for AMO listing
 * - No chrome.offscreen API — background page has full DOM access
 *
 * Output: dist/firefox/manifest.json
 */

import { readFileSync, writeFileSync, mkdirSync, cpSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

const chromeManifest = JSON.parse(
  readFileSync(resolve(root, "manifest.json"), "utf-8")
);

// Transform for Firefox
const firefoxManifest = {
  ...chromeManifest,

  // Firefox uses background.scripts, not service_worker
  background: {
    scripts: ["dist/background/service-worker.js"],
    type: "module",
  },

  // Remove Chrome-only permissions
  permissions: chromeManifest.permissions.filter(
    (p) => p !== "offscreen"
  ),

  // Add Firefox-specific settings
  browser_specific_settings: {
    gecko: {
      id: "papillon@baur-software.com",
      strict_min_version: "128.0",
    },
  },

  // Firefox MV3 CSP — derived from Chrome manifest to stay in sync.
  content_security_policy: {
    extension_pages: chromeManifest.content_security_policy.extension_pages,
  },
};

// Write Firefox manifest
const outDir = resolve(root, "dist-firefox");
mkdirSync(outDir, { recursive: true });
writeFileSync(
  resolve(outDir, "manifest.json"),
  JSON.stringify(firefoxManifest, null, 2)
);

// Copy dist contents
try {
  cpSync(resolve(root, "dist"), outDir, { recursive: true });
} catch {
  console.log("Note: Run 'npm run build' first, then 'npm run firefox:manifest'");
}

console.log(`Firefox manifest written to ${outDir}/manifest.json`);
console.log("Key differences from Chrome:");
console.log("  - background.scripts instead of service_worker");
console.log("  - No offscreen permission (background page has DOM)");
console.log("  - gecko.id: papillon@baur-software.com");
