#!/usr/bin/env node

const { execFileSync, execFile } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

const BIN_DIR = path.join(__dirname, "..", ".bin");

function getBinaryName() {
  const platform = os.platform();
  const arch = os.arch();

  const key = `${platform}-${arch}`;
  const map = {
    "linux-x64": "chrysalis-linux-x64",
    "linux-arm64": "chrysalis-linux-arm64",
    "darwin-x64": "chrysalis-macos-universal",
    "darwin-arm64": "chrysalis-macos-universal",
    "win32-x64": "chrysalis-windows-x64",
  };

  const dir = map[key];
  if (!dir) {
    console.error(`Unsupported platform: ${key}`);
    process.exit(1);
  }

  const ext = platform === "win32" ? ".exe" : "";
  return path.join(BIN_DIR, dir, `chrysalis${ext}`);
}

function run() {
  const binary = getBinaryName();

  if (!fs.existsSync(binary)) {
    console.error(
      `Chrysalis binary not found at ${binary}.\nRun "npm install" to download the binary for your platform.`
    );
    process.exit(1);
  }

  // Forward all CLI arguments to the native binary
  const args = process.argv.slice(2);

  try {
    execFileSync(binary, args, { stdio: "inherit" });
  } catch (err) {
    process.exit(err.status || 1);
  }
}

run();
