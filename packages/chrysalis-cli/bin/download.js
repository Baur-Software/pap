#!/usr/bin/env node

/**
 * postinstall script: downloads the correct Chrysalis server binary
 * for the current platform from the GitHub release.
 */

const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { execSync } = require("node:child_process");

const pkg = require("../package.json");
const VERSION = pkg.version;
const REPO = "Baur-Software/pap";
const BIN_DIR = path.join(__dirname, "..", ".bin");

function getPlatformArtifact() {
  const platform = os.platform();
  const arch = os.arch();

  const key = `${platform}-${arch}`;
  const map = {
    "linux-x64": { name: "chrysalis-linux-x64", ext: ".tar.gz" },
    "linux-arm64": { name: "chrysalis-linux-arm64", ext: ".tar.gz" },
    "darwin-x64": { name: "chrysalis-macos-universal", ext: ".tar.gz" },
    "darwin-arm64": { name: "chrysalis-macos-universal", ext: ".tar.gz" },
    "win32-x64": { name: "chrysalis-windows-x64", ext: ".zip" },
  };

  return map[key] || null;
}

async function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, { headers: { "User-Agent": "chrysalis-cli" } }, (res) => {
        // Follow redirects (GitHub releases use 302)
        if (res.statusCode === 302 || res.statusCode === 301) {
          download(res.headers.location, dest).then(resolve).catch(reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`Download failed: HTTP ${res.statusCode}`));
          return;
        }
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", reject);
  });
}

async function main() {
  const artifact = getPlatformArtifact();
  if (!artifact) {
    console.log(
      `Chrysalis: no prebuilt binary for ${os.platform()}-${os.arch()}. ` +
        "Build from source with: cargo leptos build --release -p pap-registry"
    );
    return;
  }

  const assetName = `${artifact.name}-v${VERSION}${artifact.ext}`;
  const url = `https://github.com/${REPO}/releases/download/chrysalis-v${VERSION}/${assetName}`;
  const tmpFile = path.join(os.tmpdir(), assetName);

  console.log(`Downloading Chrysalis v${VERSION} for ${os.platform()}-${os.arch()}...`);

  try {
    await download(url, tmpFile);
  } catch (err) {
    console.log(
      `Could not download binary: ${err.message}\n` +
        "You can build from source with: cargo leptos build --release -p pap-registry"
    );
    return;
  }

  // Extract
  fs.mkdirSync(BIN_DIR, { recursive: true });

  if (artifact.ext === ".tar.gz") {
    execSync(`tar xzf "${tmpFile}" -C "${BIN_DIR}"`);
  } else {
    // .zip on Windows
    execSync(`powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${BIN_DIR}' -Force"`);
  }

  // Make binary executable on Unix
  if (os.platform() !== "win32") {
    const binPath = path.join(BIN_DIR, artifact.name, "chrysalis");
    if (fs.existsSync(binPath)) {
      fs.chmodSync(binPath, 0o755);
    }
  }

  // Clean up
  try {
    fs.unlinkSync(tmpFile);
  } catch (_) {}

  console.log("Chrysalis installed successfully.");
}

main().catch((err) => {
  console.error("postinstall failed:", err.message);
  // Don't fail npm install — the binary can be installed manually
});
