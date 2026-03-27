#!/usr/bin/env node

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const DIST = path.join(__dirname, "..", "dist");
const DEFAULT_PORT = 4180;

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".ttf": "font/ttf",
};

function serve(port) {
  if (!fs.existsSync(DIST)) {
    console.error(
      "Error: dist/ directory not found. This package must be published with the built WASM frontend."
    );
    process.exit(1);
  }

  const server = http.createServer((req, res) => {
    let urlPath = new URL(req.url, `http://localhost:${port}`).pathname;

    // SPA fallback: serve index.html for non-file paths
    let filePath = path.join(DIST, urlPath);
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      filePath = path.join(DIST, "index.html");
    }

    if (!fs.existsSync(filePath)) {
      res.writeHead(404);
      res.end("Not found");
      return;
    }

    const ext = path.extname(filePath);
    const contentType = MIME[ext] || "application/octet-stream";

    const headers = { "Content-Type": contentType };
    // Enable SharedArrayBuffer for WASM threads
    headers["Cross-Origin-Opener-Policy"] = "same-origin";
    headers["Cross-Origin-Embedder-Policy"] = "require-corp";

    const stream = fs.createReadStream(filePath);
    res.writeHead(200, headers);
    stream.pipe(res);
  });

  server.listen(port, () => {
    console.log(`Papillon is running at http://localhost:${port}`);
    console.log("Press Ctrl+C to stop.");
  });
}

// Parse --port flag
const args = process.argv.slice(2);
let port = DEFAULT_PORT;
const portIdx = args.indexOf("--port");
if (portIdx !== -1 && args[portIdx + 1]) {
  port = parseInt(args[portIdx + 1], 10);
} else if (args[0] && /^\d+$/.test(args[0])) {
  port = parseInt(args[0], 10);
}

serve(port);
