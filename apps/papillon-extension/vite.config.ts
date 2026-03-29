import { defineConfig } from "vite";
import { resolve } from "path";
import { existsSync } from "fs";
import { viteStaticCopy } from "vite-plugin-static-copy";

// WASM targets are only included if wasm-pack has been run.
// Run `npm run build:wasm` first, or the extension will load without WASM.
const wasmDir = resolve(__dirname, "wasm");
const hasWasm = existsSync(resolve(wasmDir, "pap_wasm_bg.wasm"));

const wasmTargets = hasWasm
  ? [
      { src: "wasm/*.wasm", dest: "wasm" },
      { src: "wasm/pap_wasm.js", dest: "wasm" },
    ]
  : [];

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    rollupOptions: {
      input: {
        "background/service-worker": resolve(
          __dirname,
          "src/background/service-worker.ts"
        ),
        "content/content-script": resolve(
          __dirname,
          "src/content/content-script.ts"
        ),
        "offscreen/offscreen": resolve(
          __dirname,
          "src/offscreen/offscreen.ts"
        ),
        "handshake/handshake": resolve(
          __dirname,
          "src/handshake/handshake.ts"
        ),
        "popup/popup": resolve(__dirname, "src/popup/popup.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name]-[hash].js",
        assetFileNames: "assets/[name].[ext]",
      },
    },
  },
  plugins: [
    viteStaticCopy({
      targets: [
        { src: "manifest.json", dest: "." },
        { src: "_locales", dest: "." },
        { src: "icons/*", dest: "icons" },
        { src: "src/offscreen/offscreen.html", dest: "offscreen" },
        { src: "src/handshake/handshake.html", dest: "handshake" },
        { src: "src/handshake/handshake.css", dest: "handshake" },
        { src: "src/popup/popup.html", dest: "popup" },
        { src: "src/popup/popup.css", dest: "popup" },
        { src: "src/content/content.css", dest: "content" },
        { src: "src/styles/design-system.css", dest: "styles" },
        ...wasmTargets,
      ],
    }),
  ],
});
