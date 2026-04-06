# PAP Development Commands
# Run `just setup` to check prerequisites, `just --list` for all recipes.

default:
    @just --list

# Check development prerequisites
setup:
    #!/usr/bin/env bash
    set -euo pipefail
    ok=true
    check() { command -v "$1" &>/dev/null && echo "  ✓ $1" || { echo "  ✗ $1 — $2"; ok=false; }; }
    echo "Checking prerequisites..."
    echo ""
    echo "Required:"
    check rustc      "install via https://rustup.rs/"
    check cargo      "install via https://rustup.rs/"
    echo ""
    echo "Papillon (desktop app):"
    check cargo-tauri "cargo install tauri-cli"
    check trunk       "cargo install trunk"
    rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown \
        && echo "  ✓ wasm32-unknown-unknown" \
        || { echo "  ✗ wasm32-unknown-unknown — rustup target add wasm32-unknown-unknown"; ok=false; }
    echo ""
    echo "Extension (browser):"
    check node "install Node.js 20+ from https://nodejs.org/"
    check npm  "included with Node.js"
    check wasm-pack "cargo install wasm-pack"
    if command -v node &>/dev/null; then
        node_major=$(node -v | sed 's/v\([0-9]*\).*/\1/')
        [ "$node_major" -ge 20 ] && echo "  ✓ node >= 20 ($(node -v))" \
            || { echo "  ✗ node >= 20 required (found $(node -v))"; ok=false; }
    fi
    echo ""
    $ok && echo "All prerequisites met." || { echo "Some prerequisites missing. See above."; exit 1; }

# ─── Full Stack ───────────────────────────────────────────────

# Run the full dev stack (Registry + Extension + Papillon)
dev:
    #!/usr/bin/env bash
    set -euo pipefail
    pids=()
    cleanup() { for p in "${pids[@]+"${pids[@]}"}"; do kill "$p" 2>/dev/null || true; done; }
    trap cleanup EXIT INT TERM
    echo "Starting PAP dev stack..."
    echo ""
    echo "  Registry  → http://localhost:7890"
    PAP_REGISTRY_NO_TLS=true cargo run -p pap-registry --bin pap-registry --features ssr &
    pids+=($!)
    echo -n "  Waiting for registry"
    for i in $(seq 1 30); do
        curl -sf http://localhost:7890/federation/identity >/dev/null 2>&1 && { echo " ready."; break; }
        [ "$i" -eq 30 ] && { echo " timeout — registry did not start."; exit 1; }
        echo -n "."; sleep 1
    done
    # Bootstrap extension WASM if missing, then start watch
    echo -n "  Extension → "
    (
        cd apps/papillon-extension
        [ -d node_modules ] || npm install
        if [ ! -d wasm ]; then
            echo "bootstrapping WASM..."
            npm run build:wasm
        fi
        npm run dev
    ) &
    pids+=($!)
    sleep 2
    kill -0 "${pids[1]}" 2>/dev/null || { echo "extension failed to start."; exit 1; }
    echo "vite watch"
    echo "  Papillon  → cargo tauri dev"
    echo ""
    echo "Press Ctrl+C to stop all."
    cargo tauri dev -p papillon

# ─── Services ─────────────────────────────────────────────────

# Run Papillon desktop app (Tauri + Leptos frontend)
papillon:
    cargo tauri dev -p papillon

# Run federation registry (default transport)
registry:
    cargo run -p pap-registry --bin pap-registry --features ssr

# Run federation registry (plain HTTP, local dev only)
registry-local:
    PAP_REGISTRY_NO_TLS=true cargo run -p pap-registry --bin pap-registry --features ssr

# Build and watch the browser extension
extension:
    #!/usr/bin/env bash
    set -euo pipefail
    cd apps/papillon-extension
    [ -d node_modules ] || npm install
    [ -d wasm ] || { echo "Bootstrapping extension WASM..."; npm run build:wasm; }
    npm run dev

# ─── Quality ──────────────────────────────────────────────────

# Check formatting + clippy
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

alias check := lint

fmt:
    cargo fmt --all

audit:
    cargo audit

# ─── Test ─────────────────────────────────────────────────────

test:
    cargo test --workspace

# Run tests for a single crate (e.g., just test-crate pap-core)
test-crate crate:
    cargo test -p "{{crate}}"

# Run registry tests with SSR features
test-registry:
    cargo test -p pap-registry --features ssr

# ─── Build ────────────────────────────────────────────────────

build:
    cargo build --workspace

build-release:
    cargo build --workspace --release

# ─── Utilities ────────────────────────────────────────────────

# Run a protocol example (e.g., just run-example pap-search-example)
run-example name:
    cargo run -p "{{name}}"

clean:
    cargo clean
